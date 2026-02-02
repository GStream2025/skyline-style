from __future__ import annotations

import logging
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlencode, urlparse

from flask import (
    Blueprint,
    Response,
    current_app,
    flash,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.models import User, db

log = logging.getLogger("account_routes")

account_bp = Blueprint("account", __name__, url_prefix="/account", template_folder="../templates")
account_bp.strict_slashes = False

cuenta_bp = Blueprint("cuenta", __name__, url_prefix="/cuenta")
cuenta_bp.strict_slashes = False

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off", "unchecked"}

_CSRF_KEY = "csrf_token"
_SESSION_LOGIN_AT = "login_at"
_SESSION_LOGIN_NONCE = "login_nonce"

_MAX_NEXT = 512
_MAX_HDR = 240
_MAX_BODY_BYTES_DEFAULT = 120_000

_RL_PREFIX = "acc_rl:"
_RL_STORE_KEY = "acc_rl_store_v2"
_RL_STORE_CAP = 300
_RL_STORE_TTL = 60 * 30

_BLOCK_NEXT_PREFIXES = (
    "/auth/login",
    "/auth/register",
    "/auth/account",
    "/account",
    "/cuenta",
)

_NO_STORE_HEADERS = {
    "Cache-Control": "no-store, max-age=0, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _env_str(name: str, default: str = "") -> str:
    v = os.getenv(name)
    return (default if v is None else str(v)).strip()


def _env_bool(name: str, default: bool = False) -> bool:
    s = _env_str(name, "")
    if not s:
        return default
    s = s.strip().lower()
    if s in _FALSE:
        return False
    return s in _TRUE or s == "1"


def _env_int(name: str, default: int, *, min_v: int, max_v: int) -> int:
    try:
        n = int(_env_str(name, str(default)))
    except Exception:
        n = default
    return max(min_v, min(max_v, n))


def _env_float(name: str, default: float, *, min_v: float, max_v: float) -> float:
    try:
        x = float(_env_str(name, str(default)))
    except Exception:
        x = default
    return max(min_v, min(max_v, x))


ACCOUNT_ALLOW_JSON = _env_bool("ACCOUNT_ALLOW_JSON", True)
REQUIRE_CSRF_FALLBACK = _env_bool("REQUIRE_CSRF", True)

MAX_BODY_BYTES = _env_int("ACCOUNT_MAX_BODY_BYTES", _MAX_BODY_BYTES_DEFAULT, min_v=20_000, max_v=800_000)

RL_COOLDOWN_SEC = _env_float("ACCOUNT_RATE_LIMIT_SECONDS", 1.0, min_v=0.10, max_v=10.0)
RL_BURST = _env_int("ACCOUNT_RATE_LIMIT_BURST", 12, min_v=3, max_v=80)
RL_WINDOW = _env_int("ACCOUNT_RATE_LIMIT_WINDOW", 60, min_v=10, max_v=900)


def _now() -> int:
    return int(time.time())


def _norm(v: Any, *, max_len: int = 600) -> str:
    if v is None:
        return ""
    s = v if isinstance(v, str) else str(v)
    s = s.replace("\x00", "").replace("\u200b", "").strip()
    s = s.replace("\r", "").replace("\n", "")
    return s if max_len <= 0 else s[:max_len]


def _wants_json() -> bool:
    if not ACCOUNT_ALLOW_JSON:
        return False
    try:
        if request.is_json:
            return True
    except Exception:
        pass

    fmt = _norm(request.args.get("format") or "", max_len=24).lower()
    if fmt == "json":
        return True

    accept = _norm(request.headers.get("Accept") or "", max_len=_MAX_HDR).lower()
    if "application/json" in accept or "text/json" in accept:
        return True

    if (_norm(request.headers.get("X-Requested-With") or "", max_len=64).lower()) == "xmlhttprequest":
        return True

    try:
        best = request.accept_mimetypes.best_match(["application/json", "text/html"])
        return best == "application/json" and request.accept_mimetypes[best] > request.accept_mimetypes["text/html"]
    except Exception:
        return False


def _json(payload: Dict[str, Any], status: int = 200) -> Response:
    r = jsonify(payload)
    r.status_code = int(status)
    return r


def _template_exists(name: str) -> bool:
    try:
        current_app.jinja_env.get_template(name)
        return True
    except Exception:
        return False


def _render_safe(template: str, **ctx: Any):
    if _template_exists(template):
        try:
            return render_template(template, **ctx)
        except Exception:
            log.exception("render failed: %s", template)
    title = _norm(ctx.get("title") or "Cuenta", max_len=120)
    body = (
        "<!doctype html><html lang='es'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{title}</title></head>"
        "<body style='font-family:system-ui;padding:24px;max-width:920px;margin:0 auto'>"
        f"<h1 style='margin:0 0 10px'>{title}</h1>"
        "<p style='opacity:.75;margin:0'>Template faltante o error de render.</p>"
        "</body></html>"
    )
    return body, 200, {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store"}


def _no_store(resp: Response) -> Response:
    try:
        for k, v in _NO_STORE_HEADERS.items():
            resp.headers.setdefault(k, v)
        vary = resp.headers.get("Vary", "")
        parts = [p.strip() for p in vary.split(",") if p.strip()]
        if "Cookie" not in parts:
            parts.append("Cookie")
        if "Accept" not in parts:
            parts.append("Accept")
        resp.headers["Vary"] = ", ".join(parts)
        resp.headers.setdefault("X-Served-By", "skyline")
    except Exception:
        pass
    return resp


def _safe_get_json() -> Dict[str, Any]:
    try:
        cl = request.content_length
        if cl is not None and int(cl) > MAX_BODY_BYTES:
            return {}
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _ensure_csrf_token() -> str:
    tok = session.get(_CSRF_KEY)
    if not isinstance(tok, str) or len(tok) < 24:
        tok = secrets.token_urlsafe(32)
        session[_CSRF_KEY] = tok
    session.permanent = True
    session.modified = True
    return str(session[_CSRF_KEY])


def _csrf_ok_fallback() -> bool:
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return True
    if not REQUIRE_CSRF_FALLBACK:
        return True

    sess = session.get(_CSRF_KEY)
    if not isinstance(sess, str) or not sess:
        return False

    sent = ""
    try:
        sent = (request.form.get(_CSRF_KEY) or request.headers.get("X-CSRF-Token") or "").strip()
    except Exception:
        sent = ""

    if not sent:
        sent = str(_safe_get_json().get(_CSRF_KEY) or "").strip()

    if not sent:
        return False

    try:
        return secrets.compare_digest(str(sent), str(sess))
    except Exception:
        return False


def _is_safe_next(target: Optional[str]) -> bool:
    if not target:
        return False
    t = str(target).strip()
    if not t or len(t) > _MAX_NEXT:
        return False
    if not t.startswith("/") or t.startswith("//"):
        return False
    if any(x in t for x in ("\x00", "\\", "\r", "\n", "\t", " ")):
        return False
    if "://" in t:
        return False
    try:
        p = urlparse(t)
        if p.scheme or p.netloc:
            return False
        path = p.path or ""
    except Exception:
        return False
    if not path.startswith("/") or path.startswith("//"):
        return False
    if ".." in path:
        return False
    return True


def _safe_next(*, default: str = "/") -> str:
    raw = _norm(request.values.get("next") or "", max_len=_MAX_NEXT)
    if not _is_safe_next(raw):
        return default

    try:
        p = urlparse(raw)
        path = p.path or default
    except Exception:
        return default

    for pref in _BLOCK_NEXT_PREFIXES:
        if path == pref or path.startswith(pref + "/"):
            return default

    return path if path.startswith("/") else default


def _current_path() -> str:
    try:
        p = request.path or "/"
    except Exception:
        p = "/"
    return p if p.startswith("/") else "/"


def _url_for_safe(endpoint: str, **kwargs: Any) -> str:
    try:
        return url_for(endpoint, **kwargs)
    except Exception:
        return ""


def _redirect_login(*, next_url: str) -> Any:
    nxt = next_url if _is_safe_next(next_url) else "/"
    u = _url_for_safe("auth.login_get", next=nxt)
    if u:
        return redirect(u, code=302)
    return redirect(f"/auth/login?{urlencode({'next': nxt})}", code=302)


def _rl_store() -> Dict[str, Dict[str, float]]:
    raw = session.get(_RL_STORE_KEY)
    if isinstance(raw, dict):
        out: Dict[str, Dict[str, float]] = {}
        for k, v in raw.items():
            if isinstance(k, str) and isinstance(v, dict):
                try:
                    t = float(v.get("t", 0.0) or 0.0)
                except Exception:
                    t = 0.0
                try:
                    n = float(v.get("n", 0.0) or 0.0)
                except Exception:
                    n = 0.0
                try:
                    last = float(v.get("last", 0.0) or 0.0)
                except Exception:
                    last = 0.0
                out[k] = {"t": t, "n": n, "last": last}
        return out
    return {}


def _rl_save(store: Dict[str, Dict[str, float]]) -> None:
    session[_RL_STORE_KEY] = store
    session.modified = True


def _rate_limit_ok(bucket: str) -> bool:
    now = time.time()
    store = _rl_store()
    key = f"{_RL_PREFIX}{bucket}"

    cutoff = now - float(_RL_STORE_TTL)
    if store:
        for k in list(store.keys()):
            t0 = float(store.get(k, {}).get("t", 0.0) or 0.0)
            if t0 and t0 < cutoff:
                store.pop(k, None)

    if len(store) > _RL_STORE_CAP:
        items = sorted((float(v.get("t", 0.0) or 0.0), k) for k, v in store.items())
        for _, k in items[: max(0, len(store) - _RL_STORE_CAP)]:
            store.pop(k, None)

    state = store.get(key) or {"t": now, "n": 0.0, "last": 0.0}
    try:
        t0 = float(state.get("t", now) or now)
    except Exception:
        t0 = now
    try:
        n = int(state.get("n", 0.0) or 0.0)
    except Exception:
        n = 0
    try:
        last = float(state.get("last", 0.0) or 0.0)
    except Exception:
        last = 0.0

    if (now - t0) >= float(RL_WINDOW) or (now - t0) < 0:
        t0, n, last = now, 0, 0.0

    if n >= int(RL_BURST):
        return False

    if (now - last) < float(RL_COOLDOWN_SEC):
        return False

    store[key] = {"t": float(t0), "n": float(n + 1), "last": float(now)}
    _rl_save(store)
    return True


def _db_rollback_quiet() -> None:
    try:
        db.session.rollback()
    except Exception:
        pass


def _get_current_user() -> Optional[User]:
    try:
        from flask_login import current_user  # type: ignore

        if getattr(current_user, "is_authenticated", False):
            cu = current_user  # type: ignore
            if isinstance(cu, User):
                return cu
            uid = int(getattr(cu, "id", 0) or 0)
            if uid > 0:
                return db.session.execute(select(User).where(User.id == uid)).scalar_one_or_none()
    except Exception:
        pass

    try:
        uid = int(session.get("user_id") or 0)
    except Exception:
        uid = 0
    if uid <= 0:
        return None

    try:
        return db.session.execute(select(User).where(User.id == uid)).scalar_one_or_none()
    except SQLAlchemyError:
        _db_rollback_quiet()
        return None
    except Exception:
        return None


def _clear_bad_session() -> None:
    for k in ("user_id", "user_email", "is_admin", "role", "email_verified", _SESSION_LOGIN_AT, _SESSION_LOGIN_NONCE):
        session.pop(k, None)
    for k in list(session.keys()):
        if isinstance(k, str) and (k.startswith(_RL_PREFIX) or k.startswith("acc_")):
            session.pop(k, None)
    session.modified = True


def _require_login() -> Optional[Any]:
    u = _get_current_user()
    if u:
        return None
    _clear_bad_session()
    return _redirect_login(next_url=_safe_next(default=_current_path()))


def _flash(msg: str, category: str = "info") -> None:
    try:
        flash(_norm(msg, max_len=220), category)
    except Exception:
        pass


def _json_or_html(payload: Dict[str, Any], html_fn: Callable[[], Any], *, status_json: int = 200):
    if _wants_json():
        return _json(payload, status_json)
    return html_fn()


@account_bp.before_request
def _before_account():
    _ensure_csrf_token()

    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if not _rate_limit_ok("write"):
            if _wants_json():
                return _json({"ok": False, "error": "rate_limited"}, 429)
            _flash("Muy rápido 😅 Esperá un segundo y reintentá.", "warning")
            return redirect(_safe_next(default="/"), code=302)

        if not _csrf_ok_fallback():
            if _wants_json():
                return _json({"ok": False, "error": "csrf_failed"}, 400)
            _flash("CSRF inválido. Recargá la página.", "warning")
            return redirect(_safe_next(default="/"), code=302)

    return None


@account_bp.after_request
def _after_account(resp: Response):
    return _no_store(resp)


@account_bp.get("/")
def account_home():
    guard = _require_login()
    if guard:
        return guard

    u = _get_current_user()
    if not u:
        return _redirect_login(next_url=_safe_next(default="/"))

    tpl = "account/dashboard.html" if _template_exists("account/dashboard.html") else "account/account.html"
    if not _template_exists(tpl):
        tpl = "account/account.html"

    payload = {
        "ok": True,
        "user": {
            "id": int(getattr(u, "id", 0) or 0),
            "email": (getattr(u, "email", "") or ""),
            "role": str(getattr(u, "role", "") or getattr(u, "user_role", "") or "customer"),
            "email_verified": bool(getattr(u, "email_verified", False) or getattr(u, "is_verified", False)),
        },
        "next": _safe_next(default="/"),
        "csrf_token": session.get(_CSRF_KEY) or "",
    }

    return _json_or_html(
        payload,
        lambda: make_response(
            _render_safe(
                tpl,
                title="Mi cuenta",
                user=u,
                csrf_token_value=session.get(_CSRF_KEY),
                next=payload["next"],
                ui={
                    "brand": str(current_app.config.get("APP_NAME") or "Skyline Store"),
                    "support_email": str(current_app.config.get("SUPPORT_EMAIL") or ""),
                    "show_verified_badge": True,
                    "show_role_badge": True,
                },
            ),
            200,
        ),
        status_json=200,
    )


@account_bp.post("/session/refresh")
def account_session_refresh():
    guard = _require_login()
    if guard:
        return guard

    if not _rate_limit_ok("refresh"):
        if _wants_json():
            return _json({"ok": False, "error": "rate_limited"}, 429)
        _flash("Muy rápido 😅", "warning")
        return redirect(_safe_next(default="/account"), code=302)

    if not _csrf_ok_fallback():
        if _wants_json():
            return _json({"ok": False, "error": "csrf_failed"}, 400)
        _flash("CSRF inválido.", "warning")
        return redirect(_safe_next(default="/account"), code=302)

    session[_SESSION_LOGIN_AT] = _now()
    session[_SESSION_LOGIN_NONCE] = secrets.token_urlsafe(16)
    session.modified = True

    if _wants_json():
        return _json({"ok": True, "refreshed": True}, 200)

    _flash("Sesión actualizada ✅", "success")
    return redirect(_safe_next(default="/account"), code=302)


@account_bp.get("/health")
def account_health():
    if not _wants_json():
        return redirect("/account", code=302)

    u = _get_current_user()
    return _json(
        {
            "ok": True,
            "authenticated": bool(u),
            "user_id": int(getattr(u, "id", 0) or 0) if u else 0,
            "server_time_utc": utcnow().isoformat(),
        },
        200,
    )


@cuenta_bp.get("/")
def cuenta_alias():
    nxt = _safe_next(default="/")
    qs = urlencode({"next": nxt}) if nxt and nxt != "/" else ""
    return redirect("/account" + (("?" + qs) if qs else ""), code=302)


__all__ = ["account_bp", "cuenta_bp"]
