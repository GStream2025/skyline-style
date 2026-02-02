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
    current_app,
    jsonify,
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

account_bp = Blueprint(
    "account",
    __name__,
    url_prefix="/account",
    template_folder="../templates",
)
account_bp.strict_slashes = False

# Alias simple: /cuenta -> /account
cuenta_bp = Blueprint("cuenta", __name__, url_prefix="/cuenta")
cuenta_bp.strict_slashes = False

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off", "unchecked"}


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
    return s in _TRUE


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


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


ACCOUNT_ALLOW_JSON = _env_bool("ACCOUNT_ALLOW_JSON", True)
REQUIRE_CSRF_FALLBACK = _env_bool("REQUIRE_CSRF", True)

MAX_BODY_BYTES = _env_int("ACCOUNT_MAX_BODY_BYTES", 120_000, min_v=20_000, max_v=800_000)

RL_COOLDOWN_SEC = _env_float("ACCOUNT_RATE_LIMIT_SECONDS", 1.0, min_v=0.10, max_v=10.0)
RL_BURST = _env_int("ACCOUNT_RATE_LIMIT_BURST", 12, min_v=3, max_v=80)
RL_WINDOW = _env_int("ACCOUNT_RATE_LIMIT_WINDOW", 60, min_v=10, max_v=900)
_RL_PREFIX = "_acc_rl:"

# Bloquea next a auth/account para evitar loops
_BLOCK_NEXT_PREFIXES = (
    "/auth/login",
    "/auth/register",
    "/auth/account",
    "/account",
    "/cuenta",
)

_CACHE_HEADERS = {
    "Cache-Control": "no-store, max-age=0, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
    "Vary": "Cookie",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def _norm(v: Any, *, max_len: int = 600) -> str:
    if v is None:
        return ""
    s = v if isinstance(v, str) else str(v)
    s = s.replace("\x00", "").replace("\u200b", "").strip()
    s = s.replace("\r", "").replace("\n", "")
    return s[:max_len]


def _template_exists(name: str) -> bool:
    try:
        current_app.jinja_env.get_template(name)
        return True
    except Exception:
        return False


def _url_for_safe(endpoint: str, **kwargs: Any) -> str:
    try:
        return url_for(endpoint, **kwargs)
    except Exception:
        return ""


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
    accept = _norm(request.headers.get("Accept") or "", max_len=200).lower()
    if "application/json" in accept or "text/json" in accept:
        return True
    try:
        best = request.accept_mimetypes.best_match(["application/json", "text/html"])
        return best == "application/json" and request.accept_mimetypes[best] > request.accept_mimetypes["text/html"]
    except Exception:
        return False


def _safe_get_json() -> Dict[str, Any]:
    try:
        cl = request.content_length
        if cl is not None and int(cl) > MAX_BODY_BYTES:
            return {}
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _no_store(resp):
    try:
        for k, v in _CACHE_HEADERS.items():
            resp.headers.setdefault(k, v)
        resp.headers.setdefault("X-Served-By", "skyline")
    except Exception:
        pass
    return resp


def _json(payload: Dict[str, Any], status: int = 200):
    r = jsonify(payload)
    r.status_code = int(status)
    return r


def _json_or_html(payload: Dict[str, Any], html_fn: Callable[[], Any], *, status_json: int = 200):
    if _wants_json():
        return _json(payload, status_json)
    return html_fn()


def _ensure_csrf_token() -> str:
    tok = session.get("csrf_token")
    if not isinstance(tok, str) or len(tok) < 24:
        tok = secrets.token_urlsafe(32)
        session["csrf_token"] = tok
        session.modified = True
    return tok


def _csrf_ok_fallback() -> bool:
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return True
    if not REQUIRE_CSRF_FALLBACK:
        return True

    sess = session.get("csrf_token")
    if not isinstance(sess, str) or not sess:
        return False

    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not sent:
        sent = _safe_get_json().get("csrf_token")

    if not sent:
        return False

    try:
        return secrets.compare_digest(str(sent), sess)
    except Exception:
        return False


def _is_safe_next(target: Optional[str]) -> bool:
    if not target:
        return False
    t = str(target).strip()
    if not t or len(t) > 512:
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


def _safe_next(default: str = "/") -> str:
    raw = _norm(request.values.get("next") or "", max_len=512)
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
        return request.path if request.path else "/"
    except Exception:
        return "/"


def _redirect_login(*, next_url: str) -> Any:
    nxt = next_url if _is_safe_next(next_url) else "/"
    u = _url_for_safe("auth.login_get", next=nxt)
    if u:
        return redirect(u, code=302)
    return redirect(f"/auth/login?{urlencode({'next': nxt})}", code=302)


def _rate_limit_ok(bucket: str) -> bool:
    now = time.time()
    key = f"{_RL_PREFIX}{bucket}"

    state = session.get(key)
    if not isinstance(state, dict):
        state = {"t": now, "n": 0, "last": 0.0}

    try:
        t0 = float(state.get("t") or now)
    except Exception:
        t0 = now
    try:
        n = int(state.get("n") or 0)
    except Exception:
        n = 0
    try:
        last = float(state.get("last") or 0.0)
    except Exception:
        last = 0.0

    if (now - t0) >= float(RL_WINDOW):
        t0 = now
        n = 0
        last = 0.0

    if n >= int(RL_BURST):
        return False

    if (now - last) < float(RL_COOLDOWN_SEC):
        return False

    session[key] = {"t": t0, "n": n + 1, "last": now}
    session.modified = True
    return True


def _get_current_user() -> Optional[User]:
    # Soporta Flask-Login si existe
    try:
        from flask_login import current_user  # type: ignore

        if getattr(current_user, "is_authenticated", False):
            u = current_user  # type: ignore
            if isinstance(u, User):
                return u
            uid = int(getattr(u, "id", 0) or 0)
            if uid > 0:
                return db.session.execute(select(User).where(User.id == uid)).scalar_one_or_none()
    except Exception:
        pass

    # Fallback por sesión propia
    try:
        uid = int(session.get("user_id") or 0)
    except Exception:
        uid = 0
    if uid <= 0:
        return None

    try:
        return db.session.execute(select(User).where(User.id == uid)).scalar_one_or_none()
    except SQLAlchemyError:
        try:
            db.session.rollback()
        except Exception:
            pass
        return None
    except Exception:
        return None


def _clear_bad_session() -> None:
    for k in ("user_id", "user_email", "is_admin", "role", "email_verified", "login_at", "login_nonce"):
        session.pop(k, None)
    for k in list(session.keys()):
        if isinstance(k, str) and k.startswith(_RL_PREFIX):
            session.pop(k, None)
    session.modified = True


def _require_login() -> Optional[Any]:
    u = _get_current_user()
    if u:
        return None
    _clear_bad_session()
    return _redirect_login(next_url=_safe_next(default=_current_path()))


@account_bp.before_request
def _before_account():
    # Token disponible siempre (forms)
    _ensure_csrf_token()

    # Solo limitamos y validamos CSRF en writes
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if not _rate_limit_ok("write"):
            if _wants_json():
                return _json({"ok": False, "error": "rate_limited"}, 429)
            # en HTML, NO mandamos a login (no es auth fail), redirigimos a next seguro
            return redirect(_safe_next(default="/"), code=302)

        if not _csrf_ok_fallback():
            if _wants_json():
                return _json({"ok": False, "error": "csrf_failed"}, 400)
            return redirect(_safe_next(default="/"), code=302)

    return None


@account_bp.after_request
def _after_account(resp):
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

    payload = {
        "ok": True,
        "user_id": int(getattr(u, "id", 0) or 0),
        "email": (getattr(u, "email", "") or ""),
        "role": str(getattr(u, "role", "") or getattr(u, "user_role", "") or ""),
        "email_verified": bool(getattr(u, "email_verified", False) or getattr(u, "is_verified", False)),
    }

    return _json_or_html(
        payload,
        lambda: render_template(
            tpl,
            user=u,
            csrf_token_value=session.get("csrf_token"),
            next=_safe_next(default="/"),
        ),
        status_json=200,
    )


# Alias /cuenta -> /account
@cuenta_bp.get("/")
def cuenta_alias():
    # Mantener next si viene (sin loops)
    nxt = _safe_next(default="/")
    return redirect(f"/account{('?' + urlencode({'next': nxt})) if nxt and nxt != '/' else ''}", code=302)


__all__ = ["account_bp", "cuenta_bp"]
