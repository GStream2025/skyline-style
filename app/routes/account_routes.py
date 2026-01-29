from __future__ import annotations

import logging
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlencode, urljoin, urlparse

from flask import Blueprint, current_app, jsonify, redirect, render_template, request, session, url_for
from sqlalchemy import select

from app.models import User, db

log = logging.getLogger("account_routes")

account_bp = Blueprint("account", __name__, url_prefix="/account", template_folder="../templates")
cuenta_bp = Blueprint("cuenta", __name__)

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off", "unchecked"}


def _env_str(name: str, default: str = "") -> str:
    v = os.getenv(name)
    return (default if v is None else str(v)).strip()


def _env_bool(name: str, default: bool = False) -> bool:
    s = _env_str(name, "")
    if not s:
        return default
    s = s.lower()
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

MAX_BODY_BYTES = _env_int("ACCOUNT_MAX_BODY_BYTES", 120_000, min_v=20_000, max_v=500_000)
RL_COOLDOWN_SEC = _env_float("ACCOUNT_RATE_LIMIT_SECONDS", 1.2, min_v=0.15, max_v=10.0)
RL_BURST = _env_int("ACCOUNT_RATE_LIMIT_BURST", 12, min_v=3, max_v=60)
RL_WINDOW = _env_int("ACCOUNT_RATE_LIMIT_WINDOW", 60, min_v=10, max_v=600)

_CACHE_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Vary": "Cookie",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}


def _template_exists(name: str) -> bool:
    try:
        current_app.jinja_env.get_template(name)
        return True
    except Exception:
        return False


def _safe_url_for(endpoint: str, **kwargs) -> str:
    try:
        return url_for(endpoint, **kwargs)
    except Exception:
        qs = urlencode({k: v for k, v in kwargs.items() if v is not None})
        base = f"/{endpoint.replace('.', '/')}"
        return base + (f"?{qs}" if qs else "")


def _wants_json() -> bool:
    if not ACCOUNT_ALLOW_JSON:
        return False
    try:
        if request.is_json:
            return True
    except Exception:
        pass
    fmt = (request.args.get("format") or "").strip().lower()
    if fmt == "json":
        return True
    accept = (request.headers.get("Accept") or "").lower()
    if "application/json" in accept:
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
    except Exception:
        pass
    return resp


def _json_or_html(payload: Dict[str, Any], html_fn: Callable[[], Any]):
    if _wants_json():
        return jsonify(payload)
    return html_fn()


def _is_safe_next(target: Optional[str]) -> bool:
    if not target:
        return False
    t = str(target).strip()
    if not t.startswith("/") or t.startswith("//"):
        return False
    if any(x in t for x in ("\x00", "\\", "\r", "\n", "\t", " ")):
        return False
    if ".." in t:
        return False
    try:
        ref = urlparse(request.host_url)
        test = urlparse(urljoin(request.host_url, t))
        return test.scheme == ref.scheme and test.netloc == ref.netloc
    except Exception:
        return False


def _next_url(default: str = "/account") -> str:
    nxt = (request.values.get("next") or "").strip()
    return nxt if _is_safe_next(nxt) else default


def _next_after_auth(default: str = "/") -> str:
    nxt = _next_url(default)
    if nxt.startswith("/auth"):
        return default
    return nxt


def _redirect_auth_account(tab: str, nxt: str):
    tab = tab if tab in {"login", "register"} else "login"
    nxt = nxt if _is_safe_next(nxt) else "/account"
    try:
        return redirect(url_for("auth.account", tab=tab, next=nxt), code=302)
    except Exception:
        return redirect(f"/auth/account?{urlencode({'tab': tab, 'next': nxt})}", code=302)


def _ensure_csrf_token() -> str:
    tok = session.get("csrf_token")
    if not isinstance(tok, str) or len(tok) < 16:
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


def _rate_limit_ok(key: str) -> bool:
    now = time.time()
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

    if (now - t0) >= float(RL_WINDOW):
        state = {"t": now, "n": 0, "last": 0.0}
        t0 = now
        n = 0

    if n >= int(RL_BURST):
        return False

    try:
        last_hit = float(state.get("last") or 0.0)
    except Exception:
        last_hit = 0.0
    if (now - last_hit) < float(RL_COOLDOWN_SEC):
        return False

    state["n"] = n + 1
    state["last"] = now
    state["t"] = t0
    session[key] = state
    session.modified = True
    return True


def _get_current_user() -> Optional[User]:
    try:
        uid = int(session.get("user_id") or 0)
    except Exception:
        uid = 0
    if uid <= 0:
        return None
    try:
        return db.session.execute(select(User).where(User.id == uid)).scalar_one_or_none()
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        return None


def _clear_bad_session() -> None:
    for k in ("user_id", "user_email", "is_admin", "role", "email_verified", "login_at", "login_nonce"):
        session.pop(k, None)
    session.modified = True


def _require_login():
    u = _get_current_user()
    if u:
        return None
    _clear_bad_session()
    return _redirect_auth_account("login", _next_url())


@account_bp.before_request
def _before_account():
    _ensure_csrf_token()

    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if not _rate_limit_ok("acct_write"):
            if _wants_json():
                return jsonify({"ok": False, "error": "rate_limited"}), 429
            return _redirect_auth_account("login", _next_url())

        if not _csrf_ok_fallback():
            if _wants_json():
                return jsonify({"ok": False, "error": "csrf_failed"}), 400
            return redirect(_next_url("/account"), code=302)

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
        return _redirect_auth_account("login", _next_url())

    tpl = "account/dashboard.html" if _template_exists("account/dashboard.html") else "account/account.html"
    return _json_or_html(
        {"ok": True, "user_id": int(getattr(u, "id", 0) or 0)},
        lambda: render_template(tpl, user=u, csrf_token_value=session.get("csrf_token"), next=_next_after_auth("/")),
    )


__all__ = ["account_bp", "cuenta_bp"]
