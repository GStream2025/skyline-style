from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from functools import wraps
from typing import Any, Callable, Dict, Tuple, TypeVar
from urllib.parse import urlparse

from flask import current_app, flash, jsonify, redirect, request, session, url_for

F = TypeVar("F", bound=Callable[..., Any])

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off"}

_SESS_FLAG = "admin_logged_in"
_SESS_TS = "admin_ts"
_SESS_LAST = "admin_last_seen"
_SESS_EMAIL = "admin_email"
_SESS_REM = "admin_remember"
_SESS_CSRF = "admin_csrf"

_FAIL_PREFIX = "admin:fail:"
_FAILS_TTL_KEY = "admin:fail:ttl"

ADMIN_SESSION_TTL = 60 * 60 * 4
ADMIN_SESSION_TTL_REMEMBER = 60 * 60 * 24 * 7
ADMIN_SESSION_REFRESH_EVERY = 60 * 5

ADMIN_LOGIN_MAX_FAILS = 8
ADMIN_LOGIN_WINDOW_SEC = 60 * 10
ADMIN_LOCKOUT_SEC = 60 * 10


def _env(key: str, default: str = "") -> str:
    try:
        v = os.getenv(key)
        if v is None:
            v = current_app.config.get(key, default)  # type: ignore[union-attr]
        return (str(v) if v is not None else default).strip()
    except Exception:
        return default


def _env_int(key: str, default: int, *, lo: int = 0, hi: int = 10**9) -> int:
    raw = _env(key, "")
    try:
        v = int(str(raw).strip()) if raw else int(default)
    except Exception:
        v = int(default)
    if v < lo:
        return lo
    if v > hi:
        return hi
    return v


def _env_bool(key: str, default: bool = False) -> bool:
    raw = _env(key, "")
    if not raw:
        return default
    s = raw.strip().lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return default


def _now() -> int:
    return int(time.time())


def _wants_json() -> bool:
    try:
        if request.is_json:
            return True
        accept = (request.headers.get("Accept") or "").lower()
        if "application/json" in accept:
            return True
        if (request.headers.get("X-Requested-With") or "").lower() == "xmlhttprequest":
            return True
        if (request.args.get("format") or "").lower() == "json":
            return True
        if (request.args.get("json") or "") == "1":
            return True
    except Exception:
        pass
    return False


def _client_ip() -> str:
    try:
        xff = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        if xff:
            return xff[:64]
        ra = (request.remote_addr or "0.0.0.0").strip()
        return ra[:64] if ra else "0.0.0.0"
    except Exception:
        return "0.0.0.0"


def _safe_next(nxt: str) -> bool:
    if not nxt:
        return False
    s = nxt.strip()
    if not s.startswith("/") or s.startswith("//"):
        return False
    if "\n" in s or "\r" in s or "\x00" in s:
        return False
    try:
        u = urlparse(s)
        return (u.scheme == "" and u.netloc == "" and s.startswith("/"))
    except Exception:
        return False


def admin_next(default_endpoint: str = "admin.dashboard") -> str:
    nxt = (request.args.get("next") or request.form.get("next") or "").strip()
    if _safe_next(nxt):
        return nxt
    try:
        return url_for(default_endpoint)
    except Exception:
        return "/admin"


def _parse_admin_users(raw: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    s = (raw or "").strip()
    if not s:
        return out
    for part in s.split(","):
        part = part.strip()
        if not part or ":" not in part:
            continue
        user, pwd = part.split(":", 1)
        user = (user or "").strip().lower()
        pwd = (pwd or "").strip()
        if user and pwd:
            out[user] = pwd
    return out


def _get_admin_users() -> Dict[str, str]:
    users = _parse_admin_users(_env("ADMIN_USERS", ""))
    legacy_email = _env("ADMIN_EMAIL", "").strip().lower()
    legacy_pass = _env("ADMIN_PASSWORD", "").strip()
    if legacy_email and legacy_pass:
        users.setdefault(legacy_email, legacy_pass)
    return users


def _const_time_dummy(password: str) -> None:
    p = password or ""
    dummy = "x" * max(1, len(p))
    try:
        _ = hmac.compare_digest(p, dummy)
    except Exception:
        pass


def _sha256_hex(s: str) -> str:
    return hashlib.sha256((s or "").encode("utf-8")).hexdigest()


def admin_creds_ok(email: str, password: str) -> bool:
    e = (email or "").strip().lower()
    p = (password or "").strip()

    admin_email = _env("ADMIN_EMAIL", "").strip().lower()
    admin_hash = _env("ADMIN_PASSWORD_HASH", "").strip().lower()
    if admin_email and admin_hash and e == admin_email:
        try:
            return hmac.compare_digest(_sha256_hex(p), admin_hash)
        except Exception:
            _const_time_dummy(p)
            return False

    admins = _get_admin_users()
    if not admins:
        try:
            current_app.logger.warning("Admin login bloqueado: faltan credenciales en ENV.")
        except Exception:
            pass
        _const_time_dummy(p)
        return False

    stored = admins.get(e)
    if not stored:
        _const_time_dummy(p)
        return False
    try:
        return hmac.compare_digest(p, stored)
    except Exception:
        _const_time_dummy(p)
        return False


def _fail_key(ip: str) -> str:
    return f"{_FAIL_PREFIX}{ip}"


def _rate_state(ip: str) -> Dict[str, int]:
    st = session.get(_fail_key(ip))
    if isinstance(st, dict):
        try:
            return {
                "fails": int(st.get("fails") or 0),
                "win_start": int(st.get("win_start") or 0),
                "locked_until": int(st.get("locked_until") or 0),
            }
        except Exception:
            return {"fails": 0, "win_start": 0, "locked_until": 0}
    return {"fails": 0, "win_start": 0, "locked_until": 0}


def _rate_reset_if_needed(st: Dict[str, int], now: int) -> Dict[str, int]:
    ws = int(st.get("win_start") or 0)
    if not ws or (now - ws) > ADMIN_LOGIN_WINDOW_SEC:
        return {"fails": 0, "win_start": now, "locked_until": 0}
    return st


def _rate_limit_check(ip: str) -> Tuple[bool, int]:
    st = _rate_state(ip)
    now = _now()
    locked_until = int(st.get("locked_until") or 0)
    if locked_until > now:
        return True, locked_until - now
    return False, 0


def _rate_limit_fail(ip: str) -> Tuple[bool, int]:
    now = _now()
    st = _rate_reset_if_needed(_rate_state(ip), now)
    st["fails"] = int(st.get("fails") or 0) + 1
    if st["fails"] >= ADMIN_LOGIN_MAX_FAILS:
        st["locked_until"] = now + ADMIN_LOCKOUT_SEC
    session[_fail_key(ip)] = st
    if int(st.get("locked_until") or 0) > now:
        return True, int(st["locked_until"]) - now
    return False, 0


def _rate_limit_clear(ip: str) -> None:
    try:
        session.pop(_fail_key(ip), None)
    except Exception:
        pass


def _token16() -> str:
    return secrets.token_urlsafe(16)


def admin_csrf_token() -> str:
    tok = session.get(_SESS_CSRF)
    if isinstance(tok, str) and tok:
        return tok
    tok2 = _token16()
    session[_SESS_CSRF] = tok2
    return tok2


def admin_csrf_ok(token: str) -> bool:
    try:
        st = session.get(_SESS_CSRF)
        if not isinstance(st, str) or not st:
            return False
        return hmac.compare_digest((token or "").strip(), st)
    except Exception:
        return False


def _apply_env_overrides() -> None:
    global ADMIN_SESSION_TTL, ADMIN_SESSION_TTL_REMEMBER, ADMIN_SESSION_REFRESH_EVERY
    global ADMIN_LOGIN_MAX_FAILS, ADMIN_LOGIN_WINDOW_SEC, ADMIN_LOCKOUT_SEC

    ADMIN_SESSION_TTL = _env_int("ADMIN_SESSION_TTL", ADMIN_SESSION_TTL, lo=60, hi=60 * 60 * 24 * 31)
    ADMIN_SESSION_TTL_REMEMBER = _env_int(
        "ADMIN_SESSION_TTL_REMEMBER", ADMIN_SESSION_TTL_REMEMBER, lo=60 * 60, hi=60 * 60 * 24 * 90
    )
    ADMIN_SESSION_REFRESH_EVERY = _env_int(
        "ADMIN_SESSION_REFRESH_EVERY", ADMIN_SESSION_REFRESH_EVERY, lo=30, hi=60 * 60
    )

    ADMIN_LOGIN_MAX_FAILS = _env_int("ADMIN_LOGIN_MAX_FAILS", ADMIN_LOGIN_MAX_FAILS, lo=1, hi=50)
    ADMIN_LOGIN_WINDOW_SEC = _env_int("ADMIN_LOGIN_WINDOW_SEC", ADMIN_LOGIN_WINDOW_SEC, lo=30, hi=60 * 60)
    ADMIN_LOCKOUT_SEC = _env_int("ADMIN_LOCKOUT_SEC", ADMIN_LOCKOUT_SEC, lo=10, hi=60 * 60)


def admin_login(*, email: str = "", remember: bool = False) -> None:
    _apply_env_overrides()
    session.clear()
    session[_SESS_FLAG] = True
    session[_SESS_TS] = _now()
    session[_SESS_LAST] = _now()
    session[_SESS_EMAIL] = (email or "").strip().lower()
    session[_SESS_REM] = bool(remember)
    session[_SESS_CSRF] = _token16()
    try:
        session.modified = True
    except Exception:
        pass


def admin_logout() -> None:
    try:
        session.clear()
        session.modified = True
    except Exception:
        try:
            session.clear()
        except Exception:
            pass


def _ttl_current() -> int:
    return ADMIN_SESSION_TTL_REMEMBER if bool(session.get(_SESS_REM)) else ADMIN_SESSION_TTL


def _session_admin_valid() -> bool:
    if session.get(_SESS_FLAG) is not True:
        return False

    ts = session.get(_SESS_TS)
    if not isinstance(ts, int):
        return False

    now = _now()
    if (now - ts) > _ttl_current():
        return False

    last = session.get(_SESS_LAST)
    if not isinstance(last, int):
        last = 0

    if (now - last) >= ADMIN_SESSION_REFRESH_EVERY:
        session[_SESS_LAST] = now
        try:
            session.modified = True
        except Exception:
            pass

    return True


def _current_user_is_admin_db() -> bool:
    if session.get("is_admin") is True:
        return True

    uid = session.get("user_id")
    if not uid:
        return False

    try:
        from app.models import db, User  # noqa: WPS433

        try:
            model = getattr(User, "model", None) or getattr(User, "_model", None) or getattr(User, "cls", None) or User
        except Exception:
            model = User

        u = db.session.get(model, int(uid))
        return bool(getattr(u, "is_admin", False)) if u else False
    except Exception:
        return False


def is_admin_logged() -> bool:
    return _session_admin_valid() or _current_user_is_admin_db()


def admin_identity() -> Dict[str, Any]:
    return {
        "is_admin": bool(is_admin_logged()),
        "admin_email": str(session.get(_SESS_EMAIL) or ""),
        "remember": bool(session.get(_SESS_REM)),
        "ttl": int(_ttl_current()),
        "ip": _client_ip(),
    }


def admin_required(view: F) -> F:
    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any):
        if is_admin_logged():
            return view(*args, **kwargs)

        if _wants_json():
            return jsonify({"ok": False, "error": "admin_required"}), 401

        flash("Tenés que iniciar sesión como admin.", "warning")
        return redirect(url_for("admin.login", next=admin_next("admin.dashboard")))

    return wrapped  # type: ignore[misc]


def admin_login_attempt(email: str, password: str, *, remember: bool = False) -> Tuple[bool, str, int]:
    _apply_env_overrides()
    ip = _client_ip()

    locked, secs = _rate_limit_check(ip)
    if locked:
        return False, f"Demasiados intentos. Probá de nuevo en {secs}s.", 429

    ok = admin_creds_ok(email, password)
    if not ok:
        locked2, secs2 = _rate_limit_fail(ip)
        if locked2:
            return False, f"Demasiados intentos. Probá de nuevo en {secs2}s.", 429
        return False, "Credenciales inválidas.", 401

    _rate_limit_clear(ip)
    admin_login(email=email, remember=remember)
    return True, "Bienvenido al panel admin ✅", 200


__all__ = [
    "admin_required",
    "admin_creds_ok",
    "admin_login",
    "admin_logout",
    "admin_login_attempt",
    "admin_identity",
    "is_admin_logged",
    "admin_next",
    "admin_csrf_token",
    "admin_csrf_ok",
]
