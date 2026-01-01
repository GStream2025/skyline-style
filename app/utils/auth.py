from __future__ import annotations

import hmac
import os
import time
from functools import wraps
from typing import Any, Callable, TypeVar, Optional, Dict, Tuple

from flask import current_app, flash, redirect, request, session, url_for, jsonify

F = TypeVar("F", bound=Callable[..., Any])

# ============================================================
# Constantes (ULTRA PRO)
# ============================================================

_TRUE = {"1", "true", "yes", "y", "on"}
_FALSE = {"0", "false", "no", "n", "off"}

# TTL base admin (default 4h)
ADMIN_SESSION_TTL = int(os.getenv("ADMIN_SESSION_TTL", 60 * 60 * 4))

# TTL extendido si "remember" (default 7 días)
ADMIN_SESSION_TTL_REMEMBER = int(os.getenv("ADMIN_SESSION_TTL_REMEMBER", 60 * 60 * 24 * 7))

# Sliding window: cada cuánto refrescar timestamp (evita escribir en sesión en cada request)
ADMIN_SESSION_REFRESH_EVERY = int(os.getenv("ADMIN_SESSION_REFRESH_EVERY", 60 * 5))  # 5 min

# Rate limit simple por IP (anti fuerza bruta)
ADMIN_LOGIN_MAX_FAILS = int(os.getenv("ADMIN_LOGIN_MAX_FAILS", 8))
ADMIN_LOGIN_WINDOW_SEC = int(os.getenv("ADMIN_LOGIN_WINDOW_SEC", 60 * 10))  # 10 min
ADMIN_LOCKOUT_SEC = int(os.getenv("ADMIN_LOCKOUT_SEC", 60 * 10))  # 10 min

# Keys de sesión (namespace)
_SESS_FLAG = "admin_logged_in"
_SESS_TS = "admin_ts"
_SESS_LAST = "admin_last_seen"
_SESS_EMAIL = "admin_email"
_SESS_REM = "admin_remember"


# ============================================================
# Helpers ENV / Config (robustos)
# ============================================================

def _env(key: str, default: str = "") -> str:
    """
    Lee primero ENV, luego app.config, luego default.
    Nunca rompe.
    """
    try:
        return (os.getenv(key) or current_app.config.get(key) or default).strip()
    except Exception:
        return default


def _bool_env(key: str, default: bool = False) -> bool:
    v = _env(key, "")
    if not v:
        return default
    s = v.strip().lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return default


def _now() -> int:
    return int(time.time())


def _client_ip() -> str:
    """
    IP real (ProxyFix ya debería estar).
    """
    try:
        # X-Forwarded-For puede venir "ip, ip2"
        xff = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        return xff or (request.remote_addr or "0.0.0.0")
    except Exception:
        return "0.0.0.0"


def _wants_json() -> bool:
    try:
        accept = (request.headers.get("Accept") or "").lower()
        return "application/json" in accept or request.is_json
    except Exception:
        return False


# ============================================================
# Redirect seguro (anti open-redirect REAL)
# ============================================================

def _is_safe_next(nxt: str) -> bool:
    """
    Permite solo:
    - rutas relativas internas "/..."
    - misma host (si llega url absoluta por error, la rechazamos)
    """
    if not nxt:
        return False
    nxt = nxt.strip()

    # Solo rutas internas
    if nxt.startswith("/"):
        # evita //evil.com
        if nxt.startswith("//"):
            return False
        return True

    return False


def _safe_next_url(default_endpoint: str = "admin.dashboard") -> str:
    nxt = (request.args.get("next") or request.form.get("next") or "").strip()
    if _is_safe_next(nxt):
        return nxt
    try:
        return url_for(default_endpoint)
    except Exception:
        return "/"


# ============================================================
# Admin credentials (ENV) — MULTI ADMIN + compat legacy
# ============================================================

def _parse_admin_users(raw: str) -> Dict[str, str]:
    """
    ADMIN_USERS="user1:pass1,user2:pass2"
    Retorna dict normalizado {email_lower: pass}
    """
    out: Dict[str, str] = {}
    raw = (raw or "").strip()
    if not raw:
        return out

    for part in raw.split(","):
        part = part.strip()
        if not part or ":" not in part:
            continue
        user, pwd = part.split(":", 1)
        user = user.strip().lower()
        pwd = pwd.strip()
        if user and pwd:
            out[user] = pwd
    return out


def _get_admin_users() -> Dict[str, str]:
    """
    Fuente principal: ADMIN_USERS
    Fallback legacy: ADMIN_EMAIL + ADMIN_PASSWORD
    """
    users = _parse_admin_users(_env("ADMIN_USERS", ""))

    # compat legacy
    legacy_email = _env("ADMIN_EMAIL", "").strip().lower()
    legacy_pass = _env("ADMIN_PASSWORD", "").strip()
    if legacy_email and legacy_pass:
        users.setdefault(legacy_email, legacy_pass)

    return users


def _login_fail_state_key(ip: str) -> str:
    return f"admin:fail:{ip}"


def _rate_limit_check(ip: str) -> Tuple[bool, int]:
    """
    Rate limit simple usando session (sirve bien para tu caso).
    Devuelve (locked, seconds_left)
    """
    k = _login_fail_state_key(ip)
    st = session.get(k)

    if not isinstance(st, dict):
        return (False, 0)

    locked_until = int(st.get("locked_until") or 0)
    if locked_until > _now():
        return (True, locked_until - _now())

    # si ventana expiró, resetea
    win_start = int(st.get("win_start") or 0)
    if win_start and (_now() - win_start) > ADMIN_LOGIN_WINDOW_SEC:
        session.pop(k, None)
        return (False, 0)

    return (False, 0)


def _rate_limit_fail(ip: str) -> None:
    k = _login_fail_state_key(ip)
    st = session.get(k)
    if not isinstance(st, dict):
        st = {"fails": 0, "win_start": _now(), "locked_until": 0}

    # reset ventana si expiró
    win_start = int(st.get("win_start") or 0)
    if not win_start or (_now() - win_start) > ADMIN_LOGIN_WINDOW_SEC:
        st = {"fails": 0, "win_start": _now(), "locked_until": 0}

    st["fails"] = int(st.get("fails") or 0) + 1

    if st["fails"] >= ADMIN_LOGIN_MAX_FAILS:
        st["locked_until"] = _now() + ADMIN_LOCKOUT_SEC

    session[k] = st


def _rate_limit_clear(ip: str) -> None:
    session.pop(_login_fail_state_key(ip), None)


def admin_creds_ok(email: str, password: str) -> bool:
    """
    Valida credenciales admin contra ENV/config.
    - Multi admin: ADMIN_USERS
    - Fallback: ADMIN_EMAIL/ADMIN_PASSWORD
    - Const-time compare
    """
    admins = _get_admin_users()
    if not admins:
        try:
            current_app.logger.warning("⚠️ Admin login bloqueado: no hay ADMIN_USERS ni ADMIN_EMAIL/ADMIN_PASSWORD.")
        except Exception:
            pass
        return False

    e = (email or "").strip().lower()
    p = (password or "").strip()

    stored = admins.get(e)
    if not stored:
        # compara igual contra algo para no filtrar por timing
        _ = hmac.compare_digest(p, "x" * max(1, len(p)))
        return False

    return hmac.compare_digest(p, stored)


# ============================================================
# Admin session helpers (ULTRA)
# ============================================================

def admin_login(*, email: str = "", remember: bool = False) -> None:
    """
    Marca sesión admin con timestamp.
    - Anti session fixation: clear() + nuevo ts
    - Guarda email admin (audit)
    - remember -> TTL extendido
    """
    session.clear()
    session[_SESS_FLAG] = True
    session[_SESS_TS] = _now()
    session[_SESS_LAST] = _now()
    session[_SESS_EMAIL] = (email or "").strip().lower()
    session[_SESS_REM] = bool(remember)


def admin_logout() -> None:
    session.clear()


def _ttl_current() -> int:
    return ADMIN_SESSION_TTL_REMEMBER if bool(session.get(_SESS_REM)) else ADMIN_SESSION_TTL


def _session_admin_valid() -> bool:
    """
    Valida sesión admin con TTL + sliding refresh (cada X minutos).
    """
    if session.get(_SESS_FLAG) is not True:
        return False

    ts = session.get(_SESS_TS)
    if not isinstance(ts, int):
        return False

    ttl = _ttl_current()
    if (_now() - ts) > ttl:
        return False

    # refresh “cada tanto”
    last = session.get(_SESS_LAST)
    if not isinstance(last, int):
        last = 0

    if (_now() - last) >= ADMIN_SESSION_REFRESH_EVERY:
        session[_SESS_LAST] = _now()

    return True


def _current_user_is_admin() -> bool:
    """
    Fallback: usuario normal con flag admin en DB.
    """
    if session.get("is_admin") is True:
        return True

    uid = session.get("user_id")
    if not uid:
        return False

    try:
        from app.models import db, User
        u = db.session.get(User, int(uid))
        return bool(getattr(u, "is_admin", False))
    except Exception:
        return False


def is_admin_logged() -> bool:
    return _session_admin_valid() or _current_user_is_admin()


def admin_identity() -> Dict[str, Any]:
    """
    Útil para logs, auditoría, UI.
    """
    return {
        "is_admin": bool(is_admin_logged()),
        "admin_email": session.get(_SESS_EMAIL) or "",
        "remember": bool(session.get(_SESS_REM)),
        "ttl": int(_ttl_current()),
    }


# ============================================================
# Decorator (admin_required) — HTML o JSON
# ============================================================

def admin_required(view: F) -> F:
    """
    Protege rutas /admin.
    - Si es JSON -> devuelve 401 json
    - Si es HTML -> redirect a login con next seguro
    """
    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any):
        if is_admin_logged():
            return view(*args, **kwargs)

        if _wants_json():
            return jsonify({"error": "admin_required"}), 401

        flash("Tenés que iniciar sesión como admin.", "warning")
        return redirect(url_for("admin.login", next=_safe_next_url("admin.dashboard")))

    return wrapped  # type: ignore[misc]


# ============================================================
# Helper para usar en tu /admin/login POST (recomendado)
# ============================================================

def admin_login_attempt(email: str, password: str, *, remember: bool = False) -> Tuple[bool, str]:
    """
    Maneja:
    - rate limit por IP
    - valida creds
    - crea sesión admin
    Retorna (ok, message)
    """
    ip = _client_ip()

    locked, secs = _rate_limit_check(ip)
    if locked:
        return False, f"Demasiados intentos. Probá de nuevo en {secs}s."

    ok = admin_creds_ok(email, password)
    if not ok:
        _rate_limit_fail(ip)
        return False, "Credenciales inválidas."

    _rate_limit_clear(ip)
    admin_login(email=email, remember=remember)
    return True, "Bienvenido al panel admin ✅"


# ============================================================
# Exports
# ============================================================

__all__ = [
    "admin_required",
    "admin_creds_ok",
    "admin_login",
    "admin_logout",
    "admin_login_attempt",
    "admin_identity",
    "is_admin_logged",
]
