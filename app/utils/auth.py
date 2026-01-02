from __future__ import annotations

import hmac
import os
import time
from functools import wraps
from typing import Any, Callable, Dict, Mapping, Optional, Tuple, TypeVar

from flask import current_app, flash, jsonify, redirect, request, session, url_for

F = TypeVar("F", bound=Callable[..., Any])

_TRUE = {"1", "true", "yes", "y", "on"}
_FALSE = {"0", "false", "no", "n", "off"}

# -----------------------------
# Session keys (namespace)
# -----------------------------
_SESS_FLAG = "admin_logged_in"
_SESS_TS = "admin_ts"
_SESS_LAST = "admin_last_seen"
_SESS_EMAIL = "admin_email"
_SESS_REM = "admin_remember"

# Rate-limit key prefix
_FAIL_PREFIX = "admin:fail:"


# ============================================================
# ENV helpers (safe)
# ============================================================

def _env(key: str, default: str = "") -> str:
    try:
        v = os.getenv(key)
        if v is None:
            v = current_app.config.get(key, default)  # type: ignore[union-attr]
        return (str(v) if v is not None else default).strip()
    except Exception:
        return default


def _env_int(key: str, default: int) -> int:
    raw = _env(key, "")
    if not raw:
        return default
    try:
        return int(str(raw).strip())
    except Exception:
        return default


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
        accept = (request.headers.get("Accept") or "").lower()
        return ("application/json" in accept) or bool(request.is_json) or (request.args.get("json") == "1")
    except Exception:
        return False


def _client_ip() -> str:
    """
    ProxyFix ya debería estar, pero igual blindamos:
    X-Forwarded-For puede venir "ip, ip2"
    """
    try:
        xff = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        return xff or (request.remote_addr or "0.0.0.0")
    except Exception:
        return "0.0.0.0"


# ============================================================
# Redirect seguro (anti open-redirect)
# ============================================================

def _is_safe_next(nxt: str) -> bool:
    if not nxt:
        return False
    nxt = nxt.strip()

    # solo paths internos
    if not nxt.startswith("/"):
        return False

    # evita //evil.com
    if nxt.startswith("//"):
        return False

    # evita cosas raras tipo /\evil
    if "\n" in nxt or "\r" in nxt:
        return False

    return True


def admin_next(default_endpoint: str = "admin.dashboard") -> str:
    """
    Lee next desde query o form, solo si es seguro.
    """
    nxt = (request.args.get("next") or request.form.get("next") or "").strip()
    if _is_safe_next(nxt):
        return nxt
    try:
        return url_for(default_endpoint)
    except Exception:
        return "/admin"


# ============================================================
# Config (TTLs + rate-limit)
# ============================================================

ADMIN_SESSION_TTL = _env_int("ADMIN_SESSION_TTL", 60 * 60 * 4)  # 4h
ADMIN_SESSION_TTL_REMEMBER = _env_int("ADMIN_SESSION_TTL_REMEMBER", 60 * 60 * 24 * 7)  # 7d
ADMIN_SESSION_REFRESH_EVERY = _env_int("ADMIN_SESSION_REFRESH_EVERY", 60 * 5)  # 5m

ADMIN_LOGIN_MAX_FAILS = _env_int("ADMIN_LOGIN_MAX_FAILS", 8)
ADMIN_LOGIN_WINDOW_SEC = _env_int("ADMIN_LOGIN_WINDOW_SEC", 60 * 10)
ADMIN_LOCKOUT_SEC = _env_int("ADMIN_LOCKOUT_SEC", 60 * 10)


# ============================================================
# Admin credentials (ENV) — multi + legacy + hash opcional
# ============================================================

def _parse_admin_users(raw: str) -> Dict[str, str]:
    """
    ADMIN_USERS="user1:pass1,user2:pass2"
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
        user = (user or "").strip().lower()
        pwd = (pwd or "").strip()
        if user and pwd:
            out[user] = pwd
    return out


def _get_admin_users() -> Dict[str, str]:
    users = _parse_admin_users(_env("ADMIN_USERS", ""))

    # legacy
    legacy_email = _env("ADMIN_EMAIL", "").lower()
    legacy_pass = _env("ADMIN_PASSWORD", "")
    if legacy_email and legacy_pass:
        users.setdefault(legacy_email, legacy_pass)

    return users


def _const_time_dummy(password: str) -> None:
    """
    Siempre hacemos compare_digest contra algo, para timing uniform.
    """
    p = (password or "")
    dummy = "x" * max(1, len(p))
    _ = hmac.compare_digest(p, dummy)


def admin_creds_ok(email: str, password: str) -> bool:
    """
    Valida contra:
      - ADMIN_USERS (multi)
      - fallback legacy ADMIN_EMAIL/ADMIN_PASSWORD

    Además soporta opcional:
      - ADMIN_PASSWORD_HASH (sha256 hex) para single-admin rápido
        (si está, valida sha256(password) == hash)
    """
    e = (email or "").strip().lower()
    p = (password or "").strip()

    # Si config “hash-only”:
    admin_email = _env("ADMIN_EMAIL", "").strip().lower()
    admin_hash = _env("ADMIN_PASSWORD_HASH", "").strip().lower()
    if admin_email and admin_hash and e == admin_email:
        try:
            import hashlib
            got = hashlib.sha256(p.encode("utf-8")).hexdigest()
            return hmac.compare_digest(got, admin_hash)
        except Exception:
            _const_time_dummy(p)
            return False

    admins = _get_admin_users()
    if not admins:
        try:
            current_app.logger.warning("⚠️ Admin login bloqueado: faltan ADMIN_USERS o ADMIN_EMAIL/ADMIN_PASSWORD.")
        except Exception:
            pass
        _const_time_dummy(p)
        return False

    stored = admins.get(e)
    if not stored:
        _const_time_dummy(p)
        return False

    return hmac.compare_digest(p, stored)


# ============================================================
# Rate limit (por IP, guardado en session)
# ============================================================

def _fail_key(ip: str) -> str:
    return f"{_FAIL_PREFIX}{ip}"


def _rate_state(ip: str) -> Dict[str, int]:
    st = session.get(_fail_key(ip))
    if isinstance(st, dict):
        # self-heal
        return {
            "fails": int(st.get("fails") or 0),
            "win_start": int(st.get("win_start") or 0),
            "locked_until": int(st.get("locked_until") or 0),
        }
    return {"fails": 0, "win_start": 0, "locked_until": 0}


def _rate_limit_check(ip: str) -> Tuple[bool, int]:
    st = _rate_state(ip)
    now = _now()

    if st["locked_until"] > now:
        return True, st["locked_until"] - now

    # ventana expirada -> reset
    if st["win_start"] and (now - st["win_start"]) > ADMIN_LOGIN_WINDOW_SEC:
        session.pop(_fail_key(ip), None)
        return False, 0

    return False, 0


def _rate_limit_fail(ip: str) -> Tuple[bool, int]:
    st = _rate_state(ip)
    now = _now()

    # reset si no hay ventana o expiró
    if not st["win_start"] or (now - st["win_start"]) > ADMIN_LOGIN_WINDOW_SEC:
        st = {"fails": 0, "win_start": now, "locked_until": 0}

    st["fails"] += 1

    if st["fails"] >= ADMIN_LOGIN_MAX_FAILS:
        st["locked_until"] = now + ADMIN_LOCKOUT_SEC

    session[_fail_key(ip)] = st
    if st["locked_until"] > now:
        return True, st["locked_until"] - now
    return False, 0


def _rate_limit_clear(ip: str) -> None:
    try:
        session.pop(_fail_key(ip), None)
    except Exception:
        pass


# ============================================================
# Admin session
# ============================================================

def admin_login(*, email: str = "", remember: bool = False) -> None:
    """
    Anti session fixation: limpia session y crea flags admin.
    OJO: si querés conservar carrito, en vez de session.clear()
    guardá/restoreá keys específicas.
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

    # sliding refresh (no en cada request)
    if (now - last) >= ADMIN_SESSION_REFRESH_EVERY:
        session[_SESS_LAST] = now

    return True


def _current_user_is_admin_db() -> bool:
    """
    Fallback: usuario normal logueado con flag is_admin en DB.
    No rompe si faltan modelos.
    """
    if session.get("is_admin") is True:
        return True

    uid = session.get("user_id")
    if not uid:
        return False

    try:
        from app.models import db, User
        u = db.session.get(User, int(uid))
        return bool(getattr(u, "is_admin", False)) if u else False
    except Exception:
        return False


def is_admin_logged() -> bool:
    return _session_admin_valid() or _current_user_is_admin_db()


def admin_identity() -> Dict[str, Any]:
    return {
        "is_admin": bool(is_admin_logged()),
        "admin_email": session.get(_SESS_EMAIL) or "",
        "remember": bool(session.get(_SESS_REM)),
        "ttl": int(_ttl_current()),
        "ip": _client_ip(),
    }


# ============================================================
# Decorator
# ============================================================

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


# ============================================================
# Helper recomendado para /admin/login POST
# ============================================================

def admin_login_attempt(email: str, password: str, *, remember: bool = False) -> Tuple[bool, str, int]:
    """
    Maneja:
      - rate limit por IP
      - validación de creds
      - creación de sesión admin
    Retorna: (ok, message, http_status_sugerido)
    """
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
]
