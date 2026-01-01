from __future__ import annotations

import hmac
import os
import time
from functools import wraps
from typing import Any, Callable, TypeVar, Optional

from flask import current_app, flash, redirect, request, session, url_for

F = TypeVar("F", bound=Callable[..., Any])

# ============================================================
# Constantes
# ============================================================

ADMIN_SESSION_TTL = int(os.getenv("ADMIN_SESSION_TTL", 60 * 60 * 4))  # 4 horas
_TRUE = {"1", "true", "yes", "y", "on"}


# ============================================================
# ENV / Config helpers (robustos)
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


def _get_admin_email() -> str:
    return _env("ADMIN_EMAIL").lower()


def _get_admin_password() -> str:
    return _env("ADMIN_PASSWORD")


def _now() -> int:
    return int(time.time())


# ============================================================
# Redirect seguro (anti open-redirect)
# ============================================================

def _safe_next_url(default_endpoint: str = "admin.dashboard") -> str:
    """
    Permite SOLO paths internos (/algo).
    Si no es seguro → endpoint por defecto.
    """
    nxt = (request.args.get("next") or request.form.get("next") or "").strip()
    if nxt.startswith("/"):
        return nxt
    try:
        return url_for(default_endpoint)
    except Exception:
        return "/"


# ============================================================
# Admin credentials (ENV)
# ============================================================

def admin_creds_ok(email: str, password: str) -> bool:
    """
    Valida credenciales admin contra ENV/config.
    Usa comparación constante (anti timing attacks).
    """
    admin_email = _get_admin_email()
    admin_pass = _get_admin_password()

    if not admin_email or not admin_pass:
        # No rompe la app, solo bloquea login admin
        try:
            current_app.logger.warning(
                "⚠️ ADMIN_EMAIL / ADMIN_PASSWORD no configurados."
            )
        except Exception:
            pass
        return False

    email_ok = hmac.compare_digest(
        (email or "").strip().lower(),
        admin_email,
    )
    pass_ok = hmac.compare_digest(
        (password or "").strip(),
        admin_pass,
    )

    return bool(email_ok and pass_ok)


# ============================================================
# Admin session helpers
# ============================================================

def admin_login() -> None:
    """
    Marca sesión admin con timestamp.
    """
    session.clear()
    session["admin_logged_in"] = True
    session["admin_ts"] = _now()


def admin_logout() -> None:
    """
    Cierra sesión admin limpiamente.
    """
    session.clear()


def _session_admin_valid() -> bool:
    """
    Valida sesión admin con TTL (expira).
    """
    if session.get("admin_logged_in") is not True:
        return False

    ts = session.get("admin_ts")
    if not isinstance(ts, int):
        return False

    if (_now() - ts) > ADMIN_SESSION_TTL:
        return False

    # Sliding window
    session["admin_ts"] = _now()
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
    """
    Considera admin si:
    - sesión admin válida (panel)
    - sesión user con is_admin
    - User.is_admin en DB
    """
    return _session_admin_valid() or _current_user_is_admin()


# ============================================================
# Decorator
# ============================================================

def admin_required(view: F) -> F:
    """
    Protege rutas /admin.
    Redirige a login admin con next seguro.
    """
    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any):
        if is_admin_logged():
            return view(*args, **kwargs)

        flash("Tenés que iniciar sesión como admin.", "warning")
        return redirect(
            url_for(
                "admin.login",
                next=_safe_next_url("admin.dashboard"),
            )
        )

    return wrapped  # type: ignore[misc]


# ============================================================
# Exports
# ============================================================

__all__ = [
    "admin_required",
    "admin_creds_ok",
    "admin_login",
    "admin_logout",
    "is_admin_logged",
]
