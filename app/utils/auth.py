from __future__ import annotations

import hmac
import os
from functools import wraps
from typing import Any, Callable, Optional, TypeVar

from flask import current_app, flash, redirect, request, session, url_for

F = TypeVar("F", bound=Callable[..., Any])

# -----------------------------
# Config helpers
# -----------------------------

def _env(key: str, default: str = "") -> str:
    return (os.getenv(key) or current_app.config.get(key) or default).strip()

def _get_admin_email() -> str:
    return _env("ADMIN_EMAIL").lower()

def _get_admin_password() -> str:
    return _env("ADMIN_PASSWORD")

def _bool_session(key: str) -> bool:
    return bool(session.get(key) is True)

def _safe_next_url(default_endpoint: str = "admin.dashboard") -> str:
    """
    next seguro: solo permite paths internos "/..."
    Evita open redirect (http://evil.com)
    """
    nxt = (request.args.get("next") or request.form.get("next") or "").strip()
    if nxt.startswith("/"):
        return nxt
    return url_for(default_endpoint)

# -----------------------------
# DB / current user helper (opcional)
# -----------------------------

def _current_user_is_admin() -> bool:
    """
    1) Si guardás session["is_admin"] => lo usa
    2) Si no, intenta leer User.is_admin desde DB usando session["user_id"]
    """
    if session.get("is_admin") is True:
        return True

    uid = session.get("user_id")
    if not uid:
        return False

    try:
        from app.models import db, User  # usa tu hub
        u = db.session.get(User, int(uid))
        return bool(getattr(u, "is_admin", False))
    except Exception:
        return False

# -----------------------------
# Admin credentials (ENV)
# -----------------------------

def admin_creds_ok(email: str, password: str) -> bool:
    """
    Valida contra ADMIN_EMAIL / ADMIN_PASSWORD (ENV o config).
    Comparación constante para evitar timing leaks.
    """
    admin_email = _get_admin_email()
    admin_pass = _get_admin_password()

    if not admin_email or not admin_pass:
        current_app.logger.warning("⚠️ ADMIN_EMAIL / ADMIN_PASSWORD no están definidos.")
        return False

    email_ok = hmac.compare_digest((email or "").strip().lower(), admin_email)
    pass_ok = hmac.compare_digest((password or "").strip(), admin_pass)
    return bool(email_ok and pass_ok)

# -----------------------------
# Admin session helpers
# -----------------------------

def admin_login() -> None:
    """Marca la sesión como admin (para panel)."""
    session["admin_logged_in"] = True

def admin_logout() -> None:
    """Quita marca admin."""
    session.pop("admin_logged_in", None)

def is_admin_logged() -> bool:
    """
    Considera admin si:
    - session["admin_logged_in"] == True  (login admin panel)
    - session["is_admin"] == True         (login normal pero admin)
    - User.is_admin == True en DB         (fallback)
    """
    return _bool_session("admin_logged_in") or _current_user_is_admin()

# -----------------------------
# Decorator
# -----------------------------

def admin_required(view: F) -> F:
    """
    Protege rutas /admin:
    - Permite si is_admin_logged() es True
    - Si no, redirige a admin.login con next seguro
    """
    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any):
        if is_admin_logged():
            return view(*args, **kwargs)

        flash("Tenés que iniciar sesión como admin.", "warning")
        return redirect(url_for("admin.login", next=_safe_next_url("admin.dashboard")))

    return wrapped  # type: ignore[misc]
