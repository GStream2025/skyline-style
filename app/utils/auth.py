from __future__ import annotations

import os
import hmac
from functools import wraps
from typing import Callable, TypeVar, Any, Optional

from flask import current_app, redirect, request, session, url_for, flash

F = TypeVar("F", bound=Callable[..., Any])

def _get_admin_email() -> str:
    v = (os.getenv("ADMIN_EMAIL") or current_app.config.get("ADMIN_EMAIL") or "").strip().lower()
    return v

def _get_admin_password() -> str:
    v = (os.getenv("ADMIN_PASSWORD") or current_app.config.get("ADMIN_PASSWORD") or "").strip()
    return v

def admin_creds_ok(email: str, password: str) -> bool:
    admin_email = _get_admin_email()
    admin_pass = _get_admin_password()

    if not admin_email or not admin_pass:
        current_app.logger.warning("ADMIN_EMAIL / ADMIN_PASSWORD no están definidos.")
        return False

    # Comparación constante para evitar timing leaks (overkill pero pro)
    email_ok = hmac.compare_digest(email.strip().lower(), admin_email)
    pass_ok = hmac.compare_digest(password.strip(), admin_pass)
    return bool(email_ok and pass_ok)

def admin_required(view: F) -> F:
    """Protege rutas admin por sesión."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("admin_logged_in") is True:
            return view(*args, **kwargs)

        flash("Tenés que iniciar sesión como admin.", "warning")
        next_url = request.full_path if request.query_string else request.path
        return redirect(url_for("admin.login", next=next_url))

    return wrapped  # type: ignore[misc]
