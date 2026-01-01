# app/routes/auth_routes.py
from __future__ import annotations

import time
from urllib.parse import urlparse
from typing import Optional

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from app.models import db, User


# ============================================================
# Blueprint
# ============================================================
# SIN url_prefix → /login /register /logout
auth_bp = Blueprint("auth", __name__)


# ============================================================
# Config / Seguridad
# ============================================================

MAX_LOGIN_ATTEMPTS = 5          # intentos antes de lock
LOCK_TIME_SECONDS = 300         # 5 minutos
RATE_LIMIT_SECONDS = 2          # 1 intento cada 2s por sesión


# ============================================================
# Helpers — Seguridad / Session
# ============================================================

def _is_safe_next(nxt: str) -> bool:
    """Previene open-redirect: solo paths internos."""
    if not nxt:
        return False
    nxt = nxt.strip()
    if not nxt.startswith("/"):
        return False
    p = urlparse(nxt)
    return p.scheme == "" and p.netloc == ""


def _next_url(default: str) -> str:
    nxt = (request.args.get("next") or request.form.get("next") or "").strip()
    return nxt if _is_safe_next(nxt) else default


def _clear_session() -> None:
    session.clear()


def _get_current_user() -> Optional[User]:
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        uid = int(uid)
    except Exception:
        _clear_session()
        return None

    u = db.session.get(User, uid)
    if not u:
        _clear_session()
        return None
    return u


def _set_session_user(user: User) -> None:
    """Session limpia, mínima y consistente."""
    session.clear()
    session["user_id"] = int(user.id)
    session["user_email"] = (user.email or "").lower()
    session["is_admin"] = bool(getattr(user, "is_admin", False))
    session["login_at"] = int(time.time())
    session.permanent = True


def _post_login_redirect(user: User) -> str:
    """Destino post-login."""
    if bool(getattr(user, "is_admin", False)):
        return url_for("admin.dashboard")
    return url_for("account.account_home")


def _rate_limit_ok() -> bool:
    """Anti brute-force simple por sesión."""
    now = time.time()
    last = session.get("last_login_try", 0)
    if (now - last) < RATE_LIMIT_SECONDS:
        return False
    session["last_login_try"] = now
    return True


# ============================================================
# Login
# ============================================================

@auth_bp.get("/login")
def login():
    u = _get_current_user()
    if u:
        return redirect(_post_login_redirect(u))

    return render_template(
        "auth/login.html",
        next=_next_url(url_for("shop.shop")),
    )


@auth_bp.post("/login")
def login_post():
    if not _rate_limit_ok():
        flash("Esperá un momento antes de intentar de nuevo.", "warning")
        return redirect(url_for("auth.login"))

    email_raw = (request.form.get("email") or "").strip()
    password = (request.form.get("password") or "").strip()
    nxt_safe = _next_url("")

    email = (
        User.normalize_email(email_raw)
        if hasattr(User, "normalize_email")
        else email_raw.lower()
    )

    if not email or "@" not in email:
        flash("Email o contraseña incorrectos.", "error")
        return redirect(url_for("auth.login", next=nxt_safe))

    user = db.session.query(User).filter(User.email == email).first()

    # Mensaje único → no filtra info
    if not user or not user.check_password(password):
        if user and hasattr(user, "failed_login_count"):
            user.failed_login_count += 1
            if user.failed_login_count >= MAX_LOGIN_ATTEMPTS:
                if hasattr(user, "locked_until"):
                    user.locked_until = time.time() + LOCK_TIME_SECONDS
            db.session.commit()
        flash("Email o contraseña incorrectos.", "error")
        return redirect(url_for("auth.login", next=nxt_safe))

    # Cuenta bloqueada
    if hasattr(user, "can_login") and not user.can_login():
        flash("Cuenta temporalmente bloqueada. Intentá más tarde.", "error")
        return redirect(url_for("auth.login"))

    # Activa
    if hasattr(user, "is_active") and not user.is_active:
        flash("Tu cuenta está desactivada.", "error")
        return redirect(url_for("auth.login"))

    # Login OK
    try:
        if hasattr(user, "mark_login"):
            user.mark_login()
        db.session.commit()
    except Exception:
        db.session.rollback()

    _set_session_user(user)
    flash("Bienvenido 👋", "success")

    return redirect(nxt_safe or _post_login_redirect(user))


# ============================================================
# Register
# ============================================================

@auth_bp.get("/register")
def register():
    u = _get_current_user()
    if u:
        return redirect(_post_login_redirect(u))

    return render_template(
        "auth/register.html",
        next=_next_url(url_for("shop.shop")),
    )


@auth_bp.post("/register")
def register_post():
    email_raw = (request.form.get("email") or "").strip()
    password = (request.form.get("password") or "").strip()
    name = (request.form.get("name") or "").strip()
    nxt_safe = _next_url("")

    email = (
        User.normalize_email(email_raw)
        if hasattr(User, "normalize_email")
        else email_raw.lower()
    )

    if not email or "@" not in email:
        flash("Email inválido.", "warning")
        return redirect(url_for("auth.register", next=nxt_safe))

    if len(password) < 6:
        flash("La contraseña debe tener al menos 6 caracteres.", "warning")
        return redirect(url_for("auth.register", next=nxt_safe))

    if db.session.query(User).filter(User.email == email).first():
        flash("Ese email ya está registrado.", "info")
        return redirect(url_for("auth.login", next=nxt_safe))

    user = User(email=email)

    if hasattr(user, "name") and name:
        user.name = name[:120]

    user.set_password(password)

    if hasattr(user, "subscribe_email"):
        try:
            user.subscribe_email()
        except Exception:
            pass

    if hasattr(user, "is_active"):
        user.is_active = True

    db.session.add(user)
    db.session.commit()

    _set_session_user(user)
    flash("Cuenta creada con éxito ✅", "success")

    return redirect(nxt_safe or _post_login_redirect(user))


# ============================================================
# Logout
# ============================================================

@auth_bp.get("/logout")
def logout():
    _clear_session()
    flash("Sesión cerrada.", "info")
    return redirect(url_for("main.home"))


__all__ = ["auth_bp"]
