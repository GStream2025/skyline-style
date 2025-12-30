from __future__ import annotations

from urllib.parse import urlparse
from typing import Optional

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from app import db
from app.models.user import User

# ✅ Importante: sin url_prefix para que sea /login /register /logout
auth_bp = Blueprint("auth", __name__)


# ============================
# Helpers
# ============================

def _is_safe_next(nxt: str) -> bool:
    """Permite solo paths internos tipo '/algo' y bloquea esquemas/host externos."""
    if not nxt:
        return False
    if not nxt.startswith("/"):
        return False
    p = urlparse(nxt)
    return (p.scheme == "" and p.netloc == "")

def _next_url(default: str) -> str:
    nxt = (request.args.get("next") or request.form.get("next") or "").strip()
    return nxt if _is_safe_next(nxt) else default

def _set_session_user(user: User) -> None:
    session["user_id"] = int(user.id)
    session["user_email"] = (user.email or "").lower()
    # ✅ clave para /account y control de permisos
    session["is_admin"] = bool(getattr(user, "is_admin", False))

def _clear_session() -> None:
    for k in ("user_id", "user_email", "is_admin"):
        session.pop(k, None)

def _post_login_redirect(user: User) -> str:
    """Admin -> /admin/ ; user normal -> /account (o profile)"""
    if bool(getattr(user, "is_admin", False)):
        return url_for("admin.dashboard")
    # si tenés profile route en auth, podés cambiar a url_for("auth.profile")
    return url_for("account.account") if "account.account" in request.app_ctx_globals.get("current_app").view_functions else url_for("shop.shop")


# ============================
# Routes
# ============================

@auth_bp.get("/login")
def login():
    # ya logueado
    if session.get("user_id"):
        # si es admin => panel
        if session.get("is_admin"):
            return redirect(url_for("admin.dashboard"))
        # usuario normal => account
        try:
            return redirect(url_for("account.account"))
        except Exception:
            return redirect(url_for("shop.shop"))

    return render_template(
        "auth/login.html",
        next=_next_url(url_for("shop.shop")),
    )

@auth_bp.post("/login")
def login_post():
    email = (request.form.get("email") or "").strip().lower()
    password = (request.form.get("password") or "").strip()

    if not email or "@" not in email:
        flash("Ingresá un correo válido.", "warning")
        return redirect(url_for("auth.login", next=_next_url(url_for("shop.shop"))))

    if not password:
        flash("Ingresá tu contraseña.", "warning")
        return redirect(url_for("auth.login", next=_next_url(url_for("shop.shop"))))

    user = db.session.query(User).filter(User.email == email).first()

    if (not user) or (not user.password_hash) or (not check_password_hash(user.password_hash, password)):
        flash("Email o contraseña incorrectos.", "error")
        return redirect(url_for("auth.login", next=_next_url(url_for("shop.shop"))))

    if hasattr(user, "is_active") and user.is_active is False:
        flash("Tu cuenta está desactivada. Contactá soporte.", "error")
        return redirect(url_for("auth.login", next=_next_url(url_for("shop.shop"))))

    _set_session_user(user)

    # ✅ prioridad: next seguro > admin panel > account
    nxt = _next_url("")
    if nxt:
        flash("Bienvenido 👋", "success")
        return redirect(nxt)

    flash("Bienvenido 👋", "success")
    return redirect(_post_login_redirect(user))

@auth_bp.get("/register")
def register():
    if session.get("user_id"):
        # si ya está logueado, mandalo a account/panel
        if session.get("is_admin"):
            return redirect(url_for("admin.dashboard"))
        try:
            return redirect(url_for("account.account"))
        except Exception:
            return redirect(url_for("shop.shop"))

    return render_template(
        "auth/register.html",
        next=_next_url(url_for("shop.shop")),
    )

@auth_bp.post("/register")
def register_post():
    email = (request.form.get("email") or "").strip().lower()
    password = (request.form.get("password") or "").strip()

    # Validaciones PRO
    if not email or "@" not in email or "." not in email.split("@")[-1]:
        flash("Ingresá un email válido.", "warning")
        return redirect(url_for("auth.register", next=_next_url(url_for("shop.shop"))))

    if len(password) < 6:
        flash("La contraseña debe tener al menos 6 caracteres.", "warning")
        return redirect(url_for("auth.register", next=_next_url(url_for("shop.shop"))))

    exists = db.session.query(User).filter(User.email == email).first()
    if exists:
        flash("Ese email ya está registrado. Iniciá sesión.", "info")
        return redirect(url_for("auth.login", next=_next_url(url_for("shop.shop"))))

    u = User(
        email=email,
        password_hash=generate_password_hash(password),
    )

    # marketing opt-in si existe en tu modelo
    if hasattr(u, "marketing_opt_in"):
        u.marketing_opt_in = True

    db.session.add(u)
    db.session.commit()

    _set_session_user(u)

    # ✅ prioridad: next seguro > account (user normal)
    nxt = _next_url("")
    if nxt:
        flash("Cuenta creada ✅", "success")
        return redirect(nxt)

    flash("Cuenta creada ✅", "success")
    return redirect(_post_login_redirect(u))

@auth_bp.get("/logout")
def logout():
    _clear_session()
    flash("Sesión cerrada.", "info")
    return redirect(url_for("main.home"))
