# app/routes/auth_routes.py
from __future__ import annotations

import time
from urllib.parse import urlparse
from typing import Optional

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from werkzeug.routing import BuildError

from app.models import db, User

auth_bp = Blueprint("auth", __name__)

# ----------------------------
# Seguridad
# ----------------------------
MAX_LOGIN_ATTEMPTS = 5
LOCK_TIME_SECONDS = 300
RATE_LIMIT_SECONDS = 2


# ============================================================
# Helpers
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


def _safe_email(email_raw: str) -> str:
    """Normaliza email sin romper si el modelo no tiene helper."""
    email_raw = (email_raw or "").strip()
    if not email_raw:
        return ""
    email = email_raw.lower()
    if hasattr(User, "normalize_email"):
        try:
            email = User.normalize_email(email_raw)  # type: ignore[attr-defined]
        except Exception:
            pass
    return (email or "").strip().lower()


def _rate_limit_ok() -> bool:
    now = time.time()
    last = session.get("last_login_try", 0)
    try:
        last = float(last)
    except Exception:
        last = 0.0

    if (now - last) < RATE_LIMIT_SECONDS:
        return False

    session["last_login_try"] = now
    return True


def _get_current_user() -> Optional[User]:
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        uid_int = int(uid)
    except Exception:
        _clear_session()
        return None

    u = db.session.get(User, uid_int)
    if not u:
        _clear_session()
        return None
    return u


def _set_session_user(user: User) -> None:
    """Session mínima y consistente."""
    session.clear()
    session["user_id"] = int(user.id)
    session["user_email"] = (getattr(user, "email", "") or "").lower()
    session["is_admin"] = bool(getattr(user, "is_admin", False))
    session["login_at"] = int(time.time())
    session.permanent = True


def _post_login_redirect(user: User) -> str:
    """Destino post-login con fallback (no rompe si falta un endpoint)."""
    try:
        if bool(getattr(user, "is_admin", False)):
            return url_for("admin.dashboard")
        return url_for("account.account_home")
    except BuildError:
        # fallback duro
        try:
            return url_for("shop.shop")
        except BuildError:
            return "/"


def _commit_safe() -> bool:
    try:
        db.session.commit()
        return True
    except Exception:
        db.session.rollback()
        return False


# ============================================================
# Login
# ============================================================

@auth_bp.get("/login")
def login():
    u = _get_current_user()
    if u:
        return redirect(_post_login_redirect(u))

    return render_template("auth/login.html", next=_next_url(url_for("shop.shop")))


@auth_bp.post("/login")
def login_post():
    if not _rate_limit_ok():
        flash("Esperá un momento antes de intentar de nuevo.", "warning")
        return redirect(url_for("auth.login"))

    email = _safe_email(request.form.get("email") or "")
    password = (request.form.get("password") or "").strip()
    nxt_safe = _next_url("")

    if not email or "@" not in email or not password:
        flash("Email o contraseña incorrectos.", "error")
        return redirect(url_for("auth.login", next=nxt_safe))

    user = db.session.query(User).filter(User.email == email).first()

    # Si existe lock, lo respetamos ANTES de chequear password (mejor anti brute-force)
    if user and hasattr(user, "locked_until"):
        try:
            locked_until = float(getattr(user, "locked_until") or 0)
        except Exception:
            locked_until = 0
        if locked_until and locked_until > time.time():
            flash("Cuenta temporalmente bloqueada. Intentá más tarde.", "error")
            return redirect(url_for("auth.login"))

    # Mensaje único -> no filtra info
    if not user or not user.check_password(password):
        # incrementa contador si existe
        if user and hasattr(user, "failed_login_count"):
            try:
                user.failed_login_count = int(getattr(user, "failed_login_count") or 0) + 1
            except Exception:
                user.failed_login_count = 1

            if user.failed_login_count >= MAX_LOGIN_ATTEMPTS and hasattr(user, "locked_until"):
                try:
                    user.locked_until = time.time() + LOCK_TIME_SECONDS
                except Exception:
                    pass

            _commit_safe()

        flash("Email o contraseña incorrectos.", "error")
        return redirect(url_for("auth.login", next=nxt_safe))

    # Si el modelo trae can_login, lo respetamos
    if hasattr(user, "can_login"):
        try:
            if not user.can_login():
                flash("Cuenta temporalmente bloqueada. Intentá más tarde.", "error")
                return redirect(url_for("auth.login"))
        except Exception:
            pass

    # Activa
    if hasattr(user, "is_active"):
        try:
            if not bool(getattr(user, "is_active")):
                flash("Tu cuenta está desactivada.", "error")
                return redirect(url_for("auth.login"))
        except Exception:
            pass

    # Login OK: resetea contador si existe + marca login
    if hasattr(user, "failed_login_count"):
        try:
            user.failed_login_count = 0
        except Exception:
            pass
    if hasattr(user, "locked_until"):
        try:
            user.locked_until = 0
        except Exception:
            pass
    if hasattr(user, "mark_login"):
        try:
            user.mark_login()
        except Exception:
            pass

    _commit_safe()

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

    return render_template("auth/register.html", next=_next_url(url_for("shop.shop")))


@auth_bp.post("/register")
def register_post():
    email = _safe_email(request.form.get("email") or "")
    password = (request.form.get("password") or "").strip()
    name = (request.form.get("name") or "").strip()
    nxt_safe = _next_url("")

    if not email or "@" not in email:
        flash("Email inválido.", "warning")
        return redirect(url_for("auth.register", next=nxt_safe))

    if len(password) < 6:
        flash("La contraseña debe tener al menos 6 caracteres.", "warning")
        return redirect(url_for("auth.register", next=nxt_safe))

    # nombre opcional, pero limpio
    if name:
        name = name[:120]

    # ya existe
    if db.session.query(User).filter(User.email == email).first():
        flash("Ese email ya está registrado.", "info")
        return redirect(url_for("auth.login", next=nxt_safe))

    # crear
    user = User(email=email)
    if hasattr(user, "name") and name:
        try:
            user.name = name
        except Exception:
            pass

    # password
    user.set_password(password)

    # flags opcionales
    if hasattr(user, "is_active"):
        try:
            user.is_active = True
        except Exception:
            pass
    if hasattr(user, "failed_login_count"):
        try:
            user.failed_login_count = 0
        except Exception:
            pass
    if hasattr(user, "locked_until"):
        try:
            user.locked_until = 0
        except Exception:
            pass

    # suscripción email si existe
    if hasattr(user, "subscribe_email"):
        try:
            user.subscribe_email()
        except Exception:
            pass

    # persistir con rollback seguro
    try:
        db.session.add(user)
        db.session.commit()
    except Exception:
        db.session.rollback()
        flash("Error creando la cuenta. Probá de nuevo.", "error")
        return redirect(url_for("auth.register", next=nxt_safe))

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
    try:
        return redirect(url_for("main.home"))
    except BuildError:
        return redirect("/")


__all__ = ["auth_bp"]
