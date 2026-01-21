# app/routes/auth_routes.py — BULLETPROOF FINAL
from __future__ import annotations

import logging
import re
import secrets
import time
from typing import Any, Dict, Optional, Set
from urllib.parse import urlencode, urlparse

from flask import (
    Blueprint,
    flash,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy import func, select

from app.models import User, db

# Opcionales (NO rompen si faltan)
try:
    from flask_login import login_user, logout_user
except Exception:
    login_user = None
    logout_user = None

try:
    from app.models import AffiliateProfile
except Exception:
    AffiliateProfile = None

log = logging.getLogger("auth_routes")

auth_bp = Blueprint(
    "auth",
    __name__,
    url_prefix="/auth",
    template_folder="../templates",
)

_TRUE: Set[str] = {"1", "true", "yes", "y", "on", "checked"}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# ------------------------------------------------------------------
# HELPERS CRÍTICOS
# ------------------------------------------------------------------
def _safe_email(v: str) -> str:
    return (v or "").strip().lower()


def _valid_email(v: str) -> bool:
    return bool(v and EMAIL_RE.match(v))


def _safe_next(nxt: str) -> str:
    if not nxt or not nxt.startswith("/") or nxt.startswith("//"):
        return ""
    p = urlparse(nxt)
    return nxt if not p.scheme and not p.netloc else ""


def _clear_auth_session():
    """Limpia SOLO auth (no toca csrf interna)"""
    for k in list(session.keys()):
        if k.startswith("rl:") or k in {
            "user_id",
            "user_email",
            "is_admin",
            "login_at",
            "login_nonce",
        }:
            session.pop(k, None)
    session.modified = True


def _set_user_session(user: User):
    """Login fuerte y estable"""
    session.clear()  # FIX #1: elimina sesión sucia
    session["user_id"] = int(user.id)
    session["user_email"] = user.email.lower()
    session["is_admin"] = bool(getattr(user, "is_admin", False))
    session["login_at"] = int(time.time())
    session["login_nonce"] = secrets.token_urlsafe(16)
    session.permanent = True

    if login_user:
        try:
            login_user(user, remember=False)
        except Exception:
            log.exception("login_user failed (ignored)")


def _get_user_by_email(email: str) -> Optional[User]:
    try:
        return db.session.execute(
            select(User).where(func.lower(User.email) == email)
        ).scalar_one_or_none()
    except Exception:
        return None


def _json_or_redirect(msg, cat, *, tab, nxt, redirect_to=None):
    if request.is_json:
        return jsonify({"ok": cat != "error", "message": msg}), (200 if cat != "error" else 400)

    if cat != "success":
        flash(msg, cat)

    if redirect_to:
        return redirect(redirect_to)

    qs = urlencode({"tab": tab, "next": nxt})
    return redirect(f"/auth/account?{qs}")


# ------------------------------------------------------------------
# UI
# ------------------------------------------------------------------
@auth_bp.get("/account")
def account():
    if session.get("user_id"):
        return redirect(_safe_next(request.args.get("next")) or "/")

    return make_response(
        render_template(
            "auth/account.html",
            active_tab=request.args.get("tab", "login"),
            next=_safe_next(request.args.get("next")),
        ),
        200,
        {
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        },
    )


# ------------------------------------------------------------------
# LOGIN
# ------------------------------------------------------------------
@auth_bp.post("/login")
def login():
    email = _safe_email(request.form.get("email", ""))
    password = request.form.get("password", "")

    if not _valid_email(email) or not password:
        return _json_or_redirect("Email o contraseña incorrectos.", "error", tab="login", nxt="")

    user = _get_user_by_email(email)
    if not user or not user.check_password(password):
        return _json_or_redirect("Email o contraseña incorrectos.", "error", tab="login", nxt="")

    if hasattr(user, "is_active") and not user.is_active:
        return _json_or_redirect("Cuenta desactivada.", "error", tab="login", nxt="")

    _set_user_session(user)

    return _json_or_redirect(
        "Bienvenido 👋",
        "success",
        tab="login",
        nxt="",
        redirect_to=_safe_next(request.form.get("next")) or "/",
    )


# ------------------------------------------------------------------
# REGISTER
# ------------------------------------------------------------------
@auth_bp.post("/register")
def register():
    email = _safe_email(request.form.get("email", ""))
    password = request.form.get("password", "")
    password2 = request.form.get("password2", "")
    name = (request.form.get("name") or "").strip()

    if not _valid_email(email):
        return _json_or_redirect("Email inválido.", "error", tab="register", nxt="")

    if password != password2 or len(password) < 8:
        return _json_or_redirect("Contraseña inválida.", "error", tab="register", nxt="")

    if _get_user_by_email(email):
        return _json_or_redirect("Ese email ya existe.", "error", tab="login", nxt="")

    user = User(email=email)
    user.set_password(password)
    user.is_active = True
    user.email_verified = False
    if hasattr(user, "name"):
        user.name = name[:120]

    db.session.add(user)
    db.session.commit()  # FIX #2: commit REAL del user

    # Affiliate opcional (NO rompe nunca)
    if AffiliateProfile and request.form.get("want_affiliate") in _TRUE:
        try:
            db.session.add(AffiliateProfile(user_id=user.id, status="pending"))
            db.session.commit()
        except Exception:
            db.session.rollback()
            log.warning("AffiliateProfile failed (ignored)")

    _set_user_session(user)

    return _json_or_redirect(
        "Cuenta creada con éxito ✅",
        "success",
        tab="register",
        nxt="",
        redirect_to=_safe_next(request.form.get("next")) or "/",
    )


# ------------------------------------------------------------------
# LOGOUT
# ------------------------------------------------------------------
@auth_bp.route("/logout", methods=["GET", "POST"])
def logout():
    _clear_auth_session()
    if logout_user:
        try:
            logout_user()
        except Exception:
            pass

    flash("Sesión cerrada.", "info")
    return redirect("/")


__all__ = ["auth_bp"]
