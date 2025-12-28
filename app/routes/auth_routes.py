from __future__ import annotations

from typing import Optional

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from app import db
from app.models.user import User

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

def _next_url(default: str) -> str:
    nxt = (request.args.get("next") or request.form.get("next") or "").strip()
    if nxt and nxt.startswith("/"):
        return nxt
    return default

@auth_bp.get("/login")
def login():
    if session.get("user_id"):
        return redirect(url_for("shop.shop"))
    return render_template("auth/login.html", next=_next_url(url_for("shop.shop")))

@auth_bp.post("/login")
def login_post():
    email = (request.form.get("email") or "").strip().lower()
    password = (request.form.get("password") or "").strip()
    user = db.session.query(User).filter(User.email == email).first()
    if not user or not user.password_hash or not check_password_hash(user.password_hash, password):
        flash("Email o contraseña incorrectos.", "error")
        return redirect(url_for("auth.login", next=_next_url(url_for("shop.shop"))))

    session["user_id"] = user.id
    session["user_email"] = user.email
    flash("Bienvenido 👋", "success")
    return redirect(_next_url(url_for("shop.shop")))

@auth_bp.get("/register")
def register():
    return render_template("auth/register.html", next=_next_url(url_for("shop.shop")))

@auth_bp.post("/register")
def register_post():
    email = (request.form.get("email") or "").strip().lower()
    password = (request.form.get("password") or "").strip()

    if not email or "@" not in email:
        flash("Ingresá un email válido.", "warning")
        return redirect(url_for("auth.register"))

    if len(password) < 6:
        flash("La contraseña debe tener al menos 6 caracteres.", "warning")
        return redirect(url_for("auth.register"))

    exists = db.session.query(User).filter(User.email == email).first()
    if exists:
        flash("Ese email ya está registrado. Iniciá sesión.", "info")
        return redirect(url_for("auth.login"))

    u = User(email=email, password_hash=generate_password_hash(password), marketing_opt_in=True)
    db.session.add(u)
    db.session.commit()

    session["user_id"] = u.id
    session["user_email"] = u.email
    flash("Cuenta creada ✅", "success")
    return redirect(_next_url(url_for("shop.shop")))

@auth_bp.get("/logout")
def logout():
    session.pop("user_id", None)
    session.pop("user_email", None)
    flash("Sesión cerrada.", "info")
    return redirect(url_for("main.home"))
