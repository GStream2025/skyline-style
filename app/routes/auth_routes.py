# app/routes/auth_routes.py

from __future__ import annotations

import re
import time
from typing import Optional
from urllib.parse import urlparse, urljoin

from flask import (
    Blueprint, render_template, request,
    redirect, url_for, flash, session, current_app
)

# Hash seguro (incluido en Flask/Werkzeug)
from werkzeug.security import generate_password_hash, check_password_hash


# ==========================================================
# Blueprint de autenticación
# ==========================================================
auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


# ==========================================================
# Config / Helpers
# ==========================================================

# Email (más estricto que el tuyo, pero sin volverse imposible)
EMAIL_RE = re.compile(
    r"^(?=.{3,254}$)[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
)

def validar_email(email: str) -> bool:
    """Valida email de forma razonable (no perfecta RFC, pero segura y práctica)."""
    if not email:
        return False
    email = email.strip()
    return EMAIL_RE.match(email) is not None


def is_safe_url(target: str) -> bool:
    """
    Evita Open Redirect:
    permite solo redirecciones dentro del mismo host.
    """
    if not target:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


def redirect_to_main_home() -> "flask.wrappers.Response":
    """
    Redirige al home principal sin romper si el endpoint cambia.
    Intenta main.home, luego main.index, y como último recurso "/".
    """
    for endpoint in ("main.home", "main.index"):
        try:
            return redirect(url_for(endpoint))
        except Exception:
            continue
    return redirect("/")


def get_next_url(default_endpoint: Optional[str] = None) -> str:
    """
    Obtiene 'next' desde querystring o form, y lo valida para evitar open redirect.
    """
    nxt = request.args.get("next") or request.form.get("next") or ""
    if nxt and is_safe_url(nxt):
        return nxt

    if default_endpoint:
        try:
            return url_for(default_endpoint)
        except Exception:
            pass
    return "/"


# ==========================================================
# Rate-limit simple (anti brute force) en sesión
# ==========================================================
# Esto es básico pero útil. Para PRO real, usar Redis o Flask-Limiter.

def _rate_key(action: str) -> str:
    return f"rl_{action}"

def rate_limited(action: str, limit: int = 6, window_sec: int = 60) -> bool:
    """
    Permite `limit` intentos por `window_sec` segundos por sesión.
    """
    key = _rate_key(action)
    now = time.time()
    bucket = session.get(key, {"t0": now, "count": 0})

    # reset ventana
    if now - float(bucket.get("t0", now)) > window_sec:
        bucket = {"t0": now, "count": 0}

    bucket["count"] = int(bucket.get("count", 0)) + 1
    session[key] = bucket

    return bucket["count"] > limit


# ==========================================================
# "DB" demo en memoria (solo para pruebas)
# ==========================================================
# En producción: reemplazalo por tu DB real.
# Guardamos en session "users_demo" para que persista por navegador.
def _demo_users() -> dict:
    users = session.get("users_demo")
    if not isinstance(users, dict):
        users = {}
        session["users_demo"] = users
    return users


def _get_demo_user(email: str) -> Optional[dict]:
    users = _demo_users()
    return users.get(email.lower())


def _create_demo_user(email: str, password: str) -> None:
    users = _demo_users()
    users[email.lower()] = {
        "email": email.lower(),
        "password_hash": generate_password_hash(password),
        "created_at": int(time.time()),
    }
    session["users_demo"] = users


# ==========================================================
# LOGIN
# ==========================================================
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    Login PRO:
    - validación robusta
    - rate limit básico
    - 'next' seguro
    - session user
    """
    if request.method == "POST":
        if rate_limited("login", limit=8, window_sec=60):
            flash("⏳ Demasiados intentos. Esperá un minuto y probá de nuevo.", "error")
            return redirect(url_for("auth.login"))

        email = (request.form.get("email") or "").strip().lower()
        password = (request.form.get("password") or "").strip()

        # Validación
        if not email or not password:
            flash("⚠️ Completá email y contraseña.", "error")
            return redirect(url_for("auth.login"))

        if not validar_email(email):
            flash("⚠️ El email ingresado no es válido.", "error")
            return redirect(url_for("auth.login"))

        # -------- DEMO AUTH --------
        # Usuario hardcode demo (mantengo el tuyo)
        if email == "demo@skyline.com" and password == "1234":
            session["user"] = email
            flash("🎉 Bienvenido nuevamente!", "success")
            return redirect(get_next_url(default_endpoint="main.home"))

        # Usuario demo creado por register (en sesión)
        user = _get_demo_user(email)
        if user and check_password_hash(user.get("password_hash", ""), password):
            session["user"] = email
            flash("✅ Sesión iniciada correctamente.", "success")
            return redirect(get_next_url(default_endpoint="main.home"))

        flash("❌ Datos incorrectos. Verificá usuario y contraseña.", "error")
        return redirect(url_for("auth.login"))

    # GET
    return render_template("auth/login.html", next=get_next_url(default_endpoint="main.home"))


# ==========================================================
# REGISTER
# ==========================================================
@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """
    Registro PRO:
    - valida email
    - valida password
    - evita duplicados (demo)
    - guarda hash
    """
    if request.method == "POST":
        if rate_limited("register", limit=6, window_sec=60):
            flash("⏳ Demasiados intentos. Probá nuevamente en 1 minuto.", "error")
            return redirect(url_for("auth.register"))

        email = (request.form.get("email") or "").strip().lower()
        password = (request.form.get("password") or "").strip()
        password2 = (request.form.get("password2") or "").strip()

        # Validaciones
        if not email or not password:
            flash("⚠️ Completá todos los campos.", "error")
            return redirect(url_for("auth.register"))

        if not validar_email(email):
            flash("⚠️ El formato del email no es válido.", "error")
            return redirect(url_for("auth.register"))

        # Password policy (simple pero mejor)
        if len(password) < 6:
            flash("⚠️ La contraseña debe tener al menos 6 caracteres.", "error")
            return redirect(url_for("auth.register"))

        # Confirmación si el form la incluye (recomendado)
        if password2 and password2 != password:
            flash("⚠️ Las contraseñas no coinciden.", "error")
            return redirect(url_for("auth.register"))

        # Evitar duplicado (demo)
        if _get_demo_user(email) is not None or email == "demo@skyline.com":
            flash("⚠️ Ese email ya está registrado. Iniciá sesión.", "error")
            return redirect(url_for("auth.login"))

        # Crear usuario demo
        _create_demo_user(email, password)

        flash("🎉 Cuenta creada con éxito. Ahora iniciá sesión.", "success")
        return redirect(url_for("auth.login"))

    # GET
    return render_template("auth/register.html")


# ==========================================================
# LOGOUT
# ==========================================================
@auth_bp.route("/logout")
def logout():
    """Cierra sesión limpiamente."""
    session.pop("user", None)
    flash("👋 Sesión cerrada correctamente.", "success")
    return redirect_to_main_home()


# ==========================================================
# (Opcional) Guard para rutas protegidas
# ==========================================================
def require_login() -> bool:
    """
    Helper opcional: úsalo en otras rutas.
    Retorna True si hay usuario logueado.
    """
    return bool(session.get("user"))
