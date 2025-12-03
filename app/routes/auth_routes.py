# app/routes/auth_routes.py

from flask import (
    Blueprint, render_template, request,
    redirect, url_for, flash, session
)
import re

# Blueprint de autenticación
auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


# -----------------------------
# Helper de validación de email
# -----------------------------
def validar_email(email: str) -> bool:
    """Valida el formato básico del email."""
    patron = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    return re.match(patron, email) is not None


# ============================
# LOGIN
# ============================
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    Inicio de sesión para Skyline Style.
    Versión PRO optimizada y segura.
    """
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        # Validación básica
        if not email or not password:
            flash("⚠️ Todos los campos son obligatorios.", "error")
            return redirect(url_for("auth.login"))

        if not validar_email(email):
            flash("⚠️ El email ingresado no es válido.", "error")
            return redirect(url_for("auth.login"))

        # Simulación de usuario (luego podés integrar tu DB)
        # En producción harías:
        # user = User.query.filter_by(email=email).first()
        # if not user or not check_password_hash(user.password, password):
        #    ...

        if email == "demo@skyline.com" and password == "1234":
            session["user"] = email
            flash("🎉 Bienvenido nuevamente!", "success")
            return redirect(url_for("main.home"))

        # Usuario incorrecto
        flash("❌ Datos incorrectos. Verifica usuario y contraseña.", "error")
        return redirect(url_for("auth.login"))

    # GET
    return render_template("auth/login.html")


# ============================
# REGISTER
# ============================
@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """
    Registro de nuevos usuarios para Skyline Style.
    Profesional, validado y seguro.
    """
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        # Validaciones
        if not email or not password:
            flash("⚠️ Completa todos los campos.", "error")
            return redirect(url_for("auth.register"))

        if not validar_email(email):
            flash("⚠️ El formato del email no es válido.", "error")
            return redirect(url_for("auth.register"))

        if len(password) < 4:
            flash("⚠️ La contraseña debe tener al menos 4 caracteres.", "error")
            return redirect(url_for("auth.register"))

        # Simulación (aquí guardarías el usuario real en DB)
        # Ejemplo:
        # nuevo_usuario = User(email=email, password=hash_password(password))
        # db.session.add(nuevo_usuario)
        # db.session.commit()

        flash("🎉 Cuenta creada con éxito. Ahora inicia sesión.", "success")
        return redirect(url_for("auth.login"))

    # GET
    return render_template("auth/register.html")


# ============================
# LOGOUT
# ============================
@auth_bp.route("/logout")
def logout():
    """
    Cierra sesión limpiamente.
    """
    session.pop("user", None)
    flash("👋 Sesión cerrada correctamente.", "success")
    return redirect(url_for("main.home"))
