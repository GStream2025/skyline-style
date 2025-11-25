# app/routes/auth_routes.py

from flask import Blueprint, render_template, request, redirect, url_for, flash

# Blueprint de autenticación
auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    Vista de inicio de sesión (demo).
    """
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not email or not password:
            flash("Todos los campos son obligatorios.", "error")
            return redirect(url_for("auth.login"))

        # TODO: validar usuario real en base de datos
        flash("Inicio de sesión exitoso (demo).", "success")
        return redirect(url_for("main.index"))

    return render_template("auth/login.html")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """
    Vista de registro de usuario (demo).
    """
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not email or not password:
            flash("Completa todos los campos.", "error")
            return redirect(url_for("auth.register"))

        # TODO: guardar usuario en base de datos
        flash("Cuenta creada (demo).", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")
