"""
======================================================
    SKYLINE STYLE — PANEL ADMIN PRO
    Gestión de productos, categorías e imágenes extra
    Autor: Gabriel + ChatGPT
======================================================
"""

from __future__ import annotations

import os
import time
from functools import wraps
from typing import Callable, Iterable, Set

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

from app import db
from app.models import User, Product, Category, ProductImage

# =============================================
# CONFIGURACIÓN DEL BLUEPRINT ADMIN
# =============================================
admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

ALLOWED_EXTENSIONS: Set[str] = {"png", "jpg", "jpeg", "webp"}


# =============================================
# FUNCIONES AUXILIARES
# =============================================
def allowed_file(filename: str) -> bool:
    """Valida formato de archivo permitido por extensión."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def admin_required(func: Callable) -> Callable:
    """
    Decorador que exige sesión de administrador.

    Usa la clave session["is_admin"], que se setea en el login
    cuando las credenciales son correctas (usuario admin).
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Debes iniciar sesión como administrador.", "warning")
            return redirect(url_for("admin.login"))
        return func(*args, **kwargs)

    return wrapper


# =============================================
# LOGIN / LOGOUT
# =============================================
@admin_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    Login de administradores.

    Se apoya en el modelo User de la BD:
        - username (ej: 'admin')
        - password hash (password real, ej: 'admin2026', se setea con set_password)
        - is_admin = True
    """
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        user: User | None = User.query.filter_by(username=username).first()

        if not user:
            flash("El usuario no existe.", "danger")
            return redirect(url_for("admin.login"))

        if not user.is_admin:
            flash("No tienes permisos de administrador.", "danger")
            return redirect(url_for("admin.login"))

        if not user.check_password(password):
            flash("Contraseña incorrecta.", "danger")
            return redirect(url_for("admin.login"))

        # LOGIN EXITOSO
        session.clear()
        session["user_id"] = user.id
        session["is_admin"] = True

        flash("Bienvenido al panel administrador.", "success")
        return redirect(url_for("admin.dashboard"))

    return render_template("admin/login.html")


@admin_bp.route("/logout")
@admin_required
def logout():
    """Cerrar sesión del admin."""
    session.clear()
    flash("Sesión cerrada correctamente.", "info")
    return redirect(url_for("admin.login"))


# =============================================
# DASHBOARD (Inicio del panel admin)
# =============================================
@admin_bp.route("/")
@admin_required
def dashboard():
    """Página principal del panel administrador (overview rápido)."""
    total_products = Product.query.count()
    total_categories = Category.query.count()
    total_images = ProductImage.query.count()

    return render_template(
        "admin/dashboard.html",
        total_products=total_products,
        total_categories=total_categories,
        total_images=total_images,
    )


# =============================================
# GESTIÓN DE PRODUCTOS
# =============================================
@admin_bp.route("/products")
@admin_required
def products_list():
    """Listar todos los productos con su categoría y fotos extra."""
    products: Iterable[Product] = Product.query.order_by(Product.id.desc()).all()
    categories: Iterable[Category] = Category.query.order_by(Category.name.asc()).all()

    return render_template(
        "admin/products_list.html",
        products=products,
        categories=categories,
    )


@admin_bp.route("/products/<int:product_id>/update", methods=["POST"])
@admin_required
def product_update(product_id: int):
    """Actualizar categoría del producto desde la tabla rápida."""
    product: Product = Product.query.get_or_404(product_id)

    category_id = request.form.get("category_id")
    product.category_id = int(category_id) if category_id else None

    db.session.commit()
    flash("Producto actualizado correctamente.", "success")
    return redirect(url_for("admin.products_list"))


# =============================================
# EDITAR PRODUCTO + SUBIR IMÁGENES
# =============================================
@admin_bp.route("/products/<int:product_id>/edit", methods=["GET", "POST"])
@admin_required
def product_edit(product_id: int):
    """
    Editor avanzado de producto:
        - Permite cambiar categoría
        - Permite subir múltiples imágenes extra
    """
    product: Product = Product.query.get_or_404(product_id)
    categories: Iterable[Category] = Category.query.order_by(Category.name.asc()).all()

    if request.method == "POST":
        # ACTUALIZAR CATEGORÍA
        category_id = request.form.get("category_id")
        product.category_id = int(category_id) if category_id else None

        # SUBIR IMÁGENES EXTRA
        files = request.files.getlist("extra_images") or []
        upload_folder = current_app.config.get("PRODUCT_UPLOAD_FOLDER")

        if not upload_folder:
            flash(
                "No está configurada la carpeta PRODUCT_UPLOAD_FOLDER en la app.",
                "danger",
            )
        else:
            os.makedirs(upload_folder, exist_ok=True)

            for f in files:
                if not f or not f.filename:
                    continue

                if not allowed_file(f.filename):
                    flash(f"Formato no permitido: {f.filename}", "danger")
                    continue

                filename = secure_filename(f.filename)
                unique_name = f"{product.id}_{int(time.time())}_{filename}"
                save_path = os.path.join(upload_folder, unique_name)

                f.save(save_path)
                db.session.add(
                    ProductImage(product_id=product.id, filename=unique_name)
                )

        db.session.commit()
        flash("Producto actualizado correctamente.", "success")
        return redirect(url_for("admin.product_edit", product_id=product.id))

    return render_template(
        "admin/product_edit.html",
        product=product,
        categories=categories,
    )


# =============================================
# ELIMINAR IMAGEN EXTRA
# =============================================
@admin_bp.route("/products/images/<int:image_id>/delete", methods=["POST"])
@admin_required
def delete_image(image_id: int):
    """Eliminar una imagen extra de un producto (archivo + registro)."""
    img: ProductImage = ProductImage.query.get_or_404(image_id)
    upload_folder = current_app.config.get("PRODUCT_UPLOAD_FOLDER", "")
    filepath = os.path.join(upload_folder, img.filename)

    if upload_folder and os.path.exists(filepath):
        try:
            os.remove(filepath)
        except OSError:
            # Si falla el borrado físico, igual eliminamos el registro
            flash("No se pudo eliminar el archivo físico, solo el registro.", "warning")

    db.session.delete(img)
    db.session.commit()

    flash("Imagen eliminada correctamente.", "info")
    return redirect(request.referrer or url_for("admin.products_list"))


# =============================================
# GESTIÓN DE CATEGORÍAS
# =============================================
@admin_bp.route("/categories", methods=["GET", "POST"])
@admin_required
def categories():
    """Crear y listar categorías de productos."""
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()

        if not name:
            flash("El nombre de la categoría no puede estar vacío.", "warning")
        elif Category.query.filter_by(name=name).first():
            flash("La categoría ya existe.", "warning")
        else:
            db.session.add(Category(name=name))
            db.session.commit()
            flash("Categoría creada correctamente.", "success")

    all_categories: Iterable[Category] = Category.query.order_by(Category.name.asc()).all()
    return render_template("admin/categories.html", categories=all_categories)


@admin_bp.route("/categories/<int:cat_id>/delete", methods=["POST"])
@admin_required
def delete_category(cat_id: int):
    """Eliminar una categoría (solo si no tiene productos asociados)."""
    category: Category = Category.query.get_or_404(cat_id)

    if category.products:
        flash("No puedes eliminar una categoría con productos asignados.", "danger")
        return redirect(url_for("admin.categories"))

    db.session.delete(category)
    db.session.commit()

    flash("Categoría eliminada.", "info")
    return redirect(url_for("admin.categories"))
