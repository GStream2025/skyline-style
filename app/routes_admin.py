import os
import json
from pathlib import Path
from typing import Dict, Any

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    current_app,
    session,
)

from werkzeug.utils import secure_filename

admin_bp = Blueprint("admin_bp", __name__, url_prefix="/admin")

# ==============================
# CONFIG / CONSTANTES
# ==============================

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif"}
DEFAULT_CATEGORIES = [
    "Buzos & Hoodies",
    "Remeras",
    "Gorras",
    "Accesorios",
    "Edición limitada",
]

# Tamaño máximo (opcional) 8 MB
MAX_CONTENT_LENGTH = 8 * 1024 * 1024


# ==============================
# HELPERS DE METADATA (JSON)
# ==============================

def _meta_path() -> Path:
    """
    Devuelve la ruta absoluta al archivo meta.json,
    donde guardamos categorías y fotos extra por producto.
    """
    base = Path(current_app.root_path)
    return base / "static" / "uploads" / "products" / "meta.json"


def _ensure_meta_dir():
    """
    Crea la carpeta static/uploads/products si no existe.
    """
    meta = _meta_path()
    meta.parent.mkdir(parents=True, exist_ok=True)


def load_meta() -> Dict[str, Any]:
    """
    Estructura JSON base:

    {
      "categories": [...],
      "products": {
         "406401541": {
             "name": "Hoodie Galaxy Skyline",
             "sku": "SKY-HOODIE-01",
             "main_image": "https://...",
             "price": "39.99",
             "category": "Buzos & Hoodies",
             "visible": true,
             "featured": true,
             "extra_images": [
                 "uploads/products/406401541/extra_1.jpg",
                 ...
             ]
         },
         ...
      }
    }
    """
    _ensure_meta_dir()
    meta_file = _meta_path()

    if not meta_file.exists():
        # Estructura inicial
        data = {"categories": DEFAULT_CATEGORIES, "products": {}}
        meta_file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return data

    try:
        raw = meta_file.read_text(encoding="utf-8")
        data = json.loads(raw)
    except Exception:
        data = {"categories": DEFAULT_CATEGORIES, "products": {}}

    # Normalizamos para evitar errores
    if "categories" not in data or not isinstance(data["categories"], list):
        data["categories"] = DEFAULT_CATEGORIES
    if "products" not in data or not isinstance(data["products"], dict):
        data["products"] = {}

    return data


def save_meta(data: Dict[str, Any]) -> None:
    """
    Guarda el JSON de metadata formateado.
    """
    _ensure_meta_dir()
    meta_file = _meta_path()
    meta_file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def product_upload_dir(product_id: str) -> Path:
    """
    Carpeta donde se guardan las fotos extra de un producto:
    static/uploads/products/<product_id>/
    """
    base = Path(current_app.root_path)
    folder = base / "static" / "uploads" / "products" / str(product_id)
    folder.mkdir(parents=True, exist_ok=True)
    return folder


# ==============================
# SISTEMA MUY SIMPLE DE ADMIN LOGIN
# ==============================

def is_admin_logged() -> bool:
    return session.get("is_admin") is True


def require_admin():
    """
    Helper para usar dentro de cada ruta que requiera admin.
    """
    if not is_admin_logged():
        return redirect(url_for("admin_bp.login"))
    return None


@admin_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    Login súper simple:
    - Usuario y password en variables de entorno o config:

      ADMIN_USERNAME, ADMIN_PASSWORD

    Si no están definidas, se usan por defecto:
      admin / skyline2025
    """
    default_user = "admin"
    default_pass = "skyline2025"

    cfg_user = current_app.config.get("ADMIN_USERNAME") or os.getenv("ADMIN_USERNAME") or default_user
    cfg_pass = current_app.config.get("ADMIN_PASSWORD") or os.getenv("ADMIN_PASSWORD") or default_pass

    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if username == cfg_user and password == cfg_pass:
            session["is_admin"] = True
            flash("Bienvenido al panel admin ✨", "success")
            return redirect(url_for("admin_bp.products"))
        else:
            error = "Usuario o contraseña incorrectos."

    return render_template("admin/login.html", error=error)


@admin_bp.route("/logout")
def logout():
    session.pop("is_admin", None)
    flash("Sesión cerrada correctamente.", "info")
    return redirect(url_for("admin_bp.login"))


# ==============================
# LISTADO / BUSCADOR DE PRODUCTOS
# ==============================

@admin_bp.route("/productos", methods=["GET"])
def products():
    # Requiere sesión de admin
    r = require_admin()
    if r is not None:
        return r

    meta = load_meta()
    products = meta.get("products", {})
    categories = meta.get("categories", DEFAULT_CATEGORIES)

    # --- Filtros y búsqueda ---
    q = request.args.get("q", "").strip().lower()
    filter_cat = request.args.get("category", "").strip()

    filtered_products = []

    for pid, pdata in products.items():
        name = str(pdata.get("name", "")).lower()
        cat = str(pdata.get("category", "")).strip()

        if q and q not in name and q not in pid.lower():
            continue
        if filter_cat and filter_cat != "ALL" and cat != filter_cat:
            continue

        # Contar fotos extra
        extra_imgs = pdata.get("extra_images", [])
        pdata["_extra_count"] = len(extra_imgs)
        pdata["_id"] = pid
        filtered_products.append(pdata)

    # Orden: destacados primero, luego visibles, luego nombre
    filtered_products.sort(
        key=lambda p: (
            not bool(p.get("featured", False)),
            not bool(p.get("visible", True)),
            p.get("name", "").lower()
        )
    )

    # Stats para UX
    total = len(products)
    total_visible = sum(1 for p in products.values() if p.get("visible", True))
    total_featured = sum(1 for p in products.values() if p.get("featured", False))
    total_without_cat = sum(1 for p in products.values() if not p.get("category"))

    return render_template(
        "admin/products_list.html",
        products=filtered_products,
        categories=categories,
        q=q,
        filter_cat=filter_cat,
        stats={
            "total": total,
            "visible": total_visible,
            "featured": total_featured,
            "without_cat": total_without_cat,
        },
    )


# ==============================
# CREAR NUEVO PRODUCTO MANUALMENTE
# ==============================

@admin_bp.route("/productos/nuevo", methods=["GET", "POST"])
def product_new():
    r = require_admin()
    if r is not None:
        return r

    meta = load_meta()
    categories = meta.get("categories", DEFAULT_CATEGORIES)

    if request.method == "POST":
        product_id = request.form.get("product_id", "").strip()
        name = request.form.get("name", "").strip()
        sku = request.form.get("sku", "").strip()
        price = request.form.get("price", "").strip()
        main_image = request.form.get("main_image", "").strip()
        category = request.form.get("category", "").strip()
        visible = bool(request.form.get("visible"))
        featured = bool(request.form.get("featured"))

        if not product_id or not name:
            flash("ID de producto y nombre son obligatorios.", "error")
            return redirect(request.url)

        if "products" not in meta:
            meta["products"] = {}

        if product_id in meta["products"]:
            flash("Ya existe un producto con ese ID.", "error")
            return redirect(request.url)

        meta["products"][product_id] = {
            "name": name,
            "sku": sku,
            "price": price,
            "main_image": main_image,
            "category": category,
            "visible": visible,
            "featured": featured,
            "extra_images": [],
        }

        save_meta(meta)
        flash("Producto creado correctamente ✅", "success")
        return redirect(url_for("admin_bp.products"))

    return render_template(
        "admin/product_edit.html",
        product=None,
        product_id=None,
        categories=categories,
        is_new=True,
    )


# ==============================
# EDITAR PRODUCTO + SUBIR FOTOS EXTRA
# ==============================

@admin_bp.route("/productos/<product_id>/editar", methods=["GET", "POST"])
def product_edit(product_id):
    r = require_admin()
    if r is not None:
        return r

    meta = load_meta()
    categories = meta.get("categories", DEFAULT_CATEGORIES)
    products = meta.get("products", {})

    if product_id not in products:
        flash("El producto no existe en la metadata.", "error")
        return redirect(url_for("admin_bp.products"))

    product = products[product_id]

    if request.method == "POST":
        # Actualizar datos básicos
        product["name"] = request.form.get("name", "").strip()
        product["sku"] = request.form.get("sku", "").strip()
        product["price"] = request.form.get("price", "").strip()
        product["main_image"] = request.form.get("main_image", "").strip()
        product["category"] = request.form.get("category", "").strip()
        product["visible"] = bool(request.form.get("visible"))
        product["featured"] = bool(request.form.get("featured"))

        # Manejo de archivos
        if request.content_length and request.content_length > MAX_CONTENT_LENGTH:
            flash("Los archivos son demasiado grandes (máx 8 MB).", "error")
        else:
            files = request.files.getlist("extra_images")
            if files:
                upload_folder = product_upload_dir(product_id)
                rel_base = f"uploads/products/{product_id}"

                product.setdefault("extra_images", [])

                for file in files:
                    if not file or file.filename == "":
                        continue
                    if not allowed_file(file.filename):
                        flash(f"Archivo no permitido: {file.filename}", "error")
                        continue

                    filename = secure_filename(file.filename)
                    save_path = upload_folder / filename
                    file.save(save_path)

                    rel_path = f"{rel_base}/{filename}"
                    if rel_path not in product["extra_images"]:
                        product["extra_images"].append(rel_path)

        # Eliminar imágenes seleccionadas
        delete_list = request.form.getlist("delete_images")
        if delete_list:
            remain = []
            for rel_path in product.get("extra_images", []):
                if rel_path not in delete_list:
                    remain.append(rel_path)
                else:
                    # Borrar archivo físico
                    abs_path = Path(current_app.root_path) / "static" / rel_path
                    try:
                        if abs_path.exists():
                            abs_path.unlink()
                    except Exception:
                        pass
            product["extra_images"] = remain

        meta["products"][product_id] = product
        save_meta(meta)
        flash("Producto actualizado correctamente ✅", "success")
        return redirect(url_for("admin_bp.product_edit", product_id=product_id))

    # GET
    return render_template(
        "admin/product_edit.html",
        product=product,
        product_id=product_id,
        categories=categories,
        is_new=False,
    )


# ==============================
# GESTIÓN DE CATEGORÍAS (simple)
# ==============================

@admin_bp.route("/categorias", methods=["GET", "POST"])
def manage_categories():
    r = require_admin()
    if r is not None:
        return r

    meta = load_meta()
    categories = meta.get("categories", DEFAULT_CATEGORIES)

    if request.method == "POST":
        action = request.form.get("action")
        new_cat = request.form.get("new_category", "").strip()

        if action == "add" and new_cat:
            if new_cat not in categories:
                categories.append(new_cat)
                meta["categories"] = categories
                save_meta(meta)
                flash("Categoría agregada ✅", "success")
            else:
                flash("La categoría ya existe.", "error")

        elif action == "reset":
            meta["categories"] = DEFAULT_CATEGORIES.copy()
            save_meta(meta)
            flash("Categorías restauradas a los valores por defecto.", "info")

    return render_template(
        "admin/categories.html",
        categories=meta.get("categories", DEFAULT_CATEGORIES),
    )
