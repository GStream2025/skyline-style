from __future__ import annotations

import os
import re
import unicodedata
from pathlib import Path
from typing import Optional

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from werkzeug.utils import secure_filename

from app import db
from app.models.product import Product
from app.models.category import Category
from app.models.offer import Offer
from app.utils.auth import admin_required, admin_creds_ok

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

_slug_pat = re.compile(r"[^a-z0-9]+")

def _slugify(text: str) -> str:
    text = (text or "").strip().lower()
    text = unicodedata.normalize("NFKD", text)
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    text = _slug_pat.sub("-", text).strip("-")
    return text or "item"

def _uploads_dir() -> Path:
    cfg_dir = getattr(current_app.config, "UPLOADS_DIR", None) or current_app.config.get("UPLOADS_DIR")
    if cfg_dir:
        p = Path(cfg_dir)
    else:
        p = Path(current_app.root_path) / "static" / "uploads" / "products"
    p.mkdir(parents=True, exist_ok=True)
    return p

def _save_upload(file_storage) -> Optional[str]:
    if not file_storage or not getattr(file_storage, "filename", ""):
        return None

    filename = secure_filename(file_storage.filename)
    if not filename:
        return None

    ext = Path(filename).suffix.lower().lstrip(".")
    allowed = {"png", "jpg", "jpeg", "webp", "mp4", "webm"}
    if ext not in allowed:
        raise ValueError("Formato no permitido. Usá PNG/JPG/JPEG/WEBP o MP4/WEBM.")

    import time
    stamp = str(int(time.time() * 1000))
    final_name = f"{Path(filename).stem[:48]}_{stamp}.{ext}"
    dest = _uploads_dir() / final_name
    file_storage.save(dest)

    # URL pública
    return url_for("static", filename=f"uploads/products/{final_name}")

# -------------------------
# Login / Logout
# -------------------------
@admin_bp.get("/login")
def login():
    if session.get("admin_logged_in"):
        return redirect(url_for("admin.dashboard"))
    next_url = request.args.get("next") or url_for("admin.dashboard")
    return render_template("admin/login.html", next=next_url)

@admin_bp.post("/login")
def login_post():
    email = (request.form.get("email") or "").strip()
    password = (request.form.get("password") or "").strip()
    next_url = request.form.get("next") or url_for("admin.dashboard")

    if not admin_creds_ok(email, password):
        flash("Credenciales inválidas.", "error")
        return redirect(url_for("admin.login", next=next_url))

    session["admin_logged_in"] = True
    session["admin_email"] = email.strip().lower()
    flash("Bienvenido al panel admin ✅", "success")
    return redirect(next_url)

@admin_bp.get("/logout")
def logout():
    session.clear()
    flash("Sesión cerrada.", "info")
    return redirect(url_for("admin.login"))

# -------------------------
# Dashboard
# -------------------------
@admin_bp.get("/")
@admin_required
def dashboard():
    prod_count = db.session.query(Product).count()
    cat_count = db.session.query(Category).count()
    offer_count = db.session.query(Offer).count()
    return render_template("admin/dashboard.html", prod_count=prod_count, cat_count=cat_count, offer_count=offer_count)

# -------------------------
# Categories
# -------------------------
@admin_bp.get("/categories")
@admin_required
def categories():
    items = db.session.query(Category).order_by(Category.name.asc()).all()
    return render_template("admin/categories.html", categories=items)

@admin_bp.post("/categories/new")
@admin_required
def categories_new():
    name = (request.form.get("name") or "").strip()
    if not name:
        flash("Poné un nombre de categoría.", "warning")
        return redirect(url_for("admin.categories"))

    slug = _slugify(request.form.get("slug") or name)
    exists = db.session.query(Category).filter(Category.slug == slug).first()
    if exists:
        flash("Ya existe una categoría con ese slug.", "warning")
        return redirect(url_for("admin.categories"))

    c = Category(name=name, slug=slug)
    db.session.add(c)
    db.session.commit()
    flash("Categoría creada ✅", "success")
    return redirect(url_for("admin.categories"))

@admin_bp.post("/categories/delete/<int:cat_id>")
@admin_required
def categories_delete(cat_id: int):
    c = db.session.get(Category, cat_id)
    if not c:
        flash("Categoría no encontrada.", "error")
        return redirect(url_for("admin.categories"))
    db.session.delete(c)
    db.session.commit()
    flash("Categoría eliminada 🗑️", "success")
    return redirect(url_for("admin.categories"))

# -------------------------
# Offers (promo banners/cards)
# -------------------------
@admin_bp.get("/offers")
@admin_required
def offers():
    items = db.session.query(Offer).order_by(Offer.id.desc()).all()
    return render_template("admin/offers.html", offers=items)

@admin_bp.post("/offers/new")
@admin_required
def offers_new():
    title = (request.form.get("title") or "").strip()
    if not title:
        flash("El título es obligatorio.", "warning")
        return redirect(url_for("admin.offers"))

    media_url = None
    try:
        media_url = _save_upload(request.files.get("media"))
    except Exception as e:
        flash(str(e), "error")

    o = Offer(
        title=title,
        subtitle=(request.form.get("subtitle") or "").strip() or None,
        badge=(request.form.get("badge") or "").strip() or None,
        cta_text=(request.form.get("cta_text") or "").strip() or None,
        cta_url=(request.form.get("cta_url") or "").strip() or None,
        media_url=media_url,
        active=((request.form.get("active") or "").strip().lower() in {"1","true","on","yes"}),
        sort_order=int(request.form.get("sort_order") or 0),
    )
    db.session.add(o)
    db.session.commit()
    flash("Oferta creada ✅", "success")
    return redirect(url_for("admin.offers"))

@admin_bp.post("/offers/delete/<int:offer_id>")
@admin_required
def offers_delete(offer_id: int):
    o = db.session.get(Offer, offer_id)
    if not o:
        flash("Oferta no encontrada.", "error")
        return redirect(url_for("admin.offers"))
    db.session.delete(o)
    db.session.commit()
    flash("Oferta eliminada 🗑️", "success")
    return redirect(url_for("admin.offers"))

# -------------------------
# Products
# -------------------------
@admin_bp.get("/products")
@admin_required
def products_list():
    q = (request.args.get("q") or "").strip().lower()
    query = db.session.query(Product).order_by(Product.id.desc())
    if q:
        query = query.filter(Product.title.ilike(f"%{q}%"))
    items = query.limit(500).all()
    return render_template("admin/products_list.html", products=items, q=q)

@admin_bp.get("/products/new")
@admin_required
def products_new():
    cats = db.session.query(Category).order_by(Category.name.asc()).all()
    return render_template("admin/product_edit.html", product=None, categories=cats)

@admin_bp.post("/products/new")
@admin_required
def products_create():
    title = (request.form.get("title") or "").strip()
    if not title:
        flash("El título es obligatorio.", "warning")
        return redirect(url_for("admin.products_new"))

    slug = _slugify(request.form.get("slug") or title)
    base = slug
    i = 2
    while db.session.query(Product).filter(Product.slug == slug).first():
        slug = f"{base}-{i}"
        i += 1

    # números
    def fnum(key: str, default: float = 0.0) -> float:
        try:
            return float((request.form.get(key) or default))
        except Exception:
            return default

    def inum(key: str, default: int = 0) -> int:
        try:
            return int((request.form.get(key) or default))
        except Exception:
            return default

    cat_id = request.form.get("category_id")
    category_id = int(cat_id) if cat_id and cat_id.isdigit() else None

    img_url = None
    try:
        img_url = _save_upload(request.files.get("image"))
    except Exception as e:
        flash(str(e), "error")

    video_url = None
    try:
        video_url = _save_upload(request.files.get("video"))
    except Exception as e:
        flash(str(e), "error")

    p = Product(
        title=title,
        slug=slug,
        description=(request.form.get("description") or "").strip() or None,
        price=fnum("price", 0.0),
        stock_qty=inum("stock", 0),
        status=(request.form.get("status") or "active").strip(),
        category_id=category_id,
        source=(request.form.get("source") or "manual").strip(),
        external_url=(request.form.get("external_url") or "").strip() or None,
        image_url=img_url,
        video_url=video_url,
    )
    db.session.add(p)
    db.session.commit()

    flash("Producto creado ✅", "success")
    return redirect(url_for("admin.products_edit", product_id=p.id))

@admin_bp.get("/products/edit/<int:product_id>")
@admin_required
def products_edit(product_id: int):
    p = db.session.get(Product, product_id)
    if not p:
        flash("Producto no encontrado.", "error")
        return redirect(url_for("admin.products_list"))
    cats = db.session.query(Category).order_by(Category.name.asc()).all()
    return render_template("admin/product_edit.html", product=p, categories=cats)

@admin_bp.post("/products/edit/<int:product_id>")
@admin_required
def products_update(product_id: int):
    p = db.session.get(Product, product_id)
    if not p:
        flash("Producto no encontrado.", "error")
        return redirect(url_for("admin.products_list"))

    new_title = (request.form.get("title") or "").strip()
    if new_title:
        p.title = new_title

    new_slug = _slugify(request.form.get("slug") or p.slug)
    if new_slug and new_slug != p.slug:
        if db.session.query(Product).filter(Product.slug == new_slug, Product.id != p.id).first():
            flash("Ese slug ya existe. Se mantiene el anterior.", "warning")
        else:
            p.slug = new_slug

    # helpers
    def setf(attr: str, value):
        if hasattr(p, attr):
            setattr(p, attr, value)

    setf("description", (request.form.get("description") or "").strip() or None)
    try:
        setf("price", float(request.form.get("price") or 0))
    except Exception:
        pass
    try:
        setf("stock_qty", int(request.form.get("stock") or 0))
    except Exception:
        pass
    setf("status", (request.form.get("status") or "active").strip())
    setf("source", (request.form.get("source") or "manual").strip())
    setf("external_url", (request.form.get("external_url") or "").strip() or None)

    cat_id = request.form.get("category_id")
    setf("category_id", int(cat_id) if cat_id and cat_id.isdigit() else None)

    try:
        new_img = _save_upload(request.files.get("image"))
        if new_img:
            p.image_url = new_img
    except Exception as e:
        flash(str(e), "error")

    try:
        new_vid = _save_upload(request.files.get("video"))
        if new_vid:
            p.video_url = new_vid
    except Exception as e:
        flash(str(e), "error")

    db.session.commit()
    flash("Producto actualizado ✅", "success")
    return redirect(url_for("admin.products_edit", product_id=p.id))

@admin_bp.post("/products/delete/<int:product_id>")
@admin_required
def products_delete(product_id: int):
    p = db.session.get(Product, product_id)
    if not p:
        flash("Producto no encontrado.", "error")
        return redirect(url_for("admin.products_list"))
    db.session.delete(p)
    db.session.commit()
    flash("Producto eliminado 🗑️", "success")
    return redirect(url_for("admin.products_list"))
