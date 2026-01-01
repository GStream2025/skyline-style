from __future__ import annotations

import json
import re
import time
import unicodedata
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Optional, Any, Dict

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
from app.models.product import Product
from app.models.category import Category
from app.models.offer import Offer
from app.utils.auth import admin_required, admin_creds_ok


# ============================================================
# Blueprint
# ============================================================

admin_bp = Blueprint(
    "admin",
    __name__,
    url_prefix="/admin",
    template_folder="../templates",
)


# ============================================================
# Utils · Slug / Parsing
# ============================================================

_slug_pat = re.compile(r"[^a-z0-9]+")


def _slugify(text: str) -> str:
    text = (text or "").strip().lower()
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c))
    text = _slug_pat.sub("-", text).strip("-")
    return text or "item"


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(str(v).strip())
    except Exception:
        return default


def _as_decimal(v: Any, default: Decimal = Decimal("0.00")) -> Decimal:
    try:
        s = str(v).strip().replace(",", ".")
        if not s:
            return default
        return Decimal(s)
    except Exception:
        return default


def _parse_dt_local(value: str | None) -> Optional[datetime]:
    """
    Convierte datetime-local (YYYY-MM-DDTHH:MM) a datetime naive.
    (Si querés UTC real, lo pasamos a timezone-aware en tu modelo)
    """
    if not value:
        return None
    value = value.strip()
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


# ============================================================
# Uploads (products / offers) · robusto
# ============================================================

_ALLOWED_MEDIA = {"png", "jpg", "jpeg", "webp", "mp4", "webm"}
_ALLOWED_IMAGES = {"png", "jpg", "jpeg", "webp"}


def _uploads_dir(kind: str) -> Path:
    """
    Directorio final de uploads.
    Prioridad:
    1) UPLOADS_DIR en config (base)
    2) static/uploads/{kind}
    """
    base = current_app.config.get("UPLOADS_DIR")
    if base:
        root = Path(base)
    else:
        root = Path(current_app.root_path) / "static" / "uploads"

    path = root / kind
    path.mkdir(parents=True, exist_ok=True)
    return path


def _save_upload(file_storage, kind: str, allow: set[str]) -> Optional[str]:
    """
    Guarda archivo y devuelve URL pública (/static/uploads/{kind}/...)
    """
    if not file_storage or not getattr(file_storage, "filename", ""):
        return None

    filename = secure_filename(file_storage.filename)
    if not filename:
        return None

    ext = Path(filename).suffix.lower().lstrip(".")
    if ext not in allow:
        raise ValueError(f"Formato no permitido. Permitidos: {', '.join(sorted(allow))}")

    stamp = int(time.time() * 1000)
    stem = Path(filename).stem[:48] or "file"
    final_name = f"{stem}_{stamp}.{ext}"

    dest = _uploads_dir(kind) / final_name
    file_storage.save(dest)

    # IMPORTANTE: si UPLOADS_DIR no es /static/uploads, igual devolvemos ruta /static/uploads/...
    # porque tu front sirve desde /static. Recomendado: que UPLOADS_DIR apunte a app/static/uploads
    return url_for("static", filename=f"uploads/{kind}/{final_name}")


# ============================================================
# Settings · Payments (sin migraciones, en JSON)
# ============================================================

def _settings_path() -> Path:
    # instance/ (si existe) o raíz del proyecto
    inst = current_app.instance_path
    try:
        p = Path(inst)
        p.mkdir(parents=True, exist_ok=True)
    except Exception:
        p = Path(current_app.root_path)
    return p / "payments_settings.json"


def _payments_defaults() -> Dict[str, Any]:
    return {
        "mp_uy": {"active": False, "link": "", "note": ""},
        "mp_ar": {"active": False, "link": "", "note": ""},
        "paypal": {"active": False, "user": "", "email": ""},
        "transfer": {"active": False, "info": ""},
    }


def _load_payments() -> Dict[str, Any]:
    path = _settings_path()
    data = _payments_defaults()
    if path.exists():
        try:
            raw = json.loads(path.read_text("utf-8"))
            if isinstance(raw, dict):
                # merge seguro
                for k in data.keys():
                    if isinstance(raw.get(k), dict):
                        data[k].update(raw[k])
        except Exception:
            pass
    return data


def _save_payments(data: Dict[str, Any]) -> None:
    path = _settings_path()
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), "utf-8")


# ============================================================
# Auth · Login / Logout
# ============================================================

@admin_bp.get("/login")
def login():
    if session.get("admin_logged_in"):
        return redirect(url_for("admin.dashboard"))
    return render_template(
        "admin/login.html",
        next=request.args.get("next") or url_for("admin.dashboard"),
    )


@admin_bp.post("/login")
def login_post():
    email = (request.form.get("email") or "").strip().lower()
    password = (request.form.get("password") or "").strip()
    next_url = request.form.get("next") or url_for("admin.dashboard")

    if not admin_creds_ok(email, password):
        flash("Credenciales inválidas.", "error")
        return redirect(url_for("admin.login", next=next_url))

    session.clear()
    session["admin_logged_in"] = True
    session["admin_email"] = email
    flash("Bienvenido al panel admin ✅", "success")
    return redirect(next_url)


@admin_bp.get("/logout")
def logout():
    session.clear()
    flash("Sesión cerrada.", "info")
    return redirect(url_for("admin.login"))


# ============================================================
# Dashboard
# ============================================================

@admin_bp.get("/")
@admin_required
def dashboard():
    return render_template(
        "admin/dashboard.html",
        prod_count=db.session.query(Product).count(),
        cat_count=db.session.query(Category).count(),
        offer_count=db.session.query(Offer).count(),
    )


# ============================================================
# Payments
# ============================================================

@admin_bp.get("/payments")
@admin_required
def payments():
    data = _load_payments()
    return render_template("admin/payments.html", data=data)


@admin_bp.post("/payments/save")
@admin_required
def payments_save():
    data = _payments_defaults()

    data["mp_uy"]["active"] = bool(request.form.get("mp_uy_active"))
    data["mp_uy"]["link"] = (request.form.get("mp_uy_link") or "").strip()
    data["mp_uy"]["note"] = (request.form.get("mp_uy_note") or "").strip()

    data["mp_ar"]["active"] = bool(request.form.get("mp_ar_active"))
    data["mp_ar"]["link"] = (request.form.get("mp_ar_link") or "").strip()
    data["mp_ar"]["note"] = (request.form.get("mp_ar_note") or "").strip()

    data["paypal"]["active"] = bool(request.form.get("paypal_active"))
    data["paypal"]["user"] = (request.form.get("paypal_user") or "").strip()
    data["paypal"]["email"] = (request.form.get("paypal_email") or "").strip()

    data["transfer"]["active"] = bool(request.form.get("transfer_active"))
    data["transfer"]["info"] = (request.form.get("transfer_info") or "").strip()

    # Validaciones suaves (no rompen)
    if data["mp_uy"]["active"] and not data["mp_uy"]["link"]:
        flash("MP Uruguay está activo pero sin link. Pegá un link mpago.la o checkout.", "warning")
    if data["mp_ar"]["active"] and not data["mp_ar"]["link"]:
        flash("MP Argentina está activo pero sin link. Pegá un link mpago.la o checkout.", "warning")
    if data["paypal"]["active"] and not (data["paypal"]["user"] or data["paypal"]["email"]):
        flash("PayPal está activo pero faltan datos (paypal.me o email).", "warning")
    if data["transfer"]["active"] and not data["transfer"]["info"]:
        flash("Transferencias está activo pero faltan datos de cuenta.", "warning")

    try:
        _save_payments(data)
        flash("Métodos de pago guardados ✅", "success")
    except Exception:
        flash("No se pudo guardar la configuración de pagos.", "error")

    return redirect(url_for("admin.payments"))


# ============================================================
# Categories
# ============================================================

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
        flash("El nombre es obligatorio.", "warning")
        return redirect(url_for("admin.categories"))

    slug = _slugify(request.form.get("slug") or name)
    if db.session.query(Category).filter_by(slug=slug).first():
        flash("Ya existe una categoría con ese slug.", "warning")
        return redirect(url_for("admin.categories"))

    db.session.add(Category(name=name, slug=slug))
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


# ============================================================
# Offers (ULTRA PRO)
# ============================================================

@admin_bp.get("/offers")
@admin_required
def offers():
    items = db.session.query(Offer).order_by(Offer.sort_order.asc(), Offer.id.desc()).all()
    return render_template("admin/offers.html", offers=items)


@admin_bp.post("/offers/new")
@admin_required
def offers_new():
    title = (request.form.get("title") or "").strip()
    if not title:
        flash("El título es obligatorio.", "warning")
        return redirect(url_for("admin.offers"))

    # media
    media_url = None
    try:
        media_url = _save_upload(request.files.get("media"), kind="offers", allow=_ALLOWED_MEDIA)
    except Exception as e:
        flash(str(e), "error")

    # extras pro (si modelo ULTRA los tiene, se guardan; si no, no rompe por try/except)
    discount_type = (request.form.get("discount_type") or "").strip().lower() or "none"
    if discount_type not in {"none", "percent", "amount"}:
        discount_type = "none"
    discount_value = _as_decimal(request.form.get("discount_value"), Decimal("0.00"))
    theme = (request.form.get("theme") or "").strip().lower() or "auto"
    if theme not in {"auto", "amber", "emerald", "sky", "rose", "slate"}:
        theme = "auto"

    starts_at = _parse_dt_local(request.form.get("starts_at"))
    ends_at = _parse_dt_local(request.form.get("ends_at"))

    o = Offer(
        title=title,
        subtitle=(request.form.get("subtitle") or "").strip() or None,
        badge=(request.form.get("badge") or "").strip() or None,
        cta_text=(request.form.get("cta_text") or "").strip() or None,
        cta_url=(request.form.get("cta_url") or "").strip() or None,
        media_url=media_url,
        active=bool(request.form.get("active")),
        sort_order=_as_int(request.form.get("sort_order"), 0),
    )

    # Set opcionales si existen en el modelo ULTRA
    for k, v in {
        "discount_type": discount_type,
        "discount_value": discount_value,
        "theme": theme,
        "starts_at": starts_at,
        "ends_at": ends_at,
    }.items():
        if hasattr(o, k):
            setattr(o, k, v)

    db.session.add(o)
    db.session.commit()
    flash("Oferta creada ✅", "success")
    return redirect(url_for("admin.offers"))


@admin_bp.post("/offers/<int:offer_id>/delete")
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


@admin_bp.post("/offers/<int:offer_id>/toggle")
@admin_required
def offers_toggle(offer_id: int):
    o = db.session.get(Offer, offer_id)
    if not o:
        flash("Oferta no encontrada.", "error")
        return redirect(url_for("admin.offers"))
    o.active = not bool(getattr(o, "active", True))
    db.session.commit()
    flash("Estado actualizado ✅", "success")
    return redirect(url_for("admin.offers"))


@admin_bp.post("/offers/<int:offer_id>/update")
@admin_required
def offers_update(offer_id: int):
    """
    Update PRO sin borrar:
    - permite editar campos principales + extras + reemplazar media
    Ideal para cuando agregues botón "Editar" o modal.
    """
    o = db.session.get(Offer, offer_id)
    if not o:
        flash("Oferta no encontrada.", "error")
        return redirect(url_for("admin.offers"))

    # básicos
    title = (request.form.get("title") or "").strip()
    if title:
        o.title = title

    for key in ("subtitle", "badge", "cta_text", "cta_url"):
        if key in request.form:
            val = (request.form.get(key) or "").strip()
            setattr(o, key, val or None)

    if "sort_order" in request.form:
        o.sort_order = _as_int(request.form.get("sort_order"), getattr(o, "sort_order", 0))

    if "active" in request.form:
        o.active = bool(request.form.get("active"))

    # extras pro
    if hasattr(o, "discount_type") and "discount_type" in request.form:
        dt = (request.form.get("discount_type") or "").strip().lower() or "none"
        if dt not in {"none", "percent", "amount"}:
            dt = "none"
        o.discount_type = dt

    if hasattr(o, "discount_value") and "discount_value" in request.form:
        o.discount_value = _as_decimal(request.form.get("discount_value"), getattr(o, "discount_value", Decimal("0.00")))

    if hasattr(o, "theme") and "theme" in request.form:
        th = (request.form.get("theme") or "").strip().lower() or "auto"
        if th not in {"auto", "amber", "emerald", "sky", "rose", "slate"}:
            th = "auto"
        o.theme = th

    if hasattr(o, "starts_at") and "starts_at" in request.form:
        o.starts_at = _parse_dt_local(request.form.get("starts_at"))

    if hasattr(o, "ends_at") and "ends_at" in request.form:
        o.ends_at = _parse_dt_local(request.form.get("ends_at"))

    # media opcional (reemplazar)
    try:
        new_media = _save_upload(request.files.get("media"), kind="offers", allow=_ALLOWED_MEDIA)
        if new_media:
            o.media_url = new_media
    except Exception as e:
        flash(str(e), "error")

    db.session.commit()
    flash("Oferta actualizada ✅", "success")
    return redirect(url_for("admin.offers"))


# ============================================================
# Products
# ============================================================

@admin_bp.get("/products")
@admin_required
def products_list():
    q = (request.args.get("q") or "").strip()
    query = db.session.query(Product).order_by(Product.id.desc())

    if q:
        # busca por title o name (según modelo)
        if hasattr(Product, "title"):
            query = query.filter(Product.title.ilike(f"%{q}%"))
        else:
            query = query.filter(Product.name.ilike(f"%{q}%"))

    return render_template(
        "admin/products_list.html",
        products=query.limit(800).all(),
        q=q,
    )


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
    base, i = slug, 2
    while db.session.query(Product).filter_by(slug=slug).first():
        slug = f"{base}-{i}"
        i += 1

    price = float(str(request.form.get("price") or "0").replace(",", ".") or 0)
    stock = _as_int(request.form.get("stock"), 0)

    status = (request.form.get("status") or "active").strip()
    source = (request.form.get("source") or "manual").strip()
    external_url = (request.form.get("external_url") or "").strip() or None
    desc = (request.form.get("description") or "").strip() or None

    cat_id = request.form.get("category_id")
    category_id = int(cat_id) if cat_id and str(cat_id).isdigit() else None

    img_url = None
    try:
        img_url = _save_upload(request.files.get("image"), kind="products", allow=_ALLOWED_IMAGES)
    except Exception as e:
        flash(str(e), "error")

    p = Product(
        title=title if hasattr(Product, "title") else None,
        name=title if hasattr(Product, "name") else None,
        slug=slug,
        description=desc,
        price=price,
        status=status,
        source=source,
        external_url=external_url,
        category_id=category_id,
        image_url=img_url,
    )

    # stock: soporta stock o stock_qty según tu modelo
    if hasattr(p, "stock"):
        p.stock = stock
    elif hasattr(p, "stock_qty"):
        p.stock_qty = stock

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

    # campos texto
    title = (request.form.get("title") or "").strip()
    if title:
        if hasattr(p, "title"):
            p.title = title
        elif hasattr(p, "name"):
            p.name = title

    if "description" in request.form:
        p.description = (request.form.get("description") or "").strip() or None

    if "status" in request.form:
        p.status = (request.form.get("status") or "active").strip()

    if "source" in request.form:
        p.source = (request.form.get("source") or "manual").strip()

    if "external_url" in request.form:
        p.external_url = (request.form.get("external_url") or "").strip() or None

    # slug (si es único)
    new_slug = _slugify(request.form.get("slug") or getattr(p, "slug", ""))
    if new_slug and new_slug != getattr(p, "slug", ""):
        exists = db.session.query(Product).filter(Product.slug == new_slug, Product.id != p.id).first()
        if not exists:
            p.slug = new_slug

    # números
    try:
        p.price = float(str(request.form.get("price") or p.price).replace(",", "."))
    except Exception:
        pass

    stock = request.form.get("stock")
    if stock is not None:
        s = _as_int(stock, None)  # type: ignore
        if s is not None:
            if hasattr(p, "stock"):
                p.stock = s
            elif hasattr(p, "stock_qty"):
                p.stock_qty = s

    # categoría
    cat_id = request.form.get("category_id")
    p.category_id = int(cat_id) if cat_id and str(cat_id).isdigit() else None

    # imagen
    try:
        img = _save_upload(request.files.get("image"), kind="products", allow=_ALLOWED_IMAGES)
        if img:
            p.image_url = img
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


__all__ = ["admin_bp"]
