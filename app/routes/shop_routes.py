# app/routes/shop_routes.py
from __future__ import annotations

from flask import Blueprint, render_template, request
from sqlalchemy import or_, desc, asc

from app.models import db, Product, Category  # ✅ DB + modelos desde el HUB

shop_bp = Blueprint("shop", __name__)


def _safe_slug(s: str) -> str:
    return (s or "").strip().lower()


def _product_cat_slug(p) -> str:
    """
    Devuelve el slug de categoría del producto.
    Soporta:
    - p.category.slug (relación)
    - p.category_slug (string)
    - fallback: 'otros'
    """
    try:
        if getattr(p, "category", None) is not None and getattr(p.category, "slug", None):
            return _safe_slug(p.category.slug)
    except Exception:
        pass

    for attr in ("category_slug", "category", "categoria", "cat"):
        v = getattr(p, attr, None)
        if isinstance(v, str) and v.strip():
            return _safe_slug(v)

    return "otros"


@shop_bp.get("/shop")
def shop():
    # -------- params --------
    q = (request.args.get("q") or "").strip()
    cat = _safe_slug(request.args.get("categoria") or request.args.get("cat") or "")
    sort = (request.args.get("sort") or "new").strip()
    minp = request.args.get("min")
    maxp = request.args.get("max")

    # -------- base query --------
    query = Product.query

    # Activos si existe el campo
    if hasattr(Product, "is_active"):
        query = query.filter(Product.is_active.is_(True))

    # Join category si existe la relación/tabla
    if cat:
        # Si Product tiene category_id y Category tiene slug -> join
        try:
            query = query.join(Category, isouter=True).filter(Category.slug == cat)
        except Exception:
            # Si no se puede joinear, intentamos por string field en Product
            for attr in ("category_slug", "category", "categoria", "cat"):
                if hasattr(Product, attr):
                    query = query.filter(getattr(Product, attr) == cat)
                    break

    # -------- search --------
    if q:
        like = f"%{q}%"
        conds = []
        # soporte por nombres distintos
        for field in ("title", "name", "description", "tags"):
            if hasattr(Product, field):
                conds.append(getattr(Product, field).ilike(like))
        if conds:
            query = query.filter(or_(*conds))

    # -------- price range --------
    try:
        if minp is not None and str(minp).strip() != "" and hasattr(Product, "price"):
            query = query.filter(Product.price >= float(minp))
        if maxp is not None and str(maxp).strip() != "" and hasattr(Product, "price"):
            query = query.filter(Product.price <= float(maxp))
    except ValueError:
        pass

    # -------- sort --------
    created_field = getattr(Product, "created_at", None)
    price_field = getattr(Product, "price", None)

    if sort == "price_asc" and price_field is not None:
        query = query.order_by(asc(price_field))
    elif sort == "price_desc" and price_field is not None:
        query = query.order_by(desc(price_field))
    elif sort == "new" and created_field is not None:
        query = query.order_by(desc(created_field))
    else:
        # default: más nuevos si existe, sino por id desc
        if created_field is not None:
            query = query.order_by(desc(created_field))
        else:
            query = query.order_by(desc(Product.id))

    products = query.limit(120).all()

    # -------- grouped_products para tu template PRO --------
    grouped_products = {}
    for p in products:
        slug = _product_cat_slug(p)
        grouped_products.setdefault(slug, []).append(p)

    # Traemos categorías (si existen) para UI
    categories = []
    try:
        categories = Category.query.order_by(asc(Category.name)).all()
    except Exception:
        categories = []

    return render_template(
        "shop.html",
        products=products,
        grouped_products=grouped_products,  # ✅ tu shop.html PRO lo usa
        categories=categories,
        q=q,
        categoria=cat,
        sort=sort,
        min=minp,
        max=maxp,
    )
