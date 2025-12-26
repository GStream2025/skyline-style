# app/routes/shop_routes.py
from __future__ import annotations
from flask import Blueprint, render_template, request
from sqlalchemy import or_, desc, asc

from app import db
from app.models import Product, Category  # los creamos abajo si no existen

shop_bp = Blueprint("shop", __name__)

@shop_bp.get("/shop")
def shop():
    q = (request.args.get("q") or "").strip()
    cat = (request.args.get("categoria") or "").strip().lower()
    sort = (request.args.get("sort") or "relevance").strip()
    minp = request.args.get("min")
    maxp = request.args.get("max")

    query = Product.query.filter(Product.is_active.is_(True))

    # Categoria por slug
    if cat:
        query = query.join(Category, isouter=True).filter(Category.slug == cat)

    # Búsqueda full simple (nombre, descripción, tags)
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                Product.title.ilike(like),
                Product.description.ilike(like),
                Product.tags.ilike(like),
            )
        )

    # Rango de precios (si hay)
    try:
        if minp is not None and str(minp).strip() != "":
            query = query.filter(Product.price >= float(minp))
        if maxp is not None and str(maxp).strip() != "":
            query = query.filter(Product.price <= float(maxp))
    except ValueError:
        pass

    # Orden
    if sort == "price_asc":
        query = query.order_by(asc(Product.price))
    elif sort == "price_desc":
        query = query.order_by(desc(Product.price))
    elif sort == "new":
        query = query.order_by(desc(Product.created_at))
    else:
        # “relevance”: si hay q, prioriza “más nuevos”; sino también
        query = query.order_by(desc(Product.created_at))

    products = query.limit(60).all()

    return render_template(
        "shop.html",
        products=products,
        q=q,
        categoria=cat,
        sort=sort,
        min=minp,
        max=maxp,
    )
