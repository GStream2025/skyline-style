from __future__ import annotations

from datetime import datetime
from app.models import db, Category, Product, Offer


def seed_demo_store() -> dict:
    # Categorías (slug importante porque tu shop filtra por slug)
    cats = [
        ("Streetwear", "streetwear"),
        ("Zapatillas", "zapatillas"),
        ("Accesorios", "accesorios"),
        ("Tecnología", "tecnologia"),
    ]

    created_cats = 0
    for name, slug in cats:
        c = Category.query.filter_by(slug=slug).first()
        if not c:
            c = Category(name=name, slug=slug, is_active=True, created_at=datetime.utcnow())
            db.session.add(c)
            created_cats += 1

    db.session.commit()

    # Map de categorías
    cat_map = {c.slug: c for c in Category.query.all()}

    # Productos
    products = [
        dict(title="Hoodie Skyline Premium", slug="hoodie-skyline-premium", price=1890, tags="hoodie,streetwear",
             category_slug="streetwear", description="Hoodie premium, cómodo, corte moderno.", stock=25),
        dict(title="Remera Skyline Basic", slug="remera-skyline-basic", price=990, tags="remera,streetwear",
             category_slug="streetwear", description="Remera algodón, fit urbano.", stock=40),
        dict(title="Zapatillas Urban Pro", slug="zapatillas-urban-pro", price=2490, tags="zapas,urban",
             category_slug="zapatillas", description="Zapatillas urbanas, suela cómoda.", stock=15),
        dict(title="Gorra Skyline Cap", slug="gorra-skyline-cap", price=690, tags="gorra,accesorios",
             category_slug="accesorios", description="Gorra clásica con actitud.", stock=30),
        dict(title="Smartwatch Minimal", slug="smartwatch-minimal", price=3190, tags="tech,watch",
             category_slug="tecnologia", description="Reloj smart minimalista, pantalla genérica.", stock=12),
    ]

    created_products = 0
    for p in products:
        exists = Product.query.filter_by(slug=p["slug"]).first()
        if exists:
            continue

        prod = Product(
            title=p["title"],
            slug=p["slug"],
            price=float(p["price"]),
            description=p["description"],
            tags=p["tags"],
            is_active=True,
            created_at=datetime.utcnow(),
        )

        # campos opcionales
        if hasattr(prod, "stock"):
            try:
                prod.stock = int(p["stock"])
            except Exception:
                pass

        # relacion con categoría si existe tu FK/relación
        c = cat_map.get(p["category_slug"])
        if c is not None:
            if hasattr(prod, "category_id"):
                prod.category_id = c.id
            elif hasattr(prod, "category"):
                prod.category = c

        db.session.add(prod)
        created_products += 1

    db.session.commit()

    # Ofertas (opcional)
    created_offers = 0
    hoodie = Product.query.filter_by(slug="hoodie-skyline-premium").first()
    if hoodie:
        off = Offer.query.filter_by(product_id=hoodie.id).first() if hasattr(Offer, "product_id") else None
        if not off:
            offer = Offer(
                title="Oferta lanzamiento",
                is_active=True,
                created_at=datetime.utcnow(),
            )
            if hasattr(offer, "discount_percent"):
                offer.discount_percent = 15
            if hasattr(offer, "product_id"):
                offer.product_id = hoodie.id
            db.session.add(offer)
            created_offers += 1

    db.session.commit()

    return {
        "ok": True,
        "created_categories": created_cats,
        "created_products": created_products,
        "created_offers": created_offers,
    }
