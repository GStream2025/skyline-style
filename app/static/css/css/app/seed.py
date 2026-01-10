from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from app.models import db, Category, Product, Offer


def _set_if_has(obj: Any, field: str, value: Any) -> bool:
    if hasattr(obj, field):
        try:
            setattr(obj, field, value)
            return True
        except Exception:
            return False
    return False


def _get_by_slug(model: Any, slug: str):
    try:
        if hasattr(model, "query"):
            return model.query.filter_by(slug=slug).first()
    except Exception:
        return None
    return None


def _now_utc() -> datetime:
    return datetime.utcnow()


def seed_demo_store(*, overwrite: bool = False) -> Dict[str, Any]:
    """
    Seed demo para Skyline Store:
    - Categorías + Productos + Oferta demo
    - overwrite=False: no pisa lo existente
    - overwrite=True: actualiza campos principales si ya existe
    """
    report = {
        "ok": False,
        "created_categories": 0,
        "updated_categories": 0,
        "created_products": 0,
        "updated_products": 0,
        "created_offers": 0,
        "updated_offers": 0,
        "errors": [],
    }

    # ----------------------------
    # DATA
    # ----------------------------
    cats = [
        ("Streetwear", "streetwear"),
        ("Zapatillas", "zapatillas"),
        ("Accesorios", "accesorios"),
        ("Tecnología", "tecnologia"),
    ]

    products = [
        dict(
            title="Hoodie Skyline Premium",
            slug="hoodie-skyline-premium",
            price=1890,
            tags="hoodie,streetwear",
            category_slug="streetwear",
            description="Hoodie premium, cómodo, corte moderno.",
            stock=25,
        ),
        dict(
            title="Remera Skyline Basic",
            slug="remera-skyline-basic",
            price=990,
            tags="remera,streetwear",
            category_slug="streetwear",
            description="Remera algodón, fit urbano.",
            stock=40,
        ),
        dict(
            title="Zapatillas Urban Pro",
            slug="zapatillas-urban-pro",
            price=2490,
            tags="zapas,urban",
            category_slug="zapatillas",
            description="Zapatillas urbanas, suela cómoda.",
            stock=15,
        ),
        dict(
            title="Gorra Skyline Cap",
            slug="gorra-skyline-cap",
            price=690,
            tags="gorra,accesorios",
            category_slug="accesorios",
            description="Gorra clásica con actitud.",
            stock=30,
        ),
        dict(
            title="Smartwatch Minimal",
            slug="smartwatch-minimal",
            price=3190,
            tags="tech,watch",
            category_slug="tecnologia",
            description="Reloj smart minimalista, pantalla genérica.",
            stock=12,
        ),
    ]

    try:
        # ============================
        # CATEGORIES
        # ============================
        for name, slug in cats:
            c = _get_by_slug(Category, slug)
            if not c:
                c = Category()

                _set_if_has(c, "name", name)
                _set_if_has(c, "slug", slug)

                # activo
                if not _set_if_has(c, "is_active", True):
                    _set_if_has(c, "status", "active")

                # timestamps
                if not _set_if_has(c, "created_at", _now_utc()):
                    _set_if_has(c, "created_on", _now_utc())
                _set_if_has(c, "updated_at", _now_utc())

                db.session.add(c)
                report["created_categories"] += 1

            elif overwrite:
                changed = False
                changed |= _set_if_has(c, "name", name)
                changed |= _set_if_has(c, "updated_at", _now_utc())
                if changed:
                    report["updated_categories"] += 1

        db.session.commit()

        # Map categorías por slug (refresco post-commit)
        cat_map = {}
        try:
            for c in Category.query.all():
                s = (getattr(c, "slug", "") or "").strip()
                if s:
                    cat_map[s] = c
        except Exception:
            cat_map = {}

        # ============================
        # PRODUCTS
        # ============================
        for p in products:
            slug = p["slug"]
            exists = _get_by_slug(Product, slug)

            if exists and not overwrite:
                continue

            prod = exists or Product()

            title = p.get("title") or "Producto"
            desc = p.get("description") or ""
            tags = p.get("tags") or ""
            price = float(p.get("price") or 0)

            # title/name
            if hasattr(prod, "title"):
                _set_if_has(prod, "title", title)
            elif hasattr(prod, "name"):
                _set_if_has(prod, "name", title)

            _set_if_has(prod, "slug", slug)
            _set_if_has(prod, "description", desc)
            _set_if_has(prod, "tags", tags)
            _set_if_has(prod, "price", price)

            # activo (is_active o status)
            if not _set_if_has(prod, "is_active", True):
                _set_if_has(prod, "status", "active")

            # timestamps
            if not exists:
                if not _set_if_has(prod, "created_at", _now_utc()):
                    _set_if_has(prod, "created_on", _now_utc())
            _set_if_has(prod, "updated_at", _now_utc())

            # stock opcional
            if hasattr(prod, "stock"):
                try:
                    prod.stock = int(p.get("stock") or 0)
                except Exception:
                    pass

            # link categoría
            c = cat_map.get(p.get("category_slug", ""))
            if c is not None:
                if hasattr(prod, "category_id") and hasattr(c, "id"):
                    _set_if_has(prod, "category_id", c.id)
                elif hasattr(prod, "category"):
                    _set_if_has(prod, "category", c)

            if not exists:
                db.session.add(prod)
                report["created_products"] += 1
            else:
                report["updated_products"] += 1

        db.session.commit()

        # ============================
        # OFFER (best-effort)
        # ============================
        hoodie = _get_by_slug(Product, "hoodie-skyline-premium")

        if hoodie:
            # buscamos oferta existente (por product_id si existe)
            existing_offer: Optional[Any] = None
            try:
                if (
                    hasattr(Offer, "query")
                    and hasattr(Offer, "product_id")
                    and hasattr(hoodie, "id")
                ):
                    existing_offer = Offer.query.filter_by(product_id=hoodie.id).first()
            except Exception:
                existing_offer = None

            if existing_offer and not overwrite:
                report["ok"] = True
                return report

            offer = existing_offer or Offer()

            _set_if_has(offer, "title", "Oferta lanzamiento")

            # active/is_active
            if not _set_if_has(offer, "is_active", True):
                _set_if_has(offer, "active", True)

            # discount
            if hasattr(offer, "discount_percent"):
                _set_if_has(offer, "discount_percent", 15)
            elif hasattr(offer, "discount"):
                _set_if_has(offer, "discount", 15)

            # sort order opcional
            _set_if_has(offer, "sort_order", 1)

            # timestamps
            if not existing_offer:
                _set_if_has(offer, "created_at", _now_utc())
            _set_if_has(offer, "updated_at", _now_utc())

            # link product
            if hasattr(offer, "product_id") and hasattr(hoodie, "id"):
                _set_if_has(offer, "product_id", hoodie.id)
            elif hasattr(offer, "product"):
                _set_if_has(offer, "product", hoodie)

            if not existing_offer:
                db.session.add(offer)
                report["created_offers"] += 1
            else:
                report["updated_offers"] += 1

            db.session.commit()

        report["ok"] = True
        return report

    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        report["errors"].append(f"{type(e).__name__}: {e}")
        return report
