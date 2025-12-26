# app/services/product_service.py
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import or_

from app.models.product import Product, db
from app.models.offer import Offer
from app.models.category import Category


def _to_decimal(x: Any) -> Decimal:
    try:
        s = str(x).replace(",", ".").strip()
        if s == "" or s.lower() == "none":
            return Decimal("0")
        return Decimal(s)
    except (InvalidOperation, ValueError):
        return Decimal("0")


def _to_int(x: Any) -> int:
    try:
        return int(str(x).strip())
    except Exception:
        return 0


def _slugify(txt: str) -> str:
    import re
    s = (txt or "").strip().lower()
    s = re.sub(r"[^a-z0-9áéíóúñü\s-]", "", s, flags=re.I)
    s = s.replace("ñ", "n")
    s = re.sub(r"\s+", "-", s)
    s = re.sub(r"-{2,}", "-", s).strip("-")
    return s or "item"


def _parse_dt(s: str) -> Optional[datetime]:
    if not s:
        return None
    # HTML datetime-local: 2025-12-25T18:30
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            pass
    return None


class ProductService:
    def get_stats(self) -> Dict[str, Any]:
        total = db.session.query(Product).count()
        active = db.session.query(Product).filter(Product.status == "active").count()
        printful = db.session.query(Product).filter(Product.source == "printful").count()
        drops = db.session.query(Product).filter(Product.source == "dropshipping").count()
        offers = db.session.query(Offer).count()
        cats = db.session.query(Category).count()

        return {
            "total": total,
            "active": active,
            "printful": printful,
            "dropshipping": drops,
            "offers": offers,
            "categories": cats,
        }

    # ---------- Categories ----------
    def list_categories(self) -> List[Category]:
        return db.session.query(Category).order_by(Category.sort_order.asc(), Category.name.asc()).all()

    def ensure_default_categories(self) -> None:
        defaults = [
            ("Buzos", "buzos", 1),
            ("Remeras", "remeras", 2),
            ("Gorros", "gorros", 3),
            ("Accesorios", "accesorios", 4),
        ]
        for name, slug, order in defaults:
            ex = db.session.query(Category).filter(Category.slug == slug).first()
            if not ex:
                db.session.add(Category(name=name, slug=slug, sort_order=order))
        db.session.commit()

    # ---------- Products ----------
    def list_products(
        self,
        q: str = "",
        category_slug: str = "",
        source: str = "",
        status: str = "",
        limit: int = 200,
    ) -> List[Product]:
        qry = db.session.query(Product)

        if q:
            like = f"%{q}%"
            qry = qry.filter(or_(Product.title.ilike(like), Product.slug.ilike(like), Product.tags.ilike(like)))

        if category_slug:
            qry = qry.filter(Product.category_slug == category_slug)

        if source:
            qry = qry.filter(Product.source == source)

        if status:
            qry = qry.filter(Product.status == status)

        return qry.order_by(Product.updated_at.desc()).limit(limit).all()

    def get_product(self, product_id: int) -> Optional[Product]:
        return db.session.query(Product).filter(Product.id == product_id).first()

    def create_product(self, payload: Dict[str, Any]) -> Tuple[bool, str]:
        title = payload.get("title", "").strip()
        slug = payload.get("slug", "").strip() or _slugify(title)
        if not title:
            return False, "Falta el título."
        if db.session.query(Product).filter(Product.slug == slug).first():
            return False, f"El slug ya existe: {slug}"

        p = Product(
            title=title,
            slug=slug,
            description=payload.get("description", "") or "",
            price=_to_decimal(payload.get("price", 0)),
            compare_at_price=_to_decimal(payload.get("compare_at_price")) if payload.get("compare_at_price") else None,
            currency=(payload.get("currency") or "UYU").strip(),
            category_slug=(payload.get("category_slug") or "").strip() or None,
            image_url=(payload.get("image_url") or "").strip(),
            stock=_to_int(payload.get("stock", 0)),
            status=(payload.get("status") or "active").strip(),
            source=(payload.get("source") or "skyline").strip(),
            external_id=(payload.get("external_id") or "").strip() or None,
            tags=(payload.get("tags") or "").strip(),
        )
        db.session.add(p)
        db.session.commit()
        return True, "Producto creado ✅"

    def update_product(self, product_id: int, payload: Dict[str, Any]) -> Tuple[bool, str]:
        p = self.get_product(product_id)
        if not p:
            return False, "Producto no encontrado."

        title = payload.get("title", "").strip()
        slug = payload.get("slug", "").strip()
        if not title:
            return False, "Falta el título."
        if not slug:
            slug = _slugify(title)

        other = db.session.query(Product).filter(Product.slug == slug, Product.id != p.id).first()
        if other:
            return False, f"Slug en uso por otro producto: {slug}"

        p.title = title
        p.slug = slug
        p.description = payload.get("description", "") or ""
        p.price = _to_decimal(payload.get("price", 0))
        p.compare_at_price = _to_decimal(payload.get("compare_at_price")) if payload.get("compare_at_price") else None
        p.currency = (payload.get("currency") or "UYU").strip()

        p.category_slug = (payload.get("category_slug") or "").strip() or None
        p.image_url = (payload.get("image_url") or "").strip()
        p.stock = _to_int(payload.get("stock", 0))

        p.status = (payload.get("status") or "active").strip()
        p.source = (payload.get("source") or p.source).strip()
        p.external_id = (payload.get("external_id") or "").strip() or None
        p.tags = (payload.get("tags") or "").strip()

        db.session.commit()
        return True, "Producto actualizado ✅"

    def delete_product(self, product_id: int) -> Tuple[bool, str]:
        p = self.get_product(product_id)
        if not p:
            return False, "Producto no encontrado."
        db.session.delete(p)
        db.session.commit()
        return True, "Producto eliminado ✅"

    # ---------- Offers ----------
    def list_offers(self) -> List[Offer]:
        return db.session.query(Offer).order_by(Offer.updated_at.desc()).all()

    def create_offer(self, payload: Dict[str, Any]) -> Tuple[bool, str]:
        title = (payload.get("title") or "").strip()
        if not title:
            return False, "Falta el título de la oferta."

        product_id = payload.get("product_id") or None
        try:
            product_id = int(product_id) if product_id else None
        except Exception:
            product_id = None

        off = Offer(
            title=title,
            badge=(payload.get("badge") or "Oferta").strip(),
            product_id=product_id,
            discount_type=(payload.get("discount_type") or "percent").strip(),
            discount_value=_to_decimal(payload.get("discount_value", 0)),
            starts_at=_parse_dt(payload.get("starts_at", "")),
            ends_at=_parse_dt(payload.get("ends_at", "")),
            active=bool(payload.get("active", False)),
        )
        db.session.add(off)
        db.session.commit()
        return True, "Oferta creada ✅"

    def toggle_offer(self, offer_id: int) -> Tuple[bool, str]:
        off = db.session.query(Offer).filter(Offer.id == offer_id).first()
        if not off:
            return False, "Oferta no encontrada."
        off.active = not off.active
        db.session.commit()
        return True, "Estado de oferta actualizado ✅"

    def delete_offer(self, offer_id: int) -> Tuple[bool, str]:
        off = db.session.query(Offer).filter(Offer.id == offer_id).first()
        if not off:
            return False, "Oferta no encontrada."
        db.session.delete(off)
        db.session.commit()
        return True, "Oferta eliminada ✅"

    # ---------- External Upsert (Printful / Dropshipping) ----------
    def upsert_external_product(self, data: Dict[str, Any], source: str) -> Tuple[bool, str]:
        """
        data esperado:
          external_id, title, description, price, compare_at_price, currency,
          image_url, category_slug, stock, status, tags, slug (opcional)
        """
        external_id = (data.get("external_id") or "").strip()
        title = (data.get("title") or "").strip()
        if not external_id or not title:
            return False, "Faltan external_id o title en producto externo."

        p = db.session.query(Product).filter(Product.source == source, Product.external_id == external_id).first()

        slug = (data.get("slug") or "").strip()
        if not slug:
            slug = _slugify(f"{title}-{source}-{external_id}")

        if not p:
            # si slug ya existe, le agregamos sufijo
            base_slug = slug
            i = 2
            while db.session.query(Product).filter(Product.slug == slug).first():
                slug = f"{base_slug}-{i}"
                i += 1

            p = Product(
                title=title,
                slug=slug,
                description=data.get("description", "") or "",
                price=_to_decimal(data.get("price", 0)),
                compare_at_price=_to_decimal(data.get("compare_at_price")) if data.get("compare_at_price") else None,
                currency=(data.get("currency") or "UYU").strip(),
                category_slug=(data.get("category_slug") or "").strip() or None,
                image_url=(data.get("image_url") or "").strip(),
                stock=_to_int(data.get("stock", 0)),
                status=(data.get("status") or "active").strip(),
                source=source,
                external_id=external_id,
                tags=(data.get("tags") or "").strip(),
            )
            db.session.add(p)
            db.session.commit()
            return True, "Creado"

        # update existente
        p.title = title
        p.description = data.get("description", "") or p.description
        p.price = _to_decimal(data.get("price", p.price))
        p.compare_at_price = _to_decimal(data.get("compare_at_price")) if data.get("compare_at_price") else p.compare_at_price
        p.currency = (data.get("currency") or p.currency).strip()
        p.category_slug = (data.get("category_slug") or p.category_slug) or None
        p.image_url = (data.get("image_url") or p.image_url).strip()
        p.stock = _to_int(data.get("stock", p.stock))
        p.status = (data.get("status") or p.status).strip()
        p.tags = (data.get("tags") or p.tags).strip()

        db.session.commit()
        return True, "Actualizado"
