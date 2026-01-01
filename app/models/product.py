from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Optional, Any, Iterable

from sqlalchemy import event
from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property

from app.models import db  # ✅ SIEMPRE db ÚNICO


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _d(v: Any, default: str = "0.00") -> Decimal:
    """Decimal seguro (no rompe con None, '', floats raros)."""
    try:
        if v is None or v == "":
            return Decimal(default)
        if isinstance(v, Decimal):
            return v
        return Decimal(str(v))
    except (InvalidOperation, ValueError, TypeError):
        return Decimal(default)


def _clamp_money(v: Decimal) -> Decimal:
    return v if v >= Decimal("0.00") else Decimal("0.00")


_slug_re = re.compile(r"[^a-z0-9\-]+")


def slugify(text: str, max_len: int = 180) -> str:
    """Slug simple, estable y portable (sin dependencias externas)."""
    s = (text or "").strip().lower()
    s = s.replace("á", "a").replace("é", "e").replace("í", "i").replace("ó", "o").replace("ú", "u").replace("ñ", "n")
    s = re.sub(r"\s+", "-", s)
    s = _slug_re.sub("", s)
    s = re.sub(r"-{2,}", "-", s).strip("-")
    if not s:
        s = "product"
    return s[:max_len]


# ============================================================
# Many-to-many: Product <-> Tags
# ============================================================

product_tags = db.Table(
    "product_tags",
    db.Column("product_id", db.Integer, db.ForeignKey("products.id", ondelete="CASCADE"), primary_key=True),
    db.Column("tag_id", db.Integer, db.ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
)

# Many-to-many: Product <-> Extra Categories (además de la principal)
product_categories = db.Table(
    "product_categories",
    db.Column("product_id", db.Integer, db.ForeignKey("products.id", ondelete="CASCADE"), primary_key=True),
    db.Column("category_id", db.Integer, db.ForeignKey("categories.id", ondelete="CASCADE"), primary_key=True),
)


# ============================================================
# Models
# ============================================================

class Product(db.Model):
    """
    Skyline Store — Product ULTRA PRO (FINAL)

    ✅ Compatible con tus rutas actuales:
    - shop_routes filtra Product.is_active en SQL -> acá es hybrid_property (NO rompe)
    - cart/checkout usan status, stock_mode, stock_qty y main_image_url()
    - compat legacy: name/title, stock/stock_qty, description/description_html
    """
    __tablename__ = "products"

    id = db.Column(db.Integer, primary_key=True)

    # Core
    title = db.Column(db.String(180), nullable=False)
    slug = db.Column(db.String(200), unique=True, index=True, nullable=False)

    # Descripción
    short_description = db.Column(db.String(260), nullable=True)
    description_html = db.Column(db.Text, nullable=True)

    # Origen / visibilidad
    source = db.Column(db.String(20), nullable=False, default="manual")   # manual/printful/dropship/temu
    status = db.Column(db.String(20), nullable=False, default="draft")    # draft/active/hidden

    # Precios
    currency = db.Column(db.String(3), nullable=False, default="USD")
    price = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    compare_at_price = db.Column(db.Numeric(12, 2), nullable=True)

    # Stock
    stock_mode = db.Column(db.String(20), nullable=False, default="finite")  # finite/unlimited/external
    stock_qty = db.Column(db.Integer, nullable=False, default=0)

    # Categoría principal (opcional)
    category_id = db.Column(db.Integer, db.ForeignKey("categories.id", ondelete="SET NULL"), nullable=True)

    # Dropshipping / externo
    supplier_name = db.Column(db.String(80), nullable=True)
    external_url = db.Column(db.String(500), nullable=True)

    # Printful
    printful_product_id = db.Column(db.String(50), nullable=True, index=True)
    printful_store_id = db.Column(db.String(50), nullable=True)

    # SEO
    seo_title = db.Column(db.String(180), nullable=True)
    seo_description = db.Column(db.String(260), nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow, index=True)

    # relationships
    category = db.relationship("Category", foreign_keys=[category_id], lazy="select")
    extra_categories = db.relationship("Category", secondary=product_categories, lazy="select")
    tags = db.relationship("Tag", secondary=product_tags, lazy="select")
    media = db.relationship(
        "ProductMedia",
        back_populates="product",
        cascade="all, delete-orphan",
        lazy="select",
    )

    # -------------------------
    # Compatibilidad legacy (NO ROMPE CÓDIGO VIEJO)
    # -------------------------
    def __init__(self, **kwargs):
        # name -> title
        if "name" in kwargs and "title" not in kwargs:
            kwargs["title"] = kwargs.pop("name")

        # stock -> stock_qty
        if "stock" in kwargs and "stock_qty" not in kwargs:
            kwargs["stock_qty"] = kwargs.pop("stock")

        # description -> description_html
        if "description" in kwargs and "description_html" not in kwargs:
            kwargs["description_html"] = kwargs.pop("description")

        # slug auto si falta (mejora #1)
        if not kwargs.get("slug") and kwargs.get("title"):
            kwargs["slug"] = slugify(kwargs["title"])

        super().__init__(**kwargs)

    # Back-compat: name
    @property
    def name(self) -> str:
        return self.title

    @name.setter
    def name(self, value: str) -> None:
        self.title = (value or "").strip()

    # Back-compat: stock
    @property
    def stock(self) -> int:
        return int(self.stock_qty or 0)

    @stock.setter
    def stock(self, value: int) -> None:
        try:
            self.stock_qty = int(value or 0)
        except Exception:
            self.stock_qty = 0

    # -------------------------
    # is_active para TUS QUERIES (mejora #2: hybrid_property)
    # -------------------------
    @hybrid_property
    def is_active(self) -> bool:
        return (self.status or "").lower() == "active"

    @is_active.expression
    def is_active(cls):  # type: ignore[override]
        # permite: Product.is_active.is_(True) en SQLAlchemy
        return cls.status == "active"

    # -------------------------
    # Validaciones suaves (no rompen forms)
    # -------------------------
    @validates("title")
    def _v_title(self, _k, v: str) -> str:
        v = (v or "").strip()
        return v[:180] if v else "Producto"

    @validates("slug")
    def _v_slug(self, _k, v: str) -> str:
        v = slugify(v or "")
        return v[:200] if v else "product"

    @validates("currency")
    def _v_currency(self, _k, v: str) -> str:
        v = (v or "USD").strip().upper()
        return v[:3] if len(v) >= 3 else "USD"

    @validates("source")
    def _v_source(self, _k, v: str) -> str:
        v = (v or "manual").strip().lower()
        return v if v in {"manual", "printful", "dropship", "temu"} else "manual"

    @validates("status")
    def _v_status(self, _k, v: str) -> str:
        v = (v or "draft").strip().lower()
        return v if v in {"draft", "active", "hidden"} else "draft"

    @validates("stock_mode")
    def _v_stock_mode(self, _k, v: str) -> str:
        v = (v or "finite").strip().lower()
        return v if v in {"finite", "unlimited", "external"} else "finite"

    @validates("price", "compare_at_price")
    def _v_price(self, _k, v: Any):
        # mejora #3: clamp anti negativos / NaN
        d = _clamp_money(_d(v, "0.00"))
        return d

    # -------------------------
    # Helpers PRO
    # -------------------------
    def is_available(self) -> bool:
        """Disponibilidad real para comprar (mejora #4: consistente con carrito)."""
        if not self.is_active:
            return False
        mode = (self.stock_mode or "finite").lower()
        if mode in {"unlimited", "external"}:
            return True
        return int(self.stock_qty or 0) > 0

    def price_decimal(self) -> Decimal:
        return _d(self.price, "0.00")

    def compare_at_decimal(self) -> Optional[Decimal]:
        if self.compare_at_price is None:
            return None
        d = _d(self.compare_at_price, "0.00")
        return d if d > Decimal("0.00") else None

    def has_discount(self) -> bool:
        ca = self.compare_at_decimal()
        return bool(ca and ca > self.price_decimal())

    def discount_percent(self) -> Optional[int]:
        """% descuento redondeado (mejora #5: seguro)."""
        ca = self.compare_at_decimal()
        p = self.price_decimal()
        if not ca or ca <= 0 or p <= 0 or ca <= p:
            return None
        try:
            return int(((ca - p) / ca) * 100)
        except Exception:
            return None

    def main_image_url(self) -> Optional[str]:
        """Primera imagen por sort_order (mejora #6)."""
        imgs = [m for m in (self.media or []) if (m.type or "").lower() == "image" and (m.url or "").strip()]
        if not imgs:
            return None
        imgs.sort(key=lambda x: (x.sort_order or 0, x.id or 0))
        return imgs[0].url

    def main_video_url(self) -> Optional[str]:
        vids = [m for m in (self.media or []) if (m.type or "").lower() == "video" and (m.url or "").strip()]
        if not vids:
            return None
        vids.sort(key=lambda x: (x.sort_order or 0, x.id or 0))
        return vids[0].url

    def seo_title_final(self, brand: str = "Skyline Store") -> str:
        base = (self.seo_title or self.title or "Producto").strip()
        if brand.lower() in base.lower():
            return base[:180]
        return f"{base} · {brand}"[:180]

    def seo_description_final(self) -> str:
        d = (self.seo_description or self.short_description or "").strip()
        if d:
            return d[:260]
        # fallback “limpio” sin HTML (mejora #7)
        raw = (self.description_html or "").strip()
        raw = re.sub(r"<[^>]+>", " ", raw)
        raw = re.sub(r"\s+", " ", raw).strip()
        return (raw[:260] if raw else "") or ""

    def to_dict(self) -> dict:
        """mejora #8: serializable (admin/API)."""
        return {
            "id": self.id,
            "title": self.title,
            "slug": self.slug,
            "status": self.status,
            "source": self.source,
            "currency": self.currency,
            "price": str(_d(self.price)),
            "compare_at_price": str(_d(self.compare_at_price)) if self.compare_at_price is not None else None,
            "stock_mode": self.stock_mode,
            "stock_qty": int(self.stock_qty or 0),
            "category_id": self.category_id,
            "main_image": self.main_image_url(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<Product id={self.id} title={self.title!r} status={self.status!r}>"


# Índices de performance (tipo marketplace)
db.Index("ix_products_status_source", Product.status, Product.source)
db.Index("ix_products_category_status", Product.category_id, Product.status)
db.Index("ix_products_price", Product.price)
db.Index("ix_products_updated", Product.updated_at)


class ProductMedia(db.Model):
    __tablename__ = "product_media"

    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id", ondelete="CASCADE"), nullable=False, index=True)

    # image | video
    type = db.Column(db.String(10), nullable=False, default="image")

    # upload local (/static/...) o externo (https://...)
    url = db.Column(db.String(700), nullable=False)

    # para videos (opcional)
    poster_url = db.Column(db.String(700), nullable=True)
    alt_text = db.Column(db.String(200), nullable=True)
    sort_order = db.Column(db.Integer, nullable=False, default=0, index=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    product = db.relationship("Product", back_populates="media")

    @validates("type")
    def _v_type(self, _k, v: str) -> str:
        v = (v or "image").strip().lower()
        return v if v in {"image", "video"} else "image"

    @validates("url")
    def _v_url(self, _k, v: str) -> str:
        v = (v or "").strip()
        return v[:700] if v else ""

    def __repr__(self) -> str:
        return f"<ProductMedia id={self.id} product_id={self.product_id} type={self.type!r}>"


class Tag(db.Model):
    __tablename__ = "tags"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False, unique=True)
    slug = db.Column(db.String(100), nullable=False, unique=True, index=True)

    @validates("name")
    def _v_name(self, _k, v: str) -> str:
        v = (v or "").strip()
        return v[:80] if v else "tag"

    @validates("slug")
    def _v_slug(self, _k, v: str) -> str:
        return slugify(v or "tag", max_len=100)

    def __repr__(self) -> str:
        return f"<Tag id={self.id} name={self.name!r}>"


# ============================================================
# Hooks
# ============================================================

@event.listens_for(Product, "before_insert", propagate=True)
def _product_before_insert(_mapper, _conn, target: Product):
    # mejora #9: slug auto si faltó
    if not (target.slug or "").strip():
        target.slug = slugify(target.title or "product")

    # mejora #10: updated_at consistente
    target.updated_at = utcnow()
    if not target.created_at:
        target.created_at = utcnow()


@event.listens_for(Product, "before_update", propagate=True)
def _product_before_update(_mapper, _conn, target: Product):
    # garantía de updated_at (tu hook original, pero blindado)
    target.updated_at = utcnow()
