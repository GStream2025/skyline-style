from __future__ import annotations

import re
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Optional

from sqlalchemy import Index, event, select, func
from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property

from app.models import db  # db único


# ============================================================
# Helpers
# ============================================================

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
    """Slug simple, estable, portable (sin dependencias)."""
    s = (text or "").strip().lower()
    s = (
        s.replace("á", "a").replace("é", "e").replace("í", "i")
         .replace("ó", "o").replace("ú", "u").replace("ñ", "n")
    )
    s = re.sub(r"\s+", "-", s)
    s = _slug_re.sub("", s)
    s = re.sub(r"-{2,}", "-", s).strip("-")
    if not s:
        s = "product"
    return s[:max_len]


def _unique_slug(conn, base_slug: str, product_id: Optional[int] = None) -> str:
    """
    Genera slug único en DB (evita choques).
    - Usa suffix -2, -3, ...
    - No requiere dependencias.
    """
    base_slug = (base_slug or "product").strip()[:180] or "product"
    candidate = base_slug

    # EXISTS query portable
    def exists(sl: str) -> bool:
        q = select(func.count(Product.id)).where(Product.slug == sl)
        if product_id:
            q = q.where(Product.id != product_id)
        return (conn.execute(q).scalar() or 0) > 0

    if not exists(candidate):
        return candidate

    # prueba con sufijos
    for i in range(2, 5000):
        suffix = f"-{i}"
        candidate = (base_slug[: (200 - len(suffix))] + suffix).strip("-")
        if not exists(candidate):
            return candidate

    # ultra fallback (muy raro)
    return base_slug[:190] + "-x"


# ============================================================
# Many-to-many
# ============================================================

product_tags = db.Table(
    "product_tags",
    db.Column("product_id", db.Integer, db.ForeignKey("products.id", ondelete="CASCADE"), primary_key=True),
    db.Column("tag_id", db.Integer, db.ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
)

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
    Skyline Store — Product PRO (FINAL)

    ✅ Compat rutas actuales:
    - filtros por Product.is_active (SQL) -> hybrid_property OK
    - cart/checkout usan status, stock_mode, stock_qty + main_image_url()
    - legacy: name/title, stock/stock_qty, description/description_html
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

    # Relationships
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
    # Compat legacy (NO rompe)
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

        # slug si falta
        if not kwargs.get("slug") and kwargs.get("title"):
            kwargs["slug"] = slugify(kwargs["title"])

        super().__init__(**kwargs)

    @property
    def name(self) -> str:
        return self.title

    @name.setter
    def name(self, value: str) -> None:
        self.title = (value or "").strip()

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
    # is_active (Python + SQL)
    # -------------------------
    @hybrid_property
    def is_active(self) -> bool:
        return (self.status or "").lower() == "active"

    @is_active.expression
    def is_active(cls):  # type: ignore[override]
        return cls.status == "active"

    # -------------------------
    # Validaciones suaves
    # -------------------------
    @validates("title")
    def _v_title(self, _k, v: str) -> str:
        v = (v or "").strip()
        return v[:180] if v else "Producto"

    @validates("slug")
    def _v_slug(self, _k, v: str) -> str:
        # OJO: acá solo normaliza, la unicidad la resuelven hooks con DB
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
        return _clamp_money(_d(v, "0.00"))

    # -------------------------
    # Helpers PRO
    # -------------------------
    def is_available(self) -> bool:
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
        ca = self.compare_at_decimal()
        p = self.price_decimal()
        if not ca or ca <= 0 or p <= 0 or ca <= p:
            return None
        try:
            return int(((ca - p) / ca) * 100)
        except Exception:
            return None

    def main_image_url(self) -> Optional[str]:
        imgs = [
            m for m in (self.media or [])
            if (m.type or "").lower() == "image" and (m.url or "").strip()
        ]
        if not imgs:
            return None
        imgs.sort(key=lambda x: (x.sort_order or 0, x.id or 0))
        return imgs[0].url

    def main_video_url(self) -> Optional[str]:
        vids = [
            m for m in (self.media or [])
            if (m.type or "").lower() == "video" and (m.url or "").strip()
        ]
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
        raw = (self.description_html or "").strip()
        raw = re.sub(r"<[^>]+>", " ", raw)
        raw = re.sub(r"\s+", " ", raw).strip()
        return (raw[:260] if raw else "") or ""

    def to_dict(self) -> dict:
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
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return f"<Product id={self.id} title={self.title!r} status={self.status!r}>"


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
        if not v:
            # mejor fallar acá con mensaje claro antes que explotar en DB
            raise ValueError("ProductMedia.url no puede estar vacío")
        return v[:700]

    @validates("alt_text")
    def _v_alt(self, _k, v: Optional[str]) -> Optional[str]:
        v = (v or "").strip()
        return v[:200] if v else None

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
def _product_before_insert(_mapper, conn, target: Product):
    # slug base
    if not (target.slug or "").strip():
        target.slug = slugify(target.title or "product")
    else:
        target.slug = slugify(target.slug)

    # asegurar unicidad
    target.slug = _unique_slug(conn, target.slug)

    # timestamps
    now = utcnow()
    target.updated_at = now
    if not target.created_at:
        target.created_at = now


@event.listens_for(Product, "before_update", propagate=True)
def _product_before_update(_mapper, conn, target: Product):
    # si cambia title y slug quedó vacío, lo regeneramos
    if not (target.slug or "").strip():
        target.slug = slugify(target.title or "product")
    else:
        target.slug = slugify(target.slug)

    # asegurar unicidad (excluye el mismo id)
    target.slug = _unique_slug(conn, target.slug, product_id=target.id)

    target.updated_at = utcnow()


# ============================================================
# Índices PRO (marketplace)
# ============================================================

Index("ix_products_status_source", Product.status, Product.source)
Index("ix_products_category_status", Product.category_id, Product.status)
Index("ix_products_price", Product.price)
Index("ix_products_updated", Product.updated_at)
