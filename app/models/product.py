from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Optional

from sqlalchemy import CheckConstraint, Index, event, func, select
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import validates

from app.models import db


_TITLE_MAX = 180
_SLUG_MAX = 200
_SHORT_DESC_MAX = 260
_SEO_TITLE_MAX = 180
_SEO_DESC_MAX = 260
_URL_MAX = 700
_EXT_URL_MAX = 500
_TAG_NAME_MAX = 80
_TAG_SLUG_MAX = 100
_SUPPLIER_MAX = 80
_ALT_MAX = 200

_slug_re = re.compile(r"[^a-z0-9\-]+")
_space_re = re.compile(r"\s+")
_dash_re = re.compile(r"-{2,}")
_strip_tags_re = re.compile(r"<[^>]+>")

_ALLOWED_SOURCE = {"manual", "printful", "dropship", "temu"}
_ALLOWED_STATUS = {"draft", "active", "hidden"}
_ALLOWED_STOCK_MODE = {"finite", "unlimited", "external"}
_ALLOWED_MEDIA_TYPE = {"image", "video"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _clean_text(v: Any, max_len: int, *, default: str = "") -> str:
    if v is None:
        return default
    s = str(v).replace("\x00", "").strip()
    if not s:
        return default
    s = " ".join(s.split())
    return s[:max_len]


def _clean_optional(v: Any, max_len: int) -> Optional[str]:
    s = _clean_text(v, max_len, default="")
    return s or None


def _clamp_int(v: Any, default: int = 0, min_v: int = 0, max_v: int = 1_000_000) -> int:
    try:
        n = int(v)
    except Exception:
        return default
    if n < min_v:
        return min_v
    if n > max_v:
        return max_v
    return n


def _d(v: Any, default: str = "0.00") -> Decimal:
    try:
        if v is None or v == "":
            d = Decimal(default)
        elif isinstance(v, Decimal):
            d = v
        else:
            d = Decimal(str(v))
    except (InvalidOperation, ValueError, TypeError):
        d = Decimal(default)
    try:
        return d.quantize(Decimal("0.01"))
    except Exception:
        return Decimal(default)


def _clamp_money(v: Decimal) -> Decimal:
    d = v if v >= Decimal("0.00") else Decimal("0.00")
    try:
        return d.quantize(Decimal("0.01"))
    except Exception:
        return Decimal("0.00")


def _ascii_fold(s: str) -> str:
    s2 = unicodedata.normalize("NFKD", s)
    return "".join(ch for ch in s2 if not unicodedata.combining(ch))


def slugify(text: str, max_len: int = _SLUG_MAX) -> str:
    s = (text or "").strip().lower()
    if not s:
        return "product"
    s = _ascii_fold(s)
    s = _space_re.sub("-", s)
    s = _slug_re.sub("", s)
    s = _dash_re.sub("-", s).strip("-")
    out = s or "product"
    return out[:max_len]


def _unique_slug(conn, base_slug: str, product_id: Optional[int] = None) -> str:
    base = slugify(base_slug or "product", max_len=_SLUG_MAX) or "product"

    def exists(sl: str) -> bool:
        q = select(func.count(Product.id)).where(Product.slug == sl)
        if product_id:
            q = q.where(Product.id != product_id)
        return (conn.execute(q).scalar() or 0) > 0

    if not exists(base):
        return base

    for i in range(2, 5000):
        suffix = f"-{i}"
        head = base[: max(1, _SLUG_MAX - len(suffix))]
        cand = (head + suffix).strip("-")
        if not exists(cand):
            return cand

    return (base[: max(1, _SLUG_MAX - 2)] + "-x")[:_SLUG_MAX]


product_tags = db.Table(
    "product_tags",
    db.Column("product_id", db.Integer, db.ForeignKey("products.id", ondelete="CASCADE"), primary_key=True),
    db.Column("tag_id", db.Integer, db.ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
    Index("ix_product_tags_product", "product_id"),
    Index("ix_product_tags_tag", "tag_id"),
)

product_categories = db.Table(
    "product_categories",
    db.Column("product_id", db.Integer, db.ForeignKey("products.id", ondelete="CASCADE"), primary_key=True),
    db.Column("category_id", db.Integer, db.ForeignKey("categories.id", ondelete="CASCADE"), primary_key=True),
    Index("ix_product_categories_product", "product_id"),
    Index("ix_product_categories_category", "category_id"),
)


class Product(db.Model):
    __tablename__ = "products"

    id = db.Column(db.Integer, primary_key=True)

    title = db.Column(db.String(_TITLE_MAX), nullable=False)
    slug = db.Column(db.String(_SLUG_MAX), unique=True, index=True, nullable=False)

    short_description = db.Column(db.String(_SHORT_DESC_MAX), nullable=True)
    description_html = db.Column(db.Text, nullable=True)

    source = db.Column(db.String(20), nullable=False, default="manual")
    status = db.Column(db.String(20), nullable=False, default="draft")

    currency = db.Column(db.String(3), nullable=False, default="USD")
    price = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    compare_at_price = db.Column(db.Numeric(12, 2), nullable=True)

    stock_mode = db.Column(db.String(20), nullable=False, default="finite")
    stock_qty = db.Column(db.Integer, nullable=False, default=0)

    category_id = db.Column(db.Integer, db.ForeignKey("categories.id", ondelete="SET NULL"), nullable=True)

    supplier_name = db.Column(db.String(_SUPPLIER_MAX), nullable=True)
    external_url = db.Column(db.String(_EXT_URL_MAX), nullable=True)

    printful_product_id = db.Column(db.String(50), nullable=True, index=True)
    printful_store_id = db.Column(db.String(50), nullable=True)

    seo_title = db.Column(db.String(_SEO_TITLE_MAX), nullable=True)
    seo_description = db.Column(db.String(_SEO_DESC_MAX), nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow, index=True)

    category = db.relationship("Category", foreign_keys=[category_id], lazy="select")
    extra_categories = db.relationship("Category", secondary=product_categories, lazy="select")
    tags = db.relationship("Tag", secondary=product_tags, lazy="select")

    media = db.relationship(
        "ProductMedia",
        back_populates="product",
        cascade="all, delete-orphan",
        lazy="select",
    )

    __table_args__ = (
        CheckConstraint("stock_qty >= 0", name="ck_products_stock_nonneg"),
        CheckConstraint("price >= 0", name="ck_products_price_nonneg"),
        CheckConstraint("(compare_at_price IS NULL) OR (compare_at_price >= 0)", name="ck_products_compare_nonneg"),
        CheckConstraint("length(currency) = 3", name="ck_products_currency_len3"),
        Index("ix_products_status_source", "status", "source", "id"),
        Index("ix_products_category_status", "category_id", "status", "id"),
        Index("ix_products_price", "price", "id"),
        Index("ix_products_updated", "updated_at", "id"),
        Index("ix_products_printful_ids", "printful_product_id", "printful_store_id"),
    )

    def __init__(self, **kwargs):
        if "name" in kwargs and "title" not in kwargs:
            kwargs["title"] = kwargs.pop("name")
        if "stock" in kwargs and "stock_qty" not in kwargs:
            kwargs["stock_qty"] = kwargs.pop("stock")
        if "description" in kwargs and "description_html" not in kwargs:
            kwargs["description_html"] = kwargs.pop("description")
        if not kwargs.get("slug") and kwargs.get("title"):
            kwargs["slug"] = slugify(str(kwargs["title"]), max_len=_SLUG_MAX)
        super().__init__(**kwargs)

    @property
    def name(self) -> str:
        return self.title

    @name.setter
    def name(self, value: str) -> None:
        self.title = _clean_text(value, _TITLE_MAX, default="Producto")

    @property
    def stock(self) -> int:
        return int(self.stock_qty or 0)

    @stock.setter
    def stock(self, value: int) -> None:
        self.stock_qty = _clamp_int(value, default=0, min_v=0, max_v=1_000_000)

    @hybrid_property
    def is_active(self) -> bool:
        return (self.status or "").strip().lower() == "active"

    @is_active.expression
    def is_active(cls):  # type: ignore[override]
        return func.lower(func.coalesce(cls.status, "")) == "active"

    @validates("title")
    def _v_title(self, _k, v: Any) -> str:
        return _clean_text(v, _TITLE_MAX, default="Producto")

    @validates("slug")
    def _v_slug(self, _k, v: Any) -> str:
        return slugify(str(v or ""), max_len=_SLUG_MAX) or "product"

    @validates("currency")
    def _v_currency(self, _k, v: Any) -> str:
        s = _clean_text(v or "USD", 3, default="USD").upper()
        return s if len(s) == 3 else "USD"

    @validates("source")
    def _v_source(self, _k, v: Any) -> str:
        s = _clean_text(v or "manual", 20, default="manual").lower()
        return s if s in _ALLOWED_SOURCE else "manual"

    @validates("status")
    def _v_status(self, _k, v: Any) -> str:
        s = _clean_text(v or "draft", 20, default="draft").lower()
        return s if s in _ALLOWED_STATUS else "draft"

    @validates("stock_mode")
    def _v_stock_mode(self, _k, v: Any) -> str:
        s = _clean_text(v or "finite", 20, default="finite").lower()
        return s if s in _ALLOWED_STOCK_MODE else "finite"

    @validates("stock_qty")
    def _v_stock_qty(self, _k, v: Any) -> int:
        return _clamp_int(v, default=0, min_v=0, max_v=1_000_000)

    @validates("price", "compare_at_price")
    def _v_price(self, _k, v: Any):
        return _clamp_money(_d(v, "0.00"))

    @validates("external_url")
    def _v_external_url(self, _k, v: Any) -> Optional[str]:
        s = _clean_text(v, _EXT_URL_MAX, default="")
        return s or None

    @validates("supplier_name")
    def _v_supplier(self, _k, v: Any) -> Optional[str]:
        return _clean_optional(v, _SUPPLIER_MAX)

    @validates("short_description")
    def _v_short(self, _k, v: Any) -> Optional[str]:
        return _clean_optional(v, _SHORT_DESC_MAX)

    @validates("seo_title")
    def _v_seo_title(self, _k, v: Any) -> Optional[str]:
        return _clean_optional(v, _SEO_TITLE_MAX)

    @validates("seo_description")
    def _v_seo_desc(self, _k, v: Any) -> Optional[str]:
        return _clean_optional(v, _SEO_DESC_MAX)

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
        items = [m for m in (self.media or []) if (m.type or "").lower() == "image" and (m.url or "").strip()]
        if not items:
            return None
        items.sort(key=lambda x: (x.sort_order or 0, x.id or 0))
        return items[0].url

    def main_video_url(self) -> Optional[str]:
        items = [m for m in (self.media or []) if (m.type or "").lower() == "video" and (m.url or "").strip()]
        if not items:
            return None
        items.sort(key=lambda x: (x.sort_order or 0, x.id or 0))
        return items[0].url

    def seo_title_final(self, brand: str = "Skyline Store") -> str:
        base = (self.seo_title or self.title or "Producto").strip()
        if brand and brand.lower() in base.lower():
            return base[:_SEO_TITLE_MAX]
        return f"{base} · {brand}"[:_SEO_TITLE_MAX]

    def seo_description_final(self) -> str:
        d = (self.seo_description or self.short_description or "").strip()
        if d:
            return d[:_SEO_DESC_MAX]
        raw = (self.description_html or "").replace("\x00", "").strip()
        raw = _strip_tags_re.sub(" ", raw)
        raw = " ".join(raw.split()).strip()
        return (raw[:_SEO_DESC_MAX] if raw else "") or ""

    def to_dict(self) -> Dict[str, Any]:
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
            "main_video": self.main_video_url(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return f"<Product id={self.id} title={self.title!r} status={self.status!r}>"


class ProductMedia(db.Model):
    __tablename__ = "product_media"

    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id", ondelete="CASCADE"), nullable=False, index=True)

    type = db.Column(db.String(10), nullable=False, default="image")
    url = db.Column(db.String(_URL_MAX), nullable=False)
    poster_url = db.Column(db.String(_URL_MAX), nullable=True)
    alt_text = db.Column(db.String(_ALT_MAX), nullable=True)
    sort_order = db.Column(db.Integer, nullable=False, default=0, index=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    product = db.relationship("Product", back_populates="media")

    __table_args__ = (
        CheckConstraint("sort_order >= -1000000 AND sort_order <= 1000000", name="ck_product_media_sort_range"),
        Index("ix_product_media_product_sort", "product_id", "sort_order", "id"),
        Index("ix_product_media_type", "type", "id"),
    )

    @validates("type")
    def _v_type(self, _k, v: Any) -> str:
        s = _clean_text(v or "image", 10, default="image").lower()
        return s if s in _ALLOWED_MEDIA_TYPE else "image"

    @validates("url")
    def _v_url(self, _k, v: Any) -> str:
        s = _clean_text(v, _URL_MAX, default="")
        if not s:
            raise ValueError("ProductMedia.url empty")
        return s

    @validates("poster_url")
    def _v_poster(self, _k, v: Any) -> Optional[str]:
        return _clean_optional(v, _URL_MAX)

    @validates("alt_text")
    def _v_alt(self, _k, v: Any) -> Optional[str]:
        return _clean_optional(v, _ALT_MAX)

    @validates("sort_order")
    def _v_sort(self, _k, v: Any) -> int:
        return _clamp_int(v, default=0, min_v=-1_000_000, max_v=1_000_000)

    def __repr__(self) -> str:
        return f"<ProductMedia id={self.id} product_id={self.product_id} type={self.type!r}>"


class Tag(db.Model):
    __tablename__ = "tags"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(_TAG_NAME_MAX), nullable=False, unique=True)
    slug = db.Column(db.String(_TAG_SLUG_MAX), nullable=False, unique=True, index=True)

    __table_args__ = (
        Index("ix_tags_slug", "slug"),
    )

    @validates("name")
    def _v_name(self, _k, v: Any) -> str:
        s = _clean_text(v, _TAG_NAME_MAX, default="tag")
        return s or "tag"

    @validates("slug")
    def _v_slug(self, _k, v: Any) -> str:
        return slugify(str(v or "tag"), max_len=_TAG_SLUG_MAX)

    def __repr__(self) -> str:
        return f"<Tag id={self.id} name={self.name!r}>"


@event.listens_for(Product, "before_insert", propagate=True)
def _product_before_insert(_mapper, conn, target: Product):
    target.title = _clean_text(target.title, _TITLE_MAX, default="Producto")

    base = (target.slug or "").strip() or (target.title or "product")
    target.slug = slugify(base, max_len=_SLUG_MAX)
    target.slug = _unique_slug(conn, target.slug)

    now = utcnow()
    target.updated_at = now
    if not target.created_at:
        target.created_at = now


@event.listens_for(Product, "before_update", propagate=True)
def _product_before_update(_mapper, conn, target: Product):
    target.title = _clean_text(target.title, _TITLE_MAX, default="Producto")

    base = (target.slug or "").strip() or (target.title or "product")
    target.slug = slugify(base, max_len=_SLUG_MAX)
    target.slug = _unique_slug(conn, target.slug, product_id=target.id)

    target.updated_at = utcnow()


__all__ = [
    "Product",
    "ProductMedia",
    "Tag",
    "product_tags",
    "product_categories",
    "slugify",
    "utcnow",
]
