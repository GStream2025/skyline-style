from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from app import db


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# Many-to-many: Product <-> Tags
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


class Product(db.Model):
    """
    Producto universal:
    - source: manual | printful | dropship
    - status: draft | active | hidden
    - Media: imágenes + videos
    - Variants: talles/colores (si querés escalar)
    """
    __tablename__ = "products"

    id = db.Column(db.Integer, primary_key=True)

    title = db.Column(db.String(180), nullable=False)
    slug = db.Column(db.String(200), unique=True, index=True, nullable=False)

    short_description = db.Column(db.String(260), nullable=True)
    description_html = db.Column(db.Text, nullable=True)  # descripción rica (HTML)

    source = db.Column(db.String(20), nullable=False, default="manual")  # manual/printful/dropship
    status = db.Column(db.String(20), nullable=False, default="draft")  # draft/active/hidden

    # precios (USD base; luego podés convertir a UYU en checkout)
    currency = db.Column(db.String(3), nullable=False, default="USD")
    price = db.Column(db.Numeric(12, 2), nullable=False, default=0)
    compare_at_price = db.Column(db.Numeric(12, 2), nullable=True)  # precio tachado

    # stock
    stock_mode = db.Column(db.String(20), nullable=False, default="finite")  # finite/unlimited/external
    stock_qty = db.Column(db.Integer, nullable=False, default=0)

    # categoría principal (para navegación)
    category_id = db.Column(db.Integer, db.ForeignKey("categories.id", ondelete="SET NULL"), nullable=True)

    # dropshipping
    supplier_name = db.Column(db.String(80), nullable=True)
    external_url = db.Column(db.String(500), nullable=True)

    # printful
    printful_product_id = db.Column(db.String(50), nullable=True, index=True)
    printful_store_id = db.Column(db.String(50), nullable=True)

    # SEO
    seo_title = db.Column(db.String(180), nullable=True)
    seo_description = db.Column(db.String(260), nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)

    # relationships
    category = db.relationship("Category", foreign_keys=[category_id], lazy="select")
    extra_categories = db.relationship("Category", secondary=product_categories, lazy="select")
    tags = db.relationship("Tag", secondary=product_tags, lazy="select")
    media = db.relationship("ProductMedia", back_populates="product", cascade="all, delete-orphan", lazy="select")
# -------------------------
# Compatibilidad legacy
# - Algunos módulos usan `name` en lugar de `title`
# - Otros usan `stock` en lugar de `stock_qty`
# -------------------------
def __init__(self, **kwargs):
    # Soportar name/title
    if "name" in kwargs and "title" not in kwargs:
        kwargs["title"] = kwargs.pop("name")
    # Soportar stock/stock_qty
    if "stock" in kwargs and "stock_qty" not in kwargs:
        kwargs["stock_qty"] = kwargs.pop("stock")
    super().__init__(**kwargs)

@property
def name(self) -> str:
    return self.title

@name.setter
def name(self, value: str) -> None:
    self.title = value

@property
def stock(self) -> int:
    return int(self.stock_qty or 0)

@stock.setter
def stock(self, value: int) -> None:
    self.stock_qty = int(value or 0)

@property
def is_active(self) -> bool:
    return (self.status or "").lower() == "active"

    def is_available(self) -> bool:
        if self.status != "active":
            return False
        if self.stock_mode == "unlimited":
            return True
        if self.stock_mode == "external":
            return True
        return (self.stock_qty or 0) > 0

    def main_image_url(self) -> Optional[str]:
        # devuelve la primera imagen ordenada
        imgs = [m for m in (self.media or []) if m.type == "image"]
        imgs.sort(key=lambda x: x.sort_order or 0)
        return imgs[0].url if imgs else None

    def __repr__(self) -> str:
        return f"<Product id={self.id} title={self.title}>"


class ProductMedia(db.Model):
    __tablename__ = "product_media"

    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id", ondelete="CASCADE"), nullable=False)

    # image | video
    type = db.Column(db.String(10), nullable=False, default="image")

    # Si es upload local: /static/uploads/media/xxx.jpg
    # Si es externo: https://...
    url = db.Column(db.String(700), nullable=False)

    # para videos: opcional poster/thumbnail
    poster_url = db.Column(db.String(700), nullable=True)

    alt_text = db.Column(db.String(200), nullable=True)
    sort_order = db.Column(db.Integer, nullable=False, default=0)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    product = db.relationship("Product", back_populates="media")

    def __repr__(self) -> str:
        return f"<ProductMedia id={self.id} product_id={self.product_id} type={self.type}>"


class Tag(db.Model):
    __tablename__ = "tags"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False, unique=True)
    slug = db.Column(db.String(100), nullable=False, unique=True, index=True)

    def __repr__(self) -> str:
        return f"<Tag id={self.id} name={self.name}>"
