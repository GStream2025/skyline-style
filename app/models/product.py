# app/models/product.py
from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from flask_sqlalchemy import SQLAlchemy

try:
    from app.extensions import db
except Exception:
    try:
        from app import db
    except Exception:
        db = SQLAlchemy()


class Product(db.Model):
    __tablename__ = "products"

    id = db.Column(db.Integer, primary_key=True)

    # Básico
    title = db.Column(db.String(220), nullable=False)
    slug = db.Column(db.String(240), unique=True, nullable=False)
    description = db.Column(db.Text, default="", nullable=False)

    # Precios
    price = db.Column(db.Numeric(10, 2), default=0, nullable=False)
    compare_at_price = db.Column(db.Numeric(10, 2), nullable=True)
    currency = db.Column(db.String(8), default="UYU", nullable=False)

    # Cat / stock / estado
    category_slug = db.Column(db.String(140), index=True, nullable=True)
    stock = db.Column(db.Integer, default=0, nullable=False)

    status = db.Column(db.String(16), default="active", nullable=False)  # active/draft/archived
    source = db.Column(db.String(24), default="skyline", nullable=False)  # skyline/printful/dropshipping
    external_id = db.Column(db.String(120), nullable=True, index=True)    # id del proveedor
    image_url = db.Column(db.String(520), default="", nullable=False)

    # Extra
    tags = db.Column(db.String(520), default="", nullable=False)  # "streetwear, hoodie, ..."
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def final_price(self) -> Decimal:
        return Decimal(self.price or 0)

    def __repr__(self) -> str:
        return f"<Product {self.id} {self.slug} {self.source}>"
