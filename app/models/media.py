from __future__ import annotations

from datetime import datetime

from app import db


class Media(db.Model):
    """
    Media: imágenes/archivos asociados a productos, banners, etc.
    - Útil para: galería de producto, hero, banners, assets subidos por admin, etc.
    """
    __tablename__ = "media"

    id = db.Column(db.Integer, primary_key=True)

    # tipo de media (product_image, banner, avatar, etc.)
    kind = db.Column(db.String(32), nullable=False, default="generic", index=True)

    # URL externa o path local (ej: /static/img/banners/hero_home.png)
    url = db.Column(db.String(512), nullable=False)

    # texto alternativo / descripción
    alt = db.Column(db.String(140), nullable=True)

    # relación opcional con producto (si tu Product existe)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=True, index=True)

    # orden para galerías
    sort = db.Column(db.Integer, nullable=False, default=0)

    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<Media id={self.id} kind={self.kind} product_id={self.product_id} active={self.is_active}>"
