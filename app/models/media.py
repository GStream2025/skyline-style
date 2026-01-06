# app/models/media.py
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Any, Dict

from sqlalchemy import ForeignKey, Index
from sqlalchemy.orm import validates

from app.models import db  # ✅ db ÚNICO


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# JSON portable: JSON real en Postgres, TEXT en SQLite
MetaType = db.JSON().with_variant(db.Text(), "sqlite")


class Media(db.Model):
    """
    Skyline Store — Media ULTRA PRO (FINAL)

    Media universal para:
    - galerías de producto (images/videos)
    - banners/hero/home cards
    - assets admin (logos, etc.)
    - thumbnails, posters, etc.

    PRO:
    - UTC timezone-aware
    - meta JSON portable (Postgres/SQLite)
    - soft-delete (deleted_at)
    - mime/size/hash + width/height (opcional)
    - scope (dónde se usa) + kind (tipo de recurso)
    """

    __tablename__ = "media"

    id = db.Column(db.Integer, primary_key=True)

    # Dónde se usa (ej: product, home, hero, banner, category, admin_asset)
    scope = db.Column(db.String(32), nullable=False, default="generic", index=True)

    # Tipo específico (ej: image, video, pdf, logo, hero_bg, product_image)
    kind = db.Column(db.String(32), nullable=False, default="image", index=True)

    # URL externa o path local (ej: /static/uploads/media/xxx.webp)
    url = db.Column(db.String(700), nullable=False)

    # Alternativo / accesibilidad
    alt = db.Column(db.String(180), nullable=True)

    # Relación opcional con producto (si existe)
    product_id = db.Column(
        db.Integer,
        ForeignKey("products.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    # Orden para galerías / sliders
    sort_order = db.Column(db.Integer, nullable=False, default=0)

    # Estado
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)

    # Soft delete
    deleted_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)

    # Metadatos técnicos (opcionales)
    mime_type = db.Column(db.String(120), nullable=True)
    size_bytes = db.Column(db.Integer, nullable=True)
    sha256 = db.Column(db.String(64), nullable=True, index=True)

    width = db.Column(db.Integer, nullable=True)
    height = db.Column(db.Integer, nullable=True)

    # Metadatos flexibles (ej: crop, focal_point, color, poster_url, etc.)
    meta = db.Column(MetaType, nullable=True)

    created_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    # -------------------------
    # Validaciones suaves
    # -------------------------
    @validates("scope", "kind")
    def _v_short(self, _k: str, v: str) -> str:
        v = (v or "").strip().lower()
        return v[:32] if v else "generic"

    @validates("url")
    def _v_url(self, _k: str, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("Media.url es obligatorio.")
        return v[:700]

    @validates("alt")
    def _v_alt(self, _k: str, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        v = v.strip()
        return v[:180]

    # -------------------------
    # Helpers PRO
    # -------------------------
    def soft_delete(self) -> None:
        self.is_active = False
        self.deleted_at = utcnow()

    def restore(self) -> None:
        self.deleted_at = None
        self.is_active = True

    def is_deleted(self) -> bool:
        return self.deleted_at is not None

    def set_meta(self, data: Dict[str, Any]) -> None:
        self.meta = data

    def __repr__(self) -> str:
        return (
            f"<Media id={self.id} scope={self.scope!r} kind={self.kind!r} "
            f"product_id={self.product_id} active={self.is_active} deleted={self.is_deleted()}>"
        )


# Índices PRO para listados rápidos
Index("ix_media_scope_kind_active", Media.scope, Media.kind, Media.is_active)
Index("ix_media_product_sort", Media.product_id, Media.sort_order)
Index("ix_media_created_active", Media.created_at, Media.is_active)
