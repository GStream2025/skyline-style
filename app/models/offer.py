from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Index,
)
from sqlalchemy.orm import relationship, validates

from app.models import db


# ============================================================
# Time helper
# ============================================================

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ============================================================
# Offer
# ============================================================

class Offer(db.Model):
    """
    Skyline Store — Offer ULTRA PRO (FINAL)

    Sirve para:
    - Banners / cards en home y secciones
    - Promos generales (sin producto)
    - Descuentos reales por producto
    - CTA + media (imagen o video)
    - Programación por fechas
    - Orden, activación y theming
    """

    __tablename__ = "offers"

    # -------------------------
    # Identidad / control
    # -------------------------
    id = db.Column(db.Integer, primary_key=True)

    active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    sort_order = db.Column(db.Integer, nullable=False, default=0, index=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)

    # -------------------------
    # Contenido visible (UI)
    # -------------------------
    title = db.Column(db.String(80), nullable=False)
    subtitle = db.Column(db.String(120), nullable=True)
    badge = db.Column(db.String(24), nullable=True)

    # Media (imagen o video)
    media_url = db.Column(db.String(255), nullable=True)

    # CTA
    cta_text = db.Column(db.String(30), nullable=True)
    cta_url = db.Column(db.String(240), nullable=True)

    # Tema visual (auto / amber / emerald / sky / rose / slate)
    theme = db.Column(db.String(20), nullable=False, default="auto")

    # -------------------------
    # Descuento real (opcional)
    # -------------------------
    # none | percent | amount
    discount_type = db.Column(db.String(16), nullable=False, default="none")
    discount_value = db.Column(db.Numeric(10, 2), nullable=False, default=Decimal("0.00"))

    # Vigencia (opcional)
    starts_at = db.Column(db.DateTime(timezone=True), nullable=True)
    ends_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # -------------------------
    # Asociación opcional
    # -------------------------
    # NULL => oferta general (home / banners)
    product_id = db.Column(
        db.Integer,
        db.ForeignKey("products.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    product = relationship("Product", lazy="joined")

    # ============================================================
    # Validaciones suaves (NO rompen forms)
    # ============================================================

    @validates("discount_type")
    def _v_discount_type(self, _k, v: str) -> str:
        v = (v or "none").strip().lower()
        return v if v in {"none", "percent", "amount"} else "none"

    @validates("theme")
    def _v_theme(self, _k, v: str) -> str:
        v = (v or "auto").strip().lower()
        return v if v in {"auto", "amber", "emerald", "sky", "rose", "slate"} else "auto"

    @validates("title")
    def _v_title(self, _k, v: str) -> str:
        v = (v or "").strip()
        return v[:80] if v else "Oferta"

    @validates("badge")
    def _v_badge(self, _k, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        v = v.strip()
        return v[:24] if v else None

    # ============================================================
    # Helpers PRO (UI + lógica)
    # ============================================================

    def is_live(self, now: Optional[datetime] = None) -> bool:
        """
        Determina si la oferta está activa y dentro del rango de fechas.
        """
        if not self.active:
            return False

        now = now or utcnow()

        if self.starts_at and now < self.starts_at:
            return False
        if self.ends_at and now > self.ends_at:
            return False

        return True

    def has_discount(self) -> bool:
        return self.discount_type != "none" and self.discount_value > 0

    def discount_label(self, currency: str = "$") -> Optional[str]:
        """
        Etiqueta lista para UI:
        -20%
        -$500
        """
        if not self.has_discount():
            return None

        v = self.discount_value

        if self.discount_type == "percent":
            if v == v.to_integral():
                return f"-{int(v)}%"
            return f"-{v.normalize()}%"

        if self.discount_type == "amount":
            if v == v.to_integral():
                return f"-{currency}{int(v)}"
            return f"-{currency}{v.normalize()}"

        return None

    def applies_to_product(self, product_id: int) -> bool:
        """
        True si:
        - oferta general (product_id=None)
        - o coincide con el producto
        """
        return self.product_id is None or self.product_id == product_id

    def __repr__(self) -> str:
        return (
            f"<Offer id={self.id} active={self.active} "
            f"title={self.title!r} discount={self.discount_type}:{self.discount_value}>"
        )


# ============================================================
# Índices de performance (home + shop)
# ============================================================

Index("ix_offers_active_sort", Offer.active, Offer.sort_order)
Index("ix_offers_starts_ends", Offer.starts_at, Offer.ends_at)
Index("ix_offers_product", Offer.product_id)
