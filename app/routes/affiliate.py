# app/models/affiliate.py
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional, Any

from sqlalchemy import Index
from sqlalchemy.orm import validates

from app.models import db  # ✅ db ÚNICO (app/models/__init__.py)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _d(v: Any, default: str = "0.0000") -> Decimal:
    """Decimal seguro (comisiones, montos)."""
    try:
        if v is None or v == "":
            return Decimal(default)
        if isinstance(v, Decimal):
            return v
        return Decimal(str(v))
    except Exception:
        return Decimal(default)


# JSON portable: JSON real en Postgres, TEXT en SQLite
MetaType = db.JSON().with_variant(db.Text(), "sqlite")


# ============================================================
# Affiliate Partner
# ============================================================

class AffiliatePartner(db.Model):
    """
    Skyline Store — Affiliates ULTRA PRO (FINAL)

    ✅ Diseñado para afiliados tipo marketplace (Temu-like):
    - code único (ej: "partner123") => se usa en links ?aff=partner123
    - active para pausar sin borrar historial
    - comisión Decimal (0.1000 = 10%)
    - payout opcional
    - meta JSON (notas internas, condiciones, ids externos, etc.)
    - índices pro para búsqueda y performance
    """

    __tablename__ = "affiliate_partners"

    id = db.Column(db.Integer, primary_key=True)

    # Identidad afiliado
    code = db.Column(db.String(80), unique=True, index=True, nullable=False)
    name = db.Column(db.String(120), nullable=True)

    # Estado
    active = db.Column(db.Boolean, nullable=False, default=True, index=True)

    # comisión (0.1000 = 10%)
    commission_rate = db.Column(db.Numeric(6, 4), nullable=False, default=Decimal("0.1000"))

    # payout opcional
    payout_method = db.Column(db.String(30), nullable=True)   # paypal/mp/bank/etc
    payout_email = db.Column(db.String(255), nullable=True)

    # metadatos flexibles
    meta = db.Column(MetaType, nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow, index=True)

    # -------------------------
    # Validaciones suaves
    # -------------------------
    @validates("code")
    def _v_code(self, _k: str, v: str) -> str:
        # code estable (lo usan links). Recomendación: solo a-z0-9-_.
        s = (v or "").strip().lower()
        s = s.replace(" ", "-")
        # limpiado simple y seguro
        cleaned = "".join(ch for ch in s if ch.isalnum() or ch in {"-", "_"})
        return (cleaned[:80] if cleaned else "")

    @validates("name")
    def _v_name(self, _k: str, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        s = v.strip()
        return s[:120] if s else None

    @validates("commission_rate")
    def _v_commission(self, _k: str, v: Any) -> Decimal:
        # clamp 0%..80% por seguridad (evita errores/abuso)
        rate = _d(v, "0.1000")
        if rate < Decimal("0.0000"):
            rate = Decimal("0.0000")
        if rate > Decimal("0.8000"):
            rate = Decimal("0.8000")
        # normaliza a 4 decimales
        return rate.quantize(Decimal("0.0001"))

    @validates("payout_method")
    def _v_method(self, _k: str, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        s = v.strip().lower()
        return s[:30] if s else None

    @validates("payout_email")
    def _v_email(self, _k: str, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        return v.strip().lower()[:255]

    # -------------------------
    # Helpers PRO
    # -------------------------
    def is_active(self) -> bool:
        return bool(self.active)

    def commission_percent(self) -> int:
        """0.1000 -> 10"""
        try:
            return int((_d(self.commission_rate) * 100).quantize(Decimal("1")))
        except Exception:
            return 0

    def __repr__(self) -> str:
        return f"<AffiliatePartner id={self.id} code={self.code!r} active={self.active} rate={self.commission_rate}>"


# Índices pro (consultas típicas)
Index("ix_aff_partners_active_created", AffiliatePartner.active, AffiliatePartner.created_at)
Index("ix_aff_partners_code_active", AffiliatePartner.code, AffiliatePartner.active)


# ============================================================
# Affiliate Click (tracking)
# ============================================================

class AffiliateClick(db.Model):
    """
    Skyline Store — AffiliateClick ULTRA PRO (FINAL)

    ✅ Tracking de clicks (para atribución y analítica):
    - aff_code + sub_code (campaña)
    - product_id opcional
    - ip, user_agent, referrer
    - meta JSON (utm params, raw payload, etc.)
    - índices pro para dashboards
    """

    __tablename__ = "affiliate_clicks"

    id = db.Column(db.Integer, primary_key=True)

    # Identificadores (compat: tu API ya usa aff_code/sub_code)
    aff_code = db.Column(db.String(80), nullable=False, index=True)
    sub_code = db.Column(db.String(120), nullable=True, index=True)

    # Producto (opcional)
    product_id = db.Column(
        db.Integer,
        db.ForeignKey("products.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Datos request
    ip = db.Column(db.String(80), nullable=True)
    user_agent = db.Column(db.String(300), nullable=True)
    referrer = db.Column(db.String(500), nullable=True)

    # meta flexible (utm_source, utm_campaign, etc.)
    meta = db.Column(MetaType, nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)

    # relationships (opcionales; no rompen si no los usás)
    product = db.relationship("Product", lazy="select", foreign_keys=[product_id])

    # -------------------------
    # Validaciones suaves
    # -------------------------
    @validates("aff_code")
    def _v_aff(self, _k: str, v: str) -> str:
        s = (v or "").strip().lower()
        s = s.replace(" ", "-")
        cleaned = "".join(ch for ch in s if ch.isalnum() or ch in {"-", "_"})
        return (cleaned[:80] if cleaned else "")

    @validates("sub_code")
    def _v_sub(self, _k: str, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        s = v.strip()
        return s[:120] if s else None

    @validates("ip")
    def _v_ip(self, _k: str, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        s = v.strip()
        return s[:80] if s else None

    @validates("user_agent")
    def _v_ua(self, _k: str, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        s = v.strip()
        return s[:300] if s else None

    @validates("referrer")
    def _v_ref(self, _k: str, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        s = v.strip()
        return s[:500] if s else None

    def __repr__(self) -> str:
        return f"<AffiliateClick id={self.id} aff={self.aff_code!r} product_id={self.product_id}>"


# Índices PRO (dashboards / analítica)
Index("ix_aff_clicks_aff_created", AffiliateClick.aff_code, AffiliateClick.created_at)
Index("ix_aff_clicks_prod_created", AffiliateClick.product_id, AffiliateClick.created_at)
Index("ix_aff_clicks_aff_sub_created", AffiliateClick.aff_code, AffiliateClick.sub_code, AffiliateClick.created_at)
