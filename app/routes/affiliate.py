# app/models/affiliate.py
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional, Any, Dict

import re

from sqlalchemy import Index, CheckConstraint, UniqueConstraint
from sqlalchemy.orm import validates

from app.models import db  # ✅ db ÚNICO (app/models/__init__.py)


# ============================================================
# Utils
# ============================================================

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


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


def _clamp_decimal(v: Decimal, lo: str, hi: str, q: str) -> Decimal:
    """Clamp + quantize seguro."""
    try:
        lo_d = Decimal(lo)
        hi_d = Decimal(hi)
        if v < lo_d:
            v = lo_d
        if v > hi_d:
            v = hi_d
        return v.quantize(Decimal(q))
    except Exception:
        # fallback ultra safe
        return Decimal(lo).quantize(Decimal(q))


def _clean_code(v: str, max_len: int = 80) -> str:
    """code estable para links: solo a-z0-9-_ (sin espacios)."""
    s = (v or "").strip().lower()
    s = s.replace(" ", "-")
    cleaned = "".join(ch for ch in s if ch.isalnum() or ch in {"-", "_"})
    return cleaned[:max_len] if cleaned else ""


def _safe_meta(meta: Any) -> Optional[Dict[str, Any]]:
    """Asegura meta como dict JSON-friendly (o None)."""
    if meta is None or meta == "":
        return None
    if isinstance(meta, dict):
        return meta
    # Si llega string u otra cosa rara, lo guardamos como nota
    try:
        return {"note": str(meta)[:2000]}
    except Exception:
        return None


# JSON portable: JSON real en Postgres, TEXT en SQLite
MetaType = db.JSON().with_variant(db.Text(), "sqlite")


# ============================================================
# Affiliate Partner
# ============================================================


class AffiliatePartner(db.Model):
    """
    Skyline Store — Affiliates ULTRA PRO (v2)

    ✅ AffiliatePartner = afiliado activo para links ?aff=CODE
    - code único y estable
    - comisión Decimal
    - payout opcional
    - meta JSON portable
    - índices + constraints
    """

    __tablename__ = "affiliate_partners"

    id = db.Column(db.Integer, primary_key=True)

    # Identidad afiliado
    code = db.Column(db.String(80), unique=True, index=True, nullable=False)
    name = db.Column(db.String(120), nullable=True)

    # Estado
    active = db.Column(db.Boolean, nullable=False, default=True, index=True)

    # comisión (0.1000 = 10%)
    commission_rate = db.Column(
        db.Numeric(6, 4), nullable=False, default=Decimal("0.1000")
    )

    # payout opcional
    payout_method = db.Column(db.String(30), nullable=True)  # paypal/mp/bank/etc
    payout_email = db.Column(db.String(255), nullable=True)

    # metadatos flexibles
    meta = db.Column(MetaType, nullable=True)

    created_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
        index=True,
    )

    __table_args__ = (
        # ✅ evita comisiones negativas o absurdas a nivel DB también
        CheckConstraint(
            "commission_rate >= 0", name="ck_aff_partner_commission_nonneg"
        ),
        CheckConstraint(
            "commission_rate <= 0.8000", name="ck_aff_partner_commission_max"
        ),
        # ✅ code no vacío (en DB)
        CheckConstraint("length(code) >= 1", name="ck_aff_partner_code_nonempty"),
        UniqueConstraint("code", name="uq_aff_partner_code"),
    )

    # -------------------------
    # Validaciones suaves (pero seguras)
    # -------------------------
    @validates("code")
    def _v_code(self, _k: str, v: str) -> str:
        cleaned = _clean_code(v, 80)
        # ✅ no permitir vacío (evita rows rotas)
        if not cleaned:
            raise ValueError("Affiliate code inválido/vacío.")
        return cleaned

    @validates("name")
    def _v_name(self, _k: str, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        s = v.strip()
        return s[:120] if s else None

    @validates("commission_rate")
    def _v_commission(self, _k: str, v: Any) -> Decimal:
        # clamp 0%..80% + normaliza 4 decimales
        rate = _d(v, "0.1000")
        return _clamp_decimal(rate, "0.0000", "0.8000", "0.0001")

    @validates("payout_method")
    def _v_method(self, _k: str, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        s = v.strip().lower()[:30]
        return s or None

    @validates("payout_email")
    def _v_email(self, _k: str, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        s = v.strip().lower()[:255]
        # ✅ si no es email válido, lo anulamos (no rompe)
        if not _EMAIL_RE.match(s):
            return None
        return s

    @validates("meta")
    def _v_meta(self, _k: str, v: Any) -> Optional[Dict[str, Any]]:
        return _safe_meta(v)

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

    def calc_commission_amount(self, order_total: Any) -> Decimal:
        """Devuelve monto comisión = total * rate (Decimal seguro)."""
        total = _d(order_total, "0.00")
        rate = _d(self.commission_rate, "0.0000")
        try:
            return (total * rate).quantize(Decimal("0.01"))
        except Exception:
            return Decimal("0.00")

    def meta_get(self, key: str, default: Any = None) -> Any:
        try:
            if isinstance(self.meta, dict):
                return self.meta.get(key, default)
        except Exception:
            pass
        return default

    def meta_set(self, key: str, value: Any) -> None:
        d = self.meta if isinstance(self.meta, dict) else {}
        d = dict(d)  # copy safe
        d[key] = value
        self.meta = d

    def touch(self) -> None:
        """Fuerza updated_at sin depender de flush."""
        try:
            self.updated_at = utcnow()
        except Exception:
            pass

    def __repr__(self) -> str:
        return f"<AffiliatePartner id={self.id} code={self.code!r} active={self.active} rate={self.commission_rate}>"


# Índices pro (consultas típicas)
Index(
    "ix_aff_partners_active_created",
    AffiliatePartner.active,
    AffiliatePartner.created_at,
)
Index("ix_aff_partners_code_active", AffiliatePartner.code, AffiliatePartner.active)


# ============================================================
# Affiliate Click (tracking)
# ============================================================


class AffiliateClick(db.Model):
    """
    Skyline Store — AffiliateClick ULTRA PRO (v2)

    ✅ Tracking de clicks:
    - aff_code + sub_code (campaña)
    - product_id opcional
    - ip, user_agent, referrer
    - meta JSON (utm params)
    """

    __tablename__ = "affiliate_clicks"

    id = db.Column(db.Integer, primary_key=True)

    # Identificadores
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

    created_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )

    # relationships (opcionales)
    product = db.relationship("Product", lazy="select", foreign_keys=[product_id])

    __table_args__ = (
        CheckConstraint("length(aff_code) >= 1", name="ck_aff_click_aff_nonempty"),
    )

    # -------------------------
    # Validaciones suaves
    # -------------------------
    @validates("aff_code")
    def _v_aff(self, _k: str, v: str) -> str:
        cleaned = _clean_code(v, 80)
        if not cleaned:
            raise ValueError("aff_code inválido/vacío.")
        return cleaned

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

    @validates("meta")
    def _v_meta(self, _k: str, v: Any) -> Optional[Dict[str, Any]]:
        return _safe_meta(v)

    # -------------------------
    # Helpers PRO
    # -------------------------
    @staticmethod
    def from_request(
        aff_code: str,
        *,
        sub_code: Optional[str] = None,
        product_id: Optional[int] = None,
        ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        referrer: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> "AffiliateClick":
        """
        Factory pro: crea objeto click con normalización.
        (Ideal para usar desde routes/middleware).
        """
        c = AffiliateClick(
            aff_code=aff_code,
            sub_code=(sub_code or None),
            product_id=product_id,
            ip=(ip or None),
            user_agent=(user_agent or None),
            referrer=(referrer or None),
            meta=_safe_meta(meta),
        )
        return c

    def __repr__(self) -> str:
        return f"<AffiliateClick id={self.id} aff={self.aff_code!r} product_id={self.product_id}>"


# Índices PRO (dashboards / analítica)
Index("ix_aff_clicks_aff_created", AffiliateClick.aff_code, AffiliateClick.created_at)
Index(
    "ix_aff_clicks_prod_created", AffiliateClick.product_id, AffiliateClick.created_at
)
Index(
    "ix_aff_clicks_aff_sub_created",
    AffiliateClick.aff_code,
    AffiliateClick.sub_code,
    AffiliateClick.created_at,
)
