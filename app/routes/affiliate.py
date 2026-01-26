from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Mapping, Optional

from sqlalchemy import CheckConstraint, Index, UniqueConstraint
from sqlalchemy.orm import validates

from app.models import db

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _to_decimal(v: Any, default: str = "0.0000") -> Decimal:
    try:
        if v is None or v == "":
            return Decimal(default)
        if isinstance(v, Decimal):
            return v
        s = str(v).strip().replace(",", ".")
        if not s:
            return Decimal(default)
        return Decimal(s)
    except (InvalidOperation, ValueError, TypeError):
        return Decimal(default)
    except Exception:
        return Decimal(default)


def _clamp_quant(v: Decimal, lo: str, hi: str, q: str) -> Decimal:
    try:
        lo_d = Decimal(lo)
        hi_d = Decimal(hi)
        if v < lo_d:
            v = lo_d
        if v > hi_d:
            v = hi_d
        return v.quantize(Decimal(q))
    except Exception:
        return Decimal(lo).quantize(Decimal(q))


def _clean_code(v: str, max_len: int = 80) -> str:
    s = (v or "").strip().lower().replace(" ", "-")
    s = "".join(ch for ch in s if ch.isalnum() or ch in {"-", "_"})
    s = s.strip("-_")
    return (s[:max_len] if s else "")


def _clean_text(v: Any, max_len: int) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    return (s[:max_len] if s else None)


def _clean_text_lower(v: Any, max_len: int) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip().lower()
    return (s[:max_len] if s else None)


def _as_dict(v: Any) -> Optional[Dict[str, Any]]:
    if v is None or v == "":
        return None
    if isinstance(v, dict):
        return v
    if isinstance(v, Mapping):
        return dict(v)
    try:
        return {"note": str(v)[:2000]}
    except Exception:
        return None


MetaType = db.JSON().with_variant(db.Text(), "sqlite")


class AffiliatePartner(db.Model):
    __tablename__ = "affiliate_partners"

    id = db.Column(db.Integer, primary_key=True)

    code = db.Column(db.String(80), unique=True, index=True, nullable=False)
    name = db.Column(db.String(120), nullable=True)

    active = db.Column(db.Boolean, nullable=False, default=True, index=True)

    commission_rate = db.Column(db.Numeric(6, 4), nullable=False, default=Decimal("0.1000"))

    payout_method = db.Column(db.String(30), nullable=True)
    payout_email = db.Column(db.String(255), nullable=True)

    meta = db.Column(MetaType, nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow, index=True)

    __table_args__ = (
        CheckConstraint("commission_rate >= 0", name="ck_aff_partner_commission_nonneg"),
        CheckConstraint("commission_rate <= 0.8000", name="ck_aff_partner_commission_max"),
        CheckConstraint("length(code) >= 1", name="ck_aff_partner_code_nonempty"),
        UniqueConstraint("code", name="uq_aff_partner_code"),
        Index("ix_aff_partners_active_created", "active", "created_at"),
        Index("ix_aff_partners_code_active", "code", "active"),
    )

    @validates("code")
    def _v_code(self, _k: str, v: str) -> str:
        cleaned = _clean_code(v, 80)
        if not cleaned:
            raise ValueError("Affiliate code inválido/vacío.")
        return cleaned

    @validates("name")
    def _v_name(self, _k: str, v: Any) -> Optional[str]:
        return _clean_text(v, 120)

    @validates("active")
    def _v_active(self, _k: str, v: Any) -> bool:
        if isinstance(v, bool):
            return v
        s = str(v).strip().lower()
        return s in {"1", "true", "yes", "y", "on", "checked"}

    @validates("commission_rate")
    def _v_commission(self, _k: str, v: Any) -> Decimal:
        rate = _to_decimal(v, "0.1000")
        return _clamp_quant(rate, "0.0000", "0.8000", "0.0001")

    @validates("payout_method")
    def _v_method(self, _k: str, v: Any) -> Optional[str]:
        s = _clean_text_lower(v, 30)
        return s or None

    @validates("payout_email")
    def _v_email(self, _k: str, v: Any) -> Optional[str]:
        s = _clean_text_lower(v, 255)
        if not s:
            return None
        return s if _EMAIL_RE.match(s) else None

    @validates("meta")
    def _v_meta(self, _k: str, v: Any) -> Optional[Dict[str, Any]]:
        return _as_dict(v)

    def is_active(self) -> bool:
        return bool(self.active)

    def commission_percent(self) -> int:
        try:
            return int((_to_decimal(self.commission_rate) * 100).quantize(Decimal("1")))
        except Exception:
            return 0

    def calc_commission_amount(self, order_total: Any) -> Decimal:
        total = _to_decimal(order_total, "0.00")
        rate = _to_decimal(self.commission_rate, "0.0000")
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
        base = self.meta if isinstance(self.meta, dict) else {}
        d = dict(base)
        d[str(key)] = value
        self.meta = d

    def touch(self) -> None:
        try:
            self.updated_at = utcnow()
        except Exception:
            pass

    def __repr__(self) -> str:
        return f"<AffiliatePartner id={self.id} code={self.code!r} active={self.active} rate={self.commission_rate}>"


class AffiliateClick(db.Model):
    __tablename__ = "affiliate_clicks"

    id = db.Column(db.Integer, primary_key=True)

    aff_code = db.Column(db.String(80), nullable=False, index=True)
    sub_code = db.Column(db.String(120), nullable=True, index=True)

    product_id = db.Column(
        db.Integer,
        db.ForeignKey("products.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    ip = db.Column(db.String(80), nullable=True)
    user_agent = db.Column(db.String(300), nullable=True)
    referrer = db.Column(db.String(500), nullable=True)

    meta = db.Column(MetaType, nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)

    product = db.relationship("Product", lazy="select", foreign_keys=[product_id])

    __table_args__ = (
        CheckConstraint("length(aff_code) >= 1", name="ck_aff_click_aff_nonempty"),
        Index("ix_aff_clicks_aff_created", "aff_code", "created_at"),
        Index("ix_aff_clicks_prod_created", "product_id", "created_at"),
        Index("ix_aff_clicks_aff_sub_created", "aff_code", "sub_code", "created_at"),
    )

    @validates("aff_code")
    def _v_aff(self, _k: str, v: str) -> str:
        cleaned = _clean_code(v, 80)
        if not cleaned:
            raise ValueError("aff_code inválido/vacío.")
        return cleaned

    @validates("sub_code")
    def _v_sub(self, _k: str, v: Any) -> Optional[str]:
        return _clean_text(v, 120)

    @validates("ip")
    def _v_ip(self, _k: str, v: Any) -> Optional[str]:
        return _clean_text(v, 80)

    @validates("user_agent")
    def _v_ua(self, _k: str, v: Any) -> Optional[str]:
        return _clean_text(v, 300)

    @validates("referrer")
    def _v_ref(self, _k: str, v: Any) -> Optional[str]:
        return _clean_text(v, 500)

    @validates("meta")
    def _v_meta(self, _k: str, v: Any) -> Optional[Dict[str, Any]]:
        return _as_dict(v)

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
        return AffiliateClick(
            aff_code=aff_code,
            sub_code=sub_code or None,
            product_id=product_id,
            ip=_clean_text(ip, 80),
            user_agent=_clean_text(user_agent, 300),
            referrer=_clean_text(referrer, 500),
            meta=_as_dict(meta),
        )

    def __repr__(self) -> str:
        return f"<AffiliateClick id={self.id} aff={self.aff_code!r} product_id={self.product_id}>"
