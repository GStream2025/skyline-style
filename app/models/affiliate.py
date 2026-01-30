from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Dict, Mapping, Optional

from sqlalchemy import CheckConstraint, Index, UniqueConstraint
from sqlalchemy.orm import validates

from app.models import db

_EMAIL_RE = re.compile(r"^(?=.{3,254}$)[^@\s]+@[^@\s]+\.[^@\s]+$")
_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_ALLOWED_PAYOUT_METHODS = {"mp", "mercadopago", "paypal", "wise", "bank", "crypto", "manual"}

CODE_MAX = 80
NAME_MAX = 120
SUB_MAX = 120
METHOD_MAX = 30
EMAIL_MAX = 255
IP_MAX = 80
UA_MAX = 300
REF_MAX = 500
META_NOTE_MAX = 2000

RATE_MIN = Decimal("0.0000")
RATE_MAX = Decimal("0.8000")
RATE_Q = Decimal("0.0001")
MONEY_Q = Decimal("0.01")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _s(v: Any) -> str:
    if v is None:
        return ""
    return str(v).replace("\x00", "").strip()


def _to_bool(v: Any, default: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    s = _s(v).lower()
    if not s:
        return default
    return s in _TRUE


def _nfkc_lower(v: Any, max_len: int) -> Optional[str]:
    s = _s(v)
    if not s:
        return None
    s = unicodedata.normalize("NFKC", s).strip().lower()
    if not s:
        return None
    return s[:max_len]


def _nfkc(v: Any, max_len: int) -> Optional[str]:
    s = _s(v)
    if not s:
        return None
    s = unicodedata.normalize("NFKC", s).strip()
    if not s:
        return None
    return s[:max_len]


def _clean_code(v: Any, max_len: int = CODE_MAX) -> str:
    s = _s(v).lower()
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = s.replace(" ", "-")
    s = re.sub(r"[^a-z0-9_-]+", "-", s)
    s = re.sub(r"-{2,}", "-", s).strip("-_")
    return (s[:max_len] if s else "")


def _to_decimal(v: Any, default: Decimal) -> Decimal:
    if v is None or v == "":
        return default
    if isinstance(v, Decimal):
        return v
    s = _s(v).replace(",", ".")
    if not s:
        return default
    try:
        return Decimal(s)
    except (InvalidOperation, ValueError, TypeError):
        return default


def _clamp_quant(v: Decimal, lo: Decimal, hi: Decimal, q: Decimal) -> Decimal:
    if v < lo:
        v = lo
    if v > hi:
        v = hi
    try:
        return v.quantize(q, rounding=ROUND_HALF_UP)
    except Exception:
        return lo.quantize(q, rounding=ROUND_HALF_UP)


def _as_meta(v: Any) -> Optional[Dict[str, Any]]:
    if v is None or v == "":
        return None
    if isinstance(v, dict):
        return dict(v)
    if isinstance(v, Mapping):
        return dict(v)
    s = _s(v)
    if not s:
        return None
    return {"note": s[:META_NOTE_MAX]}


MetaType = db.JSON().with_variant(db.Text(), "sqlite")


class AffiliatePartner(db.Model):
    __tablename__ = "affiliate_partners"

    id = db.Column(db.Integer, primary_key=True)

    code = db.Column(db.String(CODE_MAX), nullable=False, unique=True, index=True)
    name = db.Column(db.String(NAME_MAX), nullable=True)

    active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    commission_rate = db.Column(db.Numeric(6, 4), nullable=False, default=Decimal("0.1000"))

    payout_method = db.Column(db.String(METHOD_MAX), nullable=True)
    payout_email = db.Column(db.String(EMAIL_MAX), nullable=True)

    meta = db.Column(MetaType, nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow, index=True)

    __table_args__ = (
        CheckConstraint("length(code) >= 1", name="ck_aff_partner_code_nonempty"),
        CheckConstraint("commission_rate >= 0", name="ck_aff_partner_rate_nonneg"),
        CheckConstraint("commission_rate <= 0.8000", name="ck_aff_partner_rate_max"),
        UniqueConstraint("code", name="uq_aff_partner_code"),
        Index("ix_aff_partner_active_code", "active", "code"),
        Index("ix_aff_partner_active_created", "active", "created_at"),
    )

    @validates("code")
    def _v_code(self, _k: str, v: Any) -> str:
        c = _clean_code(v, CODE_MAX)
        if not c:
            raise ValueError("Affiliate code inválido/vacío.")
        return c

    @validates("name")
    def _v_name(self, _k: str, v: Any) -> Optional[str]:
        return _nfkc(v, NAME_MAX)

    @validates("active")
    def _v_active(self, _k: str, v: Any) -> bool:
        return _to_bool(v, True)

    @validates("commission_rate")
    def _v_rate(self, _k: str, v: Any) -> Decimal:
        d = _to_decimal(v, Decimal("0.1000"))
        return _clamp_quant(d, RATE_MIN, RATE_MAX, RATE_Q)

    @validates("payout_method")
    def _v_method(self, _k: str, v: Any) -> Optional[str]:
        s = _nfkc_lower(v, METHOD_MAX)
        if not s:
            return None
        return s if s in _ALLOWED_PAYOUT_METHODS else None

    @validates("payout_email")
    def _v_email(self, _k: str, v: Any) -> Optional[str]:
        s = _nfkc_lower(v, EMAIL_MAX)
        if not s:
            return None
        return s if _EMAIL_RE.match(s) else None

    @validates("meta")
    def _v_meta(self, _k: str, v: Any) -> Optional[Dict[str, Any]]:
        return _as_meta(v)

    def is_active(self) -> bool:
        return bool(self.active)

    def commission_percent(self) -> int:
        try:
            return int((_to_decimal(self.commission_rate, Decimal("0.0")) * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
        except Exception:
            return 0

    def calc_commission_amount(self, order_total: Any) -> Decimal:
        total = _to_decimal(order_total, Decimal("0.00"))
        rate = _to_decimal(self.commission_rate, Decimal("0.0000"))
        try:
            return (total * rate).quantize(MONEY_Q, rounding=ROUND_HALF_UP)
        except Exception:
            return Decimal("0.00")

    def meta_get(self, key: str, default: Any = None) -> Any:
        m = self.meta if isinstance(self.meta, dict) else None
        if not m:
            return default
        return m.get(key, default)

    def meta_set(self, key: str, value: Any) -> None:
        base = self.meta if isinstance(self.meta, dict) else {}
        d = dict(base)
        d[str(key)] = value
        self.meta = d

    def touch(self) -> None:
        self.updated_at = utcnow()

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "id": int(self.id or 0),
            "code": self.code,
            "name": self.name,
            "active": bool(self.active),
            "commission_rate": str(self.commission_rate),
            "commission_percent": self.commission_percent(),
            "payout_method": self.payout_method,
        }

    def __repr__(self) -> str:
        return f"<AffiliatePartner id={self.id} code={self.code!r} active={self.active} rate={self.commission_rate}>"


class AffiliateClick(db.Model):
    __tablename__ = "affiliate_clicks"

    id = db.Column(db.Integer, primary_key=True)

    aff_code = db.Column(db.String(CODE_MAX), nullable=False, index=True)
    sub_code = db.Column(db.String(SUB_MAX), nullable=True, index=True)

    product_id = db.Column(db.Integer, db.ForeignKey("products.id", ondelete="SET NULL"), nullable=True, index=True)

    ip = db.Column(db.String(IP_MAX), nullable=True)
    user_agent = db.Column(db.String(UA_MAX), nullable=True)
    referrer = db.Column(db.String(REF_MAX), nullable=True)

    meta = db.Column(MetaType, nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)

    product = db.relationship("Product", lazy="select", foreign_keys=[product_id])

    __table_args__ = (
        CheckConstraint("length(aff_code) >= 1", name="ck_aff_click_aff_nonempty"),
        Index("ix_aff_click_aff_created", "aff_code", "created_at"),
        Index("ix_aff_click_prod_created", "product_id", "created_at"),
        Index("ix_aff_click_aff_sub_created", "aff_code", "sub_code", "created_at"),
    )

    @validates("aff_code")
    def _v_aff(self, _k: str, v: Any) -> str:
        c = _clean_code(v, CODE_MAX)
        if not c:
            raise ValueError("aff_code inválido/vacío.")
        return c

    @validates("sub_code")
    def _v_sub(self, _k: str, v: Any) -> Optional[str]:
        return _nfkc(v, SUB_MAX)

    @validates("ip")
    def _v_ip(self, _k: str, v: Any) -> Optional[str]:
        return _nfkc(v, IP_MAX)

    @validates("user_agent")
    def _v_ua(self, _k: str, v: Any) -> Optional[str]:
        return _nfkc(v, UA_MAX)

    @validates("referrer")
    def _v_ref(self, _k: str, v: Any) -> Optional[str]:
        return _nfkc(v, REF_MAX)

    @validates("meta")
    def _v_meta(self, _k: str, v: Any) -> Optional[Dict[str, Any]]:
        return _as_meta(v)

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
            ip=_nfkc(ip, IP_MAX),
            user_agent=_nfkc(user_agent, UA_MAX),
            referrer=_nfkc(referrer, REF_MAX),
            meta=_as_meta(meta),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": int(self.id or 0),
            "aff_code": self.aff_code,
            "sub_code": self.sub_code,
            "product_id": self.product_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<AffiliateClick id={self.id} aff={self.aff_code!r} product_id={self.product_id}>"
