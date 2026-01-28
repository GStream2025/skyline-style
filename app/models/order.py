from __future__ import annotations

import json
import re
import secrets
import time
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Dict, Iterable, Optional

from sqlalchemy import CheckConstraint, Index, UniqueConstraint, event
from sqlalchemy.orm import validates

from app.models import db

MONEY_2 = Decimal("0.01")
RATE_4 = Decimal("0.0001")
MAX_RATE = Decimal("0.8000")

_TITLE_MAX = 200
_SKU_MAX = 80
_EMAIL_MAX = 255
_PHONE_MAX = 40
_NOTE_MAX = 500
_ADDR_MAX = 200
_CITY_MAX = 80
_STATE_MAX = 80
_POSTAL_MAX = 20
_CARRIER_MAX = 80
_TRACKING_MAX = 120
_TRACKING_URL_MAX = 500

_QTY_MAX = 999
_META_MAX_BYTES = 64_000

_STATUS_MAX = 30
_PROVIDER_MAX = 40
_PROVIDER_PID_MAX = 140
_IDEM_MAX = 80

_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _s(v: Any, n: int) -> str:
    s = "" if v is None else str(v)
    s = s.replace("\x00", "").strip()
    s = _CTRL_RE.sub("", s)
    return s[:n]


def _opt(v: Any, n: int) -> Optional[str]:
    s = _s(v, n)
    s = " ".join(s.split())
    return s or None


def _d(v: Any, default: str = "0.00") -> Decimal:
    try:
        if v is None or v == "":
            return Decimal(default)
        if isinstance(v, Decimal):
            return v
        s = str(v).strip().replace(",", ".")
        return Decimal(s) if s else Decimal(default)
    except (InvalidOperation, ValueError, TypeError):
        return Decimal(default)


def _q_money(dv: Decimal) -> Decimal:
    if dv.is_nan() or dv.is_infinite() or dv < Decimal("0.00"):
        dv = Decimal("0.00")
    return dv.quantize(MONEY_2, rounding=ROUND_HALF_UP)


def _money(v: Any) -> Decimal:
    return _q_money(_d(v, "0.00"))


def _rate(v: Any) -> Decimal:
    d = _d(v, "0.0000")
    if d.is_nan() or d.is_infinite():
        d = Decimal("0.0000")
    if d > Decimal("1.0"):
        d = d / Decimal("100.0")
    if d < Decimal("0.0000"):
        d = Decimal("0.0000")
    if d > MAX_RATE:
        d = MAX_RATE
    return d.quantize(RATE_4, rounding=ROUND_HALF_UP)


def _lower(v: Any, n: int) -> Optional[str]:
    s = _opt(v, n)
    return s.casefold() if s else None


def _upper(v: Any, n: int) -> Optional[str]:
    s = _opt(v, n)
    return s.upper() if s else None


def _slugish(v: Any, n: int) -> Optional[str]:
    s = _lower(v, n)
    if not s:
        return None
    s = s.replace(" ", "-")
    cleaned = "".join(ch for ch in s if ch.isalnum() or ch in {"-", "_"}).strip("-_")
    return cleaned[:n] if cleaned else None


def _canon_currency(v: Any) -> str:
    s = _upper(v, 3) or "USD"
    return s if _CURRENCY_RE.match(s) else "USD"


def _canon_country2(v: Any) -> Optional[str]:
    s = _upper(v, 2)
    return s if s and len(s) == 2 else None


def _meta_merge(base: Any, extra: Optional[dict]) -> dict:
    out: dict = dict(base) if isinstance(base, dict) else {}
    if isinstance(extra, dict):
        for k, vv in extra.items():
            if vv is not None:
                out[str(k)] = vv
    return out


def _safe_json(obj: Any) -> Any:
    try:
        raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)
        if len(raw.encode("utf-8")) > _META_MAX_BYTES:
            return {"_meta_truncated": True}
        return json.loads(raw)
    except Exception:
        return {"_invalid_meta": True}


MetaType = db.JSON().with_variant(db.Text(), "sqlite")


class Order(db.Model):
    __tablename__ = "orders"

    STATUS_AWAITING_PAYMENT = "awaiting_payment"
    STATUS_PAID = "paid"
    STATUS_PROCESSING = "processing"
    STATUS_SHIPPED = "shipped"
    STATUS_DELIVERED = "delivered"
    STATUS_CANCELLED = "cancelled"
    STATUS_REFUNDED = "refunded"

    PAY_PENDING = "pending"
    PAY_PAID = "paid"
    PAY_FAILED = "failed"
    PAY_REFUNDED = "refunded"

    FULFILL_NONE = "none"
    FULFILL_QUEUED = "queued"
    FULFILL_SENT = "sent"
    FULFILL_DONE = "done"
    FULFILL_FAILED = "failed"

    PAYOUT_NONE = "none"
    PAYOUT_PENDING = "pending"
    PAYOUT_PAID = "paid"
    PAYOUT_REVERSED = "reversed"
    PAYOUT_HOLD = "hold"

    PM_PAYPAL = "paypal"
    PM_MP_UY = "mercadopago_uy"
    PM_MP_AR = "mercadopago_ar"
    PM_BANK = "bank_transfer"
    PM_CASH = "cash"
    PM_WISE = "wise"
    PM_PAYONEER = "payoneer"
    PM_PAXUM = "paxum"

    _ALLOWED_STATUS = {
        STATUS_AWAITING_PAYMENT,
        STATUS_PAID,
        STATUS_PROCESSING,
        STATUS_SHIPPED,
        STATUS_DELIVERED,
        STATUS_CANCELLED,
        STATUS_REFUNDED,
    }
    _ALLOWED_PAY_STATUS = {PAY_PENDING, PAY_PAID, PAY_FAILED, PAY_REFUNDED}
    _ALLOWED_FULFILL = {FULFILL_NONE, FULFILL_QUEUED, FULFILL_SENT, FULFILL_DONE, FULFILL_FAILED}
    _ALLOWED_PAYOUT = {PAYOUT_NONE, PAYOUT_PENDING, PAYOUT_PAID, PAYOUT_REVERSED, PAYOUT_HOLD}
    _ALLOWED_PM = {PM_PAYPAL, PM_MP_UY, PM_MP_AR, PM_BANK, PM_CASH, PM_WISE, PM_PAYONEER, PM_PAXUM}

    _ALLOWED_TRANSITIONS = {
        STATUS_AWAITING_PAYMENT: {STATUS_PAID, STATUS_CANCELLED},
        STATUS_PAID: {STATUS_PROCESSING, STATUS_REFUNDED},
        STATUS_PROCESSING: {STATUS_SHIPPED, STATUS_CANCELLED},
        STATUS_SHIPPED: {STATUS_DELIVERED},
        STATUS_DELIVERED: set(),
        STATUS_CANCELLED: set(),
        STATUS_REFUNDED: set(),
    }

    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.String(40), unique=True, index=True, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)

    affiliate_code = db.Column(db.String(80), index=True, nullable=True)
    affiliate_sub = db.Column(db.String(120), index=True, nullable=True)

    commission_rate_applied = db.Column(db.Numeric(6, 4), nullable=False, default=Decimal("0.0000"))
    commission_amount = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    payout_status = db.Column(db.String(20), nullable=False, default=PAYOUT_NONE, index=True)

    idempotency_key = db.Column(db.String(_IDEM_MAX), nullable=True, index=True)
    payment_provider = db.Column(db.String(_PROVIDER_MAX), nullable=True, index=True)
    provider_payment_id = db.Column(db.String(_PROVIDER_PID_MAX), nullable=True, index=True)

    customer_name = db.Column(db.String(120))
    customer_email = db.Column(db.String(_EMAIL_MAX), index=True)
    customer_phone = db.Column(db.String(_PHONE_MAX))

    ship_address1 = db.Column(db.String(_ADDR_MAX))
    ship_address2 = db.Column(db.String(_ADDR_MAX))
    ship_city = db.Column(db.String(_CITY_MAX))
    ship_state = db.Column(db.String(_STATE_MAX))
    ship_postal_code = db.Column(db.String(_POSTAL_MAX))
    ship_country = db.Column(db.String(2))

    customer_note = db.Column(db.String(_NOTE_MAX))
    internal_note = db.Column(db.String(_NOTE_MAX))

    status = db.Column(db.String(_STATUS_MAX), nullable=False, default=STATUS_AWAITING_PAYMENT, index=True)
    payment_method = db.Column(db.String(_STATUS_MAX), nullable=False, default=PM_PAYPAL, index=True)
    payment_status = db.Column(db.String(_STATUS_MAX), nullable=False, default=PAY_PENDING, index=True)
    fulfillment_status = db.Column(db.String(20), nullable=False, default=FULFILL_NONE, index=True)

    currency = db.Column(db.String(3), nullable=False, default="USD", index=True)

    subtotal = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    discount_total = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    shipping_total = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    tax_total = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    total = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))

    paypal_order_id = db.Column(db.String(120), index=True)
    mp_payment_id = db.Column(db.String(120), index=True)
    bank_transfer_ref = db.Column(db.String(120))
    wise_transfer_id = db.Column(db.String(120), index=True)

    carrier = db.Column(db.String(_CARRIER_MAX))
    tracking_number = db.Column(db.String(_TRACKING_MAX), index=True)
    tracking_url = db.Column(db.String(_TRACKING_URL_MAX))

    paid_at = db.Column(db.DateTime(timezone=True), index=True)
    cancelled_at = db.Column(db.DateTime(timezone=True), index=True)
    refunded_at = db.Column(db.DateTime(timezone=True), index=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow, index=True)

    meta = db.Column(MetaType)

    items = db.relationship(
        "OrderItem",
        back_populates="order",
        cascade="all, delete-orphan",
        lazy="select",
        passive_deletes=True,
    )

    __table_args__ = (
        CheckConstraint("subtotal >= 0", name="ck_orders_subtotal_nonneg"),
        CheckConstraint("discount_total >= 0", name="ck_orders_discount_nonneg"),
        CheckConstraint("shipping_total >= 0", name="ck_orders_shipping_nonneg"),
        CheckConstraint("tax_total >= 0", name="ck_orders_tax_nonneg"),
        CheckConstraint("total >= 0", name="ck_orders_total_nonneg"),
        CheckConstraint("commission_rate_applied >= 0", name="ck_orders_comm_rate_nonneg"),
        CheckConstraint("commission_amount >= 0", name="ck_orders_comm_amt_nonneg"),
        CheckConstraint("length(currency) = 3", name="ck_orders_currency_len3"),
        CheckConstraint("(idempotency_key IS NULL) OR (idempotency_key <> '')", name="ck_orders_idem_nonempty"),
        UniqueConstraint("user_id", "idempotency_key", name="uq_orders_user_idem"),
        Index("ix_orders_status_created", "status", "created_at"),
        Index("ix_orders_payment_status_created", "payment_status", "created_at"),
        Index("ix_orders_user_created", "user_id", "created_at"),
        Index("ix_orders_aff_created", "affiliate_code", "created_at"),
        Index("ix_orders_provider_pid", "payment_provider", "provider_payment_id"),
        Index("ix_orders_idem_user", "user_id", "idempotency_key"),
        Index("ix_orders_payout_status_created", "payout_status", "created_at"),
        Index("ix_orders_fulfillment_created", "fulfillment_status", "created_at"),
        Index("ix_orders_currency_created", "currency", "created_at"),
    )

    @staticmethod
    def _make_number() -> str:
        return f"ORD-{int(time.time())}-{secrets.token_hex(4)}"[:40]

    @validates("currency")
    def _v_currency(self, _k: str, v: Any) -> str:
        return _canon_currency(v)

    @validates("ship_country")
    def _v_ship_country(self, _k: str, v: Any) -> Optional[str]:
        return _canon_country2(v)

    @validates("status")
    def _v_status(self, _k: str, v: Any) -> str:
        s = _s(v, _STATUS_MAX).lower()
        return s if s in self._ALLOWED_STATUS else self.STATUS_AWAITING_PAYMENT

    @validates("payment_status")
    def _v_payment_status(self, _k: str, v: Any) -> str:
        s = _s(v, _STATUS_MAX).lower()
        return s if s in self._ALLOWED_PAY_STATUS else self.PAY_PENDING

    @validates("fulfillment_status")
    def _v_fulfillment(self, _k: str, v: Any) -> str:
        s = _s(v, 20).lower()
        return s if s in self._ALLOWED_FULFILL else self.FULFILL_NONE

    @validates("payout_status")
    def _v_payout(self, _k: str, v: Any) -> str:
        s = _s(v, 20).lower()
        return s if s in self._ALLOWED_PAYOUT else self.PAYOUT_NONE

    @validates("payment_method")
    def _v_payment_method(self, _k: str, v: Any) -> str:
        s = _s(v, _STATUS_MAX).lower()
        return s if s in self._ALLOWED_PM else self.PM_PAYPAL

    @validates("customer_email")
    def _v_email(self, _k: str, v: Any) -> Optional[str]:
        s = _lower(v, _EMAIL_MAX)
        if not s:
            return None
        return s if _EMAIL_RE.match(s) else s

    @validates("customer_phone")
    def _v_phone(self, _k: str, v: Any) -> Optional[str]:
        s = _opt(v, _PHONE_MAX)
        if not s:
            return None
        cleaned = "".join(ch for ch in s if ch.isdigit() or ch in "+()- ").strip()
        return cleaned[:_PHONE_MAX] if cleaned else None

    @validates("number")
    def _v_number(self, _k: str, v: Any) -> str:
        s = _opt(v, 40)
        return s if s else self._make_number()

    @validates("affiliate_code")
    def _v_aff(self, _k: str, v: Any) -> Optional[str]:
        return _slugish(v, 80)

    @validates("affiliate_sub")
    def _v_sub(self, _k: str, v: Any) -> Optional[str]:
        return _opt(v, 120)

    @validates("idempotency_key")
    def _v_idem(self, _k: str, v: Any) -> Optional[str]:
        return _slugish(v, _IDEM_MAX)

    @validates("provider_payment_id")
    def _v_ppid(self, _k: str, v: Any) -> Optional[str]:
        return _opt(v, _PROVIDER_PID_MAX)

    @validates("payment_provider")
    def _v_provider(self, _k: str, v: Any) -> Optional[str]:
        return _slugish(v, _PROVIDER_MAX)

    @validates("tracking_number")
    def _v_tracking_number(self, _k: str, v: Any) -> Optional[str]:
        return _opt(v, _TRACKING_MAX)

    @validates("tracking_url")
    def _v_tracking_url(self, _k: str, v: Any) -> Optional[str]:
        return _opt(v, _TRACKING_URL_MAX)

    @validates(
        "customer_name",
        "ship_address1",
        "ship_address2",
        "ship_city",
        "ship_state",
        "ship_postal_code",
        "customer_note",
        "internal_note",
        "bank_transfer_ref",
        "carrier",
    )
    def _v_text_fields(self, _k: str, v: Any) -> Optional[str]:
        limits = {
            "customer_name": 120,
            "ship_address1": _ADDR_MAX,
            "ship_address2": _ADDR_MAX,
            "ship_city": _CITY_MAX,
            "ship_state": _STATE_MAX,
            "ship_postal_code": _POSTAL_MAX,
            "customer_note": _NOTE_MAX,
            "internal_note": _NOTE_MAX,
            "bank_transfer_ref": 120,
            "carrier": _CARRIER_MAX,
        }
        return _opt(v, limits.get(_k, 120))

    @validates("commission_rate_applied")
    def _v_comm_rate(self, _k: str, v: Any) -> Decimal:
        return _rate(v)

    @validates("commission_amount", "subtotal", "discount_total", "shipping_total", "tax_total", "total")
    def _v_money(self, _k: str, v: Any) -> Decimal:
        return _money(v)

    def add_meta(self, **extra: Any) -> None:
        self.meta = _safe_json(_meta_merge(self.meta, extra))

    def touch_updated(self) -> None:
        self.updated_at = utcnow()

    def ensure_number(self) -> None:
        if not (self.number or "").strip():
            self.number = self._make_number()

    def set_payment_provider_id(self, provider: Optional[str], provider_payment_id: Optional[str]) -> None:
        prov = _s(provider, _PROVIDER_MAX).lower()
        pid = _s(provider_payment_id, _PROVIDER_PID_MAX)

        self.payment_provider = prov or None
        self.provider_payment_id = pid or None

        if not prov or not pid:
            return

        if prov == self.PM_PAYPAL:
            self.paypal_order_id = _s(pid, 120) or None
        elif prov.startswith("mercadopago"):
            self.mp_payment_id = _s(pid, 120) or None
        elif prov == self.PM_WISE:
            self.wise_transfer_id = _s(pid, 120) or None

    def recompute_totals(self) -> None:
        sub = Decimal("0.00")
        items: Iterable["OrderItem"] = self.items or []
        for it in items:
            it.recompute_line_total()
            sub += _d(getattr(it, "line_total", None), "0.00")

        subtotal = _money(sub)
        discount = _money(self.discount_total)
        shipping = _money(self.shipping_total)
        tax = _money(self.tax_total)

        if discount > subtotal:
            discount = subtotal

        self.subtotal = subtotal
        self.discount_total = discount
        self.shipping_total = shipping
        self.tax_total = tax

        computed = subtotal - discount + shipping + tax
        if computed < Decimal("0.00"):
            computed = Decimal("0.00")
        self.total = _q_money(computed)

    def can_transition_to(self, to_status: str) -> bool:
        cur = _s(self.status, _STATUS_MAX).lower()
        nxt = _s(to_status, _STATUS_MAX).lower()
        return nxt in self._ALLOWED_TRANSITIONS.get(cur, set())

    def transition_to(self, to_status: str) -> None:
        nxt = _s(to_status, _STATUS_MAX).lower()
        if not self.can_transition_to(nxt):
            raise ValueError(f"Transición inválida: {self.status} -> {nxt}")

        self.status = nxt
        now = utcnow()

        if nxt == self.STATUS_PAID:
            self.paid_at = self.paid_at or now
            self.payment_status = self.PAY_PAID
            if self.fulfillment_status == self.FULFILL_NONE:
                self.fulfillment_status = self.FULFILL_QUEUED

        elif nxt == self.STATUS_CANCELLED:
            self.cancelled_at = self.cancelled_at or now
            if self.payment_status == self.PAY_PENDING:
                self.payment_status = self.PAY_FAILED
            if self.fulfillment_status != self.FULFILL_DONE:
                self.fulfillment_status = self.FULFILL_FAILED

        elif nxt == self.STATUS_REFUNDED:
            self.refunded_at = self.refunded_at or now
            self.payment_status = self.PAY_REFUNDED
            if self.payout_status == self.PAYOUT_PAID:
                self.payout_status = self.PAYOUT_REVERSED

    def mark_paid(self) -> None:
        if self.status != self.STATUS_PAID:
            self.status = self.STATUS_PAID
        self.payment_status = self.PAY_PAID
        self.paid_at = self.paid_at or utcnow()
        if self.fulfillment_status == self.FULFILL_NONE:
            self.fulfillment_status = self.FULFILL_QUEUED

    def mark_cancelled(self) -> None:
        if self.status != self.STATUS_CANCELLED:
            self.status = self.STATUS_CANCELLED
        self.cancelled_at = self.cancelled_at or utcnow()

    def mark_refunded(self) -> None:
        if self.status != self.STATUS_REFUNDED:
            self.status = self.STATUS_REFUNDED
        self.payment_status = self.PAY_REFUNDED
        self.refunded_at = self.refunded_at or utcnow()
        if self.payout_status == self.PAYOUT_PAID:
            self.payout_status = self.PAYOUT_REVERSED

    def apply_commission_snapshot(self, *, sales_in_month: int, rate: Any) -> None:
        r = _rate(rate)
        base = _money(self.total)
        amt = _q_money(base * r)
        self.commission_rate_applied = r
        self.commission_amount = amt
        self.payout_status = self.PAYOUT_PENDING if amt > Decimal("0.00") else self.PAYOUT_NONE
        self.add_meta(
            commission={
                "sales_in_month": int(max(0, int(sales_in_month or 0))),
                "rate": str(r),
                "amount": str(amt),
                "snap_at": utcnow().isoformat(),
            }
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "number": self.number,
            "user_id": self.user_id,
            "status": self.status,
            "payment_status": self.payment_status,
            "payment_method": self.payment_method,
            "fulfillment_status": self.fulfillment_status,
            "currency": self.currency,
            "subtotal": str(_d(self.subtotal)),
            "discount_total": str(_d(self.discount_total)),
            "shipping_total": str(_d(self.shipping_total)),
            "tax_total": str(_d(self.tax_total)),
            "total": str(_d(self.total)),
            "affiliate_code": self.affiliate_code,
            "affiliate_sub": self.affiliate_sub,
            "commission_rate_applied": str(_d(self.commission_rate_applied, "0.0000")),
            "commission_amount": str(_d(self.commission_amount, "0.00")),
            "payout_status": self.payout_status,
            "payment_provider": self.payment_provider,
            "provider_payment_id": self.provider_payment_id,
            "carrier": self.carrier,
            "tracking_number": self.tracking_number,
            "tracking_url": self.tracking_url,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "paid_at": self.paid_at.isoformat() if self.paid_at else None,
            "cancelled_at": self.cancelled_at.isoformat() if self.cancelled_at else None,
            "refunded_at": self.refunded_at.isoformat() if self.refunded_at else None,
            "meta": self.meta if isinstance(self.meta, dict) else None,
        }

    def __repr__(self) -> str:
        return f"<Order {self.number} total={self.total} status={self.status}>"


class OrderItem(db.Model):
    __tablename__ = "order_items"

    id = db.Column(db.Integer, primary_key=True)

    order_id = db.Column(db.Integer, db.ForeignKey("orders.id", ondelete="CASCADE"), nullable=False, index=True)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id", ondelete="SET NULL"), index=True)

    title_snapshot = db.Column(db.String(_TITLE_MAX), nullable=False)
    sku_snapshot = db.Column(db.String(_SKU_MAX))

    currency = db.Column(db.String(3), nullable=False, default="USD")

    unit_price = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    qty = db.Column(db.Integer, nullable=False, default=1)
    line_total = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))

    meta = db.Column(MetaType)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)

    order = db.relationship("Order", back_populates="items", lazy="select")

    __table_args__ = (
        CheckConstraint("qty >= 1", name="ck_order_items_qty_ge_1"),
        CheckConstraint("unit_price >= 0", name="ck_order_items_unit_price_nonneg"),
        CheckConstraint("line_total >= 0", name="ck_order_items_line_total_nonneg"),
        Index("ix_order_items_order_created", "order_id", "created_at"),
        Index("ix_order_items_product_created", "product_id", "created_at"),
    )

    @validates("qty")
    def _v_qty(self, _k: str, v: Any) -> int:
        try:
            n = int(str(v).strip())
        except Exception:
            n = 1
        if n < 1:
            n = 1
        if n > _QTY_MAX:
            n = _QTY_MAX
        return n

    @validates("currency")
    def _v_cur(self, _k: str, v: Any) -> str:
        return _canon_currency(v)

    @validates("title_snapshot")
    def _v_title(self, _k: str, v: Any) -> str:
        s = _opt(v, _TITLE_MAX)
        return s if s else "Producto"

    @validates("sku_snapshot")
    def _v_sku(self, _k: str, v: Any) -> Optional[str]:
        return _opt(v, _SKU_MAX)

    @validates("unit_price", "line_total")
    def _v_money(self, _k: str, v: Any) -> Decimal:
        return _money(v)

    def recompute_line_total(self) -> None:
        qty = int(self.qty or 1)
        if qty < 1:
            qty = 1
        if qty > _QTY_MAX:
            qty = _QTY_MAX
        self.qty = qty
        self.unit_price = _money(self.unit_price)
        self.line_total = _q_money(_d(self.unit_price) * Decimal(qty))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "order_id": self.order_id,
            "product_id": self.product_id,
            "title_snapshot": self.title_snapshot,
            "sku_snapshot": self.sku_snapshot,
            "currency": self.currency,
            "unit_price": str(_d(self.unit_price)),
            "qty": int(self.qty or 1),
            "line_total": str(_d(self.line_total)),
            "meta": self.meta if isinstance(self.meta, dict) else None,
        }

    def __repr__(self) -> str:
        return f"<OrderItem id={self.id} product_id={self.product_id} qty={self.qty}>"


@event.listens_for(OrderItem, "before_insert", propagate=True)
@event.listens_for(OrderItem, "before_update", propagate=True)
def _oi_before_save(_mapper, _connection, target: OrderItem) -> None:
    target.recompute_line_total()


@event.listens_for(Order, "before_insert", propagate=True)
@event.listens_for(Order, "before_update", propagate=True)
def _o_before_save(_mapper, _connection, target: Order) -> None:
    target.ensure_number()
    target.touch_updated()
    if getattr(target, "items", None) is not None:
        target.recompute_totals()


__all__ = ["Order", "OrderItem", "utcnow"]
