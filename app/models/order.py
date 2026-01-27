from __future__ import annotations

import json
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


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _d(v: Any, default: str = "0.00") -> Decimal:
    try:
        if v is None or v == "":
            return Decimal(default)
        if isinstance(v, Decimal):
            return v
        return Decimal(str(v))
    except (InvalidOperation, ValueError, TypeError):
        return Decimal(default)


def _q_money(dv: Decimal) -> Decimal:
    if dv.is_nan() or dv.is_infinite() or dv < Decimal("0.00"):
        dv = Decimal("0.00")
    return dv.quantize(MONEY_2, rounding=ROUND_HALF_UP)


def _money(v: Any) -> Decimal:
    return _q_money(_d(v, "0.00"))


def _rate(v: Any) -> Decimal:
    dv = _d(v, "0.0000")
    if dv.is_nan() or dv.is_infinite():
        dv = Decimal("0.0000")
    if dv < Decimal("0.0000"):
        dv = Decimal("0.0000")
    if dv > MAX_RATE:
        dv = MAX_RATE
    return dv.quantize(RATE_4, rounding=ROUND_HALF_UP)


def _clip_str(v: Any, n: int) -> Optional[str]:
    if v is None:
        return None
    s = str(v).replace("\x00", "").strip()
    if not s:
        return None
    s = " ".join(s.split())
    return s[:n]


def _lower_clip(v: Any, n: int) -> Optional[str]:
    s = _clip_str(v, n)
    return s.lower() if s else None


def _upper_clip(v: Any, n: int) -> Optional[str]:
    s = _clip_str(v, n)
    return s.upper() if s else None


def _slugish(v: Any, n: int) -> Optional[str]:
    s = _lower_clip(v, n)
    if not s:
        return None
    s = s.replace(" ", "-")
    cleaned = "".join(ch for ch in s if ch.isalnum() or ch in {"-", "_"}).strip("-_")
    return cleaned[:n] if cleaned else None


def _canon_currency(v: Any) -> str:
    s = (str(v).strip().upper() if v is not None else "USD")[:3]
    return s if len(s) == 3 else "USD"


def _canon_country2(v: Any) -> Optional[str]:
    s = _upper_clip(v, 2)
    return s if s and len(s) == 2 else None


def _meta_merge(base: Any, extra: Optional[dict]) -> dict:
    out: dict = dict(base) if isinstance(base, dict) else {}
    if isinstance(extra, dict):
        for k, v in extra.items():
            if v is not None:
                out[k] = v
    return out


def _safe_json(obj: Any) -> Any:
    try:
        json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
        return obj
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

    idempotency_key = db.Column(db.String(80), nullable=True, index=True)
    payment_provider = db.Column(db.String(40), nullable=True, index=True)
    provider_payment_id = db.Column(db.String(140), nullable=True, index=True)

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

    status = db.Column(db.String(30), nullable=False, default=STATUS_AWAITING_PAYMENT, index=True)
    payment_method = db.Column(db.String(30), nullable=False, default=PM_PAYPAL, index=True)
    payment_status = db.Column(db.String(30), nullable=False, default=PAY_PENDING, index=True)
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
        UniqueConstraint("user_id", "idempotency_key", name="uq_orders_user_idem"),
        Index("ix_orders_status_created", "status", "created_at"),
        Index("ix_orders_payment_status_created", "payment_status", "created_at"),
        Index("ix_orders_user_created", "user_id", "created_at"),
        Index("ix_orders_aff_created", "affiliate_code", "created_at"),
        Index("ix_orders_provider_pid", "payment_provider", "provider_payment_id"),
        Index("ix_orders_idem_user", "user_id", "idempotency_key"),
        Index("ix_orders_payout_status_created", "payout_status", "created_at"),
        Index("ix_orders_fulfillment_created", "fulfillment_status", "created_at"),
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
        s = (str(v or "")).strip().lower()
        return s if s in self._ALLOWED_STATUS else self.STATUS_AWAITING_PAYMENT

    @validates("payment_status")
    def _v_payment_status(self, _k: str, v: Any) -> str:
        s = (str(v or "")).strip().lower()
        return s if s in self._ALLOWED_PAY_STATUS else self.PAY_PENDING

    @validates("fulfillment_status")
    def _v_fulfillment(self, _k: str, v: Any) -> str:
        s = (str(v or "")).strip().lower()
        return s if s in self._ALLOWED_FULFILL else self.FULFILL_NONE

    @validates("payout_status")
    def _v_payout(self, _k: str, v: Any) -> str:
        s = (str(v or "")).strip().lower()
        return s if s in self._ALLOWED_PAYOUT else self.PAYOUT_NONE

    @validates("payment_method")
    def _v_payment_method(self, _k: str, v: Any) -> str:
        s = (str(v or "")).strip().lower()
        return s if s in self._ALLOWED_PM else self.PM_PAYPAL

    @validates("customer_email")
    def _v_email(self, _k: str, v: Any) -> Optional[str]:
        return _lower_clip(v, _EMAIL_MAX)

    @validates("customer_phone")
    def _v_phone(self, _k: str, v: Any) -> Optional[str]:
        s = _clip_str(v, _PHONE_MAX)
        if not s:
            return None
        cleaned = "".join(ch for ch in s if ch.isdigit() or ch in "+()- ").strip()
        return cleaned[:_PHONE_MAX] if cleaned else None

    @validates("number")
    def _v_number(self, _k: str, v: Any) -> str:
        s = (str(v or "")).strip()
        return (s[:40] if s else self._make_number())

    @validates("affiliate_code")
    def _v_aff(self, _k: str, v: Any) -> Optional[str]:
        return _slugish(v, 80)

    @validates("affiliate_sub")
    def _v_sub(self, _k: str, v: Any) -> Optional[str]:
        return _clip_str(v, 120)

    @validates("idempotency_key")
    def _v_idem(self, _k: str, v: Any) -> Optional[str]:
        return _slugish(v, 80)

    @validates("provider_payment_id")
    def _v_ppid(self, _k: str, v: Any) -> Optional[str]:
        return _clip_str(v, 140)

    @validates("payment_provider")
    def _v_provider(self, _k: str, v: Any) -> Optional[str]:
        return _slugish(v, 40)

    @validates("tracking_number")
    def _v_tracking_number(self, _k: str, v: Any) -> Optional[str]:
        return _clip_str(v, _TRACKING_MAX)

    @validates("tracking_url")
    def _v_tracking_url(self, _k: str, v: Any) -> Optional[str]:
        return _clip_str(v, _TRACKING_URL_MAX)

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
        return _clip_str(v, limits.get(_k, 120))

    def add_meta(self, **extra: Any) -> None:
        merged = _meta_merge(self.meta, extra)
        self.meta = _safe_json(merged)

    def touch_updated(self) -> None:
        self.updated_at = utcnow()

    def ensure_number(self) -> None:
        if not (self.number or "").strip():
            self.number = self._make_number()

    def set_payment_provider_id(self, provider: Optional[str], provider_payment_id: Optional[str]) -> None:
        prov = (provider or "").strip().lower()
        pid = (provider_payment_id or "").strip()
        self.payment_provider = (prov[:40] if prov else None)
        self.provider_payment_id = (pid[:140] if pid else None)

        if not prov or not pid:
            return

        if prov == self.PM_PAYPAL:
            self.paypal_order_id = pid[:120]
        elif prov.startswith("mercadopago"):
            self.mp_payment_id = pid[:120]
        elif prov == self.PM_WISE:
            self.wise_transfer_id = pid[:120]

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

        computed = _d(subtotal) - _d(discount) + _d(shipping) + _d(tax)
        if computed < Decimal("0.00"):
            computed = Decimal("0.00")
        self.total = _q_money(computed)

    def can_transition_to(self, to_status: str) -> bool:
        cur = (self.status or "").strip().lower()
        nxt = (to_status or "").strip().lower()
        return nxt in self._ALLOWED_TRANSITIONS.get(cur, set())

    def transition_to(self, to_status: str) -> None:
        nxt = (to_status or "").strip().lower()
        if not self.can_transition_to(nxt):
            raise ValueError(f"Transición inválida: {self.status} -> {nxt}")

        self.status = nxt
        now = utcnow()

        if nxt == self.STATUS_PAID:
            if not self.paid_at:
                self.paid_at = now
            self.payment_status = self.PAY_PAID
            if self.fulfillment_status == self.FULFILL_NONE:
                self.fulfillment_status = self.FULFILL_QUEUED

        elif nxt == self.STATUS_CANCELLED:
            if not self.cancelled_at:
                self.cancelled_at = now
            if self.payment_status == self.PAY_PENDING:
                self.payment_status = self.PAY_FAILED
            if self.fulfillment_status != self.FULFILL_DONE:
                self.fulfillment_status = self.FULFILL_FAILED

        elif nxt == self.STATUS_REFUNDED:
            if not self.refunded_at:
                self.refunded_at = now
            self.payment_status = self.PAY_REFUNDED
            if self.payout_status == self.PAYOUT_PAID:
                self.payout_status = self.PAYOUT_REVERSED

    def mark_paid(self) -> None:
        if self.status != self.STATUS_PAID:
            self.status = self.STATUS_PAID
        self.payment_status = self.PAY_PAID
        if not self.paid_at:
            self.paid_at = utcnow()
        if self.fulfillment_status == self.FULFILL_NONE:
            self.fulfillment_status = self.FULFILL_QUEUED

    def mark_cancelled(self) -> None:
        if self.status != self.STATUS_CANCELLED:
            self.status = self.STATUS_CANCELLED
        if not self.cancelled_at:
            self.cancelled_at = utcnow()

    def mark_refunded(self) -> None:
        if self.status != self.STATUS_REFUNDED:
            self.status = self.STATUS_REFUNDED
        self.payment_status = self.PAY_REFUNDED
        if not self.refunded_at:
            self.refunded_at = utcnow()
        if self.payout_status == self.PAYOUT_PAID:
            self.payout_status = self.PAYOUT_REVERSED

    def apply_commission_snapshot(self, *, sales_in_month: int, rate: Any) -> None:
        r = _rate(rate)
        base = _money(self.total)
        amt = _q_money(base * r)
        self.commission_rate_applied = r
        self.commission_amount = amt
        self.payout_status = self.PAYOUT_PENDING if amt > Decimal("0.00") else self.PAYOUT_NONE
        snap = {
            "sales_in_month": int(max(0, int(sales_in_month or 0))),
            "rate": str(r),
            "amount": str(amt),
            "snap_at": utcnow().isoformat(),
        }
        self.add_meta(commission=snap)

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
            n = int(v)
        except Exception:
            n = 1
        if n < 1:
            n = 1
        if n > 999:
            n = 999
        return n

    @validates("currency")
    def _v_cur(self, _k: str, v: Any) -> str:
        return _canon_currency(v)

    @validates("title_snapshot")
    def _v_title(self, _k: str, v: Any) -> str:
        s = _clip_str(v, _TITLE_MAX)
        return s if s else "Producto"

    @validates("sku_snapshot")
    def _v_sku(self, _k: str, v: Any) -> Optional[str]:
        return _clip_str(v, _SKU_MAX)

    def recompute_line_total(self) -> None:
        self.unit_price = _money(self.unit_price)
        qty = int(self.qty or 1)
        if qty < 1:
            qty = 1
        if qty > 999:
            qty = 999
        self.qty = qty
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
        try:
            target.recompute_totals()
        except Exception:
            pass


__all__ = ["Order", "OrderItem", "utcnow"]
