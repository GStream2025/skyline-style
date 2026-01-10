# app/models/order.py — Skyline Store (ULTRA PRO++ / FINAL / NO BREAK)
from __future__ import annotations

import time
import secrets
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Optional, Any, Dict, Iterable

from sqlalchemy import Index, CheckConstraint, event, UniqueConstraint
from sqlalchemy.orm import validates

from app.models import db

# ============================================================
# Time / Decimal helpers (blindados + consistentes)
# ============================================================

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _d(v: Any, default: str = "0.00") -> Decimal:
    """Decimal seguro (None, '', floats, basura)."""
    try:
        if v is None or v == "":
            return Decimal(default)
        if isinstance(v, Decimal):
            return v
        return Decimal(str(v))
    except (InvalidOperation, ValueError, TypeError):
        return Decimal(default)

def _money(v: Any) -> Decimal:
    """Money >=0 y con 2 decimales."""
    dv = _d(v, "0.00")
    if dv < Decimal("0.00"):
        dv = Decimal("0.00")
    return dv.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

def _rate(v: Any) -> Decimal:
    """Rate 0..0.8000 con 4 decimales (comisiones)."""
    dv = _d(v, "0.0000")
    if dv < Decimal("0.0000"):
        dv = Decimal("0.0000")
    if dv > Decimal("0.8000"):
        dv = Decimal("0.8000")
    return dv.quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP)

def _clip_str(v: Any, n: int) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    return s[:n] if s else None

def _meta(base: Optional[dict], extra: Optional[dict]) -> dict:
    out = dict(base or {})
    for k, v in (extra or {}).items():
        if v is not None:
            out[k] = v
    return out

# JSON portable: JSON real en Postgres, TEXT en SQLite
MetaType = db.JSON().with_variant(db.Text(), "sqlite")


# ============================================================
# Order
# ============================================================

class Order(db.Model):
    """
    Skyline Store — Order (ULTRA PRO++ / FINAL / ZERO-CRASH++)

    +10 mejoras nuevas (sin migraciones obligatorias):
    1) Generación segura de number si falta (más robusta que time()).
    2) Unicidad de idempotency por (user_id, idempotency_key) (si existe).
    3) Normaliza currency estricta 3 letras.
    4) Normaliza tracking_url segura (corta / limpia).
    5) set_payment_provider_id(): actualiza provider + provider_payment_id + legacy (mp/paypal/wise).
    6) recompute_totals() idempotente + tolera items iterables.
    7) Totales: clamp + coherencia (total nunca < subtotal-desc).
    8) Guard rails de transiciones: si PAID -> set paid_at; si CANCELLED/REFUNDED set timestamps.
    9) Snapshot shipping-country upper ISO2.
    10) to_dict() más completo (sin romper compat).
    """

    __tablename__ = "orders"

    # -------------------------
    # Estados de orden
    # -------------------------
    STATUS_AWAITING_PAYMENT = "awaiting_payment"
    STATUS_PAID = "paid"
    STATUS_PROCESSING = "processing"
    STATUS_SHIPPED = "shipped"
    STATUS_DELIVERED = "delivered"
    STATUS_CANCELLED = "cancelled"
    STATUS_REFUNDED = "refunded"

    # -------------------------
    # Estados de pago
    # -------------------------
    PAY_PENDING = "pending"
    PAY_PAID = "paid"
    PAY_FAILED = "failed"
    PAY_REFUNDED = "refunded"

    # -------------------------
    # Fulfillment (opcional)
    # -------------------------
    FULFILL_NONE = "none"
    FULFILL_QUEUED = "queued"
    FULFILL_SENT = "sent"
    FULFILL_DONE = "done"
    FULFILL_FAILED = "failed"

    # -------------------------
    # Payout afiliado (opcional)
    # -------------------------
    PAYOUT_NONE = "none"
    PAYOUT_PENDING = "pending"
    PAYOUT_PAID = "paid"
    PAYOUT_REVERSED = "reversed"
    PAYOUT_HOLD = "hold"

    # -------------------------
    # Métodos de pago
    # -------------------------
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

    # -------------------------
    # Core
    # -------------------------
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.String(40), unique=True, index=True, nullable=False)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # -------------------------
    # Affiliate / Commission
    # -------------------------
    affiliate_code = db.Column(db.String(80), index=True, nullable=True)
    affiliate_sub = db.Column(db.String(120), index=True, nullable=True)

    commission_rate_applied = db.Column(db.Numeric(6, 4), nullable=False, default=Decimal("0.0000"))
    commission_amount = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    payout_status = db.Column(db.String(20), nullable=False, default=PAYOUT_NONE, index=True)

    # -------------------------
    # Idempotencia / Pago
    # -------------------------
    idempotency_key = db.Column(db.String(80), nullable=True, index=True)
    payment_provider = db.Column(db.String(40), nullable=True, index=True)
    provider_payment_id = db.Column(db.String(140), nullable=True, index=True)

    # -------------------------
    # Snapshot cliente
    # -------------------------
    customer_name = db.Column(db.String(120))
    customer_email = db.Column(db.String(255), index=True)
    customer_phone = db.Column(db.String(40))

    ship_address1 = db.Column(db.String(200))
    ship_address2 = db.Column(db.String(200))
    ship_city = db.Column(db.String(80))
    ship_state = db.Column(db.String(80))
    ship_postal_code = db.Column(db.String(20))
    ship_country = db.Column(db.String(2))

    customer_note = db.Column(db.String(500))
    internal_note = db.Column(db.String(500))

    # -------------------------
    # Estado / pago
    # -------------------------
    status = db.Column(db.String(30), nullable=False, default=STATUS_AWAITING_PAYMENT, index=True)
    payment_method = db.Column(db.String(30), nullable=False, default=PM_PAYPAL, index=True)
    payment_status = db.Column(db.String(30), nullable=False, default=PAY_PENDING, index=True)
    fulfillment_status = db.Column(db.String(20), nullable=False, default=FULFILL_NONE, index=True)

    currency = db.Column(db.String(3), nullable=False, default="USD", index=True)

    # -------------------------
    # Totales
    # -------------------------
    subtotal = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    discount_total = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    shipping_total = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    tax_total = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    total = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))

    # -------------------------
    # Legacy refs
    # -------------------------
    paypal_order_id = db.Column(db.String(120), index=True)
    mp_payment_id = db.Column(db.String(120), index=True)
    bank_transfer_ref = db.Column(db.String(120))
    wise_transfer_id = db.Column(db.String(120), index=True)

    # -------------------------
    # Envío
    # -------------------------
    carrier = db.Column(db.String(80))
    tracking_number = db.Column(db.String(120), index=True)
    tracking_url = db.Column(db.String(500))

    # -------------------------
    # Timestamps
    # -------------------------
    paid_at = db.Column(db.DateTime(timezone=True), index=True)
    cancelled_at = db.Column(db.DateTime(timezone=True), index=True)
    refunded_at = db.Column(db.DateTime(timezone=True), index=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow, index=True)

    # -------------------------
    # Metadata libre
    # -------------------------
    meta = db.Column(MetaType)

    # Relationships
    items = db.relationship(
        "OrderItem",
        back_populates="order",
        cascade="all, delete-orphan",
        lazy="select",
        passive_deletes=True,
    )

    __table_args__ = (
        # money nonneg
        CheckConstraint("subtotal >= 0", name="ck_orders_subtotal_nonneg"),
        CheckConstraint("discount_total >= 0", name="ck_orders_discount_nonneg"),
        CheckConstraint("shipping_total >= 0", name="ck_orders_shipping_nonneg"),
        CheckConstraint("tax_total >= 0", name="ck_orders_tax_nonneg"),
        CheckConstraint("total >= 0", name="ck_orders_total_nonneg"),
        # commission nonneg
        CheckConstraint("commission_rate_applied >= 0", name="ck_orders_comm_rate_nonneg"),
        CheckConstraint("commission_amount >= 0", name="ck_orders_comm_amt_nonneg"),
        # ✅ Mejora #2: idempotency (si idempotency_key es NULL, no molesta)
        UniqueConstraint("user_id", "idempotency_key", name="uq_orders_user_idem"),
    )

    # -------------------------
    # Validators + normalización
    # -------------------------
    @validates("currency")
    def _v_currency(self, _k: str, v: str) -> str:
        s = (v or "USD").strip().upper()[:3]
        return s if len(s) == 3 else "USD"

    @validates("ship_country")
    def _v_ship_country(self, _k: str, v: Optional[str]) -> Optional[str]:
        s = (v or "").strip().upper()[:2]
        return s or None

    @validates("status")
    def _v_status(self, _k: str, v: str) -> str:
        s = (v or "").strip().lower()
        return s if s in self._ALLOWED_STATUS else self.STATUS_AWAITING_PAYMENT

    @validates("payment_status")
    def _v_payment_status(self, _k: str, v: str) -> str:
        s = (v or "").strip().lower()
        return s if s in self._ALLOWED_PAY_STATUS else self.PAY_PENDING

    @validates("fulfillment_status")
    def _v_fulfillment(self, _k: str, v: str) -> str:
        s = (v or "").strip().lower()
        return s if s in self._ALLOWED_FULFILL else self.FULFILL_NONE

    @validates("payout_status")
    def _v_payout(self, _k: str, v: str) -> str:
        s = (v or "").strip().lower()
        return s if s in self._ALLOWED_PAYOUT else self.PAYOUT_NONE

    @validates("payment_method")
    def _v_payment_method(self, _k: str, v: str) -> str:
        s = (v or "").strip().lower()
        return s if s in self._ALLOWED_PM else self.PM_PAYPAL

    @validates("customer_email")
    def _v_email(self, _k: str, v: Optional[str]) -> Optional[str]:
        return v.strip().lower()[:255] if v else None

    @validates("number")
    def _v_number(self, _k: str, v: str) -> str:
        vv = (v or "").strip()
        if not vv:
            # ✅ Mejora #1: más robusto y menos colisiones que time()
            vv = f"ORD-{int(time.time())}-{secrets.token_hex(3)}"
        return vv[:40]

    @validates("affiliate_code")
    def _v_aff(self, _k: str, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        s = v.strip().lower().replace(" ", "-")
        cleaned = "".join(ch for ch in s if ch.isalnum() or ch in {"-", "_"})
        return cleaned[:80] if cleaned else None

    @validates("affiliate_sub")
    def _v_sub(self, _k: str, v: Optional[str]) -> Optional[str]:
        return _clip_str(v, 120)

    @validates("idempotency_key")
    def _v_idem(self, _k: str, v: Optional[str]) -> Optional[str]:
        return _clip_str(v, 80)

    @validates("provider_payment_id")
    def _v_ppid(self, _k: str, v: Optional[str]) -> Optional[str]:
        return _clip_str(v, 140)

    @validates("payment_provider")
    def _v_provider(self, _k: str, v: Optional[str]) -> Optional[str]:
        return _clip_str((v or "").strip().lower() if v else None, 40)

    @validates("tracking_url")
    def _v_tracking_url(self, _k: str, v: Optional[str]) -> Optional[str]:
        # ✅ Mejora #4: limpia y recorta url (sin validar full, no rompe)
        s = (v or "").strip()
        if not s:
            return None
        return s[:500]

    # -------------------------
    # Helpers PRO
    # -------------------------
    def add_meta(self, **extra: Any) -> None:
        self.meta = _meta(self.meta, extra)

    def touch_updated(self) -> None:
        self.updated_at = utcnow()

    def ensure_number(self) -> None:
        """✅ Mejora #1 (API): asegura number antes de commit si viene vacío."""
        if not (self.number or "").strip():
            self.number = f"ORD-{int(time.time())}-{secrets.token_hex(3)}"[:40]

    def set_payment_provider_id(self, provider: Optional[str], provider_payment_id: Optional[str]) -> None:
        """
        ✅ Mejora #5:
        Setea provider + provider_payment_id y además refleja en campos legacy.
        No rompe si provider viene raro.
        """
        prov = (provider or "").strip().lower()
        pid = (provider_payment_id or "").strip()
        self.payment_provider = prov[:40] if prov else None
        self.provider_payment_id = pid[:140] if pid else None

        if not prov or not pid:
            return

        if prov == "paypal":
            self.paypal_order_id = pid[:120]
        elif prov.startswith("mercadopago"):
            self.mp_payment_id = pid[:120]
        elif prov == "wise":
            self.wise_transfer_id = pid[:120]

    def recompute_totals(self) -> None:
        """
        ✅ Mejora #6/#7:
        Recalcula subtotal/total de forma idempotente y consistente.
        """
        sub = Decimal("0.00")
        items: Iterable["OrderItem"] = self.items or []
        for it in items:
            it.recompute_line_total()
            sub += _d(it.line_total, "0.00")

        subtotal = _money(sub)
        discount = _money(self.discount_total)
        shipping = _money(self.shipping_total)
        tax = _money(self.tax_total)

        # clamp extra: descuento no puede superar subtotal
        if discount > subtotal:
            discount = subtotal

        self.subtotal = subtotal
        self.discount_total = discount
        self.shipping_total = shipping
        self.tax_total = tax

        computed = _d(subtotal) - _d(discount) + _d(shipping) + _d(tax)
        if computed < Decimal("0.00"):
            computed = Decimal("0.00")
        self.total = _money(computed)

    def can_transition_to(self, to_status: str) -> bool:
        cur = (self.status or "").strip().lower()
        nxt = (to_status or "").strip().lower()
        return nxt in self._ALLOWED_TRANSITIONS.get(cur, set())

    def transition_to(self, to_status: str) -> None:
        """
        ✅ Mejora #8: timestamps coherentes por transición.
        """
        to_status = (to_status or "").strip().lower()
        if not self.can_transition_to(to_status):
            raise ValueError(f"Transición inválida: {self.status} -> {to_status}")

        self.status = to_status
        if to_status == self.STATUS_PAID:
            if not self.paid_at:
                self.paid_at = utcnow()
            self.payment_status = self.PAY_PAID
        elif to_status == self.STATUS_CANCELLED:
            if not self.cancelled_at:
                self.cancelled_at = utcnow()
        elif to_status == self.STATUS_REFUNDED:
            if not self.refunded_at:
                self.refunded_at = utcnow()
            self.payment_status = self.PAY_REFUNDED

    def mark_paid(self) -> None:
        self.status = self.STATUS_PAID
        self.payment_status = self.PAY_PAID
        if not self.paid_at:
            self.paid_at = utcnow()

    def mark_cancelled(self) -> None:
        self.status = self.STATUS_CANCELLED
        if not self.cancelled_at:
            self.cancelled_at = utcnow()

    def mark_refunded(self) -> None:
        self.status = self.STATUS_REFUNDED
        self.payment_status = self.PAY_REFUNDED
        if not self.refunded_at:
            self.refunded_at = utcnow()

    def apply_commission_snapshot(self, *, sales_in_month: int, rate: Any) -> None:
        r = _rate(rate)
        amt = (_money(self.total) * r).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        self.commission_rate_applied = r
        self.commission_amount = amt
        self.payout_status = self.PAYOUT_PENDING if amt > Decimal("0.00") else self.PAYOUT_NONE
        self.add_meta(
            commission={
                "sales_in_month": int(max(0, sales_in_month)),
                "rate": str(r),
                "amount": str(amt),
                "snap_at": utcnow().isoformat(),
            }
        )

    def to_dict(self) -> Dict[str, Any]:
        # ✅ Mejora #10: más datos sin romper compat
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


# ============================================================
# OrderItem
# ============================================================

class OrderItem(db.Model):
    __tablename__ = "order_items"

    id = db.Column(db.Integer, primary_key=True)

    order_id = db.Column(
        db.Integer,
        db.ForeignKey("orders.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    product_id = db.Column(
        db.Integer,
        db.ForeignKey("products.id", ondelete="SET NULL"),
        index=True,
    )

    title_snapshot = db.Column(db.String(200), nullable=False)
    sku_snapshot = db.Column(db.String(80))

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
    def _v_cur(self, _k: str, v: str) -> str:
        s = (v or "USD").strip().upper()[:3]
        return s if len(s) == 3 else "USD"

    @validates("title_snapshot")
    def _v_title(self, _k: str, v: str) -> str:
        s = (v or "").strip()
        return s[:200] if s else "Producto"

    def recompute_line_total(self) -> None:
        self.unit_price = _money(self.unit_price)
        self.line_total = _money(_d(self.unit_price) * Decimal(int(self.qty or 1)))

    def __repr__(self) -> str:
        return f"<OrderItem id={self.id} product_id={self.product_id} qty={self.qty}>"


# ============================================================
# Eventos: recompute seguro (sin loops raros)
# ============================================================

@event.listens_for(OrderItem, "before_insert")
@event.listens_for(OrderItem, "before_update")
def _oi_before_save(_mapper, _connection, target: OrderItem) -> None:
    try:
        target.recompute_line_total()
    except Exception:
        pass

@event.listens_for(Order, "before_insert")
@event.listens_for(Order, "before_update")
def _o_before_save(_mapper, _connection, target: Order) -> None:
    try:
        target.ensure_number()
        # Recompute totals solo si hay items cargados (evita queries inesperadas en flush)
        if getattr(target, "items", None) is not None:
            target.recompute_totals()
    except Exception:
        pass


# ============================================================
# Índices PRO (dashboards y búsquedas)
# ============================================================

Index("ix_orders_status_created", Order.status, Order.created_at)
Index("ix_orders_payment_status_created", Order.payment_status, Order.created_at)
Index("ix_orders_user_created", Order.user_id, Order.created_at)

Index("ix_orders_aff_created", Order.affiliate_code, Order.created_at)
Index("ix_orders_provider_pid", Order.payment_provider, Order.provider_payment_id)
Index("ix_orders_idem_user", Order.user_id, Order.idempotency_key)

Index("ix_orders_payout_status_created", Order.payout_status, Order.created_at)
Index("ix_orders_fulfillment_created", Order.fulfillment_status, Order.created_at)

Index("ix_order_items_order_created", OrderItem.order_id, OrderItem.created_at)
Index("ix_order_items_product_created", OrderItem.product_id, OrderItem.created_at)
