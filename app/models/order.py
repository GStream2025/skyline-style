# app/models/order.py
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Optional, Any, Dict

from sqlalchemy import Index, event
from sqlalchemy.orm import validates

from app.models import db


# ============================================================
# Time / Decimal helpers (blindados)
# ============================================================

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _d(v: Any, default: str = "0.00") -> Decimal:
    """Decimal seguro (no rompe con None, '', floats, basura)."""
    try:
        if v is None or v == "":
            return Decimal(default)
        if isinstance(v, Decimal):
            return v
        return Decimal(str(v))
    except (InvalidOperation, ValueError, TypeError):
        return Decimal(default)


def _clamp_money(v: Decimal) -> Decimal:
    """Evita montos negativos."""
    if v is None:
        return Decimal("0.00")
    return v if v >= Decimal("0.00") else Decimal("0.00")


# JSON portable: JSON real en Postgres, TEXT en SQLite
MetaType = db.JSON().with_variant(db.Text(), "sqlite")


# ============================================================
# Order
# ============================================================

class Order(db.Model):
    """
    Skyline Store — Order PRO (FINAL)

    ✅ Estados claros
    ✅ Pagos múltiples
    ✅ Snapshot del cliente
    ✅ Totales blindados
    ✅ Compatible SQLite / Postgres
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
    # Métodos de pago
    # -------------------------
    PM_PAYPAL = "paypal"
    PM_MP_UY = "mercadopago_uy"
    PM_MP_AR = "mercadopago_ar"
    PM_BANK = "bank_transfer"
    PM_CASH = "cash"

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
    _ALLOWED_PM = {PM_PAYPAL, PM_MP_UY, PM_MP_AR, PM_BANK, PM_CASH}

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
    # Snapshot cliente (NO dependemos de User)
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
    status = db.Column(
        db.String(30),
        nullable=False,
        default=STATUS_AWAITING_PAYMENT,
        index=True,
    )

    payment_method = db.Column(
        db.String(30),
        nullable=False,
        default=PM_PAYPAL,
        index=True,
    )

    payment_status = db.Column(
        db.String(30),
        nullable=False,
        default=PAY_PENDING,
        index=True,
    )

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
    # Referencias externas
    # -------------------------
    paypal_order_id = db.Column(db.String(120), index=True)
    mp_payment_id = db.Column(db.String(120), index=True)
    bank_transfer_ref = db.Column(db.String(120))

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
    cancelled_at = db.Column(db.DateTime(timezone=True))
    refunded_at = db.Column(db.DateTime(timezone=True))

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        index=True,
    )

    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )

    # -------------------------
    # Metadata libre
    # -------------------------
    meta = db.Column(MetaType)

    # -------------------------
    # Relationships
    # -------------------------
    user = db.relationship(
        "User",
        back_populates="orders",
        lazy="select",
        passive_deletes=True,
    )

    items = db.relationship(
        "OrderItem",
        back_populates="order",
        cascade="all, delete-orphan",
        lazy="select",
        passive_deletes=True,
    )

    # -------------------------
    # Validaciones suaves
    # -------------------------
    @validates("currency")
    def _v_currency(self, _k, v: str) -> str:
        return (v or "USD").strip().upper()[:3]

    @validates("status")
    def _v_status(self, _k, v: str) -> str:
        v = (v or "").strip().lower()
        return v if v in self._ALLOWED_STATUS else self.STATUS_AWAITING_PAYMENT

    @validates("payment_status")
    def _v_payment_status(self, _k, v: str) -> str:
        v = (v or "").strip().lower()
        return v if v in self._ALLOWED_PAY_STATUS else self.PAY_PENDING

    @validates("payment_method")
    def _v_payment_method(self, _k, v: str) -> str:
        v = (v or "").strip().lower()
        return v if v in self._ALLOWED_PM else self.PM_PAYPAL

    @validates("customer_email")
    def _v_email(self, _k, v: Optional[str]) -> Optional[str]:
        return v.strip().lower()[:255] if v else None

    # -------------------------
    # Helpers PRO
    # -------------------------
    def recompute_totals(self) -> None:
        sub = Decimal("0.00")
        for it in self.items or []:
            it.recompute_line_total()
            sub += _d(it.line_total)

        self.subtotal = _clamp_money(sub)
        self.total = _clamp_money(
            self.subtotal
            - _d(self.discount_total)
            + _d(self.shipping_total)
            + _d(self.tax_total)
        )

    def mark_paid(self) -> None:
        self.status = self.STATUS_PAID
        self.payment_status = self.PAY_PAID
        self.paid_at = utcnow()

    def mark_cancelled(self) -> None:
        self.status = self.STATUS_CANCELLED
        self.cancelled_at = utcnow()

    def mark_refunded(self) -> None:
        self.status = self.STATUS_REFUNDED
        self.payment_status = self.PAY_REFUNDED
        self.refunded_at = utcnow()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "number": self.number,
            "user_id": self.user_id,
            "status": self.status,
            "payment_status": self.payment_status,
            "payment_method": self.payment_method,
            "currency": self.currency,
            "subtotal": str(_d(self.subtotal)),
            "total": str(_d(self.total)),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<Order {self.number} total={self.total}>"


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

    @validates("qty")
    def _v_qty(self, _k, v: int) -> int:
        try:
            return max(1, int(v))
        except Exception:
            return 1

    def recompute_line_total(self) -> None:
        self.line_total = _clamp_money(_d(self.unit_price) * Decimal(self.qty or 1))


# ============================================================
# Índices PRO
# ============================================================

Index("ix_orders_status_created", Order.status, Order.created_at)
Index("ix_orders_payment_status_created", Order.payment_status, Order.created_at)
Index("ix_orders_user_created", Order.user_id, Order.created_at)
Index("ix_order_items_order_created", OrderItem.order_id, OrderItem.created_at)
Index("ix_order_items_product_created", OrderItem.product_id, OrderItem.created_at)
