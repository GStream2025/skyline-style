# app/models/order.py
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Optional, Any, Dict, Iterable

from sqlalchemy import Index
from sqlalchemy.orm import validates

from app.models import db  # ✅ db ÚNICO


# ============================================================
# Time / Decimal helpers
# ============================================================

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _d(v: Any, default: str = "0.00") -> Decimal:
    """Decimal seguro para montos (no revienta con None, '', float raro, etc.)."""
    try:
        if v is None or v == "":
            return Decimal(default)
        if isinstance(v, Decimal):
            return v
        return Decimal(str(v))
    except (InvalidOperation, ValueError, TypeError):
        return Decimal(default)


def _clamp_money(v: Decimal) -> Decimal:
    """Evita negativos por errores de rounding / descuentos mal cargados."""
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
    Skyline Store — Order ULTRA PRO (FINAL)

    ✅ E-commerce real:
    - order number único
    - snapshot cliente/dirección
    - payment method + status + referencias
    - totales Decimal + recompute
    - tracking
    - meta JSON portable
    - índices PRO
    """

    __tablename__ = "orders"

    # -------------------------
    # Estados
    # -------------------------
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

    PM_PAYPAL = "paypal"
    PM_MP_UY = "mercadopago_uy"
    PM_MP_AR = "mercadopago_ar"
    PM_BANK = "bank_transfer"
    PM_CASH = "cash"

    # allowlists (mejora #1: normalización consistente)
    _ALLOWED_STATUS = {
        STATUS_AWAITING_PAYMENT, STATUS_PAID, STATUS_PROCESSING,
        STATUS_SHIPPED, STATUS_DELIVERED, STATUS_CANCELLED, STATUS_REFUNDED
    }
    _ALLOWED_PAY_STATUS = {PAY_PENDING, PAY_PAID, PAY_FAILED, PAY_REFUNDED}
    _ALLOWED_PM = {PM_PAYPAL, PM_MP_UY, PM_MP_AR, PM_BANK, PM_CASH}

    id = db.Column(db.Integer, primary_key=True)

    # Número humano (ej: SKY-2025-000123)
    number = db.Column(db.String(40), unique=True, index=True, nullable=False)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # -------------------------
    # Snapshot cliente
    # -------------------------
    customer_name = db.Column(db.String(120), nullable=True)
    customer_email = db.Column(db.String(255), nullable=True, index=True)
    customer_phone = db.Column(db.String(40), nullable=True)

    # Dirección (snapshot) ✅ mantiene tus nombres ship_*
    ship_address1 = db.Column(db.String(200), nullable=True)
    ship_address2 = db.Column(db.String(200), nullable=True)
    ship_city = db.Column(db.String(80), nullable=True)
    ship_state = db.Column(db.String(80), nullable=True)
    ship_postal_code = db.Column(db.String(20), nullable=True)
    ship_country = db.Column(db.String(2), nullable=True)  # ISO2

    # Notas
    customer_note = db.Column(db.String(500), nullable=True)
    internal_note = db.Column(db.String(500), nullable=True)

    # -------------------------
    # Estado / pago
    # -------------------------
    status = db.Column(db.String(30), nullable=False, default=STATUS_AWAITING_PAYMENT, index=True)
    payment_method = db.Column(db.String(30), nullable=False, default=PM_PAYPAL, index=True)
    payment_status = db.Column(db.String(30), nullable=False, default=PAY_PENDING, index=True)

    currency = db.Column(db.String(3), nullable=False, default="USD", index=True)

    # Montos (Decimal)
    subtotal = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    discount_total = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    shipping_total = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    tax_total = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    total = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))

    # Referencias gateway (opcionales)
    paypal_order_id = db.Column(db.String(120), nullable=True, index=True)
    mp_payment_id = db.Column(db.String(120), nullable=True, index=True)
    bank_transfer_ref = db.Column(db.String(120), nullable=True)

    paid_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)
    cancelled_at = db.Column(db.DateTime(timezone=True), nullable=True)
    refunded_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Tracking (opcional)
    carrier = db.Column(db.String(80), nullable=True)
    tracking_number = db.Column(db.String(120), nullable=True, index=True)
    tracking_url = db.Column(db.String(500), nullable=True)

    # Metadatos flexibles
    meta = db.Column(MetaType, nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)

    # relationships
    user = db.relationship("User", back_populates="orders", lazy="select")
    items = db.relationship("OrderItem", back_populates="order", cascade="all, delete-orphan", lazy="select")

    # -------------------------
    # Validaciones suaves (mejora #2: allowlist con fallback)
    # -------------------------
    @validates("currency")
    def _v_currency(self, _k: str, v: str) -> str:
        v = (v or "USD").strip().upper()
        return (v[:3] if v else "USD")

    @validates("status")
    def _v_status(self, _k: str, v: str) -> str:
        vv = (v or "").strip().lower()[:30]
        return vv if vv in self._ALLOWED_STATUS else self.STATUS_AWAITING_PAYMENT

    @validates("payment_status")
    def _v_payment_status(self, _k: str, v: str) -> str:
        vv = (v or "").strip().lower()[:30]
        return vv if vv in self._ALLOWED_PAY_STATUS else self.PAY_PENDING

    @validates("payment_method")
    def _v_payment_method(self, _k: str, v: str) -> str:
        vv = (v or "").strip().lower()[:30]
        return vv if vv in self._ALLOWED_PM else self.PM_PAYPAL

    @validates("customer_email")
    def _v_email(self, _k: str, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        v = v.strip().lower()
        return v[:255]

    # -------------------------
    # Helpers PRO
    # -------------------------
    def recompute_totals(self) -> None:
        """
        Recalcula subtotal/total desde items.
        ✅ Mejora #3: clamp anti negativos
        ✅ Mejora #4: recalcula cada item primero
        """
        sub = Decimal("0.00")
        for it in (self.items or []):
            it.recompute_line_total()
            sub += _d(it.line_total)

        self.subtotal = _clamp_money(sub)

        disc = _clamp_money(_d(self.discount_total))
        ship = _clamp_money(_d(self.shipping_total))
        tax = _clamp_money(_d(self.tax_total))

        self.total = _clamp_money(self.subtotal - disc + ship + tax)

    def mark_paid(self, when: Optional[datetime] = None) -> None:
        """✅ Mejora #5: estado + timestamps consistentes."""
        self.status = self.STATUS_PAID
        self.payment_status = self.PAY_PAID
        self.paid_at = when or utcnow()

    def mark_cancelled(self, when: Optional[datetime] = None) -> None:
        self.status = self.STATUS_CANCELLED
        self.cancelled_at = when or utcnow()

    def mark_refunded(self, when: Optional[datetime] = None) -> None:
        self.status = self.STATUS_REFUNDED
        self.payment_status = self.PAY_REFUNDED
        self.refunded_at = when or utcnow()

    def is_payable(self) -> bool:
        """✅ Mejora #6: lógica clara de si puede pagarse."""
        return (
            self.status == self.STATUS_AWAITING_PAYMENT
            and self.payment_status in {self.PAY_PENDING, self.PAY_FAILED}
        )

    def is_fulfillable(self) -> bool:
        """✅ Mejora #7: listo para fulfillment."""
        return self.status in {self.STATUS_PAID, self.STATUS_PROCESSING}

    def to_dict(self) -> Dict[str, Any]:
        """✅ Mejora #8: serialización para APIs/admin."""
        return {
            "id": self.id,
            "number": self.number,
            "user_id": self.user_id,
            "status": self.status,
            "payment_method": self.payment_method,
            "payment_status": self.payment_status,
            "currency": self.currency,
            "subtotal": str(_d(self.subtotal)),
            "discount_total": str(_d(self.discount_total)),
            "shipping_total": str(_d(self.shipping_total)),
            "tax_total": str(_d(self.tax_total)),
            "total": str(_d(self.total)),
            "customer_email": self.customer_email,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<Order id={self.id} number={self.number!r} status={self.status!r} total={self.total}>"


# ============================================================
# OrderItem
# ============================================================

class OrderItem(db.Model):
    """
    Snapshot fuerte:
    ✅ orden vieja nunca se rompe si cambia Product.
    """

    __tablename__ = "order_items"

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id", ondelete="CASCADE"), nullable=False, index=True)

    product_id = db.Column(db.Integer, db.ForeignKey("products.id", ondelete="SET NULL"), nullable=True, index=True)

    title_snapshot = db.Column(db.String(200), nullable=False)
    source_snapshot = db.Column(db.String(20), nullable=False, default="manual")
    sku_snapshot = db.Column(db.String(80), nullable=True)

    currency = db.Column(db.String(3), nullable=False, default="USD")

    unit_price = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    qty = db.Column(db.Integer, nullable=False, default=1)
    line_total = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))

    printful_variant_id = db.Column(db.String(50), nullable=True, index=True)

    meta = db.Column(MetaType, nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)

    order = db.relationship("Order", back_populates="items", lazy="select")

    @validates("qty")
    def _v_qty(self, _k: str, v: int) -> int:
        """✅ Mejora #9: clamp qty robusto."""
        try:
            vv = int(v)
        except Exception:
            vv = 1
        return max(1, vv)

    @validates("currency")
    def _v_currency(self, _k: str, v: str) -> str:
        v = (v or "USD").strip().upper()
        return (v[:3] if v else "USD")

    def recompute_line_total(self) -> None:
        """✅ Mejora #10: line_total siempre consistente."""
        self.line_total = _clamp_money(_d(self.unit_price) * Decimal(int(self.qty or 1)))

    def to_dict(self) -> Dict[str, Any]:
        """✅ Mejora #11: serialización para APIs/admin."""
        return {
            "id": self.id,
            "order_id": self.order_id,
            "product_id": self.product_id,
            "title_snapshot": self.title_snapshot,
            "sku_snapshot": self.sku_snapshot,
            "unit_price": str(_d(self.unit_price)),
            "qty": int(self.qty or 1),
            "line_total": str(_d(self.line_total)),
        }

    def __repr__(self) -> str:
        return f"<OrderItem id={self.id} order_id={self.order_id} qty={self.qty} line_total={self.line_total}>"


# ============================================================
# Índices PRO (performance real)
# ============================================================

Index("ix_orders_status_created", Order.status, Order.created_at)
Index("ix_orders_payment_status_created", Order.payment_status, Order.created_at)
Index("ix_orders_user_created", Order.user_id, Order.created_at)
Index("ix_order_items_order_created", OrderItem.order_id, OrderItem.created_at)
Index("ix_order_items_product_created", OrderItem.product_id, OrderItem.created_at)
