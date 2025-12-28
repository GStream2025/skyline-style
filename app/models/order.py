# Orders and order items
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from app import db


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Order(db.Model):
    """
    Order PRO:
    - status: awaiting_payment | paid | processing | shipped | delivered | cancelled | refunded
    - payment_method: paypal | mercadopago | bank_transfer
    - payment_status: pending | paid | failed | refunded
    """
    __tablename__ = "orders"

    id = db.Column(db.Integer, primary_key=True)

    number = db.Column(db.String(40), unique=True, index=True, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    # customer snapshot
    customer_name = db.Column(db.String(120), nullable=True)
    customer_email = db.Column(db.String(255), nullable=True)
    customer_phone = db.Column(db.String(40), nullable=True)

    country = db.Column(db.String(2), nullable=True)
    city = db.Column(db.String(80), nullable=True)

    status = db.Column(db.String(30), nullable=False, default="awaiting_payment")
    payment_method = db.Column(db.String(30), nullable=False, default="paypal")
    payment_status = db.Column(db.String(30), nullable=False, default="pending")

    currency = db.Column(db.String(3), nullable=False, default="USD")
    subtotal = db.Column(db.Numeric(12, 2), nullable=False, default=0)
    discount_total = db.Column(db.Numeric(12, 2), nullable=False, default=0)
    shipping_total = db.Column(db.Numeric(12, 2), nullable=False, default=0)
    total = db.Column(db.Numeric(12, 2), nullable=False, default=0)

    # Gateway references
    paypal_order_id = db.Column(db.String(120), nullable=True, index=True)
    mp_payment_id = db.Column(db.String(120), nullable=True, index=True)
    bank_transfer_ref = db.Column(db.String(120), nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)

    # relationships
    user = db.relationship("User", back_populates="orders", lazy="select")
    items = db.relationship("OrderItem", back_populates="order", cascade="all, delete-orphan", lazy="select")

    def __repr__(self) -> str:
        return f"<Order id={self.id} number={self.number} status={self.status}>"


class OrderItem(db.Model):
    __tablename__ = "order_items"

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id", ondelete="CASCADE"), nullable=False)

    product_id = db.Column(db.Integer, db.ForeignKey("products.id", ondelete="SET NULL"), nullable=True)

    # snapshot to avoid changes breaking old orders
    title_snapshot = db.Column(db.String(200), nullable=False)
    source_snapshot = db.Column(db.String(20), nullable=False, default="manual")  # manual/printful/dropship
    sku_snapshot = db.Column(db.String(80), nullable=True)

    unit_price = db.Column(db.Numeric(12, 2), nullable=False, default=0)
    qty = db.Column(db.Integer, nullable=False, default=1)
    line_total = db.Column(db.Numeric(12, 2), nullable=False, default=0)

    # For printful fulfillment linking
    printful_variant_id = db.Column(db.String(50), nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    order = db.relationship("Order", back_populates="items", lazy="select")

    def __repr__(self) -> str:
        return f"<OrderItem id={self.id} order_id={self.order_id} qty={self.qty}>"
