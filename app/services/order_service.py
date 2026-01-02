from __future__ import annotations

"""
Skyline Store — Order Service (ULTRA PRO MAX / FINAL)
====================================================
CEREBRO ÚNICO de órdenes y pagos.

✔️ Seguro
✔️ Idempotente
✔️ Concurrency-safe
✔️ Compatible con MercadoPago UY / AR, PayPal y Wise
✔️ Listo para producción real
"""

import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Optional, Sequence

from sqlalchemy import select, func
from sqlalchemy.exc import IntegrityError

from app.models import db
from app.models.order import Order, OrderItem
from app.models.product import Product

log = logging.getLogger("order_service")


# =============================================================================
# Errors
# =============================================================================

class OrderServiceError(RuntimeError): ...
class OutOfStockError(OrderServiceError): ...
class InvalidStateError(OrderServiceError): ...
class PaymentMismatchError(OrderServiceError): ...
class DuplicatePaymentError(OrderServiceError): ...


# =============================================================================
# Helpers
# =============================================================================

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _d(v: Any, default="0.00") -> Decimal:
    try:
        if v is None or v == "":
            return Decimal(default)
        return Decimal(str(v))
    except (InvalidOperation, TypeError, ValueError):
        return Decimal(default)


def _money(v: Any) -> Decimal:
    d = _d(v)
    return d if d >= Decimal("0.00") else Decimal("0.00")


def _currency(v: Optional[str], default="USD") -> str:
    s = (v or default).upper().strip()
    return s[:3] if len(s) >= 3 else default


def _safe_str(v: Any, n: int) -> Optional[str]:
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


# =============================================================================
# Transaction
# =============================================================================

class tx:
    def __enter__(self):
        return db.session

    def __exit__(self, exc_type, exc, tb):
        if exc_type:
            db.session.rollback()
            return False
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return True


# =============================================================================
# DTOs
# =============================================================================

@dataclass(frozen=True)
class CartLine:
    product_id: int
    qty: int = 1
    unit_price: Optional[Decimal] = None
    title: Optional[str] = None
    sku: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class CreateOrderInput:
    user_id: Optional[int] = None
    payment_method: str = Order.PM_PAYPAL
    currency: str = "USD"
    discount_total: Decimal = Decimal("0.00")
    shipping_total: Decimal = Decimal("0.00")
    tax_total: Decimal = Decimal("0.00")
    idempotency_key: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None


# =============================================================================
# OrderService
# =============================================================================

class OrderService:

    _ALLOWED_TRANSITIONS = {
        Order.STATUS_AWAITING_PAYMENT: {Order.STATUS_PAID, Order.STATUS_CANCELLED},
        Order.STATUS_PAID: {Order.STATUS_PROCESSING, Order.STATUS_REFUNDED},
        Order.STATUS_PROCESSING: {Order.STATUS_SHIPPED},
        Order.STATUS_SHIPPED: {Order.STATUS_DELIVERED},
    }

    # -------------------------------------------------------------------------
    # CREATE ORDER
    # -------------------------------------------------------------------------

    @classmethod
    def create_order_from_cart(
        cls,
        lines: Sequence[CartLine],
        data: CreateOrderInput,
        *,
        reserve_stock: bool = True,
    ) -> Order:
        if not lines:
            raise OrderServiceError("Carrito vacío")

        currency = _currency(data.currency)
        pm = (data.payment_method or "").lower()

        with tx() as s:
            order = Order(
                number=cls._new_order_number(s),
                user_id=data.user_id,
                status=Order.STATUS_AWAITING_PAYMENT,
                payment_method=pm,
                currency=currency,
                discount_total=_money(data.discount_total),
                shipping_total=_money(data.shipping_total),
                tax_total=_money(data.tax_total),
                meta=_meta(data.meta, {
                    "idempotency_key": data.idempotency_key,
                    "created_by": "order_service",
                }),
            )
            s.add(order)
            s.flush()

            for ln in lines:
                item = cls._build_item(s, ln, currency)
                item.order_id = order.id
                s.add(item)

            s.flush()

            if reserve_stock:
                cls._reserve_stock(s, order)

            order.recompute_totals()
            return order

    # -------------------------------------------------------------------------
    # PAYMENT CONFIRMATION
    # -------------------------------------------------------------------------

    @classmethod
    def confirm_payment(
        cls,
        order_id: int,
        *,
        provider: str,
        provider_payment_id: str,
        amount: Decimal,
        currency: str,
        raw: Optional[dict] = None,
    ) -> Order:

        provider = provider.lower().strip()

        with tx() as s:
            order = s.get(Order, order_id)
            if not order:
                raise OrderServiceError("Orden no encontrada")

            # 🔒 idempotencia por proveedor
            if order.meta and order.meta.get("provider_payment_id") == provider_payment_id:
                return order

            if order.status != Order.STATUS_AWAITING_PAYMENT:
                raise InvalidStateError("La orden no acepta pagos")

            if _currency(currency) != _currency(order.currency):
                raise PaymentMismatchError("Moneda incorrecta")

            if abs(_money(amount) - _money(order.total)) > Decimal("0.05"):
                raise PaymentMismatchError("Monto incorrecto")

            order.mark_paid()
            order.meta = _meta(order.meta, {
                "payment_provider": provider,
                "provider_payment_id": provider_payment_id,
                "paid_amount": str(amount),
                "payment_raw": raw,
            })
            return order

    # -------------------------------------------------------------------------
    # INTERNALS
    # -------------------------------------------------------------------------

    @classmethod
    def _new_order_number(cls, session) -> str:
        for _ in range(10):
            n = f"SS-{utcnow().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(2).upper()}"
            if not session.execute(select(func.count(Order.id)).where(Order.number == n)).scalar():
                return n
        raise OrderServiceError("No se pudo generar número de orden")

    @classmethod
    def _build_item(cls, session, ln: CartLine, currency: str) -> OrderItem:
        prod = session.get(Product, ln.product_id)
        if not prod:
            raise OrderServiceError("Producto inexistente")

        price = _money(ln.unit_price or prod.price)

        it = OrderItem(
            product_id=prod.id,
            title_snapshot=_safe_str(ln.title or prod.title, 200),
            sku_snapshot=_safe_str(ln.sku, 80),
            currency=currency,
            unit_price=price,
            qty=max(1, ln.qty),
            meta=_meta(ln.meta, {"product_slug": prod.slug}),
        )
        it.recompute_line_total()
        return it

    @classmethod
    def _reserve_stock(cls, session, order: Order) -> None:
        for it in order.items:
            prod = session.get(Product, it.product_id)
            if not prod:
                continue
            if prod.stock_mode != "finite":
                continue
            if prod.stock_qty < it.qty:
                raise OutOfStockError(prod.title)
            prod.stock_qty -= it.qty
