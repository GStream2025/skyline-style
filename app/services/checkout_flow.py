from __future__ import annotations

"""
Skyline Store — Checkout Flow
=============================
Orquestador de checkout end-to-end (PRODUCCIÓN REAL).

✔️ Sin Flask request
✔️ Idempotente
✔️ Reanudable
✔️ Multi-provider
✔️ Compatible con webhooks
"""

import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Optional, Sequence, Tuple

from sqlalchemy import select

from app.models import db
from app.models.order import Order
from app.services.order_service import (
    OrderService,
    CartLine,
    CreateOrderInput,
    OrderServiceError,
    OutOfStockError,
    PaymentMismatchError,
)

log = logging.getLogger("checkout_flow")

# =============================================================================
# Errors
# =============================================================================


class CheckoutError(RuntimeError): ...


class CheckoutValidationError(CheckoutError): ...


class CheckoutProviderError(CheckoutError): ...


class CheckoutNotFoundError(CheckoutError): ...


# =============================================================================
# Helpers
# =============================================================================


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _d(v: Any, default="0.00") -> Decimal:
    try:
        return Decimal(str(v))
    except (InvalidOperation, TypeError, ValueError):
        return Decimal(default)


def _money(v: Any) -> Decimal:
    d = _d(v)
    return d if d >= Decimal("0.00") else Decimal("0.00")


def _currency(v: Optional[str], default="USD") -> str:
    s = (v or default).upper().strip()
    return s[:3] if len(s) >= 3 else default


def _email(v: str) -> str:
    return (v or "").strip().lower()


def _country(v: Optional[str]) -> Optional[str]:
    s = (v or "").strip().upper()
    return s[:2] if s else None


def _safe(v: Any, n: int) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    return s[:n] if s else None


def _merge(a: Optional[dict], b: Optional[dict]) -> dict:
    out = dict(a or {})
    for k, v in (b or {}).items():
        if v is not None:
            out[k] = v
    return out


def _token(n: int = 12) -> str:
    return secrets.token_urlsafe(n)


# =============================================================================
# DTOs
# =============================================================================


@dataclass(frozen=True)
class CheckoutState:
    checkout_key: str
    order_id: int
    order_number: str
    status: str
    payment_method: str
    payment_status: str
    currency: str
    total: str
    redirect_url: Optional[str]
    meta: Optional[Dict[str, Any]]


@dataclass(frozen=True)
class PaymentStartResult:
    provider: str
    checkout_key: str
    order_id: int
    order_number: str
    currency: str
    amount: str
    redirect_url: Optional[str]
    meta: Optional[Dict[str, Any]]


# =============================================================================
# Checkout Flow
# =============================================================================


class CheckoutFlow:
    """
    Flujo principal de checkout.
    """

    # -------------------------------------------------------------------------
    # CREATE / RESUME
    # -------------------------------------------------------------------------

    @classmethod
    def create_checkout(
        cls,
        *,
        lines: Sequence[CartLine],
        customer_email: str,
        payment_method: str,
        currency: str = "USD",
        checkout_key: Optional[str] = None,
        user_id: Optional[int] = None,
        ship_country: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
        reserve_stock: bool = True,
    ) -> CheckoutState:

        email = _email(customer_email)
        if not email or "@" not in email:
            raise CheckoutValidationError("Email inválido")

        if not lines:
            raise CheckoutValidationError("Carrito vacío")

        ck = checkout_key or f"ck_{_token()}"

        discount, shipping, tax = cls._compute_extras(
            lines=lines,
            currency=currency,
            ship_country=ship_country,
        )

        try:
            order = OrderService.create_order_from_cart(
                lines,
                CreateOrderInput(
                    user_id=user_id,
                    customer_email=email,
                    payment_method=payment_method,
                    currency=_currency(currency),
                    discount_total=discount,
                    shipping_total=shipping,
                    tax_total=tax,
                    idempotency_key=ck,
                    meta=meta,
                ),
                reserve_stock=reserve_stock,
            )
        except OutOfStockError as e:
            raise CheckoutError(str(e))
        except OrderServiceError as e:
            raise CheckoutError(str(e))

        return cls._state(order, ck)

    # -------------------------------------------------------------------------
    # START PAYMENT
    # -------------------------------------------------------------------------

    @classmethod
    def start_payment(
        cls,
        *,
        checkout_key: str,
        provider: str,
        success_url: Optional[str] = None,
        cancel_url: Optional[str] = None,
        extra_meta: Optional[Dict[str, Any]] = None,
    ) -> PaymentStartResult:

        order = cls._find_order(checkout_key)
        if not order:
            raise CheckoutNotFoundError("Checkout no encontrado")

        if order.payment_status == Order.PAY_PAID:
            return PaymentStartResult(
                provider=provider,
                checkout_key=checkout_key,
                order_id=order.id,
                order_number=order.number,
                currency=order.currency,
                amount=str(_money(order.total)),
                redirect_url=None,
                meta={"already_paid": True},
            )

        provider = provider.lower().strip()
        if provider not in {
            "paypal",
            "mercadopago_uy",
            "mercadopago_ar",
            "bank_transfer",
            "wise",
        }:
            raise CheckoutValidationError("Proveedor inválido")

        with db.session.begin():
            order.meta = _merge(
                order.meta,
                {
                    "checkout_key": checkout_key,
                    "payment_provider": provider,
                    "success_url": _safe(success_url, 500),
                    "cancel_url": _safe(cancel_url, 500),
                    "intent_created_at": utcnow().isoformat(),
                    "intent_extra": extra_meta,
                },
            )
            order.payment_method = provider
            order.payment_status = Order.PAY_PENDING
            order.updated_at = utcnow()

        # Providers NO hacen HTTP acá
        return PaymentStartResult(
            provider=provider,
            checkout_key=checkout_key,
            order_id=order.id,
            order_number=order.number,
            currency=order.currency,
            amount=str(_money(order.total)),
            redirect_url=None,
            meta={"needs_provider_call": True},
        )

    # -------------------------------------------------------------------------
    # CONFIRM PAID (manual / capture / webhook)
    # -------------------------------------------------------------------------

    @classmethod
    def confirm_paid(
        cls,
        *,
        checkout_key: str,
        provider: str,
        provider_payment_id: Optional[str],
        amount: Decimal,
        currency: str,
        raw: Optional[Dict[str, Any]] = None,
    ) -> CheckoutState:

        order = cls._find_order(checkout_key)
        if not order:
            raise CheckoutNotFoundError("Checkout no encontrado")

        try:
            order2 = OrderService.apply_payment_confirmation(
                order.id,
                provider=provider,
                provider_payment_id=provider_payment_id,
                paid_amount=amount,
                paid_currency=currency,
                raw=raw,
            )
        except PaymentMismatchError as e:
            raise CheckoutError(str(e))
        except OrderServiceError as e:
            raise CheckoutError(str(e))

        return cls._state(order2, checkout_key)

    # -------------------------------------------------------------------------
    # STATE
    # -------------------------------------------------------------------------

    @classmethod
    def get_state(cls, checkout_key: str) -> CheckoutState:
        order = cls._find_order(checkout_key)
        if not order:
            raise CheckoutNotFoundError("Checkout no encontrado")
        return cls._state(order, checkout_key)

    # =============================================================================
    # INTERNALS
    # =============================================================================

    @classmethod
    def _find_order(cls, checkout_key: str) -> Optional[Order]:
        try:
            q = select(Order).where(Order.meta["idempotency_key"].astext == checkout_key)  # type: ignore
            return db.session.execute(q).scalars().first()
        except Exception:
            return None

    @classmethod
    def _state(cls, order: Order, checkout_key: str) -> CheckoutState:
        meta = order.meta if isinstance(order.meta, dict) else {}
        return CheckoutState(
            checkout_key=checkout_key,
            order_id=order.id,
            order_number=order.number,
            status=order.status,
            payment_method=order.payment_method,
            payment_status=order.payment_status,
            currency=order.currency,
            total=str(_money(order.total)),
            redirect_url=_safe(meta.get("redirect_url"), 500),
            meta=meta,
        )

    @classmethod
    def _compute_extras(
        cls,
        *,
        lines: Sequence[CartLine],
        currency: str,
        ship_country: Optional[str],
    ) -> Tuple[Decimal, Decimal, Decimal]:
        # Hook extensible
        shipping = Decimal("0.00")
        if _country(ship_country) and _country(ship_country) != "UY":
            shipping = Decimal("9.90")
        return Decimal("0.00"), shipping, Decimal("0.00")


__all__ = [
    "CheckoutFlow",
    "CheckoutState",
    "PaymentStartResult",
    "CheckoutError",
    "CheckoutValidationError",
    "CheckoutProviderError",
    "CheckoutNotFoundError",
]
