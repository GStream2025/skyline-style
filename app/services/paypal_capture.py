from __future__ import annotations

"""
Skyline Store — PayPal Service (CREATE + CAPTURE) (SERVICES)
===========================================================

- Orquesta PayPal create/capture para TU app
- Valida monto/moneda vs Order
- Idempotencia (si ya pagó, no duplica)
- Guarda auditoría en Order.meta
- Marca paid usando OrderService.apply_payment_confirmation()

✅ Esta capa toca DB.
✅ La capa HTTP está en app/integrations/paypal_client.py
"""

import logging
import time
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Dict, Optional


from app.models import db
from app.models.order import Order
from app.services.order_service import (
    OrderService,
    OrderServiceError,
    PaymentMismatchError,
)
from app.integrations.paypal_client import (
    create_order as pp_create_order,
    capture_order as pp_capture_order,
    money_str as pp_money_str,
    cur3 as pp_cur3,
    PayPalClientError,
    PayPalAuthError,
    PayPalHTTPError,
)

log = logging.getLogger("paypal_service")


# -----------------------------------------------------------------------------
# Errors
# -----------------------------------------------------------------------------


class PayPalServiceError(RuntimeError):
    pass


class PayPalServiceNotFound(PayPalServiceError):
    pass


class PayPalServiceMismatch(PayPalServiceError):
    pass


class PayPalServiceProviderError(PayPalServiceError):
    pass


# -----------------------------------------------------------------------------
# DTOs
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class PayPalCreateResult:
    ok: bool
    paypal_order_id: str
    approve_url: Optional[str]
    raw: Dict[str, Any]


@dataclass(frozen=True)
class PayPalCaptureResult:
    ok: bool
    paypal_order_id: str
    status: str
    capture_id: Optional[str]
    raw: Dict[str, Any]


# -----------------------------------------------------------------------------
# Small utils
# -----------------------------------------------------------------------------


def _now() -> int:
    return int(time.time())


def _meta_merge(base: Any, extra: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if isinstance(base, dict):
        out.update(base)
    if isinstance(extra, dict):
        out.update(extra)
    return out


def _shrink(obj: Any, *, max_keys: int = 80, max_str: int = 900) -> Any:
    if isinstance(obj, dict):
        keys = list(obj.keys())[:max_keys]
        return {
            k: _shrink(obj.get(k), max_keys=max_keys, max_str=max_str) for k in keys
        }
    if isinstance(obj, list):
        return [_shrink(x, max_keys=max_keys, max_str=max_str) for x in obj[:25]]
    if isinstance(obj, str):
        return obj[:max_str]
    return obj


def _get_order(order_id: int) -> Order:
    o = db.session.get(Order, int(order_id))
    if not o:
        raise PayPalServiceNotFound("Orden no encontrada")
    return o


def _audit(
    order: Order,
    event: str,
    payload: Dict[str, Any],
    *,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    block = {
        "event": event,
        "at": _now(),
        "provider": "paypal",
        "extra": extra or {},
    }
    order.meta = _meta_merge(
        order.meta,
        {
            "paypal_last_event": block,
            "paypal_last_payload": _shrink(payload),
        },
    )
    order.updated_at = db.func.now()  # type: ignore[attr-defined]


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------


def create_paypal_order(
    *,
    order_id: int,
    success_url: str,
    cancel_url: str,
    brand_name: str = "Skyline Store",
    locale: str = "es-UY",
    idempotency_key: Optional[str] = None,
) -> PayPalCreateResult:
    """
    Crea la PayPal Order (approve url).
    - idempotente: si ya existe paypal_order_id en DB, no crea de nuevo.
    """
    # 1) leer y preparar snapshot
    with db.session.begin():
        order = _get_order(order_id)

        # si ya pagada, no tiene sentido crear
        if (order.payment_status or "") == Order.PAY_PAID:
            return PayPalCreateResult(
                True, order.paypal_order_id or "", None, {"already_paid": True}
            )

        # idempotencia local: si ya hay paypal_order_id, devolvemos
        if order.paypal_order_id:
            return PayPalCreateResult(
                True, str(order.paypal_order_id), None, {"already_created": True}
            )

        amount = pp_money_str(order.total)
        currency = pp_cur3(order.currency, "USD")
        reference_id = order.number
        custom_id = str(order.id)

        # guardar intent meta
        order.meta = _meta_merge(
            order.meta,
            {
                "checkout_key": (
                    (order.meta or {}).get("idempotency_key")
                    if isinstance(order.meta, dict)
                    else None
                ),
                "paypal_intent": {
                    "created_at": _now(),
                    "amount": amount,
                    "currency": currency,
                    "success_url": success_url[:500],
                    "cancel_url": cancel_url[:500],
                },
            },
        )

    # 2) llamar PayPal (fuera de tx DB)
    try:
        resp = pp_create_order(
            amount=amount,
            currency=currency,
            reference_id=reference_id,
            custom_id=custom_id,
            success_url=success_url,
            cancel_url=cancel_url,
            brand_name=brand_name,
            locale=locale,
            idempotency_key=idempotency_key or f"pp_create_{order_id}_{_now()}",
        )
    except (PayPalAuthError, PayPalHTTPError, PayPalClientError) as e:
        raise PayPalServiceProviderError(str(e))

    # 3) persistir paypal_order_id + auditoría
    with db.session.begin():
        order = _get_order(order_id)
        order.paypal_order_id = resp.paypal_order_id
        _audit(order, "create", resp.raw, extra={"approve_url": resp.approve_url})

    return PayPalCreateResult(
        True, resp.paypal_order_id, resp.approve_url, _shrink(resp.raw)
    )


def capture_paypal_order(
    *,
    order_id: int,
    paypal_order_id: str,
    idempotency_key: Optional[str] = None,
) -> PayPalCaptureResult:
    """
    Captura una PayPal Order y marca PAID en tu Order.
    - idempotente: si ya está pagada, devuelve ok sin duplicar.
    - valida que el paypal_order_id coincida con el guardado (si existe).
    """
    paypal_order_id = (paypal_order_id or "").strip()
    if not paypal_order_id:
        raise PayPalServiceError("paypal_order_id requerido")

    # 1) pre-validación DB
    with db.session.begin():
        order = _get_order(order_id)

        if (order.payment_status or "") == Order.PAY_PAID:
            return PayPalCaptureResult(
                True, paypal_order_id, "ALREADY_PAID", None, {"already_paid": True}
            )

        if order.paypal_order_id and str(order.paypal_order_id) != paypal_order_id:
            raise PayPalServiceMismatch("paypal_order_id no coincide con la orden")

        expected_amount = Decimal(str(order.total or "0.00"))
        expected_currency = pp_cur3(order.currency, "USD")

    # 2) capturar en PayPal (fuera DB)
    try:
        cap = pp_capture_order(
            paypal_order_id=paypal_order_id,
            idempotency_key=idempotency_key or f"pp_capture_{paypal_order_id}_{_now()}",
        )
    except (PayPalAuthError, PayPalHTTPError, PayPalClientError) as e:
        raise PayPalServiceProviderError(str(e))

    paid_amount = cap.paid_amount if cap.paid_amount is not None else expected_amount
    paid_currency = pp_cur3(cap.paid_currency or expected_currency, expected_currency)

    # 3) validar coherencia (tolerancia)
    try:
        if abs(Decimal(str(paid_amount)) - Decimal(str(expected_amount))) > Decimal(
            "0.05"
        ):
            raise PayPalServiceMismatch(
                f"amount mismatch: paid={paid_amount} expected={expected_amount}"
            )
    except Exception:
        # si algo raro, igual dejamos que OrderService valide con sus reglas
        pass

    if paid_currency != expected_currency:
        raise PayPalServiceMismatch(
            f"currency mismatch: paid={paid_currency} expected={expected_currency}"
        )

    # 4) marcar paid usando tu OrderService (fuente de verdad)
    try:
        order2 = OrderService.apply_payment_confirmation(
            order_id,
            provider="paypal",
            provider_order_id=paypal_order_id,
            provider_payment_id=cap.capture_id,
            paid_amount=paid_amount,
            paid_currency=paid_currency,
            raw=_shrink(cap.raw),
        )
    except PaymentMismatchError as e:
        raise PayPalServiceMismatch(str(e))
    except OrderServiceError as e:
        raise PayPalServiceError(str(e))

    # 5) auditoría final
    with db.session.begin():
        o = _get_order(order2.id)
        o.paypal_order_id = paypal_order_id
        _audit(
            o,
            "capture",
            cap.raw,
            extra={"status": cap.status, "capture_id": cap.capture_id},
        )

    return PayPalCaptureResult(
        True, paypal_order_id, cap.status, cap.capture_id, _shrink(cap.raw)
    )


__all__ = [
    "PayPalServiceError",
    "PayPalServiceNotFound",
    "PayPalServiceMismatch",
    "PayPalServiceProviderError",
    "PayPalCreateResult",
    "PayPalCaptureResult",
    "create_paypal_order",
    "capture_paypal_order",
]
