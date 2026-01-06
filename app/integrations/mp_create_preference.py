from __future__ import annotations

"""
Wise Handler — FINAL ABSOLUTO (Service)
======================================

CAPA DE SERVICIO (DB + negocio) — NO hace HTTP real por defecto.
Wise normalmente se usa como “transferencia” (bank-like) y se confirma:
- manualmente (panel admin)
- o con un webhook externo propio (si vos lo tenés)

16+ mejoras reales:
1) Genera referencia única por orden (anti-confusión)
2) Guarda instrucciones en Order.meta (portable)
3) Soporta UYU/USD y cuentas diferentes por moneda (ENV)
4) Modo "strict" valida monto/moneda si confirmás
5) Idempotente: no confirma dos veces
6) No rompe si meta no es dict
7) Auditoría completa (timestamps, actor, notas)
8) Helpers listos para admin/route
9) No depende de Flask request
10) No loguea datos sensibles
11) Soporta “proof” (comprobante) sin guardar binarios
12) Normaliza strings y limites
13) Compatible SQLite/Postgres
14) Compatible con OrderService (fuente de verdad)
15) Ready para webhook externo (si después lo conectás)
16) No se toca más

ENV sugeridas:
- WISE_RECIPIENT_NAME="Skyline Store"
- WISE_INSTRUCTIONS_UYU="BROU ... / Alias ... / Ref: {{ref}}"
- WISE_INSTRUCTIONS_USD="Wise ... / IBAN ... / Ref: {{ref}}"
Opcional:
- WISE_DEFAULT_CURRENCY=UYU
"""

import secrets
import time
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Optional

from app.models import db
from app.models.order import Order
from app.services.order_service import (
    OrderService,
    OrderServiceError,
    PaymentMismatchError,
)


# =============================================================================
# Errors
# =============================================================================


class WiseError(RuntimeError): ...


class WiseNotFound(WiseError): ...


class WiseAlreadyPaid(WiseError): ...


class WiseValidationError(WiseError): ...


# =============================================================================
# DTO
# =============================================================================


@dataclass(frozen=True)
class WiseStartResult:
    provider: str
    order_id: int
    order_number: str
    currency: str
    amount: str
    reference: str
    instructions: str


# =============================================================================
# Helpers
# =============================================================================

_TRUE = {"1", "true", "yes", "y", "on"}


def _env(k: str, d: str = "") -> str:
    import os

    return (os.getenv(k) or d).strip()


def _d(v: Any, default: str = "0.00") -> Decimal:
    try:
        if v is None or v == "":
            return Decimal(default)
        return Decimal(str(v))
    except (InvalidOperation, TypeError, ValueError):
        return Decimal(default)


def _cur3(v: Any, default: str = "UYU") -> str:
    s = (str(v) if v else default).strip().upper()
    return s[:3] if len(s) >= 3 else default


def _merge(a: Any, b: Dict[str, Any]) -> Dict[str, Any]:
    out = a if isinstance(a, dict) else {}
    out.update(b or {})
    return out


def _token_ref(prefix: str = "WISE") -> str:
    # ref corta, segura, legible
    return f"{prefix}-{secrets.token_hex(4).upper()}-{int(time.time())}"


def _render_template(text: str, *, ref: str, order: Order) -> str:
    # template simple: {{ref}} {{order_number}} {{amount}} {{currency}}
    if not text:
        return ""
    return (
        text.replace("{{ref}}", ref)
        .replace("{{order_number}}", order.number or "")
        .replace("{{amount}}", f"{_d(order.total):.2f}")
        .replace("{{currency}}", _cur3(order.currency, "UYU"))
    )


# =============================================================================
# Public API
# =============================================================================


def start_wise_transfer(
    *,
    order_id: int,
    currency: Optional[str] = None,
    note: str = "",
) -> WiseStartResult:
    """
    Prepara pago por Wise como transferencia (instrucciones).
    Guarda todo en Order.meta para que tu UI lo muestre.
    """
    with db.session.begin():
        order = db.session.get(Order, int(order_id))
        if not order:
            raise WiseNotFound("Orden no encontrada")

        if (order.payment_status or "") == Order.PAY_PAID:
            raise WiseAlreadyPaid("La orden ya está pagada")

        cur = _cur3(
            currency or order.currency or _env("WISE_DEFAULT_CURRENCY", "UYU"), "UYU"
        )

        # referencia idempotente: si ya existe, reusamos
        meta = order.meta if isinstance(order.meta, dict) else {}
        ref = str(meta.get("wise_ref") or "").strip()
        if not ref:
            ref = _token_ref("WISE")

        instr_uyu = _env("WISE_INSTRUCTIONS_UYU", "")
        instr_usd = _env("WISE_INSTRUCTIONS_USD", "")
        base_instr = instr_usd if cur == "USD" else instr_uyu
        if not base_instr:
            # fallback universal
            base_instr = (
                "Transferencia vía Wise. Referencia: {{ref}}. Orden: {{order_number}}."
            )

        instructions = _render_template(base_instr, ref=ref, order=order)[:1200]

        order.payment_method = "wise"
        order.payment_status = Order.PAY_PENDING
        order.status = Order.STATUS_AWAITING_PAYMENT

        order.meta = _merge(
            order.meta,
            {
                "payment_provider": "wise",
                "wise_ref": ref,
                "wise_currency": cur,
                "wise_amount": f"{_d(order.total):.2f}",
                "wise_started_at": int(time.time()),
                "wise_instructions": instructions,
                "wise_note": (note or "")[:300] or None,
            },
        )

    return WiseStartResult(
        provider="wise",
        order_id=order_id,
        order_number=order.number,
        currency=_cur3(order.currency, "UYU"),
        amount=f"{_d(order.total):.2f}",
        reference=ref,
        instructions=instructions,
    )


def confirm_wise_paid(
    *,
    order_id: int,
    paid_amount: Optional[Any] = None,
    paid_currency: Optional[str] = None,
    reference: Optional[str] = None,
    proof_url: Optional[str] = None,
    actor: str = "system",
    note: str = "",
    strict: bool = True,
) -> Order:
    """
    Confirma pago Wise (manual/admin o webhook externo).
    strict=True:
      - valida monto/moneda si vienen
      - valida referencia si viene
    """
    with db.session.begin():
        order = db.session.get(Order, int(order_id))
        if not order:
            raise WiseNotFound("Orden no encontrada")

        if (order.payment_status or "") == Order.PAY_PAID:
            return order  # idempotente

        meta = order.meta if isinstance(order.meta, dict) else {}
        saved_ref = str(meta.get("wise_ref") or "").strip()

        if strict and reference and saved_ref and reference.strip() != saved_ref:
            raise WiseValidationError("Referencia Wise no coincide")

        exp_amt = _d(order.total)
        exp_cur = _cur3(order.currency, "UYU")

        amt = _d(paid_amount, str(exp_amt)) if paid_amount is not None else exp_amt
        cur = _cur3(paid_currency or exp_cur, exp_cur)

        if strict:
            if abs(amt - exp_amt) > Decimal("0.05"):
                raise WiseValidationError("Monto no coincide")
            if cur != exp_cur:
                raise WiseValidationError("Moneda no coincide")

    # Confirmación oficial (fuente de verdad)
    try:
        order2 = OrderService.apply_payment_confirmation(
            order_id,
            provider="wise",
            provider_payment_id=reference or saved_ref or None,
            paid_amount=amt,
            paid_currency=cur,
            raw={
                "wise_ref": reference or saved_ref or None,
                "proof_url": (proof_url or "")[:700] or None,
                "actor": (actor or "system")[:80],
                "note": (note or "")[:400] or None,
            },
        )
    except (PaymentMismatchError, OrderServiceError) as e:
        raise WiseError(str(e))

    # Auditoría extra
    with db.session.begin():
        order = db.session.get(Order, int(order2.id))
        order.meta = _merge(
            order.meta,
            {
                "wise_confirmed_at": int(time.time()),
                "wise_confirmed_by": (actor or "system")[:80],
                "wise_proof_url": (proof_url or "")[:700] or None,
                "wise_confirm_note": (note or "")[:400] or None,
            },
        )

    return order2


__all__ = [
    "WiseStartResult",
    "start_wise_transfer",
    "confirm_wise_paid",
    "WiseError",
    "WiseNotFound",
    "WiseAlreadyPaid",
    "WiseValidationError",
]
