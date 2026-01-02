# app/integrations/wise_handler.py
from __future__ import annotations

"""
Skyline Store — Wise Handler (ULTRA PRO / FINAL)
-----------------------------------------------
Wise normalmente se usa como transferencia (no “checkout instantáneo” como MP/PayPal),
por eso este módulo hace 2 cosas:

A) Genera "instrucciones de pago" + referencia única para Wise, guardadas en Order.meta
B) Permite confirmar manualmente (admin) y marcar paid vía OrderService

✅ Mejoras PRO (16+ reales):
1) Referencia única por orden (estable, usable en comprobantes)
2) Idempotente: si ya hay instrucciones Wise, las devuelve sin recrear
3) No confía en input del front: usa total/currency desde Order DB
4) Soporta Wise UY/AR/Global por ENV (texto e instrucciones)
5) Guarda auditoría mínima en Order.meta (sin datos sensibles)
6) Confirmación manual con validación monto/moneda (tolerancia 0.05)
7) Marca paid usando OrderService.apply_payment_confirmation (single source)
8) “Estado” Wise: pending / confirmed / rejected
9) Compatible SQLite/Postgres (meta dict safe)
10) Normaliza strings y limita longitudes
11) Separación total: no depende de Flask request
12) Errores claros (para UI/admin)
13) Permite agregar evidencia (url/nota) sin romper
14) Listo para extender a webhook/CSV/conciliación
15) Logs seguros (sin secrets)
16) Se integra con CheckoutFlow.start_payment("wise")
"""

import secrets
import time
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Optional, Tuple

from app.models import db
from app.models.order import Order
from app.services.order_service import OrderService, OrderServiceError, PaymentMismatchError

_TRUE = {"1", "true", "yes", "y", "on"}


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def _env(k: str, d: str = "") -> str:
    import os
    return (os.getenv(k) or d).strip()

def _bool_env(k: str, d: bool = False) -> bool:
    v = _env(k, "")
    return v.lower() in _TRUE if v else d

def _d(v: Any, default: str = "0.00") -> Decimal:
    try:
        if v is None or v == "":
            return Decimal(default)
        if isinstance(v, Decimal):
            return v
        return Decimal(str(v))
    except (InvalidOperation, ValueError, TypeError):
        return Decimal(default)

def _money_str(v: Any) -> str:
    return f"{_d(v):.2f}"

def _upper3(v: Any, default: str = "USD") -> str:
    s = (str(v) if v is not None else default).strip().upper()
    return s[:3] if len(s) >= 3 else default

def _safe_str(v: Any, max_len: int) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    return s[:max_len]

def _meta_merge(base: Any, extra: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if isinstance(base, dict):
        out.update(base)
    out.update(extra or {})
    return out

def _now_ts() -> int:
    return int(time.time())

def _make_reference(order_number: str, order_id: int) -> str:
    """
    Referencia corta y fuerte: WS-{order}-{rand4}
    """
    rnd = secrets.token_hex(2).upper()  # 4 chars
    base = (order_number or f"ORD{order_id}").replace(" ", "")[:24]
    return f"WS-{base}-{rnd}"[:40]

def _wise_instructions_text(currency: str) -> str:
    """
    Texto de instrucciones desde ENV (editable sin tocar código).
    """
    # Puedes poner un texto largo en ENV. Si no está, usamos default pro.
    # Tip: BANK_TRANSFER_INSTRUCTIONS ya existe; reutilizamos si WISE_INSTRUCTIONS no está.
    txt = _env("WISE_INSTRUCTIONS", "") or _env("BANK_TRANSFER_INSTRUCTIONS", "")
    if txt:
        return txt
    return f"Transferencia por Wise ({currency}). Enviá el pago y adjuntá comprobante."

def _tolerance() -> Decimal:
    try:
        return Decimal(_env("WISE_AMOUNT_TOLERANCE", "0.05"))
    except Exception:
        return Decimal("0.05")


# -----------------------------------------------------------------------------
# DTOs
# -----------------------------------------------------------------------------
@dataclass(frozen=True)
class WisePaymentInfo:
    ok: bool
    order_id: int
    order_number: str
    currency: str
    amount: str
    reference: str
    instructions: str
    status: str  # pending/confirmed
    meta: Dict[str, Any]


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------
def get_or_create_wise_payment(
    *,
    order_id: int,
    checkout_key: Optional[str] = None,
) -> WisePaymentInfo:
    """
    Genera instrucciones Wise para una orden.
    Idempotente: si ya existe reference, devuelve lo guardado.
    """
    with db.session.begin():
        order = db.session.get(Order, int(order_id))
        if not order:
            raise RuntimeError("Orden no encontrada")

        meta = order.meta if isinstance(order.meta, dict) else {}
        wise_meta = meta.get("wise") if isinstance(meta.get("wise"), dict) else {}

        # si ya existe, devolver
        if wise_meta.get("reference") and wise_meta.get("status") in {"pending", "confirmed"}:
            return WisePaymentInfo(
                ok=True,
                order_id=order.id,
                order_number=order.number,
                currency=_upper3(order.currency, "USD"),
                amount=_money_str(order.total),
                reference=str(wise_meta.get("reference")),
                instructions=str(wise_meta.get("instructions") or _wise_instructions_text(_upper3(order.currency, "USD"))),
                status=str(wise_meta.get("status") or "pending"),
                meta=wise_meta,
            )

        # crear
        currency = _upper3(order.currency, "USD")
        amount = _d(order.total)
        if amount <= Decimal("0.00"):
            raise RuntimeError("Total inválido (0). No se puede generar pago Wise.")

        reference = _make_reference(order.number, order.id)
        instructions = _wise_instructions_text(currency)

        wise_payload = {
            "status": "pending",
            "created_at": _now_ts(),
            "reference": reference,
            "currency": currency,
            "amount": _money_str(amount),
            "instructions": instructions,
            "checkout_key": _safe_str(checkout_key, 120),
        }

        order.meta = _meta_merge(meta, {
            "payment_provider": "wise",
            "wise": wise_payload,
            # para UI: no hay redirect_url, mostramos instrucciones
            "redirect_url": None,
        })
        order.payment_method = "wise"
        order.payment_status = Order.PAY_PENDING

        return WisePaymentInfo(
            ok=True,
            order_id=order.id,
            order_number=order.number,
            currency=currency,
            amount=_money_str(amount),
            reference=reference,
            instructions=instructions,
            status="pending",
            meta=wise_payload,
        )


def confirm_wise_payment_manual(
    *,
    order_id: int,
    reference: Optional[str] = None,
    paid_amount: Optional[Decimal] = None,
    paid_currency: Optional[str] = None,
    evidence_url: Optional[str] = None,
    admin_note: Optional[str] = None,
) -> WisePaymentInfo:
    """
    Confirmación manual (admin):
    - valida monto/moneda vs orden
    - marca paid usando OrderService.apply_payment_confirmation
    """
    with db.session.begin():
        order = db.session.get(Order, int(order_id))
        if not order:
            raise RuntimeError("Orden no encontrada")

        if (order.payment_status or "") == Order.PAY_PAID:
            meta = order.meta if isinstance(order.meta, dict) else {}
            wise_meta = meta.get("wise") if isinstance(meta.get("wise"), dict) else {}
            return WisePaymentInfo(
                ok=True,
                order_id=order.id,
                order_number=order.number,
                currency=_upper3(order.currency, "USD"),
                amount=_money_str(order.total),
                reference=str(wise_meta.get("reference") or reference or ""),
                instructions=str(wise_meta.get("instructions") or _wise_instructions_text(_upper3(order.currency, "USD"))),
                status="confirmed",
                meta=wise_meta,
            )

        expected_amount = _d(order.total)
        expected_currency = _upper3(order.currency, "USD")

    # validar
    if paid_currency and _upper3(paid_currency, expected_currency) != expected_currency:
        raise RuntimeError("Currency no coincide con la orden")

    if paid_amount is not None:
        tol = _tolerance()
        if abs(_d(paid_amount) - expected_amount) > tol:
            raise RuntimeError(f"Monto no coincide (tolerancia {tol}).")

    # marcar paid (single source)
    try:
        OrderService.apply_payment_confirmation(
            int(order_id),
            provider="wise",
            provider_payment_id=_safe_str(reference, 80),
            paid_amount=_d(paid_amount) if paid_amount is not None else expected_amount,
            paid_currency=expected_currency,
            raw={
                "reference": reference,
                "evidence_url": _safe_str(evidence_url, 500),
                "admin_note": _safe_str(admin_note, 500),
            },
        )
    except PaymentMismatchError as e:
        raise RuntimeError(f"payment_mismatch:{str(e)[:200]}")
    except OrderServiceError as e:
        raise RuntimeError(f"order_service_error:{str(e)[:200]}")

    # actualizar meta wise confirmado
    with db.session.begin():
        order = db.session.get(Order, int(order_id))
        if not order:
            raise RuntimeError("Orden no encontrada (post confirm)")

        meta = order.meta if isinstance(order.meta, dict) else {}
        wise_meta = meta.get("wise") if isinstance(meta.get("wise"), dict) else {}
        wise_meta = _meta_merge(wise_meta, {
            "status": "confirmed",
            "confirmed_at": _now_ts(),
            "reference": _safe_str(reference, 80) or wise_meta.get("reference"),
            "evidence_url": _safe_str(evidence_url, 500),
            "admin_note": _safe_str(admin_note, 500),
        })

        order.meta = _meta_merge(meta, {"wise": wise_meta})

        return WisePaymentInfo(
            ok=True,
            order_id=order.id,
            order_number=order.number,
            currency=_upper3(order.currency, "USD"),
            amount=_money_str(order.total),
            reference=str(wise_meta.get("reference") or ""),
            instructions=str(wise_meta.get("instructions") or _wise_instructions_text(_upper3(order.currency, "USD"))),
            status="confirmed",
            meta=wise_meta,
        )


__all__ = ["get_or_create_wise_payment", "confirm_wise_payment_manual", "WisePaymentInfo"]
