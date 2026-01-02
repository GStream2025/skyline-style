from __future__ import annotations

"""
Skyline Store — MercadoPago Webhook
==================================
Procesador ULTRA PRO para webhooks de MercadoPago (UY / AR).

PRINCIPIO CLAVE:
❌ Nunca confiar en el webhook
✅ SIEMPRE validar contra la API de MercadoPago
"""

import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Optional, Tuple

import requests
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.models import db
from app.models.order import Order
from app.services.order_service import (
    OrderService,
    OrderServiceError,
    PaymentMismatchError,
)

log = logging.getLogger("mercadopago_webhook")
_SESSION = requests.Session()

# =============================================================================
# ENV / Helpers
# =============================================================================

_TRUE = {"1", "true", "yes", "y", "on"}

def _env(k: str, d: str = "") -> str:
    import os
    return (os.getenv(k) or d).strip()

def _bool_env(k: str, d: bool = False) -> bool:
    v = _env(k)
    return v.lower() in _TRUE if v else d

def _now() -> int:
    return int(time.time())

def _d(v: Any, default="0.00") -> Decimal:
    try:
        return Decimal(str(v))
    except (InvalidOperation, ValueError, TypeError):
        return Decimal(default)

def _currency(v: Any, default="USD") -> str:
    s = (str(v) if v else default).upper().strip()
    return s[:3] if len(s) >= 3 else default

def _json(raw: str) -> Dict[str, Any]:
    try:
        obj = json.loads(raw or "{}")
        return obj if isinstance(obj, dict) else {"_raw": obj}
    except Exception:
        return {"_invalid_json": True, "raw": (raw or "")[:2000]}

def _trunc(v: Any, n: int = 300) -> str:
    return str(v)[:n] if v is not None else ""

def _mp_token() -> str:
    return _env("MP_ACCESS_TOKEN")

def _mp_api() -> str:
    return _env("MP_API_BASE", "https://api.mercadopago.com").rstrip("/")

def _dry_run() -> bool:
    return _bool_env("MP_WEBHOOK_DRY_RUN", False)

# =============================================================================
# Result DTO
# =============================================================================

@dataclass(frozen=True)
class WebhookResult:
    ok: bool
    status: str     # processed | ignored | error
    message: str
    order_id: Optional[int] = None
    order_number: Optional[str] = None
    payment_id: Optional[str] = None
    raw_type: Optional[str] = None

# =============================================================================
# Signature (opcional)
# =============================================================================

def _verify_signature(headers: Dict[str, str], raw_body: str) -> Tuple[bool, str]:
    secret = _env("MP_WEBHOOK_SECRET")
    if not secret:
        return True, "no_secret"

    h = {k.lower(): v for k, v in headers.items()}
    sig = h.get("x-signature")
    ts = h.get("x-timestamp", "")
    rid = h.get("x-request-id", "")

    if not sig:
        return True, "no_signature"

    if ts.isdigit():
        delta = abs(_now() - int(ts))
        if delta > int(_env("MP_WEBHOOK_WINDOW_SEC", "300")):
            return False, "timestamp_outside_window"

    msg = f"{raw_body}|{ts}|{rid}"
    expected = hmac.new(
        secret.encode(), msg.encode(), hashlib.sha256
    ).hexdigest()

    sig = sig.replace("sha256=", "")
    return (
        hmac.compare_digest(sig, expected),
        "signature_ok" if sig == expected else "signature_invalid",
    )

# =============================================================================
# MercadoPago API
# =============================================================================

def _mp_get_payment(pid: str) -> Dict[str, Any]:
    token = _mp_token()
    if not token:
        raise RuntimeError("MP_ACCESS_TOKEN missing")

    url = f"{_mp_api()}/v1/payments/{pid}"
    headers = {"Authorization": f"Bearer {token}"}

    for i in range(3):
        try:
            r = _SESSION.get(url, headers=headers, timeout=8)
        except requests.RequestException as e:
            if i == 2:
                raise RuntimeError(str(e))
            time.sleep(0.5 * (i + 1))
            continue

        if r.status_code == 200:
            return r.json()
        if r.status_code in {401, 403}:
            raise RuntimeError("MP token invalid")
        if 500 <= r.status_code < 600:
            if i == 2:
                raise RuntimeError("MP 5xx")
            time.sleep(0.5 * (i + 1))
            continue

        raise RuntimeError(f"MP error {r.status_code}: {r.text[:200]}")

# =============================================================================
# Payload helpers
# =============================================================================

def _payment_id(payload: Dict[str, Any]) -> Optional[str]:
    if isinstance(payload.get("data"), dict):
        return str(payload["data"].get("id") or "").strip() or None
    if payload.get("id"):
        return str(payload["id"]).strip()
    res = payload.get("resource")
    if isinstance(res, str) and "/payments/" in res:
        return res.split("/payments/")[-1].split("?")[0]
    return None

def _type(payload: Dict[str, Any]) -> str:
    return (payload.get("type") or payload.get("topic") or "unknown").lower()

# =============================================================================
# Order lookup
# =============================================================================

def _find_order(payment: Dict[str, Any]) -> Optional[Order]:
    pid = str(payment.get("id") or "")
    ext = str(payment.get("external_reference") or "")
    meta = payment.get("metadata") or {}

    if pid:
        q = select(Order).where(Order.mp_payment_id == pid)
        o = db.session.execute(q).scalars().first()
        if o:
            return o

    if ext:
        q = select(Order).where(Order.number == ext)
        o = db.session.execute(q).scalars().first()
        if o:
            return o

    if meta.get("order_id"):
        try:
            q = select(Order).where(Order.id == int(meta["order_id"]))
            return db.session.execute(q).scalars().first()
        except Exception:
            pass

    ck = meta.get("checkout_key")
    if ck:
        try:
            q = select(Order).where(Order.meta["idempotency_key"].astext == ck)  # type: ignore
            return db.session.execute(q).scalars().first()
        except Exception:
            pass

    return None

# =============================================================================
# State helpers
# =============================================================================

def _is_paid(p: Dict[str, Any]) -> bool:
    return (p.get("status") or "").lower() in {"approved", "authorized"}

def _is_refunded(p: Dict[str, Any]) -> bool:
    return (p.get("status") or "").lower() in {"refunded", "charged_back"}

def _is_failed(p: Dict[str, Any]) -> bool:
    return (p.get("status") or "").lower() in {"rejected", "cancelled"}

# =============================================================================
# PUBLIC ENTRYPOINT
# =============================================================================

def handle_webhook(*, raw_body: str, headers: Optional[Dict[str, str]] = None) -> WebhookResult:
    headers = headers or {}
    payload = _json(raw_body)
    raw_type = _type(payload)

    ok_sig, sig_msg = _verify_signature(headers, raw_body)
    if not ok_sig:
        return WebhookResult(False, "error", f"signature:{sig_msg}", raw_type=raw_type)

    pid = _payment_id(payload)
    if not pid:
        return WebhookResult(True, "ignored", "no_payment_id", raw_type=raw_type)

    try:
        payment = _mp_get_payment(pid)
    except Exception as e:
        return WebhookResult(False, "error", f"mp_fetch:{_trunc(e)}", payment_id=pid)

    try:
        with db.session.begin():
            order = _find_order(payment)
            if not order:
                return WebhookResult(True, "ignored", "order_not_found", payment_id=pid)

            order.meta = {
                **(order.meta or {}),
                "mp_last_event": {
                    "at": _now(),
                    "status": payment.get("status"),
                    "detail": payment.get("status_detail"),
                    "signature": sig_msg,
                },
            }

            if not order.mp_payment_id:
                order.mp_payment_id = pid

            if _dry_run():
                return WebhookResult(True, "processed", "dry_run", order.id, order.number, pid)

        if _is_paid(payment):
            try:
                o2 = OrderService.apply_payment_confirmation(
                    order.id,
                    provider="mercadopago",
                    provider_payment_id=pid,
                    paid_amount=_d(payment.get("transaction_amount")),
                    paid_currency=_currency(payment.get("currency_id")),
                    raw=payment,
                )
                return WebhookResult(True, "processed", "paid", o2.id, o2.number, pid)
            except PaymentMismatchError as e:
                return WebhookResult(False, "error", f"mismatch:{_trunc(e)}", order.id, pid)
            except OrderServiceError as e:
                return WebhookResult(False, "error", f"service:{_trunc(e)}", order.id, pid)

        if _is_refunded(payment):
            with db.session.begin():
                order.mark_refunded()
            return WebhookResult(True, "processed", "refunded", order.id, order.number, pid)

        if _is_failed(payment):
            with db.session.begin():
                order.payment_status = Order.PAY_FAILED
            return WebhookResult(True, "processed", "failed", order.id, order.number, pid)

        return WebhookResult(True, "processed", "pending", order.id, order.number, pid)

    except SQLAlchemyError as e:
        return WebhookResult(False, "error", f"db:{_trunc(e)}", payment_id=pid)


__all__ = ["handle_webhook", "WebhookResult"]
