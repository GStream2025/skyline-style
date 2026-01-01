# app/routes/webhook_routes.py
from __future__ import annotations

import os
import hmac
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, jsonify, request, current_app

from app.models import db, Order


webhook_bp = Blueprint("webhooks", __name__, url_prefix="/webhooks")

_TRUE = {"1", "true", "yes", "y", "on"}
WEBHOOKS_ENABLED = (os.getenv("WEBHOOKS_ENABLED", "1").strip().lower() in _TRUE)

# ⚠️ Firma HMAC simple (tuya). Recomendado si tus webhooks pasan por tu infra (o proxy propio).
# MercadoPago y PayPal tienen verificación oficial más compleja; esto es un “blindaje adicional” opcional.
MP_WEBHOOK_SECRET = (os.getenv("MP_WEBHOOK_SECRET") or "").strip()
PAYPAL_WEBHOOK_SECRET = (os.getenv("PAYPAL_WEBHOOK_SECRET") or "").strip()

# Idempotencia (opcional):
# Si tu Order.meta es JSON, guardamos ids de eventos para no procesar 2 veces.
WEBHOOK_IDEMPOTENCY = (os.getenv("WEBHOOK_IDEMPOTENCY", "1").strip().lower() in _TRUE)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _safe_json() -> Dict[str, Any]:
    return request.get_json(silent=True) or {}


def _raw_body() -> bytes:
    try:
        return request.get_data(cache=False) or b""
    except Exception:
        return b""


def _hmac_ok(secret: str, body_bytes: bytes, provided: str) -> bool:
    if not secret:
        return True  # modo dev (no bloquea)
    if not provided:
        return False
    mac = hmac.new(secret.encode("utf-8"), msg=body_bytes, digestmod=hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, provided.strip().lower())


def _meta_get(order: Order) -> Dict[str, Any]:
    try:
        m = getattr(order, "meta", None)
        if isinstance(m, dict):
            return m
    except Exception:
        pass
    return {}


def _meta_set(order: Order, meta: Dict[str, Any]) -> None:
    try:
        order.meta = meta  # type: ignore[attr-defined]
    except Exception:
        # si tu columna meta no existe o no es asignable, ignoramos
        pass


def _idempotency_seen(order: Order, provider: str, event_id: str) -> bool:
    if not WEBHOOK_IDEMPOTENCY:
        return False
    if not event_id:
        return False

    meta = _meta_get(order)
    key = f"webhook_{provider}_events"
    events = meta.get(key)

    if not isinstance(events, list):
        events = []
    if event_id in events:
        return True

    # append y limitar para no crecer infinito
    events.append(event_id)
    events = events[-50:]
    meta[key] = events
    _meta_set(order, meta)
    return False


def _commit_safe() -> bool:
    try:
        db.session.commit()
        return True
    except Exception:
        db.session.rollback()
        return False


def _mark_paid_if_possible(order: Order, provider: str, ref: Optional[str] = None) -> None:
    """
    Marca paid de forma segura (idempotente por status).
    NO rompe aunque Order no tenga helpers.
    """
    try:
        if (getattr(order, "payment_status", "") or "").lower() == "paid":
            return

        if hasattr(order, "mark_paid") and callable(getattr(order, "mark_paid")):
            order.mark_paid()  # type: ignore[attr-defined]
        else:
            order.status = "paid"
            order.payment_status = "paid"
            if hasattr(order, "paid_at"):
                order.paid_at = utcnow()

        # guardar referencia gateway en campos si existen
        if provider == "mercadopago" and ref and hasattr(order, "mp_payment_id") and not getattr(order, "mp_payment_id", None):
            order.mp_payment_id = str(ref)[:120]
        if provider == "paypal" and ref and hasattr(order, "paypal_order_id") and not getattr(order, "paypal_order_id", None):
            order.paypal_order_id = str(ref)[:120]

        _commit_safe()
    except Exception:
        db.session.rollback()


@webhook_bp.before_request
def _gate():
    if not WEBHOOKS_ENABLED:
        return jsonify(ok=False, error="webhooks_disabled"), 404
    return None


# ============================================================
# MercadoPago webhook
# ============================================================

def _mp_extract(payload: Dict[str, Any]) -> Tuple[Optional[str], Optional[int], Optional[str]]:
    """
    Devuelve (order_number, order_id, event_id)
    - event_id se usa para idempotencia
    """
    order_number = None
    order_id = None
    event_id = None

    # algunos payloads típicos
    if payload.get("external_reference"):
        order_number = str(payload.get("external_reference"))

    md = payload.get("metadata")
    if isinstance(md, dict):
        if md.get("order_id") is not None:
            try:
                order_id = int(md.get("order_id"))
            except Exception:
                order_id = None

    # evento / payment id (varía)
    # lo guardamos como event_id por idempotencia
    for k in ("id", "payment_id", "data.id"):
        if k == "data.id":
            data = payload.get("data")
            if isinstance(data, dict) and data.get("id"):
                event_id = str(data.get("id"))
        else:
            if payload.get(k):
                event_id = str(payload.get(k))

    # fallback: si viene order_number explícito
    if payload.get("order_number"):
        order_number = str(payload.get("order_number"))

    return order_number, order_id, event_id


@webhook_bp.post("/mercadopago")
def mp_webhook():
    """
    MercadoPago pega acá.

    - Si configurás MP_WEBHOOK_SECRET:
      Header esperado: X-MP-Signature = HMAC_SHA256(raw_body)

    ⚠️ Nota: verificación oficial de MP suele requerir consultar su API.
    Acá hacemos un flujo robusto + idempotente, y marcamos paid SOLO si encontramos la orden.
    """
    raw = _raw_body()
    sig = (request.headers.get("X-MP-Signature") or "").strip()
    if MP_WEBHOOK_SECRET and not _hmac_ok(MP_WEBHOOK_SECRET, raw, sig):
        return jsonify(ok=False, error="invalid_signature"), 401

    payload = _safe_json()
    current_app.logger.info("MP webhook received")

    order_number, order_id, event_id = _mp_extract(payload)

    order = None
    try:
        if order_id:
            order = db.session.get(Order, int(order_id))
        elif order_number:
            order = db.session.query(Order).filter(Order.number == str(order_number)).first()
    except Exception:
        order = None

    if not order:
        # no rompemos: devolvemos ok para evitar reintentos infinitos
        return jsonify(ok=True, ignored=True, reason="order_not_found")

    # idempotencia
    if event_id and _idempotency_seen(order, "mercadopago", event_id):
        return jsonify(ok=True, ignored=True, reason="duplicate_event")

    # Guardar raw payload en meta si existe (útil para auditoría)
    meta = _meta_get(order)
    meta["last_webhook_mercadopago_at"] = utcnow().isoformat()
    meta["last_webhook_mercadopago_payload"] = payload
    _meta_set(order, meta)
    _commit_safe()

    # ✅ Marcado paid (mínimo viable).
    # Recomendación: en producción, confirmar estado con MP API usando payment_id.
    ref = event_id or payload.get("payment_id") or payload.get("id")
    _mark_paid_if_possible(order, "mercadopago", ref=str(ref) if ref else None)

    return jsonify(ok=True, processed=True)


# ============================================================
# PayPal webhook
# ============================================================

def _paypal_extract(payload: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """
    Devuelve (paypal_order_id, event_id)
    """
    event_id = str(payload.get("id")) if payload.get("id") else None

    paypal_order_id = None
    res = payload.get("resource")
    if isinstance(res, dict):
        if res.get("id"):
            paypal_order_id = str(res.get("id"))

    if payload.get("paypal_order_id"):
        paypal_order_id = str(payload.get("paypal_order_id"))

    return paypal_order_id, event_id


@webhook_bp.post("/paypal")
def paypal_webhook():
    """
    PayPal pega acá (events).

    - Si configurás PAYPAL_WEBHOOK_SECRET:
      Header esperado: X-PAYPAL-Signature = HMAC_SHA256(raw_body)

    ⚠️ Nota: verificación oficial PayPal es más compleja (transmission_id/cert_url/auth_algo).
    Acá dejamos un modo robusto + idempotente sin romper tu tienda.
    """
    raw = _raw_body()
    sig = (request.headers.get("X-PAYPAL-Signature") or "").strip()
    if PAYPAL_WEBHOOK_SECRET and not _hmac_ok(PAYPAL_WEBHOOK_SECRET, raw, sig):
        return jsonify(ok=False, error="invalid_signature"), 401

    payload = _safe_json()
    current_app.logger.info("PayPal webhook received")

    paypal_order_id, event_id = _paypal_extract(payload)

    if not paypal_order_id:
        return jsonify(ok=True, ignored=True, reason="missing_paypal_order_id")

    order = None
    try:
        order = db.session.query(Order).filter(Order.paypal_order_id == str(paypal_order_id)).first()
    except Exception:
        order = None

    if not order:
        return jsonify(ok=True, ignored=True, reason="order_not_found")

    # idempotencia
    if event_id and _idempotency_seen(order, "paypal", event_id):
        return jsonify(ok=True, ignored=True, reason="duplicate_event")

    # auditoría
    meta = _meta_get(order)
    meta["last_webhook_paypal_at"] = utcnow().isoformat()
    meta["last_webhook_paypal_payload"] = payload
    _meta_set(order, meta)
    _commit_safe()

    # ✅ Marcado paid mínimo viable (recomendado: validar con PayPal API en prod)
    _mark_paid_if_possible(order, "paypal", ref=paypal_order_id)

    return jsonify(ok=True, processed=True)


__all__ = ["webhook_bp"]
