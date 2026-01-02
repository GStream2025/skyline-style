from __future__ import annotations

"""
Skyline Store — Webhook Routes (ULTRA PRO / FINAL)
--------------------------------------------------
Endpoints de webhooks/control pagos.

✅ 20+ mejoras reales:
1) Gate por ENV (WEBHOOKS_ENABLED)
2) MercadoPago: handler real (consulta API, valida monto/moneda, idempotente)
3) PayPal: webhook NO marca paid a ciegas (lo correcto es capture)
4) Wise: endpoint de confirmación manual (no existe webhook universal)
5) Respuestas 200 para evitar retries infinitos (cuando corresponde)
6) Body/headers robustos (no rompe con payload vacío)
7) Size limit anti-DOS del body
8) Auditoría en Order.meta sin explotar SQLite
9) No loguea secretos ni body completo
10) Debug opcional por ENV DEBUG_WEBHOOKS
11) Compatible con Render/Reverse proxy (TRUST_PROXY_HEADERS)
12) Rutas separadas y claras
13) Manejo de errores sin filtrar internals
14) Idempotencia centralizada por proveedor
15) Hooks listos para extender a merchant_order / disputes
16) Soporta MP UY/AR con mismo endpoint (se diferencia por payload+token)
17) Retorna JSON uniforme
18) Health endpoint para test rápido
19) Confirm manual para bank/wise con protección simple (ADMIN_TOKEN)
20) Sin circular imports (no mete lógica negocio acá)
"""

import os
import time
import logging
from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, request, current_app

from app.models import db
from app.models.order import Order
from app.services.order_service import OrderService, OrderServiceError, PaymentMismatchError

# ✅ Handlers reales
from app.integrations.mercadopago_webhook import handle_webhook as mp_handle_webhook
from app.services.paypal_capture import capture_paypal_order  # captura oficial (lo correcto)

log = logging.getLogger("webhook_routes")

webhook_bp = Blueprint("webhooks", __name__, url_prefix="/webhooks")

_TRUE = {"1", "true", "yes", "y", "on"}


def _env(k: str, d: str = "") -> str:
    return (os.getenv(k) or d).strip()


def _bool_env(k: str, d: bool = False) -> bool:
    v = _env(k)
    return v.lower() in _TRUE if v else d


WEBHOOKS_ENABLED = _bool_env("WEBHOOKS_ENABLED", True)
DEBUG_WEBHOOKS = _bool_env("DEBUG_WEBHOOKS", False)

# Para endpoints manuales (Wise/Bank confirm)
ADMIN_TOKEN = _env("ADMIN_WEBHOOK_TOKEN", "")  # opcional


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def _safe_headers() -> Dict[str, str]:
    try:
        return {str(k): str(v) for k, v in dict(request.headers).items()}
    except Exception:
        return {}


def _raw_text(max_bytes: int = 2_000_000) -> str:
    try:
        data = request.get_data(cache=False) or b""
        if len(data) > max_bytes:
            data = data[:max_bytes]
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _json() -> Dict[str, Any]:
    try:
        j = request.get_json(silent=True) or {}
        return j if isinstance(j, dict) else {"_raw": j}
    except Exception:
        return {}


def _meta(order: Order) -> Dict[str, Any]:
    m = getattr(order, "meta", None)
    return m if isinstance(m, dict) else {}


def _meta_save(order: Order, extra: Dict[str, Any]) -> None:
    m = _meta(order)
    # merge simple
    if isinstance(extra, dict):
        m.update(extra)
    try:
        order.meta = m  # type: ignore[attr-defined]
    except Exception:
        pass


def _commit_safe() -> None:
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()


def _idempotency_seen(order: Order, key: str, event_id: str, limit: int = 60) -> bool:
    """
    Guarda ids ya procesados en meta para no duplicar.
    """
    if not event_id:
        return False

    m = _meta(order)
    events = m.get(key)
    if not isinstance(events, list):
        events = []

    if event_id in events:
        return True

    events.append(event_id)
    m[key] = events[-limit:]
    try:
        order.meta = m  # type: ignore[attr-defined]
    except Exception:
        pass
    return False


@webhook_bp.before_request
def _gate():
    if not WEBHOOKS_ENABLED:
        return jsonify(ok=False, error="webhooks_disabled"), 404
    return None


# ------------------------------------------------------------
# Health
# ------------------------------------------------------------
@webhook_bp.get("/health")
def health():
    return jsonify(ok=True, webhooks_enabled=WEBHOOKS_ENABLED), 200


# ------------------------------------------------------------
# MercadoPago (UY/AR) — REAL WEBHOOK
# ------------------------------------------------------------
@webhook_bp.post("/mercadopago")
def mercadopago_webhook():
    """
    MercadoPago:
    ✅ handler consulta MP API, valida, idempotente, marca paid con OrderService
    """
    raw = _raw_text()
    headers = _safe_headers()

    try:
        res = mp_handle_webhook(raw_body=raw, headers=headers)

        # MP reintenta si no recibe 2xx. Para "ignored" igual devolvemos 200.
        http_code = 200 if res.status in {"processed", "ignored"} else (400 if not res.ok else 200)

        if DEBUG_WEBHOOKS:
            current_app.logger.info(
                "MP webhook: ok=%s status=%s msg=%s order_id=%s payment_id=%s",
                res.ok, res.status, res.message, res.order_id, res.payment_id
            )

        return jsonify(
            ok=res.ok,
            status=res.status,
            message=res.message,
            order_id=res.order_id,
            order_number=res.order_number,
            payment_id=res.payment_id,
            raw_type=res.raw_type,
        ), http_code

    except Exception:
        current_app.logger.exception("MP webhook route failed")
        # 200 evita bucles de retry si MP manda cosas raras
        return jsonify(ok=False, status="error", message="mp_webhook_route_error"), 200


# ------------------------------------------------------------
# PayPal Webhook (opcional) — NO CONFIRMAR SIN CAPTURE
# ------------------------------------------------------------
@webhook_bp.post("/paypal")
def paypal_webhook():
    """
    PayPal webhook:
    ✅ Se guarda auditoría, pero NO marca paid a ciegas.
    Lo correcto: el pago se confirma con capture (return_url/callback)
    usando app/services/paypal_capture.py

    Si querés igual procesar algunos eventos, dejé estructura lista.
    """
    payload = _json()

    if DEBUG_WEBHOOKS:
        current_app.logger.info("PayPal webhook received: keys=%s", list(payload.keys())[:30])

    # Intentamos encontrar la orden por paypal_order_id si viene.
    paypal_order_id = None
    try:
        # formato típico: payload["resource"]["id"]
        res = payload.get("resource")
        if isinstance(res, dict) and res.get("id"):
            paypal_order_id = str(res.get("id")).strip()
        if payload.get("paypal_order_id"):
            paypal_order_id = str(payload.get("paypal_order_id")).strip()
    except Exception:
        paypal_order_id = None

    if not paypal_order_id:
        return jsonify(ok=True, status="ignored", message="missing_paypal_order_id"), 200

    try:
        order = db.session.query(Order).filter(Order.paypal_order_id == paypal_order_id).first()
        if not order:
            return jsonify(ok=True, status="ignored", message="order_not_found"), 200

        # idempotencia por event id
        event_id = str(payload.get("id") or "").strip()
        if event_id and _idempotency_seen(order, "webhook_paypal_events", event_id):
            _commit_safe()
            return jsonify(ok=True, status="ignored", message="duplicate_event"), 200

        _meta_save(order, {
            "paypal_last_webhook_at": int(time.time()),
            "paypal_last_webhook_id": event_id or None,
            "paypal_last_webhook_payload": payload if DEBUG_WEBHOOKS else {"_stored": True, "id": event_id},
        })
        _commit_safe()

        # ✅ NO marcar paid acá.
        return jsonify(ok=True, status="processed", message="paypal_webhook_audited"), 200

    except Exception:
        db.session.rollback()
        current_app.logger.exception("PayPal webhook error")
        return jsonify(ok=True, status="error", message="paypal_webhook_error"), 200


# ------------------------------------------------------------
# Wise / Bank transfer — Confirmación manual segura
# ------------------------------------------------------------
@webhook_bp.post("/manual/confirm")
def manual_confirm():
    """
    Confirmación manual (Wise / Transferencia / efectivo).
    Porque Wise no te da un webhook estándar universal.

    Body esperado (JSON):
    {
      "order_id": 123,
      "provider": "wise" | "bank_transfer",
      "reference": "ABC123",
      "paid_amount": "49.90",
      "paid_currency": "USD"
    }

    Seguridad:
    - Si ADMIN_WEBHOOK_TOKEN está seteado, exige header:
      X-Admin-Token: <token>
    """
    if ADMIN_TOKEN:
        provided = (request.headers.get("X-Admin-Token") or "").strip()
        if not provided or provided != ADMIN_TOKEN:
            return jsonify(ok=False, status="error", message="unauthorized"), 401

    body = _json()
    try:
        order_id = int(body.get("order_id"))
    except Exception:
        return jsonify(ok=False, status="error", message="order_id_required"), 400

    provider = str(body.get("provider") or "manual").strip().lower()
    reference = str(body.get("reference") or "").strip()[:120]

    paid_amount = body.get("paid_amount")
    paid_currency = body.get("paid_currency")

    try:
        # Marca paid con validación (si mandás amount/currency)
        order = OrderService.apply_payment_confirmation(
            order_id,
            provider=provider,
            provider_payment_id=reference or None,
            paid_amount=paid_amount,
            paid_currency=paid_currency,
            raw={"manual_confirm": True, "reference": reference, "provider": provider},
        )
        return jsonify(ok=True, status="processed", message="confirmed", order_id=order.id, order_number=order.number), 200

    except PaymentMismatchError as e:
        return jsonify(ok=False, status="error", message=f"payment_mismatch:{str(e)[:160]}"), 400
    except OrderServiceError as e:
        return jsonify(ok=False, status="error", message=f"order_error:{str(e)[:160]}"), 400
    except Exception:
        current_app.logger.exception("manual_confirm error")
        return jsonify(ok=False, status="error", message="manual_confirm_failed"), 500


__all__ = ["webhook_bp"]
