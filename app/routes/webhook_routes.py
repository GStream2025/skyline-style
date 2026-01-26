from __future__ import annotations

import os
import time
import logging
from typing import Any, Dict

from flask import Blueprint, jsonify, request, current_app

from app.models import db
from app.models.order import Order
from app.services.order_service import (
    OrderService,
    OrderServiceError,
    PaymentMismatchError,
)
from app.integrations.mercadopago_webhook import handle_webhook as mp_handle_webhook

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
ADMIN_TOKEN = _env("ADMIN_WEBHOOK_TOKEN", "")


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
        return j if isinstance(j, dict) else {}
    except Exception:
        return {}


def _meta(order: Order) -> Dict[str, Any]:
    m = getattr(order, "meta", None)
    return m if isinstance(m, dict) else {}


def _meta_save(order: Order, extra: Dict[str, Any]) -> None:
    try:
        m = _meta(order)
        m.update(extra)
        order.meta = m  # type: ignore[attr-defined]
    except Exception:
        pass


def _commit_safe() -> None:
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()


def _idempotency_seen(order: Order, key: str, event_id: str, limit: int = 60) -> bool:
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
        return jsonify(ok=False, error="disabled"), 404
    return None


@webhook_bp.get("/health")
def health():
    return jsonify(ok=True), 200


@webhook_bp.post("/mercadopago")
def mercadopago_webhook():
    raw = _raw_text()
    headers = _safe_headers()

    try:
        res = mp_handle_webhook(raw_body=raw, headers=headers)
        http_code = 200 if res.status in {"processed", "ignored"} else 400

        if DEBUG_WEBHOOKS:
            current_app.logger.info(
                "mp webhook ok=%s status=%s order=%s payment=%s",
                res.ok,
                res.status,
                res.order_id,
                res.payment_id,
            )

        return (
            jsonify(
                ok=res.ok,
                status=res.status,
                message=res.message,
                order_id=res.order_id,
                order_number=res.order_number,
                payment_id=res.payment_id,
            ),
            http_code,
        )
    except Exception:
        current_app.logger.exception("mp_webhook_error")
        return jsonify(ok=False, status="error"), 200


@webhook_bp.post("/paypal")
def paypal_webhook():
    payload = _json()

    paypal_order_id = None
    try:
        res = payload.get("resource")
        if isinstance(res, dict) and res.get("id"):
            paypal_order_id = str(res["id"]).strip()
        if payload.get("paypal_order_id"):
            paypal_order_id = str(payload["paypal_order_id"]).strip()
    except Exception:
        paypal_order_id = None

    if not paypal_order_id:
        return jsonify(ok=True, status="ignored"), 200

    try:
        order = (
            db.session.query(Order)
            .filter(Order.paypal_order_id == paypal_order_id)
            .first()
        )
        if not order:
            return jsonify(ok=True, status="ignored"), 200

        event_id = str(payload.get("id") or "").strip()
        if event_id and _idempotency_seen(order, "paypal_events", event_id):
            _commit_safe()
            return jsonify(ok=True, status="ignored"), 200

        _meta_save(
            order,
            {
                "paypal_webhook_at": int(time.time()),
                "paypal_event_id": event_id or None,
            },
        )
        _commit_safe()

        return jsonify(ok=True, status="processed"), 200

    except Exception:
        db.session.rollback()
        current_app.logger.exception("paypal_webhook_error")
        return jsonify(ok=True, status="error"), 200


@webhook_bp.post("/manual/confirm")
def manual_confirm():
    if ADMIN_TOKEN:
        provided = (request.headers.get("X-Admin-Token") or "").strip()
        if provided != ADMIN_TOKEN:
            return jsonify(ok=False, status="unauthorized"), 401

    body = _json()
    try:
        order_id = int(body.get("order_id"))
    except Exception:
        return jsonify(ok=False, status="order_id_required"), 400

    provider = str(body.get("provider") or "manual").strip().lower()
    reference = str(body.get("reference") or "").strip()[:120]
    paid_amount = body.get("paid_amount")
    paid_currency = body.get("paid_currency")

    try:
        order = OrderService.apply_payment_confirmation(
            order_id,
            provider=provider,
            provider_payment_id=reference or None,
            paid_amount=paid_amount,
            paid_currency=paid_currency,
            raw={"manual": True},
        )
        return (
            jsonify(
                ok=True,
                status="processed",
                order_id=order.id,
                order_number=order.number,
            ),
            200,
        )
    except PaymentMismatchError as e:
        return jsonify(ok=False, status=str(e)[:160]), 400
    except OrderServiceError as e:
        return jsonify(ok=False, status=str(e)[:160]), 400
    except Exception:
        current_app.logger.exception("manual_confirm_error")
        return jsonify(ok=False, status="error"), 500


__all__ = ["webhook_bp"]
