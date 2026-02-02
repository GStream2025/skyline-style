from __future__ import annotations

import os
import time
import logging
import secrets
from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, jsonify, request, current_app

from app.models import db
from app.models.order import Order
from app.services.order_service import OrderService, OrderServiceError, PaymentMismatchError
from app.integrations.mercadopago_webhook import handle_webhook as mp_handle_webhook

log = logging.getLogger("webhook_routes")

webhook_bp = Blueprint("webhooks", __name__, url_prefix="/webhooks")
webhook_bp.strict_slashes = False

_TRUE = {"1", "true", "yes", "y", "on", "checked"}


def _env(k: str, d: str = "") -> str:
    return (os.getenv(k) or d).strip()


def _bool_env(k: str, d: bool = False) -> bool:
    v = _env(k)
    return v.lower() in _TRUE if v else d


WEBHOOKS_ENABLED = _bool_env("WEBHOOKS_ENABLED", True)
DEBUG_WEBHOOKS = _bool_env("DEBUG_WEBHOOKS", False)
ADMIN_TOKEN = _env("ADMIN_WEBHOOK_TOKEN", "")

# Si lo activás, devuelve 4xx en errores (útil para forzar reintentos del proveedor).
WEBHOOK_STRICT_HTTP = _bool_env("WEBHOOK_STRICT_HTTP", False)

# Hardening / límites
_MAX_RAW_BYTES = int(_env("WEBHOOK_MAX_RAW_BYTES", "2000000") or "2000000")
_META_EVENT_LIMIT = int(_env("WEBHOOK_META_EVENT_LIMIT", "80") or "80")


def _now() -> int:
    return int(time.time())


def _safe_headers() -> Dict[str, str]:
    try:
        return {str(k): str(v) for k, v in dict(request.headers).items()}
    except Exception:
        return {}


def _raw_text(max_bytes: int = _MAX_RAW_BYTES) -> str:
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


def _commit_safe() -> None:
    try:
        db.session.commit()
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass


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


def _idempotency_seen(order: Order, key: str, event_id: str, limit: int = _META_EVENT_LIMIT) -> bool:
    if not event_id:
        return False
    m = _meta(order)
    events = m.get(key)
    if not isinstance(events, list):
        events = []
    if event_id in events:
        return True
    events.append(event_id)
    m[key] = events[-max(10, int(limit or 60)) :]
    try:
        order.meta = m  # type: ignore[attr-defined]
    except Exception:
        pass
    return False


def _rid() -> str:
    # Render / proxies a veces mandan X-Request-Id
    try:
        v = (request.headers.get("X-Request-Id") or request.headers.get("X-Amzn-Trace-Id") or "").strip()
        return v[:80]
    except Exception:
        return ""


def _admin_token_ok() -> bool:
    if not ADMIN_TOKEN:
        return True
    provided = (request.headers.get("X-Admin-Token") or "").strip()
    try:
        return secrets.compare_digest(provided, ADMIN_TOKEN)
    except Exception:
        return False


def _http_result(ok: bool, status: str, payload: Dict[str, Any], *, strict_code: int = 400):
    """
    Default: 200 siempre (evita storms de reintentos).
    Si WEBHOOK_STRICT_HTTP=1, devuelve 4xx cuando ok=False.
    """
    code = 200
    if (not ok) and WEBHOOK_STRICT_HTTP:
        code = int(strict_code)
    return jsonify(ok=ok, status=status, **payload), code


@webhook_bp.before_request
def _gate():
    if not WEBHOOKS_ENABLED:
        return jsonify(ok=False, error="disabled"), 404
    return None


@webhook_bp.get("/health")
def health():
    return jsonify(ok=True), 200


@webhook_bp.get("/ready")
def ready():
    """
    Estado mínimo de configuración (sin exponer secretos).
    """
    checks = {
        "webhooks_enabled": bool(WEBHOOKS_ENABLED),
        "strict_http": bool(WEBHOOK_STRICT_HTTP),
        "debug_webhooks": bool(DEBUG_WEBHOOKS),
        "admin_token_set": bool(ADMIN_TOKEN),
        # Si tu integración de MP depende de env var (MP_ACCESS_TOKEN), esto te ayuda a detectar misconfig.
        "mp_access_token_set": bool(_env("MP_ACCESS_TOKEN", "")),
    }
    ok = all([checks["webhooks_enabled"]])
    # mp_access_token_set puede ser false si no usás MP, por eso no lo meto como fatal.
    return jsonify(ok=ok, checks=checks), (200 if ok else 503)


@webhook_bp.post("/mercadopago")
def mercadopago_webhook():
    t0 = time.time()
    raw = _raw_text()
    headers = _safe_headers()

    try:
        res = mp_handle_webhook(raw_body=raw, headers=headers)

        # Nota: res.status esperado: processed / ignored / error
        ok = bool(getattr(res, "ok", False))
        status = str(getattr(res, "status", "") or "unknown")
        msg = str(getattr(res, "message", "") or "")

        order_id = getattr(res, "order_id", None)
        order_number = getattr(res, "order_number", None)
        payment_id = getattr(res, "payment_id", None)

        if DEBUG_WEBHOOKS:
            current_app.logger.info(
                "mp_webhook rid=%s ok=%s status=%s order_id=%s payment_id=%s ms=%s",
                _rid() or "-",
                ok,
                status,
                order_id,
                payment_id,
                int((time.time() - t0) * 1000),
            )

        # Si tu handler marcó error, no lo ocultamos: lo devolvemos, pero por defecto igual 200 (configurable).
        strict_code = 400
        if status in {"processed", "ignored"}:
            return _http_result(True, status, {
                "message": msg,
                "order_id": order_id,
                "order_number": order_number,
                "payment_id": payment_id,
            }, strict_code=strict_code)

        return _http_result(False, status or "error", {
            "message": msg or "mp handler error",
            "order_id": order_id,
            "order_number": order_number,
            "payment_id": payment_id,
        }, strict_code=strict_code)

    except Exception:
        current_app.logger.exception("mp_webhook_error rid=%s", _rid() or "-")
        # No silencioso: status=error + log. HTTP 200 por defecto para evitar retry loop (configurable).
        return _http_result(False, "error", {"message": "exception"}, strict_code=500)


@webhook_bp.post("/paypal")
def paypal_webhook():
    t0 = time.time()
    payload = _json()

    # Intentamos extraer ids standard PayPal
    event_id = _safe_headers().get("PayPal-Transmission-Id") or str(payload.get("id") or "").strip()
    paypal_order_id: Optional[str] = None
    try:
        res = payload.get("resource")
        if isinstance(res, dict) and res.get("id"):
            paypal_order_id = str(res["id"]).strip()
        if payload.get("paypal_order_id"):
            paypal_order_id = str(payload["paypal_order_id"]).strip()
    except Exception:
        paypal_order_id = None

    if not paypal_order_id:
        return _http_result(True, "ignored", {"message": "no paypal_order_id"}, strict_code=400)

    try:
        order = db.session.query(Order).filter(Order.paypal_order_id == paypal_order_id).first()
        if not order:
            return _http_result(True, "ignored", {"message": "order not found"}, strict_code=404)

        if event_id and _idempotency_seen(order, "paypal_events", event_id):
            _commit_safe()
            return _http_result(True, "ignored", {"message": "duplicate"}, strict_code=200)

        _meta_save(order, {
            "paypal_webhook_at": _now(),
            "paypal_event_id": event_id or None,
            "paypal_order_id": paypal_order_id,
            "paypal_debug_type": _safe_str(payload.get("event_type") or payload.get("summary") or "", max_len=120),
        })
        _commit_safe()

        if DEBUG_WEBHOOKS:
            current_app.logger.info(
                "paypal_webhook rid=%s order=%s event=%s ms=%s",
                _rid() or "-",
                getattr(order, "id", None),
                event_id or "-",
                int((time.time() - t0) * 1000),
            )

        # Acá NO confirmo pago porque tu flujo actual no lo hace.
        # Si querés que confirme, lo agregamos en el próximo paso cuando veamos tu OrderService/estado de order.
        return _http_result(True, "processed", {"order_id": getattr(order, "id", None)}, strict_code=200)

    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        current_app.logger.exception("paypal_webhook_error rid=%s", _rid() or "-")
        return _http_result(False, "error", {"message": "exception"}, strict_code=500)


def _safe_str(v: Any, *, max_len: int = 600) -> str:
    if v is None:
        return ""
    s = v if isinstance(v, str) else str(v)
    s = s.replace("\x00", "").replace("\u200b", "").strip().replace("\r", "").replace("\n", "")
    return s[:max_len]


def _norm_currency(v: Any) -> str:
    s = _safe_str(v, max_len=10).upper()
    return s[:3] if s else ""


def _to_amount(v: Any):
    # No forzamos float (por errores binarios); OrderService debería parsear mejor.
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)):
        return v
    s = _safe_str(v, max_len=40).replace(",", ".")
    try:
        return float(s)
    except Exception:
        return v


@webhook_bp.post("/manual/confirm")
def manual_confirm():
    # Seguridad: token opcional (si está configurado, lo exige)
    if not _admin_token_ok():
        return jsonify(ok=False, status="unauthorized"), 401

    body = _json()
    try:
        order_id = int(body.get("order_id"))
    except Exception:
        return jsonify(ok=False, status="order_id_required"), 400

    provider = _safe_str(body.get("provider") or "manual", max_len=40).lower()
    reference = _safe_str(body.get("reference") or "", max_len=120)
    paid_amount = _to_amount(body.get("paid_amount"))
    paid_currency = _norm_currency(body.get("paid_currency"))

    # Idempotencia opcional (cliente puede mandar header o body)
    idem_key = _safe_str(request.headers.get("Idempotency-Key") or body.get("idempotency_key") or "", max_len=80)
    if idem_key:
        # Guardamos un historial por orden para no duplicar confirmaciones manuales.
        try:
            order = db.session.get(Order, order_id)
            if order:
                if _idempotency_seen(order, "manual_confirm_events", idem_key):
                    _commit_safe()
                    return jsonify(ok=True, status="ignored", order_id=order_id), 200
                _commit_safe()
        except Exception:
            try:
                db.session.rollback()
            except Exception:
                pass

    try:
        order = OrderService.apply_payment_confirmation(
            order_id,
            provider=provider,
            provider_payment_id=(reference or None),
            paid_amount=paid_amount,
            paid_currency=(paid_currency or None),
            raw={"manual": True, "rid": _rid() or None, "idempotency_key": idem_key or None},
        )
        return jsonify(ok=True, status="processed", order_id=order.id, order_number=order.number), 200

    except PaymentMismatchError as e:
        return jsonify(ok=False, status=str(e)[:160]), 400
    except OrderServiceError as e:
        return jsonify(ok=False, status=str(e)[:160]), 400
    except Exception:
        current_app.logger.exception("manual_confirm_error rid=%s", _rid() or "-")
        return jsonify(ok=False, status="error"), 500


__all__ = ["webhook_bp"]
