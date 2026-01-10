from __future__ import annotations

"""
PayPal Client (INTEGRATIONS)
============================
Capa de integración pura (HTTP) con PayPal:
- OAuth token (cacheado)
- Create order
- Capture order
- Retries/timeouts seguros
- Idempotencia PayPal-Request-Id
- NO toca DB
"""

import base64
import json
import time
import logging
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Optional, Tuple

import requests

log = logging.getLogger("paypal_client")
_SESSION = requests.Session()

_TRUE = {"1", "true", "yes", "y", "on"}


# -----------------------------------------------------------------------------
# ENV / helpers
# -----------------------------------------------------------------------------


def _env(k: str, d: str = "") -> str:
    import os

    return (os.getenv(k) or d).strip()


def _bool_env(k: str, d: bool = False) -> bool:
    v = _env(k, "")
    return v.lower() in _TRUE if v else d


def _timeout() -> int:
    try:
        return int(_env("PAYPAL_TIMEOUT_SEC", "12"))
    except Exception:
        return 12


def _paypal_mode() -> str:
    m = _env("PAYPAL_MODE", "").lower()
    if m in {"sandbox", "live"}:
        return m
    if _bool_env("PAYPAL_SANDBOX", False):
        return "sandbox"
    return "live"


def paypal_base_url() -> str:
    return (
        "https://api-m.sandbox.paypal.com"
        if _paypal_mode() == "sandbox"
        else "https://api-m.paypal.com"
    )


def _d(v: Any, default="0.00") -> Decimal:
    try:
        if v is None or v == "":
            return Decimal(default)
        return Decimal(str(v))
    except (InvalidOperation, ValueError, TypeError):
        return Decimal(default)


def money_str(v: Any) -> str:
    return f"{_d(v):.2f}"


def cur3(v: Any, default="USD") -> str:
    s = (str(v) if v else default).strip().upper()
    return s[:3] if len(s) >= 3 else default


def _trunc(v: Any, n: int = 300) -> str:
    return (str(v) if v is not None else "")[:n]


def _basic_auth(client_id: str, secret: str) -> str:
    raw = f"{client_id}:{secret}".encode("utf-8")
    return base64.b64encode(raw).decode("utf-8")


# -----------------------------------------------------------------------------
# Errors
# -----------------------------------------------------------------------------


class PayPalClientError(RuntimeError):
    pass


class PayPalAuthError(PayPalClientError):
    pass


class PayPalHTTPError(PayPalClientError):
    pass


# -----------------------------------------------------------------------------
# Token cache
# -----------------------------------------------------------------------------

_TOKEN_CACHE: Dict[str, Any] = {"access_token": None, "expires_at": 0}


def _get_oauth_token(force_refresh: bool = False) -> str:
    now = int(time.time())
    if not force_refresh:
        tok = _TOKEN_CACHE.get("access_token")
        exp = int(_TOKEN_CACHE.get("expires_at") or 0)
        if tok and now < exp - 30:
            return str(tok)

    cid = _env("PAYPAL_CLIENT_ID")
    sec = _env("PAYPAL_SECRET")
    if not cid or not sec:
        raise PayPalAuthError("PayPal no configurado: PAYPAL_CLIENT_ID / PAYPAL_SECRET")

    url = f"{paypal_base_url()}/v1/oauth2/token"
    headers = {
        "Authorization": f"Basic {_basic_auth(cid, sec)}",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = "grant_type=client_credentials"

    for i in range(3):
        try:
            r = _SESSION.post(url, headers=headers, data=data, timeout=_timeout())
        except requests.RequestException as e:
            if i == 2:
                raise PayPalAuthError(f"PayPal OAuth error: {_trunc(e)}")
            time.sleep(0.5 * (i + 1))
            continue

        if r.status_code == 200:
            j = r.json()
            token = j.get("access_token")
            ttl = int(j.get("expires_in") or 0)
            if not token:
                raise PayPalAuthError("PayPal OAuth: falta access_token")
            _TOKEN_CACHE["access_token"] = token
            _TOKEN_CACHE["expires_at"] = now + max(60, ttl)
            return str(token)

        if r.status_code in {401, 403}:
            raise PayPalAuthError("PayPal OAuth: credenciales inválidas")

        if 500 <= r.status_code < 600:
            if i == 2:
                raise PayPalAuthError(f"PayPal OAuth 5xx: {r.status_code}")
            time.sleep(0.5 * (i + 1))
            continue

        raise PayPalAuthError(f"PayPal OAuth {r.status_code}: {r.text[:250]}")

    raise PayPalAuthError("PayPal OAuth: failed")


def _headers(
    idempotency_key: Optional[str] = None, *, refresh_token: bool = False
) -> Dict[str, str]:
    tok = _get_oauth_token(force_refresh=refresh_token)
    h = {
        "Authorization": f"Bearer {tok}",
        "Content-Type": "application/json",
    }
    if idempotency_key:
        h["PayPal-Request-Id"] = idempotency_key[:64]
    return h


# -----------------------------------------------------------------------------
# DTOs
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class PayPalCreateResp:
    paypal_order_id: str
    approve_url: Optional[str]
    raw: Dict[str, Any]


@dataclass(frozen=True)
class PayPalCaptureResp:
    paypal_order_id: str
    status: str
    capture_id: Optional[str]
    paid_amount: Optional[Decimal]
    paid_currency: Optional[str]
    raw: Dict[str, Any]


# -----------------------------------------------------------------------------
# API calls
# -----------------------------------------------------------------------------


def create_order(
    *,
    amount: str,
    currency: str,
    reference_id: str,
    custom_id: str,
    success_url: str,
    cancel_url: str,
    brand_name: str = "Skyline Store",
    locale: str = "es-UY",
    idempotency_key: Optional[str] = None,
) -> PayPalCreateResp:
    """
    Crea una PayPal order y devuelve approve link.
    amount: string "12.34"
    currency: "USD"
    """
    body = {
        "intent": "CAPTURE",
        "purchase_units": [
            {
                "reference_id": reference_id[:256],
                "description": f"Order {reference_id}"[:127],
                "custom_id": custom_id[:127],
                "amount": {"currency_code": cur3(currency, "USD"), "value": amount},
            }
        ],
        "application_context": {
            "brand_name": brand_name[:127],
            "locale": locale,
            "landing_page": "LOGIN",
            "shipping_preference": "NO_SHIPPING",
            "user_action": "PAY_NOW",
            "return_url": success_url,
            "cancel_url": cancel_url,
        },
    }

    url = f"{paypal_base_url()}/v2/checkout/orders"

    for i in range(3):
        try:
            r = _SESSION.post(
                url,
                headers=_headers(idempotency_key),
                data=json.dumps(body),
                timeout=_timeout(),
            )
        except requests.RequestException as e:
            if i == 2:
                raise PayPalHTTPError(f"PayPal create error: {_trunc(e)}")
            time.sleep(0.5 * (i + 1))
            continue

        if r.status_code in {200, 201}:
            j = r.json() if r.content else {}
            pid = str(j.get("id") or "").strip()
            approve = None
            links = j.get("links") or []
            if isinstance(links, list):
                for l in links:
                    if isinstance(l, dict) and l.get("rel") == "approve":
                        approve = l.get("href")
                        break
            if not pid:
                raise PayPalHTTPError("PayPal create: missing id")
            return PayPalCreateResp(
                paypal_order_id=pid,
                approve_url=approve,
                raw=j if isinstance(j, dict) else {"_raw": j},
            )

        if r.status_code in {401, 403}:
            # token vencido -> refresh 1 vez
            if i < 2:
                _TOKEN_CACHE["access_token"] = None
                _TOKEN_CACHE["expires_at"] = 0
                # reintentar con refresh real
                try:
                    _get_oauth_token(force_refresh=True)
                except Exception:
                    pass
                time.sleep(0.25)
                continue
            raise PayPalAuthError("PayPal create: unauthorized")

        if 500 <= r.status_code < 600:
            if i == 2:
                raise PayPalHTTPError(f"PayPal create 5xx: {r.status_code}")
            time.sleep(0.5 * (i + 1))
            continue

        raise PayPalHTTPError(f"PayPal create {r.status_code}: {r.text[:350]}")

    raise PayPalHTTPError("PayPal create failed")


def capture_order(
    *, paypal_order_id: str, idempotency_key: Optional[str] = None
) -> PayPalCaptureResp:
    paypal_order_id = (paypal_order_id or "").strip()
    if not paypal_order_id:
        raise PayPalClientError("paypal_order_id requerido")

    url = f"{paypal_base_url()}/v2/checkout/orders/{paypal_order_id}/capture"

    for i in range(3):
        try:
            r = _SESSION.post(
                url, headers=_headers(idempotency_key), timeout=_timeout()
            )
        except requests.RequestException as e:
            if i == 2:
                raise PayPalHTTPError(f"PayPal capture error: {_trunc(e)}")
            time.sleep(0.5 * (i + 1))
            continue

        if r.status_code in {200, 201}:
            j = r.json() if r.content else {}
            status = str(j.get("status") or "").upper()

            capture_id, paid_amount, paid_currency = _extract_capture_details(
                j if isinstance(j, dict) else {}
            )
            return PayPalCaptureResp(
                paypal_order_id=paypal_order_id,
                status=status or "OK",
                capture_id=capture_id,
                paid_amount=paid_amount,
                paid_currency=paid_currency,
                raw=j if isinstance(j, dict) else {"_raw": j},
            )

        if r.status_code in {401, 403}:
            if i < 2:
                _TOKEN_CACHE["access_token"] = None
                _TOKEN_CACHE["expires_at"] = 0
                try:
                    _get_oauth_token(force_refresh=True)
                except Exception:
                    pass
                time.sleep(0.25)
                continue
            raise PayPalAuthError("PayPal capture: unauthorized")

        if 500 <= r.status_code < 600:
            if i == 2:
                raise PayPalHTTPError(f"PayPal capture 5xx: {r.status_code}")
            time.sleep(0.5 * (i + 1))
            continue

        raise PayPalHTTPError(f"PayPal capture {r.status_code}: {r.text[:350]}")

    raise PayPalHTTPError("PayPal capture failed")


def _extract_capture_details(
    payload: Dict[str, Any]
) -> Tuple[Optional[str], Optional[Decimal], Optional[str]]:
    """
    Extrae capture_id + amount/currency desde capture response.
    """
    try:
        pus = payload.get("purchase_units") or []
        if not isinstance(pus, list) or not pus:
            return None, None, None

        pu0 = pus[0] if isinstance(pus[0], dict) else {}
        payments = pu0.get("payments") or {}
        captures = payments.get("captures") or []

        if isinstance(captures, list) and captures:
            c0 = captures[0] if isinstance(captures[0], dict) else {}
            cap_id = c0.get("id")
            amt = c0.get("amount") or {}
            if isinstance(amt, dict):
                val = amt.get("value")
                cur = amt.get("currency_code")
                return (
                    str(cap_id) if cap_id else None,
                    _d(val) if val is not None else None,
                    str(cur) if cur else None,
                )
    except Exception:
        pass
    return None, None, None


__all__ = [
    "PayPalClientError",
    "PayPalAuthError",
    "PayPalHTTPError",
    "PayPalCreateResp",
    "PayPalCaptureResp",
    "create_order",
    "capture_order",
    "money_str",
    "cur3",
]
