from __future__ import annotations

import os
import time
from typing import Any, Dict, Optional
from urllib.parse import urlencode, urlparse

from flask import (
    Blueprint,
    current_app,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from app.models import db, User, UserAddress
from app.routes.cart_routes import cart_snapshot
from app.services.checkout_flow import CheckoutFlow, CheckoutError
from app.services.paypal_capture import capture_paypal_order

checkout_bp = Blueprint("checkout", __name__, url_prefix="/checkout")
checkout_bp.strict_slashes = False

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off"}

DEFAULT_CURRENCY = (os.getenv("DEFAULT_CURRENCY") or "USD").strip().upper()[:3] or "USD"
CHECKOUT_RL_SECONDS = max(1, int((os.getenv("CHECKOUT_RATELIMIT_SECONDS") or "2").strip() or "2"))

ENABLE_PAYMENTS = (os.getenv("ENABLE_PAYMENTS") or "0").strip().lower() in _TRUE
ENABLE_MP = bool((os.getenv("MP_ACCESS_TOKEN") or "").strip())
ENABLE_PAYPAL = bool((os.getenv("PAYPAL_CLIENT_ID") or "").strip() and (os.getenv("PAYPAL_SECRET") or "").strip())

SESSION_CHECKOUT_KEY = "checkout_key_v2"
SESSION_RL_KEY = "checkout_rl_ts_v2"

_ALLOWED_PROVIDERS = {"mercadopago", "paypal", "bank", "wise"}


def _safe_str(v: Any, *, max_len: int = 500) -> str:
    if v is None:
        return ""
    s = v.strip() if isinstance(v, str) else str(v).strip()
    s = s.replace("\x00", "").replace("\r", "").replace("\n", "")
    return s[:max_len]


def _is_safe_next(nxt: str) -> bool:
    if not nxt:
        return False
    u = _safe_str(nxt, max_len=600)
    if not u or " " in u:
        return False
    if any(ch in u for ch in ("\x00", "\r", "\n", "\t", "\\")):
        return False
    if u.startswith("//") or "://" in u:
        return False
    if ".." in u:
        return False
    p = urlparse(u)
    if p.scheme or p.netloc:
        return False
    if not (p.path or "").startswith("/"):
        return False
    # evita loops directos
    if (p.path or "").startswith(("/auth/login", "/auth/register")):
        return False
    return True


def _safe_next_from_request(default: str = "/checkout/") -> str:
    raw = ""
    try:
        raw = request.full_path if request.query_string else request.path
    except Exception:
        raw = ""
    raw = _safe_str(raw, max_len=600)
    return raw if _is_safe_next(raw) else default


def _redirect_login(next_url: str):
    nxt = next_url if _is_safe_next(next_url) else "/"
    try:
        return redirect(url_for("auth.login_get", next=nxt), code=302)
    except Exception:
        return redirect(f"/auth/login?{urlencode({'next': nxt})}", code=302)


def _require_login():
    uid = session.get("user_id")
    if not uid:
        return _redirect_login(_safe_next_from_request("/"))
    return None


def _current_user() -> Optional[User]:
    try:
        uid = int(session.get("user_id") or 0)
    except Exception:
        uid = 0
    if uid <= 0:
        return None
    try:
        return db.session.get(User, uid)
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        return None


def _rate_limit_ok(bucket: str = "default") -> bool:
    now = time.time()
    st = session.get(SESSION_RL_KEY)
    if not isinstance(st, dict):
        st = {}

    # limpieza rápida para evitar crecimiento
    if len(st) > 60:
        for k in list(st.keys()):
            try:
                if now - float(st.get(k) or 0.0) > 3600:
                    st.pop(k, None)
            except Exception:
                st.pop(k, None)

    last = 0.0
    try:
        last = float(st.get(bucket, 0.0) or 0.0)
    except Exception:
        last = 0.0

    if now - last < float(CHECKOUT_RL_SECONDS):
        return False

    st[bucket] = now
    session[SESSION_RL_KEY] = st
    session.modified = True
    return True


def _read_payload() -> Dict[str, Any]:
    try:
        if request.is_json:
            j = request.get_json(silent=True) or {}
            return j if isinstance(j, dict) else {}
    except Exception:
        pass
    try:
        return {k: v for k, v in (request.form or {}).items()}
    except Exception:
        return {}


def _get_address_for_user(user_id: int, address_id: Any) -> Optional[UserAddress]:
    if not address_id:
        return None
    try:
        aid = int(_safe_str(address_id, max_len=40))
    except Exception:
        return None
    if aid <= 0:
        return None
    try:
        addr = db.session.get(UserAddress, aid)
    except Exception:
        return None
    if not addr:
        return None
    if int(getattr(addr, "user_id", 0) or 0) != int(user_id):
        return None
    return addr


def _cart_is_empty(snap: Any) -> bool:
    try:
        lines = snap.get("lines") if isinstance(snap, dict) else None
        return not lines
    except Exception:
        return True


def _checkout_key() -> Optional[str]:
    v = session.get(SESSION_CHECKOUT_KEY)
    if not v:
        return None
    s = _safe_str(v, max_len=220)
    return s or None


def _no_store(resp):
    try:
        resp.headers.setdefault("Cache-Control", "no-store, max-age=0, must-revalidate")
        resp.headers.setdefault("Pragma", "no-cache")
        resp.headers.setdefault("Expires", "0")
        resp.headers.setdefault("Vary", "Cookie")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    except Exception:
        pass
    return resp


@checkout_bp.after_request
def _after(resp):
    # checkout nunca se cachea
    return _no_store(resp)


@checkout_bp.get("/")
def checkout_page():
    gate = _require_login()
    if gate:
        return gate

    snap = cart_snapshot()
    if _cart_is_empty(snap):
        try:
            return redirect(url_for("cart.cart_view"), code=302)
        except Exception:
            return redirect("/cart/", code=302)

    user = _current_user()
    if not user:
        session.pop("user_id", None)
        session.modified = True
        return _require_login()

    try:
        addresses = (
            UserAddress.query.filter_by(user_id=user.id)
            .order_by(UserAddress.is_default.desc())
            .limit(50)
            .all()
        )
    except Exception:
        addresses = []

    return render_template(
        "checkout/checkout.html",
        cart=snap,
        user=user,
        addresses=addresses,
        mp_enabled=ENABLE_MP,
        paypal_enabled=ENABLE_PAYPAL,
        payments_enabled=ENABLE_PAYMENTS,
    )


@checkout_bp.post("/start")
def checkout_start():
    gate = _require_login()
    if gate:
        return gate

    if not ENABLE_PAYMENTS:
        return jsonify(ok=False, error="payments_disabled"), 400

    if not _rate_limit_ok("start"):
        return jsonify(ok=False, error="rate_limited"), 429

    user = _current_user()
    if not user:
        return jsonify(ok=False, error="not_authenticated"), 401

    data = _read_payload()
    payment_method = _safe_str(data.get("payment_method") or "mercadopago", max_len=32).lower()
    if payment_method not in _ALLOWED_PROVIDERS:
        payment_method = "mercadopago"

    if payment_method == "mercadopago" and not ENABLE_MP:
        return jsonify(ok=False, error="mercadopago_unavailable"), 400
    if payment_method == "paypal" and not ENABLE_PAYPAL:
        return jsonify(ok=False, error="paypal_unavailable"), 400

    snap = cart_snapshot()
    if _cart_is_empty(snap):
        return jsonify(ok=False, error="cart_empty"), 400

    address = _get_address_for_user(int(user.id), data.get("address_id"))
    ck = _checkout_key()

    try:
        state = CheckoutFlow.create_checkout(
            lines=snap.get("lines") or [],
            customer_email=_safe_str(getattr(user, "email", "") or "", max_len=254).lower(),
            currency=_safe_str(snap.get("currency") or DEFAULT_CURRENCY, max_len=3).upper() or DEFAULT_CURRENCY,
            payment_method=payment_method,
            user_id=int(user.id),
            customer_name=_safe_str(getattr(user, "name", "") or "", max_len=140) or None,
            customer_phone=_safe_str(getattr(user, "phone", "") or "", max_len=40) or None,
            ship_address1=(_safe_str(getattr(address, "address1", "") or "", max_len=180) if address else None) or None,
            ship_city=(_safe_str(getattr(address, "city", "") or "", max_len=120) if address else None) or None,
            ship_country=(_safe_str(getattr(address, "country", "") or "", max_len=2) if address else None) or None,
            checkout_key=ck,
        )
    except CheckoutError as e:
        return jsonify(ok=False, error=_safe_str(e, max_len=180)), 400
    except Exception:
        current_app.logger.exception("checkout_create_failed")
        return jsonify(ok=False, error="checkout_create_failed"), 500

    session[SESSION_CHECKOUT_KEY] = _safe_str(state.checkout_key, max_len=200)
    session.modified = True

    return jsonify(
        ok=True,
        checkout_key=state.checkout_key,
        order_id=state.order_id,
        total=state.total,
        currency=state.currency,
    )


@checkout_bp.post("/pay/<provider>")
def checkout_pay(provider: str):
    gate = _require_login()
    if gate:
        return gate

    if not ENABLE_PAYMENTS:
        return jsonify(ok=False, error="payments_disabled"), 400

    if not _rate_limit_ok("pay"):
        return jsonify(ok=False, error="rate_limited"), 429

    ck = _checkout_key()
    if not ck:
        return jsonify(ok=False, error="checkout_not_started"), 400

    provider = _safe_str(provider or "", max_len=24).lower()
    if provider not in _ALLOWED_PROVIDERS:
        return jsonify(ok=False, error="invalid_provider"), 400

    if provider == "mercadopago" and not ENABLE_MP:
        return jsonify(ok=False, error="mercadopago_unavailable"), 400
    if provider == "paypal" and not ENABLE_PAYPAL:
        return jsonify(ok=False, error="paypal_unavailable"), 400

    success = url_for("checkout.payment_success", provider=provider, _external=True)
    cancel = url_for("checkout.payment_failure", provider=provider, _external=True)

    try:
        res = CheckoutFlow.start_payment(
            checkout_key=ck,
            provider=provider,
            success_url=success,
            cancel_url=cancel,
        )
    except CheckoutError as e:
        return jsonify(ok=False, error=_safe_str(e, max_len=180)), 400
    except Exception:
        current_app.logger.exception("payment_start_failed")
        return jsonify(ok=False, error="payment_start_failed"), 500

    return jsonify(ok=True, redirect_url=res.redirect_url, provider=res.provider)


@checkout_bp.get("/paypal/capture")
def paypal_capture():
    gate = _require_login()
    if gate:
        return gate

    if not ENABLE_PAYPAL:
        return redirect(url_for("checkout.payment_failure", provider="paypal"), code=302)

    if not _rate_limit_ok("paypal_capture"):
        return redirect(url_for("checkout.payment_failure", provider="paypal"), code=302)

    ck = _checkout_key()
    token = _safe_str(request.args.get("token") or "", max_len=220)
    if not ck or not token:
        return redirect(url_for("checkout.payment_failure", provider="paypal"), code=302)

    try:
        state = CheckoutFlow.get_state(ck)
        capture_paypal_order(order_id=state.order_id, paypal_order_id=token)
    except Exception:
        current_app.logger.exception("paypal_capture_failed")
        return redirect(url_for("checkout.payment_failure", provider="paypal"), code=302)

    return redirect(url_for("checkout.payment_success", provider="paypal"), code=302)


@checkout_bp.get("/payment/<provider>/success")
def payment_success(provider: str):
    provider = _safe_str(provider or "", max_len=24).lower()
    if provider not in _ALLOWED_PROVIDERS:
        provider = "unknown"
    return render_template("checkout/success.html", provider=provider)


@checkout_bp.get("/payment/<provider>/failure")
def payment_failure(provider: str):
    provider = _safe_str(provider or "", max_len=24).lower()
    if provider not in _ALLOWED_PROVIDERS:
        provider = "unknown"
    return render_template("checkout/failure.html", provider=provider)


@checkout_bp.get("/payment/<provider>/pending")
def payment_pending(provider: str):
    provider = _safe_str(provider or "", max_len=24).lower()
    if provider not in _ALLOWED_PROVIDERS:
        provider = "unknown"
    return render_template("checkout/pending.html", provider=provider)


__all__ = ["checkout_bp"]
