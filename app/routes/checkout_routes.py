from __future__ import annotations

import os
import time
from typing import Any, Optional

from flask import (
    Blueprint,
    current_app,
    jsonify,
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

_TRUE = {"1", "true", "yes", "y", "on"}

DEFAULT_CURRENCY = (os.getenv("DEFAULT_CURRENCY") or "USD").strip().upper()[:3] or "USD"
CHECKOUT_RL_SECONDS = max(1, int((os.getenv("CHECKOUT_RATELIMIT_SECONDS") or "2").strip() or "2"))

ENABLE_PAYMENTS = (os.getenv("ENABLE_PAYMENTS") or "0").strip().lower() in _TRUE
ENABLE_MP = bool((os.getenv("MP_ACCESS_TOKEN") or "").strip())
ENABLE_PAYPAL = bool((os.getenv("PAYPAL_CLIENT_ID") or "").strip() and (os.getenv("PAYPAL_SECRET") or "").strip())

SESSION_CHECKOUT_KEY = "checkout_key_v2"
SESSION_RL_KEY = "checkout_rl_ts_v2"


def _safe_next(p: str) -> bool:
    if not p:
        return False
    p = p.strip()
    return p.startswith("/") and not p.startswith("//")


def _require_login():
    uid = session.get("user_id")
    if not uid:
        nxt = request.full_path if request.query_string else request.path
        nxt = nxt if _safe_next(nxt) else "/"
        try:
            return redirect(url_for("auth.login", next=nxt))
        except Exception:
            return redirect(f"/auth/login?next={nxt}")
    return None


def _current_user() -> Optional[User]:
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        return db.session.get(User, int(uid))
    except Exception:
        return None


def _rate_limit_ok(bucket: str = "default") -> bool:
    now = time.time()
    st = session.get(SESSION_RL_KEY)
    if not isinstance(st, dict):
        st = {}
    last = float(st.get(bucket, 0.0) or 0.0)
    if now - last < float(CHECKOUT_RL_SECONDS):
        return False
    st[bucket] = now
    session[SESSION_RL_KEY] = st
    session.modified = True
    return True


def _get_address_for_user(user_id: int, address_id: Any) -> Optional[UserAddress]:
    if not address_id:
        return None
    try:
        aid = int(str(address_id).strip())
    except Exception:
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
    s = str(v).strip()
    return s[:200] if s else None


@checkout_bp.get("/")
def checkout_page():
    gate = _require_login()
    if gate:
        return gate

    snap = cart_snapshot()
    if _cart_is_empty(snap):
        try:
            return redirect(url_for("cart.cart_view"))
        except Exception:
            return redirect("/cart/")

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

    data = request.get_json(silent=True) or request.form
    payment_method = str(data.get("payment_method") or "mercadopago").strip().lower()[:32]
    if payment_method not in {"mercadopago", "paypal", "bank", "wise"}:
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
            customer_email=str(getattr(user, "email", "") or "").strip()[:254],
            currency=str(snap.get("currency") or DEFAULT_CURRENCY).strip().upper()[:3] or DEFAULT_CURRENCY,
            payment_method=payment_method,
            user_id=int(user.id),
            customer_name=str(getattr(user, "name", "") or "").strip()[:140] or None,
            customer_phone=str(getattr(user, "phone", "") or "").strip()[:40] or None,
            ship_address1=(str(getattr(address, "address1", "") or "").strip()[:180] if address else None),
            ship_city=(str(getattr(address, "city", "") or "").strip()[:120] if address else None),
            ship_country=(str(getattr(address, "country", "") or "").strip()[:2] if address else None),
            checkout_key=ck,
        )
    except CheckoutError as e:
        return jsonify(ok=False, error=str(e)), 400
    except Exception:
        current_app.logger.exception("Checkout create failed")
        return jsonify(ok=False, error="checkout_create_failed"), 500

    session[SESSION_CHECKOUT_KEY] = str(state.checkout_key)[:200]
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

    provider = str(provider or "").strip().lower()[:24]
    if provider not in {"mercadopago", "paypal", "bank", "wise"}:
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
        return jsonify(ok=False, error=str(e)), 400
    except Exception:
        current_app.logger.exception("Start payment failed")
        return jsonify(ok=False, error="payment_start_failed"), 500

    return jsonify(ok=True, redirect_url=res.redirect_url, provider=res.provider)


@checkout_bp.get("/paypal/capture")
def paypal_capture():
    gate = _require_login()
    if gate:
        return gate

    if not ENABLE_PAYPAL:
        return redirect(url_for("checkout.payment_failure", provider="paypal"))

    if not _rate_limit_ok("paypal_capture"):
        return redirect(url_for("checkout.payment_failure", provider="paypal"))

    ck = _checkout_key()
    token = (request.args.get("token") or "").strip()

    if not ck or not token:
        return redirect(url_for("checkout.payment_failure", provider="paypal"))

    try:
        state = CheckoutFlow.get_state(ck)
        capture_paypal_order(order_id=state.order_id, paypal_order_id=token)
    except Exception:
        current_app.logger.exception("PayPal capture failed")
        return redirect(url_for("checkout.payment_failure", provider="paypal"))

    return redirect(url_for("checkout.payment_success", provider="paypal"))


@checkout_bp.get("/payment/<provider>/success")
def payment_success(provider: str):
    provider = str(provider or "").strip().lower()[:24]
    return render_template("checkout/success.html", provider=provider)


@checkout_bp.get("/payment/<provider>/failure")
def payment_failure(provider: str):
    provider = str(provider or "").strip().lower()[:24]
    return render_template("checkout/failure.html", provider=provider)


@checkout_bp.get("/payment/<provider>/pending")
def payment_pending(provider: str):
    provider = str(provider or "").strip().lower()[:24]
    return render_template("checkout/pending.html", provider=provider)


__all__ = ["checkout_bp"]
