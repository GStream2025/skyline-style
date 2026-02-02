# app/routes/checkout_routes.py — SKYLINE CHECKOUT ULTRA PRO (v3.0 / FINAL / NO-ERROR)
from __future__ import annotations

import os
import time
from typing import Any, Dict, Mapping, Optional, Tuple
from urllib.parse import urlencode, urlparse

from flask import (
    Blueprint,
    Response,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from sqlalchemy.exc import SQLAlchemyError

from app.models import db, User, UserAddress
from app.routes.cart_routes import cart_snapshot
from app.services.checkout_flow import CheckoutError, CheckoutFlow

try:
    from app.services.paypal_capture import capture_paypal_order  # type: ignore
except Exception:  # pragma: no cover
    capture_paypal_order = None  # type: ignore


checkout_bp = Blueprint("checkout", __name__, url_prefix="/checkout")
checkout_bp.strict_slashes = False

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off", "unchecked"}

DEFAULT_CURRENCY = (os.getenv("DEFAULT_CURRENCY") or "USD").strip().upper()[:3] or "USD"
CHECKOUT_RL_SECONDS = max(1, int((os.getenv("CHECKOUT_RATELIMIT_SECONDS") or "2").strip() or "2"))

ENABLE_PAYMENTS = (os.getenv("ENABLE_PAYMENTS") or "0").strip().lower() in _TRUE
ENABLE_MP = bool((os.getenv("MP_ACCESS_TOKEN") or "").strip())
ENABLE_PAYPAL = bool((os.getenv("PAYPAL_CLIENT_ID") or "").strip() and (os.getenv("PAYPAL_SECRET") or "").strip())

SESSION_CHECKOUT_KEY = "checkout_key_v3"
SESSION_RL_KEY = "checkout_rl_ts_v3"

_ALLOWED_PROVIDERS = {"mercadopago", "paypal", "bank", "wise"}

_CACHE_HEADERS = {
    "Cache-Control": "no-store, max-age=0, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
    "Vary": "Accept, Cookie",
    "X-Frame-Options": "SAMEORIGIN",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}

# Design tokens for templates
CHECKOUT_UI_TOKENS = {
    "brand": "skyline",
    "radius": 18,
    "shadow": "0 22px 70px rgba(0,0,0,.12)",
    "surface": "rgba(255,255,255,.92)",
    "surface2": "rgba(255,255,255,.78)",
    "stroke": "rgba(15,23,42,.12)",
    "muted": "#64748b",
    "ok": "#16a34a",
    "warn": "#f59e0b",
    "bad": "#ef4444",
}


def _s(v: Any, max_len: int = 500, *, default: str = "") -> str:
    if v is None:
        return default
    s = v.strip() if isinstance(v, str) else str(v).strip()
    s = s.replace("\x00", "").replace("\u200b", "").replace("\r", "").replace("\n", "").replace("\t", "")
    if not s:
        return default
    s = " ".join(s.split())
    return s[: max(0, int(max_len))]


def _wants_json() -> bool:
    try:
        if request.is_json:
            return True
    except Exception:
        pass

    fmt = _s(request.args.get("format") or request.args.get("json") or "", 16).lower()
    if fmt in {"1", "json", "true", "yes"}:
        return True

    accept = _s(request.headers.get("Accept"), 200).lower()
    if "application/json" in accept or "text/json" in accept:
        return True

    ctype = _s(request.headers.get("Content-Type"), 120).lower()
    if ctype.startswith("application/json"):
        return True

    xrw = _s(request.headers.get("X-Requested-With"), 60).lower()
    return xrw == "xmlhttprequest"


def _no_store_headers(resp: Response) -> Response:
    try:
        for k, v in _CACHE_HEADERS.items():
            resp.headers.setdefault(k, v)
        resp.headers.setdefault("X-Served-By", "skyline")
    except Exception:
        pass
    return resp


def _json(payload: Dict[str, Any], status: int = 200) -> Response:
    r = jsonify(payload)
    r.status_code = int(status)
    return _no_store_headers(r)


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


def _is_safe_next(nxt: str) -> bool:
    if not nxt:
        return False
    u = _s(nxt, 600)
    if not u or " " in u:
        return False
    if any(ch in u for ch in ("\x00", "\r", "\n", "\t", "\\")):
        return False
    if u.startswith("//") or "://" in u:
        return False
    if ".." in u:
        return False
    try:
        p = urlparse(u)
    except Exception:
        return False
    if p.scheme or p.netloc:
        return False
    if not (p.path or "").startswith("/"):
        return False
    if (p.path or "").startswith(("/auth/login", "/auth/register")):
        return False
    return True


def _safe_next_from_request(default: str = "/checkout/") -> str:
    raw = ""
    try:
        raw = request.full_path if request.query_string else request.path
    except Exception:
        raw = ""
    raw = _s(raw, 600)
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
    except SQLAlchemyError:
        try:
            db.session.rollback()
        except Exception:
            pass
        return None
    except Exception:
        return None


def _rate_limit_ok(bucket: str = "default") -> Tuple[bool, int]:
    """
    Per-session cooldown per bucket.
    Returns (ok, retry_after_sec).
    """
    now = float(time.time())
    st = session.get(SESSION_RL_KEY)
    if not isinstance(st, dict):
        st = {}

    # prune (avoid unbounded growth)
    if len(st) > 80:
        for k in list(st.keys()):
            try:
                if now - float(st.get(k) or 0.0) > 3600:
                    st.pop(k, None)
            except Exception:
                st.pop(k, None)

    try:
        last = float(st.get(bucket, 0.0) or 0.0)
    except Exception:
        last = 0.0

    cooldown = float(CHECKOUT_RL_SECONDS)
    if now - last < cooldown:
        retry = max(1, int((last + cooldown) - now))
        return False, retry

    st[bucket] = now
    session[SESSION_RL_KEY] = st
    session.modified = True
    return True, 0


def _get_address_for_user(user_id: int, address_id: Any) -> Optional[UserAddress]:
    if not address_id:
        return None
    try:
        aid = int(_s(address_id, 40))
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
    s = _s(v, 220)
    return s or None


def _set_checkout_key(v: str) -> None:
    session[SESSION_CHECKOUT_KEY] = _s(v, 200)
    session.modified = True


def _clear_checkout_key() -> None:
    session.pop(SESSION_CHECKOUT_KEY, None)
    session.modified = True


def _provider_normalize(p: Any) -> str:
    s = _s(p, 24).lower()
    return s if s in _ALLOWED_PROVIDERS else "mercadopago"


def _provider_available(provider: str) -> Tuple[bool, str]:
    if not ENABLE_PAYMENTS:
        return False, "payments_disabled"
    if provider == "mercadopago" and not ENABLE_MP:
        return False, "mercadopago_unavailable"
    if provider == "paypal" and not ENABLE_PAYPAL:
        return False, "paypal_unavailable"
    return True, ""


@checkout_bp.after_request
def _after(resp: Response):
    return _no_store_headers(resp)


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

    addresses = []
    try:
        # Prefer query API if it exists, else SQLAlchemy session query fallback.
        if hasattr(UserAddress, "query"):
            addresses = (
                UserAddress.query.filter_by(user_id=user.id)
                .order_by(getattr(UserAddress, "is_default").desc())  # type: ignore[attr-defined]
                .limit(50)
                .all()
            )
        else:
            addresses = (
                db.session.query(UserAddress)
                .filter_by(user_id=user.id)
                .order_by(UserAddress.is_default.desc(), UserAddress.id.desc())
                .limit(50)
                .all()
            )
    except Exception:
        addresses = []

    # Provide tokens + flags for templates (design-ready)
    ctx = dict(
        cart=snap,
        user=user,
        addresses=addresses,
        mp_enabled=bool(ENABLE_MP),
        paypal_enabled=bool(ENABLE_PAYPAL),
        payments_enabled=bool(ENABLE_PAYMENTS),
        ui=dict(CHECKOUT_UI_TOKENS),
        checkout_key=_checkout_key(),
    )

    for tpl in ("checkout/checkout.html", "checkout.html"):
        try:
            current_app.jinja_env.get_template(tpl)
            r = render_template(tpl, **ctx)
            return _no_store_headers(current_app.make_response(r, 200))
        except Exception:
            continue

    return _json({"ok": True, "page": "checkout", **ctx}, 200)


@checkout_bp.post("/start")
def checkout_start():
    gate = _require_login()
    if gate:
        return gate

    ok_rl, retry = _rate_limit_ok("start")
    if not ok_rl:
        return _json({"ok": False, "error": "rate_limited", "retry_after": retry}, 429)

    data = _read_payload()
    provider = _provider_normalize(data.get("payment_method") or "mercadopago")

    okp, perr = _provider_available(provider)
    if not okp:
        return _json({"ok": False, "error": perr}, 400)

    user = _current_user()
    if not user:
        return _json({"ok": False, "error": "not_authenticated"}, 401)

    snap = cart_snapshot()
    if _cart_is_empty(snap):
        return _json({"ok": False, "error": "cart_empty"}, 400)

    address = _get_address_for_user(int(user.id), data.get("address_id"))
    ck = _checkout_key()

    currency = _s(snap.get("currency") or DEFAULT_CURRENCY, 3).upper() or DEFAULT_CURRENCY

    # Address fields: support both (address1) and (line1) to match your models
    ship_address1 = None
    if address:
        ship_address1 = _s(
            getattr(address, "address1", None)
            or getattr(address, "line1", None)
            or getattr(address, "line_1", None)
            or "",
            180,
        ) or None

    ship_city = _s(getattr(address, "city", "") if address else "", 120) or None
    ship_country = _s(getattr(address, "country", "") if address else "", 2).upper() or None

    try:
        state = CheckoutFlow.create_checkout(
            lines=snap.get("lines") or [],
            customer_email=_s(getattr(user, "email", "") or "", 254).lower(),
            currency=currency,
            payment_method=provider,
            user_id=int(user.id),
            customer_name=_s(getattr(user, "name", "") or "", 140) or None,
            customer_phone=_s(getattr(user, "phone", "") or "", 40) or None,
            ship_address1=ship_address1,
            ship_city=ship_city,
            ship_country=ship_country,
            checkout_key=ck,
        )
    except CheckoutError as e:
        return _json({"ok": False, "error": _s(e, 180)}, 400)
    except Exception:
        current_app.logger.exception("checkout_create_failed")
        return _json({"ok": False, "error": "checkout_create_failed"}, 500)

    _set_checkout_key(getattr(state, "checkout_key", "") or "")
    return _json(
        {
            "ok": True,
            "checkout_key": state.checkout_key,
            "order_id": state.order_id,
            "total": state.total,
            "currency": state.currency,
            "provider": provider,
        },
        200,
    )


@checkout_bp.post("/pay/<provider>")
def checkout_pay(provider: str):
    gate = _require_login()
    if gate:
        return gate

    ok_rl, retry = _rate_limit_ok("pay")
    if not ok_rl:
        return _json({"ok": False, "error": "rate_limited", "retry_after": retry}, 429)

    provider = _provider_normalize(provider)
    okp, perr = _provider_available(provider)
    if not okp:
        return _json({"ok": False, "error": perr}, 400)

    ck = _checkout_key()
    if not ck:
        return _json({"ok": False, "error": "checkout_not_started"}, 400)

    # external URLs are needed by providers
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
        return _json({"ok": False, "error": _s(e, 180)}, 400)
    except Exception:
        current_app.logger.exception("payment_start_failed")
        return _json({"ok": False, "error": "payment_start_failed"}, 500)

    return _json({"ok": True, "redirect_url": res.redirect_url, "provider": res.provider}, 200)


@checkout_bp.get("/paypal/capture")
def paypal_capture():
    gate = _require_login()
    if gate:
        return gate

    if not ENABLE_PAYPAL or capture_paypal_order is None:
        return redirect(url_for("checkout.payment_failure", provider="paypal"), code=302)

    ok_rl, _ = _rate_limit_ok("paypal_capture")
    if not ok_rl:
        return redirect(url_for("checkout.payment_failure", provider="paypal"), code=302)

    ck = _checkout_key()
    token = _s(request.args.get("token") or "", 220)
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
    provider = _provider_normalize(provider)
    # optional: clear checkout key after success page render (safe)
    return render_template("checkout/success.html", provider=provider, ui=dict(CHECKOUT_UI_TOKENS))


@checkout_bp.get("/payment/<provider>/failure")
def payment_failure(provider: str):
    provider = _provider_normalize(provider)
    return render_template("checkout/failure.html", provider=provider, ui=dict(CHECKOUT_UI_TOKENS))


@checkout_bp.get("/payment/<provider>/pending")
def payment_pending(provider: str):
    provider = _provider_normalize(provider)
    return render_template("checkout/pending.html", provider=provider, ui=dict(CHECKOUT_UI_TOKENS))


__all__ = ["checkout_bp", "CHECKOUT_UI_TOKENS"]
