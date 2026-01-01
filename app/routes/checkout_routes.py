# app/routes/checkout_routes.py — SKYLINE CHECKOUT ULTRA PRO (FINAL)
from __future__ import annotations

import os
import time
import secrets
import hashlib
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Dict, Optional, Tuple, List, Callable

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

from app.models import db, User, UserAddress, Order, OrderItem
from app.routes.cart_routes import cart_snapshot  # ✅ carrito real anti-trampa


checkout_bp = Blueprint("checkout", __name__, url_prefix="/checkout")

# ============================================================
# Config PRO (ENV)
# ============================================================

_TRUE = {"1", "true", "yes", "y", "on"}

ORDER_NUMBER_PREFIX = (os.getenv("ORDER_NUMBER_PREFIX", "SKY").strip() or "SKY")[:10]
DEFAULT_CURRENCY = ((os.getenv("DEFAULT_CURRENCY", "USD").strip().upper() or "USD")[:3])

# Shipping simple (luego: reglas por país/peso/umbral)
SHIPPING_FLAT_USD = Decimal(os.getenv("SHIPPING_FLAT_USD", "0.00") or "0.00")

# MercadoPago
MP_ACCESS_TOKEN_UY = (os.getenv("MP_ACCESS_TOKEN_UY", "").strip())
MP_ACCESS_TOKEN_AR = (os.getenv("MP_ACCESS_TOKEN_AR", "").strip())

# PayPal
PAYPAL_CLIENT_ID = (os.getenv("PAYPAL_CLIENT_ID", "").strip())
PAYPAL_CLIENT_SECRET = (os.getenv("PAYPAL_CLIENT_SECRET", "").strip())
PAYPAL_MODE = (os.getenv("PAYPAL_MODE", "sandbox").strip().lower() or "sandbox")  # sandbox|live

# Seguridad / Idempotencia
CHECKOUT_ORDER_SESSION_KEY = "checkout_order_id"
CHECKOUT_SNAPSHOT_HASH_KEY = "checkout_cart_hash_v1"
CHECKOUT_IDEMPOTENCY_KEY = "checkout_idempotency_v1"
CHECKOUT_RATELIMIT_KEY = "checkout_rl_last"
CHECKOUT_RATELIMIT_SECONDS = int(os.getenv("CHECKOUT_RATELIMIT_SECONDS", "2") or "2")  # anti doble click
MAX_PERMITTED_TOTAL = Decimal(os.getenv("CHECKOUT_MAX_TOTAL", "999999.99") or "999999.99")  # anti abuso

# Métodos permitidos (allowlist)
ALLOWED_PAYMENT_METHODS = {"paypal", "mercadopago", "bank_transfer"}

# Si lo activás, permite marcar paid en PayPal capture sin validar con API (NO recomendado)
PAYPAL_TRUST_CAPTURE = (os.getenv("PAYPAL_TRUST_CAPTURE", "0").strip().lower() in _TRUE)

# ✅ PRO: Moneda segura (MP usa currency_id tipo "USD", "UYU", "ARS")
MP_ALLOWED_CURRENCIES = {"USD", "UYU", "ARS"}

# ✅ PRO: cache de templates para no recalcular siempre
_TPL_CACHE: Dict[str, bool] = {}


# ============================================================
# Helpers base (blindados)
# ============================================================

def _d(x: Any) -> Decimal:
    try:
        return Decimal(str(x))
    except Exception:
        return Decimal("0.00")


def _money_dec(x: Any) -> Decimal:
    return _d(x).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def _money_str(x: Any) -> str:
    return str(_money_dec(x))


def _is_json_request() -> bool:
    accept = (request.headers.get("Accept") or "").lower()
    ctype = (request.headers.get("Content-Type") or "").lower()
    return ("application/json" in accept) or ("application/json" in ctype) or (request.args.get("json") == "1")


def _json(status: int, **payload):
    return jsonify(payload), status


def _endpoint_exists(endpoint: str) -> bool:
    try:
        return endpoint in (current_app.view_functions or {})
    except Exception:
        return False


def _url_for_safe(endpoint: str, fallback_path: str = "/", **kwargs) -> str:
    """✅ PRO: nunca revienta si falta endpoint."""
    try:
        if _endpoint_exists(endpoint):
            return url_for(endpoint, **kwargs)
    except Exception:
        pass
    return fallback_path


def _reply(payload: Dict[str, Any], *, status: int = 200, redirect_endpoint: Optional[str] = None, fallback_path: str = "/", **ep_kwargs):
    """Respuesta dual: JSON o redirect (sin duplicar lógica)."""
    if _is_json_request() or not redirect_endpoint:
        return jsonify(payload), status
    return redirect(_url_for_safe(redirect_endpoint, fallback_path=fallback_path, **ep_kwargs))


def _rate_limit_ok() -> bool:
    """Anti doble-click / spam del botón (por sesión)."""
    now = time.time()
    last = session.get(CHECKOUT_RATELIMIT_KEY, 0)
    try:
        last = float(last)
    except Exception:
        last = 0.0
    if (now - last) < max(1, CHECKOUT_RATELIMIT_SECONDS):
        return False
    session[CHECKOUT_RATELIMIT_KEY] = now
    session.modified = True
    return True


def _require_login():
    """Login requerido: en JSON devuelve 401, en UI redirige con next."""
    if session.get("user_id"):
        return None
    if _is_json_request():
        return _json(401, ok=False, error="auth_required")
    return redirect(_url_for_safe("auth.login", fallback_path="/login", next=request.path))


def _current_user() -> Optional[User]:
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        return db.session.get(User, int(uid))
    except Exception:
        return None


def _safe_template(name: str) -> bool:
    """✅ PRO: cache + no rompe."""
    if name in _TPL_CACHE:
        return _TPL_CACHE[name]
    try:
        current_app.jinja_env.get_template(name)
        _TPL_CACHE[name] = True
        return True
    except Exception:
        _TPL_CACHE[name] = False
        return False


def _order_number() -> str:
    # SKY-YYYYMMDD-ABC123
    stamp = time.strftime("%Y%m%d")
    rnd = secrets.token_hex(3).upper()
    return f"{ORDER_NUMBER_PREFIX}-{stamp}-{rnd}"


def _mp_token_for_country(country: str) -> str:
    c = (country or "").strip().upper()
    if c == "AR":
        return MP_ACCESS_TOKEN_AR
    if c == "UY":
        return MP_ACCESS_TOKEN_UY
    return MP_ACCESS_TOKEN_UY or MP_ACCESS_TOKEN_AR


def _shipping_total(_user: Optional[User], _snap: Dict[str, Any]) -> Decimal:
    # listo para reglas por país/peso/umbral
    return _money_dec(SHIPPING_FLAT_USD)


def _build_customer_snapshot(user: User, address: Optional[UserAddress]) -> Dict[str, Any]:
    """No rompe si faltan campos en modelos."""
    def _get(obj, name, default=None):
        try:
            return getattr(obj, name, default)
        except Exception:
            return default

    return {
        "customer_name": (((_get(address, "full_name") or _get(user, "name") or "")[:120]) or None),
        "customer_email": (((_get(user, "email") or "")[:255]) or None),
        "customer_phone": (((_get(address, "phone") or _get(user, "phone") or "")[:40]) or None),
        "country": (_get(address, "country") or _get(user, "country") or None),
        "city": (_get(address, "city") or _get(user, "city") or None),
    }


def _get_default_address(user_id: int) -> Optional[UserAddress]:
    try:
        return (
            db.session.query(UserAddress)
            .filter(UserAddress.user_id == user_id)
            .order_by(UserAddress.is_default.desc(), UserAddress.id.desc())
            .first()
        )
    except Exception:
        return None


def _get_address_for_checkout(user_id: int, address_id: Optional[int]) -> Optional[UserAddress]:
    if address_id:
        try:
            a = db.session.get(UserAddress, int(address_id))
            if a and a.user_id == user_id:
                return a
        except Exception:
            pass
    return _get_default_address(user_id)


def _pick_currency_from_snapshot(snap: Dict[str, Any]) -> str:
    cur = (snap.get("currency") or DEFAULT_CURRENCY)
    cur = str(cur).strip().upper()
    cur = cur[:3] if len(cur) >= 3 else DEFAULT_CURRENCY

    # ✅ PRO: clamp a set permitido para MP
    if cur not in MP_ALLOWED_CURRENCIES:
        return DEFAULT_CURRENCY
    return cur


def _cart_hash(snap: Dict[str, Any]) -> str:
    """
    Hash del carrito para detectar cambios entre start y pago (anti-trampa).
    Incluye: líneas, subtotal, descuento, currency.
    """
    lines = snap.get("lines") or []
    safe_lines = []
    for ln in lines:
        try:
            pid = int(ln.get("product_id") or 0)
            qty = int(ln.get("qty") or 0)
            up = str(ln.get("unit_price") or ln.get("unit_price_display") or "0")
            safe_lines.append((pid, qty, up))
        except Exception:
            continue
    safe_lines.sort(key=lambda x: x[0])

    base = "|".join([f"{pid}:{qty}:{up}" for pid, qty, up in safe_lines])
    base += f"|sub:{snap.get('subtotal')}|disc:{snap.get('discount_total')}|cur:{snap.get('currency')}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


def _set_field_safe(obj: Any, field: str, value: Any) -> None:
    try:
        if hasattr(obj, field):
            setattr(obj, field, value)
    except Exception:
        pass


def _order_is_editable(order: Any) -> bool:
    st = (getattr(order, "status", "") or "").lower()
    pay = (getattr(order, "payment_status", "") or "").lower()
    if st in {"paid", "completed", "cancelled", "canceled", "refunded"}:
        return False
    if pay in {"paid", "approved"}:
        return False
    return True


def _ensure_idempotency_key() -> str:
    """Key por sesión para evitar doble creación por refresh / doble click."""
    k = session.get(CHECKOUT_IDEMPOTENCY_KEY)
    if isinstance(k, str) and k:
        return k
    k = secrets.token_urlsafe(16)
    session[CHECKOUT_IDEMPOTENCY_KEY] = k
    session.modified = True
    return k


def _get_affiliate_from_request() -> Dict[str, Optional[str]]:
    """Afiliados tipo Temu: ?aff=xxx&sub=yyy (persistido en session)."""
    aff = (request.args.get("aff") or request.form.get("aff") or "").strip()[:80] or None
    sub = (request.args.get("sub") or request.form.get("sub") or "").strip()[:120] or None

    if not aff:
        aff = (session.get("aff_code") or None)
        if isinstance(aff, str):
            aff = aff.strip()[:80] or None
    if not sub:
        sub = (session.get("aff_sub") or None)
        if isinstance(sub, str):
            sub = sub.strip()[:120] or None

    if aff:
        session["aff_code"] = aff
    if sub:
        session["aff_sub"] = sub
    session.modified = True

    return {"aff": aff, "sub": sub}


def _validate_total_guard(total: Decimal) -> Optional[str]:
    if total < Decimal("0.00"):
        return "total_invalid"
    if total > MAX_PERMITTED_TOTAL:
        return "total_too_large"
    return None


def _load_order_for_user(user: User, order_id: Any) -> Optional[Order]:
    """✅ PRO: helper único, evita repetir lógica y errores."""
    try:
        o = db.session.get(Order, int(order_id))
        if not o:
            return None
        if getattr(o, "user_id", None) != user.id:
            return None
        return o
    except Exception:
        return None


def _cart_changed_since_start() -> bool:
    try:
        current_hash = _cart_hash(cart_snapshot())
        started_hash = session.get(CHECKOUT_SNAPSHOT_HASH_KEY)
        return bool(started_hash and started_hash != current_hash)
    except Exception:
        return False


# ============================================================
# Core: crear/reusar Order (blindado)
# ============================================================

def _create_order_from_cart(
    user: User,
    address: Optional[UserAddress],
    payment_method: str,
) -> Tuple[Optional[Order], Optional[str]]:
    """
    Crea Order + OrderItems desde snapshot anti-trampa.

    ✅ PRO mejoras (resumen):
    1) Rate-limit anti doble click
    2) Idempotencia por sesión (reusa orden editable)
    3) Hash carrito (detecta cambios)
    4) Total robusto (subtotal - descuento + shipping, clamp 0)
    5) Guarda afiliado (safe fields)
    6) Transacción real + rollback seguro
    7) No rompe si faltan campos en modelos
    8) Captura SKU/source/printful info best-effort
    9) Session persist segura + modified=True
    10) Logs claros con exception
    """
    if payment_method not in ALLOWED_PAYMENT_METHODS:
        payment_method = "mercadopago"

    if not _rate_limit_ok():
        return None, "Acción repetida muy rápido. Probá de nuevo."

    snap = cart_snapshot()
    if not snap.get("lines"):
        return None, "Tu carrito está vacío."

    # Idempotencia: reusar si existe y es editable
    existing_id = session.get(CHECKOUT_ORDER_SESSION_KEY)
    if existing_id:
        try:
            existing = db.session.get(Order, int(existing_id))
            if existing and getattr(existing, "user_id", None) == user.id and _order_is_editable(existing):
                session[CHECKOUT_SNAPSHOT_HASH_KEY] = _cart_hash(snap)
                session.modified = True
                return existing, None
        except Exception:
            pass

    currency = _pick_currency_from_snapshot(snap)
    subtotal = _money_dec(snap.get("subtotal", "0"))
    discount_total = _money_dec(snap.get("discount_total", "0"))
    shipping_total = _shipping_total(user, snap)

    total = subtotal - discount_total + shipping_total
    total = max(Decimal("0.00"), _money_dec(total))

    guard_err = _validate_total_guard(total)
    if guard_err:
        return None, "Total inválido. Revisá tu carrito."

    customer = _build_customer_snapshot(user, address)
    aff = _get_affiliate_from_request()

    order_kwargs: Dict[str, Any] = {
        "number": _order_number(),
        "user_id": user.id,
        "status": "awaiting_payment",
        "payment_method": payment_method,
        "payment_status": "pending",
        "currency": currency,
        "subtotal": subtotal,
        "discount_total": discount_total,
        "shipping_total": shipping_total,
        "total": total,
        **customer,
        "affiliate_code": aff["aff"],
        "affiliate_sub": aff["sub"],
    }

    try:
        with db.session.begin():
            try:
                o = Order(**order_kwargs)
            except TypeError:
                # fallback mínimo si tu Order no tiene todos esos campos
                o = Order(number=order_kwargs["number"], user_id=order_kwargs["user_id"])
                _set_field_safe(o, "status", order_kwargs["status"])
                _set_field_safe(o, "payment_method", payment_method)
                _set_field_safe(o, "payment_status", "pending")
                _set_field_safe(o, "currency", currency)
                _set_field_safe(o, "subtotal", subtotal)
                _set_field_safe(o, "discount_total", discount_total)
                _set_field_safe(o, "shipping_total", shipping_total)
                _set_field_safe(o, "total", total)
                for k, v in customer.items():
                    _set_field_safe(o, k, v)
                _set_field_safe(o, "affiliate_code", aff["aff"])
                _set_field_safe(o, "affiliate_sub", aff["sub"])

            db.session.add(o)
            db.session.flush()  # asegura o.id

            for ln in snap["lines"]:
                pid = int(ln.get("product_id") or 0)
                qty = max(1, int(ln.get("qty") or 1))

                unit_price = _money_dec(ln.get("unit_price") or ln.get("unit_price_display") or "0")
                line_total = _money_dec(ln.get("line_total") or ln.get("line_total_display") or (unit_price * qty))

                sku = None
                src = "manual"
                printful_variant_id = None

                try:
                    from app.models import Product
                    p = db.session.get(Product, pid)
                    if p:
                        src = (getattr(p, "source", None) or "manual")[:20]
                        sku = (getattr(p, "sku", None) or getattr(p, "printful_product_id", None))
                        printful_variant_id = getattr(p, "printful_variant_id", None)
                except Exception:
                    pass

                try:
                    it = OrderItem(
                        order_id=o.id,
                        product_id=pid,
                        title_snapshot=(str(ln.get("title") or "Producto")[:200]),
                        source_snapshot=src,
                        sku_snapshot=(str(sku)[:80] if sku else None),
                        unit_price=unit_price,
                        qty=qty,
                        line_total=line_total,
                        printful_variant_id=printful_variant_id,
                    )
                except TypeError:
                    it = OrderItem(order_id=o.id, product_id=pid)
                    _set_field_safe(it, "title_snapshot", (str(ln.get("title") or "Producto")[:200]))
                    _set_field_safe(it, "source_snapshot", src)
                    _set_field_safe(it, "sku_snapshot", (str(sku)[:80] if sku else None))
                    _set_field_safe(it, "unit_price", unit_price)
                    _set_field_safe(it, "qty", qty)
                    _set_field_safe(it, "line_total", line_total)
                    _set_field_safe(it, "printful_variant_id", printful_variant_id)

                db.session.add(it)

        session[CHECKOUT_ORDER_SESSION_KEY] = int(o.id)
        session[CHECKOUT_SNAPSHOT_HASH_KEY] = _cart_hash(snap)
        session.modified = True

        return o, None

    except Exception as exc:
        db.session.rollback()
        current_app.logger.exception("Checkout create_order failed: %s", exc)
        return None, "No se pudo crear la orden. Intentá de nuevo."


def _addr_to_dict(a: UserAddress) -> Dict[str, Any]:
    return {
        "id": a.id,
        "label": getattr(a, "label", None),
        "full_name": getattr(a, "full_name", None),
        "phone": getattr(a, "phone", None),
        "line1": getattr(a, "line1", None),
        "line2": getattr(a, "line2", None),
        "city": getattr(a, "city", None),
        "state": getattr(a, "state", None),
        "postal_code": getattr(a, "postal_code", None),
        "country": getattr(a, "country", None),
        "is_default": bool(getattr(a, "is_default", False)),
    }


# ============================================================
# Routes UI
# ============================================================

@checkout_bp.get("/")
def checkout_home():
    gate = _require_login()
    if gate:
        return gate

    user = _current_user()
    if not user:
        return redirect(_url_for_safe("auth.login", fallback_path="/login", next=request.path))

    # afiliados: captura en session si viene por query
    _get_affiliate_from_request()

    snap = cart_snapshot()
    if not snap.get("lines"):
        # ✅ PRO: endpoint fallback si tu cart blueprint cambia
        return _reply(
            {"ok": False, "error": "cart_empty"},
            status=400,
            redirect_endpoint="cart.cart_view",
            fallback_path="/cart",
        )

    # Direcciones (best effort)
    try:
        addresses: List[UserAddress] = (
            db.session.query(UserAddress)
            .filter(UserAddress.user_id == user.id)
            .order_by(UserAddress.is_default.desc(), UserAddress.id.desc())
            .all()
        )
    except Exception:
        addresses = []

    # ✅ PRO: si no existe template, devuelve JSON usable
    if not _safe_template("checkout/checkout.html"):
        return jsonify(
            ok=True,
            cart=snap,
            addresses=[_addr_to_dict(a) for a in addresses],
            paypal_enabled=bool(PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET),
            mp_uy_enabled=bool(MP_ACCESS_TOKEN_UY),
            mp_ar_enabled=bool(MP_ACCESS_TOKEN_AR),
            paypal_mode=PAYPAL_MODE,
        )

    return render_template(
        "checkout/checkout.html",
        cart=snap,
        addresses=addresses,
        user=user,
        paypal_enabled=bool(PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET),
        mp_uy_enabled=bool(MP_ACCESS_TOKEN_UY),
        mp_ar_enabled=bool(MP_ACCESS_TOKEN_AR),
        paypal_mode=PAYPAL_MODE,
    )


# ============================================================
# Start checkout -> crea/reusa Order
# ============================================================

@checkout_bp.post("/start")
def checkout_start():
    gate = _require_login()
    if gate:
        return gate

    user = _current_user()
    if not user:
        return _json(401, ok=False, error="not_logged_in")

    _ensure_idempotency_key()

    data = request.get_json(silent=True) or request.form
    payment_method = (str(data.get("payment_method") or "mercadopago").strip().lower())
    address_id = data.get("address_id")

    if payment_method not in ALLOWED_PAYMENT_METHODS:
        payment_method = "mercadopago"

    try:
        addr_id_int = int(address_id) if address_id else None
    except Exception:
        addr_id_int = None

    address = _get_address_for_checkout(user.id, addr_id_int)

    order, err = _create_order_from_cart(user, address, payment_method=payment_method)
    if err:
        return _json(400, ok=False, error=err)

    assert order is not None

    return jsonify(
        ok=True,
        order_id=int(order.id),
        order_number=getattr(order, "number", ""),
        payment_method=getattr(order, "payment_method", payment_method),
        currency=getattr(order, "currency", DEFAULT_CURRENCY),
        total=_money_str(getattr(order, "total", "0")),
        cart_hash=session.get(CHECKOUT_SNAPSHOT_HASH_KEY),
    )


# ============================================================
# MercadoPago (UY/AR) - Create Preference
# ============================================================

@checkout_bp.post("/mercadopago/create")
def mp_create_preference():
    gate = _require_login()
    if gate:
        return gate

    user = _current_user()
    if not user:
        return _json(401, ok=False, error="not_logged_in")

    data = request.get_json(silent=True) or request.form
    order_id = data.get("order_id") or session.get(CHECKOUT_ORDER_SESSION_KEY)
    country = (str(data.get("country") or getattr(user, "country", None) or "UY").strip().upper())

    order = _load_order_for_user(user, order_id)
    if not order:
        return _json(404, ok=False, error="order_not_found")

    if not _order_is_editable(order):
        return _json(400, ok=False, error="order_not_editable")

    if _cart_changed_since_start():
        return _json(409, ok=False, error="cart_changed", message="El carrito cambió. Re-iniciá el checkout.")

    token = _mp_token_for_country(country)
    if not token:
        return _json(400, ok=False, error="mp_not_configured", message="MercadoPago no configurado (MP_ACCESS_TOKEN_UY/AR).")

    try:
        import mercadopago  # type: ignore
    except Exception:
        return _json(400, ok=False, error="mp_sdk_missing", message="SDK mercadopago no instalado. (pip install mercadopago)")

    try:
        sdk = mercadopago.SDK(token)

        order_items = db.session.query(OrderItem).filter(OrderItem.order_id == order.id).all()

        currency = (getattr(order, "currency", DEFAULT_CURRENCY) or DEFAULT_CURRENCY)[:3]
        if currency not in MP_ALLOWED_CURRENCIES:
            currency = DEFAULT_CURRENCY

        items = []
        for it in order_items:
            items.append({
                "title": (getattr(it, "title_snapshot", "Producto") or "Producto")[:255],
                "quantity": int(getattr(it, "qty", 1) or 1),
                "unit_price": float(_money_dec(getattr(it, "unit_price", 0))),
                "currency_id": currency,
            })

        # ✅ PRO: si no hay items, no crear preferencia
        if not items:
            return _json(400, ok=False, error="empty_order_items", message="La orden no tiene items.")

        # ✅ PRO: agregar shipping como ítem (si tu shipping > 0)
        ship = _money_dec(getattr(order, "shipping_total", 0))
        if ship > Decimal("0.00"):
            items.append({
                "title": "Envío",
                "quantity": 1,
                "unit_price": float(ship),
                "currency_id": currency,
            })

        pref = {
            "items": items,
            "metadata": {"order_id": int(order.id), "order_number": getattr(order, "number", "")},
            "external_reference": str(getattr(order, "number", order.id)),
            "back_urls": {
                "success": url_for("checkout.payment_success", provider="mercadopago", _external=True),
                "failure": url_for("checkout.payment_failure", provider="mercadopago", _external=True),
                "pending": url_for("checkout.payment_pending", provider="mercadopago", _external=True),
            },
            "auto_return": "approved",
            "notification_url": url_for("checkout.mp_webhook", _external=True),
        }

        resp = sdk.preference().create(pref)
        body = (resp or {}).get("response") or {}
        init_point = body.get("init_point") or body.get("sandbox_init_point")
        pref_id = body.get("id")

        if not init_point:
            return _json(500, ok=False, error="mp_preference_failed")

        _set_field_safe(order, "mp_preference_id", str(pref_id) if pref_id else None)
        _set_field_safe(order, "payment_method", "mercadopago")
        db.session.commit()

        return jsonify(ok=True, init_point=init_point, preference_id=pref_id)

    except Exception as exc:
        current_app.logger.exception("MercadoPago create preference error: %s", exc)
        db.session.rollback()
        return _json(500, ok=False, error="mp_create_failed")


# ============================================================
# PayPal - Create (datos para JS SDK) + Capture
# ============================================================

@checkout_bp.post("/paypal/create")
def paypal_create():
    gate = _require_login()
    if gate:
        return gate

    user = _current_user()
    if not user:
        return _json(401, ok=False, error="not_logged_in")

    if not (PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET):
        return _json(400, ok=False, error="paypal_not_configured")

    data = request.get_json(silent=True) or request.form
    order_id = data.get("order_id") or session.get(CHECKOUT_ORDER_SESSION_KEY)

    order = _load_order_for_user(user, order_id)
    if not order:
        return _json(404, ok=False, error="order_not_found")

    if not _order_is_editable(order):
        return _json(400, ok=False, error="order_not_editable")

    if _cart_changed_since_start():
        return _json(409, ok=False, error="cart_changed", message="El carrito cambió. Re-iniciá el checkout.")

    return jsonify(
        ok=True,
        mode=PAYPAL_MODE,
        client_id=PAYPAL_CLIENT_ID,
        order_id=int(order.id),
        order_number=getattr(order, "number", ""),
        amount=_money_str(getattr(order, "total", "0")),
        currency=(getattr(order, "currency", None) or DEFAULT_CURRENCY),
        capture_url=url_for("checkout.paypal_capture", _external=True),
    )


@checkout_bp.post("/paypal/capture")
def paypal_capture():
    """
    Capture PRO (blindado):
    - Guarda paypal_order_id
    - Por defecto NO marca paid sin validar con API (anti-fraude)
    - Si PAYPAL_TRUST_CAPTURE=1, permite marcar paid (NO recomendado)
    """
    gate = _require_login()
    if gate:
        return gate

    user = _current_user()
    if not user:
        return _json(401, ok=False, error="not_logged_in")

    data = request.get_json(silent=True) or {}
    order_id = data.get("order_id") or session.get(CHECKOUT_ORDER_SESSION_KEY)
    paypal_order_id = (str(data.get("paypal_order_id") or "").strip())[:120]

    order = _load_order_for_user(user, order_id)
    if not order:
        return _json(404, ok=False, error="order_not_found")

    if not paypal_order_id:
        return _json(400, ok=False, error="paypal_order_id_required")

    if not _order_is_editable(order):
        return _json(400, ok=False, error="order_not_editable")

    try:
        _set_field_safe(order, "payment_method", "paypal")
        _set_field_safe(order, "paypal_order_id", paypal_order_id)
        _set_field_safe(order, "payment_status", "pending")

        # SOLO si lo habilitás explícito
        if PAYPAL_TRUST_CAPTURE:
            _set_field_safe(order, "payment_status", "paid")
            _set_field_safe(order, "status", "paid")

        db.session.commit()
    except Exception:
        db.session.rollback()
        return _json(500, ok=False, error="save_failed")

    return jsonify(
        ok=True,
        trusted_capture=bool(PAYPAL_TRUST_CAPTURE),
        message=("Pago marcado como pagado (modo TRUST)."
                 if PAYPAL_TRUST_CAPTURE else
                 "PayPal order registrado. Falta validación/capture real para marcar pagado."),
        order_number=getattr(order, "number", ""),
    )


# ============================================================
# Webhooks / Returns (no rompen)
# ============================================================

@checkout_bp.post("/webhooks/mercadopago")
def mp_webhook():
    """
    Webhook/IPN MercadoPago.
    - No rompe aunque llegue cualquier payload.
    - PRO: log info y responder ok.
    """
    payload = request.get_json(silent=True) or {}
    current_app.logger.info("MP webhook: %s", payload)
    return jsonify(ok=True)


@checkout_bp.get("/payment/<provider>/success")
def payment_success(provider: str):
    # ✅ PRO: template fallback a JSON
    if _safe_template("checkout/success.html"):
        return render_template("checkout/success.html", provider=provider)
    return jsonify(ok=True, provider=provider)


@checkout_bp.get("/payment/<provider>/failure")
def payment_failure(provider: str):
    if _safe_template("checkout/failure.html"):
        return render_template("checkout/failure.html", provider=provider)
    return jsonify(ok=False, provider=provider)


@checkout_bp.get("/payment/<provider>/pending")
def payment_pending(provider: str):
    if _safe_template("checkout/pending.html"):
        return render_template("checkout/pending.html", provider=provider)
    return jsonify(ok=True, pending=True, provider=provider)


__all__ = ["checkout_bp"]
