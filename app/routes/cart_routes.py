# app/routes/cart_routes.py — SKYLINE CART ULTRA PRO (v3.0 / FINAL / NO-ERROR)
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP
from time import time
from typing import Any, Dict, List, Mapping, Optional, Tuple

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

from app.models import db, Product

try:
    from app.models import Offer  # type: ignore
except Exception:  # pragma: no cover
    Offer = None  # type: ignore


cart_bp = Blueprint("cart", __name__, url_prefix="/cart")

CART_SESSION_KEY = "cart_v3"
CART_SCHEMA_VERSION = 3

MAX_QTY_PER_ITEM = 25
MIN_QTY_PER_ITEM = 1
MAX_DISTINCT_ITEMS = 120

DEFAULT_CURRENCY = "USD"
ALLOWED_CURRENCIES = {"USD", "UYU", "ARS"}

RL_WINDOW_SEC = 2.0
RL_MAX_ACTIONS = 14
_RL_KEY = "cart_rl_v3"

CSRF_SESSION_KEY = "csrf_token"
_REQ_CACHE_KEY = "_cart_snapshot_cache_v3"


def _now_ts() -> int:
    return int(time())


def _d(x: Any) -> Decimal:
    try:
        if isinstance(x, Decimal):
            return x
        return Decimal(str(x))
    except Exception:
        return Decimal("0.00")


def _money(x: Any) -> str:
    return str(_d(x).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def _is_json_request() -> bool:
    accept = (request.headers.get("Accept") or "").lower()
    ctype = (request.headers.get("Content-Type") or "").lower()
    return ("application/json" in accept) or ("application/json" in ctype) or (request.args.get("json") == "1")


def _endpoint_exists(endpoint: str) -> bool:
    try:
        return endpoint in (current_app.view_functions or {})
    except Exception:
        return False


def _url_for_safe(endpoint: str, fallback_path: str = "/cart", **kwargs) -> str:
    try:
        if _endpoint_exists(endpoint):
            return url_for(endpoint, **kwargs)
    except Exception:
        pass
    return fallback_path


def _reply(
    payload: Dict[str, Any],
    *,
    html_redirect_endpoint: Optional[str] = None,
    status: int = 200,
    fallback_path: str = "/cart",
    **ep_kwargs,
):
    if _is_json_request() or html_redirect_endpoint is None:
        return jsonify(payload), status
    return redirect(_url_for_safe(html_redirect_endpoint, fallback_path=fallback_path, **ep_kwargs))


def _err(
    code: str,
    message: str,
    status: int = 400,
    *,
    details: Optional[Dict[str, Any]] = None,
    html_redirect_endpoint: Optional[str] = "cart.cart_view",
):
    payload: Dict[str, Any] = {"ok": False, "error": {"code": code, "message": message}}
    if details:
        payload["error"]["details"] = details
    return _reply(payload, status=status, html_redirect_endpoint=html_redirect_endpoint, fallback_path="/cart")


def _csrf_enabled() -> bool:
    return bool((session.get(CSRF_SESSION_KEY) or "").strip())


def _check_csrf() -> bool:
    token = (session.get(CSRF_SESSION_KEY) or "").strip()
    got = (
        (request.headers.get("X-CSRF-Token") or "")
        or (request.form.get("csrf_token") or "")
        or (((request.get_json(silent=True) or {}).get("csrf_token")) if request.is_json else "")
        or ""
    )
    got = str(got).strip()
    if not token:
        return True
    try:
        import secrets
        return bool(got) and secrets.compare_digest(token, got)
    except Exception:
        return token == got


def _csrf_required() -> Optional[Any]:
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and _csrf_enabled():
        if not _check_csrf():
            return _err("csrf_invalid", "Token inválido. Recargá la página e intentá de nuevo.", 400)
    return None


def _rate_limit_ok(bucket: str) -> bool:
    try:
        st = session.get(_RL_KEY)
        if not isinstance(st, dict):
            st = {}

        now = float(time())
        b = st.get(bucket)
        if not isinstance(b, dict):
            b = {}

        win_start = float(b.get("start", now))
        count = int(b.get("count", 0))

        if now - win_start > RL_WINDOW_SEC:
            b = {"start": now, "count": 1}
        else:
            b["count"] = count + 1

        st[bucket] = b
        session[_RL_KEY] = st
        session.modified = True
        return int(b.get("count", 0)) <= RL_MAX_ACTIONS
    except Exception:
        return True


def _clamp_qty(qty: int) -> int:
    if qty < MIN_QTY_PER_ITEM:
        return MIN_QTY_PER_ITEM
    if qty > MAX_QTY_PER_ITEM:
        return MAX_QTY_PER_ITEM
    return qty


def _parse_int(value: Any, default: int) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return default


def _parse_qty(value: Any, default: int = 1) -> int:
    q = _parse_int(value, default)
    if q <= 0:
        return 0
    return _clamp_qty(q)


def _invalidate_snapshot_cache() -> None:
    try:
        setattr(request, _REQ_CACHE_KEY, None)
    except Exception:
        pass


def _cart() -> Dict[str, Any]:
    c = session.get(CART_SESSION_KEY)
    if not isinstance(c, dict):
        c = {"v": CART_SCHEMA_VERSION, "items": {}, "meta": {}}
        session[CART_SESSION_KEY] = c
        session.modified = True

    if int(c.get("v") or 0) != CART_SCHEMA_VERSION:
        old_items = c.get("items") if isinstance(c.get("items"), dict) else {}
        new_items: Dict[str, Dict[str, Any]] = {}
        if isinstance(old_items, dict):
            for k, v in old_items.items():
                if not isinstance(v, dict):
                    continue
                qty = _parse_qty(v.get("qty") or v.get("q") or 1, 1)
                if qty <= 0:
                    continue
                new_items[str(k)] = {"q": qty, "a": int(v.get("added_at") or v.get("a") or _now_ts())}
        c = {"v": CART_SCHEMA_VERSION, "items": new_items, "meta": dict(c.get("meta") or {})}
        session[CART_SESSION_KEY] = c
        session.modified = True

    c.setdefault("items", {})
    c.setdefault("meta", {})

    cur = (str(c["meta"].get("currency") or DEFAULT_CURRENCY).strip().upper()[:3] or DEFAULT_CURRENCY)
    if cur not in ALLOWED_CURRENCIES:
        cur = DEFAULT_CURRENCY
    c["meta"]["currency"] = cur
    c["meta"].setdefault("updated_at", _now_ts())
    return c


def _save_cart(c: Dict[str, Any]) -> None:
    c.setdefault("meta", {})
    c["meta"]["updated_at"] = _now_ts()
    session[CART_SESSION_KEY] = c
    session.modified = True
    _invalidate_snapshot_cache()


def _get_product(product_id: int) -> Optional[Product]:
    try:
        return db.session.get(Product, int(product_id))
    except Exception:
        return None


def _product_price_decimal(p: Product) -> Decimal:
    return _d(getattr(p, "price", 0))


def _product_title(p: Product) -> str:
    for k in ("title", "name"):
        v = getattr(p, k, None)
        if isinstance(v, str) and v.strip():
            return v.strip()[:180]
    return "Producto"


def _product_image(p: Product) -> Optional[str]:
    try:
        if hasattr(p, "main_image_url") and callable(getattr(p, "main_image_url")):
            u = p.main_image_url()
            if u:
                return str(u)
    except Exception:
        pass

    try:
        media = getattr(p, "media", None)
        if media and len(media) > 0:
            u = getattr(media[0], "url", None)
            if u:
                return str(u)
    except Exception:
        pass

    for k in ("image_url", "img", "image"):
        v = getattr(p, k, None)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _product_currency(p: Product) -> str:
    c = getattr(p, "currency", None) or DEFAULT_CURRENCY
    c = str(c).strip().upper()
    c = c[:3] if len(c) >= 3 else DEFAULT_CURRENCY
    return c if c in ALLOWED_CURRENCIES else DEFAULT_CURRENCY


def _is_available(p: Product, qty: int) -> Tuple[bool, str, int]:
    status = (getattr(p, "status", "active") or "").lower()
    if status != "active":
        return False, "Producto no disponible.", 0

    stock_mode = (getattr(p, "stock_mode", "finite") or "finite").lower()
    if stock_mode in {"unlimited", "external"}:
        return True, "", qty

    stock_qty = getattr(p, "stock_qty", None)
    if stock_qty is None:
        stock_qty = getattr(p, "stock", 0)

    try:
        stock_qty_int = int(stock_qty or 0)
    except Exception:
        stock_qty_int = 0

    if stock_qty_int <= 0:
        return False, "Sin stock.", 0

    if qty > stock_qty_int:
        return False, f"Solo hay {stock_qty_int} unidades disponibles.", stock_qty_int

    return True, "", qty


def _apply_offer_discount_if_any(p: Product, unit_price: Decimal) -> Tuple[Decimal, Optional[str], Optional[Decimal]]:
    if Offer is None or not hasattr(Offer, "query"):
        return unit_price, None, None

    try:
        o = None
        if hasattr(Offer, "product_id"):
            o = Offer.query.filter(Offer.product_id == p.id).first()
        if not o:
            return unit_price, None, None

        try:
            from datetime import datetime
            now_dt = datetime.utcnow()
            starts = getattr(o, "starts_at", None)
            ends = getattr(o, "ends_at", None)
            if starts and starts > now_dt:
                return unit_price, None, None
            if ends and ends < now_dt:
                return unit_price, None, None
        except Exception:
            pass

        dtype = (getattr(o, "discount_type", None) or getattr(o, "type", "none") or "none").lower()
        dval = _d(getattr(o, "discount_value", None) or getattr(o, "value", 0))
        if dval <= 0:
            return unit_price, None, None

        if dtype in {"percent", "%"}:
            pct = dval / Decimal("100")
            newp = unit_price * (Decimal("1.00") - pct)
            newp = max(Decimal("0.00"), newp)
            return newp, f"-{int(dval)}%", dval

        if dtype in {"amount", "fixed", "$"}:
            newp = unit_price - dval
            newp = max(Decimal("0.00"), newp)
            return newp, f"-{_money(dval)}", dval

        return unit_price, None, None
    except Exception as exc:
        current_app.logger.info("Offer discount hook ignored: %s", exc)
        return unit_price, None, None


@dataclass
class CartLine:
    product_id: int
    qty: int
    title: str
    slug: Optional[str]
    image_url: Optional[str]
    currency: str
    unit_price: Decimal
    unit_price_display: str
    line_total: Decimal
    line_total_display: str
    compare_at_display: Optional[str] = None
    discount_badge: Optional[str] = None
    available: bool = True
    note: Optional[str] = None
    added_at: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "product_id": self.product_id,
            "qty": self.qty,
            "title": self.title,
            "slug": self.slug,
            "image_url": self.image_url,
            "currency": self.currency,
            "unit_price": _money(self.unit_price),
            "unit_price_display": self.unit_price_display,
            "line_total": _money(self.line_total),
            "line_total_display": self.line_total_display,
            "compare_at_display": self.compare_at_display,
            "discount_badge": self.discount_badge,
            "available": self.available,
            "note": self.note,
            "added_at": self.added_at,
        }


def cart_snapshot() -> Dict[str, Any]:
    try:
        cached = getattr(request, _REQ_CACHE_KEY, None)
        if isinstance(cached, dict):
            return cached
    except Exception:
        pass

    c = _cart()
    items: Dict[str, Dict[str, Any]] = c.get("items", {}) or {}

    if len(items) > MAX_DISTINCT_ITEMS:
        keys = list(items.keys())[:MAX_DISTINCT_ITEMS]
        items = {k: items[k] for k in keys}
        c["items"] = items
        _save_cart(c)

    cart_currency = (str(c.get("meta", {}).get("currency") or DEFAULT_CURRENCY).upper()[:3] or DEFAULT_CURRENCY)
    if cart_currency not in ALLOWED_CURRENCIES:
        cart_currency = DEFAULT_CURRENCY
        c["meta"]["currency"] = cart_currency

    lines: List[CartLine] = []
    subtotal = Decimal("0.00")
    discount_total = Decimal("0.00")
    to_delete: List[str] = []
    mixed_currency = False

    for pid_str, row in items.items():
        try:
            pid = int(pid_str)
        except Exception:
            to_delete.append(pid_str)
            continue

        qty = _parse_qty((row or {}).get("q", 1), 1)
        if qty <= 0:
            to_delete.append(pid_str)
            continue

        p = _get_product(pid)
        if not p:
            to_delete.append(pid_str)
            continue

        ok, msg, allowed = _is_available(p, qty)
        if not ok:
            if allowed <= 0:
                to_delete.append(pid_str)
                continue
            qty = _clamp_qty(allowed)

        base_unit = _product_price_decimal(p)
        compare_at = getattr(p, "compare_at_price", None)
        compare_at_dec = _d(compare_at) if compare_at is not None else None

        discounted_unit, badge, _ = _apply_offer_discount_if_any(p, base_unit)

        compare_at_display = None
        if compare_at_dec is not None and compare_at_dec > base_unit and compare_at_dec > 0:
            compare_at_display = _money(compare_at_dec)

        if discounted_unit < base_unit:
            discount_total += (base_unit - discounted_unit) * Decimal(qty)

        line_total = discounted_unit * Decimal(qty)
        subtotal += line_total

        if _product_currency(p) != cart_currency:
            mixed_currency = True

        added_at = int((row or {}).get("a") or _now_ts())

        lines.append(
            CartLine(
                product_id=pid,
                qty=qty,
                title=_product_title(p),
                slug=getattr(p, "slug", None),
                image_url=_product_image(p),
                currency=cart_currency,
                unit_price=discounted_unit,
                unit_price_display=_money(discounted_unit),
                line_total=line_total,
                line_total_display=_money(line_total),
                compare_at_display=compare_at_display,
                discount_badge=badge,
                available=True,
                note=(msg or None),
                added_at=added_at,
            )
        )

        items[str(pid)] = {"q": qty, "a": added_at}

    for k in to_delete:
        items.pop(k, None)

    lines.sort(key=lambda x: (int(x.added_at or 0), int(x.product_id)), reverse=True)

    c["items"] = items
    _save_cart(c)

    out: Dict[str, Any] = {
        "schema": CART_SCHEMA_VERSION,
        "items_count": sum(ln.qty for ln in lines),
        "distinct_items": len(lines),
        "currency": cart_currency,
        "lines": [ln.to_dict() for ln in lines],
        "subtotal": _money(subtotal),
        "discount_total": _money(discount_total),
        "total": _money(subtotal),
        "updated_at": c.get("meta", {}).get("updated_at", _now_ts()),
        "has_items": bool(lines),
    }
    if mixed_currency:
        out["warning"] = "mixed_currency_detected"

    try:
        setattr(request, _REQ_CACHE_KEY, out)
    except Exception:
        pass
    return out


def merge_cart_items(into_user_id: int) -> None:
    _ = into_user_id
    return


@cart_bp.get("/")
def cart_view():
    snap = cart_snapshot()

    for tpl in ("cart/cart.html", "cart.html"):
        try:
            current_app.jinja_env.get_template(tpl)
            return render_template(tpl, cart=snap)
        except Exception:
            continue

    return jsonify(ok=True, cart=snap)


@cart_bp.get("/json")
def cart_json():
    return jsonify(ok=True, cart=cart_snapshot())


@cart_bp.get("/count")
def cart_count():
    snap = cart_snapshot()
    return jsonify(ok=True, items_count=int(snap.get("items_count") or 0), distinct_items=int(snap.get("distinct_items") or 0))


@cart_bp.get("/checkout")
def cart_checkout_bridge():
    snap = cart_snapshot()
    if not snap.get("has_items"):
        if _is_json_request():
            return jsonify(ok=False, error="cart_empty"), 400
        return redirect(_url_for_safe("cart.cart_view", fallback_path="/cart"))

    if _endpoint_exists("checkout.checkout_home"):
        return redirect(url_for("checkout.checkout_home"))

    for ep in ("shop.checkout", "shop.checkout_home", "main.checkout", "main.checkout_home"):
        if _endpoint_exists(ep):
            return redirect(url_for(ep))

    return redirect("/checkout/")


@cart_bp.post("/add")
def cart_add():
    gate = _csrf_required()
    if gate:
        return gate
    if not _rate_limit_ok("add"):
        return _err("rate_limited", "Demasiadas acciones. Probá de nuevo en un momento.", 429)

    data = request.get_json(silent=True) or request.form
    pid = data.get("product_id") or data.get("id")
    qty = _parse_qty(data.get("qty") or 1, 1)
    mode = str(data.get("mode") or "inc").strip().lower()

    try:
        pid_int = int(pid)
    except Exception:
        return _err("product_id_invalid", "ID de producto inválido.", 400)

    p = _get_product(pid_int)
    if not p:
        return _err("product_not_found", "Producto no encontrado.", 404)

    c = _cart()
    items: Dict[str, Dict[str, Any]] = c["items"]

    cur = items.get(str(pid_int), {}) or {}
    cur_qty = _parse_qty(cur.get("q", 0), 0)

    new_qty = qty if mode == "set" else _clamp_qty(cur_qty + qty)

    if new_qty <= 0:
        items.pop(str(pid_int), None)
        _save_cart(c)
        return _reply({"ok": True, "cart": cart_snapshot()}, status=200, html_redirect_endpoint="cart.cart_view")

    ok, msg, allowed = _is_available(p, new_qty)
    if not ok:
        if allowed > 0:
            new_qty = _clamp_qty(allowed)
        else:
            return _err("not_available", msg, 400)

    items[str(pid_int)] = {"q": new_qty, "a": int(cur.get("a") or _now_ts())}
    c["items"] = items
    _save_cart(c)

    return _reply({"ok": True, "cart": cart_snapshot()}, status=200, html_redirect_endpoint="cart.cart_view")


@cart_bp.post("/update")
def cart_update():
    gate = _csrf_required()
    if gate:
        return gate
    if not _rate_limit_ok("update"):
        return _err("rate_limited", "Demasiadas acciones. Probá de nuevo en un momento.", 429)

    data = request.get_json(silent=True) or request.form

    batch = None
    if isinstance(data, Mapping):
        batch = data.get("items")

    c = _cart()
    items: Dict[str, Dict[str, Any]] = c["items"]

    def _update_one(pid_any: Any, qty_any: Any) -> Optional[Tuple[str, int, str]]:
        try:
            pid_int = int(pid_any)
        except Exception:
            return ("product_id_invalid", 400, "ID inválido.")

        qty = _parse_qty(qty_any or 1, 1)

        if str(pid_int) not in items:
            return ("not_in_cart", 404, "El producto no está en el carrito.")

        if qty <= 0:
            items.pop(str(pid_int), None)
            return None

        p = _get_product(pid_int)
        if not p:
            items.pop(str(pid_int), None)
            return None

        ok, msg, allowed = _is_available(p, qty)
        if not ok:
            if allowed > 0:
                qty = _clamp_qty(allowed)
            else:
                return ("not_available", 400, msg or "Producto no disponible o sin stock.")

        items[str(pid_int)]["q"] = qty
        items[str(pid_int)].setdefault("a", _now_ts())
        return None

    if isinstance(batch, list):
        for it in batch:
            if not isinstance(it, Mapping):
                continue
            err = _update_one(it.get("product_id") or it.get("id"), it.get("qty"))
            if err:
                code, status, msg = err
                return _err(code, msg, status, details={"item": dict(it)})
    else:
        pid = data.get("product_id") or data.get("id")
        qty = data.get("qty") or 1
        err = _update_one(pid, qty)
        if err:
            code, status, msg = err
            return _err(code, msg, status)

    c["items"] = items
    _save_cart(c)

    return _reply({"ok": True, "cart": cart_snapshot()}, status=200, html_redirect_endpoint="cart.cart_view")


@cart_bp.post("/remove")
def cart_remove():
    gate = _csrf_required()
    if gate:
        return gate
    if not _rate_limit_ok("remove"):
        return _err("rate_limited", "Demasiadas acciones. Probá de nuevo en un momento.", 429)

    data = request.get_json(silent=True) or request.form
    pid = data.get("product_id") or data.get("id")

    try:
        pid_int = int(pid)
    except Exception:
        return _err("product_id_invalid", "ID de producto inválido.", 400)

    c = _cart()
    c["items"].pop(str(pid_int), None)
    _save_cart(c)

    return _reply({"ok": True, "cart": cart_snapshot()}, status=200, html_redirect_endpoint="cart.cart_view")


@cart_bp.post("/clear")
def cart_clear():
    gate = _csrf_required()
    if gate:
        return gate
    if not _rate_limit_ok("clear"):
        return _err("rate_limited", "Demasiadas acciones. Probá de nuevo en un momento.", 429)

    session.pop(CART_SESSION_KEY, None)
    session.modified = True
    _invalidate_snapshot_cache()

    return _reply({"ok": True, "cart": cart_snapshot()}, status=200, html_redirect_endpoint="cart.cart_view")


__all__ = ["cart_bp", "cart_snapshot", "merge_cart_items"]
