# app/routes/cart_routes.py — SKYLINE CART ULTRA PRO (v4.0 / FINAL / NO-ERROR)
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP
from time import time
from typing import Any, Dict, List, Mapping, Optional, Tuple
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

from app.models import db, Product

try:
    from app.models import Offer  # type: ignore
except Exception:  # pragma: no cover
    Offer = None  # type: ignore


cart_bp = Blueprint("cart", __name__, url_prefix="/cart")
cart_bp.strict_slashes = False

CART_SESSION_KEY = "cart_v4"
CART_SCHEMA_VERSION = 4

MAX_QTY_PER_ITEM = 25
MIN_QTY_PER_ITEM = 1
MAX_DISTINCT_ITEMS = 120

DEFAULT_CURRENCY = "USD"
ALLOWED_CURRENCIES = {"USD", "UYU", "ARS"}

# RL per-session per bucket (windowed)
RL_WINDOW_SEC = 2.0
RL_MAX_ACTIONS = 14
_RL_KEY = "cart_rl_v4"

# CSRF compatible with your app-wide token
CSRF_SESSION_KEY = "csrf_token"

# Snapshot cache per-request
_REQ_CACHE_KEY = "_cart_snapshot_cache_v4"

# Security / cache headers for cart responses
_CACHE_HEADERS = {
    "Cache-Control": "no-store, max-age=0, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
    "Vary": "Accept, Cookie",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
}

# Design tokens (template-friendly). Used by templates and JSON consumers.
CART_UI_TOKENS = {
    "brand": "skyline",
    "radius": 18,
    "shadow": "0 22px 70px rgba(0,0,0,.12)",
    "surface": "rgba(255,255,255,.92)",
    "surface2": "rgba(255,255,255,.78)",
    "stroke": "rgba(15,23,42,.12)",
    "muted": "#64748b",
}


def _now_ts() -> int:
    return int(time())


def _s(v: Any, max_len: int, *, default: str = "") -> str:
    if v is None:
        return default
    s = v if isinstance(v, str) else str(v)
    s = s.replace("\x00", "").replace("\u200b", "").strip()
    s = s.replace("\r", "").replace("\n", "").replace("\t", "")
    if not s:
        return default
    s = " ".join(s.split())
    return s[: max(0, int(max_len))]


def _d(x: Any) -> Decimal:
    try:
        if isinstance(x, Decimal):
            return x
        return Decimal(str(x))
    except Exception:
        return Decimal("0.00")


def _money(x: Any) -> str:
    return str(_d(x).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


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
    if xrw == "xmlhttprequest":
        return True

    try:
        best = request.accept_mimetypes.best_match(["application/json", "text/html"])
        if best == "application/json" and request.accept_mimetypes[best] > request.accept_mimetypes["text/html"]:
            return True
    except Exception:
        pass

    return False


def _endpoint_exists(endpoint: str) -> bool:
    try:
        return endpoint in (current_app.view_functions or {})
    except Exception:
        return False


def _url_for_safe(endpoint: str, fallback_path: str = "/cart", **kwargs: Any) -> str:
    try:
        if _endpoint_exists(endpoint):
            return url_for(endpoint, **kwargs)
    except Exception:
        pass
    return fallback_path


def _no_store_headers(resp: Response) -> Response:
    try:
        for k, v in _CACHE_HEADERS.items():
            resp.headers.setdefault(k, v)
    except Exception:
        pass
    return resp


def _reply(
    payload: Dict[str, Any],
    *,
    status: int = 200,
    html_redirect_endpoint: Optional[str] = None,
    fallback_path: str = "/cart",
    **ep_kwargs: Any,
):
    if _wants_json() or html_redirect_endpoint is None:
        r = jsonify(payload)
        r.status_code = int(status)
        return _no_store_headers(r)
    return redirect(_url_for_safe(html_redirect_endpoint, fallback_path=fallback_path, **ep_kwargs), code=302)


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
    tok = session.get(CSRF_SESSION_KEY)
    return isinstance(tok, str) and len(tok.strip()) >= 16


def _csrf_from_request() -> str:
    h = _s(request.headers.get("X-CSRF-Token") or request.headers.get("X-CSRFToken"), 1024, default="")
    if h:
        return h
    f = _s(request.form.get("csrf_token"), 1024, default="")
    if f:
        return f
    try:
        if request.is_json:
            j = request.get_json(silent=True) or {}
            if isinstance(j, dict):
                return _s(j.get("csrf_token"), 1024, default="")
    except Exception:
        pass
    return ""


def _check_csrf() -> bool:
    # If your app didn't set CSRF token, we do NOT block (same behavior as your v3).
    if not _csrf_enabled():
        return True

    token = _s(session.get(CSRF_SESSION_KEY), 1024, default="")
    got = _csrf_from_request()
    if not token or not got:
        return False

    try:
        import secrets as _secrets

        return _secrets.compare_digest(token, got)
    except Exception:
        return False


def _csrf_required() -> Optional[Any]:
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if not _check_csrf():
            return _err("csrf_invalid", "Token inválido. Recargá la página e intentá de nuevo.", 400)
    return None


def _rate_limit_ok(bucket: str) -> Tuple[bool, int]:
    """
    Window-based RL per session.
    Returns (ok, retry_after_seconds).
    """
    now = float(time())
    try:
        st = session.get(_RL_KEY)
        if not isinstance(st, dict):
            st = {}

        b = st.get(bucket)
        if not isinstance(b, dict):
            b = {}

        win_start = float(b.get("start", now))
        count = int(b.get("count", 0) or 0)

        if (now - win_start) > float(RL_WINDOW_SEC) or (now - win_start) < 0:
            win_start = now
            count = 0

        count += 1
        b = {"start": win_start, "count": count}
        st[bucket] = b

        session[_RL_KEY] = st
        session.modified = True

        if count <= int(RL_MAX_ACTIONS):
            return True, 0

        retry = max(1, int((win_start + float(RL_WINDOW_SEC)) - now))
        return False, retry
    except Exception:
        # Never hard-break cart if sessions behave oddly.
        return True, 0


def _clamp_qty(qty: int) -> int:
    if qty < int(MIN_QTY_PER_ITEM):
        return int(MIN_QTY_PER_ITEM)
    if qty > int(MAX_QTY_PER_ITEM):
        return int(MAX_QTY_PER_ITEM)
    return int(qty)


def _parse_int(value: Any, default: int) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return int(default)


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

    # Migration
    if int(c.get("v") or 0) != int(CART_SCHEMA_VERSION):
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

    meta = c["meta"] if isinstance(c["meta"], dict) else {}
    cur = (_s(meta.get("currency"), 3, default=DEFAULT_CURRENCY).upper() or DEFAULT_CURRENCY)[:3]
    if cur not in ALLOWED_CURRENCIES:
        cur = DEFAULT_CURRENCY
    meta["currency"] = cur
    meta.setdefault("updated_at", _now_ts())
    c["meta"] = meta
    return c


def _save_cart(c: Dict[str, Any]) -> None:
    c.setdefault("meta", {})
    if isinstance(c["meta"], dict):
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
        if media and hasattr(media, "__len__") and len(media) > 0:
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
    c = str(c).strip().upper()[:3] or DEFAULT_CURRENCY
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
            from datetime import datetime as _dt

            now_dt = _dt.utcnow()
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

    if len(items) > int(MAX_DISTINCT_ITEMS):
        # deterministic trim
        keys = list(items.keys())[: int(MAX_DISTINCT_ITEMS)]
        items = {k: items[k] for k in keys}
        c["items"] = items
        _save_cart(c)

    cart_currency = (_s(c.get("meta", {}).get("currency"), 3, default=DEFAULT_CURRENCY).upper() or DEFAULT_CURRENCY)[:3]
    if cart_currency not in ALLOWED_CURRENCIES:
        cart_currency = DEFAULT_CURRENCY
        c.setdefault("meta", {})
        if isinstance(c["meta"], dict):
            c["meta"]["currency"] = cart_currency

    lines: List[CartLine] = []
    subtotal = Decimal("0.00")
    discount_total = Decimal("0.00")
    to_delete: List[str] = []
    mixed_currency = False

    for pid_str, row in list(items.items()):
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

        # normalize stored shape
        items[str(pid)] = {"q": qty, "a": added_at}

    for k in to_delete:
        items.pop(k, None)

    lines.sort(key=lambda x: (int(x.added_at or 0), int(x.product_id)), reverse=True)

    c["items"] = items
    _save_cart(c)

    out: Dict[str, Any] = {
        "schema": CART_SCHEMA_VERSION,
        "items_count": sum(int(ln.qty) for ln in lines),
        "distinct_items": len(lines),
        "currency": cart_currency,
        "lines": [ln.to_dict() for ln in lines],
        "subtotal": _money(subtotal),
        "discount_total": _money(discount_total),
        "total": _money(subtotal),
        "updated_at": int(c.get("meta", {}).get("updated_at") or _now_ts()),
        "has_items": bool(lines),
        "ui": dict(CART_UI_TOKENS),
    }
    if mixed_currency:
        out["warning"] = "mixed_currency_detected"

    try:
        setattr(request, _REQ_CACHE_KEY, out)
    except Exception:
        pass
    return out


def merge_cart_items(into_user_id: int) -> None:
    # hook for future: merge session cart into persisted cart
    _ = into_user_id
    return


def _parse_payload() -> Mapping[str, Any]:
    try:
        if request.is_json:
            j = request.get_json(silent=True)
            if isinstance(j, Mapping):
                return j
    except Exception:
        pass
    try:
        return request.form  # type: ignore[return-value]
    except Exception:
        return {}  # type: ignore[return-value]


def _pid_from_payload(data: Mapping[str, Any]) -> Tuple[Optional[int], Optional[Response]]:
    pid = data.get("product_id") or data.get("id")
    try:
        pid_int = int(str(pid).strip())
        if pid_int <= 0:
            raise ValueError("pid<=0")
        return pid_int, None
    except Exception:
        return None, _err("product_id_invalid", "ID de producto inválido.", 400)


def _qty_from_payload(data: Mapping[str, Any], *, default: int = 1) -> int:
    return _parse_qty(data.get("qty") if isinstance(data, Mapping) else None, default)


@cart_bp.after_request
def _after_cart(resp: Response):
    return _no_store_headers(resp)


@cart_bp.get("/")
def cart_view():
    snap = cart_snapshot()

    for tpl in ("cart/cart.html", "cart.html"):
        try:
            current_app.jinja_env.get_template(tpl)
            r = render_template(tpl, cart=snap, csrf_token=session.get(CSRF_SESSION_KEY), ui=snap.get("ui"))
            # render_template returns str; wrap into Response for headers
            return _no_store_headers(current_app.make_response(r, 200))
        except Exception:
            continue

    return _reply({"ok": True, "cart": snap}, status=200, html_redirect_endpoint=None)


@cart_bp.get("/json")
def cart_json():
    return _reply({"ok": True, "cart": cart_snapshot()}, status=200, html_redirect_endpoint=None)


@cart_bp.get("/count")
def cart_count():
    snap = cart_snapshot()
    return _reply(
        {
            "ok": True,
            "items_count": int(snap.get("items_count") or 0),
            "distinct_items": int(snap.get("distinct_items") or 0),
        },
        status=200,
        html_redirect_endpoint=None,
    )


@cart_bp.get("/checkout")
def cart_checkout_bridge():
    snap = cart_snapshot()
    if not snap.get("has_items"):
        if _wants_json():
            return _reply({"ok": False, "error": {"code": "cart_empty", "message": "El carrito está vacío."}}, status=400)
        return redirect(_url_for_safe("cart.cart_view", fallback_path="/cart"), code=302)

    if _endpoint_exists("checkout.checkout_home"):
        return redirect(url_for("checkout.checkout_home"), code=302)

    for ep in ("shop.checkout", "shop.checkout_home", "main.checkout", "main.checkout_home"):
        if _endpoint_exists(ep):
            return redirect(url_for(ep), code=302)

    return redirect("/checkout/", code=302)


@cart_bp.post("/add")
def cart_add():
    gate = _csrf_required()
    if gate:
        return gate

    ok_rl, retry = _rate_limit_ok("add")
    if not ok_rl:
        r = _err("rate_limited", "Demasiadas acciones. Probá de nuevo en un momento.", 429, details={"retry_after": retry})
        try:
            if hasattr(r, "headers"):
                r.headers["Retry-After"] = str(int(retry))
        except Exception:
            pass
        return r

    data = _parse_payload()
    pid, err_resp = _pid_from_payload(data)
    if err_resp is not None:
        return err_resp
    qty = _qty_from_payload(data, default=1)

    mode = _s(data.get("mode") or "inc", 12, default="inc").lower()
    if mode not in {"inc", "set"}:
        mode = "inc"

    p = _get_product(int(pid))
    if not p:
        return _err("product_not_found", "Producto no encontrado.", 404)

    c = _cart()
    items: Dict[str, Dict[str, Any]] = c["items"] if isinstance(c.get("items"), dict) else {}
    c["items"] = items

    key = str(int(pid))
    cur = items.get(key, {}) if isinstance(items.get(key), dict) else {}
    cur_qty = _parse_qty(cur.get("q", 0), 0)

    new_qty = qty if mode == "set" else _clamp_qty(cur_qty + qty)

    if new_qty <= 0:
        items.pop(key, None)
        _save_cart(c)
        return _reply({"ok": True, "cart": cart_snapshot()}, status=200, html_redirect_endpoint="cart.cart_view")

    ok, msg, allowed = _is_available(p, new_qty)
    if not ok:
        if allowed > 0:
            new_qty = _clamp_qty(allowed)
        else:
            return _err("not_available", msg or "Producto no disponible.", 400)

    added_at = int(cur.get("a") or _now_ts())
    items[key] = {"q": int(new_qty), "a": added_at}
    _save_cart(c)

    return _reply({"ok": True, "cart": cart_snapshot()}, status=200, html_redirect_endpoint="cart.cart_view")


@cart_bp.post("/update")
def cart_update():
    gate = _csrf_required()
    if gate:
        return gate

    ok_rl, retry = _rate_limit_ok("update")
    if not ok_rl:
        r = _err("rate_limited", "Demasiadas acciones. Probá de nuevo en un momento.", 429, details={"retry_after": retry})
        try:
            if hasattr(r, "headers"):
                r.headers["Retry-After"] = str(int(retry))
        except Exception:
            pass
        return r

    data = _parse_payload()

    batch = None
    if isinstance(data, Mapping):
        batch = data.get("items")

    c = _cart()
    items: Dict[str, Dict[str, Any]] = c["items"] if isinstance(c.get("items"), dict) else {}
    c["items"] = items

    def _update_one(pid_any: Any, qty_any: Any) -> Optional[Tuple[str, int, str]]:
        try:
            pid_int = int(str(pid_any).strip())
            if pid_int <= 0:
                raise ValueError("pid<=0")
        except Exception:
            return ("product_id_invalid", 400, "ID inválido.")

        key = str(pid_int)
        if key not in items:
            return ("not_in_cart", 404, "El producto no está en el carrito.")

        qty = _parse_qty(qty_any or 1, 1)

        if qty <= 0:
            items.pop(key, None)
            return None

        p = _get_product(pid_int)
        if not p:
            items.pop(key, None)
            return None

        ok, msg, allowed = _is_available(p, qty)
        if not ok:
            if allowed > 0:
                qty = _clamp_qty(allowed)
            else:
                return ("not_available", 400, msg or "Producto no disponible o sin stock.")

        items[key]["q"] = int(qty)
        items[key].setdefault("a", _now_ts())
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
        pid = data.get("product_id") or data.get("id") if isinstance(data, Mapping) else None
        qty = data.get("qty") if isinstance(data, Mapping) else None
        err = _update_one(pid, qty)
        if err:
            code, status, msg = err
            return _err(code, msg, status)

    _save_cart(c)
    return _reply({"ok": True, "cart": cart_snapshot()}, status=200, html_redirect_endpoint="cart.cart_view")


@cart_bp.post("/remove")
def cart_remove():
    gate = _csrf_required()
    if gate:
        return gate

    ok_rl, retry = _rate_limit_ok("remove")
    if not ok_rl:
        r = _err("rate_limited", "Demasiadas acciones. Probá de nuevo en un momento.", 429, details={"retry_after": retry})
        try:
            if hasattr(r, "headers"):
                r.headers["Retry-After"] = str(int(retry))
        except Exception:
            pass
        return r

    data = _parse_payload()
    pid, err_resp = _pid_from_payload(data)
    if err_resp is not None:
        return err_resp

    c = _cart()
    items = c.get("items")
    if not isinstance(items, dict):
        items = {}
    items.pop(str(int(pid)), None)
    c["items"] = items
    _save_cart(c)

    return _reply({"ok": True, "cart": cart_snapshot()}, status=200, html_redirect_endpoint="cart.cart_view")


@cart_bp.post("/clear")
def cart_clear():
    gate = _csrf_required()
    if gate:
        return gate

    ok_rl, retry = _rate_limit_ok("clear")
    if not ok_rl:
        r = _err("rate_limited", "Demasiadas acciones. Probá de nuevo en un momento.", 429, details={"retry_after": retry})
        try:
            if hasattr(r, "headers"):
                r.headers["Retry-After"] = str(int(retry))
        except Exception:
            pass
        return r

    session.pop(CART_SESSION_KEY, None)
    session.modified = True
    _invalidate_snapshot_cache()

    return _reply({"ok": True, "cart": cart_snapshot()}, status=200, html_redirect_endpoint="cart.cart_view")


__all__ = ["cart_bp", "cart_snapshot", "merge_cart_items", "CART_UI_TOKENS"]
