# app/routes/shop_routes.py — SKYLINE SHOP ULTRA PRO (v4.0 / FINAL / NO-ERROR / NO-BREAK)
from __future__ import annotations

import hashlib
import os
import time
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse

from flask import (
    Blueprint,
    Response,
    current_app,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy import asc, desc, func, or_
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import selectinload

from app.models import Category, Product, db

shop_bp = Blueprint("shop", __name__, url_prefix="/shop")
shop_bp.strict_slashes = False

# Legacy/compat (URLs viejas sin /shop prefix)
shop_compat_bp = Blueprint("shop_compat", __name__)
shop_compat_bp.strict_slashes = False

AFF_COOKIE_NAME = "sk_aff"
AFF_COOKIE_SUB_NAME = "sk_sub"
AFF_COOKIE_TTL_DAYS = 30

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off", "unchecked"}

DEFAULT_CURRENCY = (os.getenv("DEFAULT_CURRENCY") or "USD").strip().upper()[:3] or "USD"

# Design tokens (para templates: look premium sin tocar HTML todavía)
SHOP_UI_TOKENS = {
    "brand": "skyline",
    "radius": 18,
    "shadow": "0 22px 70px rgba(0,0,0,.10)",
    "surface": "rgba(255,255,255,.92)",
    "surface2": "rgba(255,255,255,.78)",
    "stroke": "rgba(15,23,42,.12)",
    "muted": "#64748b",
    "ok": "#16a34a",
    "warn": "#f59e0b",
    "bad": "#ef4444",
}

# Cache headers
_NO_STORE_HEADERS = {
    "Cache-Control": "no-store, max-age=0, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
    "Vary": "Accept, Cookie",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}

_PUBLIC_CACHE_FMT = "public, max-age={sec}, stale-while-revalidate=30"
_MAX_PER = 120
_MIN_PER = 12


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _s(v: Any, *, max_len: int = 500, default: str = "") -> str:
    if v is None:
        return default
    s = v.strip() if isinstance(v, str) else str(v).strip()
    s = s.replace("\x00", "").replace("\u200b", "").replace("\r", "").replace("\n", "").replace("\t", "")
    if not s:
        return default
    s = " ".join(s.split())
    return s[: max(0, int(max_len))]


def _safe_slug(v: Any, *, max_len: int = 80) -> str:
    raw = _s(v, max_len=max_len).lower().replace(" ", "-")
    out = "".join(ch for ch in raw if ch.isalnum() or ch in {"-", "_"})
    out = out.strip("-_")
    return out[:max_len]


def _int_arg(name: str, default: int, *, min_v: int, max_v: int) -> int:
    raw = _s(request.args.get(name), max_len=40)
    try:
        val = int(raw) if raw else int(default)
    except Exception:
        val = int(default)
    return max(int(min_v), min(int(max_v), int(val)))


def _decimal_arg(name: str) -> Optional[Decimal]:
    raw = _s(request.args.get(name), max_len=40)
    if not raw:
        return None
    raw = raw.replace(",", ".")
    try:
        d = Decimal(raw)
        if d.is_nan() or d.is_infinite():
            return None
        return d
    except (InvalidOperation, ValueError):
        return None


def _get_client_ip() -> str:
    xff = _s(request.headers.get("X-Forwarded-For"), max_len=300)
    ip = (xff.split(",")[0].strip() if xff else "") or _s(request.remote_addr, max_len=120) or "unknown"
    return ip[:80]


def _escape_like(value: str) -> str:
    v = _s(value, max_len=80).strip()
    if not v:
        return ""
    return v.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _safe_like(value: str) -> str:
    v = _escape_like(value)
    return f"%{v}%" if v else ""


def _safe_sort(raw: Any) -> str:
    v = _safe_slug(raw, max_len=24)
    allowed = {"new", "updated", "price_asc", "price_desc"}
    return v if v in allowed else "new"


def _safe_per(default: int = 48) -> int:
    per = _int_arg("per", default, min_v=_MIN_PER, max_v=_MAX_PER)
    presets = (12, 18, 24, 36, 48, 60, 72, 96, 120)
    return int(min(presets, key=lambda p: abs(p - per)))


def _qs(override: Dict[str, Any]) -> str:
    base = request.args.to_dict(flat=True)
    for k, v in override.items():
        if v is None or v == "":
            base.pop(k, None)
        else:
            base[k] = str(v)
    return urlencode(base)


def _get_aff_params_from_request() -> Tuple[Optional[str], Optional[str]]:
    aff = _s(request.args.get("aff"), max_len=120) or None
    sub = _s(request.args.get("sub"), max_len=160) or None

    if aff:
        a = aff.lower().replace(" ", "-")[:80]
        a = "".join(ch for ch in a if ch.isalnum() or ch in {"-", "_"})[:80]
        aff = a or None
    if sub:
        sub = sub[:120] or None
    return aff, sub


def _get_aff_attribution() -> Tuple[Optional[str], Optional[str]]:
    aff = session.get("aff_code")
    sub = session.get("aff_sub")

    if not aff:
        aff = _s(request.cookies.get(AFF_COOKIE_NAME), max_len=120) or None
    if not sub:
        sub = _s(request.cookies.get(AFF_COOKIE_SUB_NAME), max_len=160) or None

    aff = (aff[:80] if isinstance(aff, str) else "") or None
    sub = (sub[:120] if isinstance(sub, str) else "") or None
    return aff, sub


def _capture_affiliation_for_response(resp: Response) -> Response:
    aff, sub = _get_aff_params_from_request()
    if not aff:
        return resp

    session["aff_code"] = aff
    if sub:
        session["aff_sub"] = sub
    session.modified = True

    try:
        max_age = int(AFF_COOKIE_TTL_DAYS * 24 * 3600)
        secure = bool(current_app.config.get("SESSION_COOKIE_SECURE", False))
        samesite = current_app.config.get("SESSION_COOKIE_SAMESITE", "Lax")
        domain = current_app.config.get("SESSION_COOKIE_DOMAIN", None)

        resp.set_cookie(
            AFF_COOKIE_NAME,
            aff,
            max_age=max_age,
            httponly=True,
            secure=secure,
            samesite=samesite,
            path="/",
            domain=domain,
        )
        if sub:
            resp.set_cookie(
                AFF_COOKIE_SUB_NAME,
                sub,
                max_age=max_age,
                httponly=True,
                secure=secure,
                samesite=samesite,
                path="/",
                domain=domain,
            )
    except Exception:
        pass

    return resp


def _track_aff_click_if_any(product_id: int) -> None:
    aff, sub = _get_aff_attribution()
    if not aff or not product_id:
        return

    try:
        from app.models import AffiliateClick  # type: ignore
    except Exception:
        AffiliateClick = None  # type: ignore

    if AffiliateClick is None:
        return

    # micro-rate-limit para no spamear clicks por refresh
    try:
        k = f"aff_click:{int(product_id)}"
        now = int(time.time())
        last = int(session.get(k) or 0)
        if now - last < 3:
            return
        session[k] = now
        session.modified = True
    except Exception:
        pass

    try:
        click = AffiliateClick(
            aff_code=aff[:80],
            sub_code=(sub[:120] if sub else None),
            product_id=int(product_id),
            ip=_get_client_ip(),
            user_agent=_s(request.headers.get("User-Agent"), max_len=300) or None,
            referrer=_s(request.referrer, max_len=500) or None,
            meta={"path": request.path, "ts": utcnow().isoformat()},
        )
        db.session.add(click)
        db.session.commit()
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass


def _product_cat_slug(p: Product) -> str:
    try:
        cat = getattr(p, "category", None)
        if cat is not None and getattr(cat, "slug", None):
            return _safe_slug(cat.slug)
    except Exception:
        pass

    for attr in ("category_slug", "category", "categoria", "cat"):
        v = getattr(p, attr, None)
        if isinstance(v, str) and v.strip():
            return _safe_slug(v)
    return "otros"


def _apply_active_filter(query):
    try:
        if hasattr(Product, "status"):
            return query.filter(Product.status == "active")
    except Exception:
        pass
    try:
        if hasattr(Product, "is_active"):
            return query.filter(getattr(Product, "is_active").is_(True))
    except Exception:
        pass
    return query


def _apply_available_filter(query):
    available = _s(request.args.get("available"), max_len=20).lower()
    if available not in _TRUE:
        return query

    try:
        if hasattr(Product, "stock_mode") and hasattr(Product, "stock_qty"):
            return query.filter(
                or_(
                    Product.stock_mode.in_(["unlimited", "external"]),
                    Product.stock_qty > 0,
                )
            )
    except Exception:
        pass

    try:
        if hasattr(Product, "stock_qty"):
            return query.filter(Product.stock_qty > 0)
    except Exception:
        pass

    return query


def _resp_no_store(resp: Response) -> Response:
    try:
        for k, v in _NO_STORE_HEADERS.items():
            resp.headers.setdefault(k, v)
        resp.headers.setdefault("X-Served-By", "skyline")
    except Exception:
        pass
    return resp


def _resp_public_cache(resp: Response, seconds: int = 30) -> Response:
    sec = max(0, int(seconds))
    if sec <= 0:
        return _resp_no_store(resp)
    try:
        resp.headers["Cache-Control"] = _PUBLIC_CACHE_FMT.format(sec=sec)
        resp.headers.setdefault("Vary", "Accept")
        resp.headers.setdefault("X-Served-By", "skyline")
    except Exception:
        pass
    return resp


def _is_personalized() -> bool:
    aff_q, _ = _get_aff_params_from_request()
    if aff_q:
        return True
    aff_s, _ = _get_aff_attribution()
    return bool(aff_s)


def _template_exists(name: str) -> bool:
    try:
        current_app.jinja_env.get_template(name)
        return True
    except Exception:
        return False


def _etag_for_shop_listing(args: Dict[str, Any], *, total: int, page: int, per: int) -> str:
    raw = f"{sorted(args.items())}|t={total}|p={page}|per={per}|v=4"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _maybe_304(etag: str) -> Optional[Response]:
    inm = _s(request.headers.get("If-None-Match"), max_len=200)
    if inm and inm.strip('"') == etag:
        r = make_response("", 304)
        r.headers["ETag"] = f'"{etag}"'
        return r
    return None


def _render_404():
    try:
        vf = getattr(current_app, "view_functions", {}) or {}
        handler = vf.get("main.not_found")
        if handler:
            return handler(None)  # type: ignore[misc]
    except Exception:
        pass
    try:
        if _template_exists("error.html"):
            return render_template(
                "error.html",
                error_code=404,
                error_title="No encontrado",
                error_message="La página no existe.",
                ui=dict(SHOP_UI_TOKENS),
            ), 404
        if _template_exists("404.html"):
            return render_template("404.html", ui=dict(SHOP_UI_TOKENS)), 404
    except Exception:
        pass
    return ("Not Found", 404)


# -----------------------
# Compat URLs (legacy)
# -----------------------
@shop_compat_bp.get("/shop")
def compat_shop_redirect():
    qs = request.args.to_dict(flat=True)
    return redirect(url_for("shop.shop", **qs), code=301)


@shop_compat_bp.get("/shop/product/<path:slug>")
def compat_product_redirect(slug: str):
    qs = request.args.to_dict(flat=True)
    return redirect(url_for("shop.product_detail", slug=slug, **qs), code=301)


# -----------------------
# Routes oficiales
# -----------------------
@shop_bp.get("/")
def shop():
    q = _s(request.args.get("q"), max_len=120)
    cat = _safe_slug(request.args.get("categoria") or request.args.get("cat"), max_len=80)
    sort = _safe_sort(request.args.get("sort") or "new")

    minp = _decimal_arg("min")
    maxp = _decimal_arg("max")

    page = _int_arg("page", 1, min_v=1, max_v=9999)
    per = _safe_per(48)

    if minp is not None and maxp is not None and minp > maxp:
        minp, maxp = maxp, minp

    # Base query (compat Flask-SQLAlchemy y SQLAlchemy puro)
    try:
        query = Product.query
    except Exception:
        query = db.session.query(Product)

    opts = []
    if hasattr(Product, "category"):
        try:
            opts.append(selectinload(Product.category))
        except Exception:
            pass
    if hasattr(Product, "media"):
        try:
            opts.append(selectinload(Product.media))
        except Exception:
            pass
    if opts:
        try:
            query = query.options(*opts)
        except Exception:
            pass

    query = _apply_active_filter(query)
    query = _apply_available_filter(query)

    # Category filter (robusto a distintos esquemas)
    if cat:
        try:
            query = query.join(Category, isouter=True)
            if hasattr(Category, "slug_path"):
                query = query.filter(or_(Category.slug == cat, Category.slug_path == cat))
            else:
                query = query.filter(Category.slug == cat)
        except Exception:
            # fallback: product fields
            for attr in ("category_slug", "category", "categoria", "cat"):
                if hasattr(Product, attr):
                    try:
                        query = query.filter(getattr(Product, attr) == cat)
                        break
                    except Exception:
                        pass

    # Search filter
    if q:
        like = _safe_like(q)
        if like:
            conds = []
            for field in ("title", "slug", "short_description", "description_html", "description"):
                if hasattr(Product, field):
                    col = getattr(Product, field)
                    try:
                        conds.append(col.ilike(like, escape="\\"))
                    except Exception:
                        try:
                            conds.append(col.ilike(like))
                        except Exception:
                            pass
            if conds:
                query = query.filter(or_(*conds))

    # Price filter
    if hasattr(Product, "price"):
        try:
            if minp is not None:
                query = query.filter(Product.price >= minp)
            if maxp is not None:
                query = query.filter(Product.price <= maxp)
        except Exception:
            pass

    created_field = getattr(Product, "created_at", None)
    updated_field = getattr(Product, "updated_at", None)
    price_field = getattr(Product, "price", None)

    # Sort
    try:
        if sort == "price_asc" and price_field is not None:
            query = query.order_by(asc(price_field), desc(Product.id))
        elif sort == "price_desc" and price_field is not None:
            query = query.order_by(desc(price_field), desc(Product.id))
        elif sort == "updated" and updated_field is not None:
            query = query.order_by(desc(updated_field), desc(Product.id))
        elif sort == "new" and created_field is not None:
            query = query.order_by(desc(created_field), desc(Product.id))
        else:
            if updated_field is not None:
                query = query.order_by(desc(updated_field), desc(Product.id))
            elif created_field is not None:
                query = query.order_by(desc(created_field), desc(Product.id))
            else:
                query = query.order_by(desc(Product.id))
    except Exception:
        query = query.order_by(desc(Product.id))

    # Total count (safe) — y fallback a "no total" si falla
    total = 0
    try:
        total = int(query.order_by(None).count())
    except Exception:
        try:
            total = int(query.count())
        except Exception:
            total = 0

    offset = (page - 1) * per

    # Si pidieron page muy grande, llevamos a la última
    if offset >= total and total > 0:
        last_page = max((total + per - 1) // per, 1)
        merged = {**request.args.to_dict(flat=True), "page": last_page}
        return redirect(url_for("shop.shop", **merged), code=302)

    products: List[Product] = []
    try:
        products = query.offset(offset).limit(per).all()
    except SQLAlchemyError:
        try:
            db.session.rollback()
        except Exception:
            pass
        products = []
    except Exception:
        products = []

    grouped_products: Dict[str, List[Product]] = {}
    for p in products:
        grouped_products.setdefault(_product_cat_slug(p), []).append(p)

    categories: List[Category] = []
    try:
        try:
            categories = Category.query.order_by(asc(Category.name)).all()  # type: ignore[attr-defined]
        except Exception:
            categories = db.session.query(Category).order_by(asc(Category.name)).all()
    except Exception:
        categories = []

    aff_code, aff_sub = _get_aff_attribution()

    # URLs next/prev consistentes
    has_next = (offset + per) < total
    has_prev = page > 1
    next_url = f"/shop/?{_qs({'page': page + 1})}" if has_next else None
    prev_url = f"/shop/?{_qs({'page': page - 1})}" if has_prev else None

    ctx = dict(
        products=products,
        grouped_products=grouped_products,
        categories=categories,
        q=q,
        categoria=cat,
        sort=sort,
        min=str(minp) if minp is not None else "",
        max=str(maxp) if maxp is not None else "",
        page=page,
        per=per,
        total=total,
        has_next=has_next,
        has_prev=has_prev,
        next_page=(page + 1) if has_next else None,
        prev_page=(page - 1) if has_prev else None,
        next_url=next_url,
        prev_url=prev_url,
        aff_code=aff_code,
        aff_sub=aff_sub,
        ui=dict(SHOP_UI_TOKENS),
        currency=DEFAULT_CURRENCY,
    )

    # Render template con fallback
    tpl = "shop.html" if _template_exists("shop.html") else "shop/shop.html"
    html = render_template(tpl, **ctx)

    resp = make_response(html)
    resp = _capture_affiliation_for_response(resp)

    # ETag (solo para listados “cacheables”)
    ttl = int(current_app.config.get("SHOP_CACHE_TTL", 30) or 30)
    is_filtered = bool(q or cat or (minp is not None) or (maxp is not None))
    if _is_personalized() or is_filtered:
        return _resp_no_store(resp)

    try:
        etag = _etag_for_shop_listing(request.args.to_dict(flat=True), total=total, page=page, per=per)
        maybe = _maybe_304(etag)
        if maybe:
            maybe.headers["ETag"] = f'"{etag}"'
            return _resp_public_cache(maybe, seconds=ttl)
        resp.headers["ETag"] = f'"{etag}"'
    except Exception:
        pass

    return _resp_public_cache(resp, seconds=ttl)


@shop_bp.get("/product/<path:slug>")
def product_detail(slug: str):
    slug = _s(slug, max_len=220)
    if not slug:
        return _render_404()

    p: Optional[Product] = None
    try:
        q = db.session.query(Product)

        if hasattr(Product, "category"):
            try:
                q = q.options(selectinload(Product.category))
            except Exception:
                pass
        if hasattr(Product, "media"):
            try:
                q = q.options(selectinload(Product.media))
            except Exception:
                pass

        q = _apply_active_filter(q)
        p = q.filter(Product.slug == slug).first()
    except SQLAlchemyError:
        try:
            db.session.rollback()
        except Exception:
            pass
        p = None
    except Exception:
        p = None

    if not p:
        return _render_404()

    _track_aff_click_if_any(int(getattr(p, "id", 0) or 0))

    aff_code, aff_sub = _get_aff_attribution()

    tpl = "product_detail.html"
    if not _template_exists("product_detail.html") and _template_exists("shop/product_detail.html"):
        tpl = "shop/product_detail.html"

    html = render_template(tpl, product=p, aff_code=aff_code, aff_sub=aff_sub, ui=dict(SHOP_UI_TOKENS))
    resp = make_response(html)
    resp = _capture_affiliation_for_response(resp)

    # Product pages: no-store (precio/stock/affiliate)
    return _resp_no_store(resp)


__all__ = ["shop_bp", "shop_compat_bp", "SHOP_UI_TOKENS"]
