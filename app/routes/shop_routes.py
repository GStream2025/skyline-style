from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional, Tuple

from flask import Blueprint, current_app, make_response, redirect, render_template, request, session, url_for
from sqlalchemy import asc, desc, or_
from sqlalchemy.orm import selectinload

from app.models import Category, Product, db

shop_bp = Blueprint("shop", __name__, url_prefix="/shop")

AFF_COOKIE_NAME = "sk_aff"
AFF_COOKIE_SUB_NAME = "sk_sub"
AFF_COOKIE_TTL_DAYS = 30

_TRUE = {"1", "true", "yes", "y", "on", "checked"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _safe_str(v: Any, *, max_len: int = 500) -> str:
    if v is None:
        return ""
    s = v.strip() if isinstance(v, str) else str(v).strip()
    return s[:max_len]


def _safe_slug(v: Any, *, max_len: int = 80) -> str:
    raw = _safe_str(v, max_len=max_len).lower().replace(" ", "-")
    out = "".join(ch for ch in raw if ch.isalnum() or ch in {"-", "_", "."})
    return out[:max_len]


def _int_arg(name: str, default: int, *, min_v: int, max_v: int) -> int:
    raw = _safe_str(request.args.get(name), max_len=40)
    try:
        val = int(raw) if raw else int(default)
    except Exception:
        val = int(default)
    return max(min_v, min(max_v, val))


def _decimal_arg(name: str) -> Optional[Decimal]:
    raw = _safe_str(request.args.get(name), max_len=40)
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
    xff = _safe_str(request.headers.get("X-Forwarded-For"), max_len=300)
    ip = (xff.split(",")[0].strip() if xff else "") or _safe_str(request.remote_addr, max_len=120) or "unknown"
    return ip[:80]


def _safe_like(value: str) -> str:
    v = _safe_str(value, max_len=80).replace("%", "").replace("_", "").strip()
    return f"%{v}%" if v else ""


def _safe_sort(raw: Any) -> str:
    v = _safe_slug(raw, max_len=24)
    allowed = {"new", "updated", "price_asc", "price_desc"}
    return v if v in allowed else "new"


def _safe_per(default: int = 48) -> int:
    per = _int_arg("per", default, min_v=12, max_v=120)
    presets = (12, 18, 24, 36, 48, 60, 72, 96, 120)
    return int(min(presets, key=lambda p: abs(p - per)))


def _get_aff_params_from_request() -> Tuple[Optional[str], Optional[str]]:
    aff = _safe_str(request.args.get("aff"), max_len=120) or None
    sub = _safe_str(request.args.get("sub"), max_len=160) or None

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
        aff = _safe_str(request.cookies.get(AFF_COOKIE_NAME), max_len=120) or None
    if not sub:
        sub = _safe_str(request.cookies.get(AFF_COOKIE_SUB_NAME), max_len=160) or None

    if isinstance(aff, str):
        aff = aff[:80] or None
    else:
        aff = None

    if isinstance(sub, str):
        sub = sub[:120] or None
    else:
        sub = None

    return aff, sub


def _capture_affiliation_for_response(resp):
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

    try:
        click = AffiliateClick(
            aff_code=aff[:80],
            sub_code=(sub[:120] if sub else None),
            product_id=int(product_id),
            ip=_get_client_ip(),
            user_agent=_safe_str(request.headers.get("User-Agent"), max_len=300) or None,
            referrer=_safe_str(request.referrer, max_len=500) or None,
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
    available = _safe_str(request.args.get("available"), max_len=20).lower()
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


def _safe_count(query) -> int:
    try:
        return int(query.order_by(None).count())
    except Exception:
        try:
            return int(query.count())
        except Exception:
            return 0


def _resp_no_store(resp):
    resp.headers.setdefault("Cache-Control", "no-store")
    resp.headers.setdefault("Pragma", "no-cache")
    resp.headers.setdefault("Vary", "Cookie")
    return resp


def _resp_public_cache(resp, seconds: int = 30):
    sec = max(0, int(seconds))
    if sec <= 0:
        return _resp_no_store(resp)
    resp.headers["Cache-Control"] = f"public, max-age={sec}, stale-while-revalidate=30"
    resp.headers.setdefault("Vary", "Cookie")
    return resp


def _render_404():
    try:
        vf = getattr(current_app, "view_functions", {}) or {}
        handler = vf.get("main.not_found")
        if handler:
            return handler(None)  # type: ignore[misc]
    except Exception:
        pass
    try:
        return render_template("error.html", error_code=404, error_title="No encontrado", error_message="La página no existe."), 404
    except Exception:
        try:
            return render_template("404.html"), 404
        except Exception:
            return ("Not Found", 404)


@shop_bp.get("/shop")
def _compat_shop_redirect():
    return redirect(url_for("shop.shop", **request.args.to_dict(flat=True)), code=301)


@shop_bp.get("/shop/product/<path:slug>")
def _compat_product_redirect(slug: str):
    return redirect(url_for("shop.product_detail", slug=slug, **request.args.to_dict(flat=True)), code=301)


@shop_bp.get("/")
def shop():
    q = _safe_str(request.args.get("q"), max_len=120)
    cat = _safe_slug(request.args.get("categoria") or request.args.get("cat"), max_len=80)
    sort = _safe_sort(request.args.get("sort") or "new")

    minp = _decimal_arg("min")
    maxp = _decimal_arg("max")

    page = _int_arg("page", 1, min_v=1, max_v=9999)
    per = _safe_per(48)

    if minp is not None and maxp is not None and minp > maxp:
        minp, maxp = maxp, minp

    query = Product.query

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
        query = query.options(*opts)

    query = _apply_active_filter(query)
    query = _apply_available_filter(query)

    if cat:
        try:
            slug_path_attr = getattr(Category, "slug_path", None)
            if slug_path_attr is not None:
                query = query.join(Category, isouter=True).filter(or_(Category.slug == cat, slug_path_attr == cat))
            else:
                query = query.join(Category, isouter=True).filter(Category.slug == cat)
        except Exception:
            for attr in ("category_slug", "category", "categoria", "cat"):
                if hasattr(Product, attr):
                    try:
                        query = query.filter(getattr(Product, attr) == cat)
                        break
                    except Exception:
                        pass

    if q:
        like = _safe_like(q)
        if like:
            conds = []
            for field in ("title", "slug", "short_description", "description_html", "description"):
                if hasattr(Product, field):
                    try:
                        conds.append(getattr(Product, field).ilike(like))
                    except Exception:
                        pass
            if conds:
                query = query.filter(or_(*conds))

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

    total = _safe_count(query)
    offset = (page - 1) * per

    if offset >= total and total > 0:
        last_page = max((total + per - 1) // per, 1)
        return redirect(url_for("shop.shop", **{**request.args.to_dict(flat=True), "page": last_page}), code=302)

    try:
        products: List[Product] = query.offset(offset).limit(per).all()
    except Exception:
        products = []

    grouped_products: Dict[str, List[Product]] = {}
    for p in products:
        grouped_products.setdefault(_product_cat_slug(p), []).append(p)

    categories: List[Category] = []
    try:
        categories = Category.query.order_by(asc(Category.name)).all()
    except Exception:
        categories = []

    aff_code, aff_sub = _get_aff_attribution()

    html = render_template(
        "shop.html",
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
        has_next=(offset + per) < total,
        has_prev=page > 1,
        next_page=(page + 1) if (offset + per) < total else None,
        prev_page=(page - 1) if page > 1 else None,
        aff_code=aff_code,
        aff_sub=aff_sub,
    )

    resp = make_response(html)
    resp = _capture_affiliation_for_response(resp)
    return _resp_public_cache(resp, seconds=int(current_app.config.get("SHOP_CACHE_TTL", 30) or 30))


@shop_bp.get("/product/<path:slug>")
def product_detail(slug: str):
    slug = _safe_str(slug, max_len=220)
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

        p = q.filter(Product.slug == slug).first()
    except Exception:
        p = None

    if not p or (getattr(p, "status", "") or "").lower() != "active":
        return _render_404()

    _track_aff_click_if_any(int(getattr(p, "id", 0) or 0))

    aff_code, aff_sub = _get_aff_attribution()
    html = render_template("product_detail.html", product=p, aff_code=aff_code, aff_sub=aff_sub)

    resp = make_response(html)
    resp = _capture_affiliation_for_response(resp)
    return _resp_no_store(resp)


__all__ = ["shop_bp"]
