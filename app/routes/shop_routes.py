# app/routes/shop_routes.py — Skyline Store (ULTRA PRO++ / NO BREAK / FAIL-SAFE)
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Dict, List, Optional, Tuple

from flask import (
    Blueprint,
    render_template,
    request,
    url_for,
    session,
    current_app,
    make_response,
    redirect,
)
from sqlalchemy import asc, desc, or_
from sqlalchemy.orm import selectinload

from app.models import db, Product, Category  # ✅ modelos desde el HUB

shop_bp = Blueprint("shop", __name__)

# ============================================================
# Affiliates / Attribution (Temu-like)
# ============================================================

AFF_COOKIE_NAME = "sk_aff"
AFF_COOKIE_SUB_NAME = "sk_sub"
AFF_COOKIE_TTL_DAYS = 30  # ventana de atribución

_TRUE = {"1", "true", "yes", "y", "on", "checked"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _safe_str(s: Optional[str]) -> str:
    return (s or "").strip()


def _safe_slug(s: Optional[str]) -> str:
    return _safe_str(s).lower()


def _int_arg(name: str, default: int, *, min_v: int, max_v: int) -> int:
    try:
        v = int(_safe_str(request.args.get(name)) or default)
    except Exception:
        v = default
    if v < min_v:
        v = min_v
    if v > max_v:
        v = max_v
    return v


def _decimal_arg(name: str) -> Optional[Decimal]:
    raw = _safe_str(request.args.get(name))
    if not raw:
        return None
    try:
        return Decimal(raw)
    except (InvalidOperation, ValueError):
        return None


def _get_client_ip() -> str:
    # ProxyFix ya te acomoda X-Forwarded-For si lo usás en create_app
    ip = (
        (request.headers.get("X-Forwarded-For", "") or request.remote_addr or "unknown")
        .split(",")[0]
        .strip()
    )
    return ip[:80]


def _get_aff_params_from_request() -> Tuple[Optional[str], Optional[str]]:
    aff = _safe_str(request.args.get("aff")) or None
    sub = _safe_str(request.args.get("sub")) or None

    # normalización suave
    if aff:
        aff = aff.lower().replace(" ", "-")[:80]
        aff = "".join(ch for ch in aff if ch.isalnum() or ch in {"-", "_"})[:80] or None
    if sub:
        sub = sub[:120] or None

    return aff, sub


def _get_aff_attribution() -> Tuple[Optional[str], Optional[str]]:
    """
    Fuente de verdad:
    1) session (si ya lo capturamos)
    2) cookies
    """
    aff = session.get("aff_code")
    sub = session.get("aff_sub")

    if not aff:
        aff = _safe_str(request.cookies.get(AFF_COOKIE_NAME)) or None
    if not sub:
        sub = _safe_str(request.cookies.get(AFF_COOKIE_SUB_NAME)) or None

    return (aff[:80] if aff else None), (sub[:120] if sub else None)


def _capture_affiliation_for_response(resp):
    """
    Si llega ?aff=... lo guardamos en session + cookie (persistente).
    """
    aff, sub = _get_aff_params_from_request()
    if not aff:
        return resp

    # session (para backend/checkout)
    session["aff_code"] = aff
    if sub:
        session["aff_sub"] = sub

    # cookie (atribución persistente)
    try:
        max_age = int(AFF_COOKIE_TTL_DAYS * 24 * 3600)
        secure = bool(current_app.config.get("SESSION_COOKIE_SECURE", False))
        samesite = current_app.config.get("SESSION_COOKIE_SAMESITE", "Lax")

        resp.set_cookie(
            AFF_COOKIE_NAME,
            aff,
            max_age=max_age,
            httponly=True,
            secure=secure,
            samesite=samesite,
            path="/",
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
            )
    except Exception:
        # no rompe jamás por cookies
        pass

    return resp


def _track_aff_click_if_any(product_id: int) -> None:
    """
    Trackea click afiliado si existe AffiliateClick model (no rompe si no existe).
    Solo registra si hay aff_code vigente.
    """
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
            user_agent=_safe_str(request.headers.get("User-Agent"))[:300] or None,
            referrer=_safe_str(request.referrer)[:500] or None,
            meta={"path": request.path, "ts": utcnow().isoformat()},
        )
        db.session.add(click)
        db.session.commit()
    except Exception:
        db.session.rollback()


def _product_cat_slug(p: Product) -> str:
    """
    Devuelve slug de categoría del producto.
    1) relación p.category.slug
    2) campos string (category_slug/category/categoria/cat)
    3) fallback: 'otros'
    """
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
    """
    Filtro robusto de productos activos.
    En tu modelo PRO: status = draft|active|hidden
    """
    try:
        if hasattr(Product, "status"):
            return query.filter(Product.status == "active")
    except Exception:
        pass
    # fallback
    try:
        if hasattr(Product, "is_active"):
            return query.filter(getattr(Product, "is_active").is_(True))
    except Exception:
        pass
    return query


def _apply_available_filter(query):
    """
    available=1 -> solo disponibles:
    - stock_mode unlimited/external -> disponible
    - stock_mode finite -> stock_qty > 0
    """
    available = _safe_str(request.args.get("available"))
    if available.lower() not in _TRUE:
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
        return int(query.count())
    except Exception:
        return 0


def _safe_like(value: str) -> str:
    # evita búsquedas raras con %%%%
    v = value.replace("%", "").replace("_", "").strip()
    return f"%{v}%" if v else ""


def _resp_no_store(resp):
    resp.headers.setdefault("Cache-Control", "no-store")
    resp.headers.setdefault("Pragma", "no-cache")
    return resp


def _resp_public_cache(resp, seconds: int = 60):
    resp.headers["Cache-Control"] = f"public, max-age={max(0, int(seconds))}"
    return resp


def _render_404():
    """
    404 consistente:
    - si main.not_found existe, lo usamos (usa tu error.html)
    - si no, fallback 404.html / texto
    """
    try:
        vf = getattr(current_app, "view_functions", {}) or {}
        if "main.not_found" in vf:
            return vf["main.not_found"](None)  # type: ignore[misc]
    except Exception:
        pass

    try:
        return render_template("404.html"), 404
    except Exception:
        return ("Not Found", 404)


# ============================================================
# Routes
# ============================================================

# ❌ ELIMINADO: @shop_bp.get("/") (evita duplicado con main.home "/")
# Si querés que "/" vaya a la tienda, hacelo en main_routes.py con redirect a shop.shop.


@shop_bp.get("/shop")
def shop():
    # -------------------------
    # Params
    # -------------------------
    q = _safe_str(request.args.get("q"))
    cat = _safe_slug(request.args.get("categoria") or request.args.get("cat"))
    sort = _safe_slug(request.args.get("sort") or "new")

    minp = _decimal_arg("min")
    maxp = _decimal_arg("max")

    page = _int_arg("page", 1, min_v=1, max_v=9999)
    per = _int_arg("per", 48, min_v=12, max_v=120)

    # -------------------------
    # Base query + performance
    # -------------------------
    query = Product.query

    opts = []
    try:
        if hasattr(Product, "category"):
            opts.append(selectinload(Product.category))
    except Exception:
        pass
    try:
        if hasattr(Product, "media"):
            opts.append(selectinload(Product.media))
    except Exception:
        pass
    if opts:
        query = query.options(*opts)

    query = _apply_active_filter(query)
    query = _apply_available_filter(query)

    # -------------------------
    # Category filter (slug or slug_path)
    # -------------------------
    if cat:
        try:
            # join seguro (si Category existe)
            query = query.join(Category, isouter=True).filter(
                or_(
                    Category.slug == cat,
                    getattr(Category, "slug_path", Category.slug) == cat,
                )
            )
        except Exception:
            # fallback por campo string
            for attr in ("category_slug", "category", "categoria", "cat"):
                if hasattr(Product, attr):
                    try:
                        query = query.filter(getattr(Product, attr) == cat)
                        break
                    except Exception:
                        pass

    # -------------------------
    # Search
    # -------------------------
    if q:
        like = _safe_like(q)
        if like:
            conds = []
            for field in ("title", "slug", "short_description", "description_html"):
                if hasattr(Product, field):
                    try:
                        conds.append(getattr(Product, field).ilike(like))
                    except Exception:
                        pass
            if conds:
                query = query.filter(or_(*conds))

    # -------------------------
    # Price range
    # -------------------------
    if hasattr(Product, "price"):
        try:
            if minp is not None:
                query = query.filter(Product.price >= minp)
            if maxp is not None:
                query = query.filter(Product.price <= maxp)
        except Exception:
            pass

    # -------------------------
    # Sorting
    # -------------------------
    created_field = getattr(Product, "created_at", None)
    price_field = getattr(Product, "price", None)
    updated_field = getattr(Product, "updated_at", None)

    try:
        if sort == "price_asc" and price_field is not None:
            query = query.order_by(asc(price_field))
        elif sort == "price_desc" and price_field is not None:
            query = query.order_by(desc(price_field))
        elif sort == "updated" and updated_field is not None:
            query = query.order_by(desc(updated_field))
        elif sort == "new" and created_field is not None:
            query = query.order_by(desc(created_field))
        else:
            if updated_field is not None:
                query = query.order_by(desc(updated_field))
            elif created_field is not None:
                query = query.order_by(desc(created_field))
            else:
                query = query.order_by(desc(Product.id))
    except Exception:
        query = query.order_by(desc(Product.id))

    # -------------------------
    # Pagination
    # -------------------------
    total = _safe_count(query)
    offset = (page - 1) * per

    try:
        products: List[Product] = query.offset(offset).limit(per).all()
    except Exception:
        products = []

    # grouped_products para tu template PRO
    grouped_products: Dict[str, List[Product]] = {}
    for p in products:
        slug = _product_cat_slug(p)
        grouped_products.setdefault(slug, []).append(p)

    # Categories para UI
    categories: List[Category] = []
    try:
        categories = Category.query.order_by(asc(Category.name)).all()
    except Exception:
        categories = []

    # Affiliate context (para links/checkout)
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
        aff_code=aff_code,
        aff_sub=aff_sub,
    )

    resp = make_response(html)
    resp = _capture_affiliation_for_response(resp)
    # cache corto: listado cambia seguido, pero ayuda rendimiento
    return _resp_public_cache(resp, seconds=30)


@shop_bp.get("/shop/product/<path:slug>")
def product_detail(slug: str):
    """
    Página de producto.
    - captura aff/sub si vienen
    - trackea click afiliado si hay
    """
    slug = _safe_str(slug)

    p: Optional[Product] = None
    try:
        q = db.session.query(Product)

        # perf: carga relaciones si existen
        try:
            if hasattr(Product, "category"):
                q = q.options(selectinload(Product.category))
        except Exception:
            pass
        try:
            if hasattr(Product, "media"):
                q = q.options(selectinload(Product.media))
        except Exception:
            pass

        p = q.filter(Product.slug == slug).first()
    except Exception:
        p = None

    if not p or (getattr(p, "status", "") or "").lower() != "active":
        return _render_404()

    # Track click afiliado si corresponde
    _track_aff_click_if_any(int(getattr(p, "id", 0) or 0))

    aff_code, aff_sub = _get_aff_attribution()

    html = render_template(
        "product_detail.html",
        product=p,
        aff_code=aff_code,
        aff_sub=aff_sub,
    )
    resp = make_response(html)
    resp = _capture_affiliation_for_response(resp)
    # producto: no-store (precio/stock)
    return _resp_no_store(resp)


__all__ = ["shop_bp"]
