# app/routes/api_routes.py
from __future__ import annotations

import os
import time
from typing import Any, Dict, Optional, Tuple, List

from flask import Blueprint, jsonify, request, current_app, url_for

from app.models import db, Product, Category

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")

_TRUE = {"1", "true", "yes", "y", "on"}


# ============================================================
# Config (dinámico, no “congelado” en import)
# ============================================================


def _env_flag(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in _TRUE


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None:
        return default
    try:
        return int(v)
    except Exception:
        return default


def _env_list(name: str) -> List[str]:
    raw = (os.getenv(name, "") or "").strip()
    if not raw:
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]


def _api_enabled() -> bool:
    return _env_flag("API_PUBLIC_ENABLED", False)


def _api_keys() -> List[str]:
    return _env_list("API_KEYS")


def _cors_origins() -> List[str]:
    return _env_list("API_CORS_ORIGINS")


def _rate_limit_enabled() -> bool:
    return _env_flag("API_RATE_LIMIT", True)


def _rate_limit_rpm() -> int:
    return max(10, _env_int("API_RATE_LIMIT_RPM", 120))


# ============================================================
# Rate limit in-memory (por proceso)
# ============================================================

_RL_BUCKET: Dict[str, List[float]] = {}


def _now() -> float:
    return time.time()


def _client_ip() -> str:
    """
    ProxyFix en Render suele setear bien request.remote_addr,
    pero si llega X-Forwarded-For con varios, tomamos el primero.
    """
    xff = (request.headers.get("X-Forwarded-For") or "").strip()
    if xff:
        return xff.split(",")[0].strip()[:80] or "unknown"
    return (request.remote_addr or "unknown")[:80]


def _rate_limit_check() -> Tuple[bool, int]:
    """
    True/False y retry_after en segundos.
    """
    if not _rate_limit_enabled():
        return True, 0

    ip = _client_ip()
    window = 60.0
    max_req = _rate_limit_rpm()

    ts = _now()
    arr = _RL_BUCKET.get(ip, [])
    arr = [t for t in arr if (ts - t) <= window]

    if len(arr) >= max_req:
        retry = int(window - (ts - arr[0]))
        _RL_BUCKET[ip] = arr
        return False, max(1, retry)

    arr.append(ts)
    _RL_BUCKET[ip] = arr
    return True, 0


# ============================================================
# CORS
# ============================================================


def _cors_headers(resp):
    origins = _cors_origins()
    if not origins:
        return resp

    origin = (request.headers.get("Origin") or "").strip()
    if origin and origin in origins:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = (
            "Content-Type,Authorization,X-API-Key"
        )
        resp.headers["Access-Control-Max-Age"] = "600"
    return resp


def _json_ok(payload: Dict[str, Any], status: int = 200):
    resp = jsonify(payload)
    resp.status_code = status
    return _cors_headers(resp)


# ============================================================
# Gate global API
# ============================================================


@api_bp.before_request
def _api_gate():
    # Preflight CORS
    if request.method == "OPTIONS":
        return _json_ok({"ok": True}, 200)

    if not _api_enabled():
        return _json_ok({"ok": False, "error": "api_disabled"}, 404)

    ok, retry = _rate_limit_check()
    if not ok:
        resp = _json_ok(
            {"ok": False, "error": "rate_limited", "retry_after": retry}, 429
        )
        resp.headers["Retry-After"] = str(retry)
        return resp

    keys = _api_keys()
    if keys:
        got = (request.headers.get("X-API-Key") or "").strip() or (
            request.args.get("api_key") or ""
        ).strip()
        if not got or got not in keys:
            return _json_ok({"ok": False, "error": "invalid_api_key"}, 401)

    return None


@api_bp.after_request
def _api_after(resp):
    return _cors_headers(resp)


# ============================================================
# Helpers
# ============================================================


def _int(v: Any, default: int) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _str(v: Any, default: str = "") -> str:
    return str(v).strip() if v is not None else default


def _money(v: Any) -> str:
    try:
        return str(v)
    except Exception:
        return "0.00"


def _safe_iso(dt: Any) -> Optional[str]:
    try:
        return dt.isoformat() if dt else None
    except Exception:
        return None


def _product_public(p: Product) -> Dict[str, Any]:
    # Imagen principal
    img = None
    try:
        img = p.main_image_url()
    except Exception:
        img = getattr(p, "image_url", None)

    # Categoría snapshot
    cat = None
    try:
        c = getattr(p, "category", None)
        if c:
            cat = {
                "id": getattr(c, "id", None),
                "name": getattr(c, "name", None),
                "slug": getattr(c, "slug", None),
                "path": getattr(c, "slug_path", None),
            }
    except Exception:
        cat = None

    # Stock
    in_stock = True
    try:
        in_stock = bool(p.is_available()) if hasattr(p, "is_available") else True
    except Exception:
        in_stock = True

    return {
        "id": getattr(p, "id", None),
        "title": getattr(p, "title", None),
        "slug": getattr(p, "slug", None),
        "status": getattr(p, "status", None),
        "source": getattr(p, "source", "manual"),
        "currency": getattr(p, "currency", "USD"),
        "price": _money(getattr(p, "price", "0.00")),
        "compare_at_price": (
            _money(getattr(p, "compare_at_price", None))
            if getattr(p, "compare_at_price", None) is not None
            else None
        ),
        "in_stock": in_stock,
        "stock_mode": getattr(p, "stock_mode", "finite"),
        "stock_qty": int(getattr(p, "stock_qty", 0) or 0),
        "short_description": getattr(p, "short_description", None),
        "seo_title": (
            p.seo_title_final()
            if hasattr(p, "seo_title_final")
            else getattr(p, "seo_title", None)
        ),
        "seo_description": (
            p.seo_description_final()
            if hasattr(p, "seo_description_final")
            else getattr(p, "seo_description", None)
        ),
        "image": img,
        "category": cat,
        "updated_at": _safe_iso(getattr(p, "updated_at", None)),
    }


def _base_shop_url() -> str:
    # external True necesita ProxyFix + Host headers.
    try:
        return url_for("shop.shop_home", _external=True).rstrip("/")
    except Exception:
        return ""


def _make_aff_link(product_id: int, aff: str, sub: Optional[str] = None) -> str:
    """
    Link afiliado:
      /shop/product/<slug>?aff=xxx&sub=yyy
    Ajusta el endpoint si tu tienda usa otro.
    """
    try:
        p = db.session.get(Product, int(product_id))
    except Exception:
        p = None

    if not p or (getattr(p, "status", "") or "").lower() != "active":
        return ""

    # 1) Intento endpoint canonical
    try:
        base = url_for("shop.product_detail", slug=p.slug, _external=True)
    except Exception:
        # 2) Fallback por URL base
        base_shop = _base_shop_url()
        if base_shop:
            base = f"{base_shop}/product/{p.slug}"
        else:
            # 3) Fallback relativo (no rompe)
            base = f"/shop/product/{p.slug}"

    sep = "&" if "?" in base else "?"
    link = f"{base}{sep}aff={aff}"
    if sub:
        link += f"&sub={sub}"
    return link


# ============================================================
# API: Health
# ============================================================


@api_bp.get("/health")
def api_health():
    return _json_ok(
        {
            "ok": True,
            "api_enabled": True,
            "version": "v1",
            "rate_limit": {"enabled": _rate_limit_enabled(), "rpm": _rate_limit_rpm()},
            "auth_required": bool(_api_keys()),
        }
    )


# ============================================================
# API: Productos
# ============================================================


@api_bp.get("/products")
def api_products_list():
    """
    GET /api/v1/products
    Query:
      - q: búsqueda por título
      - category: slug o id o slug_path
      - page, per_page
      - active_only=1 (default)
    """
    q = _str(request.args.get("q"))
    category = request.args.get("category")
    page = max(1, _int(request.args.get("page"), 1))
    per_page = min(50, max(1, _int(request.args.get("per_page"), 20)))
    active_only = _str(request.args.get("active_only"), "1").lower() in _TRUE

    query = db.session.query(Product)

    if active_only:
        try:
            query = query.filter(Product.status == "active")
        except Exception:
            pass

    if q:
        try:
            like = f"%{q}%"
            query = query.filter(Product.title.ilike(like))
        except Exception:
            pass

    if category:
        try:
            cid = int(str(category))
            query = query.filter(Product.category_id == cid)
        except Exception:
            # slug o slug_path
            try:
                c = (
                    db.session.query(Category)
                    .filter(
                        (Category.slug == str(category))
                        | (
                            getattr(Category, "slug_path", Category.slug)
                            == str(category)
                        )
                    )
                    .first()
                )
                if c:
                    query = query.filter(Product.category_id == c.id)
            except Exception:
                pass

    try:
        total = query.count()
    except Exception:
        total = 0

    try:
        items = (
            query.order_by(Product.updated_at.desc(), Product.id.desc())
            .offset((page - 1) * per_page)
            .limit(per_page)
            .all()
        )
    except Exception:
        items = []

    return _json_ok(
        {
            "ok": True,
            "page": page,
            "per_page": per_page,
            "total": total,
            "products": [_product_public(p) for p in items],
        }
    )


@api_bp.get("/products/<int:product_id>")
def api_product_detail(product_id: int):
    p = db.session.get(Product, product_id)
    if not p:
        return _json_ok({"ok": False, "error": "not_found"}, 404)

    if (getattr(p, "status", "") or "").lower() != "active":
        return _json_ok({"ok": False, "error": "not_available"}, 404)

    return _json_ok({"ok": True, "product": _product_public(p)})


@api_bp.get("/products/slug/<path:slug>")
def api_product_by_slug(slug: str):
    try:
        p = db.session.query(Product).filter(Product.slug == slug).first()
    except Exception:
        p = None

    if not p:
        return _json_ok({"ok": False, "error": "not_found"}, 404)

    if (getattr(p, "status", "") or "").lower() != "active":
        return _json_ok({"ok": False, "error": "not_available"}, 404)

    return _json_ok({"ok": True, "product": _product_public(p)})


# ============================================================
# API: Afiliados
# ============================================================


@api_bp.post("/affiliate/click")
def api_affiliate_click():
    """
    POST /api/v1/affiliate/click
    Body JSON:
      { "aff": "partner123", "sub": "campaignX", "product_id": 10, "ref": "https://...", "ua": "..."}

    Guarda click en DB si existe AffiliateClick model; si no, NO rompe.
    """
    data = request.get_json(silent=True) or {}

    aff = _str(data.get("aff"))
    sub = _str(data.get("sub")) or None
    product_id = _int(data.get("product_id"), 0)

    ref = (
        _str(data.get("ref"))[:500]
        or (request.headers.get("Referer") or "")[:500]
        or None
    )
    ua = _str(data.get("ua") or request.headers.get("User-Agent"))[:300] or None
    ip = _client_ip()

    if not aff or product_id <= 0:
        return _json_ok({"ok": False, "error": "aff_and_product_id_required"}, 400)

    p = db.session.get(Product, product_id)
    if not p or (getattr(p, "status", "") or "").lower() != "active":
        return _json_ok({"ok": False, "error": "product_not_available"}, 404)

    AffiliateClick = None
    try:
        from app.models import AffiliateClick as _AC  # type: ignore

        AffiliateClick = _AC
    except Exception:
        AffiliateClick = None

    stored = False
    if AffiliateClick is not None:
        try:
            click = AffiliateClick(
                aff_code=aff[:80],
                sub_code=(sub[:120] if sub else None),
                product_id=getattr(p, "id", None),
                ip=ip[:80],
                user_agent=ua,
                referrer=ref,
            )
            db.session.add(click)
            db.session.commit()
            stored = True
        except Exception as exc:
            db.session.rollback()
            current_app.logger.info("AffiliateClick save ignored: %s", exc)

    link = _make_aff_link(getattr(p, "id", product_id), aff, sub)
    return _json_ok(
        {
            "ok": True,
            "tracked": True,
            "stored": stored,
            "product_id": getattr(p, "id", product_id),
            "link": link,
        }
    )


@api_bp.get("/affiliate/link")
def api_affiliate_link():
    """
    GET /api/v1/affiliate/link?product_id=10&aff=partner123&sub=camp
    Devuelve link afiliado.
    """
    product_id = _int(request.args.get("product_id"), 0)
    aff = _str(request.args.get("aff"))
    sub = _str(request.args.get("sub")) or None

    if product_id <= 0 or not aff:
        return _json_ok({"ok": False, "error": "product_id_and_aff_required"}, 400)

    link = _make_aff_link(product_id, aff, sub)
    if not link:
        return _json_ok({"ok": False, "error": "product_not_available"}, 404)

    return _json_ok({"ok": True, "link": link})


__all__ = ["api_bp"]
