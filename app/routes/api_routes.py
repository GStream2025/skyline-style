# app/routes/api_routes.py — Skyline Store (ULTRA PRO v3.0 / NO-ERROR / PROD-READY)
from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from flask import Blueprint, jsonify, request, current_app, url_for, make_response
from sqlalchemy import text

from app.models import db

try:
    from app.models import Product, Category  # type: ignore
except Exception:  # pragma: no cover
    Product = None  # type: ignore
    Category = None  # type: ignore


api_bp = Blueprint("api", __name__, url_prefix="/api/v1")

_TRUE = {"1", "true", "yes", "y", "on"}
_RL_BUCKET: Dict[str, List[float]] = {}
_RL_SOFT_MAX_KEYS = 2400

_MAX_QUERY_KEYS = 64
_MAX_KEY_LEN = 60
_MAX_VAL_LEN = 240


def _env_flag(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in _TRUE


def _env_int(name: str, default: int, *, min_v: int, max_v: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        v = default
    else:
        try:
            v = int(raw.strip())
        except Exception:
            v = default
    return max(min_v, min(max_v, v))


def _env_list(name: str) -> List[str]:
    raw = (os.getenv(name, "") or "").strip()
    if not raw:
        return []
    out: List[str] = []
    for x in raw.split(","):
        x = x.strip()
        if x:
            out.append(x)
    return out


def _api_enabled() -> bool:
    return _env_flag("API_PUBLIC_ENABLED", False)


def _api_keys() -> List[str]:
    return _env_list("API_KEYS")


def _cors_origins() -> List[str]:
    return _env_list("API_CORS_ORIGINS")


def _rate_limit_enabled() -> bool:
    return _env_flag("API_RATE_LIMIT", True)


def _rate_limit_rpm() -> int:
    return _env_int("API_RATE_LIMIT_RPM", 120, min_v=10, max_v=6000)


def _now() -> float:
    return time.time()


def _client_ip() -> str:
    xff = (request.headers.get("X-Forwarded-For") or "").strip()
    if xff:
        return (xff.split(",")[0].strip()[:80] or "unknown")
    return (request.remote_addr or "unknown")[:80]


def _rl_cleanup(ts: float) -> None:
    if len(_RL_BUCKET) < _RL_SOFT_MAX_KEYS:
        return
    cutoff = ts - 180.0
    dead: List[str] = []
    for k, arr in _RL_BUCKET.items():
        try:
            if not arr or arr[-1] < cutoff:
                dead.append(k)
        except Exception:
            dead.append(k)
    for k in dead[:4000]:
        _RL_BUCKET.pop(k, None)


def _rate_limit_check() -> Tuple[bool, int]:
    if not _rate_limit_enabled():
        return True, 0

    ip = _client_ip()
    window = 60.0
    max_req = _rate_limit_rpm()

    ts = _now()
    _rl_cleanup(ts)

    arr = _RL_BUCKET.get(ip, [])
    if arr:
        arr = [t for t in arr if (ts - t) <= window]
    if len(arr) >= max_req:
        retry = int(window - (ts - arr[0])) if arr else 1
        _RL_BUCKET[ip] = arr
        return False, max(1, retry)

    arr.append(ts)
    _RL_BUCKET[ip] = arr
    return True, 0


def _cors_headers(resp):
    origins = _cors_origins()
    if not origins:
        return resp

    origin = (request.headers.get("Origin") or "").strip()
    if origin and origin in origins:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization,X-API-Key"
        resp.headers["Access-Control-Max-Age"] = "600"
    return resp


def _json_ok(payload: Dict[str, Any], status: int = 200):
    resp = jsonify(payload)
    resp.status_code = status
    resp.headers["Cache-Control"] = "no-store, max-age=0"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return _cors_headers(resp)


def _str(v: Any, default: str = "") -> str:
    return (str(v).strip() if v is not None else default)


def _int(v: Any, default: int) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _safe_iso(dt: Any) -> Optional[str]:
    try:
        return dt.isoformat() if dt else None
    except Exception:
        return None


def _money(v: Any) -> str:
    try:
        return str(v)
    except Exception:
        return "0.00"


def _clean_utm() -> Dict[str, str]:
    keys = ("utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content")
    out: Dict[str, str] = {}
    for k in keys:
        v = (request.args.get(k) or "").strip()
        if v:
            out[k] = v[:120]
    return out


def _product_public(p: Any) -> Dict[str, Any]:
    img = None
    try:
        img = p.main_image_url()
    except Exception:
        img = getattr(p, "image_url", None)

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
        "seo_title": (p.seo_title_final() if hasattr(p, "seo_title_final") else getattr(p, "seo_title", None)),
        "seo_description": (
            p.seo_description_final()
            if hasattr(p, "seo_description_final")
            else getattr(p, "seo_description", None)
        ),
        "image": img,
        "category": cat,
        "updated_at": _safe_iso(getattr(p, "updated_at", None)),
    }


def _safe_external_url(endpoint: str, **values) -> str:
    try:
        return url_for(endpoint, _external=True, **values)
    except Exception:
        try:
            return url_for(endpoint, _external=False, **values)
        except Exception:
            return ""


def _base_shop_url() -> str:
    u = _safe_external_url("shop.shop_home")
    return u.rstrip("/") if u else ""


def _make_aff_link(product_id: int, aff: str, sub: Optional[str] = None) -> str:
    if not Product:
        return ""

    try:
        p = db.session.get(Product, int(product_id))
    except Exception:
        p = None

    if not p or (getattr(p, "status", "") or "").lower() != "active":
        return ""

    base = ""
    try:
        base = _safe_external_url("shop.product_detail", slug=p.slug)
    except Exception:
        base = ""

    if not base:
        base_shop = _base_shop_url()
        if base_shop:
            base = f"{base_shop}/product/{p.slug}"
        else:
            base = f"/shop/product/{p.slug}"

    sep = "&" if "?" in base else "?"
    link = f"{base}{sep}aff={aff}"
    if sub:
        link += f"&sub={sub}"
    return link


def _same_origin(ref: str) -> bool:
    try:
        ru = urlparse(ref)
        return bool(ru.netloc and request.host and ru.netloc == request.host)
    except Exception:
        return False


@api_bp.before_request
def _api_gate():
    if request.method == "OPTIONS":
        return _json_ok({"ok": True}, 200)

    if not _api_enabled():
        return _json_ok({"ok": False, "error": "api_disabled"}, 404)

    if Product is None:
        return _json_ok({"ok": False, "error": "models_missing"}, 501)

    ok, retry = _rate_limit_check()
    if not ok:
        resp = _json_ok({"ok": False, "error": "rate_limited", "retry_after": retry}, 429)
        resp.headers["Retry-After"] = str(retry)
        return resp

    keys = _api_keys()
    if keys:
        got = (request.headers.get("X-API-Key") or "").strip() or (request.args.get("api_key") or "").strip()
        if not got or got not in keys:
            return _json_ok({"ok": False, "error": "invalid_api_key"}, 401)

    return None


@api_bp.after_request
def _api_after(resp):
    return _cors_headers(resp)


@api_bp.get("/health")
def api_health():
    db_ok = True
    try:
        db.session.execute(text("SELECT 1"))
    except Exception:
        db_ok = False

    return _json_ok(
        {
            "ok": True,
            "api_enabled": True,
            "version": "v1",
            "db_ok": db_ok,
            "rate_limit": {"enabled": _rate_limit_enabled(), "rpm": _rate_limit_rpm()},
            "auth_required": bool(_api_keys()),
            "cors": bool(_cors_origins()),
        }
    )


@api_bp.get("/products")
def api_products_list():
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

    if category and Category is not None:
        try:
            cid = int(str(category))
            query = query.filter(Product.category_id == cid)
        except Exception:
            try:
                cat_val = str(category)
                slug_path_col = getattr(Category, "slug_path", None)
                if slug_path_col is not None:
                    c = db.session.query(Category).filter((Category.slug == cat_val) | (Category.slug_path == cat_val)).first()
                else:
                    c = db.session.query(Category).filter(Category.slug == cat_val).first()
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

    return _json_ok({"ok": True, "page": page, "per_page": per_page, "total": total, "products": [_product_public(p) for p in items]})


@api_bp.get("/products/<int:product_id>")
def api_product_detail(product_id: int):
    try:
        p = db.session.get(Product, product_id)
    except Exception:
        p = None

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


@api_bp.post("/affiliate/click")
def api_affiliate_click():
    data = request.get_json(silent=True) or {}

    aff = _str(data.get("aff"))[:80]
    sub_raw = _str(data.get("sub"))[:120]
    sub = sub_raw or None
    product_id = _int(data.get("product_id"), 0)

    ref_in = _str(data.get("ref"))[:800]
    ref_hdr = (request.headers.get("Referer") or "")[:800]
    ref = None
    if ref_in and _same_origin(ref_in):
        ref = ref_in[:500]
    elif ref_hdr and _same_origin(ref_hdr):
        ref = ref_hdr[:500]

    ua = _str(data.get("ua") or request.headers.get("User-Agent"))[:300] or None
    ip = _client_ip()

    if not aff or product_id <= 0:
        return _json_ok({"ok": False, "error": "aff_and_product_id_required"}, 400)

    try:
        p = db.session.get(Product, product_id)
    except Exception:
        p = None

    if not p or (getattr(p, "status", "") or "").lower() != "active":
        return _json_ok({"ok": False, "error": "product_not_available"}, 404)

    AC = None
    try:
        from app.models.affiliate import AffiliateClick as _AC  # type: ignore
        AC = _AC
    except Exception:
        AC = None

    stored = False
    if AC is not None:
        try:
            meta: Dict[str, Any] = {
                "utm": _clean_utm(),
                "path": (request.path or "")[:200],
            }
            click = AC(
                aff_code=aff,
                sub_code=sub,
                product_id=getattr(p, "id", None),
                ip=ip[:80],
                user_agent=ua,
                referrer=ref,
                meta=meta,
            )
            db.session.add(click)
            db.session.commit()
            stored = True
        except Exception as exc:
            try:
                db.session.rollback()
            except Exception:
                pass
            current_app.logger.info("AffiliateClick save ignored: %s", exc)

    link = _make_aff_link(getattr(p, "id", product_id), aff, sub)
    return _json_ok({"ok": True, "tracked": True, "stored": stored, "product_id": getattr(p, "id", product_id), "link": link})


@api_bp.get("/affiliate/link")
def api_affiliate_link():
    product_id = _int(request.args.get("product_id"), 0)
    aff = _str(request.args.get("aff"))[:80]
    sub = _str(request.args.get("sub"))[:120] or None

    if product_id <= 0 or not aff:
        return _json_ok({"ok": False, "error": "product_id_and_aff_required"}, 400)

    link = _make_aff_link(product_id, aff, sub)
    if not link:
        return _json_ok({"ok": False, "error": "product_not_available"}, 404)

    return _json_ok({"ok": True, "link": link})


__all__ = ["api_bp"]
