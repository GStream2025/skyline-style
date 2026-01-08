# app/routes/main_routes.py
from __future__ import annotations

import html
import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from flask import (
    Blueprint,
    current_app,
    jsonify,
    make_response,
    render_template,
    request,
    url_for,
    has_request_context,
)
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.models import db

main_bp = Blueprint("main", __name__)
log = logging.getLogger("main_routes")

_TRUE = {"1", "true", "yes", "y", "on"}

# -------------------------
# Cache home
# -------------------------
_HOME_CACHE_TTL = int(os.getenv("HOME_CACHE_TTL", "120") or "120")
_HOME_CACHE_TTL = max(10, min(_HOME_CACHE_TTL, 3600))

_HOME_CACHE: Dict[str, Dict[str, Any]] = {}
_HOME_LOCK = threading.Lock()
_HOME_INFLIGHT: Dict[str, threading.Event] = {}

SEO_DEFAULTS = {
    "meta_title": os.getenv("SEO_TITLE", "Skyline Store · Moda urbana, accesorios y tecnología"),
    "meta_description": os.getenv(
        "SEO_DESCRIPTION",
        "Comprá moda urbana, accesorios y tecnología en un solo lugar. Envíos rápidos y pagos seguros.",
    ),
    "og_image": os.getenv("SEO_OG_IMAGE", "/static/img/banners/hero_home.png"),
    "robots": os.getenv("SEO_ROBOTS", "index,follow"),
}


# ============================================================
# Helpers (E1/E2/E4)
# ============================================================

def _is_json_request() -> bool:
    try:
        if not has_request_context():
            return False
        if request.args.get("json") == "1":
            return True
        accept = (request.headers.get("Accept") or "").lower()
        if "application/json" in accept:
            return True
        if (request.headers.get("X-Requested-With") or "").lower() == "xmlhttprequest":
            return True
        if (request.path or "").lower().startswith("/api/"):
            return True
    except Exception:
        pass
    return False


def _template_exists(name: str) -> bool:
    try:
        current_app.jinja_env.get_template(name)
        return True
    except Exception:
        return False


def _canonical() -> str:
    try:
        if has_request_context():
            return request.base_url
    except Exception:
        pass
    return "/"


def _abs_url(path_or_url: str) -> str:
    s = (path_or_url or "").strip()
    if not s:
        return ""
    if s.startswith("http://") or s.startswith("https://"):
        return s
    if not s.startswith("/"):
        s = "/" + s
    try:
        if has_request_context():
            return request.url_root.rstrip("/") + s
    except Exception:
        pass
    return s


def _safe_text(s: Any, max_len: int = 200) -> str:
    try:
        out = str(s or "").strip()
    except Exception:
        out = ""
    return html.escape(out[:max_len], quote=True)


def _rollback_silent() -> None:
    try:
        db.session.rollback()
    except Exception:
        pass


def safe_url_for(endpoint: str, **values) -> str:
    """E1) url_for que NO rompe nunca."""
    try:
        # si el endpoint no existe, url_for tira BuildError.
        if not has_request_context():
            return "/"
        vf = getattr(current_app, "view_functions", {}) or {}
        if endpoint not in vf:
            return "/"
        return url_for(endpoint, **values)
    except Exception:
        return "/"


def _render_fallback_html(template: str, ctx: Dict[str, Any], status: int = 200):
    title = _safe_text(ctx.get("meta_title") or SEO_DEFAULTS["meta_title"], 120)
    desc = _safe_text(ctx.get("meta_description") or SEO_DEFAULTS["meta_description"], 240)
    templ = _safe_text(template, 120)

    html_doc = f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <meta name="description" content="{desc}">
  <meta name="robots" content="{_safe_text(ctx.get("robots","index,follow"), 40)}">
  <link rel="canonical" href="{_safe_text(ctx.get("canonical","/"), 200)}">
  <style>
    body{{font-family:system-ui,-apple-system,Segoe UI,Roboto; padding:28px; background:#f7f8fb; color:#0b1220}}
    .card{{max-width:900px;margin:0 auto;background:#fff;border:1px solid #e8edf5;border-radius:18px;padding:18px 18px 10px;
      box-shadow:0 18px 40px rgba(2,6,23,.10)}}
    h1{{margin:0;font-size:22px;letter-spacing:-.3px}}
    p{{opacity:.78; font-weight:600}}
    code{{background:#f1f5ff;padding:2px 6px;border-radius:8px}}
  </style>
</head>
<body>
  <div class="card">
    <h1>{title}</h1>
    <p>{desc}</p>
    <p style="opacity:.6">Fallback activado (template: <code>{templ}</code>)</p>
  </div>
</body>
</html>"""
    return html_doc, status, {"Content-Type": "text/html; charset=utf-8"}


def _render_safe(template: str, *, status: int = 200, **ctx):
    """
    E4) Render blindado:
    - Si falta template => fallback.
    - Si template existe pero revienta => fallback igual (sin 500).
    """
    ctx.setdefault("meta_title", SEO_DEFAULTS["meta_title"])
    ctx.setdefault("meta_description", SEO_DEFAULTS["meta_description"])
    ctx.setdefault("og_image", SEO_DEFAULTS["og_image"])
    ctx.setdefault("robots", SEO_DEFAULTS["robots"])
    ctx.setdefault("canonical", _canonical())
    ctx.setdefault("og_image_abs", _abs_url(ctx.get("og_image") or ""))

    if _is_json_request():
        safe_ctx = {k: v for k, v in ctx.items() if k not in {"featured"}}
        safe_ctx["featured_count"] = len(ctx.get("featured") or [])
        return jsonify(ok=True, template=template, data=safe_ctx), status

    # template missing
    if not _template_exists(template):
        return _render_fallback_html(template, ctx, status)

    # template exists but might crash
    try:
        return render_template(template, **ctx), status
    except Exception as e:
        log.warning("Template error (%s): %s", template, e)
        return _render_fallback_html(template, ctx, status)


# ============================================================
# Models (safe)
# ============================================================

def _get_model(name: str):
    try:
        import app.models as models  # type: ignore
        return getattr(models, name, None)
    except Exception:
        return None


# ============================================================
# Product helpers
# ============================================================

def _product_title(p: Any) -> str:
    t = getattr(p, "title", None) or getattr(p, "name", None) or "Producto"
    s = str(t).strip()
    return s[:120] or "Producto"


def _product_image(p: Any) -> str:
    try:
        if hasattr(p, "main_image_url") and callable(p.main_image_url):
            img = p.main_image_url()
            if img:
                return str(img)
    except Exception:
        pass

    try:
        media = getattr(p, "media", None)
        if media:
            first = list(media)[0]
            url = getattr(first, "url", None)
            if url:
                return str(url)
    except Exception:
        pass

    img = getattr(p, "image_url", None)
    if img:
        return str(img)

    return "/static/img/banners/hero_home.png"


def _product_href(p: Any) -> str:
    slug = (getattr(p, "slug", "") or "").strip()
    if not slug:
        return "/shop"
    # E1) no BuildError
    try:
        return safe_url_for("shop.product_detail", slug=slug) or f"/shop?q={slug}"
    except Exception:
        return f"/shop?q={slug}"


def _is_active_product(p: Any) -> bool:
    try:
        st = (getattr(p, "status", "") or "").lower().strip()
        if st:
            return st == "active"
    except Exception:
        pass
    try:
        if hasattr(p, "is_active"):
            return bool(getattr(p, "is_active"))
    except Exception:
        pass
    return True


def _limit_clamp(n: Any, lo: int = 1, hi: int = 24, default: int = 8) -> int:
    try:
        n_int = int(n)
    except Exception:
        n_int = default
    return max(lo, min(hi, n_int))


def _currency_of(p: Any) -> str:
    cur = getattr(p, "currency", None) or current_app.config.get("CURRENCY", "UYU")
    try:
        cur = str(cur).strip().upper()
    except Exception:
        cur = "UYU"
    return cur or "UYU"


def _price_value_of(p: Any) -> Optional[Any]:
    v = getattr(p, "price", None)
    return v if v is not None else None


def _compare_at_of(p: Any) -> Optional[Any]:
    for key in ("compare_at", "compare_at_price", "old_price", "price_old"):
        v = getattr(p, key, None)
        if v is not None and str(v).strip() != "":
            return v
    return None


def _discount_pct_of(p: Any, price_value: Any, compare_at: Any) -> Optional[int]:
    for key in ("discount_pct", "discount_percent", "discount"):
        v = getattr(p, key, None)
        if v is not None and str(v).strip() != "":
            try:
                iv = int(float(v))
                return max(0, min(100, iv))
            except Exception:
                pass
    try:
        if compare_at is None or price_value is None:
            return None
        c = float(compare_at)
        pr = float(price_value)
        if c > 0 and pr < c:
            pct = int(round(((c - pr) / c) * 100))
            return max(0, min(100, pct))
    except Exception:
        pass
    return None


def _money_label(currency: str, price_value: Any) -> str:
    try:
        return f"{currency} {price_value}"
    except Exception:
        return f"{currency} {str(price_value)}"


# ============================================================
# Featured builder + cache signature (E3)
# ============================================================

def _table_exists_products() -> bool:
    """E3) Confirma tabla products sin romper."""
    try:
        # Works on Postgres & SQLite
        row = db.session.execute(
            text("SELECT 1 FROM information_schema.tables WHERE table_name='products' LIMIT 1")
        ).first()
        if row:
            return True
    except Exception:
        pass
    try:
        # SQLite fallback
        row2 = db.session.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='products' LIMIT 1")
        ).first()
        return bool(row2)
    except Exception:
        _rollback_silent()
        return False


def _column_exists_products(col: str) -> bool:
    """E3) Detecta columna de products."""
    try:
        row = db.session.execute(
            text(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name='products' AND column_name=:c LIMIT 1"
            ),
            {"c": col},
        ).first()
        if row:
            return True
    except Exception:
        pass
    try:
        # SQLite fallback: PRAGMA table_info
        rows = db.session.execute(text("PRAGMA table_info(products)")).fetchall()
        return any((r[1] == col) for r in rows)  # r[1]=name
    except Exception:
        _rollback_silent()
        return False


def _db_signature() -> str:
    """
    Firma best-effort para invalidar cache.
    - No rompe si tabla/columna no existen.
    """
    try:
        if not _table_exists_products():
            return "0|"
        row = db.session.execute(text("SELECT COUNT(*) FROM products")).first()
        ct = int(row[0]) if row else 0

        mx = None
        if _column_exists_products("updated_at"):
            row2 = db.session.execute(text("SELECT MAX(updated_at) FROM products")).first()
            mx = row2[0] if row2 else None
        elif _column_exists_products("created_at"):
            row3 = db.session.execute(text("SELECT MAX(created_at) FROM products")).first()
            mx = row3[0] if row3 else None

        return f"{ct}|{mx}"
    except Exception:
        _rollback_silent()
        return ""


def _build_featured(limit: int = 8) -> List[Dict[str, Any]]:
    limit = _limit_clamp(limit, 1, 24, 8)
    ProductModel = _get_model("Product")
    if not ProductModel:
        return []

    try:
        q = ProductModel.query  # type: ignore[attr-defined]

        try:
            if hasattr(ProductModel, "status"):
                q = q.filter(ProductModel.status == "active")  # type: ignore[attr-defined]
            elif hasattr(ProductModel, "is_active"):
                q = q.filter(ProductModel.is_active.is_(True))  # type: ignore[attr-defined]
        except Exception:
            pass

        try:
            if hasattr(ProductModel, "updated_at"):
                q = q.order_by(ProductModel.updated_at.desc())  # type: ignore[attr-defined]
            elif hasattr(ProductModel, "created_at"):
                q = q.order_by(ProductModel.created_at.desc())  # type: ignore[attr-defined]
            else:
                q = q.order_by(ProductModel.id.desc())  # type: ignore[attr-defined]
        except Exception:
            pass

        items = q.limit(limit).all()

        out: List[Dict[str, Any]] = []
        for p in items:
            if not _is_active_product(p):
                continue

            currency = _currency_of(p)
            price_value = _price_value_of(p)
            compare_at = _compare_at_of(p)
            discount_pct = _discount_pct_of(p, price_value, compare_at)

            out.append(
                {
                    "img": _product_image(p),
                    "title": _product_title(p),
                    "href": _product_href(p),
                    "price_value": price_value,
                    "currency": currency,
                    "compare_at": compare_at,
                    "discount_pct": discount_pct,
                    "price_label": _money_label(currency, price_value) if price_value is not None else "",
                }
            )
        return out

    except Exception as e:
        log.info("Featured dinámico falló: %s", e)
        _rollback_silent()
        return []


def _static_featured() -> List[Dict[str, Any]]:
    return [
        {"img": "/static/img/products/hero-hoodie.png", "title": "Hoodies Premium", "href": "/shop",
         "price_value": 1990, "currency": "UYU", "compare_at": None, "discount_pct": None, "price_label": "UYU 1990"},
        {"img": "/static/img/products/hero-sneakers.png", "title": "Zapatillas Urbanas", "href": "/shop",
         "price_value": 2590, "currency": "UYU", "compare_at": None, "discount_pct": None, "price_label": "UYU 2590"},
        {"img": "/static/img/products/hero-headphones.png", "title": "Audio Inalámbrico", "href": "/shop",
         "price_value": 1290, "currency": "UYU", "compare_at": None, "discount_pct": None, "price_label": "UYU 1290"},
        {"img": "/static/img/products/hero-watch.png", "title": "Smartwatch", "href": "/shop",
         "price_value": 1490, "currency": "UYU", "compare_at": None, "discount_pct": None, "price_label": "UYU 1490"},
    ]


def _cache_key_home() -> str:
    """
    E2) Key estable sin depender de request context.
    """
    cur = str(current_app.config.get("CURRENCY", "UYU") or "UYU").upper()
    lang = "default"
    try:
        if has_request_context():
            lang = (request.headers.get("Accept-Language") or "").split(",")[0].strip().lower() or "default"
            lang = lang[:8]
    except Exception:
        lang = "default"
    return f"home|cur={cur}|lang={lang}"


def _get_cached_featured(key: str) -> Optional[List[Dict[str, Any]]]:
    bucket = _HOME_CACHE.get(key) or {}
    ts = float(bucket.get("ts") or 0.0)
    if (time.time() - ts) > _HOME_CACHE_TTL:
        return None

    try:
        sig = _db_signature()
        old = bucket.get("sig") or ""
        if sig and old and sig != old:
            return None
    except Exception:
        pass

    featured = bucket.get("featured")
    return featured if isinstance(featured, list) and featured else None


def _set_cached_featured(key: str, items: List[Dict[str, Any]]) -> None:
    _HOME_CACHE.setdefault(key, {})
    _HOME_CACHE[key]["ts"] = time.time()
    _HOME_CACHE[key]["featured"] = items
    _HOME_CACHE[key]["sig"] = _db_signature() or ""


def _get_or_build_featured(key: str, limit: int = 8) -> List[Dict[str, Any]]:
    cached = _get_cached_featured(key)
    if cached:
        return cached

    with _HOME_LOCK:
        cached2 = _get_cached_featured(key)
        if cached2:
            return cached2

        ev = _HOME_INFLIGHT.get(key)
        if ev is None:
            ev = threading.Event()
            _HOME_INFLIGHT[key] = ev
            is_builder = True
        else:
            is_builder = False

    if not is_builder:
        ev.wait(timeout=1.8)
        return _get_cached_featured(key) or _static_featured()

    try:
        built = _build_featured(limit=limit) or _static_featured()
        with _HOME_LOCK:
            _set_cached_featured(key, built)
        return built
    finally:
        with _HOME_LOCK:
            ev2 = _HOME_INFLIGHT.pop(key, None)
            if ev2:
                ev2.set()


# ============================================================
# Routes
# ============================================================

@main_bp.get("/")
def home():
    key = _cache_key_home()
    featured = _get_or_build_featured(key, limit=8)

    ctx = {
        "featured": featured,
        **SEO_DEFAULTS,
        "canonical": _canonical(),
        "og_image_abs": _abs_url(SEO_DEFAULTS.get("og_image", "")),
    }

    # home.html primero, si no existe usa index.html
    template = "home.html" if _template_exists("home.html") else "index.html"
    return _render_safe(template, **ctx)


@main_bp.get("/healthz")
def healthz():
    try:
        db.session.execute(text("SELECT 1"))
        key = _cache_key_home()
        bucket = _HOME_CACHE.get(key) or {}
        return {
            "ok": True,
            "db": "ok",
            "env": current_app.config.get("ENV"),
            "cache_ttl": _HOME_CACHE_TTL,
            "cache_age": int(time.time() - float(bucket.get("ts") or 0.0)),
            "cache_key": key,
        }, 200
    except SQLAlchemyError as e:
        _rollback_silent()
        log.warning("Health DB error: %s", e)
        return {"ok": False, "db": "error"}, 500
    except Exception as e:
        log.warning("Health error: %s", e)
        return {"ok": False, "db": "error"}, 500


@main_bp.get("/robots.txt")
def robots_txt():
    if os.getenv("ROBOTS_DISALLOW_ALL", "0").strip().lower() in _TRUE:
        body = "User-agent: *\nDisallow: /\n"
    else:
        body = "User-agent: *\nAllow: /\nSitemap: /sitemap.xml\n"
    resp = make_response(body, 200)
    resp.headers["Content-Type"] = "text/plain; charset=utf-8"
    resp.headers["Cache-Control"] = "public, max-age=300"
    return resp


def _best_lastmod(p: Any) -> Optional[str]:
    for key in ("updated_at", "created_at"):
        v = getattr(p, key, None)
        if not v:
            continue
        try:
            return v.replace(microsecond=0).isoformat()
        except Exception:
            try:
                return str(v)
            except Exception:
                return None
    return None


@main_bp.get("/sitemap.xml")
def sitemap_xml():
    base = ""
    try:
        base = (request.url_root or "").rstrip("/") if has_request_context() else ""
    except Exception:
        base = ""

    urls: List[Tuple[str, Optional[str]]] = []

    def add(path: str, lastmod: Optional[str] = None):
        if not path.startswith("/"):
            path = "/" + path
        urls.append(((base + path) if base else path, lastmod))

    add("/")
    add("/shop")

    limit = _limit_clamp(os.getenv("SITEMAP_LIMIT", "500"), 1, 2000, 500)
    ProductModel = _get_model("Product")

    if ProductModel:
        try:
            q = ProductModel.query  # type: ignore[attr-defined]
            try:
                if hasattr(ProductModel, "status"):
                    q = q.filter(ProductModel.status == "active")  # type: ignore[attr-defined]
                elif hasattr(ProductModel, "is_active"):
                    q = q.filter(ProductModel.is_active.is_(True))  # type: ignore[attr-defined]
            except Exception:
                pass

            try:
                if hasattr(ProductModel, "updated_at"):
                    q = q.order_by(ProductModel.updated_at.desc())  # type: ignore[attr-defined]
                else:
                    q = q.order_by(ProductModel.id.desc())  # type: ignore[attr-defined]
            except Exception:
                pass

            for p in q.limit(limit).all():
                slug = (getattr(p, "slug", "") or "").strip()
                if not slug:
                    continue
                lastmod = _best_lastmod(p)
                href = safe_url_for("shop.product_detail", slug=slug)
                if href == "/":
                    href = f"/shop?q={slug}"
                add(href, lastmod=lastmod)

        except Exception:
            _rollback_silent()

    def xml_escape(s: str) -> str:
        return _safe_text(s, 500)

    xml_items = []
    for loc, lastmod in urls:
        if lastmod:
            xml_items.append(
                f"  <url><loc>{xml_escape(loc)}</loc><lastmod>{xml_escape(lastmod)}</lastmod></url>"
            )
        else:
            xml_items.append(f"  <url><loc>{xml_escape(loc)}</loc></url>")

    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
{chr(10).join(xml_items)}
</urlset>
"""
    resp = make_response(xml, 200)
    resp.headers["Content-Type"] = "application/xml; charset=utf-8"
    resp.headers["Cache-Control"] = "public, max-age=300"
    return resp


__all__ = ["main_bp"]
