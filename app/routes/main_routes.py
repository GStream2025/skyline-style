# app/routes/main_routes.py
"""
Skyline Store · Main Routes (ULTRA PRO FINAL / ZERO-500)

✅ NO importa modelos al import-time (evita mapper/init issues)
✅ DB signature compatible SQLite/Postgres (sin NOW())
✅ Featured + cache bulletproof (anti-stampede + TTL + firma best-effort)
✅ Render seguro: template faltante -> HTML/JSON fallback sin 500
✅ Sitemap/robots ultra safe
✅ Health separado (/healthz) para no chocar con create_app
"""

from __future__ import annotations

import html
import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from flask import Blueprint, current_app, jsonify, make_response, render_template, request, url_for
from sqlalchemy import text

from app.models import db  # ✅ solo db (no Product proxy)

main_bp = Blueprint("main", __name__)
log = logging.getLogger("main_routes")

_TRUE = {"1", "true", "yes", "y", "on"}

# -------------------------
# Cache home
# -------------------------
_HOME_CACHE_TTL = int(os.getenv("HOME_CACHE_TTL", "120") or "120")
_HOME_CACHE_TTL = max(10, min(_HOME_CACHE_TTL, 3600))

_HOME_CACHE: Dict[str, Any] = {"ts": 0.0, "featured": [], "sig": ""}
_HOME_LOCK = threading.Lock()

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
# Helpers
# ============================================================

def _is_json_request() -> bool:
    if request.args.get("json") == "1":
        return True
    accept = (request.headers.get("Accept") or "").lower()
    if "application/json" in accept:
        return True
    if (request.headers.get("X-Requested-With") or "").lower() == "xmlhttprequest":
        return True
    if (request.path or "").lower().startswith("/api/"):
        return True
    return False


def _template_exists(name: str) -> bool:
    try:
        current_app.jinja_env.get_template(name)
        return True
    except Exception:
        return False


def _canonical() -> str:
    try:
        return request.url.split("?")[0]
    except Exception:
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
        return request.url_root.rstrip("/") + s
    except Exception:
        return s


def _safe_text(s: Any, max_len: int = 200) -> str:
    try:
        out = str(s or "").strip()
    except Exception:
        out = ""
    out = out[:max_len]
    return html.escape(out, quote=True)


def _render_safe(template: str, *, status: int = 200, **ctx):
    """
    Render blindado:
    - si falta template => JSON u HTML mínimo
    - nunca rompe la app
    """
    ctx.setdefault("meta_title", SEO_DEFAULTS["meta_title"])
    ctx.setdefault("meta_description", SEO_DEFAULTS["meta_description"])
    ctx.setdefault("og_image", SEO_DEFAULTS["og_image"])
    ctx.setdefault("robots", SEO_DEFAULTS["robots"])
    ctx.setdefault("canonical", _canonical())
    ctx.setdefault("og_image_abs", _abs_url(ctx.get("og_image") or ""))

    if _template_exists(template):
        return render_template(template, **ctx), status

    if _is_json_request():
        safe_ctx = {k: v for k, v in ctx.items() if k not in {"featured"}}
        safe_ctx["featured_count"] = len(ctx.get("featured") or [])
        return jsonify(ok=True, template_missing=template, data=safe_ctx), status

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
    <p style="opacity:.6">Template faltante: <code>{templ}</code></p>
  </div>
</body>
</html>"""
    return html_doc, status, {"Content-Type": "text/html; charset=utf-8"}


# ============================================================
# Model resolver (CRÍTICO: evita mapper/init issues)
# ============================================================

def _get_model(name: str):
    """
    Resuelve modelos desde el hub SIN forzar imports al import-time.
    Si el hub no está listo aún, devuelve None (y caemos a fallback).
    """
    try:
        from app.models import init_models  # lazy import
        # no llamamos init_models acá; create_app ya lo hace.
        from app.models import __dict__ as models_ns  # type: ignore
        m = models_ns.get(name)
        # m puede ser _ModelProxy: si no está cargado, puede tirar RuntimeError en _resolve()
        return m
    except Exception:
        return None


# ============================================================
# Product helpers (no tipamos Product para no atar a la clase)
# ============================================================

def _product_title(p: Any) -> str:
    t = getattr(p, "title", None) or getattr(p, "name", None) or "Producto"
    s = str(t).strip()
    return (s[:120] or "Producto")


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
    try:
        return url_for("shop.product_detail", slug=slug)
    except Exception:
        return f"/shop?q={slug}"


def _money(p: Any) -> str:
    price = getattr(p, "price", None)
    if price is None:
        return ""
    cur = getattr(p, "currency", None) or current_app.config.get("CURRENCY", "UYU")
    try:
        return f"{cur} {price}"
    except Exception:
        return f"{cur} {str(price)}"


def _is_active_product(p: Any) -> bool:
    try:
        if hasattr(p, "is_active"):
            return bool(getattr(p, "is_active"))
    except Exception:
        pass
    try:
        st = (getattr(p, "status", "") or "").lower()
        return st == "active"
    except Exception:
        return True


def _limit_clamp(n: Any, lo: int = 1, hi: int = 24, default: int = 8) -> int:
    try:
        n_int = int(n)
    except Exception:
        n_int = default
    return max(lo, min(hi, n_int))


# ============================================================
# Featured builder + cache signature (SQLite/Postgres safe)
# ============================================================

def _db_signature() -> str:
    """
    Firma best-effort para invalidar cache.
    ✅ SQLite-safe (sin NOW()).
    Si falla: "" (cache sólo por TTL).
    """
    try:
        # 1) count siempre
        row = db.session.execute(text("SELECT COUNT(*) FROM products")).first()
        ct = int(row[0]) if row else 0

        # 2) max updated_at si existe columna (puede fallar si no existe)
        mx = None
        try:
            row2 = db.session.execute(text("SELECT MAX(updated_at) FROM products")).first()
            mx = row2[0] if row2 else None
        except Exception:
            mx = None

        return f"{ct}|{mx}"
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
    return ""


def _build_featured(limit: int = 8) -> List[Dict[str, Any]]:
    limit = _limit_clamp(limit, 1, 24, 8)

    ProductModel = _get_model("Product")
    if not ProductModel:
        return []

    try:
        # si es proxy y todavía no está cargado -> puede explotar acá
        try:
            q = ProductModel.query  # type: ignore[attr-defined]
        except Exception:
            return []

        # filtro activo
        try:
            if hasattr(ProductModel, "status"):
                q = q.filter(ProductModel.status == "active")  # type: ignore[attr-defined]
            elif hasattr(ProductModel, "is_active"):
                q = q.filter(ProductModel.is_active.is_(True))  # type: ignore[attr-defined]
        except Exception:
            pass

        # ordering
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
            out.append(
                {
                    "img": _product_image(p),
                    "title": _product_title(p),
                    "price": _money(p),
                    "href": _product_href(p),
                }
            )
        return out

    except Exception as e:
        # IMPORTANTE: no spamear en prod, pero dejar pista.
        log.info("Featured dinámico falló: %s", e)
        try:
            db.session.rollback()
        except Exception:
            pass
        return []


def _static_featured() -> List[Dict[str, Any]]:
    return [
        {"img": "/static/img/products/hero-hoodie.png", "title": "Hoodies Premium", "price": "UYU 1990", "href": "/shop"},
        {"img": "/static/img/products/hero-sneakers.png", "title": "Zapatillas Urbanas", "price": "UYU 2590", "href": "/shop"},
        {"img": "/static/img/products/hero-headphones.png", "title": "Audio Inalámbrico", "price": "UYU 1290", "href": "/shop"},
        {"img": "/static/img/products/hero-watch.png", "title": "Smartwatch", "price": "UYU 1490", "href": "/shop"},
    ]


def _get_cached_featured() -> Optional[List[Dict[str, Any]]]:
    ts = float(_HOME_CACHE.get("ts") or 0.0)
    if (time.time() - ts) > _HOME_CACHE_TTL:
        return None

    # firma best-effort
    try:
        sig = _db_signature()
        old = _HOME_CACHE.get("sig") or ""
        if sig and old and sig != old:
            return None
    except Exception:
        pass

    featured = _HOME_CACHE.get("featured")
    return featured if isinstance(featured, list) and featured else None


def _set_cached_featured(items: List[Dict[str, Any]]) -> None:
    _HOME_CACHE["ts"] = time.time()
    _HOME_CACHE["featured"] = items
    try:
        _HOME_CACHE["sig"] = _db_signature()
    except Exception:
        _HOME_CACHE["sig"] = ""


# ============================================================
# Routes
# ============================================================

@main_bp.get("/")
def home():
    # double-checked locking: rápido sin lock cuando cache sirve
    featured = _get_cached_featured()
    if not featured:
        with _HOME_LOCK:
            featured = _get_cached_featured()
            if not featured:
                featured = _build_featured(limit=8) or _static_featured()
                _set_cached_featured(featured)

    ctx = {
        "featured": featured,
        **SEO_DEFAULTS,
        "canonical": _canonical(),
        "og_image_abs": _abs_url(SEO_DEFAULTS.get("og_image", "")),
    }
    return _render_safe("index.html", **ctx)


@main_bp.get("/about")
def about():
    return _render_safe(
        "about.html",
        meta_title="Sobre Skyline Store",
        meta_description="Conocé Skyline Store, una tienda online moderna y confiable.",
    )


@main_bp.get("/contact")
def contact():
    return _render_safe(
        "contact.html",
        meta_title="Contacto · Skyline Store",
        meta_description="Contactanos para soporte, ventas o consultas.",
    )


# ============================================================
# Health (separado para no chocar con create_app)
# ============================================================

@main_bp.get("/healthz")
def healthz():
    try:
        db.session.execute(text("SELECT 1"))
        return {
            "ok": True,
            "db": "ok",
            "env": current_app.config.get("ENV"),
            "cache_ttl": _HOME_CACHE_TTL,
            "cache_age": int(time.time() - float(_HOME_CACHE.get("ts") or 0.0)),
        }, 200
    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        log.warning("Health DB error: %s", e)
        return {"ok": False, "db": "error"}, 500


# ============================================================
# Robots + Sitemap
# ============================================================

@main_bp.get("/robots.txt")
def robots_txt():
    if (os.getenv("ROBOTS_DISALLOW_ALL", "0").strip().lower() in _TRUE):
        body = "User-agent: *\nDisallow: /\n"
    else:
        body = "User-agent: *\nAllow: /\nSitemap: /sitemap.xml\n"
    resp = make_response(body, 200)
    resp.headers["Content-Type"] = "text/plain; charset=utf-8"
    return resp


@main_bp.get("/sitemap.xml")
def sitemap_xml():
    urls: List[str] = []
    base = (request.url_root or "").rstrip("/")

    def add(path: str):
        if not path.startswith("/"):
            path = "/" + path
        urls.append(base + path)

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

            items = q.limit(limit).all()
            for p in items:
                slug = (getattr(p, "slug", "") or "").strip()
                if not slug:
                    continue
                try:
                    add(url_for("shop.product_detail", slug=slug))
                except Exception:
                    add(f"/shop?q={slug}")

        except Exception:
            try:
                db.session.rollback()
            except Exception:
                pass

    xml_items = "\n".join([f"  <url><loc>{_safe_text(u, 300)}</loc></url>" for u in urls])
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
{xml_items}
</urlset>
"""
    resp = make_response(xml, 200)
    resp.headers["Content-Type"] = "application/xml; charset=utf-8"
    return resp


__all__ = ["main_bp"]
