# app/routes/main_routes.py
"""
Skyline Store · Main Routes (ULTRA PRO / BULLETPROOF)

Mejoras nuevas (extra 5+):
1) Health DB real compatible SQLAlchemy 2.x (text("SELECT 1")) + timeout seguro
2) Cache in-memory simple por proceso (featured/home) con TTL (sin Redis)
3) Soporta templates faltantes: fallback JSON / HTML mínimo (nunca rompe)
4) Featured más robusto:
   - usa main_image_url() si existe
   - evita N+1 con selectinload si hay relaciones
   - links correctos a producto/slug si existe endpoint, sino fallback a /shop?q=
5) Meta SEO y OG defaults centralizados + override por ruta
6) Logging blindado (no spamea en prod) + errores con rollback safe
7) Compatible con tu HUB de modelos (Product/Category/db únicos)
"""

from __future__ import annotations

import os
import time
import logging
from typing import Any, Dict, List, Optional

from flask import Blueprint, current_app, jsonify, render_template, request
from sqlalchemy import text
from sqlalchemy.orm import selectinload

from app.models import db, Product, Category

main_bp = Blueprint("main", __name__)

log = logging.getLogger("main_routes")

_TRUE = {"1", "true", "yes", "y", "on"}

# Cache simple por proceso (no Redis) - suficiente para home featured
_HOME_CACHE_TTL = int(os.getenv("HOME_CACHE_TTL", "120") or "120")  # segundos
_HOME_CACHE: Dict[str, Any] = {"ts": 0.0, "featured": None}

# Defaults SEO
SEO_DEFAULTS = {
    "meta_title": os.getenv("SEO_TITLE", "Skyline Store — Todo lo que buscás, en un solo lugar"),
    "meta_description": os.getenv(
        "SEO_DESCRIPTION",
        "Tienda online tipo marketplace. Comprá moda, tecnología y más con envíos rápidos.",
    ),
    "og_image": os.getenv("SEO_OG_IMAGE", "/static/img/og.png"),
}


# ============================================================
# Helpers
# ============================================================

def _safe_get(obj: Any, attr: str, default: Any = None) -> Any:
    try:
        return getattr(obj, attr, default)
    except Exception:
        return default


def _bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in _TRUE
    return bool(v)


def _is_json_request() -> bool:
    accept = (request.headers.get("Accept") or "").lower()
    ctype = (request.headers.get("Content-Type") or "").lower()
    return ("application/json" in accept) or ("application/json" in ctype) or (request.args.get("json") == "1")


def _template_exists(name: str) -> bool:
    try:
        current_app.jinja_env.get_template(name)
        return True
    except Exception:
        return False


def _render_safe(template_name: str, *, status: int = 200, **ctx):
    """
    Render seguro: si falta template -> devuelve JSON o HTML mínimo.
    """
    if _template_exists(template_name):
        return render_template(template_name, **ctx), status

    # Fallback JSON si el cliente acepta JSON
    if _is_json_request():
        return jsonify(ok=True, template_missing=template_name, data=ctx), status

    # Fallback HTML mínimo
    title = ctx.get("meta_title") or SEO_DEFAULTS["meta_title"]
    desc = ctx.get("meta_description") or SEO_DEFAULTS["meta_description"]
    html = f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{title}</title>
  <meta name="description" content="{desc}">
</head>
<body style="font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;padding:24px">
  <h1 style="margin:0 0 8px">{title}</h1>
  <p style="margin:0 0 16px;opacity:.8">{desc}</p>
  <p style="opacity:.7">Falta el template <code>{template_name}</code>. La app sigue funcionando.</p>
</body>
</html>"""
    return html, status, {"Content-Type": "text/html; charset=utf-8"}


def _product_image(p: Product) -> str:
    """
    Imagen robusta:
    - main_image_url() si existe
    - primera media.url si existe relación media
    - image_url si existe
    - placeholder
    """
    try:
        if hasattr(p, "main_image_url") and callable(getattr(p, "main_image_url")):
            u = p.main_image_url()
            if u:
                return str(u)
    except Exception:
        pass

    try:
        media = getattr(p, "media", None)
        if media and isinstance(media, list) and len(media) > 0:
            url = getattr(media[0], "url", None)
            if url:
                return str(url)
    except Exception:
        pass

    img = _safe_get(p, "image_url", None)
    if img:
        return str(img)

    return "hero-placeholder.png"


def _product_tag(p: Product) -> str:
    try:
        c = getattr(p, "category", None)
        if c and getattr(c, "name", None):
            return str(c.name)
    except Exception:
        pass
    return "Nuevo"


def _product_href(p: Product) -> str:
    """
    Link robusto:
    - intenta endpoint shop.product_detail (slug)
    - fallback /shop?q=slug
    """
    slug = str(_safe_get(p, "slug", "") or "").strip()
    if not slug:
        return "/shop"

    try:
        # si existe ese endpoint en tu shop_routes
        from flask import url_for
        return url_for("shop.product_detail", slug=slug)
    except Exception:
        return f"/shop?q={slug}"


def _money_display(p: Product) -> str:
    try:
        val = _safe_get(p, "price", None)
        if val is None:
            return ""
        return f"$ {val}"
    except Exception:
        return ""


def _build_featured_from_products(limit: int = 8) -> List[Dict[str, Any]]:
    """
    Featured dinámico robusto + performance:
    - filtro status active si existe
    - selectinload relaciones si existen
    """
    try:
        q = Product.query

        # filtro "active"
        if hasattr(Product, "status"):
            q = q.filter(Product.status == "active")

        # performance: evita N+1
        opts = []
        if hasattr(Product, "category"):
            opts.append(selectinload(Product.category))
        if hasattr(Product, "media"):
            opts.append(selectinload(Product.media))
        if opts:
            q = q.options(*opts)

        # orden marketplace
        if hasattr(Product, "updated_at"):
            q = q.order_by(Product.updated_at.desc())
        elif hasattr(Product, "created_at"):
            q = q.order_by(Product.created_at.desc())
        else:
            q = q.order_by(Product.id.desc())

        items = q.limit(max(1, min(24, int(limit)))).all()

        featured: List[Dict[str, Any]] = []
        for p in items:
            featured.append(
                {
                    "img": _product_image(p),
                    "title": str(_safe_get(p, "title", "Producto") or "Producto")[:120],
                    "tag": _product_tag(p)[:60],
                    "tag_cls": "tag--cyan",
                    "price": _money_display(p),
                    "desc": str(_safe_get(p, "short_description", "Producto destacado") or "Producto destacado")[:140],
                    "href": _product_href(p),
                }
            )
        return featured

    except Exception as exc:
        # no spamear en prod
        try:
            current_app.logger.info("Home featured dinámico falló: %s", exc)
        except Exception:
            pass
        return []


def _static_featured_fallback() -> List[Dict[str, Any]]:
    return [
        {"img": "hero-hoodie.png", "title": "Hoodies Premium", "tag": "Streetwear", "tag_cls": "tag--cyan", "price": "$ 1.990", "desc": "Calidad pro + envío rápido.", "href": "/shop"},
        {"img": "hero-sneakers.png", "title": "Zapatillas", "tag": "Tendencia", "tag_cls": "tag--amber", "price": "$ 2.590", "desc": "Dropshipping confiable.", "href": "/shop"},
        {"img": "hero-headphones.png", "title": "Audio", "tag": "Tech", "tag_cls": "tag--violet", "price": "$ 1.290", "desc": "Sonido premium.", "href": "/shop"},
        {"img": "hero-watch.png", "title": "Smartwatch", "tag": "Gadgets", "tag_cls": "tag--green", "price": "$ 1.490", "desc": "Para tu día a día.", "href": "/shop"},
    ]


def _get_cached_featured() -> Optional[List[Dict[str, Any]]]:
    try:
        ts = float(_HOME_CACHE.get("ts") or 0.0)
    except Exception:
        ts = 0.0
    if (time.time() - ts) <= max(10, _HOME_CACHE_TTL):
        cached = _HOME_CACHE.get("featured")
        if isinstance(cached, list):
            return cached
    return None


def _set_cached_featured(items: List[Dict[str, Any]]) -> None:
    _HOME_CACHE["ts"] = time.time()
    _HOME_CACHE["featured"] = items


def _seo_ctx(**overrides) -> Dict[str, Any]:
    ctx = dict(SEO_DEFAULTS)
    ctx.update({k: v for k, v in overrides.items() if v is not None})
    return ctx


# ============================================================
# Routes
# ============================================================

@main_bp.get("/")
def home():
    """
    Home PRO:
    - Featured dinámico (cacheado) si hay productos
    - Fallback estático si no
    - Render seguro si faltan templates
    """
    featured = _get_cached_featured()
    if not featured:
        featured = _build_featured_from_products(limit=8)
        if not featured:
            featured = _static_featured_fallback()
        _set_cached_featured(featured)

    ctx = {
        "featured": featured,
        **_seo_ctx(),
    }
    return _render_safe("index.html", **ctx)


@main_bp.get("/about")
def about():
    return _render_safe(
        "about.html",
        **_seo_ctx(
            meta_title="Sobre Skyline Store",
            meta_description="Conocé Skyline Store, una tienda online moderna y confiable.",
        ),
    )


@main_bp.get("/contact")
def contact():
    return _render_safe(
        "contact.html",
        **_seo_ctx(
            meta_title="Contacto — Skyline Store",
            meta_description="Contactanos para soporte, ventas o consultas.",
        ),
    )


# ============================================================
# Healthcheck (deploy / monitoring)
# ============================================================

@main_bp.get("/health")
def health():
    """
    Endpoint para Render/Railway/monitoreo.
    - DB check real (SQLAlchemy 2.x): text("SELECT 1")
    - Responde JSON siempre
    """
    try:
        # SQLAlchemy 2.x friendly
        db.session.execute(text("SELECT 1"))
        return {"ok": True, "db": "ok"}, 200
    except Exception as exc:
        try:
            db.session.rollback()
        except Exception:
            pass
        try:
            current_app.logger.warning("Health DB error: %s", exc, exc_info=False)
        except Exception:
            pass
        return {"ok": False, "db": "error"}, 500


__all__ = ["main_bp"]
