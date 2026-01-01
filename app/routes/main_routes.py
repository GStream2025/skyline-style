# app/routes/main_routes.py
"""
Skyline Store · Main Routes (ULTRA PRO / FINAL / BULLETPROOF)

- Home marketplace-ready
- Featured cacheado
- SEO centralizado
- Render seguro (nunca 500 por template)
- Healthcheck real SQLAlchemy 2.x
"""

from __future__ import annotations

import os
import time
import logging
from typing import Any, Dict, List, Optional

from flask import Blueprint, current_app, jsonify, render_template, request
from sqlalchemy import text
from sqlalchemy.orm import selectinload

from app.models import db, Product

main_bp = Blueprint("main", __name__)
log = logging.getLogger("main_routes")

# --------------------------------------------------
# Config
# --------------------------------------------------

_TRUE = {"1", "true", "yes", "y", "on"}

_HOME_CACHE_TTL = int(os.getenv("HOME_CACHE_TTL", "120"))
_HOME_CACHE: Dict[str, Any] = {
    "ts": 0.0,
    "featured": [],
}

SEO_DEFAULTS = {
    "meta_title": os.getenv(
        "SEO_TITLE",
        "Skyline Store · Moda urbana, accesorios y tecnología",
    ),
    "meta_description": os.getenv(
        "SEO_DESCRIPTION",
        "Comprá moda urbana, accesorios y tecnología en un solo lugar. Envíos rápidos y pagos seguros.",
    ),
    "og_image": os.getenv(
        "SEO_OG_IMAGE",
        "/static/img/banners/hero_home.png",
    ),
}

# --------------------------------------------------
# Helpers
# --------------------------------------------------

def _is_json_request() -> bool:
    accept = (request.headers.get("Accept") or "").lower()
    return "application/json" in accept or request.args.get("json") == "1"


def _template_exists(name: str) -> bool:
    try:
        current_app.jinja_env.get_template(name)
        return True
    except Exception:
        return False


def _render_safe(template: str, *, status: int = 200, **ctx):
    """
    Render blindado:
    - si falta template → JSON u HTML mínimo
    - nunca rompe la app
    """
    if _template_exists(template):
        return render_template(template, **ctx), status

    if _is_json_request():
        return jsonify(ok=True, template_missing=template, data=ctx), status

    title = ctx.get("meta_title") or SEO_DEFAULTS["meta_title"]
    desc = ctx.get("meta_description") or SEO_DEFAULTS["meta_description"]

    html = f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>{title}</title>
  <meta name="description" content="{desc}">
</head>
<body style="font-family:system-ui;padding:24px">
  <h1>{title}</h1>
  <p>{desc}</p>
  <p style="opacity:.7">Template faltante: <code>{template}</code></p>
</body>
</html>"""
    return html, status, {"Content-Type": "text/html; charset=utf-8"}


def _product_image(p: Product) -> str:
    """
    Devuelve URL o filename local.
    """
    try:
        if hasattr(p, "main_image_url") and callable(p.main_image_url):
            img = p.main_image_url()
            if img:
                return str(img)
    except Exception:
        pass

    try:
        media = getattr(p, "media", None)
        if media and isinstance(media, list) and media:
            url = getattr(media[0], "url", None)
            if url:
                return str(url)
    except Exception:
        pass

    return getattr(p, "image_url", None) or "hero-placeholder.png"


def _product_href(p: Product) -> str:
    slug = (getattr(p, "slug", "") or "").strip()
    if not slug:
        return "/shop"

    try:
        from flask import url_for
        return url_for("shop.product_detail", slug=slug)
    except Exception:
        return f"/shop?q={slug}"


def _money(p: Product) -> str:
    price = getattr(p, "price", None)
    return f"$ {price}" if price is not None else ""


# --------------------------------------------------
# Featured builder
# --------------------------------------------------

def _build_featured(limit: int = 8) -> List[Dict[str, Any]]:
    try:
        q = Product.query

        if hasattr(Product, "status"):
            q = q.filter(Product.status == "active")

        opts = []
        if hasattr(Product, "media"):
            opts.append(selectinload(Product.media))
        if opts:
            q = q.options(*opts)

        if hasattr(Product, "updated_at"):
            q = q.order_by(Product.updated_at.desc())
        elif hasattr(Product, "created_at"):
            q = q.order_by(Product.created_at.desc())
        else:
            q = q.order_by(Product.id.desc())

        items = q.limit(max(1, min(24, limit))).all()

        out: List[Dict[str, Any]] = []
        for p in items:
            out.append(
                {
                    "img": _product_image(p),
                    "title": (getattr(p, "title", "Producto") or "Producto")[:120],
                    "price": _money(p),
                    "href": _product_href(p),
                }
            )
        return out

    except Exception as e:
        log.info("Featured dinámico falló: %s", e)
        return []


def _static_featured() -> List[Dict[str, Any]]:
    return [
        {"img": "hero-hoodie.png", "title": "Hoodies Premium", "price": "$ 1.990", "href": "/shop"},
        {"img": "hero-sneakers.png", "title": "Zapatillas Urbanas", "price": "$ 2.590", "href": "/shop"},
        {"img": "hero-headphones.png", "title": "Audio Inalámbrico", "price": "$ 1.290", "href": "/shop"},
        {"img": "hero-watch.png", "title": "Smartwatch", "price": "$ 1.490", "href": "/shop"},
    ]


def _get_cached_featured() -> Optional[List[Dict[str, Any]]]:
    if (time.time() - _HOME_CACHE["ts"]) <= max(10, _HOME_CACHE_TTL):
        return _HOME_CACHE.get("featured") or None
    return None


def _set_cached_featured(items: List[Dict[str, Any]]) -> None:
    _HOME_CACHE["ts"] = time.time()
    _HOME_CACHE["featured"] = items


# --------------------------------------------------
# Routes
# --------------------------------------------------

@main_bp.get("/")
def home():
    featured = _get_cached_featured()
    if not featured:
        featured = _build_featured(limit=8)
        if not featured:
            featured = _static_featured()
        _set_cached_featured(featured)

    ctx = {
        "featured": featured,
        **SEO_DEFAULTS,
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


# --------------------------------------------------
# Healthcheck
# --------------------------------------------------

@main_bp.get("/health")
def health():
    try:
        db.session.execute(text("SELECT 1"))
        return {
            "ok": True,
            "db": "ok",
            "env": current_app.config.get("ENV"),
            "cache_ttl": _HOME_CACHE_TTL,
        }, 200
    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        log.warning("Health DB error: %s", e)
        return {"ok": False, "db": "error"}, 500


__all__ = ["main_bp"]
