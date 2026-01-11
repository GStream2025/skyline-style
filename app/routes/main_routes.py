# app/routes/main_routes.py — Skyline Store (ULTRA PRO / NO BREAK / FAIL-SAFE)
from __future__ import annotations

import os
import time
import logging
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from flask import (
    Blueprint,
    current_app,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
    jsonify,
)

# Si tu proyecto tiene db en app.models:
try:
    from app.models import db  # type: ignore
except Exception:  # pragma: no cover
    db = None  # type: ignore


log = logging.getLogger("main_routes")

main_bp = Blueprint(
    "main",
    __name__,
    template_folder="../templates",
)

# -----------------------------------------------------------------------------
# Config / Defaults
# -----------------------------------------------------------------------------

_TRUE = {"1", "true", "yes", "y", "on"}

def _env_bool(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    return str(v).strip().lower() in _TRUE

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

@dataclass(frozen=True)
class SeoDefaults:
    title: str
    description: str
    og_image: str

SEO_DEFAULTS = SeoDefaults(
    title=os.getenv("SEO_TITLE", "Skyline Store · Tech + Streetwear premium"),
    description=os.getenv(
        "SEO_DESCRIPTION",
        "Comprá moda urbana, accesorios y tecnología en un solo lugar. Envíos rápidos y pagos seguros.",
    ),
    og_image=os.getenv("OG_IMAGE", "img/og.png"),
)

HOME_CACHE_TTL = int(os.getenv("HOME_CACHE_TTL", "120") or "120")
HOME_CACHE_TTL = max(0, min(HOME_CACHE_TTL, 3600))  # 0 = sin cache
ENABLE_HOME_CACHE = _env_bool("ENABLE_HOME_CACHE", True)

# cache simple en memoria (por proceso)
_HOME_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
# key -> (expires_at, payload)

def _cache_get(key: str) -> Optional[Dict[str, Any]]:
    if not (ENABLE_HOME_CACHE and HOME_CACHE_TTL > 0):
        return None
    item = _HOME_CACHE.get(key)
    if not item:
        return None
    expires_at, payload = item
    if time.time() > expires_at:
        _HOME_CACHE.pop(key, None)
        return None
    return payload

def _cache_set(key: str, payload: Dict[str, Any]) -> None:
    if not (ENABLE_HOME_CACHE and HOME_CACHE_TTL > 0):
        return
    _HOME_CACHE[key] = (time.time() + HOME_CACHE_TTL, payload)

def _is_safe_next(url: str) -> bool:
    # evita open-redirect. Solo paths locales.
    if not url:
        return False
    return url.startswith("/") and not url.startswith("//")

def _best_scheme() -> str:
    # ProxyFix ya está habilitado en prod por tus logs
    return request.headers.get("X-Forwarded-Proto", request.scheme or "https")

def _absolute_url(endpoint: str, **values: Any) -> str:
    values.setdefault("_external", True)
    values.setdefault("_scheme", _best_scheme())
    return url_for(endpoint, **values)

def _etag_for(text: str) -> str:
    h = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return f"W/\"{h[:32]}\""

def _resp_no_store(resp):
    resp.headers["Cache-Control"] = "no-store"
    return resp

def _resp_cache_public(resp, seconds: int):
    resp.headers["Cache-Control"] = f"public, max-age={max(0, int(seconds))}"
    return resp

def _render(template: str, *, status: int = 200, **ctx: Any):
    """
    Render seguro: inyecta SEO defaults y valores comunes.
    """
    ctx.setdefault("meta_title", SEO_DEFAULTS.title)
    ctx.setdefault("meta_description", SEO_DEFAULTS.description)
    # og_image puede ser path estático; lo convertimos a URL externa si parece relativo.
    og = ctx.get("og_image") or SEO_DEFAULTS.og_image
    if isinstance(og, str) and not og.startswith(("http://", "https://")):
        # si ya viene con "static/..." o "img/..."
        if og.startswith("static/"):
            ctx["og_image"] = _absolute_url("static", filename=og.replace("static/", "", 1))
        else:
            ctx["og_image"] = _absolute_url("static", filename=og)
    else:
        ctx["og_image"] = og

    # Útil para templates que muestran el año
    ctx.setdefault("now_year", _utcnow().year)
    return make_response(render_template(template, **ctx), status)

# -----------------------------------------------------------------------------
# After-request hardening (sin romper)
# -----------------------------------------------------------------------------

@main_bp.after_request
def _security_headers(resp):
    # No pisa Flask-Talisman si ya lo setea; solo completa.
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")

    # Permisos mínimos (no rompe embeds normales)
    resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

    # Evita caching de respuestas sensibles por defecto
    if request.path.startswith(("/auth", "/admin", "/account", "/checkout")):
        resp.headers.setdefault("Cache-Control", "no-store")

    return resp

# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------

@main_bp.get("/")
def home():
    """
    ✅ HOME REAL
    Renderiza templates/index.html (NO login).
    """
    # cache key por idioma o query si quisieras
    key = "home:v1"
    cached = _cache_get(key)
    if cached:
        resp = _render("index.html", **cached)
        # cache corto para home (si habilitado)
        return _resp_cache_public(resp, HOME_CACHE_TTL)

    payload: Dict[str, Any] = {
        "meta_title": SEO_DEFAULTS.title,
        "meta_description": SEO_DEFAULTS.description,
    }

    _cache_set(key, payload)
    resp = _render("index.html", **payload)
    return _resp_cache_public(resp, HOME_CACHE_TTL if ENABLE_HOME_CACHE else 0)

@main_bp.get("/about")
def about():
    # Existe templates/about.html en tu estructura
    return _render("about.html", meta_title=f"Sobre nosotros | {SEO_DEFAULTS.title}")

@main_bp.get("/health")
def health():
    """
    Healthcheck para Render / uptime.
    Incluye ping DB si está disponible.
    """
    ok = True
    db_ok: Optional[bool] = None
    db_err: Optional[str] = None

    if db is not None:
        try:
            # SQLAlchemy 2: ejecuta un SELECT 1
            db.session.execute(db.text("SELECT 1"))  # type: ignore[attr-defined]
            db_ok = True
        except Exception as e:  # pragma: no cover
            ok = False
            db_ok = False
            db_err = str(e)[:300]

    data = {
        "status": "ok" if ok else "degraded",
        "time_utc": _utcnow().isoformat(),
        "db_ok": db_ok,
        "db_error": db_err,
    }
    resp = jsonify(data)
    return _resp_no_store(resp), (200 if ok else 503)

@main_bp.get("/robots.txt")
def robots():
    """
    robots.txt simple.
    """
    base = _absolute_url("main.home")
    txt = "\n".join([
        "User-agent: *",
        "Allow: /",
        f"Sitemap: {base.rstrip('/')}/sitemap.xml",
        "",
    ])
    resp = make_response(txt, 200)
    resp.headers["Content-Type"] = "text/plain; charset=utf-8"
    resp.headers["ETag"] = _etag_for(txt)
    return _resp_cache_public(resp, 3600)

@main_bp.get("/sitemap.xml")
def sitemap():
    """
    Sitemap minimal (sumá URLs cuando quieras).
    """
    urls = [
        _absolute_url("main.home"),
        _absolute_url("main.about"),
        # si existe shop.shop:
        _absolute_url("shop.shop") if "shop.shop" in current_app.view_functions else None,
    ]
    urls = [u for u in urls if u]

    now = _utcnow().date().isoformat()
    items = []
    for u in urls:
        items.append(
            f"<url><loc>{u}</loc><lastmod>{now}</lastmod><changefreq>daily</changefreq><priority>0.8</priority></url>"
        )

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        + "".join(items) +
        "</urlset>"
    )

    resp = make_response(xml, 200)
    resp.headers["Content-Type"] = "application/xml; charset=utf-8"
    resp.headers["ETag"] = _etag_for(xml)
    return _resp_cache_public(resp, 3600)

@main_bp.get("/go")
def go():
    """
    Redirect seguro interno: /go?next=/shop
    (evita open redirect).
    """
    nxt = request.args.get("next", "").strip()
    if _is_safe_next(nxt):
        return redirect(nxt)
    return redirect(url_for("main.home"))

# -----------------------------------------------------------------------------
# Error pages (sin romper)
# -----------------------------------------------------------------------------

@main_bp.app_errorhandler(404)
def not_found(e):
    # existe templates/error.html en tu estructura
    return _render(
        "error.html",
        status=404,
        meta_title=f"No encontrado | {SEO_DEFAULTS.title}",
        error_code=404,
        error_title="Página no encontrada",
        error_message="La página que buscás no existe o fue movida.",
    )

@main_bp.app_errorhandler(500)
def server_error(e):
    log.exception("500 error: %s", e)
    return _render(
        "error.html",
        status=500,
        meta_title=f"Error | {SEO_DEFAULTS.title}",
        error_code=500,
        error_title="Error interno",
        error_message="Ocurrió un error. Probá de nuevo en unos segundos.",
    )
