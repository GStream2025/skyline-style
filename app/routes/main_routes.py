# app/routes/main_routes.py — Skyline Store (ULTRA PRO++ / NO BREAK / FAIL-SAFE v3)
from __future__ import annotations

import hashlib
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

from flask import (
    Blueprint,
    current_app,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)

# SQL text helper (evita db.text inexistente en Flask-SQLAlchemy)
try:
    from sqlalchemy import text as sql_text
except Exception:  # pragma: no cover
    sql_text = None  # type: ignore

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


def _now_year() -> int:
    return _utcnow().year


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
    # puede ser "img/og.png" (static filename) o URL absoluta
    og_image=os.getenv("OG_IMAGE", "img/og.png"),
)

HOME_CACHE_TTL = int(os.getenv("HOME_CACHE_TTL", "120") or "120")
HOME_CACHE_TTL = max(0, min(HOME_CACHE_TTL, 3600))  # 0 = sin cache
ENABLE_HOME_CACHE = _env_bool("ENABLE_HOME_CACHE", True)

# Respeta Render config
FORCE_HTTPS = _env_bool("FORCE_HTTPS", False)
PREFERRED_URL_SCHEME = (os.getenv("PREFERRED_URL_SCHEME") or "").strip().lower() or ("https" if FORCE_HTTPS else "")

# cache simple en memoria (por proceso)
_HOME_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}  # key -> (expires_at, payload)


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
    """
    Anti open-redirect:
    - permite SOLO paths locales tipo "/shop"
    - bloquea scheme/host, "//", "\" y control chars
    """
    if not url:
        return False
    u = url.strip()
    if not u or any(ch in u for ch in ("\x00", "\r", "\n")):
        return False
    if "\\" in u:
        return False
    if u.startswith("//"):
        return False
    parsed = urlparse(u)
    if parsed.scheme or parsed.netloc:
        return False
    return u.startswith("/")


def _safe_next_from_args() -> str:
    nxt = (request.args.get("next") or "").strip()
    return nxt if _is_safe_next(nxt) else ""


def _best_scheme() -> str:
    """
    Render/ProxyFix: X-Forwarded-Proto suele venir.
    Además respeta PREFERRED_URL_SCHEME / FORCE_HTTPS.
    """
    if PREFERRED_URL_SCHEME in {"http", "https"}:
        return PREFERRED_URL_SCHEME
    if FORCE_HTTPS:
        return "https"
    return request.headers.get("X-Forwarded-Proto", request.scheme or "https")


def _absolute_url(endpoint: str, **values: Any) -> str:
    values.setdefault("_external", True)
    values.setdefault("_scheme", _best_scheme())
    return url_for(endpoint, **values)


def _etag_for(text: str) -> str:
    h = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return f'W/"{h[:32]}"'


def _resp_no_store(resp):
    resp.headers["Cache-Control"] = "no-store"
    return resp


def _resp_cache_public(resp, seconds: int):
    resp.headers["Cache-Control"] = f"public, max-age={max(0, int(seconds))}"
    return resp


def _maybe_304(req_etag: Optional[str], etag: str):
    """
    Conditional GET (ETag):
    - si coincide, devolvemos 304 sin body
    """
    if not req_etag:
        return None
    try:
        return make_response("", 304) if req_etag == etag else None
    except Exception:
        return None


def _safe_og_image(value: str) -> str:
    """
    Acepta:
    - URL absoluta: https://...
    - filename de static: "img/og.png" o "static/img/og.png"
    """
    og = (value or "").strip()
    if not og:
        og = SEO_DEFAULTS.og_image

    if og.startswith(("http://", "https://")):
        return og

    # tolera "static/..."
    if og.startswith("static/"):
        og = og.replace("static/", "", 1)

    return _absolute_url("static", filename=og)


def _render(template: str, *, status: int = 200, **ctx: Any):
    """
    Render seguro: inyecta SEO defaults + valores comunes.
    NO depende de variables que a veces faltan en producción.
    """
    ctx.setdefault("meta_title", SEO_DEFAULTS.title)
    ctx.setdefault("meta_description", SEO_DEFAULTS.description)
    ctx["og_image"] = _safe_og_image(str(ctx.get("og_image") or SEO_DEFAULTS.og_image))
    ctx.setdefault("now_year", _now_year())

    # Exponer ENV de forma segura (para robots/meta)
    env = (os.getenv("ENV") or os.getenv("FLASK_ENV") or "").strip().lower() or "production"
    ctx.setdefault("ENV", env)

    # view_functions para templates “safe resolver”
    ctx.setdefault("view_functions", getattr(current_app, "view_functions", {}) or {})

    # config para feature flags en templates (tu account.html lo usa)
    ctx.setdefault("config", getattr(current_app, "config", {}) or {})

    return make_response(render_template(template, **ctx), status)


# -----------------------------------------------------------------------------
# After-request hardening (sin romper)
# -----------------------------------------------------------------------------

@main_bp.after_request
def _security_headers(resp):
    # No pisa Talisman; solo completa si falta
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

    # No cachear pantallas sensibles
    if request.path.startswith(("/auth", "/admin", "/account", "/checkout", "/cart")):
        resp.headers.setdefault("Cache-Control", "no-store")

    # Señal útil para debugging de proxies (no sensible)
    resp.headers.setdefault("X-Served-By", "skyline")

    return resp


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------

@main_bp.get("/")
def home():
    """
    ✅ HOME REAL
    Renderiza templates/index.html
    - Cache opcional con TTL
    - ETag + 304
    """
    lang = (request.headers.get("Accept-Language") or "es").split(",")[0].strip().lower()
    key = f"home:v3:lang={lang}"

    cached = _cache_get(key)
    if cached:
        etag = _etag_for(f"{cached.get('meta_title','')}-{cached.get('meta_description','')}-{lang}")
        maybe = _maybe_304(request.headers.get("If-None-Match"), etag)
        if maybe is not None:
            maybe.headers["ETag"] = etag
            return _resp_cache_public(maybe, HOME_CACHE_TTL)

        resp = _render("index.html", **cached)
        resp.headers["ETag"] = etag
        return _resp_cache_public(resp, HOME_CACHE_TTL)

    payload: Dict[str, Any] = {
        "meta_title": SEO_DEFAULTS.title,
        "meta_description": SEO_DEFAULTS.description,
    }

    _cache_set(key, payload)

    etag = _etag_for(f"{payload.get('meta_title','')}-{payload.get('meta_description','')}-{lang}")
    maybe = _maybe_304(request.headers.get("If-None-Match"), etag)
    if maybe is not None:
        maybe.headers["ETag"] = etag
        return _resp_cache_public(maybe, HOME_CACHE_TTL if ENABLE_HOME_CACHE else 0)

    resp = _render("index.html", **payload)
    resp.headers["ETag"] = etag
    return _resp_cache_public(resp, HOME_CACHE_TTL if ENABLE_HOME_CACHE else 0)


@main_bp.get("/account")
def account():
    """
    ✅ Página de cuenta (tabs login/register)
    Renderiza templates/account.html
    """
    nxt = _safe_next_from_args()
    return _render(
        "account.html",
        meta_title=f"Mi cuenta | {SEO_DEFAULTS.title}",
        next=nxt,
    )


@main_bp.get("/cuenta")
def cuenta_alias():
    """
    Alias por si en algún lado linkeaste /cuenta
    """
    nxt = _safe_next_from_args()
    if nxt:
        return redirect(url_for("main.account", next=nxt), code=302)
    return redirect(url_for("main.account"), code=302)


@main_bp.get("/about")
def about():
    return _render("about.html", meta_title=f"Sobre nosotros | {SEO_DEFAULTS.title}")


@main_bp.get("/health")
def health():
    """
    Healthcheck para Render / uptime.
    - DB ping si db + sql_text existen
    - Nunca rompe
    """
    ok = True
    db_ok: Optional[bool] = None
    db_err: Optional[str] = None

    if db is not None and sql_text is not None:
        try:
            db.session.execute(sql_text("SELECT 1"))  # type: ignore[attr-defined]
            db_ok = True
        except Exception as e:  # pragma: no cover
            ok = False
            db_ok = False
            db_err = f"{type(e).__name__}: {str(e)[:260]}"
    else:
        db_ok = None

    data = {
        "status": "ok" if ok else "degraded",
        "time_utc": _utcnow().isoformat(),
        "db_ok": db_ok,
        "db_error": db_err,
    }

    resp = jsonify(data)
    resp = _resp_no_store(resp)
    return resp, (200 if ok else 503)


@main_bp.get("/robots.txt")
def robots():
    env = (os.getenv("ENV") or os.getenv("FLASK_ENV") or "production").strip().lower()
    base = _absolute_url("main.home").rstrip("/")

    lines = ["User-agent: *"]
    if env == "production":
        lines += ["Allow: /"]
    else:
        lines += ["Disallow: /"]

    lines += [f"Sitemap: {base}/sitemap.xml", ""]
    txt = "\n".join(lines)

    etag = _etag_for(txt)
    maybe = _maybe_304(request.headers.get("If-None-Match"), etag)
    if maybe is not None:
        maybe.headers["Content-Type"] = "text/plain; charset=utf-8"
        maybe.headers["ETag"] = etag
        return _resp_cache_public(maybe, 3600)

    resp = make_response(txt, 200)
    resp.headers["Content-Type"] = "text/plain; charset=utf-8"
    resp.headers["ETag"] = etag
    return _resp_cache_public(resp, 3600)


@main_bp.get("/sitemap.xml")
def sitemap():
    def _xml_escape(s: str) -> str:
        return (
            (s or "")
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&apos;")
        )

    vf = getattr(current_app, "view_functions", {}) or {}

    urls = [
        _absolute_url("main.home"),
        _absolute_url("main.about"),
        _absolute_url("main.account"),
    ]

    if "shop.shop" in vf:
        try:
            urls.append(_absolute_url("shop.shop"))
        except Exception:
            pass

    now = _utcnow().date().isoformat()
    items = []
    for u in urls:
        u = str(u)
        items.append(
            "<url>"
            f"<loc>{_xml_escape(u)}</loc>"
            f"<lastmod>{now}</lastmod>"
            "<changefreq>daily</changefreq>"
            "<priority>0.8</priority>"
            "</url>"
        )

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        + "".join(items) +
        "</urlset>"
    )

    etag = _etag_for(xml)
    maybe = _maybe_304(request.headers.get("If-None-Match"), etag)
    if maybe is not None:
        maybe.headers["Content-Type"] = "application/xml; charset=utf-8"
        maybe.headers["ETag"] = etag
        return _resp_cache_public(maybe, 3600)

    resp = make_response(xml, 200)
    resp.headers["Content-Type"] = "application/xml; charset=utf-8"
    resp.headers["ETag"] = etag
    return _resp_cache_public(resp, 3600)


@main_bp.get("/go")
def go():
    nxt = (request.args.get("next", "") or "").strip()
    if _is_safe_next(nxt):
        return redirect(nxt)
    return redirect(url_for("main.home"))


@main_bp.get("/favicon.ico")
def favicon():
    try:
        url = url_for("static", filename="favicon.ico")
        return redirect(url)
    except Exception:
        return ("", 204)


# -----------------------------------------------------------------------------
# Error pages (sin romper)
# -----------------------------------------------------------------------------

@main_bp.app_errorhandler(404)
def not_found(e):
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
