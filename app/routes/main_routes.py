# app/routes/main_routes.py — Skyline Store (ULTRA PRO++ / NO BREAK / FAIL-SAFE v3.6.1 BULLETPROOF)
from __future__ import annotations

import hashlib
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse, urlencode  # ✅ FIX: faltaba urlencode

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

try:
    from sqlalchemy import text as sql_text
except Exception:  # pragma: no cover
    sql_text = None  # type: ignore

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

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off", "unchecked"}


def _env_bool(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    s = str(v).strip().lower()
    if not s:
        return default
    if s in _FALSE:
        return False
    return s in _TRUE


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _now_year() -> int:
    return _utcnow().year


HOME_REDIRECT_TO_SHOP = _env_bool("HOME_REDIRECT_TO_SHOP", False)
HOME_CANONICAL_PATH = (os.getenv("HOME_CANONICAL_PATH") or "/").strip() or "/"

HOME_CACHE_TTL = int(os.getenv("HOME_CACHE_TTL", "120") or "120")
HOME_CACHE_TTL = max(0, min(HOME_CACHE_TTL, 3600))
ENABLE_HOME_CACHE = _env_bool("ENABLE_HOME_CACHE", True)

FORCE_HTTPS = _env_bool("FORCE_HTTPS", False)
PREFERRED_URL_SCHEME = (os.getenv("PREFERRED_URL_SCHEME") or "").strip().lower() or ("https" if FORCE_HTTPS else "")

HOME_ASSET_VER = (os.getenv("HOME_CSS_VER") or os.getenv("HOME_ASSET_VER") or "162").strip() or "162"

_HOME_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_HOME_CACHE_MAX_KEYS = int(os.getenv("HOME_CACHE_MAX_KEYS", "32") or "32")
_HOME_CACHE_MAX_KEYS = max(8, min(_HOME_CACHE_MAX_KEYS, 256))


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

    now = time.time()

    for k in list(_HOME_CACHE.keys()):
        exp, _ = _HOME_CACHE[k]
        if now > exp:
            _HOME_CACHE.pop(k, None)

    while len(_HOME_CACHE) >= _HOME_CACHE_MAX_KEYS:
        _HOME_CACHE.pop(next(iter(_HOME_CACHE)), None)

    _HOME_CACHE[key] = (now + HOME_CACHE_TTL, payload)


def _is_safe_next(url: str) -> bool:
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


def _maybe_304(req_etag: Optional[str], etag: str):
    if not req_etag:
        return None
    try:
        inm = req_etag.strip()
        if inm == etag or etag in {x.strip() for x in inm.split(",")}:
            return make_response("", 304)
        return None
    except Exception:
        return None


def _resp_no_store(resp, *, vary_cookie: bool = True):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    if vary_cookie:
        resp.headers.setdefault("Vary", "Cookie")
    return resp


def _resp_cache_public(resp, seconds: int):
    s = max(0, int(seconds))
    resp.headers["Cache-Control"] = f"public, max-age={s}, stale-while-revalidate=30"
    return resp


def _safe_og_image(value: str) -> str:
    og = (value or "").strip() or SEO_DEFAULTS.og_image
    if og.startswith(("http://", "https://")):
        return og
    if og.startswith("static/"):
        og = og.replace("static/", "", 1)
    return _absolute_url("static", filename=og)


def _render(template: str, *, status: int = 200, **ctx: Any):
    ctx.setdefault("meta_title", SEO_DEFAULTS.title)
    ctx.setdefault("meta_description", SEO_DEFAULTS.description)
    ctx["og_image"] = _safe_og_image(str(ctx.get("og_image") or SEO_DEFAULTS.og_image))
    ctx.setdefault("now_year", _now_year())

    env = (os.getenv("ENV") or os.getenv("FLASK_ENV") or "").strip().lower() or "production"
    ctx.setdefault("ENV", env)

    ctx.setdefault("view_functions", getattr(current_app, "view_functions", {}) or {})
    ctx.setdefault("config", getattr(current_app, "config", {}) or {})
    ctx.setdefault("HOME_CSS_VER", HOME_ASSET_VER)

    try:
        return make_response(render_template(template, **ctx), status)
    except Exception:
        log.exception("Template render failed: %s", template)
        try:
            return make_response(
                render_template(
                    "error.html",
                    error_code=500,
                    error_title="Error",
                    error_message="Ocurrió un error.",
                ),
                500,
            )
        except Exception:
            return make_response("Ocurrió un error cargando la página.", 500)


@main_bp.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    resp.headers.setdefault("X-Served-By", "skyline")
    resp.headers.setdefault("X-Home-Asset-Ver", str(HOME_ASSET_VER))

    if request.path.startswith(("/auth", "/admin", "/account", "/checkout", "/cart")):
        resp.headers.setdefault("Cache-Control", "no-store")
        resp.headers.setdefault("Vary", "Cookie")

    return resp


@main_bp.get("/")
def home():
    if HOME_REDIRECT_TO_SHOP:
        try:
            return redirect(url_for("shop.shop"), code=302)
        except Exception:
            return redirect("/shop", code=302)

    try:
        if HOME_CANONICAL_PATH and HOME_CANONICAL_PATH != "/" and request.path == "/":
            return redirect(HOME_CANONICAL_PATH, code=302)
    except Exception:
        pass

    lang = (request.headers.get("Accept-Language") or "es").split(",")[0].strip().lower()
    lang = (lang or "es")[:12]

    key = f"home:v3.6.1:lang={lang}:ver={HOME_ASSET_VER}"

    cached = _cache_get(key)
    if cached:
        etag = _etag_for(f"{cached.get('meta_title','')}|{cached.get('meta_description','')}|{lang}|{HOME_ASSET_VER}")
        maybe = _maybe_304(request.headers.get("If-None-Match"), etag)
        if maybe is not None:
            maybe.headers["ETag"] = etag
            maybe.headers.setdefault("Vary", "Accept-Language")
            return _resp_cache_public(maybe, HOME_CACHE_TTL)

        resp = _render("index.html", **cached)
        resp.headers["ETag"] = etag
        resp.headers.setdefault("Vary", "Accept-Language")
        return _resp_cache_public(resp, HOME_CACHE_TTL)

    payload: Dict[str, Any] = {
        "meta_title": SEO_DEFAULTS.title,
        "meta_description": SEO_DEFAULTS.description,
        "HOME_CSS_VER": HOME_ASSET_VER,
    }
    _cache_set(key, payload)

    etag = _etag_for(f"{payload.get('meta_title','')}|{payload.get('meta_description','')}|{lang}|{HOME_ASSET_VER}")
    maybe = _maybe_304(request.headers.get("If-None-Match"), etag)
    if maybe is not None:
        maybe.headers["ETag"] = etag
        maybe.headers.setdefault("Vary", "Accept-Language")
        return _resp_cache_public(maybe, HOME_CACHE_TTL if ENABLE_HOME_CACHE else 0)

    resp = _render("index.html", **payload)
    resp.headers["ETag"] = etag
    resp.headers.setdefault("Vary", "Accept-Language")
    return _resp_cache_public(resp, HOME_CACHE_TTL if ENABLE_HOME_CACHE else 0)


@main_bp.get("/account")
def account_alias():
    nxt = _safe_next_from_args()
    tab = (request.args.get("tab") or request.args.get("mode") or "").strip().lower()
    tab = "register" if tab in {"register", "signup", "crear"} else "login"

    try:
        return redirect(url_for("auth.account", tab=tab, next=nxt), code=302)
    except Exception:
        qs = urlencode({"tab": tab, "next": nxt}) if nxt else urlencode({"tab": tab})
        return redirect(f"/auth/account?{qs}", code=302)


@main_bp.get("/cuenta")
def cuenta_alias():
    nxt = _safe_next_from_args()
    try:
        return redirect(url_for("main.account_alias", next=nxt) if nxt else url_for("main.account_alias"), code=302)
    except Exception:
        qs = urlencode({"next": nxt}) if nxt else ""
        return redirect(f"/account{('?' + qs) if qs else ''}", code=302)


@main_bp.get("/about")
def about():
    return _render("about.html", meta_title=f"Sobre nosotros | {SEO_DEFAULTS.title}")


@main_bp.get("/health")
def health():
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
        "home_cache_enabled": bool(ENABLE_HOME_CACHE and HOME_CACHE_TTL > 0),
        "home_asset_ver": str(HOME_ASSET_VER),
    }

    resp = jsonify(data)
    _resp_no_store(resp, vary_cookie=False)
    resp.status_code = 200 if ok else 503
    return resp


@main_bp.get("/robots.txt")
def robots():
    env = (os.getenv("ENV") or os.getenv("FLASK_ENV") or "production").strip().lower()
    base = _absolute_url("main.home").rstrip("/")

    lines = ["User-agent: *"]
    lines += ["Allow: /"] if env == "production" else ["Disallow: /"]
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
        _absolute_url("auth.account") if "auth.account" in vf else _absolute_url("main.account_alias"),
    ]

    if "shop.shop" in vf:
        try:
            urls.append(_absolute_url("shop.shop"))
        except Exception:
            pass

    now = _utcnow().date().isoformat()
    items = []
    for u in urls:
        items.append(
            "<url>"
            f"<loc>{_xml_escape(str(u))}</loc>"
            f"<lastmod>{now}</lastmod>"
            "<changefreq>daily</changefreq>"
            "<priority>0.8</priority>"
            "</url>"
        )

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        + "".join(items)
        + "</urlset>"
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
        return redirect(nxt, code=302)
    return redirect(url_for("main.home"), code=302)


@main_bp.get("/favicon.ico")
def favicon():
    try:
        return redirect(url_for("static", filename="favicon.ico"), code=302)
    except Exception:
        return ("", 204)


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


__all__ = ["main_bp"]
