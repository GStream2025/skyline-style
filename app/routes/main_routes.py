from __future__ import annotations

import hashlib
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlencode, urlparse

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
    from sqlalchemy import text as sql_text  # type: ignore
except Exception:  # pragma: no cover
    sql_text = None  # type: ignore

try:
    from app.models import db  # type: ignore
except Exception:  # pragma: no cover
    db = None  # type: ignore

try:
    from app.models import Category, Product  # type: ignore
except Exception:  # pragma: no cover
    Category = None  # type: ignore
    Product = None  # type: ignore


log = logging.getLogger("main_routes")
main_bp = Blueprint("main", __name__, template_folder="../templates")
main_bp.strict_slashes = False

_TRUE = {"1", "true", "yes", "y", "on", "checked", "enable", "enabled"}
_FALSE = {"0", "false", "no", "n", "off", "unchecked", "disable", "disabled"}


# =========================================================
# 0) Helpers config/env (robustos)
# =========================================================
def _env_str(k: str, d: str = "") -> str:
    return (os.getenv(k) or d).strip()


def _cfg_str(k: str, d: str = "") -> str:
    try:
        v = current_app.config.get(k, None)
        if v is not None:
            s = str(v).strip()
            return s if s else d
    except Exception:
        pass
    return _env_str(k, d)


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


def _cfg_bool(key: str, default: bool = False) -> bool:
    try:
        v = current_app.config.get(key, None)
        if v is None:
            return _env_bool(key, default)
        if isinstance(v, bool):
            return v
        s = str(v).strip().lower()
        if not s:
            return default
        if s in _FALSE:
            return False
        return s in _TRUE
    except Exception:
        return _env_bool(key, default)


def _clamp_int(v: Any, default: int, *, min_v: int, max_v: int) -> int:
    try:
        n = int(v)
    except Exception:
        n = default
    return min(max(n, min_v), max_v)


def _norm_str(v: Any, *, max_len: int = 600) -> str:
    if v is None:
        return ""
    s = v if isinstance(v, str) else str(v)
    s = s.replace("\x00", "").replace("\u200b", "").strip().replace("\r", "").replace("\n", "")
    return s[:max_len]


def _sanitize_path(p: str, *, default: str = "/") -> str:
    s = (p or "").strip()
    if not s:
        return default
    if "://" in s or s.startswith("//") or "\\" in s:
        return default
    if not s.startswith("/"):
        s = "/" + s
    if ".." in s or any(ch in s for ch in ("\x00", "\r", "\n", "\t")):
        return default
    return (s[:256] or default)


HOME_CANONICAL_PATH = _sanitize_path(_env_str("HOME_CANONICAL_PATH", "/") or "/", default="/")
HOME_REDIRECT_TO_SHOP = (_env_str("HOME_REDIRECT_TO_SHOP", "").lower() in _TRUE) or _env_bool("HOME_REDIRECT_TO_SHOP", False)
HOME_CACHE_TTL = _clamp_int(_env_str("HOME_CACHE_TTL", "120") or "120", 120, min_v=0, max_v=3600)

ENABLE_HOME_CACHE_RAW = _env_str("ENABLE_HOME_CACHE", "")
ENABLE_HOME_CACHE = True if not ENABLE_HOME_CACHE_RAW else (ENABLE_HOME_CACHE_RAW.lower() in _TRUE)

ASSET_VER = (_env_str("ASSET_VER") or _env_str("HOME_ASSET_VER") or _env_str("HOME_CSS_VER") or "162").strip() or "162"

_HOME_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_HOME_CACHE_LOCK = RLock()
_HOME_CACHE_MAX_KEYS = _clamp_int(_env_str("HOME_CACHE_MAX_KEYS", "32") or "32", 32, min_v=8, max_v=256)

_SITEMAP_MAX_CATEGORIES = _clamp_int(_env_str("SITEMAP_MAX_CATEGORIES", "2000") or "2000", 2000, min_v=100, max_v=5000)
_SITEMAP_MAX_PRODUCTS = _clamp_int(_env_str("SITEMAP_MAX_PRODUCTS", "20000") or "20000", 20000, min_v=500, max_v=50000)


@dataclass(frozen=True)
class SeoDefaults:
    title: str
    description: str
    og_image: str


SEO_DEFAULTS = SeoDefaults(
    title=(_env_str("SEO_TITLE", "Skyline Store · Tech + Streetwear premium") or "Skyline Store").strip(),
    description=(
        _env_str("SEO_DESCRIPTION")
        or "Comprá moda urbana, accesorios y tecnología en un solo lugar. Envíos rápidos y pagos seguros."
    ).strip(),
    og_image=(_env_str("OG_IMAGE", "img/og/og-home.png") or "img/og/og-home.png").strip(),
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _now_year() -> int:
    return _utcnow().year


def _best_scheme() -> str:
    preferred = _env_str("PREFERRED_URL_SCHEME", "").lower()
    if preferred in {"http", "https"}:
        return preferred
    if _env_bool("FORCE_HTTPS", False) or _cfg_bool("FORCE_HTTPS", False):
        return "https"
    try:
        xf = (request.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
        if xf in {"http", "https"}:
            return xf
    except Exception:
        pass
    try:
        return (request.scheme or "https").lower()
    except Exception:
        return "https"


def _safe_url_for(endpoint: str, **values: Any) -> str:
    try:
        return url_for(endpoint, **values)
    except Exception:
        return ""


def _site_base_url() -> str:
    site = (_cfg_str("SITE_URL", "") or _env_str("SITE_URL", "")).strip().rstrip("/")
    if site.startswith(("http://", "https://")) and site:
        return site
    try:
        scheme = _best_scheme()
        host = (request.headers.get("X-Forwarded-Host") or request.host or "").strip()
        if host:
            return f"{scheme}://{host}".rstrip("/")
    except Exception:
        pass
    return "https://skyline-style.onrender.com"


def _absolute_url(endpoint: str, **values: Any) -> str:
    values.setdefault("_external", True)
    values.setdefault("_scheme", _best_scheme())
    u = _safe_url_for(endpoint, **values)
    if u:
        return u
    base = _site_base_url()
    if endpoint == "static" and values.get("filename"):
        p = str(values["filename"]).lstrip("/")
        return f"{base}/static/{p}"
    return base


def _etag_for(text: str) -> str:
    h = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return f'W/"{h[:32]}"'


def _maybe_304(req_etag: Optional[str], etag: str):
    if not req_etag:
        return None
    try:
        inm = req_etag.strip()
        parts = {p.strip() for p in inm.split(",") if p.strip()}
        if inm == etag or etag in parts:
            return make_response("", 304)
    except Exception:
        pass
    return None


def _resp_no_store(resp, *, vary_cookie: bool = True):
    resp.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    if vary_cookie:
        resp.headers.setdefault("Vary", "Cookie")
    return resp


def _resp_cache_public(resp, seconds: int):
    s = _clamp_int(seconds, 0, min_v=0, max_v=86400)
    if s <= 0:
        return _resp_no_store(resp)
    resp.headers["Cache-Control"] = f"public, max-age={s}, stale-while-revalidate=60"
    return resp


def _is_safe_next(url: str) -> bool:
    u = (url or "").strip()
    if not u or len(u) > 512:
        return False
    if any(ch in u for ch in ("\x00", "\r", "\n", "\t", " ")):
        return False
    if u.startswith("//") or "://" in u or "\\" in u:
        return False
    if ".." in u:
        return False
    try:
        parsed = urlparse(u)
        if parsed.scheme or parsed.netloc:
            return False
    except Exception:
        return False
    if not u.startswith("/"):
        return False
    # evita loops a auth/admin
    if u.startswith(("/auth/", "/admin/")) or u in ("/auth", "/admin"):
        return False
    return True


def _safe_next_from_args() -> str:
    nxt = _norm_str(request.args.get("next") or "", max_len=512)
    return nxt if _is_safe_next(nxt) else ""


def _accept_language() -> str:
    raw = _norm_str(request.headers.get("Accept-Language") or "es", max_len=120).strip()
    lang = (raw.split(",")[0] if raw else "es").strip().lower()
    lang = "".join(ch for ch in lang if ch.isalnum() or ch in {"-", "_"})
    base = (lang.split("-")[0] if lang else "es").strip()
    return ("en" if base == "en" else "es")


def _vary_add(resp, token: str) -> None:
    cur = resp.headers.get("Vary")
    if not cur:
        resp.headers["Vary"] = token
        return
    parts = [p.strip() for p in cur.split(",") if p.strip()]
    if token not in parts:
        parts.append(token)
        resp.headers["Vary"] = ", ".join(parts)


def _cache_key_home(lang: str) -> str:
    salt = _env_str("HOME_CACHE_SALT", "")
    return f"home:v6:lang={lang}:ver={ASSET_VER}:salt={salt}"


def _cache_get(key: str) -> Optional[Dict[str, Any]]:
    if not (ENABLE_HOME_CACHE and HOME_CACHE_TTL > 0):
        return None
    with _HOME_CACHE_LOCK:
        item = _HOME_CACHE.get(key)
        if not item:
            return None
        expires_at, payload = item
        if time.time() > float(expires_at):
            _HOME_CACHE.pop(key, None)
            return None
        return payload if isinstance(payload, dict) else None


def _cache_set(key: str, payload: Dict[str, Any]) -> None:
    if not (ENABLE_HOME_CACHE and HOME_CACHE_TTL > 0):
        return
    now = time.time()
    with _HOME_CACHE_LOCK:
        # limpia expiradas
        for k in list(_HOME_CACHE.keys()):
            try:
                exp, _ = _HOME_CACHE[k]
                if now > float(exp):
                    _HOME_CACHE.pop(k, None)
            except Exception:
                _HOME_CACHE.pop(k, None)

        # limita tamaño
        while len(_HOME_CACHE) >= _HOME_CACHE_MAX_KEYS:
            try:
                _HOME_CACHE.pop(next(iter(_HOME_CACHE)))
            except Exception:
                _HOME_CACHE.clear()
                break

        _HOME_CACHE[key] = (now + float(HOME_CACHE_TTL), dict(payload))


def _safe_og_image(value: str) -> str:
    og = (value or "").strip() or SEO_DEFAULTS.og_image
    if og.startswith(("http://", "https://")):
        return og
    if og.startswith("static/"):
        og = og.replace("static/", "", 1)
    og = og.lstrip("/")
    u = _absolute_url("static", filename=og, v=ASSET_VER)
    return u or f"{_site_base_url()}/static/{og}?v={ASSET_VER}"


def _asset_url(filename: str) -> str:
    # ✅ mejora real: versionado consistente para CSS/JS/img (cache busting)
    fn = (filename or "").lstrip("/")
    u = _safe_url_for("static", filename=fn, v=ASSET_VER)
    if u:
        return u
    return f"{_site_base_url()}/static/{fn}?v={ASSET_VER}"


@main_bp.app_context_processor
def inject_globals():
    # ✅ mejora real: tus templates pueden usar asset_url("css/home.css")
    return {
        "asset_url": _asset_url,
        "ASSET_VER": ASSET_VER,
        "SITE_URL": _site_base_url,
    }


def _render(template: str, *, status: int = 200, **ctx: Any):
    ctx.setdefault("APP_NAME", _cfg_str("APP_NAME", "Skyline Store"))
    ctx.setdefault("meta_title", SEO_DEFAULTS.title)
    ctx.setdefault("meta_description", SEO_DEFAULTS.description)
    ctx["og_image"] = _safe_og_image(str(ctx.get("og_image") or SEO_DEFAULTS.og_image))
    ctx.setdefault("now_year", _now_year())
    ctx.setdefault("SITE_URL", _site_base_url())
    ctx.setdefault("ASSET_VER", ASSET_VER)

    env = (_env_str("ENV") or _env_str("FLASK_ENV") or _cfg_str("ENV", "production") or "production").lower()
    ctx.setdefault("ENV", env)

    try:
        return make_response(render_template(template, **ctx), status)
    except Exception:
        log.exception("Template render failed: %s", template)
        # fallback si error.html rompe por algún include
        try:
            return make_response(
                render_template(
                    "error.html",
                    error_code=500,
                    error_title="Error",
                    error_message="Ocurrió un error al cargar la página.",
                    meta_title=f"Error | {SEO_DEFAULTS.title}",
                    meta_description=SEO_DEFAULTS.description,
                    og_image=_safe_og_image(SEO_DEFAULTS.og_image),
                    now_year=_now_year(),
                    SITE_URL=_site_base_url(),
                    ASSET_VER=ASSET_VER,
                    APP_NAME=_cfg_str("APP_NAME", "Skyline Store"),
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
    resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    resp.headers.setdefault("X-Served-By", "skyline")
    resp.headers.setdefault("X-Asset-Ver", str(ASSET_VER))

    try:
        if _best_scheme() == "https" and _cfg_bool("HSTS", False):
            resp.headers.setdefault("Strict-Transport-Security", "max-age=15552000; includeSubDomains")
    except Exception:
        pass

    # ✅ mejora real: páginas sensibles nunca cache
    try:
        p = request.path or ""
        if p.startswith(("/auth", "/admin", "/account", "/checkout", "/cart", "/webhooks")):
            resp.headers.setdefault("Cache-Control", "no-store, max-age=0, must-revalidate")
            resp.headers.setdefault("Pragma", "no-cache")
            _vary_add(resp, "Cookie")
    except Exception:
        pass

    return resp


# =========================================================
# 1) Home
# =========================================================
@main_bp.get("/")
def home():
    if HOME_REDIRECT_TO_SHOP:
        for ep in ("shop.shop_home", "shop.shop", "shop.home"):
            u = _safe_url_for(ep)
            if u:
                return redirect(u, code=302)
        return redirect("/shop", code=302)

    try:
        if HOME_CANONICAL_PATH and HOME_CANONICAL_PATH != "/" and request.path == "/":
            code = 301 if (_env_str("ENV", "").lower() in {"production", ""}) else 302
            return redirect(HOME_CANONICAL_PATH, code=code)
    except Exception:
        pass

    lang = _accept_language()
    cache_enabled = bool(ENABLE_HOME_CACHE and HOME_CACHE_TTL > 0)

    key = _cache_key_home(lang)
    cached = _cache_get(key) if cache_enabled else None

    if cached:
        etag = _etag_for(f"{cached.get('meta_title','')}|{cached.get('meta_description','')}|{lang}|{ASSET_VER}")
        maybe = _maybe_304(request.headers.get("If-None-Match"), etag)
        if maybe is not None:
            maybe.headers["ETag"] = etag
            _vary_add(maybe, "Accept-Language")
            return _resp_cache_public(maybe, HOME_CACHE_TTL)

        resp = _render("index.html", **cached)
        resp.headers["ETag"] = etag
        _vary_add(resp, "Accept-Language")
        return _resp_cache_public(resp, HOME_CACHE_TTL)

    payload: Dict[str, Any] = {
        "meta_title": SEO_DEFAULTS.title,
        "meta_description": SEO_DEFAULTS.description,
        "og_image": SEO_DEFAULTS.og_image,
        "ASSET_VER": ASSET_VER,
    }

    if cache_enabled:
        _cache_set(key, payload)

    etag = _etag_for(f"{payload.get('meta_title','')}|{payload.get('meta_description','')}|{lang}|{ASSET_VER}")
    maybe = _maybe_304(request.headers.get("If-None-Match"), etag)
    if maybe is not None:
        maybe.headers["ETag"] = etag
        _vary_add(maybe, "Accept-Language")
        return _resp_cache_public(maybe, HOME_CACHE_TTL)

    resp = _render("index.html", **payload)
    resp.headers["ETag"] = etag
    _vary_add(resp, "Accept-Language")
    return _resp_cache_public(resp, HOME_CACHE_TTL if cache_enabled else 0)


# =========================================================
# 2) Aliases de cuenta
# =========================================================
@main_bp.get("/account")
def account_alias():
    nxt = _safe_next_from_args()
    raw = _norm_str((request.args.get("tab") or request.args.get("mode") or ""), max_len=24).lower()
    wants_register = raw in {"register", "signup", "crear", "alta"}

    u = _safe_url_for("auth.register_get", next=nxt) if (wants_register and nxt) else ""
    if not u and wants_register:
        u = _safe_url_for("auth.register_get")
    if not wants_register:
        u = _safe_url_for("auth.login_get", next=nxt) if nxt else _safe_url_for("auth.login_get")

    if u:
        return redirect(u, code=302)

    base = "/auth/register" if wants_register else "/auth/login"
    return redirect(f"{base}?{urlencode({'next': nxt})}" if nxt else base, code=302)


@main_bp.get("/cuenta")
def cuenta_alias():
    nxt = _safe_next_from_args()
    u = _safe_url_for("main.account_alias", next=nxt) if nxt else _safe_url_for("main.account_alias")
    if u:
        return redirect(u, code=302)
    qs = urlencode({"next": nxt}) if nxt else ""
    return redirect(f"/account{('?' + qs) if qs else ''}", code=302)


# =========================================================
# 3) Aliases de tienda/ofertas (evita links rotos)
# =========================================================
@main_bp.get("/tienda")
def tienda_alias():
    u = _safe_url_for("shop.shop") or _safe_url_for("shop.shop_home") or _safe_url_for("shop.home")
    return redirect(u or "/shop", code=302)


@main_bp.get("/ofertas")
def ofertas_alias():
    u = _safe_url_for("shop.shop") or "/shop"
    sep = "&" if "?" in u else "?"
    return redirect(f"{u}{sep}ofertas=1", code=302)


# =========================================================
# 4) ✅ FIX CLAVE: Alias de producto (MATA el SS-404 por rutas viejas)
# =========================================================
def _redirect_product_detail(slug: str):
    s = _norm_str(slug, max_len=140).strip().strip("/")
    if not s:
        return None

    # 1) Si existe endpoint real, redirigimos ahí (no adivinamos: probamos varios)
    for ep in ("shop.product_detail", "shop.product", "shop.product_view", "main.product_detail"):
        u = _safe_url_for(ep, slug=s) or _safe_url_for(ep, product_slug=s) or _safe_url_for(ep, id=s)
        if u:
            return redirect(u, code=302)

    # 2) Fallback: si tenés Product model + template, render directo
    if db is not None and Product is not None:
        try:
            q = db.session.query(Product)  # type: ignore
            if hasattr(Product, "slug"):
                q = q.filter(getattr(Product, "slug") == s)  # type: ignore
            else:
                q = q.filter(getattr(Product, "id") == s)  # type: ignore
            if hasattr(Product, "is_active"):
                q = q.filter(getattr(Product, "is_active") == True)  # noqa: E712
            p = q.first()
            if p is not None:
                return _render(
                    "product_detail.html",
                    product=p,
                    meta_title=f"{getattr(p, 'name', 'Producto')} | {SEO_DEFAULTS.title}",
                    meta_description=str(getattr(p, "short_description", "") or SEO_DEFAULTS.description)[:180],
                    og_image=str(getattr(p, "image_url", "") or SEO_DEFAULTS.og_image),
                )
        except Exception:
            try:
                db.session.rollback()  # type: ignore[attr-defined]
            except Exception:
                pass

    return None


@main_bp.get("/producto/<path:slug>")
def producto_alias(slug: str):
    r = _redirect_product_detail(slug)
    return r if r is not None else _render(
        "error.html",
        status=404,
        meta_title=f"No encontrado | {SEO_DEFAULTS.title}",
        error_code=404,
        error_title="Producto no encontrado",
        error_message="Ese producto no existe o fue movido. Probá buscarlo desde la tienda.",
    )


@main_bp.get("/product/<path:slug>")
def product_alias(slug: str):
    r = _redirect_product_detail(slug)
    return r if r is not None else redirect("/tienda", code=302)


# =========================================================
# 5) Páginas estáticas
# =========================================================
@main_bp.get("/about")
def about():
    return _render("about.html", meta_title=f"Sobre nosotros | {SEO_DEFAULTS.title}")


@main_bp.get("/terms")
def terms():
    try:
        return _render("terms.html", meta_title=f"Términos | {SEO_DEFAULTS.title}")
    except Exception:
        return _render(
            "error.html",
            status=200,
            meta_title=f"Términos | {SEO_DEFAULTS.title}",
            error_code=200,
            error_title="Términos",
            error_message="Próximamente.",
        )


@main_bp.get("/privacy")
def privacy():
    try:
        return _render("privacy.html", meta_title=f"Privacidad | {SEO_DEFAULTS.title}")
    except Exception:
        return _render(
            "error.html",
            status=200,
            meta_title=f"Privacidad | {SEO_DEFAULTS.title}",
            error_code=200,
            error_title="Privacidad",
            error_message="Próximamente.",
        )


# =========================================================
# 6) Health
# =========================================================
@main_bp.get("/health")
def health():
    ok = True
    db_ok: Optional[bool] = None
    db_err: Optional[str] = None

    if db is not None and sql_text is not None:
        try:
            db.session.execute(sql_text("SELECT 1"))  # type: ignore[attr-defined]
            db_ok = True
        except Exception as e:
            ok = False
            db_ok = False
            db_err = f"{type(e).__name__}: {str(e)[:260]}"
            try:
                db.session.rollback()  # type: ignore[attr-defined]
            except Exception:
                pass

    data = {
        "status": "ok" if ok else "degraded",
        "time_utc": _utcnow().isoformat(),
        "db_ok": db_ok,
        "db_error": db_err,
        "site_url": _site_base_url(),
        "home_cache_enabled": bool(ENABLE_HOME_CACHE and HOME_CACHE_TTL > 0),
        "home_cache_ttl": int(HOME_CACHE_TTL),
        "asset_ver": str(ASSET_VER),
    }

    resp = jsonify(data)
    _resp_no_store(resp, vary_cookie=False)
    resp.status_code = 200 if ok else 503
    return resp


# =========================================================
# 7) Robots + Sitemap (con URLs reales si existen)
# =========================================================
@main_bp.get("/robots.txt")
def robots_txt():
    base = _site_base_url()
    u = _safe_url_for("static", filename="robots.txt", v=ASSET_VER)
    if u:
        return redirect(u, code=302)
    txt = f"User-agent: *\nAllow: /\n\nSitemap: {base}/sitemap.xml\n"
    resp = make_response(txt, 200)
    resp.headers["Content-Type"] = "text/plain; charset=utf-8"
    return _resp_cache_public(resp, 3600)


def _iso_utc(dt: Optional[datetime]) -> Optional[str]:
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


@main_bp.get("/sitemap.xml")
def sitemap_xml():
    base = _site_base_url()
    now = _iso_utc(_utcnow())

    static_urls: List[Dict[str, Any]] = [
        {"loc": f"{base}/", "lastmod": now, "changefreq": "daily", "priority": "1.0"},
        {"loc": f"{base}/tienda", "lastmod": now, "changefreq": "daily", "priority": "0.9"},
        {"loc": f"{base}/ofertas", "lastmod": now, "changefreq": "weekly", "priority": "0.8"},
        {"loc": f"{base}/about", "lastmod": now, "changefreq": "monthly", "priority": "0.4"},
        {"loc": f"{base}/terms", "lastmod": now, "changefreq": "yearly", "priority": "0.2"},
        {"loc": f"{base}/privacy", "lastmod": now, "changefreq": "yearly", "priority": "0.2"},
    ]

    categories: List[Dict[str, Any]] = []
    products: List[Dict[str, Any]] = []
    seen: Set[str] = {u["loc"] for u in static_urls}

    if db is not None and Category is not None and Product is not None:
        try:
            q_cat = db.session.query(Category)  # type: ignore
            if hasattr(Category, "is_active"):
                q_cat = q_cat.filter(getattr(Category, "is_active") == True)  # noqa: E712

            for c in q_cat.limit(_SITEMAP_MAX_CATEGORIES).all():
                slug = getattr(c, "slug", None) or getattr(c, "id", None)
                if not slug:
                    continue
                slug_s = str(slug).strip()
                if not slug_s:
                    continue
                loc = f"{base}/tienda?cat={slug_s}"
                if loc in seen:
                    continue
                seen.add(loc)
                lastmod = _iso_utc(getattr(c, "updated_at", None) or getattr(c, "created_at", None))
                categories.append({"loc": loc, "lastmod": lastmod, "changefreq": "weekly", "priority": "0.6"})

            q_prod = db.session.query(Product)  # type: ignore
            if hasattr(Product, "is_active"):
                q_prod = q_prod.filter(getattr(Product, "is_active") == True)  # noqa: E712

            for p in q_prod.limit(_SITEMAP_MAX_PRODUCTS).all():
                slug = getattr(p, "slug", None) or getattr(p, "id", None)
                if not slug:
                    continue
                slug_s = str(slug).strip()
                if not slug_s:
                    continue

                # ✅ mejora real: sitemap usa alias estable /producto/<slug>
                loc = f"{base}/producto/{slug_s}"

                if loc in seen:
                    continue
                seen.add(loc)
                lastmod = _iso_utc(getattr(p, "updated_at", None) or getattr(p, "created_at", None))
                products.append({"loc": loc, "lastmod": lastmod, "changefreq": "weekly", "priority": "0.7"})
        except Exception as e:
            try:
                current_app.logger.warning("sitemap: fallback static only (%s)", str(e)[:200])
                db.session.rollback()  # type: ignore[attr-defined]
            except Exception:
                pass

    try:
        xml = render_template("sitemap.xml", static_urls=static_urls, categories=categories, products=products)
    except Exception:
        xml = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
            + "\n".join(
                f'  <url><loc>{u["loc"]}</loc>'
                f'{("<lastmod>"+u["lastmod"]+"</lastmod>") if u.get("lastmod") else ""}'
                f'{("<changefreq>"+u["changefreq"]+"</changefreq>") if u.get("changefreq") else ""}'
                f'{("<priority>"+u["priority"]+"</priority>") if u.get("priority") else ""}'
                f"</url>"
                for u in (static_urls + categories + products)
            )
            + "\n</urlset>\n"
        )

    etag = _etag_for(xml)
    maybe = _maybe_304(request.headers.get("If-None-Match"), etag)
    if maybe is not None:
        maybe.headers["ETag"] = etag
        maybe.headers["Content-Type"] = "application/xml; charset=utf-8"
        return _resp_cache_public(maybe, 3600)

    resp = make_response(xml, 200)
    resp.headers["Content-Type"] = "application/xml; charset=utf-8"
    resp.headers["ETag"] = etag
    return _resp_cache_public(resp, 3600)


# =========================================================
# 8) Utilidades
# =========================================================
@main_bp.get("/go")
def go():
    nxt = _norm_str(request.args.get("next", "") or "", max_len=512)
    if _is_safe_next(nxt):
        return redirect(nxt, code=302)
    return redirect(_safe_url_for("main.home") or "/", code=302)


@main_bp.get("/favicon.ico")
def favicon():
    u = _safe_url_for("static", filename="favicon.ico", v=ASSET_VER)
    return redirect(u, code=302) if u else ("", 204)


# =========================================================
# 9) Error handlers: usa templates/errors si existen
# =========================================================
@main_bp.app_errorhandler(404)
def not_found(e):
    _ = e
    # ✅ mejora real: si existe templates/errors/404.html lo usa
    try:
        return _render(
            "errors/404.html",
            status=404,
            meta_title=f"No encontrado | {SEO_DEFAULTS.title}",
        )
    except Exception:
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
    try:
        return _render("errors/500.html", status=500, meta_title=f"Error | {SEO_DEFAULTS.title}")
    except Exception:
        return _render(
            "error.html",
            status=500,
            meta_title=f"Error | {SEO_DEFAULTS.title}",
            error_code=500,
            error_title="Error interno",
            error_message="Ocurrió un error. Probá de nuevo en unos segundos.",
        )


__all__ = ["main_bp"]
