from __future__ import annotations

import importlib
import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from functools import partial
from typing import Any, Optional, Type, cast
from urllib.parse import urlencode, urlparse, urlunparse

from flask import Flask, Response, g, jsonify, redirect, render_template, request, url_for
from flask_wtf import CSRFProtect
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from app.config import get_config
from app.models import db, init_models

try:
    from sqlalchemy import text as sql_text  # type: ignore
except Exception:  # pragma: no cover
    sql_text = None  # type: ignore


_TRUE = {"1", "true", "yes", "y", "on", "checked", "enable", "enabled"}
_FALSE = {"0", "false", "no", "n", "off", "disable", "disabled"}
_ALLOWED_LOG_LEVELS = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}

_STATIC_404_PASSTHROUGH = {"/favicon.ico", "/robots.txt", "/sitemap.xml"}


# -----------------------------------------------------------------------------
# Env helpers
# -----------------------------------------------------------------------------
def _env_str(name: str, default: str = "", *, max_len: int = 4096) -> str:
    v = os.getenv(name)
    s = (default if v is None else str(v)).strip()
    if max_len > 0 and len(s) > max_len:
        s = s[:max_len]
    return s


def _env_bool(name: str, default: bool = False) -> bool:
    v = _env_str(name, "")
    if not v:
        return default
    s = v.lower().strip()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return default


def _env_int(name: str, default: int, *, min_v: int = 0, max_v: int = 10**9) -> int:
    try:
        v = int(_env_str(name, str(default)))
    except Exception:
        v = int(default)
    if v < min_v:
        return int(min_v)
    if v > max_v:
        return int(max_v)
    return int(v)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# -----------------------------------------------------------------------------
# Env detection
# -----------------------------------------------------------------------------
def _env_name(app: Flask) -> str:
    env = (
        app.config.get("ENV")
        or app.config.get("ENVIRONMENT")
        or _env_str("ENV")
        or _env_str("FLASK_ENV")
        or ("development" if bool(app.debug) else "production")
    )
    env_s = str(env).lower().strip()
    if env_s in {"prod", "production"}:
        return "production"
    if env_s in {"dev", "development"}:
        return "development"
    if env_s in {"test", "testing"}:
        return "testing"
    return "development" if bool(app.debug) else "production"


def _is_prod(app: Flask) -> bool:
    return _env_name(app) == "production" and not bool(app.debug)


def _is_testing(app: Flask) -> bool:
    return bool(app.config.get("TESTING")) or _env_name(app) == "testing"


# -----------------------------------------------------------------------------
# Content negotiation
# -----------------------------------------------------------------------------
def wants_json() -> bool:
    try:
        if request.is_json:
            return True
        accept = (request.headers.get("Accept") or "").lower()
        if "application/json" in accept or "text/json" in accept:
            return True
        if (request.headers.get("X-Requested-With") or "").lower() == "xmlhttprequest":
            return True
        if (request.args.get("format") or "").lower() == "json":
            return True
    except Exception:
        return False
    return False


def current_app_config(key: str, default: Any = None) -> Any:
    try:
        from flask import current_app

        return current_app.config.get(key, default)
    except Exception:
        return default


# -----------------------------------------------------------------------------
# Errors
# -----------------------------------------------------------------------------
def resp_error(status: int, code: str, message: str):
    status_i = int(status or 500)
    err = (code or "error").strip().lower()[:64] or "error"
    msg = (message or "Error").strip()

    if wants_json():
        return jsonify({"ok": False, "error": err, "message": msg, "status": status_i}), status_i

    headers: dict[str, str] = {}
    if bool(current_app_config("NO_STORE_ERROR_PAGES", True)):
        headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
        headers["Pragma"] = "no-cache"
        headers["Expires"] = "0"

    # ✅ mejora: orden preferido y variables consistentes
    for tpl in (f"errors/{status_i}.html", "errors/error.html", "error.html"):
        try:
            return render_template(tpl, message=msg, status=status_i, code=err), status_i, headers
        except Exception:
            continue

    return msg, status_i, headers


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
def setup_logging(app: Flask) -> None:
    env_level = (_env_str("LOG_LEVEL", "") or "").upper().strip()
    if env_level in _ALLOWED_LOG_LEVELS:
        level = getattr(logging, env_level, logging.INFO)
    else:
        level = logging.DEBUG if bool(app.debug) else logging.INFO

    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(
            level=level,
            format="%(asctime)s | %(levelname)s | %(name)s:%(lineno)d — %(message)s",
        )
    root.setLevel(level)
    app.logger.setLevel(level)

    if _is_prod(app):
        logging.getLogger("werkzeug").setLevel(logging.WARNING)


# -----------------------------------------------------------------------------
# Safe redirect handling
# -----------------------------------------------------------------------------
def _safe_next_path(v: str) -> str:
    nxt = (v or "").strip()
    if not nxt:
        return ""
    if len(nxt) > 2048:
        nxt = nxt[:2048]
    if any(c in nxt for c in ("\x00", "\r", "\n", "\\", " ")):
        return ""
    if "://" in nxt or nxt.startswith("//"):
        return ""
    if not nxt.startswith("/"):
        return ""
    p = urlparse(nxt)
    if p.scheme or p.netloc:
        return ""
    path_only = p.path or ""
    if not path_only.startswith("/") or path_only.startswith("//"):
        return ""
    if ".." in path_only:
        return ""
    # ✅ mejora: evita loops a auth/admin directos
    if path_only.startswith(("/auth/", "/admin/")):
        return ""
    return path_only[:512]


def _endpoint_exists(app: Flask, endpoint: str) -> bool:
    try:
        return endpoint in (app.view_functions or {})
    except Exception:
        return False


def _rule_exists(app: Flask, rule: str) -> bool:
    try:
        for r in app.url_map.iter_rules():
            if r.rule == rule:
                return True
    except Exception:
        return False
    return False


# -----------------------------------------------------------------------------
# Blueprint loading
# -----------------------------------------------------------------------------
def _import_bp(module_name: str, attr: str):
    try:
        mod = importlib.import_module(module_name)
        return getattr(mod, attr, None), ""
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def _register_blueprints(app: Flask) -> dict[str, Any]:
    stats: dict[str, Any] = {
        "registered": 0,
        "failed": 0,
        "skipped": 0,
        "errors": {},
        "failed_names": [],
        "routes_report": {},
    }

    # Preferred: centralized registrar
    try:
        from app.routes import register_blueprints as reg  # type: ignore

        rep = reg(app)
        if isinstance(rep, dict):
            stats["routes_report"] = rep
        stats["registered"] = len(app.blueprints or {})
        return stats
    except Exception as e:
        stats["errors"]["app.routes.register_blueprints"] = f"{type(e).__name__}: {e}"

    # Fallback direct imports
    candidates = [
        ("app.routes.main_routes", "main_bp"),
        ("app.routes.shop_routes", "shop_bp"),
        ("app.routes.shop_routes", "shop_compat_bp"),  # ✅ mejora: no te olvides del compat
        ("app.routes.auth_routes", "auth_bp"),
        ("app.routes.account_routes", "account_bp"),
        ("app.routes.cart_routes", "cart_bp"),
        ("app.routes.checkout_routes", "checkout_bp"),
        ("app.routes.api_routes", "api_bp"),
        ("app.routes.affiliate_routes", "affiliate_bp"),
        ("app.routes.marketing_routes", "marketing_bp"),
        ("app.routes.webhook_routes", "webhook_bp"),
        ("app.routes.admin_routes", "admin_bp"),
        ("app.routes.admin_auth_routes", "admin_auth_bp"),
        ("app.routes.admin_payments_routes", "admin_payments_bp"),
        ("app.routes.printful_routes", "printful_bp"),
        ("app.routes.address_routes", "address_bp"),
        ("app.routes.profile_routes", "profile_bp"),
    ]

    for mod_name, bp_name in candidates:
        bp, err = _import_bp(mod_name, bp_name)
        if bp is None:
            if err:
                stats["errors"][f"{mod_name}:{bp_name}"] = err
            continue
        try:
            name = str(getattr(bp, "name", "") or "").strip()
            if name and name in (app.blueprints or {}):
                stats["skipped"] += 1
                continue
            app.register_blueprint(bp)
            stats["registered"] += 1
        except Exception as e:
            stats["failed"] += 1
            stats["failed_names"].append(f"{mod_name}:{bp_name}")
            stats["errors"][f"{mod_name}:{bp_name}"] = f"{type(e).__name__}: {e}"

    return stats


# -----------------------------------------------------------------------------
# Runtime defaults
# -----------------------------------------------------------------------------
def _apply_runtime_defaults(app: Flask) -> None:
    is_prod = _is_prod(app)

    app.config.setdefault(
        "MAX_CONTENT_LENGTH",
        _env_int("MAX_CONTENT_LENGTH", 2_000_000, min_v=200_000, max_v=25_000_000),
    )
    app.config.setdefault("JSON_SORT_KEYS", False)
    app.config.setdefault("TEMPLATES_AUTO_RELOAD", not is_prod)
    app.config.setdefault("SEND_FILE_MAX_AGE_DEFAULT", 31536000 if is_prod else 0)

    app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
    app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
    app.config.setdefault(
        "PERMANENT_SESSION_LIFETIME",
        timedelta(days=_env_int("SESSION_DAYS", 14, min_v=1, max_v=365)),
    )
    app.config.setdefault("SESSION_REFRESH_EACH_REQUEST", False)
    app.config.setdefault("PREFERRED_URL_SCHEME", "https" if is_prod else "http")
    app.config.setdefault("SESSION_COOKIE_SECURE", is_prod)

    app.config.setdefault("PROXYFIX_X_FOR", _env_int("PROXYFIX_X_FOR", 1, min_v=0, max_v=5))
    app.config.setdefault("PROXYFIX_X_PROTO", _env_int("PROXYFIX_X_PROTO", 1, min_v=0, max_v=5))
    app.config.setdefault("PROXYFIX_X_HOST", _env_int("PROXYFIX_X_HOST", 1, min_v=0, max_v=5))

    app.config.setdefault("SEC_HEADERS_ENABLED", True)
    app.config.setdefault("HSTS_ENABLED", is_prod)
    app.config.setdefault("HSTS_MAX_AGE", 31536000)
    app.config.setdefault("NO_STORE_ERROR_PAGES", True)

    app.config.setdefault("WTF_CSRF_ENABLED", _env_bool("WTF_CSRF_ENABLED", True))
    app.config.setdefault("WTF_CSRF_TIME_LIMIT", _env_int("WTF_CSRF_TIME_LIMIT", 3600, min_v=300, max_v=86400))
    app.config.setdefault("WTF_CSRF_SSL_STRICT", _env_bool("WTF_CSRF_SSL_STRICT", is_prod))

    app.config.setdefault("MAIL_ENABLED", _env_bool("MAIL_ENABLED", False))
    app.config.setdefault("MAIL_FROM", _env_str("MAIL_FROM", "no-reply@localhost"))
    app.config.setdefault("PUBLIC_BASE_URL", _env_str("PUBLIC_BASE_URL", ""))

    app.config.setdefault("VERIFY_EMAIL_ENABLED", _env_bool("VERIFY_EMAIL_ENABLED", True))
    app.config.setdefault("VERIFY_EMAIL_TTL_HOURS", _env_int("VERIFY_EMAIL_TTL_HOURS", 24, min_v=1, max_v=168))

    app.config.setdefault("CSP_ENABLED", _env_bool("CSP_ENABLED", is_prod))
    app.config.setdefault("CSP_POLICY", _env_str("CSP_POLICY", ""))

    app.config.setdefault("STRICT_STARTUP", _env_bool("STRICT_STARTUP", is_prod))
    app.config.setdefault("HEALTH_REVEAL_ERRORS", _env_bool("HEALTH_REVEAL_ERRORS", not is_prod))

    app.config.setdefault("ADMIN_LOGIN_ENDPOINT", _env_str("ADMIN_LOGIN_ENDPOINT", "admin.login"))
    app.config.setdefault("AUTH_ACCOUNT_ENDPOINT", _env_str("AUTH_ACCOUNT_ENDPOINT", "auth.account"))

    if _is_testing(app):
        app.config.setdefault("TRUST_PROXY_HEADERS", False)
        app.config.setdefault("HSTS_ENABLED", False)


def _ensure_secret_key(app: Flask) -> None:
    if app.config.get("SECRET_KEY"):
        return
    if _is_prod(app):
        raise RuntimeError("SECRET_KEY requerido en producción")
    app.config["SECRET_KEY"] = secrets.token_urlsafe(48)


def _ensure_proxyfix_once(app: Flask) -> None:
    if not bool(app.config.get("TRUST_PROXY_HEADERS", _is_prod(app))):
        return
    if getattr(app, "_proxyfix_applied", False):
        return
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=int(app.config.get("PROXYFIX_X_FOR", 1)),
        x_proto=int(app.config.get("PROXYFIX_X_PROTO", 1)),
        x_host=int(app.config.get("PROXYFIX_X_HOST", 1)),
    )
    app._proxyfix_applied = True  # type: ignore[attr-defined]


def _apply_security_headers(app: Flask, resp: Response) -> Response:
    if not bool(app.config.get("SEC_HEADERS_ENABLED", True)):
        return resp

    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")

    if bool(app.config.get("HSTS_ENABLED", False)) and _is_prod(app):
        max_age = int(app.config.get("HSTS_MAX_AGE", 31536000) or 31536000)
        resp.headers.setdefault("Strict-Transport-Security", f"max-age={max_age}; includeSubDomains")

    if bool(app.config.get("CSP_ENABLED", False)):
        policy = str(app.config.get("CSP_POLICY") or "").strip()
        if not policy:
            policy = (
                "default-src 'self'; "
                "img-src 'self' data: https:; "
                "style-src 'self' 'unsafe-inline' https:; "
                "script-src 'self' https:; "
                "font-src 'self' data: https:; "
                "connect-src 'self' https:; "
                "frame-ancestors 'self'; "
                "base-uri 'self'"
            )
        resp.headers.setdefault("Content-Security-Policy", policy)

    return resp


# -----------------------------------------------------------------------------
# SQLAlchemy config (no double-init / sqlite-safe)
# -----------------------------------------------------------------------------
def _normalize_db_uri(uri: str, *, is_prod: bool) -> str:
    u = (uri or "").strip()
    if not u:
        return ""
    if u.startswith("postgres://"):
        u = "postgresql://" + u[len("postgres://") :]
    if is_prod and u.startswith("postgresql://"):
        if "sslmode=" not in u.lower():
            try:
                p = urlparse(u)
                q = p.query or ""
                q2 = (q + "&" if q else "") + "sslmode=require"
                u = urlunparse(p._replace(query=q2))
            except Exception:
                sep = "&" if "?" in u else "?"
                u = u + f"{sep}sslmode=require"
    return u


def _configure_sqlalchemy(app: Flask) -> None:
    is_prod = _is_prod(app)

    if _is_testing(app):
        uri = str(app.config.get("SQLALCHEMY_DATABASE_URI") or "sqlite://").strip()
        uri = _normalize_db_uri(uri, is_prod=False)
        app.config["SQLALCHEMY_DATABASE_URI"] = uri
        app.config.setdefault("SQLALCHEMY_TRACK_MODIFICATIONS", False)

        engine_opts = dict(app.config.get("SQLALCHEMY_ENGINE_OPTIONS") or {})
        if uri.startswith("sqlite"):
            engine_opts.pop("pool_size", None)
            engine_opts.pop("max_overflow", None)
            engine_opts.pop("pool_timeout", None)
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = engine_opts

        if app.extensions.get("sqlalchemy") is not db:
            db.init_app(app)
        return

    db_url = _env_str("DATABASE_URL", "")
    cfg_uri = str(app.config.get("SQLALCHEMY_DATABASE_URI") or "").strip()

    if is_prod:
        uri = db_url or cfg_uri
        if not uri:
            raise RuntimeError("DATABASE_URL requerido en producción")
    else:
        uri = cfg_uri or db_url

    uri = _normalize_db_uri(uri, is_prod=is_prod)
    if uri:
        app.config["SQLALCHEMY_DATABASE_URI"] = uri

    app.config.setdefault("SQLALCHEMY_TRACK_MODIFICATIONS", False)

    engine_opts = dict(app.config.get("SQLALCHEMY_ENGINE_OPTIONS") or {})
    if not engine_opts:
        pool_size = _env_int("DB_POOL_SIZE", 5, min_v=1, max_v=50)
        max_overflow = _env_int("DB_MAX_OVERFLOW", 10, min_v=0, max_v=100)
        pool_timeout = _env_int("DB_POOL_TIMEOUT", 30, min_v=5, max_v=120)
        recycle = _env_int("DB_POOL_RECYCLE", 280, min_v=30, max_v=7200)
        engine_opts = {
            "pool_pre_ping": True,
            "pool_recycle": recycle,
            "pool_size": pool_size,
            "max_overflow": max_overflow,
            "pool_timeout": pool_timeout,
        }

    if str(app.config.get("SQLALCHEMY_DATABASE_URI") or "").startswith("sqlite"):
        engine_opts.pop("pool_size", None)
        engine_opts.pop("max_overflow", None)
        engine_opts.pop("pool_timeout", None)

    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = engine_opts

    if app.extensions.get("sqlalchemy") is not db:
        db.init_app(app)


# -----------------------------------------------------------------------------
# Redirects
# -----------------------------------------------------------------------------
def _best_redirect_to_account(app: Flask, tab: str) -> Response:
    nxt = _safe_next_path(request.args.get("next", "")) or "/"
    endpoint = str(app.config.get("AUTH_ACCOUNT_ENDPOINT", "auth.account") or "auth.account")
    # ✅ mejora: si existe endpoint real, usalo; si no, fallback a path fijo
    if _endpoint_exists(app, endpoint):
        try:
            return redirect(url_for(endpoint, tab=tab, next=nxt), code=302)
        except Exception:
            pass
    return redirect("/auth/account?" + urlencode({"tab": tab, "next": nxt}), code=302)


# -----------------------------------------------------------------------------
# Jinja helpers (safe_url REAL)
# -----------------------------------------------------------------------------
def _safe_url(app: Flask, endpoint: str, fallback: str = "", **values: Any) -> str:
    ep = (endpoint or "").strip()
    fb = (fallback or "").strip()
    if not ep or not _endpoint_exists(app, ep):
        return fb
    try:
        return url_for(ep, **values)
    except Exception:
        return fb


# -----------------------------------------------------------------------------
# App factory
# -----------------------------------------------------------------------------
def create_app(overrides: Optional[dict[str, Any]] = None) -> Flask:
    cfg: Type = get_config()

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
        instance_relative_config=True,
    )

    app.config.from_mapping(cfg.as_flask_config())
    if overrides:
        app.config.update(overrides)

    _apply_runtime_defaults(app)
    _ensure_secret_key(app)
    setup_logging(app)

    _ensure_proxyfix_once(app)
    _configure_sqlalchemy(app)

    strict_startup = bool(app.config.get("STRICT_STARTUP", _is_prod(app)))

    csrf = CSRFProtect()
    if bool(app.config.get("WTF_CSRF_ENABLED", True)):
        csrf.init_app(app)

    # ✅ mejora: context globals estables (no expone view_functions gigante)
    @app.context_processor
    def _inject_globals():
        app_name = app.config.get("APP_NAME", "Skyline Store")
        asset_ver = app.config.get("ASSET_VER", app.config.get("BASE_CSS_VER", "1"))
        home_ver = app.config.get("HOME_CSS_VER", asset_ver)
        return {
            "ENV": _env_name(app),
            "APP_NAME": app_name,
            "ASSET_VER": asset_ver,
            "HOME_CSS_VER": home_ver,
            "PUBLIC_BASE_URL": app.config.get("PUBLIC_BASE_URL", ""),
            "MAIL_FROM": app.config.get("MAIL_FROM", ""),
            "now_year": utcnow().year,
            "REQUEST_ID": cast(str, getattr(g, "request_id", "")) if hasattr(g, "request_id") else "",
            "safe_url": partial(_safe_url, app),
        }

    @app.before_request
    def _before():
        if request.method == "OPTIONS":
            return "", 204

        rid = (request.headers.get("X-Request-Id") or "").strip()
        g.request_id = rid[:128] if rid else secrets.token_urlsafe(10)
        g._t0 = time.perf_counter()

        # ✅ mejora: aliases /login /register y /auth/login /auth/register sin loops
        if request.method in {"GET", "HEAD"}:
            p = request.path.rstrip("/") or "/"
            if p in {"/login", "/auth/login"}:
                return _best_redirect_to_account(app, "login")
            if p in {"/register", "/auth/register"}:
                return _best_redirect_to_account(app, "register")

        return None

    @app.after_request
    def _after(resp: Response):
        try:
            resp.headers.setdefault("X-Request-Id", cast(str, getattr(g, "request_id", "")))
        except Exception:
            pass

        try:
            t0 = getattr(g, "_t0", None)
            if isinstance(t0, (int, float)):
                ms = int((time.perf_counter() - float(t0)) * 1000)
                resp.headers.setdefault("X-Response-Time", f"{ms}ms")
        except Exception:
            pass

        # ✅ mejora: no-store en errores, excepto assets típicos
        if (
            bool(app.config.get("NO_STORE_ERROR_PAGES", True))
            and resp.status_code >= 400
            and request.path not in _STATIC_404_PASSTHROUGH
        ):
            resp.headers.setdefault("Cache-Control", "no-store, max-age=0, must-revalidate")
            resp.headers.setdefault("Pragma", "no-cache")
            resp.headers.setdefault("Expires", "0")

        return _apply_security_headers(app, resp)

    # ✅ mejora: init_models no tumba el server si STRICT_STARTUP off
    init_ok = True
    init_err: Optional[str] = None
    try:
        ping = bool(app.config.get("PING_DB_ON_STARTUP", True)) and not _is_testing(app)
        init_models(app, create_admin=True, log_loaded_models=True, ping_db=ping)
    except Exception as e:
        init_ok = False
        init_err = f"{type(e).__name__}: {e}"
        app.config["_INIT_MODELS_ERROR"] = init_err
        app.logger.exception("init_models() falló: %s", e)
        if strict_startup:
            raise

    @app.teardown_appcontext
    def _shutdown(_exc):
        try:
            db.session.remove()
        except Exception:
            pass

    stats = _register_blueprints(app)

    # ✅ mejora: no crear fallback si ya existe regla real (evita colisiones)
    if not _rule_exists(app, "/auth/login"):
        app.add_url_rule(
            "/auth/login",
            "_fallback_auth_login",
            partial(_best_redirect_to_account, app, "login"),
            methods=["GET", "HEAD"],
        )

    if not _rule_exists(app, "/auth/register"):
        app.add_url_rule(
            "/auth/register",
            "_fallback_auth_register",
            partial(_best_redirect_to_account, app, "register"),
            methods=["GET", "HEAD"],
        )

    for rule, endpoint, tab in (
        ("/login", "_fallback_login", "login"),
        ("/register", "_fallback_register", "register"),
    ):
        if not _rule_exists(app, rule):
            app.add_url_rule(rule, endpoint, partial(_best_redirect_to_account, app, tab), methods=["GET", "HEAD"])

    # ✅ emergencia /auth/account si falta endpoint
    account_ep = str(app.config.get("AUTH_ACCOUNT_ENDPOINT", "auth.account") or "auth.account")
    if not _endpoint_exists(app, account_ep) and not _rule_exists(app, "/auth/account"):

        @app.get("/auth/account")
        def _emergency_account():
            tab = (request.args.get("tab") or "login").strip().lower()
            if tab not in {"login", "register"}:
                tab = "login"
            nxt = _safe_next_path(request.args.get("next", "")) or "/"
            return render_template("auth/account.html", active_tab=tab, next=nxt, prefill_email=""), 200

    # Root fallback si nadie lo registró
    if not _rule_exists(app, "/"):

        @app.get("/")
        def _root():
            for ep in ("main.home", "main.index", "shop.shop"):
                if _endpoint_exists(app, ep):
                    try:
                        return redirect(url_for(ep), code=302)
                    except Exception:
                        continue
            return "Skyline Store", 200, {"Cache-Control": "no-store"}

    # ✅ health: útil para Render + debug
    @app.get("/health")
    def health():
        rr = stats.get("routes_report") if isinstance(stats.get("routes_report"), dict) else {}
        imports_failed = rr.get("imports_failed", []) if isinstance(rr, dict) else []
        reveal = bool(app.config.get("HEALTH_REVEAL_ERRORS", not _is_prod(app)))

        try:
            routes_count = sum(1 for _ in app.url_map.iter_rules())
        except Exception:
            routes_count = 0

        payload: dict[str, Any] = {
            "status": "ok" if init_ok else "degraded",
            "env": _env_name(app),
            "app": app.config.get("APP_NAME", "Skyline Store"),
            "blueprints": list((app.blueprints or {}).keys()),
            "routes": int(routes_count),
            "bp_registered": int(stats.get("registered", 0)),
            "bp_failed": int(stats.get("failed", 0)),
            "bp_skipped": int(stats.get("skipped", 0)),
            "auth_account": bool(_endpoint_exists(app, account_ep) or _rule_exists(app, "/auth/account")),
            "init_models_ok": bool(init_ok),
            "ts": int(time.time()),
        }
        if reveal:
            payload["bp_failed_names"] = stats.get("failed_names", [])
            payload["errors"] = stats.get("errors", {})
            payload["imports_failed"] = imports_failed
            payload["init_models_error"] = init_err
        return payload

    # ✅ ready: check DB real
    @app.get("/ready")
    def ready():
        if _is_testing(app):
            return {"ok": True, "db": True, "init": bool(init_ok), "env": _env_name(app), "ts": int(time.time())}, 200

        ok = True
        db_ok = True
        err: Optional[str] = None
        try:
            if sql_text is None:
                raise RuntimeError("sqlalchemy.text no disponible")
            with db.engine.connect() as conn:  # type: ignore[attr-defined]
                conn.execute(sql_text("SELECT 1"))
        except Exception as e:
            ok = False
            db_ok = False
            err = f"{type(e).__name__}: {e}"

        if not init_ok:
            ok = False

        payload: dict[str, Any] = {"ok": ok, "db": db_ok, "init": init_ok, "env": _env_name(app), "ts": int(time.time())}
        if bool(app.config.get("HEALTH_REVEAL_ERRORS", not _is_prod(app))) and err:
            payload["db_error"] = err[:260]
        return payload, (200 if ok else 503)

    # ✅ error handlers
    @app.errorhandler(HTTPException)
    def http_error(e: HTTPException):
        code = int(getattr(e, "code", 500) or 500)
        name = (getattr(e, "name", "http_error") or "http_error").strip().lower()
        desc = (getattr(e, "description", "Error") or "Error").strip()
        return resp_error(code, name, desc)

    @app.errorhandler(Exception)
    def fatal(e: Exception):
        app.logger.exception("Fatal error: %s", e)
        return resp_error(500, "server_error", "Error interno del servidor")

    app.logger.info(
        "✅ Skyline Store (%s) strict=%s init=%s blueprints=%s",
        _env_name(app),
        "ON" if strict_startup else "OFF",
        "OK" if init_ok else "FAIL",
        list((app.blueprints or {}).keys()),
    )
    return app


__all__ = ["create_app", "db"]
