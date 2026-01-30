from __future__ import annotations

import importlib
import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from functools import partial
from typing import Any, Optional, Type, cast
from urllib.parse import urlencode, urlparse

from flask import Flask, Response, g, jsonify, redirect, render_template, request, url_for
from flask_wtf import CSRFProtect
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from app.config import get_config
from app.models import db, init_models

try:
    from sqlalchemy import text as sql_text  # type: ignore
except Exception:
    sql_text = None  # type: ignore

try:
    from werkzeug.security import safe_join  # type: ignore
except Exception:
    safe_join = None  # type: ignore


_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off"}


def _env_str(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


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
        v = default
    return max(min_v, min(max_v, v))


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


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
    return "development" if bool(app.debug) else "production"


def _is_prod(app: Flask) -> bool:
    return _env_name(app) == "production" and not bool(app.debug)


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

    for tpl in (f"errors/{status_i}.html", "error.html"):
        try:
            return render_template(tpl, message=msg, status=status_i, code=err), status_i, headers
        except Exception:
            continue

    return msg, status_i, headers


def setup_logging(app: Flask) -> None:
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


def _safe_next_path(v: str) -> str:
    nxt = (v or "").strip()
    if not nxt:
        return ""
    if any(c in nxt for c in ("\x00", "\r", "\n", "\\")):
        return ""
    if "://" in nxt:
        return ""
    if not nxt.startswith("/") or nxt.startswith("//"):
        return ""
    p = urlparse(nxt)
    if p.scheme or p.netloc:
        return ""
    if "?" in nxt:
        nxt = nxt.split("?", 1)[0]
    if "#" in nxt:
        nxt = nxt.split("#", 1)[0]
    if ".." in nxt:
        return ""
    return nxt[:512]


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


def _import_bp(module_name: str, attr: str):
    try:
        mod = importlib.import_module(module_name)
        return getattr(mod, attr, None), ""
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def _register_blueprints(app: Flask) -> dict[str, Any]:
    stats: dict[str, Any] = {"registered": 0, "failed": 0, "skipped": 0, "errors": {}, "failed_names": []}

    try:
        from app.routes import register_blueprints as reg  # type: ignore

        rep = reg(app)
        if isinstance(rep, dict):
            stats.update({"routes_report": rep})
        stats["registered"] = len(app.blueprints or {})
        return stats
    except Exception as e:
        stats["errors"]["app.routes.register_blueprints"] = f"{type(e).__name__}: {e}"

    candidates = [
        ("app.routes.main_routes", "main_bp"),
        ("app.routes.shop_routes", "shop_bp"),
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


def _apply_runtime_defaults(app: Flask) -> None:
    app.config.setdefault("MAX_CONTENT_LENGTH", _env_int("MAX_CONTENT_LENGTH", 2_000_000, min_v=200_000, max_v=25_000_000))
    app.config.setdefault("JSON_SORT_KEYS", False)
    app.config.setdefault("TEMPLATES_AUTO_RELOAD", not _is_prod(app))
    app.config.setdefault("SEND_FILE_MAX_AGE_DEFAULT", 31536000 if _is_prod(app) else 0)

    app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
    app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
    app.config.setdefault("PERMANENT_SESSION_LIFETIME", timedelta(days=_env_int("SESSION_DAYS", 14, min_v=1, max_v=90)))
    app.config.setdefault("SESSION_REFRESH_EACH_REQUEST", False)
    app.config.setdefault("PREFERRED_URL_SCHEME", "https" if _is_prod(app) else "http")
    app.config.setdefault("SESSION_COOKIE_SECURE", _is_prod(app))

    app.config.setdefault("PROXYFIX_X_FOR", _env_int("PROXYFIX_X_FOR", 1, min_v=0, max_v=5))
    app.config.setdefault("PROXYFIX_X_PROTO", _env_int("PROXYFIX_X_PROTO", 1, min_v=0, max_v=5))
    app.config.setdefault("PROXYFIX_X_HOST", _env_int("PROXYFIX_X_HOST", 1, min_v=0, max_v=5))

    app.config.setdefault("SEC_HEADERS_ENABLED", True)
    app.config.setdefault("HSTS_ENABLED", _is_prod(app))
    app.config.setdefault("HSTS_MAX_AGE", 31536000)
    app.config.setdefault("NO_STORE_ERROR_PAGES", True)

    app.config.setdefault("CSRF_ENABLED", True)
    app.config.setdefault("CSRF_TIME_LIMIT", _env_int("CSRF_TIME_LIMIT", 3600, min_v=300, max_v=86400))

    app.config.setdefault("MAIL_ENABLED", _env_bool("MAIL_ENABLED", False))
    app.config.setdefault("MAIL_FROM", _env_str("MAIL_FROM", "no-reply@localhost"))
    app.config.setdefault("PUBLIC_BASE_URL", _env_str("PUBLIC_BASE_URL", ""))

    app.config.setdefault("VERIFY_EMAIL_ENABLED", _env_bool("VERIFY_EMAIL_ENABLED", True))
    app.config.setdefault("VERIFY_EMAIL_TTL_HOURS", _env_int("VERIFY_EMAIL_TTL_HOURS", 24, min_v=1, max_v=168))

    app.config.setdefault("CSP_ENABLED", _env_bool("CSP_ENABLED", _is_prod(app)))
    app.config.setdefault("CSP_POLICY", _env_str("CSP_POLICY", ""))

    app.config.setdefault("STRICT_STARTUP", _env_bool("STRICT_STARTUP", _is_prod(app)))
    app.config.setdefault("HEALTH_REVEAL_ERRORS", _env_bool("HEALTH_REVEAL_ERRORS", not _is_prod(app)))

    app.config.setdefault("ADMIN_LOGIN_ENDPOINT", _env_str("ADMIN_LOGIN_ENDPOINT", "admin.login"))
    app.config.setdefault("AUTH_ACCOUNT_ENDPOINT", _env_str("AUTH_ACCOUNT_ENDPOINT", "auth.account"))


def _ensure_secret_key(app: Flask) -> None:
    if app.config.get("SECRET_KEY"):
        return
    if _is_prod(app):
        raise RuntimeError("SECRET_KEY requerido en producción")
    app.config["SECRET_KEY"] = secrets.token_urlsafe(48)


def _ensure_proxyfix_once(app: Flask) -> None:
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
            policy = "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https:; script-src 'self' 'unsafe-inline' https:; font-src 'self' data: https:; connect-src 'self' https:; frame-ancestors 'self'; base-uri 'self'"
        resp.headers.setdefault("Content-Security-Policy", policy)

    return resp


def _normalize_db_uri(uri: str) -> str:
    u = (uri or "").strip()
    if not u:
        return ""
    if u.startswith("postgres://"):
        u = "postgresql://" + u[len("postgres://") :]
    if "sslmode=" not in u and u.startswith("postgresql://"):
        sep = "&" if "?" in u else "?"
        u = u + f"{sep}sslmode=require"
    return u


def _configure_sqlalchemy(app: Flask) -> None:
    uri = app.config.get("SQLALCHEMY_DATABASE_URI") or _env_str("DATABASE_URL", "")
    uri = _normalize_db_uri(str(uri or ""))
    if uri:
        app.config["SQLALCHEMY_DATABASE_URI"] = uri

    app.config.setdefault("SQLALCHEMY_TRACK_MODIFICATIONS", False)

    pool_size = _env_int("DB_POOL_SIZE", 5, min_v=1, max_v=50)
    max_overflow = _env_int("DB_MAX_OVERFLOW", 10, min_v=0, max_v=100)
    pool_timeout = _env_int("DB_POOL_TIMEOUT", 30, min_v=5, max_v=120)
    recycle = _env_int("DB_POOL_RECYCLE", 1800, min_v=300, max_v=7200)

    engine_opts: dict[str, Any] = {
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

    app.config.setdefault("SQLALCHEMY_ENGINE_OPTIONS", engine_opts)

    db.init_app(app)


def _best_redirect_to_account(app: Flask, tab: str) -> Response:
    nxt = _safe_next_path(request.args.get("next", "")) or "/"
    endpoint = str(app.config.get("AUTH_ACCOUNT_ENDPOINT", "auth.account") or "auth.account")
    if _endpoint_exists(app, endpoint):
        return redirect(url_for(endpoint, tab=tab, next=nxt), code=302)
    return redirect("/auth/account?" + urlencode({"tab": tab, "next": nxt}), code=302)


def create_app() -> Flask:
    cfg: Type = get_config()

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
        instance_relative_config=True,
    )

    app.config.from_mapping(cfg.as_flask_config())
    _apply_runtime_defaults(app)
    _ensure_secret_key(app)
    setup_logging(app)

    _ensure_proxyfix_once(app)
    _configure_sqlalchemy(app)

    strict_startup = bool(app.config.get("STRICT_STARTUP", _is_prod(app)))

    csrf = CSRFProtect()
    if bool(app.config.get("CSRF_ENABLED", True)):
        csrf.init_app(app)

    @app.context_processor
    def _inject_globals():
        try:
            vf = set((app.view_functions or {}).keys())
        except Exception:
            vf = set()

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
            "view_functions": {k: True for k in vf},
            "REQUEST_ID": cast(str, getattr(g, "request_id", "")) if hasattr(g, "request_id") else "",
        }

    @app.before_request
    def _before():
        if request.method == "OPTIONS":
            return "", 204

        rid = (request.headers.get("X-Request-Id") or "").strip()
        g.request_id = rid[:128] if rid else secrets.token_urlsafe(10)
        g._t0 = time.time()

        p = request.path.rstrip("/") or "/"
        if request.method in {"GET", "HEAD"}:
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
                ms = int((time.time() - float(t0)) * 1000)
                resp.headers.setdefault("X-Response-Time", f"{ms}ms")
        except Exception:
            pass

        if bool(app.config.get("NO_STORE_ERROR_PAGES", True)) and (resp.status_code >= 400):
            resp.headers.setdefault("Cache-Control", "no-store, max-age=0, must-revalidate")
            resp.headers.setdefault("Pragma", "no-cache")
            resp.headers.setdefault("Expires", "0")

        return _apply_security_headers(app, resp)

    init_ok = True
    init_err: Optional[str] = None
    try:
        init_models(app, create_admin=True, log_loaded_models=True, ping_db=True)
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

    if not _endpoint_exists(app, "_fallback_auth_login"):
        app.add_url_rule(
            "/auth/login",
            "_fallback_auth_login",
            partial(_best_redirect_to_account, app, "login"),
            methods=["GET", "HEAD"],
        )

    if not _endpoint_exists(app, "_fallback_auth_register"):
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
        if not _endpoint_exists(app, endpoint) and not _rule_exists(app, rule):
            app.add_url_rule(rule, endpoint, partial(_best_redirect_to_account, app, tab), methods=["GET", "HEAD"])

    if not _endpoint_exists(app, str(app.config.get("AUTH_ACCOUNT_ENDPOINT", "auth.account"))) and not _rule_exists(app, "/auth/account"):

        @app.get("/auth/account")
        def _emergency_account():
            tab = (request.args.get("tab") or "login").strip().lower()
            if tab not in {"login", "register"}:
                tab = "login"
            nxt = _safe_next_path(request.args.get("next", "")) or "/"
            headers = {}
            if bool(app.config.get("NO_STORE_ERROR_PAGES", True)):
                headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
                headers["Pragma"] = "no-cache"
                headers["Expires"] = "0"
            return render_template("auth/account.html", active_tab=tab, next=nxt, prefill_email=""), 200, headers

    if not _rule_exists(app, "/"):

        @app.get("/")
        def _root():
            for ep in ("main.home", "main.index", "shop.shop"):
                if _endpoint_exists(app, ep):
                    return redirect(url_for(ep), code=302)
            return "Skyline Store", 200, {"Cache-Control": "no-store"}

    @app.get("/health")
    def health():
        rr = stats.get("routes_report") if isinstance(stats.get("routes_report"), dict) else {}
        imports_failed = rr.get("imports_failed", []) if isinstance(rr, dict) else []
        reveal = bool(app.config.get("HEALTH_REVEAL_ERRORS", not _is_prod(app)))
        payload = {
            "status": "ok" if init_ok else "degraded",
            "env": _env_name(app),
            "app": app.config.get("APP_NAME", "Skyline Store"),
            "blueprints": list((app.blueprints or {}).keys()),
            "routes": len(list(app.url_map.iter_rules())),
            "bp_registered": int(stats.get("registered", 0)),
            "bp_failed": int(stats.get("failed", 0)),
            "bp_skipped": int(stats.get("skipped", 0)),
            "auth_account": bool(_endpoint_exists(app, str(app.config.get("AUTH_ACCOUNT_ENDPOINT", "auth.account"))) or _rule_exists(app, "/auth/account")),
            "init_models_ok": bool(init_ok),
            "ts": int(time.time()),
        }
        if reveal:
            payload["bp_failed_names"] = stats.get("failed_names", [])
            payload["errors"] = stats.get("errors", {})
            payload["imports_failed"] = imports_failed
            payload["init_models_error"] = init_err
        return payload

    @app.get("/ready")
    def ready():
        ok = True
        db_ok = True
        try:
            if sql_text is not None:
                db.session.execute(sql_text("SELECT 1"))
            else:
                db.session.execute("SELECT 1")  # type: ignore[arg-type]
        except Exception:
            ok = False
            db_ok = False

        if not init_ok:
            ok = False

        payload = {"ok": ok, "db": db_ok, "init": init_ok, "env": _env_name(app), "ts": int(time.time())}
        return payload, (200 if ok else 503)

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
