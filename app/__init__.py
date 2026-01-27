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
except Exception:  # pragma: no cover
    sql_text = None  # type: ignore


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
    if v < min_v:
        return min_v
    if v > max_v:
        return max_v
    return v


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _env_name(app: Flask) -> str:
    env = (
        app.config.get("ENV")
        or app.config.get("ENVIRONMENT")
        or _env_str("ENV")
        or _env_str("FLASK_ENV")
        or "production"
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
        if "application/json" in accept:
            return True
        if (request.headers.get("X-Requested-With") or "").lower() == "xmlhttprequest":
            return True
        if (request.args.get("format") or "").lower() == "json":
            return True
    except Exception:
        return False
    return False


def resp_error(status: int, code: str, message: str):
    status_i = int(status or 500)
    err = (code or "error").strip().lower()[:64] or "error"
    msg = (message or "Error").strip()

    if wants_json():
        return jsonify({"ok": False, "error": err, "message": msg, "status": status_i}), status_i

    for tpl in (f"errors/{status_i}.html", "error.html"):
        try:
            body = render_template(tpl, message=msg, status=status_i, code=err)
            return body, status_i, {"Cache-Control": "no-store"}
        except Exception:
            continue

    return msg, status_i, {"Cache-Control": "no-store"}


def setup_logging(app: Flask) -> None:
    level = logging.DEBUG if bool(app.debug) else logging.INFO
    root = logging.getLogger()

    # (1) No dup handlers (evita logs repetidos con gunicorn / reloader)
    if not root.handlers:
        logging.basicConfig(
            level=level,
            format="%(asctime)s | %(levelname)s | %(name)s:%(lineno)d — %(message)s",
        )

    root.setLevel(level)
    app.logger.setLevel(level)


def _safe_next_url(v: str) -> str:
    # (2) Solo paths internos + anti header-injection + length cap
    nxt = (v or "").strip()
    if not nxt or not nxt.startswith("/") or nxt.startswith("//"):
        return ""
    if any(c in nxt for c in ("\x00", "\r", "\n", "\\")):
        return ""
    p = urlparse(nxt)
    if p.scheme or p.netloc:
        return ""
    return nxt[:512] if len(nxt) > 512 else nxt


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


def _register_blueprints_fail_safe(app: Flask) -> dict[str, Any]:
    stats: dict[str, Any] = {
        "registered": 0,
        "failed": 0,
        "skipped": 0,
        "failed_names": [],
        "errors": {},
        "routes_report": {},
    }

    # (3) Preferimos un register_blueprints central si existe
    try:
        from app.routes import register_blueprints as _register_blueprints  # type: ignore

        report = _register_blueprints(app)
        stats["routes_report"] = report if isinstance(report, dict) else {}
        stats["registered"] = len(app.blueprints or {})
        return stats
    except Exception as e:
        app.logger.exception("register_blueprints() falló: %s", e)
        stats["errors"]["app.routes.register_blueprints"] = f"{type(e).__name__}: {e}"

    # (4) Fallback: lista segura (no rompe startup si falta un módulo)
    candidates = [
        ("app.routes.main_routes", "main_bp"),
        ("app.routes.shop_routes", "shop_bp"),
        ("app.routes.auth_routes", "auth_bp"),
        ("app.routes.account_routes", "account_bp"),
        ("app.routes.cuenta_routes", "cuenta_bp"),
        ("app.routes.cart_routes", "cart_bp"),
        ("app.routes.checkout_routes", "checkout_bp"),
        ("app.routes.api_routes", "api_bp"),
        ("app.routes.affiliate_routes", "affiliate_bp"),
        ("app.routes.marketing_routes", "marketing_bp"),
        ("app.routes.webhooks_routes", "webhooks_bp"),
        ("app.routes.webhook_routes", "webhook_bp"),
        ("app.routes.admin_routes", "admin_bp"),
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
            # (5) Evita doble registro por name
            bp_real_name = str(getattr(bp, "name", "") or "").strip()
            if bp_real_name and bp_real_name in (app.blueprints or {}):
                stats["skipped"] += 1
                continue

            app.register_blueprint(bp)
            stats["registered"] += 1
        except Exception as e:
            stats["failed"] += 1
            stats["failed_names"].append(f"{mod_name}:{bp_name}")
            stats["errors"][f"{mod_name}:{bp_name}"] = f"{type(e).__name__}: {e}"

    return stats


def _apply_default_runtime_config(app: Flask) -> None:
    # (6) Defaults “seguros” + consistentes
    app.config.setdefault("MAX_CONTENT_LENGTH", _env_int("MAX_CONTENT_LENGTH", 2_000_000, min_v=200_000, max_v=25_000_000))
    app.config.setdefault("JSON_SORT_KEYS", False)
    app.config.setdefault("JSONIFY_PRETTYPRINT_REGULAR", False)

    # Cookies / sesiones (7-12)
    app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
    app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
    app.config.setdefault("PERMANENT_SESSION_LIFETIME", timedelta(days=14))
    app.config.setdefault("SESSION_REFRESH_EACH_REQUEST", False)
    app.config.setdefault("PREFERRED_URL_SCHEME", "https" if _is_prod(app) else "http")

    # Secure cookies solo prod (13)
    app.config.setdefault("SESSION_COOKIE_SECURE", _is_prod(app))

    # ProxyFix knobs por env/config (14)
    app.config.setdefault("PROXYFIX_X_FOR", _env_int("PROXYFIX_X_FOR", 1, min_v=0, max_v=5))
    app.config.setdefault("PROXYFIX_X_PROTO", _env_int("PROXYFIX_X_PROTO", 1, min_v=0, max_v=5))
    app.config.setdefault("PROXYFIX_X_HOST", _env_int("PROXYFIX_X_HOST", 1, min_v=0, max_v=5))

    # Security headers toggles (15-18)
    app.config.setdefault("SEC_HEADERS_ENABLED", True)
    app.config.setdefault("HSTS_ENABLED", _is_prod(app))
    app.config.setdefault("HSTS_MAX_AGE", 31536000)
    app.config.setdefault("NO_STORE_ERROR_PAGES", True)

    # CSRF toggle (19)
    app.config.setdefault("CSRF_ENABLED", True)


def _ensure_secret_key(app: Flask) -> None:
    # (20) Secret key: fail hard en prod, generar en dev
    if app.config.get("SECRET_KEY"):
        return
    if _is_prod(app):
        raise RuntimeError("SECRET_KEY requerido en producción")
    app.config["SECRET_KEY"] = secrets.token_urlsafe(48)


def _ensure_proxyfix_once(app: Flask) -> None:
    # (21) ProxyFix una sola vez (anti-double wrap)
    if getattr(app, "_proxyfix_applied", False):
        return
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=int(app.config.get("PROXYFIX_X_FOR", 1)),
        x_proto=int(app.config.get("PROXYFIX_X_PROTO", 1)),
        x_host=int(app.config.get("PROXYFIX_X_HOST", 1)),
    )
    app._proxyfix_applied = True  # type: ignore[attr-defined]


def _security_headers_after_request(app: Flask, resp: Response) -> Response:
    if not bool(app.config.get("SEC_HEADERS_ENABLED", True)):
        return resp

    # (22) Cabeceras seguras con setdefault (no pisa lo que ya pusiste)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")

    # (23) HSTS solo prod (si no está detrás de HTTPS real, desactivalo)
    if bool(app.config.get("HSTS_ENABLED", False)) and _is_prod(app):
        max_age = int(app.config.get("HSTS_MAX_AGE", 31536000) or 31536000)
        resp.headers.setdefault("Strict-Transport-Security", f"max-age={max_age}; includeSubDomains")

    return resp


def create_app() -> Flask:
    cfg: Type = get_config()

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
        instance_relative_config=True,
    )

    # (24) Config centralizado + defaults runtime
    app.config.from_mapping(cfg.as_flask_config())
    _apply_default_runtime_config(app)

    setup_logging(app)

    strict_startup = _env_bool("STRICT_STARTUP", _is_prod(app))

    _ensure_secret_key(app)
    _ensure_proxyfix_once(app)

    # (25) CSRF opcional (para APIs / webhooks)
    csrf = CSRFProtect()
    if bool(app.config.get("CSRF_ENABLED", True)):
        csrf.init_app(app)

    # (26) Context globals robusto (no explota si faltan cosas)
    @app.context_processor
    def _inject_globals():
        try:
            vf = set((app.view_functions or {}).keys())
        except Exception:
            vf = set()

        asset_ver = app.config.get("ASSET_VER", app.config.get("BASE_CSS_VER", "1"))
        home_ver = app.config.get("HOME_CSS_VER", asset_ver)

        return {
            "ENV": _env_name(app),
            "APP_NAME": app.config.get("APP_NAME", "Skyline Store"),
            "ASSET_VER": asset_ver,
            "HOME_CSS_VER": home_ver,
            "now_year": utcnow().year,
            # Mapa booleando para Jinja (no filtra funciones reales)
            "view_functions": {k: True for k in vf},
        }

    # (27-31) Observabilidad: request id + timing sin ensuciar request object
    @app.before_request
    def _before():
        # OPTIONS rápido (útil para preflight, health checks, etc.)
        if request.method == "OPTIONS":
            return "", 204

        rid = (request.headers.get("X-Request-Id") or "").strip()
        g.request_id = (rid[:128] if rid else secrets.token_urlsafe(10))
        g._t0 = time.time()

        # (32-35) Canonicalización de login/register sin loops
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            return None

        p = request.path.rstrip("/") or "/"
        nxt = _safe_next_url(request.args.get("next", "")) or "/"

        if p in {"/login", "/auth/login"}:
            if _endpoint_exists(app, "_fallback_auth_login"):
                return redirect(url_for("_fallback_auth_login", next=nxt), code=302)
            return redirect("/auth/login?" + urlencode({"next": nxt}), code=302)

        if p in {"/register", "/auth/register"}:
            if _endpoint_exists(app, "_fallback_auth_register"):
                return redirect(url_for("_fallback_auth_register", next=nxt), code=302)
            return redirect("/auth/register?" + urlencode({"next": nxt}), code=302)

        return None

    @app.after_request
    def _after(resp: Response):
        # (36) Request id + response time
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

        # (37) Security headers centralizados
        resp = _security_headers_after_request(app, resp)
        return resp

    # (38-43) init_models fail-safe + strict_startup
    init_ok = True
    init_err: Optional[str] = None
    try:
        init_models(app, create_admin=True, log_loaded_models=True, ping_db=True)
    except Exception as e:
        init_ok = False
        init_err = f"{type(e).__name__}: {e}"
        app.logger.exception("init_models() falló: %s", e)
        app.config["_INIT_MODELS_ERROR"] = init_err
        if strict_startup:
            raise

    @app.teardown_appcontext
    def _shutdown(_exc):
        # (44) Cierre de sesión DB seguro
        try:
            db.session.remove()
        except Exception:
            pass

    stats = _register_blueprints_fail_safe(app)

    def _redir_account(tab: str):
        # (45) Redirección account robusta (endpoint si existe, si no hardlink)
        nxt = _safe_next_url(request.args.get("next", "")) or "/"
        if _endpoint_exists(app, "auth.account"):
            return redirect(url_for("auth.account", tab=tab, next=nxt), code=302)
        return redirect("/auth/account?" + urlencode({"tab": tab, "next": nxt}), code=302)

    # Fallbacks /auth/login y /auth/register (GET/HEAD)
    if not _endpoint_exists(app, "_fallback_auth_login"):
        app.add_url_rule(
            "/auth/login",
            "_fallback_auth_login",
            partial(_redir_account, "login"),
            methods=["GET", "HEAD"],
        )

    if not _endpoint_exists(app, "_fallback_auth_register"):
        app.add_url_rule(
            "/auth/register",
            "_fallback_auth_register",
            partial(_redir_account, "register"),
            methods=["GET", "HEAD"],
        )

    # /login y /register legacy (solo si no existen)
    for rule, endpoint, tab in (
        ("/login", "_fallback_login", "login"),
        ("/register", "_fallback_register", "register"),
    ):
        if not _endpoint_exists(app, endpoint) and not _rule_exists(app, rule):
            app.add_url_rule(rule, endpoint, partial(_redir_account, tab), methods=["GET", "HEAD"])

    # Emergency /auth/account si falta el endpoint real
    if not _endpoint_exists(app, "auth.account") and not _rule_exists(app, "/auth/account"):

        @app.get("/auth/account")
        def _emergency_account():
            tab = (request.args.get("tab") or "login").strip().lower()
            if tab not in {"login", "register"}:
                tab = "login"
            nxt = _safe_next_url(request.args.get("next", "")) or "/"
            headers = {"Cache-Control": "no-store"} if bool(app.config.get("NO_STORE_ERROR_PAGES", True)) else {}
            return render_template("auth/account.html", active_tab=tab, next=nxt, prefill_email=""), 200, headers

    # Root fallback si nadie definió "/"
    if not _rule_exists(app, "/"):

        @app.get("/")
        def _root():
            if _endpoint_exists(app, "main.home"):
                return redirect(url_for("main.home"), code=302)
            if _endpoint_exists(app, "main.index"):
                return redirect(url_for("main.index"), code=302)
            if _endpoint_exists(app, "shop.shop"):
                return redirect(url_for("shop.shop"), code=302)
            return "Skyline Store", 200, {"Cache-Control": "no-store"}

    @app.get("/health")
    def health():
        rr = stats.get("routes_report") if isinstance(stats.get("routes_report"), dict) else {}
        imports_failed = rr.get("imports_failed", []) if isinstance(rr, dict) else []
        return {
            "status": "ok" if init_ok else "degraded",
            "env": _env_name(app),
            "app": app.config.get("APP_NAME", "Skyline Store"),
            "blueprints": list((app.blueprints or {}).keys()),
            "routes": len(list(app.url_map.iter_rules())),
            "bp_registered": int(stats.get("registered", 0)),
            "bp_failed": int(stats.get("failed", 0)),
            "bp_skipped": int(stats.get("skipped", 0)),
            "bp_failed_names": stats.get("failed_names", []),
            "auth_account": bool(_endpoint_exists(app, "auth.account") or _rule_exists(app, "/auth/account")),
            "errors": stats.get("errors", {}),
            "imports_failed": imports_failed,
            "init_models_ok": bool(init_ok),
            "init_models_error": init_err,
            "ts": int(time.time()),
        }

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
        "✅ Skyline Store iniciado (%s) | strict_startup=%s | init_models=%s | blueprints=%s | auth.account=%s",
        _env_name(app),
        "ON" if strict_startup else "OFF",
        "OK" if init_ok else "FAIL",
        list((app.blueprints or {}).keys()),
        "OK" if _endpoint_exists(app, "auth.account") else "MISSING",
    )
    return app


__all__ = ["create_app", "db"]
