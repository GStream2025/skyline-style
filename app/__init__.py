from __future__ import annotations

import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Type

from flask import Flask, jsonify, redirect, render_template, request, url_for
from flask_wtf import CSRFProtect
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from app.config import get_config
from app.models import db, init_models

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
    env = str(env).lower().strip()
    if env in {"prod", "production"}:
        return "production"
    if env in {"dev", "development"}:
        return "development"
    return "development" if bool(app.config.get("DEBUG")) else "production"


def _is_prod(app: Flask) -> bool:
    return _env_name(app) == "production" and not bool(app.debug)


def wants_json() -> bool:
    if request.is_json:
        return True
    accept = (request.headers.get("Accept") or "").lower()
    if "application/json" in accept:
        return True
    if (request.headers.get("X-Requested-With") or "").lower() == "xmlhttprequest":
        return True
    if (request.args.get("format") or "").lower() == "json":
        return True
    return False


def resp_error(status: int, code: str, message: str):
    status = int(status or 500)
    code = (code or "error").strip().lower()[:64] or "error"
    message = (message or "Error").strip()

    if wants_json():
        return jsonify({"ok": False, "error": code, "message": message, "status": status}), status

    for tpl in (f"errors/{status}.html", "error.html"):
        try:
            return render_template(tpl, message=message, status=status, code=code), status
        except Exception:
            continue

    return message, status


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


def _safe_next_url(v: str) -> str:
    nxt = (v or "").strip()
    if not nxt:
        return ""
    if not nxt.startswith("/") or nxt.startswith("//"):
        return ""
    if any(c in nxt for c in ("\x00", "\r", "\n", "\\")):
        return ""
    return nxt[:512]


def _route_exists(app: Flask, endpoint: str) -> bool:
    try:
        return endpoint in (app.view_functions or {})
    except Exception:
        return False


def _register_blueprints_fail_safe(app: Flask) -> dict:
    stats = {
        "registered": 0,
        "failed": 0,
        "failed_names": [],
    }

    try:
        from app.routes import register_blueprints as _register_blueprints  # type: ignore

        _register_blueprints(app)
        stats["registered"] = len(app.blueprints or {})
        return stats
    except Exception as e:
        app.logger.exception("register_blueprints() falló: %s", e)

    candidates = [
        ("app.routes.auth_routes", "auth_bp"),
        ("app.routes.main_routes", "main_bp"),
        ("app.routes.shop_routes", "shop_bp"),
        ("app.routes.cart_routes", "cart_bp"),
        ("app.routes.checkout_routes", "checkout_bp"),
        ("app.routes.admin_routes", "admin_bp"),
        ("app.routes.account_routes", "account_bp"),
        ("app.routes.profile_routes", "profile_bp"),
        ("app.routes.marketing_routes", "marketing_bp"),
        ("app.routes.api_routes", "api_bp"),
        ("app.routes.webhook_routes", "webhook_bp"),
        ("app.routes.affiliate_routes", "affiliate_bp"),
        ("app.routes.printful_routes", "printful_bp"),
        ("app.routes.address_routes", "address_bp"),
        ("app.routes.admin_payments_routes", "admin_payments_bp"),
    ]

    for mod_name, bp_name in candidates:
        try:
            mod = __import__(mod_name, fromlist=[bp_name])
            bp = getattr(mod, bp_name, None)
            if bp is None:
                continue
            app.register_blueprint(bp)
            stats["registered"] += 1
        except Exception:
            stats["failed"] += 1
            stats["failed_names"].append(f"{mod_name}:{bp_name}")

    return stats


def create_app() -> Flask:
    cfg: Type = get_config()

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
        instance_relative_config=True,
    )

    app.config.from_mapping(cfg.as_flask_config())

    app.config.setdefault(
        "MAX_CONTENT_LENGTH",
        _env_int("MAX_CONTENT_LENGTH", 2_000_000, min_v=200_000, max_v=25_000_000),
    )

    setup_logging(app)

    if not app.config.get("SECRET_KEY"):
        if _is_prod(app):
            raise RuntimeError("SECRET_KEY requerido en producción")
        app.config["SECRET_KEY"] = secrets.token_urlsafe(32)

    if not getattr(app, "_proxyfix", False):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
        app._proxyfix = True  # type: ignore[attr-defined]

    app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
    app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
    app.config.setdefault("SESSION_COOKIE_SECURE", _is_prod(app))
    app.config.setdefault("PERMANENT_SESSION_LIFETIME", timedelta(days=7))
    app.config.setdefault("SESSION_REFRESH_EACH_REQUEST", False)
    app.config.setdefault("PREFERRED_URL_SCHEME", "https" if _is_prod(app) else "http")

    csrf = CSRFProtect()
    csrf.init_app(app)

    @app.context_processor
    def _inject_globals():
        try:
            vf = dict(app.view_functions)
        except Exception:
            vf = {}
        return {
            "ENV": _env_name(app),
            "APP_NAME": app.config.get("APP_NAME", "Skyline Store"),
            "ASSET_VER": app.config.get("ASSET_VER", app.config.get("BASE_CSS_VER", "1")),
            "HOME_CSS_VER": app.config.get("HOME_CSS_VER", app.config.get("ASSET_VER", "1")),
            "now_year": utcnow().year,
            "view_functions": vf,
        }

    @app.before_request
    def _before():
        if request.method == "OPTIONS":
            return "", 204

        rid = (request.headers.get("X-Request-Id") or "").strip()
        request._rid = rid[:128] if rid else secrets.token_urlsafe(8)  # type: ignore[attr-defined]
        request._t0 = time.time()  # type: ignore[attr-defined]

        if request.method in {"GET", "HEAD"}:
            p = request.path.rstrip("/") or "/"
            nxt = _safe_next_url(request.args.get("next", "")) or "/"

            if p in {"/login", "/auth/login"}:
                if _route_exists(app, "auth.account"):
                    return redirect(url_for("auth.account", tab="login", next=nxt))
                return redirect("/auth/account?tab=login&next=" + nxt)

            if p in {"/register", "/auth/register"}:
                if _route_exists(app, "auth.account"):
                    return redirect(url_for("auth.account", tab="register", next=nxt))
                return redirect("/auth/account?tab=register&next=" + nxt)

    @app.after_request
    def _after(resp):
        resp.headers.setdefault("X-Request-Id", getattr(request, "_rid", ""))
        t0 = getattr(request, "_t0", None)
        if isinstance(t0, (int, float)):
            ms = int((time.time() - float(t0)) * 1000)
            resp.headers.setdefault("X-Response-Time", f"{ms}ms")

        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")

        if _is_prod(app):
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

        return resp

    init_models(app, create_admin=True, log_loaded_models=True, ping_db=True)

    @app.teardown_appcontext
    def _shutdown(_exc):
        try:
            db.session.remove()
        except Exception:
            pass

    stats = _register_blueprints_fail_safe(app)

    if not _route_exists(app, "auth.account"):
        app.logger.error("❌ auth.account NO registrado. Revisá app/routes/__init__.py o imports de auth_routes.py")

    if not _route_exists(app, "main.home") and not _route_exists(app, "main.index"):
        app.logger.warning("⚠️ main blueprint no detectado (home/index).")

    if "/" not in app.view_functions:

        @app.get("/")
        def root():
            if _route_exists(app, "main.home"):
                return redirect(url_for("main.home"))
            if _route_exists(app, "main.index"):
                return redirect(url_for("main.index"))
            if _route_exists(app, "shop.shop"):
                return redirect(url_for("shop.shop"))
            return "Skyline Store"

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "env": _env_name(app),
            "app": app.config.get("APP_NAME", "Skyline Store"),
            "blueprints": list((app.blueprints or {}).keys()),
            "routes": len(list(app.url_map.iter_rules())),
            "bp_registered": int(stats.get("registered", 0)),
            "bp_failed": int(stats.get("failed", 0)),
            "bp_failed_names": stats.get("failed_names", []),
            "auth_account": bool(_route_exists(app, "auth.account")),
            "ts": int(time.time()),
        }

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

    app.logger.info("✅ Skyline Store iniciado correctamente (%s) | blueprints=%s", _env_name(app), list((app.blueprints or {}).keys()))
    return app


__all__ = ["create_app", "db"]
