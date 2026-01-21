# app/__init__.py — Skyline Store
# ULTRA PRO / NO BREAK / Render-safe / Flask 3 READY / BULLETPROOF

from __future__ import annotations

import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Type
from urllib.parse import urlencode

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from app.config import ProductionConfig, get_config
from app.models import db, init_models

# ─────────────────────────────────────────────────────────────
# Optional admin bootstrap
# ─────────────────────────────────────────────────────────────
try:
    from app.models import create_admin_if_missing  # type: ignore
except Exception:
    create_admin_if_missing = None  # type: ignore


# ─────────────────────────────────────────────────────────────
# ENV helpers
# ─────────────────────────────────────────────────────────────
_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off"}


def _env_str(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


def _env_bool(name: str, default: bool = False) -> bool:
    v = _env_str(name, "")
    if not v:
        return default
    return v.lower() in _TRUE


def _env_int(name: str, default: int, *, min_v: int = 0, max_v: int = 10**9) -> int:
    try:
        v = int(_env_str(name, str(default)))
    except Exception:
        v = default
    return max(min_v, min(max_v, v))


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _env_name(app: Flask) -> str:
    return (
        app.config.get("ENV")
        or app.config.get("ENVIRONMENT")
        or _env_str("ENV")
        or "production"
    ).lower().strip()


def _is_prod(app: Flask) -> bool:
    return not bool(app.debug) and _env_name(app) == "production"


# ─────────────────────────────────────────────────────────────
# JSON negotiation
# ─────────────────────────────────────────────────────────────
def wants_json() -> bool:
    if request.is_json:
        return True
    if (request.headers.get("Accept") or "").lower().find("application/json") >= 0:
        return True
    if (request.headers.get("X-Requested-With") or "").lower() == "xmlhttprequest":
        return True
    if (request.args.get("format") or "").lower() == "json":
        return True
    return False


def resp_error(status: int, code: str, message: str):
    if wants_json():
        return jsonify(
            {"ok": False, "error": code, "message": message, "status": status}
        ), status

    for tpl in (f"errors/{status}.html", "error.html"):
        try:
            return render_template(tpl, message=message, status=status, code=code), status
        except Exception:
            pass

    return message, status


# ─────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────
def setup_logging(app: Flask) -> None:
    level = logging.DEBUG if app.debug else logging.INFO
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(
            level=level,
            format="%(asctime)s | %(levelname)s | %(name)s:%(lineno)d — %(message)s",
        )
    root.setLevel(level)
    app.logger.setLevel(level)


# ─────────────────────────────────────────────────────────────
# App Factory
# ─────────────────────────────────────────────────────────────
def create_app() -> Flask:
    cfg: Type = get_config()

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
        instance_relative_config=True,
    )

    # Config
    app.config.from_mapping(cfg.as_flask_config())

    # Seguridad base
    app.config.setdefault(
        "MAX_CONTENT_LENGTH",
        _env_int("MAX_CONTENT_LENGTH", 2_000_000, min_v=200_000, max_v=25_000_000),
    )

    setup_logging(app)

    # SECRET KEY
    if not app.config.get("SECRET_KEY"):
        if _is_prod(app):
            raise RuntimeError("SECRET_KEY requerido en producción")
        app.config["SECRET_KEY"] = secrets.token_urlsafe(32)

    # ProxyFix (Render / Cloudflare safe)
    if not getattr(app, "_proxyfix", False):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
        app._proxyfix = True  # type: ignore[attr-defined]

    # Cookies / sesión
    app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
    app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
    app.config.setdefault("SESSION_COOKIE_SECURE", _is_prod(app))
    app.config.setdefault("PERMANENT_SESSION_LIFETIME", timedelta(days=7))

    # CSRF
    from flask_wtf import CSRFProtect
    CSRFProtect(app)

    # Request pipeline
    @app.before_request
    def _before():
        if request.method == "OPTIONS":
            return "", 204
        request._rid = request.headers.get("X-Request-Id") or secrets.token_urlsafe(8)  # type: ignore
        request._t0 = time.time()  # type: ignore

        # Legacy redirects (NO 404)
        if request.method in {"GET", "HEAD"}:
            p = request.path
            if p in {"/login", "/auth/login"}:
                return redirect(url_for("auth.account", tab="login", next="/"))
            if p in {"/register", "/auth/register"}:
                return redirect(url_for("auth.account", tab="register", next="/"))

    @app.after_request
    def _after(resp):
        resp.headers.setdefault("X-Request-Id", getattr(request, "_rid", ""))
        if hasattr(request, "_t0"):
            ms = int((time.time() - request._t0) * 1000)  # type: ignore
            resp.headers.setdefault("X-Response-Time", f"{ms}ms")

        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")

        if _is_prod(app):
            resp.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return resp

    # DB init
    init_models(app, create_admin=True, log_loaded_models=True, ping_db=True)

    @app.teardown_appcontext
    def _shutdown(_exc):
        try:
            db.session.remove()
        except Exception:
            pass

    # Blueprints
    from app.routes import register_blueprints
    register_blueprints(app)

    # Root safety
    if "/" not in app.view_functions:
        @app.get("/")
        def root():
            return redirect(url_for("shop.shop")) if "shop.shop" in app.view_functions else "Skyline Store"

    # Health
    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "env": _env_name(app),
            "app": app.config.get("APP_NAME", "Skyline Store"),
            "ts": int(time.time()),
        }

    # Errors
    @app.errorhandler(HTTPException)
    def http_error(e: HTTPException):
        return resp_error(e.code or 500, e.name.lower(), e.description)

    @app.errorhandler(Exception)
    def fatal(e: Exception):
        app.logger.exception("Fatal error")
        return resp_error(500, "server_error", "Error interno del servidor")

    app.logger.info("✅ Skyline Store iniciado correctamente (%s)", _env_name(app))
    return app


__all__ = ["create_app", "db"]
