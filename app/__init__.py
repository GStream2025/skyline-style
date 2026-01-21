from __future__ import annotations

import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Type

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from flask_wtf import CSRFProtect
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from app.config import get_config
from app.models import db, init_models

_TRUE = {"1", "true", "yes", "y", "on", "checked"}


def _env_str(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


def _env_bool(name: str, default: bool = False) -> bool:
    v = _env_str(name, "")
    if not v:
        return default
    s = v.lower().strip()
    if s in _TRUE:
        return True
    if s in {"0", "false", "no", "n", "off"}:
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


def _safe_next_url() -> Optional[str]:
    nxt = (request.args.get("next") or "").strip()
    if not nxt:
        return None
    if nxt.startswith("/") and not nxt.startswith("//"):
        return nxt[:512]
    return None


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

    csrf = CSRFProtect()
    csrf.init_app(app)

    @app.before_request
    def _before():
        if request.method == "OPTIONS":
            return "", 204

        rid = (request.headers.get("X-Request-Id") or "").strip()
        request._rid = rid[:128] if rid else secrets.token_urlsafe(8)  # type: ignore[attr-defined]
        request._t0 = time.time()  # type: ignore[attr-defined]

        if request.method in {"GET", "HEAD"}:
            p = request.path
            nxt = _safe_next_url() or "/"
            if p in {"/login", "/auth/login"}:
                return redirect(url_for("auth.account", tab="login", next=nxt))
            if p in {"/register", "/auth/register"}:
                return redirect(url_for("auth.account", tab="register", next=nxt))

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

    from app.routes import register_blueprints

    register_blueprints(app)

    if "/" not in app.view_functions:

        @app.get("/")
        def root():
            if "shop.shop" in app.view_functions:
                return redirect(url_for("shop.shop"))
            return "Skyline Store"

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "env": _env_name(app),
            "app": app.config.get("APP_NAME", "Skyline Store"),
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

    app.logger.info("✅ Skyline Store iniciado correctamente (%s)", _env_name(app))
    return app


__all__ = ["create_app", "db"]
