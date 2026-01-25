from __future__ import annotations

import importlib
import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Type
from urllib.parse import urlencode, urlparse

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from flask_wtf import CSRFProtect
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from app.config import get_config
from app.models import db, init_models

try:
    from sqlalchemy import text as sql_text  # type: ignore
except Exception:
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
    status_i = int(status or 500)
    err = (code or "error").strip().lower()[:64] or "error"
    msg = (message or "Error").strip()

    if wants_json():
        return jsonify({"ok": False, "error": err, "message": msg, "status": status_i}), status_i

    for tpl in (f"errors/{status_i}.html", "error.html"):
        try:
            return render_template(tpl, message=msg, status=status_i, code=err), status_i
        except Exception:
            continue

    return msg, status_i


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
    if not nxt or not nxt.startswith("/") or nxt.startswith("//"):
        return ""
    if any(c in nxt for c in ("\x00", "\r", "\n", "\\")):
        return ""
    p = urlparse(nxt)
    if p.scheme or p.netloc:
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
        return False
    except Exception:
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
    }

    try:
        from app.routes import register_blueprints as _register_blueprints  # type: ignore

        _register_blueprints(app)
        stats["registered"] = len(app.blueprints or {})
        return stats
    except Exception as e:
        app.logger.exception("register_blueprints() falló: %s", e)
        stats["errors"]["app.routes.register_blueprints"] = f"{type(e).__name__}: {e}"

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
            bp_real_name = getattr(bp, "name", "") or ""
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
    app.config.setdefault("JSON_SORT_KEYS", False)
    app.config.setdefault("JSONIFY_PRETTYPRINT_REGULAR", False)

    setup_logging(app)

    if not app.config.get("SECRET_KEY"):
        if _is_prod(app):
            raise RuntimeError("SECRET_KEY requerido en producción")
        app.config["SECRET_KEY"] = secrets.token_urlsafe(48)

    if not getattr(app, "_proxyfix", False):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
        app._proxyfix = True  # type: ignore[attr-defined]

    app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
    app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
    app.config.setdefault("SESSION_COOKIE_SECURE", _is_prod(app))
    app.config.setdefault("PERMANENT_SESSION_LIFETIME", timedelta(days=14))
    app.config.setdefault("SESSION_REFRESH_EACH_REQUEST", False)
    app.config.setdefault("PREFERRED_URL_SCHEME", "https" if _is_prod(app) else "http")

    csrf = CSRFProtect()
    csrf.init_app(app)

    @app.context_processor
    def _inject_globals():
        try:
            vf = set(app.view_functions.keys())
        except Exception:
            vf = set()
        return {
            "ENV": _env_name(app),
            "APP_NAME": app.config.get("APP_NAME", "Skyline Store"),
            "ASSET_VER": app.config.get("ASSET_VER", app.config.get("BASE_CSS_VER", "1")),
            "HOME_CSS_VER": app.config.get("HOME_CSS_VER", app.config.get("ASSET_VER", "1")),
            "now_year": utcnow().year,
            "view_functions": {k: True for k in vf},
        }

    @app.before_request
    def _before():
        if request.method == "OPTIONS":
            return "", 204

        rid = (request.headers.get("X-Request-Id") or "").strip()
        request._rid = rid[:128] if rid else secrets.token_urlsafe(10)  # type: ignore[attr-defined]
        request._t0 = time.time()  # type: ignore[attr-defined]

        if request.method not in {"GET", "HEAD"}:
            return None

        p = request.path.rstrip("/") or "/"
        nxt = _safe_next_url(request.args.get("next", "")) or "/"

        if p in {"/login", "/auth/login"}:
            return redirect(url_for("_fallback_auth_login", next=nxt), code=302)

        if p in {"/register", "/auth/register"}:
            return redirect(url_for("_fallback_auth_register", next=nxt), code=302)

        return None

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

    def _redir_account(tab: str):
        nxt = _safe_next_url(request.args.get("next", "")) or "/"
        if _endpoint_exists(app, "auth.account"):
            return redirect(url_for("auth.account", tab=tab, next=nxt), code=302)
        return redirect("/auth/account?" + urlencode({"tab": tab, "next": nxt}), code=302)

    if not _endpoint_exists(app, "_fallback_auth_login"):
        app.add_url_rule(
            "/auth/login",
            "_fallback_auth_login",
            lambda: _redir_account("login"),
            methods=["GET", "HEAD"],
        )
        app.add_url_rule(
            "/auth/login/",
            "_fallback_auth_login_slash",
            lambda: _redir_account("login"),
            methods=["GET", "HEAD"],
        )

    if not _endpoint_exists(app, "_fallback_auth_register"):
        app.add_url_rule(
            "/auth/register",
            "_fallback_auth_register",
            lambda: _redir_account("register"),
            methods=["GET", "HEAD"],
        )
        app.add_url_rule(
            "/auth/register/",
            "_fallback_auth_register_slash",
            lambda: _redir_account("register"),
            methods=["GET", "HEAD"],
        )

    for rule, endpoint, tab in (
        ("/login", "_fallback_login", "login"),
        ("/login/", "_fallback_login_slash", "login"),
        ("/register", "_fallback_register", "register"),
        ("/register/", "_fallback_register_slash", "register"),
    ):
        if not _endpoint_exists(app, endpoint) and not _rule_exists(app, rule):
            app.add_url_rule(rule, endpoint, lambda t=tab: _redir_account(t), methods=["GET", "HEAD"])

    if not _endpoint_exists(app, "auth.account") and not _rule_exists(app, "/auth/account"):
        @app.get("/auth/account")
        def _emergency_account():
            tab = (request.args.get("tab") or "login").strip().lower()
            if tab not in {"login", "register"}:
                tab = "login"
            nxt = _safe_next_url(request.args.get("next", "")) or "/"
            return (
                render_template(
                    "auth/account.html",
                    active_tab=tab,
                    next=nxt,
                    prefill_email="",
                ),
                200,
                {"Cache-Control": "no-store"},
            )

    if not _rule_exists(app, "/"):
        @app.get("/")
        def _root():
            if _endpoint_exists(app, "main.home"):
                return redirect(url_for("main.home"), code=302)
            if _endpoint_exists(app, "main.index"):
                return redirect(url_for("main.index"), code=302)
            if _endpoint_exists(app, "shop.shop"):
                return redirect(url_for("shop.shop"), code=302)
            return "Skyline Store", 200

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
            "bp_skipped": int(stats.get("skipped", 0)),
            "bp_failed_names": stats.get("failed_names", []),
            "auth_account": bool(_endpoint_exists(app, "auth.account") or _rule_exists(app, "/auth/account")),
            "errors": stats.get("errors", {}),
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
        return {"ok": ok, "db": db_ok, "env": _env_name(app), "ts": int(time.time())}, (200 if ok else 503)

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
        "✅ Skyline Store iniciado (%s) | blueprints=%s | auth.account=%s",
        _env_name(app),
        list((app.blueprints or {}).keys()),
        "OK" if _endpoint_exists(app, "auth.account") else "MISSING",
    )
    return app


__all__ = ["create_app", "db"]
