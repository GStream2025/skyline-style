# app/__init__.py — Skyline Store (ULTRA PRO / NO BREAK / Render-safe)
from __future__ import annotations

import logging
import os
import secrets
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Type

from flask import Flask, jsonify, render_template, request, session
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from app.models import db, init_models
from app.config import get_config, ProductionConfig


# ✅ compat (no rompe si no existe)
try:
    from app.models import create_admin_if_missing  # type: ignore
except Exception:
    create_admin_if_missing = None  # type: ignore


# =============================================================================
# Helpers
# =============================================================================

_TRUE = {"1", "true", "yes", "y", "on"}
_FALSE = {"0", "false", "no", "n", "off"}


def _env_str(name: str, default: str = "") -> str:
    v = os.getenv(name)
    return (default if v is None else str(v)).strip()


def _env_bool(name: str, default: bool = False) -> bool:
    v = _env_str(name, "")
    if not v:
        return default
    v = v.lower()
    if v in _TRUE:
        return True
    if v in _FALSE:
        return False
    return default


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def wants_json() -> bool:
    """Negociación JSON correcta (API / AJAX / Accept)."""
    p = (request.path or "").lower()
    if p.startswith("/api/") or p.startswith("/webhooks/") or p.startswith("/webhook"):
        return True
    if (_env_str("FORCE_JSON_ERRORS", "") or "").lower() in _TRUE:
        return True
    if (request.args.get("format") or "").lower() == "json":
        return True
    accept = (request.headers.get("Accept") or "").lower()
    if "application/json" in accept:
        return True
    if (request.headers.get("X-Requested-With") or "").lower() == "xmlhttprequest":
        return True
    return False


def resp_error(status: int, code: str, message: str):
    if wants_json():
        return jsonify({"ok": False, "error": code, "message": message, "status": status}), status
    try:
        return render_template(f"errors/{status}.html", message=message), status
    except Exception:
        try:
            return render_template("error.html", message=message), status
        except Exception:
            return message, status


def setup_logging(app: Flask) -> None:
    """Idempotente: no duplica handlers en gunicorn."""
    lvl = (_env_str("LOG_LEVEL", "")).upper()
    if lvl in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}:
        level = getattr(logging, lvl)
    else:
        level = logging.DEBUG if app.debug else logging.INFO

    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(
            level=level,
            format="%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d - %(message)s",
        )
    root.setLevel(level)
    app.logger.setLevel(level)


def safe_init(app: Flask, label: str, fn: Callable[[], Any]) -> Any:
    """Init opcional sin romper deploy."""
    try:
        out = fn()
        app.logger.info("✅ %s inicializado", label)
        return out
    except Exception as e:
        app.logger.warning("⚠️ %s omitido: %s", label, e, exc_info=bool(app.debug))
        return None


def critical_init(app: Flask, label: str, fn: Callable[[], Any]) -> Any:
    """Init crítico con log full."""
    try:
        out = fn()
        app.logger.info("✅ %s inicializado", label)
        return out
    except Exception as e:
        app.logger.exception("🔥 %s falló (CRÍTICO): %s", label, e)
        raise


def has_endpoint(app: Flask, endpoint: str) -> bool:
    """Helper para Jinja: evita romper templates si una ruta no existe."""
    try:
        return endpoint in app.view_functions
    except Exception:
        return False


def current_user_from_session() -> Any:
    """Fallback simple si todavía no estás usando Flask-Login para todo."""
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        from app.models import User  # lazy import (no rompe)
        return db.session.get(User, int(uid))
    except Exception:
        return None


def _is_prod(app: Flask) -> bool:
    env = (app.config.get("ENV") or _env_str("ENV") or _env_str("FLASK_ENV") or "production").lower()
    return env == "production"


def _require_secret_key_prod(app: Flask) -> None:
    """Guard fuerte en prod (evita CSRF/session mismatch)."""
    if not _is_prod(app):
        return
    sk = (app.config.get("SECRET_KEY") or "").strip()
    if (not sk) or (len(sk) < 32):
        raise RuntimeError(
            "SECRET_KEY requerido en producción (>=32 chars). "
            "Si no, CSRF y sesiones fallan (token mismatch)."
        )


# =============================================================================
# CSRF (Flask-WTF)
# =============================================================================

def init_csrf(app: Flask) -> None:
    """
    CSRFProtect estable para Render.
    ✅ No pisa csrf_token()
    ✅ Exime prefijos (webhooks/api) sin re-exempt cada request
    ✅ Manejo de CSRFError uniforme
    """
    from flask_wtf import CSRFProtect
    from flask_wtf.csrf import CSRFError

    csrf = CSRFProtect()
    csrf.init_app(app)

    exempt_prefixes: Set[str] = {
        "/webhook",
        "/webhooks",
        "/api/webhook",
        "/api/webhooks",
    }
    extra = _env_str("CSRF_EXEMPT_PREFIXES", "")
    if extra:
        for pref in [x.strip() for x in extra.split(",") if x.strip()]:
            exempt_prefixes.add(pref)

    exempted_endpoints: Set[str] = set()

    @app.before_request
    def _csrf_exempt_by_prefix():
        if request.method in {"GET", "HEAD", "OPTIONS"}:
            return None

        p = (request.path or "")
        if not p:
            return None

        for pref in exempt_prefixes:
            if p.startswith(pref):
                ep = request.endpoint or ""
                if ep and ep not in exempted_endpoints:
                    try:
                        vf = app.view_functions.get(ep)
                        if vf:
                            csrf.exempt(vf)
                            exempted_endpoints.add(ep)
                    except Exception:
                        pass
                break
        return None

    @app.errorhandler(CSRFError)
    def _handle_csrf_error(_e: CSRFError):
        return resp_error(
            400,
            "csrf_failed",
            "Solicitud inválida. El formulario expiró o el token de seguridad no coincide. "
            "Recargá la página e intentá nuevamente.",
        )


# =============================================================================
# Optional extensions (no-break)
# =============================================================================

def init_compress(app: Flask) -> None:
    from flask_compress import Compress
    Compress(app)


def init_talisman(app: Flask) -> None:
    from flask_talisman import Talisman

    force_https = bool(app.config.get("FORCE_HTTPS", _is_prod(app)))
    csp = app.config.get("CONTENT_SECURITY_POLICY", None)

    # No romper si CSP no es dict
    Talisman(
        app,
        force_https=force_https,
        content_security_policy=csp if isinstance(csp, dict) else None,
    )


def init_migrate(app: Flask) -> None:
    from flask_migrate import Migrate
    Migrate(app, db)


def init_limiter(app: Flask) -> None:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address

    storage = _env_str("RATE_LIMIT_STORAGE_URI", "memory://")
    default_limit = _env_str("RATE_LIMIT_DEFAULT", "300 per hour")
    Limiter(get_remote_address, app=app, storage_uri=storage, default_limits=[default_limit])


# =============================================================================
# App Factory
# =============================================================================

def create_app() -> Flask:
    cfg_cls: Type = get_config()  # ✅ es CLASE, no instancia
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
        instance_relative_config=True,
    )

    # 1) Cargar config primero
    app.config.from_mapping(cfg_cls.as_flask_config())

    # 2) Logging idempotente
    setup_logging(app)

    # 3) Guard fuerte en prod antes de tocar extensiones
    _require_secret_key_prod(app)
    if cfg_cls is ProductionConfig:
        ProductionConfig.validate_required()

    # 4) ProxyFix (Render / Cloudflare / reverse proxy)
    if bool(app.config.get("TRUST_PROXY_HEADERS", True)):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    # =============================================================================
    # Cookies/sesión “Render-proof”
    # =============================================================================
    # IMPORTANTE:
    # - Para login/register estándar, SameSite=Lax es lo más estable.
    # - NO forzar None salvo que uses iframes / cross-site POST.
    if _is_prod(app):
        app.config.setdefault("SESSION_COOKIE_SECURE", True)
        app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
    else:
        app.config.setdefault("SESSION_COOKIE_SECURE", False)
        app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")

    app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
    app.config.setdefault("SESSION_REFRESH_EACH_REQUEST", False)

    # Lifetime robusto
    try:
        days = int(_env_str("SESSION_DAYS", str(app.config.get("SESSION_DAYS", 7))) or "7")
    except Exception:
        days = 7
    app.config.setdefault("PERMANENT_SESSION_LIFETIME", timedelta(days=max(1, min(days, 90))))

    # CSRF: si querés más TTL, setealo en env; si viene None, se respeta
    # SSL strict: por defecto False (proxy), vos podés forzarlo en env
    app.config.setdefault("WTF_CSRF_SSL_STRICT", _env_bool("WTF_CSRF_SSL_STRICT", default=False))

    # Esquema para urls absolutas
    app.config.setdefault("PREFERRED_URL_SCHEME", "https" if _is_prod(app) else "http")

    app.logger.info(
        "🚀 create_app ENV=%s DEBUG=%s DB=%s SECURE=%s SAMESITE=%s CSRF_TTL=%s",
        (app.config.get("ENV") or "").lower(),
        bool(app.debug),
        app.config.get("SQLALCHEMY_DATABASE_URI"),
        app.config.get("SESSION_COOKIE_SECURE"),
        app.config.get("SESSION_COOKIE_SAMESITE"),
        app.config.get("WTF_CSRF_TIME_LIMIT"),
    )

    # =============================================================================
    # Init extensiones
    # =============================================================================
    safe_init(app, "db.init_app", lambda: db.init_app(app))
    critical_init(app, "CSRFProtect", lambda: init_csrf(app))

    safe_init(app, "Flask-Compress", lambda: init_compress(app) if app.config.get("ENABLE_COMPRESS", True) else None)
    safe_init(app, "Flask-Talisman", lambda: init_talisman(app) if app.config.get("ENABLE_TALISMAN", False) else None)
    safe_init(app, "Flask-Migrate", lambda: init_migrate(app))
    safe_init(app, "Flask-Limiter", lambda: init_limiter(app))

    # Models hub (crítico)
    def _models_hub():
        return init_models(app, create_admin=True, log_loaded_models=True, ping_db=True)

    critical_init(app, "Models hub", _models_hub)

    # =============================================================================
    # Hooks: request-id + admin no-cache + headers
    # =============================================================================
    @app.before_request
    def _before_request():
        rid = request.headers.get("X-Request-Id") or secrets.token_urlsafe(8)
        try:
            request._request_id = rid  # type: ignore[attr-defined]
        except Exception:
            pass

        if _env_bool("ADMIN_NO_CACHE", True) and (request.path or "").startswith("/admin"):
            try:
                request._admin_no_cache = True  # type: ignore[attr-defined]
            except Exception:
                pass

        if _env_bool("SESSION_PERMANENT_DEFAULT", True):
            try:
                session.permanent = True
            except Exception:
                pass

    @app.after_request
    def _after_request(resp):
        # request-id
        try:
            rid = getattr(request, "_request_id", None)
            if rid:
                resp.headers.setdefault("X-Request-Id", str(rid))
        except Exception:
            pass

        # admin no-cache
        try:
            if getattr(request, "_admin_no_cache", False):
                resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
                resp.headers["Pragma"] = "no-cache"
        except Exception:
            pass

        # Headers seguros mínimos
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

        if _is_prod(app) and bool(app.config.get("FORCE_HTTPS", True)):
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

        rel = _env_str("RELEASE", "")
        if rel:
            resp.headers.setdefault("X-App-Release", rel)

        return resp

    # =============================================================================
    # Template globals (NO pisa csrf_token())
    # =============================================================================
    @app.context_processor
    def inject_globals() -> Dict[str, Any]:
        try:
            from flask_login import current_user as fl_current_user  # type: ignore
            cu = fl_current_user if getattr(fl_current_user, "is_authenticated", False) else current_user_from_session()
        except Exception:
            cu = current_user_from_session()

        return {
            "APP_NAME": app.config.get("APP_NAME", "Skyline Store"),
            "APP_URL": app.config.get("APP_URL", ""),
            "ENV": (app.config.get("ENV") or "").lower(),
            "now_utc": utcnow(),
            "request_id": getattr(request, "_request_id", None),
            "current_user": cu,
            "is_logged_in": bool(getattr(cu, "id", None)),
            "is_admin": bool(getattr(cu, "is_admin", False)) if cu else bool(session.get("is_admin")),
            "current_app": app,
            "view_functions": app.view_functions,
            "has_endpoint": lambda ep: has_endpoint(app, ep),
        }

    # =============================================================================
    # Blueprints
    # =============================================================================
    registered: List[str] = []

    def _register_all_routes():
        from app.routes import register_blueprints
        register_blueprints(app)
        registered[:] = sorted(app.blueprints.keys())
        return True

    if _env_bool("ROUTES_STRICT", False):
        critical_init(app, "Register Blueprints", _register_all_routes)
    else:
        safe_init(app, "Register Blueprints", _register_all_routes)

    # =============================================================================
    # Health
    # =============================================================================
    def _db_check() -> Tuple[bool, str]:
        if not _env_bool("HEALTH_DB_CHECK", False):
            return True, "skipped"
        try:
            from sqlalchemy import text
            db.session.execute(text("SELECT 1"))
            return True, "ok"
        except Exception as e:
            return False, str(e)

    @app.get("/health")
    def health():
        ok_db, db_msg = _db_check()
        return {
            "status": "ok" if ok_db else "degraded",
            "env": (app.config.get("ENV") or "").lower(),
            "debug": bool(app.debug),
            "blueprints": registered,
            "db": db_msg,
            "app": app.config.get("APP_NAME", "Skyline Store"),
            "ts": int(time.time()),
            "request_id": getattr(request, "_request_id", None),
        }

    @app.get("/ready")
    def ready():
        ok_db, db_msg = _db_check()
        return jsonify({"ok": bool(ok_db), "db": db_msg}), (200 if ok_db else 503)

    # =============================================================================
    # Error handlers
    # =============================================================================
    @app.errorhandler(HTTPException)
    def http_error(e: HTTPException):
        code = int(e.code or 500)
        name = (e.name or "http_error").lower().replace(" ", "_")
        return resp_error(code, name, e.description)

    @app.errorhandler(404)
    def not_found(_e):
        return resp_error(404, "not_found", f"No encontrado: {request.path}")

    @app.errorhandler(500)
    def server_error(e):
        app.logger.exception("🔥 Error 500: %s", e)
        return resp_error(500, "server_error", "Error interno del servidor.")

    # =============================================================================
    # CLI útiles
    # =============================================================================
    @app.cli.command("create-admin")
    def cli_create_admin():
        if not create_admin_if_missing:
            print("create_admin_if_missing no está disponible en app.models")
            return
        out = create_admin_if_missing(app)  # type: ignore[misc]
        print(out)

    @app.cli.command("seed")
    def cli_seed():
        if not create_admin_if_missing:
            print("create_admin_if_missing no está disponible en app.models")
            return
        with app.app_context():
            print(create_admin_if_missing(app))  # type: ignore[misc]

    return app


__all__ = ["create_app", "db"]
