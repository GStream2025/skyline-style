# app/__init__.py — Skyline Store (ULTRA PRO MAX · FINAL · Bulletproof)
from __future__ import annotations

import logging
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from flask import Flask, jsonify, render_template, request, session
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from app.models import db, init_models

# Config PRO (tu archivo app/config.py)
from app.config import get_config, ProductionConfig


# ✅ compat (no rompe si no existe)
try:
    from app.models import create_admin_if_missing  # type: ignore
except Exception:
    create_admin_if_missing = None  # type: ignore


# =============================================================================
# Helpers
# =============================================================================

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def wants_json() -> bool:
    """Negociación JSON correcta (API / AJAX / Accept)."""
    p = (request.path or "").lower()
    if p.startswith("/api/") or p.startswith("/webhooks/") or p.startswith("/webhook"):
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
    lvl = (os.getenv("LOG_LEVEL") or "").strip().upper()
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
        app.logger.warning(⚠️ %s omitido: %s", label, e, exc_info=bool(app.debug))
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
        from app.models import User  # import lazy (no rompe)
        return db.session.get(User, int(uid))
    except Exception:
        return None


# =============================================================================
# CSRF (Flask-WTF) — evita el error “token no coincide”
# =============================================================================

def init_csrf(app: Flask) -> None:
    """
    Usa Flask-WTF CSRFProtect (estable).
    NO pisamos csrf_token() en templates.
    """
    from flask_wtf import CSRFProtect
    from flask_wtf.csrf import CSRFError

    csrf = CSRFProtect()
    csrf.init_app(app)

    # Excepciones por prefijo (webhooks/APIs) — no deben requerir CSRF
    exempt_prefixes = {
        "/webhook",
        "/webhooks",
        "/api/webhook",
        "/api/webhooks",
    }
    extra = (os.getenv("CSRF_EXEMPT_PREFIXES") or "").strip()
    if extra:
        for pref in [x.strip() for x in extra.split(",") if x.strip()]:
            exempt_prefixes.add(pref)

    @app.before_request
    def _csrf_exempt_by_prefix():
        if request.method in {"GET", "HEAD", "OPTIONS"}:
            return None
        p = (request.path or "")
        for pref in exempt_prefixes:
            if p.startswith(pref):
                # Flask-WTF: marcar endpoint exento
                try:
                    csrf.exempt(request.endpoint)  # type: ignore[arg-type]
                except Exception:
                    pass
                break
        return None

    @app.errorhandler(CSRFError)
    def _handle_csrf_error(e: CSRFError):
        # Mensaje claro como tu screenshot
        return resp_error(400, "csrf_failed", "Solicitud inválida. El formulario expiró o el token no coincide. Recargá la página e intentá nuevamente.")


# =============================================================================
# Optional extensions
# =============================================================================

def init_compress(app: Flask) -> None:
    from flask_compress import Compress
    Compress(app)


def init_talisman(app: Flask) -> None:
    from flask_talisman import Talisman

    # OJO: si luego querés CSP duro, lo definís desde config.py
    force_https = bool(app.config.get("FORCE_HTTPS", app.config.get("ENV") == "production"))
    csp = app.config.get("CONTENT_SECURITY_POLICY", None)

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

    storage = os.getenv("RATE_LIMIT_STORAGE_URI") or "memory://"
    default_limit = os.getenv("RATE_LIMIT_DEFAULT") or "300 per hour"
    Limiter(get_remote_address, app=app, storage_uri=storage, default_limits=[default_limit])


# =============================================================================
# App Factory
# =============================================================================

def create_app() -> Flask:
    cfg = get_config()
    app = Flask(__name__, template_folder="templates", static_folder="static", instance_relative_config=True)

    # Cargar config PRO
    app.config.from_mapping(cfg.as_flask_config())

    # Validación fuerte en prod (corta el “token mismatch” por SECRET_KEY mal)
    if cfg is ProductionConfig:
        ProductionConfig.validate_required()

    # ProxyFix (Render/Cloudflare)
    if bool(app.config.get("TRUST_PROXY_HEADERS", True)):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    setup_logging(app)

    app.logger.info(
        "🚀 create_app ENV=%s DEBUG=%s DB=%s SECURE=%s SAMESITE=%s CSRF_TTL=%s",
        app.config.get("ENV"),
        bool(app.debug),
        app.config.get("SQLALCHEMY_DATABASE_URI"),
        app.config.get("SESSION_COOKIE_SECURE"),
        app.config.get("SESSION_COOKIE_SAMESITE"),
        app.config.get("WTF_CSRF_TIME_LIMIT"),
    )

    # Inicializar DB (si tu models hub ya lo hace, esto no rompe)
    safe_init(app, "db.init_app", lambda: db.init_app(app))

    # CSRF real (Flask-WTF) — CLAVE para no tener más “Solicitud inválida”
    critical_init(app, "CSRFProtect", lambda: init_csrf(app))

    # Extensiones opcionales (no rompen deploy)
    safe_init(app, "Flask-Compress", lambda: init_compress(app) if app.config.get("ENABLE_COMPRESS", True) else None)
    safe_init(app, "Flask-Talisman", lambda: init_talisman(app) if app.config.get("ENABLE_TALISMAN", False) else None)
    safe_init(app, "Flask-Migrate", lambda: init_migrate(app))
    safe_init(app, "Flask-Limiter", lambda: init_limiter(app))

    # Models hub (crítico)
    def _models_hub():
        # init_models ya hace ping DB, carga modelos, etc (según tu implementación)
        return init_models(app, create_admin=True, log_loaded_models=True, ping_db=True)

    critical_init(app, "Models hub", _models_hub)

    # =============================================================================
    # Request hooks (request-id + headers + admin no-cache)
    # =============================================================================
    @app.before_request
    def _before_request():
        rid = request.headers.get("X-Request-Id") or secrets.token_urlsafe(8)
        try:
            request._request_id = rid  # type: ignore[attr-defined]
        except Exception:
            pass

        # Admin no-cache opcional
        if os.getenv("ADMIN_NO_CACHE", "1").strip().lower() in {"1", "true", "yes", "y", "on"}:
            if (request.path or "").startswith("/admin"):
                try:
                    request._admin_no_cache = True  # type: ignore[attr-defined]
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

        # headers de seguridad mínimos (sin romper CSP)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

        # HSTS si HTTPS forzado en prod (si Talisman no lo setea)
        if app.config.get("ENV") == "production" and bool(app.config.get("FORCE_HTTPS", True)):
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

        return resp

    # =============================================================================
    # Template globals (NO pisar csrf_token())
    # =============================================================================
    @app.context_processor
    def inject_globals() -> Dict[str, Any]:
        # Si usás Flask-Login, current_user ya existe como proxy.
        # Si no, dejamos fallback de sesión.
        try:
            from flask_login import current_user as fl_current_user  # type: ignore
            cu = fl_current_user if getattr(fl_current_user, "is_authenticated", False) else current_user_from_session()
        except Exception:
            cu = current_user_from_session()

        return {
            "APP_NAME": app.config.get("APP_NAME", "Skyline Store"),
            "APP_URL": app.config.get("APP_URL", ""),
            "ENV": app.config.get("ENV"),
            "now_utc": utcnow(),
            "request_id": getattr(request, "_request_id", None),
            "current_user": cu,
            "is_logged_in": bool(getattr(cu, "id", None)),
            "is_admin": bool(getattr(cu, "is_admin", False)) if cu else bool(session.get("is_admin")),
            # ✅ FIX para tus templates:
            # permite: {% if 'auth.forgot' in current_app.view_functions %}
            "current_app": app,
            "view_functions": app.view_functions,
            # ✅ mejor: {%- if has_endpoint('auth.forgot') -%}
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

    # Si querés estrictísimo, poné ROUTES_STRICT=1
    if os.getenv("ROUTES_STRICT", "0").strip().lower() in {"1", "true", "yes", "y", "on"}:
        critical_init(app, "Register Blueprints", _register_all_routes)
    else:
        safe_init(app, "Register Blueprints", _register_all_routes)

    # =============================================================================
    # Health
    # =============================================================================
    def _db_check() -> Tuple[bool, str]:
        if os.getenv("HEALTH_DB_CHECK", "0").strip().lower() not in {"1", "true", "yes", "y", "on"}:
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
            "env": app.config.get("ENV"),
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
