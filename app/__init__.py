# app/__init__.py — Skyline Store (ULTRA PRO / NO BREAK / Render-safe) — vNEXT FINAL
from __future__ import annotations

import logging
import os
import secrets
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Dict, List, Set, Tuple, Type

from flask import Flask, jsonify, render_template, request, session
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from app.config import get_config, ProductionConfig
from app.models import db, init_models

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
    vv = v.lower()
    if vv in _TRUE:
        return True
    if vv in _FALSE:
        return False
    return default


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _env_name(app: Flask) -> str:
    """
    Nombre de entorno estable.
    Flask 3 no recomienda ENV/FLASK_ENV, pero lo soportamos igual.
    """
    candidates = [
        app.config.get("ENV"),
        app.config.get("ENVIRONMENT"),
        _env_str("ENV"),
        _env_str("FLASK_ENV"),
        _env_str("ENVIRONMENT"),
    ]
    for c in candidates:
        if c:
            return str(c).lower().strip()
    return "production"


def _is_prod(app: Flask) -> bool:
    # Si DEBUG=True => NO prod (aunque ENV diga otra cosa)
    if bool(app.config.get("DEBUG")) or bool(app.debug):
        return False
    return _env_name(app) == "production"


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

    # templates de errores: intenta por status, luego fallback
    try:
        return render_template(f"errors/{status}.html", message=message), status
    except Exception:
        try:
            return render_template("error.html", message=message), status
        except Exception:
            return message, status


def setup_logging(app: Flask) -> None:
    """Idempotente: no duplica handlers en gunicorn."""
    lvl = (_env_str("LOG_LEVEL", "")).upper().strip()
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
        return bool(endpoint) and (endpoint in app.view_functions)
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


def _ensure_secret_key_dev(app: Flask) -> None:
    """
    ✅ En dev/testing, si falta SECRET_KEY, generamos una por proceso
    (evita errores raros con session/csrf local).
    """
    if _is_prod(app):
        return
    if not (app.config.get("SECRET_KEY") or "").strip():
        app.config["SECRET_KEY"] = secrets.token_urlsafe(32)


def _mask_db_url(uri: Any) -> str:
    """✅ Mejora: no logs la password real."""
    s = str(uri or "")
    if not s:
        return ""
    # formato típico: scheme://user:pass@host/db
    try:
        if "://" in s and "@" in s and ":" in s.split("://", 1)[1].split("@", 1)[0]:
            left, right = s.split("://", 1)
            creds, rest = right.split("@", 1)
            user = creds.split(":", 1)[0]
            return f"{left}://{user}:***@{rest}"
    except Exception:
        pass
    return s


# =============================================================================
# CSRF (Flask-WTF)
# =============================================================================

def init_csrf(app: Flask) -> None:
    """
    CSRFProtect estable para Render.
    ✅ Exime prefijos (webhooks) sin romper forms
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
                    vf = app.view_functions.get(ep)
                    if vf:
                        try:
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
    cfg_cls: Type = get_config()  # ✅ CLASE, no instancia

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
        instance_relative_config=True,
    )

    # 1) Config primero (CRÍTICO)
    app.config.from_mapping(cfg_cls.as_flask_config())

    # ✅ Mejora extra: evitá configs que rompen cookies en Render si quedaron seteadas
    # (si vos querés usarlas explícitamente, poné ALLOW_COOKIE_DOMAIN=1)
    if not _env_bool("ALLOW_COOKIE_DOMAIN", False):
        app.config.pop("SESSION_COOKIE_DOMAIN", None)

    # 2) Logging idempotente
    setup_logging(app)

    # 3) Secret key guard (prod estricta, dev auto)
    _ensure_secret_key_dev(app)
    _require_secret_key_prod(app)

    # ✅ Si cfg_cls es ProductionConfig o subclase, valida required
    if isinstance(cfg_cls, type) and issubclass(cfg_cls, ProductionConfig):
        ProductionConfig.validate_required()

    # 4) ProxyFix (Render / reverse proxy)
    if bool(app.config.get("TRUST_PROXY_HEADERS", True)):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

    # =============================================================================
    # Cookies/sesión “Render-proof”
    # =============================================================================
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

    # CSRF defaults
    app.config.setdefault("WTF_CSRF_SSL_STRICT", _env_bool("WTF_CSRF_SSL_STRICT", default=False))
    app.config.setdefault("WTF_CSRF_TIME_LIMIT", int(_env_str("WTF_CSRF_TIME_LIMIT", "3600") or "3600"))

    # URL scheme
    app.config.setdefault("PREFERRED_URL_SCHEME", "https" if _is_prod(app) else "http")

    app.logger.info(
        "🚀 create_app ENV=%s DEBUG=%s DB=%s SECURE=%s SAMESITE=%s CSRF_TTL=%s",
        _env_name(app),
        bool(app.debug),
        _mask_db_url(app.config.get("SQLALCHEMY_DATABASE_URI")),
        app.config.get("SESSION_COOKIE_SECURE"),
        app.config.get("SESSION_COOKIE_SAMESITE"),
        app.config.get("WTF_CSRF_TIME_LIMIT"),
    )

    # =============================================================================
    # Init extensiones (orden importante)
    # =============================================================================
    critical_init(app, "CSRFProtect", lambda: init_csrf(app))

    safe_init(
        app,
        "Flask-Compress",
        lambda: init_compress(app) if app.config.get("ENABLE_COMPRESS", True) else None,
    )
    safe_init(
        app,
        "Flask-Talisman",
        lambda: init_talisman(app) if app.config.get("ENABLE_TALISMAN", False) else None,
    )

    # ✅ MODELS HUB (CRÍTICO)
    def _models_hub():
        return init_models(app, create_admin=True, log_loaded_models=True, ping_db=True)

    critical_init(app, "Models hub", _models_hub)

    # ✅ Migrate / Limiter DESPUÉS de DB lista
    safe_init(app, "Flask-Migrate", lambda: init_migrate(app))
    safe_init(app, "Flask-Limiter", lambda: init_limiter(app))

    # =============================================================================
    # Hooks: request-id + admin no-cache + session permanent
    # =============================================================================
    @app.before_request
    def _before_request():
        rid = request.headers.get("X-Request-Id") or secrets.token_urlsafe(10)
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
    # Template globals (CSRF definitivo: generate_csrf desde Python)
    # =============================================================================
    @app.context_processor
    def inject_globals() -> Dict[str, Any]:
        # Flask-Login si está disponible
        cu = None
        try:
            from flask_login import current_user as fl_current_user  # type: ignore
            if getattr(fl_current_user, "is_authenticated", False):
                cu = fl_current_user
        except Exception:
            cu = None

        if cu is None:
            cu = current_user_from_session()

        # ✅ CSRF definitivo: se genera acá (request-context) y se pasa como string
        csrf_value = ""
        try:
            from flask_wtf.csrf import generate_csrf
            csrf_value = str(generate_csrf() or "")
        except Exception:
            csrf_value = ""

        return {
            "APP_NAME": app.config.get("APP_NAME", "Skyline Store"),
            "APP_URL": app.config.get("APP_URL", ""),
            "ENV": _env_name(app),
            "now_utc": utcnow(),
            "request_id": getattr(request, "_request_id", None),
            "current_user": cu,
            "is_logged_in": bool(getattr(cu, "id", None)) if cu else False,
            "is_admin": bool(getattr(cu, "is_admin", False)) if cu else bool(session.get("is_admin")),
            "view_functions": app.view_functions,  # para safe_url
            "has_endpoint": (lambda ep: has_endpoint(app, ep)),
            # ✅ USAR EN base.html: <meta name="csrf-token" content="{{ csrf_token_value }}">
            "csrf_token_value": csrf_value,
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
    # Health / Ready
    # =============================================================================
    def _db_check() -> Tuple[bool, str]:
        # ✅ por defecto: no exige DB en health para que no mate deploy si DB tarda
        if not _env_bool("HEALTH_DB_CHECK", False):
            return True, "skipped"

        try:
            if "sqlalchemy" not in app.extensions:
                return False, "sqlalchemy_not_registered"
        except Exception:
            return False, "sqlalchemy_not_registered"

        try:
            from sqlalchemy import text
            db.session.execute(text("SELECT 1"))
            return True, "ok"
        except Exception as e:
            return False, (str(e) or "db_error")[:240]

    @app.get("/health")
    def health():
        ok_db, db_msg = _db_check()
        return {
            "status": "ok" if ok_db else "degraded",
            "env": _env_name(app),
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

    @app.errorhandler(Exception)
    def unhandled_error(e: Exception):
        if isinstance(e, HTTPException):
            return e
        app.logger.exception("🔥 Unhandled error: %s", e)
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
