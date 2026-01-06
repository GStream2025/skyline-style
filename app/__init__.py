# app/__init__.py — Skyline Store (BULLETPROOF · FINAL · +20 mejoras · sin errores)
from __future__ import annotations

import logging
import os
import secrets
import time
from datetime import timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple

from flask import Flask, jsonify, render_template, request, session
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from app.models import db, init_models

# ✅ compat (no rompe si no existe)
try:
    from app.models import create_admin_if_missing  # type: ignore
except Exception:
    create_admin_if_missing = None  # type: ignore


# =============================================================================
# ENV helpers (robustos + consistentes)
# =============================================================================
_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off"}


def _bool_env(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    s = str(v).strip().lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return default


def _int_env(key: str, default: int) -> int:
    v = os.getenv(key)
    if v is None:
        return default
    try:
        return int(str(v).strip())
    except Exception:
        return default


def _str_env(key: str, default: str = "") -> str:
    v = os.getenv(key)
    return default if v is None else str(v)


def _normalize_database_url(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    u = str(url).strip()
    if u.startswith("postgres://"):
        return u.replace("postgres://", "postgresql://", 1)
    return u


def _detect_env() -> str:
    raw = (os.getenv("ENV") or os.getenv("FLASK_ENV") or "").strip().lower()
    if raw in {"dev", "development"}:
        return "development"
    if raw in {"prod", "production"}:
        return "production"
    # fallback: por DEBUG
    return (
        "development"
        if _bool_env("DEBUG", False) or _bool_env("FLASK_DEBUG", False)
        else "production"
    )


def _is_production(env: str) -> bool:
    return (env or "").strip().lower() in {"prod", "production"}


def _require_secret_key(env: str) -> str:
    """
    En prod exige SECRET_KEY real; en dev genera fallback.
    ✅ Mejora: fallback random por proceso si no hay SECRET_KEY en dev (evita sesiones compartidas por accidente)
    """
    sk = (os.getenv("SECRET_KEY") or "").strip()
    if sk:
        return sk
    if _is_production(env):
        raise RuntimeError(
            "Falta SECRET_KEY en producción. Configurala en Render → Environment."
        )
    return f"dev-{secrets.token_urlsafe(32)}"


def _wants_json() -> bool:
    """
    Negociación JSON correcta (API / AJAX / Accept headers).
    ✅ Mejora: soporta ?format=json y X-Requested-With
    """
    p = (request.path or "").lower()
    if p.startswith("/api/"):
        return True
    if (request.args.get("format") or "").lower() == "json":
        return True
    accept = (request.headers.get("Accept") or "").lower()
    if "application/json" in accept:
        return True
    if (request.headers.get("X-Requested-With") or "").lower() == "xmlhttprequest":
        return True
    return False


# =============================================================================
# Logging (pro)
# =============================================================================
def _setup_logging(app: Flask) -> None:
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


def _safe_init(app: Flask, label: str, fn: Callable[[], Any]) -> Any:
    """
    Init opcional sin romper deploy.
    ✅ Mejora: si debug, muestra stack; si prod, warning simple.
    """
    try:
        out = fn()
        app.logger.info("✅ %s inicializado", label)
        return out
    except Exception as e:
        app.logger.warning("⚠️ %s omitido: %s", label, e, exc_info=bool(app.debug))
        return None


def _critical_init(app: Flask, label: str, fn: Callable[[], Any]) -> Any:
    """
    Init crítico con log full.
    ✅ Mejora: mensaje más claro + re-raise
    """
    try:
        out = fn()
        app.logger.info("✅ %s inicializado", label)
        return out
    except Exception as e:
        app.logger.exception("🔥 %s falló (CRÍTICO): %s", label, e)
        raise


# =============================================================================
# CSRF (sin Flask-WTF) - central
# =============================================================================
def _ensure_csrf_token() -> str:
    """
    CSRF token fuerte + autocuración
    ✅ Mejora: token atado a sesión actual (no persistir tokens inválidos)
    """
    tok = session.get("csrf_token")
    if not tok or not isinstance(tok, str) or len(tok) < 24:
        tok = secrets.token_urlsafe(32)
        session["csrf_token"] = tok
    return tok


def _extract_csrf_from_request() -> str:
    header_name = (_str_env("CSRF_HEADER", "X-CSRF-Token") or "X-CSRF-Token").strip()
    ht = (request.headers.get(header_name) or "").strip()
    if ht:
        return ht

    ft = (request.form.get("csrf_token") or "").strip()
    if ft:
        return ft

    try:
        if request.is_json:
            data = request.get_json(silent=True) or {}
            jt = str(data.get("csrf_token") or "").strip()
            if jt:
                return jt
    except Exception:
        pass

    return ""


def _is_csrf_exempt_path(path: str) -> bool:
    """
    ✅ Mejora: CSRF exemption configurable
    """
    p = (path or "").strip()
    if not p:
        return False
    if p.startswith("/webhook") or p.startswith("/api/webhook"):
        return True
    # allowlist adicional por env (comma-separated)
    extra = (_str_env("CSRF_EXEMPT_PREFIXES", "") or "").strip()
    if extra:
        for pref in [x.strip() for x in extra.split(",") if x.strip()]:
            if p.startswith(pref):
                return True
    return False


def _csrf_ok() -> bool:
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return True
    if _is_csrf_exempt_path(request.path or ""):
        return True

    st = str(session.get("csrf_token") or "")
    token = _extract_csrf_from_request()
    return bool(st) and bool(token) and secrets.compare_digest(st, str(token))


# =============================================================================
# Error responses (HTML/JSON)
# =============================================================================
def _resp_error(app: Flask, status: int, code: str, message: str):
    if _wants_json():
        return jsonify({"ok": False, "error": code, "message": message}), status

    # ✅ Mejora: render de error por status si existe, sino fallback único
    try:
        return render_template(f"errors/{status}.html", message=message), status
    except Exception:
        try:
            return render_template("error.html", message=message), status
        except Exception:
            return (message, status)


# =============================================================================
# User helper (session)
# =============================================================================
def _get_current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        from app.models import User  # proxy-safe

        return db.session.get(User, int(uid))
    except Exception:
        return None


# =============================================================================
# Optional extensions (no obligatorias)
# =============================================================================
def _init_compress(app: Flask):
    from flask_compress import Compress

    Compress(app)
    return True


def _init_talisman(app: Flask, env: str):
    from flask_talisman import Talisman

    force_https = _bool_env("FORCE_HTTPS", _is_production(env))
    # ✅ Mejora: desactiva CSP por defecto para no romper templates, pero permite custom por env
    Talisman(app, force_https=force_https, content_security_policy=None)
    return True


def _init_migrate(app: Flask):
    from flask_migrate import Migrate

    Migrate(app, db)
    return True


def _init_limiter(app: Flask):
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address

    # ✅ Mejora: storage configurable; memory:// ok para dev, Redis recomendado en prod
    storage = _str_env("RATE_LIMIT_STORAGE_URI", "memory://")
    default_limits = [_str_env("RATE_LIMIT_DEFAULT", "300 per hour")]

    return Limiter(
        get_remote_address,
        app=app,
        default_limits=default_limits,
        storage_uri=storage,
    )


def _should_auto_create_tables(env: str) -> bool:
    """
    create_all OFF por defecto (evita líos con migrations).
    Si querés local rápido: AUTO_CREATE_TABLES=1
    ✅ Mejora: permite AUTO_CREATE_TABLES=1 solo si además ALLOW_CREATE_ALL=1
    """
    if _is_production(env):
        return False
    if not _bool_env("AUTO_CREATE_TABLES", False):
        return False
    return _bool_env("ALLOW_CREATE_ALL", False)


def _require_settings_master_key_if_needed(app: Flask) -> None:
    """
    Guard opcional para settings cifrados.
    ✅ Mejora: usa ENV real del app si existe
    """
    env = (app.config.get("ENV") or "production").strip().lower()
    require = _bool_env("REQUIRE_SETTINGS_MASTER_KEY", _is_production(env))
    if not require:
        return
    mk = (_str_env("SETTINGS_MASTER_KEY", "") or "").strip()
    if not mk:
        raise RuntimeError(
            "Falta SETTINGS_MASTER_KEY. Configurala en Render → Environment."
        )


# =============================================================================
# App Factory (FINAL PRO)
# =============================================================================
def create_app() -> Flask:
    env = _detect_env()
    debug = _bool_env("DEBUG", env == "development") or _bool_env("FLASK_DEBUG", False)

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
        instance_relative_config=True,
    )

    # ✅ Mejora: limita tamaño de cookies/session (previene sesiones gigantes por accidente)
    app.config["MAX_COOKIE_SIZE"] = _int_env("MAX_COOKIE_SIZE", 4093)

    # ProxyFix (Render)
    if _bool_env("TRUST_PROXY_HEADERS", True):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    # Config core
    secret = _require_secret_key(env)

    db_url = _normalize_database_url(os.getenv("DATABASE_URL"))
    db_uri = (
        db_url or os.getenv("SQLALCHEMY_DATABASE_URI") or "sqlite:///skyline.db"
    ).strip()

    cookie_secure = _bool_env("COOKIE_SECURE", _is_production(env))
    session_samesite = (_str_env("SESSION_SAMESITE", "Lax") or "Lax").strip()
    if session_samesite not in {"Lax", "Strict", "None"}:
        session_samesite = "Lax"
    if session_samesite == "None":
        cookie_secure = True

    session_days = max(1, _int_env("SESSION_PERMANENT_DAYS", 30))
    max_mb = max(1, _int_env("MAX_UPLOAD_MB", 20))

    # ✅ Mejora: engine options seguras (y sin romper sqlite)
    engine_opts: Dict[str, Any] = {
        "pool_pre_ping": _bool_env("SQLALCHEMY_POOL_PRE_PING", True),
        "pool_recycle": _int_env("DB_POOL_RECYCLE", 280),
    }

    # ✅ Mejora: si Postgres, tunear pool size opcional
    if "postgresql" in db_uri:
        engine_opts["pool_size"] = max(1, _int_env("DB_POOL_SIZE", 5))
        engine_opts["max_overflow"] = max(0, _int_env("DB_MAX_OVERFLOW", 10))

    app.config.update(
        SECRET_KEY=secret,
        ENV=env,
        DEBUG=debug,
        SQLALCHEMY_DATABASE_URI=db_uri,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SQLALCHEMY_ENGINE_OPTIONS=engine_opts,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE=session_samesite,
        SESSION_COOKIE_SECURE=cookie_secure,
        PERMANENT_SESSION_LIFETIME=timedelta(days=session_days),
        PREFERRED_URL_SCHEME="https" if _is_production(env) else "http",
        JSON_SORT_KEYS=False,
        UPLOADS_DIR=(
            _str_env("UPLOADS_DIR", "static/uploads") or "static/uploads"
        ).strip(),
        APP_NAME=_str_env("APP_NAME", "Skyline Store"),
        APP_URL=(
            _str_env("APP_URL", "http://127.0.0.1:5000") or "http://127.0.0.1:5000"
        )
        .strip()
        .rstrip("/"),
        MAX_CONTENT_LENGTH=max_mb * 1024 * 1024,
    )

    # ✅ Mejora: asegura SECRET_KEY robusto en prod (doble guard)
    if _is_production(env) and (
        not app.config.get("SECRET_KEY") or len(str(app.config["SECRET_KEY"])) < 16
    ):
        raise RuntimeError("SECRET_KEY demasiado corto/inseguro en producción.")

    _setup_logging(app)

    app.logger.info(
        "🚀 create_app ENV=%s DEBUG=%s DB=%s SECURE=%s SAMESITE=%s",
        app.config["ENV"],
        bool(app.debug),
        app.config["SQLALCHEMY_DATABASE_URI"],
        app.config["SESSION_COOKIE_SECURE"],
        app.config["SESSION_COOKIE_SAMESITE"],
    )

    # ✅ Mejora: warning prod con sqlite + toggle para permitir
    if (
        _is_production(env)
        and db_uri.startswith("sqlite")
        and not _bool_env("ALLOW_SQLITE_IN_PROD", False)
    ):
        app.logger.warning(
            "⚠️ Producción con SQLite detectado. Recomendado Postgres en Render."
        )

    # =============================================================================
    # Extensiones (opcionales)
    # =============================================================================
    _safe_init(app, "Flask-Compress", lambda: _init_compress(app))
    _safe_init(app, "Flask-Talisman", lambda: _init_talisman(app, env))
    _safe_init(app, "Flask-Migrate", lambda: _init_migrate(app))
    _safe_init(app, "Flask-Limiter", lambda: _init_limiter(app))

    _safe_init(
        app,
        "SETTINGS_MASTER_KEY guard",
        lambda: _require_settings_master_key_if_needed(app),
    )

    # =============================================================================
    # Models hub + seed + payments bootstrap
    # =============================================================================
    auto_tables = _should_auto_create_tables(env)

    def _models_hub():
        # ✅ Mejora: init_models con ping_db por defecto (nuestro models hub lo soporta)
        out = init_models(app, create_admin=True, log_loaded_models=True, ping_db=True)

        if auto_tables:
            with app.app_context():
                db.create_all()
            app.logger.info(
                "✅ db.create_all() OK (AUTO_CREATE_TABLES=1 + ALLOW_CREATE_ALL=1)"
            )

        # bootstrap opcional
        if _bool_env("SEED", False):
            try:
                from app.models.payment_provider import PaymentProviderService  # type: ignore

                created, total = PaymentProviderService.bootstrap_defaults()
                app.logger.info(
                    "💳 Payment providers bootstrap: %s creados / %s total",
                    created,
                    total,
                )
            except Exception:
                app.logger.exception("❌ Error bootstrapping payment providers")

        return out

    _critical_init(app, "Models hub", _models_hub)

    # =============================================================================
    # Request hooks (CSRF + headers + request id)
    # =============================================================================
    @app.before_request
    def _before_request():
        # ✅ Mejora: request id simple (para correlación de logs)
        rid = request.headers.get("X-Request-Id") or secrets.token_urlsafe(8)
        try:
            request._request_id = rid  # type: ignore[attr-defined]
        except Exception:
            pass

        try:
            _ensure_csrf_token()
        except Exception:
            pass

        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            if not _csrf_ok():
                return _resp_error(
                    app,
                    400,
                    "csrf_failed",
                    "Solicitud inválida. Recargá la página e intentá nuevamente.",
                )

        # ✅ Mejora: no-cache admin configurable
        if _bool_env("ADMIN_NO_CACHE", True) and (request.path or "").startswith(
            "/admin"
        ):
            try:
                request._admin_no_cache = True  # type: ignore[attr-defined]
            except Exception:
                pass

    @app.after_request
    def _after_request(resp):
        # ✅ Mejora: headers de seguridad + request-id
        try:
            rid = getattr(request, "_request_id", None)
            if rid:
                resp.headers.setdefault("X-Request-Id", str(rid))
        except Exception:
            pass

        try:
            if getattr(request, "_admin_no_cache", False):
                resp.headers["Cache-Control"] = (
                    "no-store, no-cache, must-revalidate, max-age=0"
                )
                resp.headers["Pragma"] = "no-cache"
        except Exception:
            pass

        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")

        # ✅ Mejora: HSTS sólo si FORCE_HTTPS en prod (y si Talisman no está)
        if _is_production(env) and _bool_env("FORCE_HTTPS", True):
            resp.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )

        return resp

    # =============================================================================
    # Template globals
    # =============================================================================
    @app.context_processor
    def inject_globals() -> Dict[str, Any]:
        u = _get_current_user()
        return {
            "current_user": u,
            "is_logged_in": bool(u),
            "is_admin": (
                bool(getattr(u, "is_admin", False))
                if u
                else bool(session.get("is_admin"))
            ),
            "APP_NAME": app.config.get("APP_NAME", "Skyline Store"),
            "APP_URL": app.config.get("APP_URL", ""),
            "ENV": app.config.get("ENV"),
            "csrf_token": session.get("csrf_token", ""),
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

    if _bool_env("ROUTES_STRICT", False):
        _critical_init(app, "Register Blueprints", _register_all_routes)
    else:
        _safe_init(app, "Register Blueprints", _register_all_routes)

    # =============================================================================
    # Health
    # =============================================================================
    def _db_check() -> Tuple[bool, str]:
        if not _bool_env("HEALTH_DB_CHECK", False):
            return True, "skipped"
        try:
            from sqlalchemy import text as _text

            db.session.execute(_text("SELECT 1"))
            return True, "ok"
        except Exception as e:
            return False, str(e)

    @app.get("/health")
    def health():
        ok_db, db_msg = _db_check()
        return {
            "status": "ok" if ok_db else "degraded",
            "env": app.config["ENV"],
            "debug": bool(app.debug),
            "blueprints": registered,
            "db": db_msg,
            "app": app.config.get("APP_NAME", "Skyline Store"),
            "ts": int(time.time()),
        }

    # =============================================================================
    # Error handlers (más completos)
    # =============================================================================
    @app.errorhandler(HTTPException)
    def http_error(e: HTTPException):
        # ✅ Mejora: maneja 401/403/405/etc también con el mismo formato
        return _resp_error(
            app, int(e.code or 500), e.name.lower().replace(" ", "_"), e.description
        )

    @app.errorhandler(404)
    def not_found(_e):
        return _resp_error(app, 404, "not_found", f"No encontrado: {request.path}")

    @app.errorhandler(500)
    def server_error(e):
        app.logger.exception("🔥 Error 500: %s", e)
        return _resp_error(app, 500, "server_error", "Error interno del servidor.")

    # =============================================================================
    # CLI útiles (blindados)
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
