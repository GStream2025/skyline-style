# app/__init__.py
from __future__ import annotations

import logging
import os
import secrets
import time
from datetime import timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple

from flask import Flask, jsonify, render_template, request, session
from werkzeug.middleware.proxy_fix import ProxyFix

from app.models import db, init_models, create_admin_if_missing


# ============================================================
# ENV helpers (robustos)
# ============================================================
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
    # Render antiguamente daba postgres://
    if u.startswith("postgres://"):
        return u.replace("postgres://", "postgresql://", 1)
    return u


def _detect_env() -> str:
    raw = (os.getenv("ENV") or os.getenv("FLASK_ENV") or "production").strip().lower()
    return "development" if raw in {"dev", "development"} else "production"


def _is_production(env: str) -> bool:
    return (env or "").strip().lower() in {"prod", "production"}


def _require_secret_key(env: str) -> str:
    """
    ✅ Mejora 1: en prod EXIGE SECRET_KEY real
    """
    sk = (os.getenv("SECRET_KEY") or "").strip()
    if sk:
        return sk
    if _is_production(env):
        raise RuntimeError("Falta SECRET_KEY en producción. Configurala en Render → Environment.")
    return "dev-secret-change-me"


def _wants_json() -> bool:
    """
    ✅ Mejora 2: negociación JSON correcta (API / AJAX)
    """
    p = (request.path or "").lower()
    if p.startswith("/api/"):
        return True
    accept = (request.headers.get("Accept") or "").lower()
    if "application/json" in accept:
        return True
    if (request.headers.get("X-Requested-With") or "").lower() == "xmlhttprequest":
        return True
    return False


# ============================================================
# Logging (pro)
# ============================================================
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
    ✅ Mejora 3: init opcional sin romper deploy
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
    ✅ Mejora 4: init crítico con log full
    """
    try:
        out = fn()
        app.logger.info("✅ %s inicializado", label)
        return out
    except Exception as e:
        app.logger.exception("🔥 %s falló (CRÍTICO): %s", label, e)
        raise


# ============================================================
# CSRF (sin Flask-WTF) - central
# ============================================================
def _ensure_csrf_token() -> str:
    """
    ✅ Mejora 5: CSRF token fuerte + autocuración
    """
    tok = session.get("csrf_token")
    if not tok or not isinstance(tok, str) or len(tok) < 24:
        tok = secrets.token_urlsafe(32)
        session["csrf_token"] = tok
    return tok


def _extract_csrf_from_request() -> str:
    header_name = (os.getenv("CSRF_HEADER") or "X-CSRF-Token").strip()
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


def _csrf_ok() -> bool:
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return True

    # ✅ Mejora 6: whitelist para webhooks (no exigir CSRF)
    p = (request.path or "")
    if p.startswith("/webhook") or p.startswith("/api/webhook"):
        return True

    st = str(session.get("csrf_token") or "")
    token = _extract_csrf_from_request()
    return bool(st) and bool(token) and secrets.compare_digest(st, str(token))


# ============================================================
# Error responses (HTML/JSON)
# ============================================================
def _resp_error(app: Flask, status: int, code: str, message: str):
    """
    ✅ Mejora 7: errores consistentes y “bonitos”
    """
    if _wants_json():
        return jsonify({"ok": False, "error": code, "message": message}), status

    # intenta templates modernos si existen
    try:
        return render_template(f"errors/{status}.html", message=message), status
    except Exception:
        try:
            return render_template("error.html", message=message), status
        except Exception:
            return (message, status)


# ============================================================
# User helper (session)
# ============================================================
def _get_current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        from app.models import User
        return db.session.get(User, int(uid))
    except Exception:
        return None


# ============================================================
# Optional extensions (sin obligarte a instalar)
# ============================================================
def _init_compress(app: Flask):
    from flask_compress import Compress
    Compress(app)
    return True


def _init_talisman(app: Flask, env: str):
    from flask_talisman import Talisman
    force_https = _bool_env("FORCE_HTTPS", _is_production(env))
    # CSP: no la forzamos para no romper assets; la activás luego si querés
    Talisman(app, force_https=force_https, content_security_policy=None)
    return True


def _init_migrate(app: Flask):
    from flask_migrate import Migrate
    Migrate(app, db)
    return True


def _init_limiter(app: Flask):
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    return Limiter(
        get_remote_address,
        app=app,
        default_limits=[os.getenv("RATE_LIMIT_DEFAULT", "300 per hour")],
        storage_uri=os.getenv("RATE_LIMIT_STORAGE_URI", "memory://"),
    )


def _should_auto_create_tables(env: str) -> bool:
    """
    ✅ Mejora 8: create_all OFF por defecto (evita líos con migrations).
    Si querés local rápido: AUTO_CREATE_TABLES=1
    """
    return _bool_env("AUTO_CREATE_TABLES", False) if not _is_production(env) else False


def _require_settings_master_key_if_needed(app: Flask) -> None:
    """
    ✅ Mejora 9: si vas a usar Settings cifrados (pagos config desde admin),
    exigimos SETTINGS_MASTER_KEY para que NO quede inseguro.
    """
    # Si vas a gestionar pagos/settings desde admin, esto debe existir.
    # Si preferís no exigirlo en local, poné REQUIRE_SETTINGS_MASTER_KEY=0.
    require = _bool_env("REQUIRE_SETTINGS_MASTER_KEY", True)
    if not require:
        return

    mk = (os.getenv("SETTINGS_MASTER_KEY") or "").strip()
    if not mk:
        raise RuntimeError(
            "Falta SETTINGS_MASTER_KEY. Configurala en .env y en Render → Environment."
        )


# ============================================================
# App Factory (FINAL PRO)
# ============================================================
def create_app() -> Flask:
    env = _detect_env()
    debug = _bool_env("DEBUG", env == "development") or _bool_env("FLASK_DEBUG", False)

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
        instance_relative_config=True,
    )

    # ProxyFix (Render)
    if _bool_env("TRUST_PROXY_HEADERS", True):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    # Config core
    secret = _require_secret_key(env)

    db_url = _normalize_database_url(os.getenv("DATABASE_URL"))
    db_uri = (db_url or os.getenv("SQLALCHEMY_DATABASE_URI") or "sqlite:///skyline.db").strip()

    cookie_secure = _bool_env("COOKIE_SECURE", _is_production(env))
    session_samesite = (_str_env("SESSION_SAMESITE", "Lax") or "Lax").strip()
    if session_samesite not in {"Lax", "Strict", "None"}:
        session_samesite = "Lax"
    # si SameSite=None => Secure obligatorio en navegadores
    if session_samesite == "None":
        cookie_secure = True

    session_days = max(1, _int_env("SESSION_PERMANENT_DAYS", 30))
    max_mb = max(1, _int_env("MAX_UPLOAD_MB", 20))

    engine_opts: Dict[str, Any] = {
        "pool_pre_ping": _bool_env("SQLALCHEMY_POOL_PRE_PING", True),
        "pool_recycle": _int_env("DB_POOL_RECYCLE", 280),
    }

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

        UPLOADS_DIR=(os.getenv("UPLOADS_DIR") or "static/uploads").strip(),
        APP_NAME=os.getenv("APP_NAME", "Skyline Store"),
        APP_URL=(os.getenv("APP_URL") or "http://127.0.0.1:5000").strip().rstrip("/"),

        MAX_CONTENT_LENGTH=max_mb * 1024 * 1024,
    )

    _setup_logging(app)

    app.logger.info(
        "🚀 create_app ENV=%s DEBUG=%s DB=%s SECURE=%s SAMESITE=%s",
        app.config["ENV"],
        bool(app.debug),
        app.config["SQLALCHEMY_DATABASE_URI"],
        app.config["SESSION_COOKIE_SECURE"],
        app.config["SESSION_COOKIE_SAMESITE"],
    )

    if _is_production(env) and db_uri.startswith("sqlite"):
        app.logger.warning("⚠️ Producción con SQLite detectado. Recomendado Postgres en Render.")

    # Extensiones (opcionales)
    _safe_init(app, "Flask-Compress", lambda: _init_compress(app))
    _safe_init(app, "Flask-Talisman", lambda: _init_talisman(app, env))
    _safe_init(app, "Flask-Migrate", lambda: _init_migrate(app))
    _safe_init(app, "Flask-Limiter", lambda: _init_limiter(app))

    # ========= Settings master key (pagos/admin settings) =========
    # ✅ Mejora 9 aplicada acá (antes de usar panel settings)
    _critical_init(app, "SETTINGS_MASTER_KEY guard", lambda: _require_settings_master_key_if_needed(app))

    # ============================================================
    # Models hub + seed + payments bootstrap
    # ============================================================
    auto_tables = _should_auto_create_tables(env)

    def _models_hub():
        out = init_models(app, create_admin=True, log_loaded_models=True)

        # create_all SOLO si lo pedís explícitamente en local
        if auto_tables:
            db.create_all()
            app.logger.info("✅ db.create_all() OK (AUTO_CREATE_TABLES=1)")

        # ✅ Mejora 10: bootstrap de PaymentProviders cuando SEED=1 (sin habilitar)
        if _bool_env("SEED", False):
            try:
                from app.models.payment_provider import PaymentProviderService  # type: ignore
                created, total = PaymentProviderService.bootstrap_defaults()
                app.logger.info("💳 Payment providers bootstrap: %s creados / %s total", created, total)
            except Exception:
                app.logger.exception("❌ Error bootstrapping payment providers")

        return out

    _critical_init(app, "Models hub", _models_hub)

    # ============================================================
    # Request hooks (CSRF + headers)
    # ============================================================
    @app.before_request
    def _before_request():
        try:
            _ensure_csrf_token()
        except Exception:
            pass

        # CSRF gate mutadores
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            if not _csrf_ok():
                return _resp_error(app, 400, "csrf_failed", "Solicitud inválida. Recargá la página e intentá nuevamente.")

        # No-cache en admin (evita pantallas viejas)
        if _bool_env("ADMIN_NO_CACHE", True) and (request.path or "").startswith("/admin"):
            try:
                request._admin_no_cache = True  # type: ignore[attr-defined]
            except Exception:
                pass

    @app.after_request
    def _after_request(resp):
        # no-cache admin
        try:
            if getattr(request, "_admin_no_cache", False):
                resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
                resp.headers["Pragma"] = "no-cache"
        except Exception:
            pass

        # hardening headers (sin romper)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        return resp

    # Template globals
    @app.context_processor
    def inject_globals() -> Dict[str, Any]:
        u = _get_current_user()
        return {
            "current_user": u,
            "is_logged_in": bool(u),
            "is_admin": bool(getattr(u, "is_admin", False)) if u else bool(session.get("is_admin")),
            "APP_NAME": app.config.get("APP_NAME", "Skyline Store"),
            "APP_URL": app.config.get("APP_URL", ""),
            "ENV": app.config.get("ENV"),
            "csrf_token": session.get("csrf_token", ""),
        }

    # Blueprints
    registered: List[str] = []

    def _register_all_routes():
        from app.routes import register_blueprints
        register_blueprints(app)
        registered[:] = sorted(app.blueprints.keys())
        return True

    # estricto opcional (si querés que falle rápido cuando falta una ruta)
    if _bool_env("ROUTES_STRICT", False):
        _critical_init(app, "Register Blueprints", _register_all_routes)
    else:
        _safe_init(app, "Register Blueprints", _register_all_routes)

    # Health
    def _db_check() -> Tuple[bool, str]:
        if not _bool_env("HEALTH_DB_CHECK", False):
            return True, "skipped"
        try:
            db.session.execute(db.text("SELECT 1"))
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

    # Error handlers
    @app.errorhandler(404)
    def not_found(_e):
        return _resp_error(app, 404, "not_found", f"No encontrado: {request.path}")

    @app.errorhandler(500)
    def server_error(e):
        app.logger.exception("🔥 Error 500: %s", e)
        return _resp_error(app, 500, "server_error", "Error interno del servidor.")

    # CLI útiles
    @app.cli.command("create-admin")
    def cli_create_admin():
        out = create_admin_if_missing(app)
        print(out)

    @app.cli.command("seed")
    def cli_seed():
        with app.app_context():
            print(create_admin_if_missing(app))

    return app


__all__ = ["create_app", "db"]
