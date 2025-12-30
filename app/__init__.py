# app/__init__.py — SKYLINE STYLE PRO (ULTRA FINAL v2)
from __future__ import annotations

import logging
import os
import secrets
from typing import Optional, Callable, Any, List, Dict

from flask import Flask, jsonify, render_template, request, session
from werkzeug.middleware.proxy_fix import ProxyFix

# ✅ NO crear SQLAlchemy acá. Usamos el db ÚNICO del hub de modelos
from app.models import db, init_models, create_admin_if_missing


# ============================================================
# ENV helpers
# ============================================================

_TRUE = {"1", "true", "yes", "y", "on"}
_FALSE = {"0", "false", "no", "n", "off"}


def _bool_env(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    s = v.strip().lower()
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
        return int(v)
    except (TypeError, ValueError):
        return default


def _normalize_database_url(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    # Heroku legacy
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql://", 1)
    return url


def _is_prod(app: Flask) -> bool:
    return (app.config.get("ENV") or "").lower() == "production"


# ============================================================
# Logging
# ============================================================

def _setup_logging(app: Flask) -> None:
    """
    Logging consistente local/prod.
    Respeta LOG_LEVEL si existe.
    """
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
    app.logger.setLevel(level)


def _safe_init(app: Flask, label: str, fn: Callable[[], Any]) -> Any:
    try:
        out = fn()
        app.logger.info("✅ %s inicializado", label)
        return out
    except Exception as e:
        app.logger.warning("⚠️ %s no pudo inicializarse: %s", label, e, exc_info=app.debug)
        return None


# ============================================================
# Auth helpers
# ============================================================

def _get_current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        from app.models import User  # export del hub
        return db.session.get(User, int(uid))
    except Exception:
        return None


def _secure_default_secret(debug: bool) -> str:
    """
    En prod: si no hay SECRET_KEY, generamos una aleatoria en runtime
    (no rompe deploy). OJO: reinicios invalidan sesiones.
    En local: mantenemos dev-secret si querés.
    """
    env_secret = os.getenv("SECRET_KEY")
    if env_secret:
        return env_secret
    if debug:
        return "dev-secret-change-me"
    return secrets.token_urlsafe(48)


# ============================================================
# App Factory
# ============================================================

def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")

    # -------------------------
    # Base env/debug
    # -------------------------
    env_raw = (os.getenv("ENV") or os.getenv("FLASK_ENV") or "production").strip().lower()
    debug = _bool_env("DEBUG", env_raw == "development") or _bool_env("FLASK_DEBUG", False)

    # 🔥 Render/Proxy: arregla scheme/https y headers cuando hay proxy
    # x_for=1, x_proto=1 suele ser suficiente en Render
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    app.config.update(
        SECRET_KEY=_secure_default_secret(debug),
        ENV="development" if debug else "production",
        DEBUG=debug,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,

        # Sesiones (hardening)
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE=os.getenv("SESSION_SAMESITE", "Lax"),
        # En prod: Secure True; en dev: False para http://127.0.0.1
        SESSION_COOKIE_SECURE=_bool_env("COOKIE_SECURE", not debug),

        # JSON
        JSON_SORT_KEYS=False,
    )
    app.debug = debug

    _setup_logging(app)
    app.logger.info("🚀 create_app() ENV=%s DEBUG=%s", app.config["ENV"], app.config["DEBUG"])

    # -------------------------
    # Database URI (NO init_app acá)
    # -------------------------
    db_url = _normalize_database_url(os.getenv("DATABASE_URL"))
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url or "sqlite:///skyline.db"

    # -------------------------
    # Extensions (safe)
    # -------------------------
    _safe_init(app, "Flask-Compress",
               lambda: __import__("flask_compress").flask_compress.Compress(app))

    def _talisman():
        from flask_talisman import Talisman

        # En prod, normalmente querés HTTPS
        force_https = _bool_env("FORCE_HTTPS", _is_prod(app))
        # Si estás detrás de proxy, Flask-Talisman + ProxyFix ya funcionan bien.
        Talisman(
            app,
            force_https=force_https,
            content_security_policy=None,  # podés endurecer después
        )

    _safe_init(app, "Flask-Talisman", _talisman)

    def _cache():
        from flask_caching import Cache
        Cache(app, config={
            "CACHE_TYPE": os.getenv("CACHE_TYPE", "SimpleCache"),
            "CACHE_DEFAULT_TIMEOUT": _int_env("CACHE_DEFAULT_TIMEOUT", 300),
        })

    _safe_init(app, "Flask-Caching", _cache)

    def _minify():
        from flask_minify import Minify
        Minify(app=app, html=True, js=True, cssless=True)

    _safe_init(app, "Flask-Minify", _minify)

    def _migrate():
        from flask_migrate import Migrate
        Migrate(app, db)

    _safe_init(app, "Flask-Migrate", _migrate)

    # -------------------------
    # Models hub + AUTO TABLES + ADMIN (orden correcto)
    # -------------------------
    def _models_bootstrap():
        """
        1) init_models => db.init_app + import de modelos
        2) DEV: create_all opcional (evita 'no such table' en local)
        3) Admin bootstrap (crea/actualiza admin si falta)
        """
        init_models(app, create_admin=False)

        auto_tables = _bool_env("AUTO_CREATE_TABLES", True)

        # ✅ SOLO en development (nunca en prod)
        if app.config.get("ENV") == "development" and auto_tables:
            with app.app_context():
                db.create_all()
                app.logger.info("✅ db.create_all() OK (development)")

        return create_admin_if_missing(app)

    _safe_init(app, "Models hub + Auto tables + Admin", _models_bootstrap)

    # -------------------------
    # Template globals
    # -------------------------
    @app.context_processor
    def inject_globals() -> Dict[str, Any]:
        u = _get_current_user()
        return {
            "current_user": u,
            "is_logged_in": bool(u),
            # preferimos la DB, pero bancamos legacy session flag
            "is_admin": bool(getattr(u, "is_admin", False)) if u else bool(session.get("is_admin")),
            "APP_NAME": os.getenv("APP_NAME", "Skyline Store"),
            "ENV": app.config.get("ENV"),
        }

    # -------------------------
    # Blueprints (safe)
    # -------------------------
    registered: List[str] = []

    def reg(label: str, module_path: str, bp_name: str, url_prefix: Optional[str] = None):
        module = __import__(module_path, fromlist=[bp_name])
        bp = getattr(module, bp_name)
        app.register_blueprint(bp, url_prefix=url_prefix)
        registered.append(label)
        app.logger.info("🔗 Blueprint registrado: %s (%s)", label, url_prefix or "/")

    # Orden recomendado: main → shop → auth → account → admin → integraciones
    _safe_init(app, "Blueprint main_routes",
               lambda: reg("main_bp", "app.routes.main_routes", "main_bp", url_prefix=""))

    _safe_init(app, "Blueprint shop_routes",
               lambda: reg("shop_bp", "app.routes.shop_routes", "shop_bp", url_prefix=""))

    _safe_init(app, "Blueprint auth_routes",
               lambda: reg("auth_bp", "app.routes.auth_routes", "auth_bp", url_prefix=""))

    _safe_init(app, "Blueprint account_routes",
               lambda: reg("account_bp", "app.routes.account_routes", "account_bp", url_prefix=""))

    _safe_init(app, "Blueprint admin_routes",
               lambda: reg("admin_bp", "app.routes.admin_routes", "admin_bp", url_prefix="/admin"))

    _safe_init(app, "Blueprint printful_routes",
               lambda: reg("printful_bp", "app.routes.printful_routes", "printful_bp", url_prefix="/printful"))

    _safe_init(app, "Blueprint marketing_routes",
               lambda: reg("marketing_bp", "app.routes.marketing_routes", "marketing_bp", url_prefix=""))

    # -------------------------
    # Base routes (fallbacks)
    # -------------------------
    @app.get("/")
    def home_fallback():
        return render_template("index.html")

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "env": app.config["ENV"],
            "debug": bool(app.debug),
            "blueprints": registered,
            "db": app.config.get("SQLALCHEMY_DATABASE_URI", ""),
        }

    @app.errorhandler(404)
    def not_found(_e):
        try:
            return render_template("404.html"), 404
        except Exception:
            return jsonify({"error": "not_found", "path": request.path}), 404

    @app.errorhandler(500)
    def server_error(e):
        app.logger.exception("🔥 Error 500: %s", e)
        try:
            return render_template("500.html"), 500
        except Exception:
            return jsonify({"error": "server_error"}), 500

    # -------------------------
    # CLI helpers (PRO)
    # -------------------------
    @app.cli.command("create-admin")
    def cli_create_admin():
        """Crea/actualiza admin desde ENV ADMIN_EMAIL/ADMIN_PASSWORD."""
        out = create_admin_if_missing(app)
        print(out)

    @app.cli.command("create-tables")
    def cli_create_tables():
        """Crea tablas en DB (local rápido)."""
        with app.app_context():
            db.create_all()
            print("✅ Tablas creadas")

    @app.cli.command("seed")
    def cli_seed():
        """Seed mínimo (admin)."""
        with app.app_context():
            print(create_admin_if_missing(app))

    return app


__all__ = ["create_app", "db"]
