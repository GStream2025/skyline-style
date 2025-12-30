# app/__init__.py
from __future__ import annotations

import logging
import os
from typing import Optional, Callable, Any, List, Dict

from flask import Flask, jsonify, render_template, request, session

# ✅ IMPORTANTE: NO crear db acá.
# ✅ Usamos el db ÚNICO desde app.models
from app.models import db, init_models, create_admin_if_missing


# ============================================================
# ENV helpers
# ============================================================

def _bool_env(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}


def _int_env(key: str, default: int) -> int:
    v = os.getenv(key)
    if v is None:
        return default
    try:
        return int(v)
    except ValueError:
        return default


def _normalize_database_url(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    if url.startswith("postgres://"):  # legacy
        return url.replace("postgres://", "postgresql://", 1)
    return url


# ============================================================
# Logging
# ============================================================

def _setup_logging(app: Flask) -> None:
    """
    Logging consistente en local/prod.
    Respeta LOG_LEVEL si existe, sino DEBUG cuando app.debug.
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
# Auth helpers (simple)
# ============================================================

def _get_current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        # usa exports del hub (app/models/__init__.py)
        from app.models import User
        return db.session.get(User, int(uid))
    except Exception:
        return None


# ============================================================
# App Factory
# ============================================================

def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")

    # -------------------------
    # Base config
    # -------------------------
    env_raw = (os.getenv("ENV") or os.getenv("FLASK_ENV") or "production").strip().lower()
    debug = _bool_env("DEBUG", env_raw == "development") or _bool_env("FLASK_DEBUG", False)

    app.config.update(
        SECRET_KEY=os.getenv("SECRET_KEY", "dev-secret-change-me"),
        ENV="development" if debug else "production",
        DEBUG=debug,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
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
    # Extensions (safe + reales)
    # -------------------------
    _safe_init(
        app,
        "Flask-Compress",
        lambda: __import__("flask_compress").flask_compress.Compress(app),
    )

    def _talisman():
        from flask_talisman import Talisman
        Talisman(
            app,
            force_https=_bool_env("FORCE_HTTPS", False),
            content_security_policy=None,
        )

    _safe_init(app, "Flask-Talisman", _talisman)

    def _cache():
        from flask_caching import Cache
        Cache(
            app,
            config={
                "CACHE_TYPE": os.getenv("CACHE_TYPE", "SimpleCache"),
                "CACHE_DEFAULT_TIMEOUT": _int_env("CACHE_DEFAULT_TIMEOUT", 300),
            },
        )

    _safe_init(app, "Flask-Caching", _cache)

    def _minify():
        from flask_minify import Minify
        Minify(app=app, html=True, js=True, cssless=True)

    _safe_init(app, "Flask-Minify", _minify)

    def _migrate():
        from flask_migrate import Migrate
        # ✅ esto habilita "flask db ..." SI tenés Flask-Migrate instalado
        Migrate(app, db)

    _safe_init(app, "Flask-Migrate", _migrate)

    # -------------------------
    # Models hub + AUTO TABLES + ADMIN (orden correcto)
    # -------------------------
    def _models_bootstrap():
        """
        1) init_models => db.init_app + import de modelos (registro real)
        2) DEV: db.create_all (opcional) para evitar 'no such table'
        3) create_admin_if_missing => deja admin listo
        """
        init_models(app, create_admin=False)

        auto_tables = _bool_env("AUTO_CREATE_TABLES", True)
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

    _safe_init(app, "Blueprint main_routes",
               lambda: reg("main_bp", "app.routes.main_routes", "main_bp", url_prefix=""))
    _safe_init(app, "Blueprint shop_routes",
               lambda: reg("shop_bp", "app.routes.shop_routes", "shop_bp", url_prefix=""))
    _safe_init(app, "Blueprint auth_routes",
               lambda: reg("auth_bp", "app.routes.auth_routes", "auth_bp", url_prefix=""))
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
        # si main_bp existe igual no rompe; tu blueprint puede definir "/" también
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
