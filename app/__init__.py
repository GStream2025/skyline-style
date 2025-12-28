from __future__ import annotations

import logging
import os
from typing import Optional, Callable, Any, List

from flask import Flask, jsonify, render_template, request, session
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

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
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql://", 1)
    return url

# ============================================================
# Logging
# ============================================================

def _setup_logging(app: Flask) -> None:
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
        app.logger.info(" %s inicializado", label)
        return out
    except Exception as e:
        app.logger.warning(
            " %s no pudo inicializarse: %s",
            label,
            e,
            exc_info=app.debug
        )
        return None

# ============================================================
# Auth helpers
# ============================================================

def _get_current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        from app.models.user import User
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
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")

    env = (os.getenv("ENV") or os.getenv("FLASK_ENV") or "production").strip().lower()
    debug = _bool_env("DEBUG", env == "development")

    app.config.update(
        ENV="development" if debug else "production",
        DEBUG=debug,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )
    app.debug = debug

    _setup_logging(app)
    app.logger.info(" create_app() ENV=%s DEBUG=%s", app.config["ENV"], app.config["DEBUG"])

    # -------------------------
    # Database
    # -------------------------
    db_url = _normalize_database_url(os.getenv("DATABASE_URL"))
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url or "sqlite:///skyline.db"
    db.init_app(app)

    # -------------------------
    # Model registry (best-effort)
    # -------------------------
    def _register_models():
        for mod in ("user", "category", "product", "order", "campaign"):
            try:
                __import__(f"app.models.{mod}")
            except Exception:
                pass

    _safe_init(app, "Model registry", _register_models)

    # -------------------------
    # Optional extensions
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
        Migrate(app, db)

    _safe_init(app, "Flask-Migrate", _migrate)

    # -------------------------
    # Template globals
    # -------------------------
    @app.context_processor
    def inject_globals():
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

    def reg(label: str, module_path: str, bp_name: str):
        module = __import__(module_path, fromlist=[bp_name])
        bp = getattr(module, bp_name)
        app.register_blueprint(bp)
        registered.append(label)
        app.logger.info(" Blueprint registrado: %s", label)

    _safe_init(app, "Blueprint main_routes",
               lambda: reg("main_bp", "app.routes.main_routes", "main_bp"))
    _safe_init(app, "Blueprint shop_routes",
               lambda: reg("shop_bp", "app.routes.shop_routes", "shop_bp"))
    _safe_init(app, "Blueprint auth_routes",
               lambda: reg("auth_bp", "app.routes.auth_routes", "auth_bp"))
    _safe_init(app, "Blueprint admin_routes",
               lambda: reg("admin_bp", "app.routes.admin_routes", "admin_bp"))
    _safe_init(app, "Blueprint printful_routes",
               lambda: reg("printful_bp", "app.routes.printful_routes", "printful_bp"))
    _safe_init(app, "Blueprint marketing_routes",
               lambda: reg("marketing_bp", "app.routes.marketing_routes", "marketing_bp"))

    # -------------------------
    # Routes base
    # -------------------------
    @app.get("/")
    def home_fallback():
        try:
            return render_template("index.html")
        except Exception:
            return jsonify({
                "app": "Skyline Store",
                "status": "ok",
                "blueprints": registered
            })

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "env": app.config["ENV"],
            "debug": bool(app.debug),
            "blueprints": registered,
        }

    @app.errorhandler(404)
    def not_found(_e):
        return jsonify({
            "error": "not_found",
            "path": request.path,
            "tip": "Probá /health",
        }), 404

    return app


__all__ = ["create_app", "db"]
