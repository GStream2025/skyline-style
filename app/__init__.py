from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request
from flask_sqlalchemy import SQLAlchemy
from loguru import logger
from werkzeug.middleware.proxy_fix import ProxyFix


# =============================================================================
# EXTENSIONES GLOBALES
# =============================================================================
db = SQLAlchemy()


# =============================================================================
# PATHS
# =============================================================================
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent


# =============================================================================
# FACTORY
# =============================================================================
def create_app(env_name: Optional[str] = None) -> Flask:
    """
    Factory principal de Skyline Store.
    Producción-ready · Render-friendly · Premium architecture.
    """

    _load_env()
    _setup_logging()

    from app.config import get_config  # lazy import

    config_class = get_config(env_name)
    env = getattr(config_class, "ENV", os.getenv("FLASK_ENV", "production"))

    app = Flask(
        __name__,
        static_folder="static",
        template_folder="templates",
    )

    app.config.from_object(config_class)

    logger.info("🚀 Skyline Store iniciando | ENV={}", env)

    # ProxyFix (Render / HTTPS real)
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=1,
        x_proto=1,
        x_host=1,
        x_port=1,
    )

    _init_extensions(app)
    _register_blueprints(app)
    _register_error_handlers(app)
    _register_health(app)
    _register_db_safety(app)

    logger.success("✅ Skyline Store lista y operativa")
    return app


# =============================================================================
# HELPERS
# =============================================================================
def _load_env() -> None:
    env_path = PROJECT_ROOT / ".env"
    if env_path.exists():
        load_dotenv(env_path)


def _setup_logging() -> None:
    level = os.getenv("LOG_LEVEL", "INFO").upper()

    logger.remove()
    logger.add(
        sys.stdout,
        level=level,
        colorize=True,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level>"
        ),
    )

    logger.debug("Logging activo · level={}", level)


def _init_extensions(app: Flask) -> None:
    db.init_app(app)
    logger.debug("SQLAlchemy inicializado")

    # Extensiones opcionales (no rompen si faltan)
    try:
        from flask_compress import Compress
        Compress(app)
        logger.debug("Flask-Compress activo")
    except Exception:
        logger.debug("Flask-Compress no disponible")

    try:
        from flask_minify import Minify
        if not app.debug:
            Minify(app, html=True, js=True, cssless=True)
            logger.debug("Flask-Minify activo")
    except Exception:
        logger.debug("Flask-Minify no disponible")

    try:
        from flask_talisman import Talisman
        Talisman(app, force_https=True)
        logger.debug("Flask-Talisman activo")
    except Exception:
        logger.debug("Flask-Talisman no disponible")


def _register_blueprints(app: Flask) -> None:
    """
    Registro explícito y validado de blueprints.
    Si falla uno crítico, se lanza error.
    """

    from app.routes.main_routes import main_bp
    from app.routes.auth_routes import auth_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)

    logger.success("Blueprints públicos registrados")

    # Opcionales
    try:
        from app.routes.printful_routes import printful_bp
        app.register_blueprint(printful_bp)
        logger.debug("Blueprint Printful registrado")
    except Exception:
        logger.warning("Blueprint Printful no disponible")

    try:
        from app.routes_admin import admin_bp
        app.register_blueprint(admin_bp)
        logger.debug("Blueprint Admin registrado")
    except Exception:
        logger.debug("Blueprint Admin no disponible")


def _register_error_handlers(app: Flask) -> None:
    @app.errorhandler(404)
    def not_found(error):
        logger.warning("404 {} {}", request.method, request.path)
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.exception("500 {} {}", request.method, request.path)
        return render_template("500.html"), 500


def _register_health(app: Flask) -> None:
    @app.get("/health")
    def health():
        return jsonify(
            status="ok",
            service="skyline-store",
            env=app.config.get("ENV", "production"),
        )


def _register_db_safety(app: Flask) -> None:
    @app.teardown_request
    def teardown(exc):
        if exc:
            try:
                db.session.rollback()
            except Exception:
                pass
        db.session.remove()
