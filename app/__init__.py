# app/__init__.py
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

from flask import Flask, jsonify, request
from dotenv import load_dotenv
from loguru import logger
from werkzeug.middleware.proxy_fix import ProxyFix

from flask_sqlalchemy import SQLAlchemy

# -----------------------------------------------------------------------------
# 0) EXTENSIONES GLOBALES
# -----------------------------------------------------------------------------
db = SQLAlchemy()

# Extensiones opcionales (no obligatorias)
compress = None
Minify = None
talisman = None

try:
    from flask_compress import Compress
    compress = Compress()
except ImportError:
    pass

try:
    from flask_minify import Minify
except ImportError:
    pass

try:
    from flask_talisman import Talisman
    talisman = Talisman
except ImportError:
    talisman = None


# -----------------------------------------------------------------------------
# 1) PATHS
# -----------------------------------------------------------------------------
MODULE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = MODULE_DIR.parent


# -----------------------------------------------------------------------------
# 2) FACTORY PRINCIPAL
# -----------------------------------------------------------------------------
def create_app(env_name: Optional[str] = None) -> Flask:
    _load_env()
    _configure_logging()

    from app.config import get_config

    config_class = get_config()
    env = config_class.ENV

    logger.info("🚀 Iniciando Skyline Style Store (env: {})", env)

    app = Flask(
        __name__,
        static_folder="static",
        template_folder="templates",
    )

    # -------------------------------------------------------------------------
    # CONFIGURACIÓN
    # -------------------------------------------------------------------------
    app.config.from_object(config_class)

    # -------------------------------------------------------------------------
    # PROXY FIX (Render / HTTPS correcto)
    # -------------------------------------------------------------------------
    if app.config.get("TRUST_PROXY_HEADERS", False):
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=1,
            x_proto=1,
            x_host=1,
            x_port=1,
        )
        logger.debug("ProxyFix habilitado (Render / reverse proxy)")

    # -------------------------------------------------------------------------
    # EXTENSIONES
    # -------------------------------------------------------------------------
    _init_extensions(app)

    # -------------------------------------------------------------------------
    # BLUEPRINTS
    # -------------------------------------------------------------------------
    _register_blueprints(app)

    # -------------------------------------------------------------------------
    # ERRORES
    # -------------------------------------------------------------------------
    _register_error_handlers(app)

    # -------------------------------------------------------------------------
    # HEALTHCHECK (Render)
    # -------------------------------------------------------------------------
    _register_healthcheck(app)

    logger.success("🔥 Skyline Style Store lista y operativa")
    return app


# -----------------------------------------------------------------------------
# HELPERS INTERNOS
# -----------------------------------------------------------------------------
def _load_env():
    env_path = PROJECT_ROOT / ".env"
    if env_path.exists():
        load_dotenv(env_path)
        logger.debug(".env cargado desde {}", env_path)


def _configure_logging():
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()

    logger.remove()
    logger.add(
        sys.stdout,
        level=log_level,
        backtrace=False,
        diagnose=False,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{message}</cyan>"
        ),
    )


def _init_extensions(app: Flask):
    # -------------------------
    # DATABASE
    # -------------------------
    db.init_app(app)
    logger.debug("SQLAlchemy inicializado")

    # -------------------------
    # COMPRESS
    # -------------------------
    if compress and app.config.get("ENABLE_COMPRESS", False):
        compress.init_app(app)
        logger.debug("Flask-Compress habilitado")

    # -------------------------
    # MINIFY (solo prod)
    # -------------------------
    if Minify and app.config.get("ENABLE_MINIFY", False) and not app.debug:
        Minify(app=app, html=True, js=True, cssless=True)
        logger.debug("Flask-Minify activo")

    # -------------------------
    # TALISMAN (seguridad HTTPS)
    # -------------------------
    if talisman and app.config.get("ENABLE_TALISMAN", False):
        talisman(
            app,
            force_https=app.config.get("FORCE_HTTPS", True),
            content_security_policy=app.config.get("CONTENT_SECURITY_POLICY"),
        )
        logger.debug("Flask-Talisman activo (HTTPS + CSP)")


def _register_blueprints(app: Flask):
    def safe_register(import_path: str, bp_name: str):
        try:
            module = __import__(import_path, fromlist=[bp_name])
            bp = getattr(module, bp_name)
            app.register_blueprint(bp)
            logger.debug("Blueprint {} registrado", bp_name)
        except Exception as exc:
            logger.warning("No se pudo registrar {}: {}", bp_name, exc)

    safe_register("app.routes.main_routes", "main_bp")
    safe_register("app.routes.auth_routes", "auth_bp")
    safe_register("app.routes.printful_routes", "printful_bp")
    safe_register("app.routes_admin", "admin_bp")


def _register_error_handlers(app: Flask):
    from flask import render_template

    @app.errorhandler(404)
    def not_found(error):
        logger.warning("404 {} {}", request.method, request.path)
        try:
            return render_template("error.html", code=404, message="Página no encontrada"), 404
        except Exception:
            return jsonify(error="Not Found"), 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.error("500 {}", error)
        try:
            return render_template("error.html", code=500, message="Error interno del servidor"), 500
        except Exception:
            return jsonify(error="Internal Server Error"), 500


def _register_healthcheck(app: Flask):
    @app.route("/health", methods=["GET"])
    def health():
        return jsonify(
            status="ok",
            app="skyline-style",
            env=app.config.get("FLASK_ENV", "production"),
        ), 200
