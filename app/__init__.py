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


# -----------------------------------------------------------------------------
# 0) EXTENSIONES GLOBALES
# -----------------------------------------------------------------------------
db = SQLAlchemy()

# Extensiones opcionales
compress = None
minify_ext = None
talisman_ext = None

try:
    from flask_compress import Compress  # type: ignore
    compress = Compress()
except Exception:
    compress = None

try:
    from flask_minify import Minify  # type: ignore
    minify_ext = Minify
except Exception:
    minify_ext = None

try:
    from flask_talisman import Talisman  # type: ignore
    talisman_ext = Talisman
except Exception:
    talisman_ext = None


# -----------------------------------------------------------------------------
# 1) PATHS
# -----------------------------------------------------------------------------
MODULE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = MODULE_DIR.parent


# -----------------------------------------------------------------------------
# 2) FACTORY PRINCIPAL
# -----------------------------------------------------------------------------
def create_app(env_name: Optional[str] = None) -> Flask:
    """
    Factory principal de Flask.
    - Carga .env (si existe)
    - Configura logging (Loguru)
    - Aplica config por entorno
    - Inicia extensiones
    - Registra blueprints
    - Maneja errores + healthcheck
    """
    _load_env()

    # Logging primero (para loguear todo lo que venga después)
    _configure_logging()

    from app.config import get_config  # lazy import (evita circular)

    config_class = get_config(env_name) if env_name else get_config()
    env = getattr(config_class, "ENV", os.getenv("FLASK_ENV", "production"))

    app = Flask(
        __name__,
        static_folder="static",
        template_folder="templates",
    )

    # Config base
    app.config.from_object(config_class)

    logger.info("🚀 Iniciando Skyline Style Store (env: {})", env)

    # ProxyFix (Render/Reverse proxy) para scheme/https correctos
    if app.config.get("TRUST_PROXY_HEADERS", True):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
        logger.debug("ProxyFix habilitado (reverse proxy headers)")

    # Extensiones
    _init_extensions(app)

    # Blueprints
    _register_blueprints(app)

    # Errores
    _register_error_handlers(app)

    # Healthcheck
    _register_healthcheck(app)

    # DB safety: rollback automático si algo falla en request
    _register_db_safety(app)

    # Opcional: create_all para DEV (NO recomendado en producción)
    if app.config.get("AUTO_CREATE_DB", False):
        _create_db_if_needed(app)

    logger.success("🔥 Skyline Style Store lista y operativa")
    return app


# -----------------------------------------------------------------------------
# HELPERS INTERNOS
# -----------------------------------------------------------------------------
def _load_env() -> None:
    """
    Carga variables desde .env si existe.
    IMPORTANTE: acá NO usamos logger (todavía no está configurado).
    """
    env_path = PROJECT_ROOT / ".env"
    if env_path.exists():
        load_dotenv(env_path)


def _configure_logging() -> None:
    """
    Config de Loguru a stdout (Render friendly).
    """
    log_level = os.getenv("LOG_LEVEL", "INFO").upper().strip()

    logger.remove()
    logger.add(
        sys.stdout,
        level=log_level,
        backtrace=False,
        diagnose=False,
        colorize=True,
        enqueue=True,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level>"
        ),
    )

    # Ahora sí podemos loguear
    env_path = PROJECT_ROOT / ".env"
    if env_path.exists():
        logger.debug(".env cargado desde {}", env_path)
    logger.debug("Log level: {}", log_level)


def _init_extensions(app: Flask) -> None:
    # -------------------------
    # DATABASE
    # -------------------------
    db.init_app(app)
    logger.debug("SQLAlchemy inicializado")

    # -------------------------
    # COMPRESS
    # -------------------------
    if compress and app.config.get("ENABLE_COMPRESS", True):
        compress.init_app(app)
        logger.debug("Flask-Compress habilitado")

    # -------------------------
    # MINIFY (solo prod)
    # -------------------------
    if minify_ext and app.config.get("ENABLE_MINIFY", False) and not app.debug:
        minify_ext(app=app, html=True, js=True, cssless=True)
        logger.debug("Flask-Minify activo (prod)")

    # -------------------------
    # TALISMAN (seguridad HTTPS/CSP)
    # -------------------------
    if talisman_ext and app.config.get("ENABLE_TALISMAN", False):
        talisman_ext(
            app,
            force_https=app.config.get("FORCE_HTTPS", True),
            content_security_policy=app.config.get("CONTENT_SECURITY_POLICY"),
            strict_transport_security=app.config.get("HSTS", True),
        )
        logger.debug("Flask-Talisman activo (HTTPS + CSP + HSTS)")


def _register_blueprints(app: Flask) -> None:
    """
    Registro robusto de blueprints.
    Si uno falla, no rompe toda la app (log warning).
    """
    def safe_register(import_path: str, bp_name: str, url_prefix: Optional[str] = None) -> None:
        try:
            module = __import__(import_path, fromlist=[bp_name])
            bp = getattr(module, bp_name)
            app.register_blueprint(bp, url_prefix=url_prefix)
            logger.debug("Blueprint '{}' registrado ({})", bp_name, import_path)
        except Exception as exc:
            logger.warning("No se pudo registrar blueprint '{}' desde '{}': {}", bp_name, import_path, exc)

    safe_register("app.routes.main_routes", "main_bp")
    safe_register("app.routes.auth_routes", "auth_bp")
    safe_register("app.routes.printful_routes", "printful_bp")
    # Admin opcional
    safe_register("app.routes_admin", "admin_bp")


def _register_error_handlers(app: Flask) -> None:
    @app.errorhandler(404)
    def not_found(_error):
        logger.warning("404 {} {}", request.method, request.path)
        try:
            return render_template("error.html", code=404, message="Página no encontrada"), 404
        except Exception:
            return jsonify(error="Not Found"), 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.error("500 {} {} | {}", request.method, request.path, error)
        try:
            return render_template("error.html", code=500, message="Error interno del servidor"), 500
        except Exception:
            return jsonify(error="Internal Server Error"), 500


def _register_healthcheck(app: Flask) -> None:
    @app.get("/health")
    def health():
        return jsonify(
            status="ok",
            app="skyline-style",
            env=app.config.get("ENV", app.config.get("FLASK_ENV", "production")),
            debug=bool(app.debug),
        ), 200


def _register_db_safety(app: Flask) -> None:
    """
    Si ocurre una excepción, aseguramos rollback.
    Y al final de cada request, quitamos la sesión para evitar leaks.
    """
    @app.teardown_request
    def teardown_request(exc):
        if exc:
            try:
                db.session.rollback()
            except Exception:
                pass
        try:
            db.session.remove()
        except Exception:
            pass


def _create_db_if_needed(app: Flask) -> None:
    """
    Solo para DEV/entornos simples. En producción se recomienda migraciones.
    """
    with app.app_context():
        try:
            db.create_all()
            logger.info("DB create_all() ejecutado (AUTO_CREATE_DB=True)")
        except Exception as exc:
            logger.warning("No se pudo ejecutar create_all(): {}", exc)
