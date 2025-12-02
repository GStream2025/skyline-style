# app/__init__.py
from __future__ import annotations

import os
import sys
from pathlib import Path

from flask import Flask
from app.config import Config

# Extras
from dotenv import load_dotenv
from loguru import logger

# Extensiones opcionales: solo se usan si están instaladas
try:
    from flask_compress import Compress
except ImportError:  # por si no está instalada (no debería pasar porque está en requirements)
    Compress = None  # type: ignore

try:
    from flask_minify import Minify
except ImportError:
    Minify = None  # type: ignore

# Instancia global opcional de Flask-Compress
compress = Compress() if Compress else None


def create_app(config_class: type[Config] = Config) -> Flask:
    """
    Application factory principal de Skyline Style Store.

    - Carga variables de entorno (.env)
    - Aplica configuración base
    - Inicializa extensiones ligeras (compresión, minify)
    - Registra blueprints
    - Registra handlers de error y logging
    """
    _load_env()
    _configure_logging()

    logger.info("Iniciando aplicación Skyline Style Store…")

    app = Flask(
        __name__,
        static_folder="static",
        template_folder="templates",
    )

    # ============================
    #        CONFIGURACIÓN
    # ============================
    app.config.from_object(config_class)

    # ============================
    #        EXTENSIONES
    # ============================
    _init_extensions(app)

    # ============================
    #        BLUEPRINTS
    # ============================
    _register_blueprints(app)

    # ============================
    #    HANDLERS DE ERRORES
    # ============================
    _register_error_handlers(app)

    logger.success("Skyline Style Store cargada correctamente ✅")

    return app


# --------------------------------------------------------------------
# Helpers internos
# --------------------------------------------------------------------
def _load_env() -> None:
    """Carga variables desde .env si existe (útil en desarrollo / Render)."""
    root_dir = Path(__file__).resolve().parent.parent
    env_path = root_dir / ".env"
    if env_path.exists():
        load_dotenv(env_path)
        logger.debug(f".env cargado desde: {env_path}")


def _init_extensions(app: Flask) -> None:
    """Inicializa extensiones ligeras (no BD ni cosas pesadas)."""
    # Compresión gzip/br para respuestas
    if compress:
        compress.init_app(app)
        logger.debug("Flask-Compress inicializado")

    # Minificar HTML/JS/CSS solo en producción (no en debug/testing)
    if Minify and not app.debug and not app.testing:
        Minify(app=app, html=True, js=True, cssless=True)
        logger.debug("Flask-Minify inicializado (producción)")


def _register_blueprints(app: Flask) -> None:
    """Importa y registra los blueprints de la app."""
    # Rutas públicas: home, tienda, producto, about
    try:
        from app.routes.main_routes import main_bp

        app.register_blueprint(main_bp)
        logger.debug("Blueprint 'main_bp' registrado")
    except Exception as exc:
        logger.error(f"No se pudo registrar main_bp (obligatorio): {exc}")
        raise

    # Blueprint de auth (opcional)
    try:
        from app.routes.auth_routes import auth_bp

        app.register_blueprint(auth_bp)
        logger.debug("Blueprint 'auth_bp' registrado")
    except Exception as exc:
        logger.warning(f"No se pudo registrar auth_bp (opcional): {exc}")

    # Blueprint de rutas extra de Printful (opcional)
    try:
        from app.routes.printful_routes import printful_bp

        app.register_blueprint(printful_bp)
        logger.debug("Blueprint 'printful_bp' registrado")
    except Exception as exc:
        logger.warning(f"No se pudo registrar printful_bp (opcional): {exc}")


def _register_error_handlers(app: Flask) -> None:
    """Páginas de error personalizadas (404 y 500)."""
    from flask import render_template

    @app.errorhandler(404)
    def not_found(error):  # type: ignore[override]
        logger.warning(f"404 Not Found: {error}")
        try:
            return (
                render_template(
                    "error.html",
                    code=404,
                    message="La página que buscás no existe o fue movida.",
                ),
                404,
            )
        except Exception:
            # Fallback mínimo si no existe error.html
            return "404 - Página no encontrada", 404

    @app.errorhandler(500)
    def internal_error(error):  # type: ignore[override]
        logger.error(f"500 Internal Server Error: {error}")
        try:
            return (
                render_template(
                    "error.html",
                    code=500,
                    message="Ocurrió un error inesperado. Estamos trabajando en ello.",
                ),
                500,
            )
        except Exception:
            return "500 - Error interno del servidor", 500


def _configure_logging() -> None:
    """Configura loguru para logs prolijos en consola (ideal para Render)."""
    logger.remove()  # limpia handlers anteriores
    logger.add(
        sys.stdout,
        level=os.getenv("LOG_LEVEL", "INFO"),
        backtrace=True,
        diagnose=False,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
               "<level>{level: <8}</level> | "
               "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
               "<level>{message}</level>",
    )
