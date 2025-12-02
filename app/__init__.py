# app/__init__.py
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Type, Optional

from flask import Flask
from dotenv import load_dotenv
from loguru import logger

# ----------------------------------------------------------------------
# 1) Importar configuración de forma flexible
#    - Soporta tanto:
#        config = {"development": ..., "production": ...}
#      como:
#        class Config: ...
# ----------------------------------------------------------------------
CONFIG_MAP = {}
DEFAULT_CONFIG_CLASS: Optional[Type] = None

try:
    # Caso config.py PRO (dict con entornos)
    from app.config import config as CONFIG_MAP  # type: ignore
except Exception:
    CONFIG_MAP = {}

try:
    # Caso clásico: class Config
    from app.config import Config as DEFAULT_CONFIG_CLASS  # type: ignore
except Exception:
    DEFAULT_CONFIG_CLASS = None  # type: ignore


# ----------------------------------------------------------------------
# 2) Extras opcionales
# ----------------------------------------------------------------------
try:
    from flask_compress import Compress
except ImportError:
    Compress = None  # type: ignore

try:
    from flask_minify import Minify
except ImportError:
    Minify = None  # type: ignore

compress = Compress() if Compress else None

# Paths base del proyecto
MODULE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = MODULE_DIR.parent


# ----------------------------------------------------------------------
# 3) Factory principal
# ----------------------------------------------------------------------
def create_app(env_name: str | None = None) -> Flask:
    """
    Application factory principal de Skyline Style Store.

    - Carga variables de entorno desde .env (si existe)
    - Detecta el entorno (development / production)
    - Selecciona la configuración adecuada
    - Inicializa extensiones ligeras (compress, minify)
    - Registra blueprints
    - Registra handlers de error
    """
    _load_env()
    _configure_logging()

    env = _detect_env(env_name)
    config_obj = _select_config(env)

    logger.info("Iniciando aplicación Skyline Style Store…")
    logger.info("Entorno detectado: {}", env)

    # Crear la app
    app = Flask(
        __name__,
        static_folder="static",
        template_folder="templates",
    )

    # ============================
    #       CONFIGURACIÓN
    # ============================
    if config_obj is not None:
        app.config.from_object(config_obj)
        logger.debug("Configuración cargada desde: {}", config_obj)
    else:
        logger.warning(
            "No se encontró configuración específica. "
            "La app usará valores por defecto de Flask."
        )

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


# ----------------------------------------------------------------------
# Helpers internos
# ----------------------------------------------------------------------
def _load_env() -> None:
    """
    Carga variables desde .env en la raíz del proyecto (solo si existe).
    Útil en desarrollo/local. En Render las env vars vienen del panel.
    """
    env_path = PROJECT_ROOT / ".env"
    if env_path.exists():
        load_dotenv(env_path)
        logger.debug(".env cargado desde: {}", env_path)
    else:
        logger.debug("No se encontró .env en {}, usando solo variables del sistema.", PROJECT_ROOT)


def _detect_env(explicit_env: str | None = None) -> str:
    """
    Determina el entorno activo:
    - Prioriza el parámetro explícito
    - Luego FLASK_ENV
    - Por defecto 'production'
    """
    if explicit_env:
        return explicit_env.lower()

    env = os.getenv("FLASK_ENV", "production").lower()
    if env not in {"development", "production"}:
        logger.warning("Valor de FLASK_ENV desconocido: {}. Usando 'production'.", env)
        env = "production"
    return env


def _select_config(env: str):
    """
    Selecciona la clase de configuración adecuada según:
    - dict config[env] en app.config (si existe)
    - DEFAULT_CONFIG_CLASS (class Config) si no hay dict
    """
    # Caso PRO: config = {"development": ..., "production": ...}
    if CONFIG_MAP:
        cfg = CONFIG_MAP.get(env)
        if cfg is None:
            logger.warning(
                "No se encontró configuración para '{}'. "
                "Se usará la primera disponible en config.",
                env,
            )
            # fallback: primera del dict
            cfg = next(iter(CONFIG_MAP.values()))
        return cfg

    # Caso simple: class Config en app.config
    if DEFAULT_CONFIG_CLASS is not None:
        return DEFAULT_CONFIG_CLASS

    # Sin configuración disponible
    logger.error(
        "No se encontró ni 'config' dict ni clase 'Config' en app.config. "
        "Revisá tu archivo config.py."
    )
    return None


def _init_extensions(app: Flask) -> None:
    """Inicializa extensiones ligeras (compresión, minify)."""
    # Compresión gzip/br para respuestas HTTP
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
        logger.error("No se pudo registrar main_bp (obligatorio): {}", exc)
        raise

    # Blueprint de auth (opcional)
    try:
        from app.routes.auth_routes import auth_bp

        app.register_blueprint(auth_bp)
        logger.debug("Blueprint 'auth_bp' registrado")
    except Exception as exc:
        logger.warning("No se pudo registrar auth_bp (opcional): {}", exc)

    # Blueprint de rutas extra de Printful (opcional)
    try:
        from app.routes.printful_routes import printful_bp

        app.register_blueprint(printful_bp)
        logger.debug("Blueprint 'printful_bp' registrado")
    except Exception as exc:
        logger.warning("No se pudo registrar printful_bp (opcional): {}", exc)


def _register_error_handlers(app: Flask) -> None:
    """Páginas de error personalizadas (404 y 500)."""
    from flask import render_template

    @app.errorhandler(404)
    def not_found(error):  # type: ignore[override]
        logger.warning("404 Not Found: {}", error)
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
        logger.error("500 Internal Server Error: {}", error)
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
    """
    Configura loguru para logs prolijos en consola (ideal para Render y dev).
    Respeta LOG_LEVEL si está definido en las variables de entorno.
    """
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()

    logger.remove()  # limpia handlers anteriores
    logger.add(
        sys.stdout,
        level=log_level,
        backtrace=True,
        diagnose=False,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level>"
        ),
    )

    logger.debug("Logging configurado con nivel: {}", log_level)
