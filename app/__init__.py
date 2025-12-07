# app/__init__.py
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Type, Optional

from flask import Flask
from dotenv import load_dotenv
from loguru import logger

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

# ----------------------------------------------------------------------
# 0) Instancias globales de extensiones
#    (importables desde otros módulos: from app import db)
# ----------------------------------------------------------------------
db = SQLAlchemy()
migrate = Migrate()

# ----------------------------------------------------------------------
# 1) Importar configuración de forma flexible
#    - Soporta:
#        config = {"development": ..., "production": ...}
#      o:
#        class Config: ...
# ----------------------------------------------------------------------
CONFIG_MAP = {}
DEFAULT_CONFIG_CLASS: Optional[Type] = None

try:
    # Caso PRO: config = {"development": ..., "production": ...}
    from app.config import config as CONFIG_MAP  # type: ignore[attr-defined]
except Exception:
    CONFIG_MAP = {}

try:
    # Caso clásico: class Config
    from app.config import Config as DEFAULT_CONFIG_CLASS  # type: ignore[attr-defined]
except Exception:
    DEFAULT_CONFIG_CLASS = None  # type: ignore[assignment]

# ----------------------------------------------------------------------
# 2) Extras opcionales (se usan solo si están instalados)
# ----------------------------------------------------------------------
try:
    from flask_compress import Compress
except ImportError:  # pragma: no cover - entorno sin dependencia
    Compress = None  # type: ignore[assignment]

try:
    from flask_minify import Minify
except ImportError:  # pragma: no cover
    Minify = None  # type: ignore[assignment]

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

    Responsabilidades:
        - Cargar variables de entorno desde .env (en desarrollo)
        - Configurar logging con loguru
        - Detectar entorno (development / production)
        - Seleccionar la configuración adecuada (Config o dict config)
        - Inicializar extensiones (DB, migraciones, compresión, minify)
        - Registrar todos los blueprints (main, auth, printful, admin)
        - Registrar handlers de error globales
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

    Ideal en desarrollo/local. En producción (Render, Railway, etc.)
    las variables vienen del panel de la plataforma.
    """
    env_path = PROJECT_ROOT / ".env"
    if env_path.exists():
        load_dotenv(env_path)
        logger.debug(".env cargado desde: {}", env_path)
    else:
        logger.debug(
            "No se encontró .env en {}. Usando solo variables del sistema.",
            PROJECT_ROOT,
        )


def _detect_env(explicit_env: str | None = None) -> str:
    """
    Determina el entorno activo:
        - Si se pasa env_name a create_app, se usa ese
        - Si no, se toma FLASK_ENV
        - Por defecto: 'production'
    """
    if explicit_env:
        return explicit_env.lower()

    env = os.getenv("FLASK_ENV", "production").lower()
    if env not in {"development", "production"}:
        logger.warning(
            "Valor de FLASK_ENV desconocido: '{}'. Usando 'production'.",
            env,
        )
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
    """
    Inicializa extensiones de la app:
        - Base de datos (SQLAlchemy)
        - Migraciones (Flask-Migrate)
        - Compresión gzip/br (opcional)
        - Minificado de HTML/JS/CSS (solo producción, opcional)
    """
    # DB + migraciones
    db.init_app(app)
    migrate.init_app(app, db)
    logger.debug("SQLAlchemy y Flask-Migrate inicializados")

    # Compresión gzip/br para respuestas HTTP
    if compress:
        compress.init_app(app)
        logger.debug("Flask-Compress inicializado")

    # Minificar HTML/JS/CSS solo en producción (no en debug/testing)
    if Minify and not app.debug and not app.testing:
        Minify(app=app, html=True, js=True, cssless=True)
        logger.debug("Flask-Minify inicializado (producción)")


def _register_blueprints(app: Flask) -> None:
    """
    Importa y registra los blueprints de la app.

    Si alguno opcional falla, lo loguea pero no rompe la app,
    salvo el main_bp que sí es obligatorio.
    """
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

    # Blueprint del PANEL ADMIN (obligatorio para tu modo admin)
    try:
        from app.routes_admin import admin_bp

        app.register_blueprint(admin_bp)
        logger.debug("Blueprint 'admin_bp' registrado en /admin")
    except Exception as exc:
        logger.warning(
            "No se pudo registrar admin_bp. "
            "El panel admin no estará disponible: {}",
            exc,
        )


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
