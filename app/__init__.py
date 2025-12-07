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

# ----------------------------------------------------------------------
# 0) EXTENSIONES GLOBALES
# ----------------------------------------------------------------------
db = SQLAlchemy()

# ----------------------------------------------------------------------
# 1) CONFIGURACIÓN FLEXIBLE
# ----------------------------------------------------------------------
CONFIG_MAP = {}
DEFAULT_CONFIG_CLASS: Optional[Type] = None

try:
    # config = {'development': X, 'production': Y}
    from app.config import config as CONFIG_MAP
except Exception:
    CONFIG_MAP = {}

try:
    from app.config import Config as DEFAULT_CONFIG_CLASS
except Exception:
    DEFAULT_CONFIG_CLASS = None


# ----------------------------------------------------------------------
# 2) EXTENSIONES OPCIONALES (solo si están instaladas)
# ----------------------------------------------------------------------
try:
    from flask_compress import Compress
    compress = Compress()
except ImportError:
    compress = None

try:
    from flask_minify import Minify
except ImportError:
    Minify = None


# ----------------------------------------------------------------------
# 3) PATHS BASE
# ----------------------------------------------------------------------
MODULE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = MODULE_DIR.parent


# ----------------------------------------------------------------------
# 4) FACTORY PRINCIPAL
# ----------------------------------------------------------------------
def create_app(env_name: str | None = None) -> Flask:
    _load_env()
    _configure_logging()

    env = _detect_env(env_name)
    config_obj = _select_config(env)

    logger.info("🚀 Iniciando Skyline Style Store… (modo: {})", env)

    app = Flask(
        __name__,
        static_folder="static",
        template_folder="templates",
    )

    # -------------------------
    # CONFIG
    # -------------------------
    if config_obj:
        app.config.from_object(config_obj)
        logger.debug("Configuración cargada: {}", config_obj)
    else:
        logger.warning("⚠ No se encontró configuración válida.")

    # -------------------------
    # EXTENSIONES
    # -------------------------
    _init_extensions(app)

    # -------------------------
    # BLUEPRINTS
    # -------------------------
    _register_blueprints(app)

    # -------------------------
    # ERRORES
    # -------------------------
    _register_error_handlers(app)

    logger.success("🔥 Skyline Style Store cargada sin errores!")
    return app


# ----------------------------------------------------------------------
# HELPERS INTERNOS
# ----------------------------------------------------------------------
def _load_env():
    env_path = PROJECT_ROOT / ".env"
    if env_path.exists():
        load_dotenv(env_path)
        logger.debug("Archivo .env cargado desde {}", env_path)
    else:
        logger.debug("No existe .env; se usan variables del sistema.")


def _detect_env(explicit_env: str | None = None) -> str:
    if explicit_env:
        return explicit_env.lower()

    env = os.getenv("FLASK_ENV", "production").lower()
    return env if env in {"development", "production"} else "production"


def _select_config(env: str):
    if CONFIG_MAP:
        cfg = CONFIG_MAP.get(env)
        return cfg or next(iter(CONFIG_MAP.values()))

    return DEFAULT_CONFIG_CLASS


def _init_extensions(app: Flask):
    """
    Inicialización mínima y 100% compatible con Render.
    Sin Flask-Migrate (NO se usa y causaba error).
    """
    db.init_app(app)
    logger.debug("SQLAlchemy inicializado (sin migraciones)")

    if compress:
        compress.init_app(app)
        logger.debug("Flask-Compress habilitado (gzip/br)")

    if Minify and not app.debug:
        Minify(app=app, html=True, js=True, cssless=True)
        logger.debug("Flask-Minify activo (producción)")


def _register_blueprints(app: Flask):
    # MAIN
    from app.routes.main_routes import main_bp
    app.register_blueprint(main_bp)
    logger.debug("Blueprint main_bp registrado")

    # AUTH
    try:
        from app.routes.auth_routes import auth_bp
        app.register_blueprint(auth_bp)
        logger.debug("Blueprint auth_bp registrado")
    except Exception as exc:
        logger.warning("auth_bp no disponible: {}", exc)

    # PRINTFUL
    try:
        from app.routes.printful_routes import printful_bp
        app.register_blueprint(printful_bp)
        logger.debug("Blueprint printful_bp registrado")
    except Exception as exc:
        logger.warning("printful_bp no disponible: {}", exc)

    # ADMIN
    try:
        from app.routes_admin import admin_bp
        app.register_blueprint(admin_bp)
        logger.debug("Blueprint admin_bp registrado")
    except Exception as exc:
        logger.warning("Admin panel no disponible: {}", exc)


def _register_error_handlers(app: Flask):
    from flask import render_template

    @app.errorhandler(404)
    def not_found(error):
        logger.warning("404: {}", error)
        try:
            return render_template("error.html", code=404, message="Página no encontrada."), 404
        except Exception:
            return "404 Not Found", 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.error("500: {}", error)
        try:
            return render_template("error.html", code=500, message="Error interno."), 500
        except Exception:
            return "500 Error interno", 500


def _configure_logging():
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()

    logger.remove()
    logger.add(
        sys.stdout,
        level=log_level,
        backtrace=False,
        diagnose=False,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level}</level> | <cyan>{message}</cyan>",
    )
