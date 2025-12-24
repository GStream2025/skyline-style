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

    - Carga .env SOLO en local (no en Render/producción)
    - Logging pro con Loguru
    - ProxyFix configurable (Render / reverse proxy)
    - Extensiones opcionales sin romper deploy
    - Blueprints robustos (si falla uno opcional, no tumba todo)
    - Error handlers seguros (fallback JSON si faltan templates)
    - Healthcheck /health
    - Seguridad de DB: rollback + remove por request
    """

    _load_env_only_local()
    _setup_logging()

    # Config (lazy import para evitar circulares)
    from app.config import get_config  # type: ignore

    # Acepta env_name o usa FLASK_ENV
    config_class = get_config(env_name) if env_name else get_config()
    env = getattr(config_class, "ENV", os.getenv("FLASK_ENV", "production"))

    app = Flask(
        __name__,
        static_folder="static",
        template_folder="templates",
    )

    app.config.from_object(config_class)

    logger.info("🚀 Skyline Store iniciando | ENV={}", env)

    # ProxyFix (Render / HTTPS real) configurable
    if app.config.get("TRUST_PROXY_HEADERS", True):
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=int(os.getenv("PROXYFIX_X_FOR", "1")),
            x_proto=int(os.getenv("PROXYFIX_X_PROTO", "1")),
            x_host=int(os.getenv("PROXYFIX_X_HOST", "1")),
            x_port=int(os.getenv("PROXYFIX_X_PORT", "1")),
        )
        logger.debug("ProxyFix activo (TRUST_PROXY_HEADERS=True)")

    _init_extensions(app)
    _register_blueprints(app)
    _register_error_handlers(app)
    _register_health(app)
    _register_db_safety(app)

    # Año global para footer (si lo usás en templates)
    @app.context_processor
    def _inject_globals():
        return {"current_year": int(os.getenv("CURRENT_YEAR", "2025"))}

    logger.success("✅ Skyline Store lista y operativa")
    return app


# =============================================================================
# HELPERS
# =============================================================================
def _is_truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _load_env_only_local() -> None:
    """
    Carga .env SOLO en desarrollo local.
    En Render/producción, las variables van por Environment Settings.
    """
    env_path = PROJECT_ROOT / ".env"
    is_render = _is_truthy(os.getenv("RENDER")) or bool(os.getenv("RENDER_SERVICE_ID"))

    if env_path.exists() and not is_render:
        load_dotenv(env_path)
    # En Render NO cargamos .env (seguridad + evita pisar env vars)


def _setup_logging() -> None:
    """
    Loguru a stdout (Render-friendly).
    """
    level = os.getenv("LOG_LEVEL", "INFO").upper().strip()
    debug = _is_truthy(os.getenv("DEBUG")) or os.getenv("FLASK_ENV", "production").lower() == "development"

    logger.remove()
    logger.add(
        sys.stdout,
        level="DEBUG" if debug else level,
        colorize=True,
        enqueue=True,
        backtrace=False,
        diagnose=False,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level>"
        ),
    )
    logger.debug("Logging activo · level={} · debug={}", level, debug)


def _init_extensions(app: Flask) -> None:
    # -------------------------
    # DATABASE
    # -------------------------
    db.init_app(app)
    logger.debug("SQLAlchemy inicializado")

    # -------------------------
    # COMPRESS (opcional)
    # -------------------------
    if app.config.get("ENABLE_COMPRESS", True):
        try:
            from flask_compress import Compress  # type: igno_
