"""
run.py — Entry point de Skyline Store (Producción + Desarrollo)

✅ Carga .env SOLO en local (no en producción).
✅ Configura logging profesional con loguru.
✅ Valida env vars críticas y avisa con claridad.
✅ Expone `app` para Gunicorn: gunicorn run:app
✅ Compatible con Render (PORT dinámico).
✅ Evita errores silenciosos y mejora trazabilidad.
"""

from __future__ import annotations

import os
import sys
from typing import Iterable, List, Tuple

from dotenv import load_dotenv
from loguru import logger


# =============================================================================
# Helpers
# =============================================================================

def _is_truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _env(key: str, default: str | None = None) -> str | None:
    val = os.getenv(key)
    if val is None:
        return default
    return val


def _load_dotenv_if_local() -> str:
    """
    Carga .env SOLO cuando estamos en entorno local.
    Render/producción ya inyecta env vars por panel.
    """
    base_dir = os.path.abspath(os.path.dirname(__file__))
    dotenv_path = os.path.join(base_dir, ".env")

    # Heurística: si existe .env y NO estamos en Render, lo cargamos.
    # Render suele setear RENDER=true (no siempre), pero esta es buena práctica.
    is_render = _is_truthy(os.getenv("RENDER")) or bool(os.getenv("RENDER_SERVICE_ID"))
    if os.path.exists(dotenv_path) and not is_render:
        load_dotenv(dotenv_path)
        return f".env cargado (local): {dotenv_path}"

    if os.path.exists(dotenv_path) and is_render:
        return "Detectado entorno Render: .env presente pero NO se carga (seguridad)."

    return "No se encontró .env (o no se carga). Usando variables del sistema/Render."


def _setup_logger(debug: bool) -> None:
    logger.remove()
    logger.add(
        sys.stderr,
        level="DEBUG" if debug else "INFO",
        backtrace=True,
        diagnose=debug,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level>"
        ),
    )


def _check_env(required: Iterable[str], optional: Iterable[str]) -> None:
    missing_required = [k for k in required if not os.getenv(k)]
    if missing_required:
        for k in missing_required:
            logger.warning(
                "Falta variable obligatoria: '{}' — Configúrala en Render (Environment) o en .env local.",
                k,
            )

    for k in optional:
        if not os.getenv(k):
            logger.debug("Variable opcional no definida: '{}'", k)


# =============================================================================
# 1) Cargar .env (solo local)
# =============================================================================

dotenv_msg = _load_dotenv_if_local()


# =============================================================================
# 2) Configuración de entorno
# =============================================================================

# Mejor práctica: FLASK_ENV ya está deprecado en Flask moderno, pero lo soportamos igual.
ENV = (_env("FLASK_ENV", "production") or "production").lower()
DEBUG = ENV == "development" or _is_truthy(os.getenv("DEBUG"))

# Render asigna PORT automáticamente. No hardcodees 10000 en producción.
HOST = _env("HOST", "0.0.0.0") or "0.0.0.0"
PORT = int(_env("PORT", "5000") or "5000")

_setup_logger(DEBUG)

logger.info("Iniciando Skyline Store · run.py")
logger.info("ENV: {} | DEBUG: {} | HOST: {} | PORT: {}", ENV, DEBUG, HOST, PORT)
logger.info(dotenv_msg)


# =============================================================================
# 3) Validación de env vars
# =============================================================================

# Claves críticas
REQUIRED_ENV_VARS: List[str] = [
    "SECRET_KEY",
]

# Printful: tu app usa PRINTFUL_API_KEY (según tu main_routes.py)
OPTIONAL_ENV_VARS: List[str] = [
    "PRINTFUL_API_KEY",
    "PRINTFUL_STORE_ID",
    "PRINTFUL_CACHE_TTL",
    "DATABASE_URL",
    "MP_ACCESS_TOKEN",
    "MP_PUBLIC_KEY",
]

_check_env(REQUIRED_ENV_VARS, OPTIONAL_ENV_VARS)

# Aviso si hay mezcla rara
if DEBUG and ENV == "production":
    logger.warning("DEBUG está activo con FLASK_ENV=production. Recomendado apagar DEBUG en producción.")


# =============================================================================
# 4) Crear Flask app (factory)
# =============================================================================

try:
    from app import create_app
except Exception as import_error:  # noqa: BLE001
    logger.exception(
        "No se pudo importar create_app desde app/__init__.py. "
        "Verificá que exista create_app() y que no haya imports circulares."
    )
    raise import_error

try:
    app = create_app()
    logger.info("✅ App creada correctamente (create_app()).")
except Exception as app_error:  # noqa: BLE001
    logger.exception("❌ Error creando la app con create_app().")
    raise app_error


# =============================================================================
# 5) Debug local (python run.py)
# =============================================================================

if __name__ == "__main__":
    logger.info("Servidor local: http://{}:{}/", HOST, PORT)
    try:
        app.run(host=HOST, port=PORT, debug=DEBUG)
    except Exception as run_error:  # noqa: BLE001
        logger.exception("Error ejecutando servidor local.")
        raise run_error
