"""
run.py — Entry point de Skyline Store (Producción + Desarrollo)

✅ Carga .env SOLO en local (no en producción).
✅ Logging profesional con loguru (stdout/stderr friendly).
✅ Valida env vars críticas y avisa con claridad.
✅ Expone `app` para Gunicorn: gunicorn run:app
✅ Compatible con Render (PORT dinámico).
✅ Errores claros si falla create_app().
"""

from __future__ import annotations

import os
import sys
import platform
from typing import Iterable, List

from loguru import logger


# =============================================================================
# Helpers
# =============================================================================
def _is_truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _env(key: str, default: str | None = None) -> str | None:
    val = os.getenv(key)
    return default if val is None else val


def _running_on_render() -> bool:
    # Render suele setear estas env vars
    return bool(os.getenv("RENDER")) or bool(os.getenv("RENDER_SERVICE_ID"))


def _load_dotenv_if_local() -> str:
    """
    Carga .env SOLO en local.
    En Render NO se debe cargar .env por seguridad.
    Además: si python-dotenv no está instalado, NO rompe.
    """
    base_dir = os.path.abspath(os.path.dirname(__file__))
    dotenv_path = os.path.join(base_dir, ".env")

    if os.path.exists(dotenv_path) and not _running_on_render():
        try:
            from dotenv import load_dotenv  # import opcional
            load_dotenv(dotenv_path)
            return f".env cargado (LOCAL): {dotenv_path}"
        except ModuleNotFoundError:
            return (
                "No se cargó .env porque falta la dependencia 'python-dotenv'. "
                "Instalala en local con: pip install python-dotenv"
            )
        except Exception as e:  # noqa: BLE001
            return f"No se pudo cargar .env por error: {e}"

    if os.path.exists(dotenv_path) and _running_on_render():
        return "Render detectado: .env existe pero NO se carga (seguridad)."

    return "No se encontró .env (o no se carga). Usando env vars del sistema/Render."


def _setup_logger(debug: bool) -> None:
    """
    Render muestra mejor logs por stdout/stderr.
    """
    logger.remove()
    logger.add(
        sys.stderr,
        level="DEBUG" if debug else "INFO",
        backtrace=True,
        diagnose=debug,
        enqueue=True,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level>"
        ),
    )


def _check_env(required: Iterable[str], optional: Iterable[str]) -> None:
    missing_required = [k for k in required if not (os.getenv(k) or "").strip()]
    if missing_required:
        for k in missing_required:
            logger.warning(
                "Falta variable OBLIGATORIA: '{}' — setéala en Render (Environment) o en tu .env local.",
                k,
            )

    for k in optional:
        if not (os.getenv(k) or "").strip():
            logger.debug("Variable opcional no definida: '{}'", k)


# =============================================================================
# 1) Cargar .env (solo local)
# =============================================================================
dotenv_msg = _load_dotenv_if_local()


# =============================================================================
# 2) Entorno
# =============================================================================
ENV = (_env("FLASK_ENV", "production") or "production").lower()
DEBUG = ENV == "development" or _is_truthy(os.getenv("DEBUG"))

HOST = _env("HOST", "0.0.0.0") or "0.0.0.0"
PORT = int(_env("PORT", "5000") or "5000")

_setup_logger(DEBUG)

logger.info("🚀 Iniciando Skyline Store")
logger.info("ENV={} DEBUG={} HOST={} PORT={}", ENV, DEBUG, HOST, PORT)
logger.info("Python={} | Platform={}", sys.version.split()[0], platform.platform())
logger.info(dotenv_msg)


# =============================================================================
# 3) Validación de env vars
# =============================================================================
REQUIRED_ENV_VARS: List[str] = [
    "SECRET_KEY",
]

# Aceptamos ambos nombres para no romper: PRINTFUL_KEY o PRINTFUL_API_KEY
OPTIONAL_ENV_VARS: List[str] = [
    "PRINTFUL_KEY",
    "PRINTFUL_API_KEY",
    "PRINTFUL_STORE_ID",
    "PRINTFUL_CACHE_TTL",
    "DATABASE_URL",
    "MP_ACCESS_TOKEN",
    "MP_PUBLIC_KEY",
]

_check_env(REQUIRED_ENV_VARS, OPTIONAL_ENV_VARS)

if DEBUG and ENV == "production":
    logger.warning("⚠️ DEBUG activo con FLASK_ENV=production. Recomendado apagar DEBUG en producción.")


# =============================================================================
# 4) Crear Flask app (factory)
# =============================================================================
try:
    from app import create_app
except Exception:  # noqa: BLE001
    logger.exception(
        "❌ No se pudo importar create_app desde app/__init__.py.\n"
        "Causas típicas:\n"
        " - Falta una dependencia en requirements.txt\n"
        " - Imports circulares\n"
        " - Nombre de paquete/carpeta incorrecto\n"
    )
    raise

try:
    app = create_app()
    logger.success("✅ App creada correctamente (create_app).")
except Exception:  # noqa: BLE001
    logger.exception("❌ Error creando la app con create_app().")
    raise


# =============================================================================
# 5) Dev local (python run.py)
# =============================================================================
if __name__ == "__main__":
    logger.info("🧪 Servidor local: http://{}:{}/", HOST, PORT)
    app.run(host=HOST, port=PORT, debug=DEBUG)
