"""
run.py — Skyline Store (ENTRYPOINT FINAL)

✔ Compatible con Render / Gunicorn
✔ Carga .env SOLO en local
✔ Logging profesional (Loguru opcional)
✔ Valida variables críticas
✔ Expone `app` correctamente (gunicorn run:app)
✔ No interfiere con static/templates (eso lo maneja create_app)
"""

from __future__ import annotations

import os
import sys
import platform
import logging
from typing import Iterable, List

# =============================================================================
# Logging (Loguru opcional + fallback estándar)
# =============================================================================
class _StdLogger:
    """Wrapper estilo Loguru si no está instalado."""

    def __init__(self, name: str = "skyline"):
        self._log = logging.getLogger(name)

    def debug(self, msg, *a): self._log.debug(str(msg).format(*a))
    def info(self, msg, *a): self._log.info(str(msg).format(*a))
    def warning(self, msg, *a): self._log.warning(str(msg).format(*a))
    def error(self, msg, *a): self._log.error(str(msg).format(*a))
    def exception(self, msg, *a): self._log.exception(str(msg).format(*a))
    def success(self, msg, *a): self._log.info("✅ " + str(msg).format(*a))


try:
    from loguru import logger as _loguru_logger  # type: ignore
    _HAS_LOGURU = True
except ModuleNotFoundError:
    _HAS_LOGURU = False
    _loguru_logger = None  # type: ignore

logger = _loguru_logger if _HAS_LOGURU else _StdLogger()


def _setup_logger(debug: bool) -> None:
    if _HAS_LOGURU:
        logger.remove()  # type: ignore[attr-defined]
        logger.add(  # type: ignore[attr-defined]
            sys.stderr,
            level="DEBUG" if debug else "INFO",
            enqueue=True,
            backtrace=debug,
            diagnose=debug,
            format=(
                "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
                "<level>{level: <8}</level> | "
                "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
                "<level>{message}</level>"
            ),
        )
    else:
        level = logging.DEBUG if debug else logging.INFO
        logging.basicConfig(
            level=level,
            stream=sys.stderr,
            format="%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d - %(message)s",
        )


# =============================================================================
# Helpers
# =============================================================================
def _truthy(val: str | None) -> bool:
    return (val or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _env(key: str, default: str | None = None) -> str | None:
    return os.getenv(key, default)


def _running_on_render() -> bool:
    return bool(os.getenv("RENDER")) or bool(os.getenv("RENDER_SERVICE_ID"))


def _load_dotenv_if_local() -> str:
    """Carga .env SOLO en local."""
    base_dir = os.path.abspath(os.path.dirname(__file__))
    dotenv_path = os.path.join(base_dir, ".env")

    if os.path.exists(dotenv_path) and not _running_on_render():
        try:
            from dotenv import load_dotenv
            load_dotenv(dotenv_path)
            return f".env cargado (LOCAL): {dotenv_path}"
        except ModuleNotFoundError:
            return "⚠️ python-dotenv no instalado. .env NO cargado."
        except Exception as e:
            return f"⚠️ Error cargando .env: {e}"

    if os.path.exists(dotenv_path) and _running_on_render():
        return "Render detectado: .env existe pero NO se carga (seguridad)."

    return "No se encontró .env. Usando variables del sistema / Render."


def _check_env(required: Iterable[str], optional: Iterable[str]) -> None:
    missing = [k for k in required if not (os.getenv(k) or "").strip()]
    for k in missing:
        logger.warning(
            "Falta variable OBLIGATORIA: '{}' — configúrala en Render (Environment) o en .env local.",
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
DEBUG = ENV == "development" or _truthy(os.getenv("DEBUG"))

HOST = _env("HOST", "0.0.0.0") or "0.0.0.0"
PORT = int(_env("PORT", "10000") or "10000")  # Render usa PORT dinámico

_setup_logger(DEBUG)

logger.info("🚀 Iniciando Skyline Store")
logger.info("ENV={} DEBUG={} HOST={} PORT={}", ENV, DEBUG, HOST, PORT)
logger.info("Python={} | Platform={}", sys.version.split()[0], platform.platform())
logger.info(dotenv_msg)

if DEBUG and ENV == "production":
    logger.warning("⚠️ DEBUG activo en producción. Recomendado desactivarlo.")

# =============================================================================
# 3) Validación de variables
# =============================================================================
REQUIRED_ENV_VARS: List[str] = [
    "SECRET_KEY",
]

OPTIONAL_ENV_VARS: List[str] = [
    "DATABASE_URL",
    "PRINTFUL_API_KEY",
    "PRINTFUL_STORE_ID",
    "PRINTFUL_CACHE_TTL",
    "MP_ACCESS_TOKEN",
    "MP_PUBLIC_KEY",
    "FORCE_HTTPS",
]

_check_env(REQUIRED_ENV_VARS, OPTIONAL_ENV_VARS)

# =============================================================================
# 4) Crear Flask App (Factory)
# =============================================================================
try:
    from app import create_app
except Exception:
    logger.exception(
        "❌ No se pudo importar create_app.\n"
        "Revisá:\n"
        " - app/__init__.py existe\n"
        " - imports circulares\n"
        " - dependencias faltantes"
    )
    raise

try:
    app = create_app()
    logger.success("App creada correctamente con create_app()")
except Exception:
    logger.exception("❌ Error creando la app.")
    raise


# =============================================================================
# 5) Local DEV
# =============================================================================
if __name__ == "__main__":
    logger.info("🧪 Servidor local → http://{}:{}/", HOST, PORT)
    app.run(host=HOST, port=PORT, debug=DEBUG)
