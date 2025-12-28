"""
run.py — Skyline Store (ENTRYPOINT FINAL PRO)

✔ Compatible con Render / Gunicorn
✔ Expone `app` correctamente (gunicorn run:app)
✔ Carga .env SOLO en local
✔ Logging profesional (Loguru opcional)
✔ Valida variables críticas
✔ No interfiere con static/templates (lo maneja create_app)
"""

from __future__ import annotations

import os
import sys
import platform
import logging
from typing import Iterable, List, Optional


# =============================================================================
# Logging (Loguru opcional + fallback estándar)
# =============================================================================
class _StdLogger:
    """
    Logger simple con API parecida a Loguru.
    Nota: usa % formatting / f-strings (no {} tipo loguru).
    """

    def __init__(self, name: str = "skyline"):
        self._log = logging.getLogger(name)

    def debug(self, msg: str, *a): self._log.debug(msg % a if a else msg)
    def info(self, msg: str, *a): self._log.info(msg % a if a else msg)
    def warning(self, msg: str, *a): self._log.warning(msg % a if a else msg)
    def error(self, msg: str, *a): self._log.error(msg % a if a else msg)
    def exception(self, msg: str, *a): self._log.exception(msg % a if a else msg)
    def success(self, msg: str, *a): self._log.info("✅ " + (msg % a if a else msg))


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
def _truthy(val: Optional[str]) -> bool:
    return (val or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _env(key: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(key)
    return v if v is not None else default


def _running_on_render() -> bool:
    # Render suele setear PORT + RENDER_SERVICE_ID (o RENDER)
    return bool(os.getenv("RENDER")) or bool(os.getenv("RENDER_SERVICE_ID"))


def _load_dotenv_if_local() -> str:
    """
    Carga .env SOLO en local.
    - Si detecta Render => NO carga.
    - Si no detecta Render y existe .env => intenta cargar.
    """
    base_dir = os.path.abspath(os.path.dirname(__file__))
    dotenv_path = os.path.join(base_dir, ".env")

    if _running_on_render():
        if os.path.exists(dotenv_path):
            return "Render detectado: .env existe pero NO se carga (seguridad)."
        return "Render detectado: usando Environment Variables."

    # Local
    if os.path.exists(dotenv_path):
        try:
            from dotenv import load_dotenv
            load_dotenv(dotenv_path)
            return f".env cargado (LOCAL): {dotenv_path}"
        except ModuleNotFoundError:
            return "⚠️ python-dotenv no instalado. .env NO cargado."
        except Exception as e:
            return f"⚠️ Error cargando .env: {e}"

    return "No se encontró .env. Usando variables del sistema."


def _check_env(required: Iterable[str], optional: Iterable[str]) -> None:
    missing = [k for k in required if not (os.getenv(k) or "").strip()]
    for k in missing:
        if _HAS_LOGURU:
            logger.warning(
                "Falta variable OBLIGATORIA: '{}' — configúrala en Render (Environment) o en .env local.",
                k,
            )
        else:
            logger.warning("Falta variable OBLIGATORIA: '%s' — configúrala en Render (Environment) o en .env local.", k)

    for k in optional:
        if not (os.getenv(k) or "").strip():
            if _HAS_LOGURU:
                logger.debug("Variable opcional no definida: '{}'", k)
            else:
                logger.debug("Variable opcional no definida: '%s'", k)


# =============================================================================
# 1) Cargar .env (solo local)
# =============================================================================
dotenv_msg = _load_dotenv_if_local()

# =============================================================================
# 2) Entorno (NO pisar; solo leer)
# =============================================================================
ENV = (_env("FLASK_ENV") or _env("ENV") or "production").lower()
DEBUG = (ENV == "development") or _truthy(_env("DEBUG"))

HOST = _env("HOST", "0.0.0.0") or "0.0.0.0"
PORT = int(_env("PORT", "10000") or "10000")  # Render usa PORT dinámico

_setup_logger(DEBUG)

# Logs arranque
if _HAS_LOGURU:
    logger.info("🚀 Iniciando Skyline Store")
    logger.info("ENV={} DEBUG={} HOST={} PORT={}", ENV, DEBUG, HOST, PORT)
    logger.info("Python={} | Platform={}", sys.version.split()[0], platform.platform())
    logger.info(dotenv_msg)
else:
    logger.info("🚀 Iniciando Skyline Store")
    logger.info("ENV=%s DEBUG=%s HOST=%s PORT=%s", ENV, DEBUG, HOST, PORT)
    logger.info("Python=%s | Platform=%s", sys.version.split()[0], platform.platform())
    logger.info("%s", dotenv_msg)

if DEBUG and ENV == "production":
    if _HAS_LOGURU:
        logger.warning("⚠️ DEBUG activo en producción. Recomendado desactivarlo.")
    else:
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
# 4) Crear Flask App (Factory) y exponer `app` para Gunicorn
# =============================================================================
try:
    from app import create_app
except Exception:
    if _HAS_LOGURU:
        logger.exception(
            "❌ No se pudo importar create_app.\n"
            "Revisá:\n"
            " - app/__init__.py existe\n"
            " - imports circulares\n"
            " - dependencias faltantes"
        )
    else:
        logger.exception("❌ No se pudo importar create_app. Revisá app/__init__.py / imports / deps.")
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
    if _HAS_LOGURU:
        logger.info("🧪 Servidor local → http://{}:{}/", HOST, PORT)
    else:
        logger.info("🧪 Servidor local → http://%s:%s/", HOST, PORT)

    app.run(host=HOST, port=PORT, debug=DEBUG)
