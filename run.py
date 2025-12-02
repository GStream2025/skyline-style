"""
run.py – Punto de entrada principal de la aplicación Skyline Style.

✔ Carga variables de entorno desde .env (solo en local).
✔ Crea la app usando el factory app.create_app().
✔ Expone la variable `app` para producción (gunicorn run:app).
✔ Registra logs profesionales con loguru.
✔ Valida variables de entorno importantes y muestra advertencias útiles.
"""

from __future__ import annotations

import os
import sys
from typing import List

from dotenv import load_dotenv
from loguru import logger

# ---------------------------------------------------------------------------
# 1) Cargar variables de entorno (.env solo en desarrollo)
# ---------------------------------------------------------------------------

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DOTENV_PATH = os.path.join(BASE_DIR, ".env")

# Si existe un .env lo carga (útil para desarrollo local)
if os.path.exists(DOTENV_PATH):
    load_dotenv(DOTENV_PATH)
    dotenv_msg = f".env cargado desde: {DOTENV_PATH}"
else:
    dotenv_msg = "No se encontró .env, usando solo variables de entorno del sistema."

# ---------------------------------------------------------------------------
# 2) Configuración básica de entorno
# ---------------------------------------------------------------------------

ENV = os.getenv("FLASK_ENV", "production").lower()  # "development" o "production"
DEBUG = ENV == "development"

# En Render / producción SIEMPRE conviene 0.0.0.0
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "5000"))

# Variables que son importantes para la app
REQUIRED_ENV_VARS: List[str] = [
    "SECRET_KEY",        # seguridad de sesiones / cookies
]

OPTIONAL_ENV_VARS: List[str] = [
    "PRINTFUL_KEY",
    "DATABASE_URL",
    "PRINTFUL_STORE_ID",
]

# ---------------------------------------------------------------------------
# 3) Configurar logger profesional (loguru)
# ---------------------------------------------------------------------------

logger.remove()
logger.add(
    sys.stderr,
    level="DEBUG" if DEBUG else "INFO",
    backtrace=True,
    diagnose=DEBUG,
    format=(
        "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
        "<level>{message}</level>"
    ),
)

logger.info("Iniciando run.py de Skyline Style")
logger.info(dotenv_msg)
logger.info("Entorno FLASK_ENV: {} | DEBUG: {}", ENV, DEBUG)

# Comprobación básica de variables obligatorias
for var in REQUIRED_ENV_VARS:
    if not os.getenv(var):
        logger.warning(
            "Variable de entorno obligatoria '{}' NO está definida. "
            "Configúrala en Render o en tu archivo .env.",
            var,
        )

for var in OPTIONAL_ENV_VARS:
    if not os.getenv(var):
        logger.debug("Variable de entorno opcional '{}' no está definida.", var)

if DEBUG and ENV == "production":
    logger.warning(
        "DEBUG está activo pero FLASK_ENV=production. "
        "Desactiva DEBUG en producción por seguridad."
    )

# ---------------------------------------------------------------------------
# 4) Crear la aplicación Flask usando el factory de app/__init__.py
# ---------------------------------------------------------------------------

try:
    from app import create_app
except Exception as import_error:
    logger.exception(
        "Error importando create_app desde app/__init__.py. "
        "Verifica que exista la función create_app()."
    )
    raise import_error

try:
    app = create_app()
    logger.info("Aplicación Skyline Style creada correctamente.")
except Exception as app_error:
    logger.exception("Error al crear la aplicación Flask con create_app().")
    raise app_error

# ---------------------------------------------------------------------------
# 5) Servidor de desarrollo local
#    (python run.py) → útil para pruebas en tu PC
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logger.info("Iniciando servidor de desarrollo en http://{}:{}/", HOST, PORT)
    try:
        app.run(
            host=HOST,
            port=PORT,
            debug=DEBUG,
        )
    except Exception as run_error:
        logger.exception("Error al ejecutar el servidor de desarrollo.")
        raise run_error
