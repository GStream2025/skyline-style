"""
run.py – Punto de entrada de la aplicación Skyline Style.

- Carga variables de entorno desde .env
- Crea la app con el factory create_app()
- Expone la variable `app` para gunicorn (Render: gunicorn run:app)
- Si se ejecuta directamente (python run.py) levanta servidor de desarrollo
"""

import os
import sys

from dotenv import load_dotenv
from loguru import logger

from app import create_app

# === 1) Cargar variables de entorno ===
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DOTENV_PATH = os.path.join(BASE_DIR, ".env")
load_dotenv(DOTENV_PATH)

# === 2) Configuración de entorno ===
ENV = os.getenv("FLASK_ENV", "production")  # "development" o "production"
DEBUG = ENV == "development"

# En Render conviene 0.0.0.0; local también funciona bien
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "5000"))

# === 3) Logger profesional con loguru ===
logger.remove()
logger.add(
    sys.stderr,
    level="DEBUG" if DEBUG else "INFO",
    backtrace=True,
    diagnose=DEBUG,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
           "<level>{level: <8}</level> | "
           "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
           "<level>{message}</level>",
)

# === 4) Crear la app usando el factory de app/__init__.py ===
app = create_app()
logger.info("Aplicación Skyline Style inicializada en entorno: {}", ENV)


# === 5) Modo desarrollo local ===
if __name__ == "__main__":
    logger.info("Iniciando servidor de desarrollo en http://{}:{}/", HOST, PORT)
    app.run(
        host=HOST,
        port=PORT,
        debug=DEBUG,
    )
