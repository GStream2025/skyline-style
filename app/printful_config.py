# app/printful_config.py
import os

PRINTFUL_API_KEY = os.getenv("PRINTFUL_API_KEY")
PRINTFUL_BASE_URL = "https://api.printful.com"

if not PRINTFUL_API_KEY:
    raise RuntimeError(
        "PRINTFUL_API_KEY no está definido en las variables de entorno."
    )
