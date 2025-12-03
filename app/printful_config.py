# app/printful_config.py
# Carga segura de configuración para Printful
# NO guardar claves directamente en este archivo

import os

PRINTFUL_API_KEY = os.getenv("PRINTFUL_API_KEY")
PRINTFUL_BASE_URL = "https://api.printful.com"
