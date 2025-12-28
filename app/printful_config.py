import os

PRINTFUL_API_KEY = (os.getenv("PRINTFUL_API_KEY") or "").strip()
PRINTFUL_BASE_URL = (os.getenv("PRINTFUL_BASE_URL") or "https://api.printful.com").strip()

# No tiramos RuntimeError al importar.
# La validación se hace dentro de PrintfulClient.
