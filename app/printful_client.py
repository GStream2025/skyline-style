# app/printful_client.py
import time
import logging
import requests
from .printful_config import PRINTFUL_API_KEY, PRINTFUL_BASE_URL


# -------------------------------------------
# Logger opcional (se integra con tu servidor)
# -------------------------------------------
logger = logging.getLogger(__name__)

# Sesión global para reusar conexiones (más rápido)
_session = requests.Session()

# Cache simple en memoria (evita repetir llamadas innecesarias)
_cache = {}
CACHE_TTL = 300  # 5 minutos


def _cache_get(key: str):
    item = _cache.get(key)
    if not item:
        return None

    value, ts = item
    if time.time() - ts > CACHE_TTL:
        return None
    return value


def _cache_set(key: str, value):
    _cache[key] = (value, time.time())


# ===================================================
#                   CLASE PRINCIPAL
# ===================================================

class PrintfulClient:
    def __init__(self, api_key: str = PRINTFUL_API_KEY, base_url: str = PRINTFUL_BASE_URL):
        if not api_key:
            raise RuntimeError("PRINTFUL_API_KEY no está definido en el entorno.")

        self.api_key = api_key
        self.base_url = base_url.rstrip("/")

        print(f"[PrintfulClient] API Key cargada correctamente (longitud: {len(api_key)})")

    # ---------------------------
    # Headers para cada request
    # ---------------------------
    def _headers(self):
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    # ---------------------------
    # Método interno GET seguro
    # con manejo de rate limit
    # ---------------------------
    def _get(self, endpoint: str, params: dict | None = None, retries: int = 4):
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        params = params or {}

        for attempt in range(retries):
            resp = _session.get(url, headers=self._headers(), params=params)

            # Log del request
            print(f"[Printful GET] {url} -> {resp.status_code}")

            # Si la respuesta es ok, devolver JSON parseado
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except ValueError:
                    resp.raise_for_status()
                    return None

                return data.get("result", data)

            # ---------------------------
            # Manejo de rate limit (429)
            # ---------------------------
            if resp.status_code == 429:
                retry_after = resp.headers.get("Retry-After")

                if retry_after:
                    wait = int(retry_after)
                else:
                    wait = 2 ** attempt  # backoff progresivo

                logger.warning(f"⚠️ Rate limit 429 recibido. Esperando {wait}s…")
                time.sleep(wait)
                continue

            # ---------------------------
            # Errores 5xx (Printful caído)
            # ---------------------------
            if 500 <= resp.status_code < 600:
                wait = 1 + attempt
                logger.warning(f"⚠️ Error {resp.status_code} en Printful. Reintentando en {wait}s…")
                time.sleep(wait)
                continue

            # ---------------------------
            # Otros errores → lanzar excepción
            # ---------------------------
            try:
                error_json = resp.json()
                message = error_json.get("error", {}).get("message", error_json)
            except Exception:
                message = resp.text

            raise RuntimeError(f"Error Printful ({resp.status_code}): {message}")

        raise RuntimeError("Demasiados errores consecutivos llamando a Printful API")

    # ===================================================
    #            MÉTODOS PÚBLICOS (GETTERS)
    # ===================================================

    def get_synced_products(self, limit: int = 50, offset: int = 0, use_cache: bool = True):
        cache_key = f"products_{limit}_{offset}"

        if use_cache:
            cached = _cache_get(cache_key)
            if cached:
                return cached

        data = self._get("store/products", params={"limit": limit, "offset": offset})

        if use_cache:
            _cache_set(cache_key, data)

        return data

    def get_synced_product(self, product_id: int | str, use_cache: bool = True):
        cache_key = f"product_{product_id}"

        if use_cache:
            cached = _cache_get(cache_key)
            if cached:
                return cached

        data = self._get(f"store/products/{product_id}")

        if use_cache:
            _cache_set(cache_key, data)

        return data

    def get_synced_variant(self, variant_id: int | str, use_cache: bool = True):
        cache_key = f"variant_{variant_id}"

        if use_cache:
            cached = _cache_get(cache_key)
            if cached:
                return cached

        data = self._get(f"store/variants/{variant_id}")

        if use_cache:
            _cache_set(cache_key, data)

        return data
