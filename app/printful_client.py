# app/printful_client.py

import requests
from .printful_config import PRINTFUL_API_KEY, PRINTFUL_BASE_URL


class PrintfulClient:
    def __init__(self, api_key: str = PRINTFUL_API_KEY, base_url: str = PRINTFUL_BASE_URL):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")  # por si acaso

        # Debug opcional: ver que realmente lee la API key
        print(f"[PrintfulClient] API key cargada, longitud: {len(self.api_key)}")

        # IMPORTANTE:
        # Ya no validamos manualmente el token.
        # Si es incorrecto, Printful devolverá un error 401/403 en _get().

    def _headers(self):
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _get(self, endpoint: str, params: dict | None = None):
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        response = requests.get(url, headers=self._headers(), params=params or {})

        print(f"[Printful GET] {url} -> {response.status_code}")

        try:
            data = response.json()
        except ValueError:
            response.raise_for_status()
            raise

        if not response.ok:
            error_msg = data.get("error", {}).get("message") if isinstance(data, dict) else None
            raise RuntimeError(
                f"Error al llamar a Printful ({response.status_code}): {error_msg or data}"
            )

        if isinstance(data, dict) and "result" in data:
            return data["result"]

        return data

    def get_synced_products(self, limit: int = 50, offset: int = 0):
        params = {"limit": limit, "offset": offset}
        return self._get("store/products", params=params)

    def get_synced_product(self, product_id: int | str):
        return self._get(f"store/products/{product_id}")

    def get_synced_variant(self, variant_id: int | str):
        return self._get(f"store/variants/{variant_id}")
