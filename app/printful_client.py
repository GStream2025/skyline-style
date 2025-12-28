from __future__ import annotations

import os
import time
import logging
from typing import Any, Dict, Optional, Mapping

import requests

from .printful_config import PRINTFUL_BASE_URL

logger = logging.getLogger(__name__)

_SESSION = requests.Session()

class PrintfulError(RuntimeError):
    pass

def _env(key: str, default: str = "") -> str:
    return (os.getenv(key) or default).strip()

def _backoff(attempt: int, base: float = 1.0, cap: float = 20.0) -> float:
    return min(cap, base * (2 ** attempt))

class PrintfulClient:
    """Cliente Printful robusto (GET) con retries + rate limit."""

    def __init__(self, api_key: Optional[str] = None, base_url: str = PRINTFUL_BASE_URL):
        self.api_key = (api_key or _env("PRINTFUL_API_KEY")).strip()
        if not self.api_key:
            raise PrintfulError("PRINTFUL_API_KEY no está definido (Render Environment o .env local).")

        self.base_url = (base_url or PRINTFUL_BASE_URL).rstrip("/")

        # Cache TTL configurable (en memoria por instancia)
        try:
            self.cache_ttl = int(_env("PRINTFUL_CACHE_TTL", "300"))
        except ValueError:
            self.cache_ttl = 300
        self._cache: Dict[str, tuple[float, Any]] = {}

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "SkylineStore/1.0",
        }

    def _cache_get(self, key: str) -> Any:
        item = self._cache.get(key)
        if not item:
            return None
        ts, val = item
        if time.time() - ts > self.cache_ttl:
            self._cache.pop(key, None)
            return None
        return val

    def _cache_set(self, key: str, value: Any) -> None:
        self._cache[key] = (time.time(), value)

    def _get(self, endpoint: str, params: Optional[Mapping[str, Any]] = None, retries: int = 4) -> Any:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        params = dict(params or {})

        for attempt in range(retries):
            try:
                resp = _SESSION.get(url, headers=self._headers(), params=params, timeout=20)
            except requests.RequestException as e:
                wait = _backoff(attempt)
                logger.warning("Printful request error (%s). Retry en %.1fs", e, wait)
                time.sleep(wait)
                continue

            if resp.status_code == 200:
                try:
                    data = resp.json()
                except ValueError:
                    raise PrintfulError("Respuesta inválida (no JSON) desde Printful.")
                return data

            # Rate limit
            if resp.status_code == 429:
                retry_after = resp.headers.get("Retry-After")
                wait = float(retry_after) if retry_after and retry_after.isdigit() else _backoff(attempt, base=1.5)
                logger.warning("Printful 429 rate limit. Esperando %.1fs", wait)
                time.sleep(wait)
                continue

            # 5xx
            if 500 <= resp.status_code < 600:
                wait = _backoff(attempt)
                logger.warning("Printful %s. Retry en %.1fs", resp.status_code, wait)
                time.sleep(wait)
                continue

            # Otros errores
            try:
                payload = resp.json()
                msg = payload.get("error", {}).get("message") or payload.get("message") or str(payload)
            except Exception:
                msg = resp.text[:500]
            raise PrintfulError(f"Error Printful ({resp.status_code}): {msg}")

        raise PrintfulError("Demasiados errores consecutivos llamando a Printful API.")

    # -------------------------
    # Públicos
    # -------------------------
    def get_synced_products(self, limit: int = 50, offset: int = 0, use_cache: bool = True) -> Any:
        key = f"store/products?limit={limit}&offset={offset}"
        if use_cache:
            cached = self._cache_get(key)
            if cached is not None:
                return cached
        data = self._get("store/products", params={"limit": limit, "offset": offset})
        if use_cache:
            self._cache_set(key, data)
        return data

    def get_synced_product(self, product_id: int | str, use_cache: bool = True) -> Any:
        key = f"store/products/{product_id}"
        if use_cache:
            cached = self._cache_get(key)
            if cached is not None:
                return cached
        data = self._get(f"store/products/{product_id}")
        if use_cache:
            self._cache_set(key, data)
        return data

    def get_synced_variant(self, variant_id: int | str, use_cache: bool = True) -> Any:
        key = f"store/variants/{variant_id}"
        if use_cache:
            cached = self._cache_get(key)
            if cached is not None:
                return cached
        data = self._get(f"store/variants/{variant_id}")
        if use_cache:
            self._cache_set(key, data)
        return data
