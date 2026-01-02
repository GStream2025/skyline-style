from __future__ import annotations

import os
import time
import json
import random
import logging
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Any, Dict, Optional, Mapping, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .printful_config import PRINTFUL_BASE_URL

logger = logging.getLogger(__name__)


# =============================================================================
# Errors
# =============================================================================

class PrintfulError(RuntimeError):
    """Base error."""


class PrintfulAuthError(PrintfulError):
    """401/403"""


class PrintfulNotFoundError(PrintfulError):
    """404"""


class PrintfulRateLimitError(PrintfulError):
    """429"""


class PrintfulServerError(PrintfulError):
    """5xx"""


# =============================================================================
# ENV helpers
# =============================================================================

_TRUE = {"1", "true", "yes", "y", "on"}

def _env(key: str, default: str = "") -> str:
    return (os.getenv(key) or default).strip()

def _env_int(key: str, default: int) -> int:
    v = os.getenv(key)
    if v is None:
        return default
    try:
        return int(str(v).strip())
    except Exception:
        return default

def _env_bool(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    return str(v).strip().lower() in _TRUE


# =============================================================================
# Retry / Backoff helpers
# =============================================================================

def _backoff(attempt: int, base: float = 0.8, cap: float = 20.0, jitter: float = 0.25) -> float:
    """
    Exponential backoff con jitter.
    attempt=0 -> ~base
    """
    t = min(cap, base * (2 ** attempt))
    # jitter +- jitter%
    j = 1.0 + random.uniform(-jitter, jitter)
    return max(0.0, t * j)

def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    """
    Retry-After puede ser:
    - segundos ("5")
    - fecha HTTP ("Wed, 21 Oct 2015 07:28:00 GMT")
    """
    if not value:
        return None
    v = value.strip()
    if not v:
        return None
    if v.isdigit():
        return float(v)
    try:
        dt = parsedate_to_datetime(v)
        # segundos hasta esa fecha
        return max(0.0, dt.timestamp() - time.time())
    except Exception:
        return None


# =============================================================================
# Small in-memory TTL cache (bounded)
# =============================================================================

@dataclass
class _CacheItem:
    ts: float
    val: Any

class _TTLCache:
    def __init__(self, ttl: int = 300, max_items: int = 128):
        self.ttl = max(5, int(ttl))
        self.max_items = max(16, int(max_items))
        self._data: Dict[str, _CacheItem] = {}

    def _evict_if_needed(self) -> None:
        if len(self._data) <= self.max_items:
            return
        # Evict oldest first (simple + safe)
        items = sorted(self._data.items(), key=lambda kv: kv[1].ts)
        for k, _ in items[: max(1, len(items) - self.max_items)]:
            self._data.pop(k, None)

    def get(self, key: str) -> Any:
        it = self._data.get(key)
        if not it:
            return None
        if (time.time() - it.ts) > self.ttl:
            self._data.pop(key, None)
            return None
        return it.val

    def set(self, key: str, val: Any) -> None:
        self._data[key] = _CacheItem(ts=time.time(), val=val)
        self._evict_if_needed()

    def clear(self) -> None:
        self._data.clear()


# =============================================================================
# Session factory (requests + urllib3 retry)
# =============================================================================

def _make_session() -> requests.Session:
    s = requests.Session()

    # Retry de nivel transporte (DNS/reset/5xx) — NO maneja 429 bien, eso lo hacemos nosotros
    retry = Retry(
        total=0,  # lo manejamos en _request para tener control fino
        connect=0,
        read=0,
        status=0,
        backoff_factor=0,
        allowed_methods={"GET"},
        raise_on_status=False,
        respect_retry_after_header=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


_SESSION = _make_session()


# =============================================================================
# Client
# =============================================================================

class PrintfulClient:
    """
    Cliente Printful PRO (GET) con:
    - retries con backoff + jitter
    - rate limit handling (429 + Retry-After)
    - errores tipados
    - cache TTL en memoria (bounded)
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = PRINTFUL_BASE_URL,
        *,
        timeout_connect: float = 6.05,
        timeout_read: float = 20.0,
        retries: int = 4,
        cache_ttl: Optional[int] = None,
        cache_max_items: Optional[int] = None,
    ):
        self.api_key = (api_key or _env("PRINTFUL_API_KEY")).strip()
        if not self.api_key:
            raise PrintfulError("PRINTFUL_API_KEY no está definido (Render Environment o .env local).")

        self.base_url = (base_url or PRINTFUL_BASE_URL).rstrip("/")
        self.timeout: Tuple[float, float] = (
            float(_env("PRINTFUL_TIMEOUT_CONNECT", str(timeout_connect)) or timeout_connect),
            float(_env("PRINTFUL_TIMEOUT_READ", str(timeout_read)) or timeout_read),
        )

        self.retries = max(1, _env_int("PRINTFUL_RETRIES", retries))

        ttl = cache_ttl if cache_ttl is not None else _env_int("PRINTFUL_CACHE_TTL", 300)
        max_items = cache_max_items if cache_max_items is not None else _env_int("PRINTFUL_CACHE_MAX", 128)
        self.cache = _TTLCache(ttl=ttl, max_items=max_items)

        self.user_agent = _env("PRINTFUL_USER_AGENT", "SkylineStore/1.0 (+https://skylinestore)")
        self.debug = _env_bool("PRINTFUL_DEBUG", False)

    # -------------------------
    # Internals
    # -------------------------

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": self.user_agent,
        }

    def _cache_key(self, endpoint: str, params: Optional[Mapping[str, Any]]) -> str:
        ep = "/" + endpoint.lstrip("/")
        if not params:
            return ep
        # key determinística
        try:
            items = sorted((str(k), str(v)) for k, v in dict(params).items())
        except Exception:
            items = [(str(k), str(v)) for k, v in (params or {}).items()]
        return ep + "?" + "&".join([f"{k}={v}" for k, v in items])

    def _extract_error_message(self, resp: requests.Response) -> str:
        # Printful suele responder {"error":{"message":...}} o {"message":...}
        try:
            data = resp.json()
            if isinstance(data, dict):
                err = data.get("error") or {}
                if isinstance(err, dict) and err.get("message"):
                    return str(err.get("message"))
                if data.get("message"):
                    return str(data.get("message"))
                return json.dumps(data)[:500]
        except Exception:
            pass
        try:
            return (resp.text or "").strip()[:500] or f"HTTP {resp.status_code}"
        except Exception:
            return f"HTTP {resp.status_code}"

    def _request_get(self, endpoint: str, params: Optional[Mapping[str, Any]] = None) -> Any:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        params_dict = dict(params or {})

        last_err: Optional[Exception] = None

        for attempt in range(self.retries):
            try:
                resp = _SESSION.get(
                    url,
                    headers=self._headers(),
                    params=params_dict,
                    timeout=self.timeout,
                )
            except requests.RequestException as e:
                last_err = e
                wait = _backoff(attempt)
                logger.warning("Printful GET error (%s) endpoint=%s attempt=%d wait=%.1fs", e, endpoint, attempt + 1, wait)
                time.sleep(wait)
                continue

            code = resp.status_code

            if code == 200:
                try:
                    return resp.json()
                except Exception:
                    raise PrintfulError("Respuesta inválida (no JSON) desde Printful.")

            # Auth errors
            if code in (401, 403):
                raise PrintfulAuthError(f"Printful auth error ({code}): {self._extract_error_message(resp)}")

            # Not found
            if code == 404:
                raise PrintfulNotFoundError(f"Printful not found (404): {endpoint}")

            # Rate limit
            if code == 429:
                ra = _parse_retry_after(resp.headers.get("Retry-After"))
                wait = ra if ra is not None else _backoff(attempt, base=1.2)
                msg = self._extract_error_message(resp)
                logger.warning("Printful 429 rate limit endpoint=%s attempt=%d wait=%.1fs msg=%s", endpoint, attempt + 1, wait, msg)
                time.sleep(wait)
                last_err = PrintfulRateLimitError(msg)
                continue

            # Server errors
            if 500 <= code < 600:
                wait = _backoff(attempt)
                msg = self._extract_error_message(resp)
                logger.warning("Printful %d endpoint=%s attempt=%d wait=%.1fs msg=%s", code, endpoint, attempt + 1, wait, msg)
                time.sleep(wait)
                last_err = PrintfulServerError(msg)
                continue

            # Other errors (400, etc.)
            msg = self._extract_error_message(resp)
            raise PrintfulError(f"Error Printful ({code}): {msg}")

        # exhausted
        if last_err:
            raise PrintfulError(f"Demasiados errores consecutivos llamando Printful: {last_err}")
        raise PrintfulError("Demasiados errores consecutivos llamando Printful.")

    def _get(self, endpoint: str, params: Optional[Mapping[str, Any]] = None, *, use_cache: bool = True) -> Any:
        key = self._cache_key(endpoint, params)
        if use_cache:
            cached = self.cache.get(key)
            if cached is not None:
                return cached

        data = self._request_get(endpoint, params=params)

        if use_cache:
            self.cache.set(key, data)
        return data

    # -------------------------
    # Public API
    # -------------------------

    def get_synced_products(self, limit: int = 50, offset: int = 0, use_cache: bool = True) -> Any:
        limit = max(1, min(int(limit), 200))
        offset = max(0, int(offset))
        return self._get("store/products", params={"limit": limit, "offset": offset}, use_cache=use_cache)

    def get_synced_product(self, product_id: int | str, use_cache: bool = True) -> Any:
        pid = str(product_id).strip()
        if not pid:
            raise ValueError("product_id inválido")
        return self._get(f"store/products/{pid}", use_cache=use_cache)

    def get_synced_variant(self, variant_id: int | str, use_cache: bool = True) -> Any:
        vid = str(variant_id).strip()
        if not vid:
            raise ValueError("variant_id inválido")
        return self._get(f"store/variants/{vid}", use_cache=use_cache)

    # Extras útiles
    def clear_cache(self) -> None:
        self.cache.clear()
