from __future__ import annotations

import os


# =============================================================================
# ENV helpers (locales y seguros)
# =============================================================================

_TRUE = {"1", "true", "yes", "y", "on"}


def _env(key: str, default: str = "") -> str:
    return (os.getenv(key) or default).strip()


def _env_bool(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    return v.strip().lower() in _TRUE


# =============================================================================
# Printful Config — ULTRA PRO / SAFE IMPORT
# =============================================================================
# ⚠️ Este módulo:
# - NUNCA levanta RuntimeError al importar
# - Solo define configuración y helpers
# - La validación fuerte se hace en PrintfulClient
# =============================================================================


# --- API KEY -------------------------------------------------
# Soporta aliases viejos para no romper deploys
PRINTFUL_API_KEY: str = _env(
    "PRINTFUL_API_KEY",
    _env("PRINTFUL_KEY", _env("PRINTFUL_API_TOKEN", "")),
)

# --- BASE URL ------------------------------------------------
PRINTFUL_BASE_URL: str = _env("PRINTFUL_BASE_URL", "https://api.printful.com").rstrip(
    "/"
)

# --- Feature flag --------------------------------------------
# Permite desactivar Printful sin borrar código
ENABLE_PRINTFUL: bool = _env_bool("ENABLE_PRINTFUL", default=bool(PRINTFUL_API_KEY))

# --- Cache / Timeouts (defaults globales) --------------------
PRINTFUL_CACHE_TTL: int
try:
    PRINTFUL_CACHE_TTL = int(_env("PRINTFUL_CACHE_TTL", "300"))
except ValueError:
    PRINTFUL_CACHE_TTL = 300

PRINTFUL_RETRIES: int
try:
    PRINTFUL_RETRIES = int(_env("PRINTFUL_RETRIES", "4"))
except ValueError:
    PRINTFUL_RETRIES = 4

PRINTFUL_TIMEOUT_CONNECT: float
try:
    PRINTFUL_TIMEOUT_CONNECT = float(_env("PRINTFUL_TIMEOUT_CONNECT", "6.05"))
except ValueError:
    PRINTFUL_TIMEOUT_CONNECT = 6.05

PRINTFUL_TIMEOUT_READ: float
try:
    PRINTFUL_TIMEOUT_READ = float(_env("PRINTFUL_TIMEOUT_READ", "20"))
except ValueError:
    PRINTFUL_TIMEOUT_READ = 20.0

PRINTFUL_USER_AGENT: str = _env(
    "PRINTFUL_USER_AGENT",
    "SkylineStore/1.0 (+https://skylinestore)",
)

PRINTFUL_DEBUG: bool = _env_bool("PRINTFUL_DEBUG", default=False)


# =============================================================================
# Helpers públicos (opcionales, pero útiles)
# =============================================================================


def printful_enabled() -> bool:
    """
    True si Printful debería usarse.
    Útil para rutas/servicios que quieran fallback silencioso.
    """
    return ENABLE_PRINTFUL and bool(PRINTFUL_API_KEY)


def printful_summary() -> dict:
    """
    Resumen seguro para logs / healthchecks.
    NO expone la API key.
    """
    return {
        "enabled": ENABLE_PRINTFUL,
        "has_api_key": bool(PRINTFUL_API_KEY),
        "base_url": PRINTFUL_BASE_URL,
        "cache_ttl": PRINTFUL_CACHE_TTL,
        "retries": PRINTFUL_RETRIES,
        "timeout": {
            "connect": PRINTFUL_TIMEOUT_CONNECT,
            "read": PRINTFUL_TIMEOUT_READ,
        },
        "debug": PRINTFUL_DEBUG,
    }


__all__ = [
    "PRINTFUL_API_KEY",
    "PRINTFUL_BASE_URL",
    "ENABLE_PRINTFUL",
    "PRINTFUL_CACHE_TTL",
    "PRINTFUL_RETRIES",
    "PRINTFUL_TIMEOUT_CONNECT",
    "PRINTFUL_TIMEOUT_READ",
    "PRINTFUL_USER_AGENT",
    "PRINTFUL_DEBUG",
    "printful_enabled",
    "printful_summary",
]
