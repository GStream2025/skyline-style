"""
Skyline Style — Utils Hub (ULTRA PRO / BULLETPROOF) — FINAL
-----------------------------------------------------------
Punto único de entrada para utilidades compartidas.

Reglas:
- NO lógica de negocio acá
- SOLO exports públicos
- IMPORTS LAZY (evita circular imports)
- Si falta un módulo -> NO rompe la app (fallback seguro)

Uso recomendado:
  from app import utils
  utils.admin_required(...)
  utils.admin_login_attempt(...)
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional, Tuple, TYPE_CHECKING

log = logging.getLogger("utils")

_TRUE = {"1", "true", "yes", "y", "on"}

def _env_bool(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    return v.strip().lower() in _TRUE

# Strict (dev): si algo falta, queremos enterarnos rápido
_UTILS_STRICT = _env_bool("UTILS_STRICT", False)

# ============================================================
# Registry de símbolos públicos (nombre -> (module, symbol))
# ============================================================

_EXPORTS: Dict[str, Tuple[str, str]] = {
    # -----------------------
    # Auth / Admin
    # -----------------------
    "admin_required": ("app.utils.auth", "admin_required"),
    "admin_creds_ok": ("app.utils.auth", "admin_creds_ok"),
    "admin_login": ("app.utils.auth", "admin_login"),
    "admin_logout": ("app.utils.auth", "admin_logout"),
    "admin_login_attempt": ("app.utils.auth", "admin_login_attempt"),
    "is_admin_logged": ("app.utils.auth", "is_admin_logged"),
    "admin_identity": ("app.utils.auth", "admin_identity"),
    "admin_next": ("app.utils.auth", "admin_next"),

    # -----------------------
    # Security (URLs / redirects)
    # -----------------------
    "safe_next_url": ("app.utils.security", "safe_next_url"),
    "is_safe_url": ("app.utils.security", "is_safe_url"),

    # -----------------------
    # Printful mapping
    # -----------------------
    "map_printful_product": ("app.utils.printful_mapper", "map_printful_product"),
    "map_printful_variant": ("app.utils.printful_mapper", "map_printful_variant"),
}

# Alias opcionales (compat si renombraste)
_ALIASES: Dict[str, str] = {
    # ejemplo: "safe_next": "safe_next_url",
}

# Cache: símbolo -> objeto
_CACHE: Dict[str, Any] = {}


# ============================================================
# Helpers internos (safe import + fallback)
# ============================================================

def _safe_import(module: str, symbol: str) -> Any:
    """
    Importa símbolo de forma segura.
    - En prod: no rompe, devuelve None.
    - En strict dev: levanta RuntimeError para que lo veas al toque.
    """
    try:
        mod = __import__(module, fromlist=[symbol])
        return getattr(mod, symbol)
    except Exception as e:
        # debug only (no ensucia prod)
        try:
            log.debug("utils import failed: %s.%s (%s)", module, symbol, e)
        except Exception:
            pass

        if _UTILS_STRICT:
            raise RuntimeError(f"Utils strict: no se pudo importar {module}.{symbol}: {e}") from e

        return None


def _missing(name: str):
    """
    Crea un stub que falla con error claro SOLO cuando se usa.
    """
    def _fn(*_a: Any, **_k: Any):
        raise RuntimeError(
            f"Utilidad no disponible: {name}. "
            f"Revisá imports/archivo faltante o typo en registry _EXPORTS."
        )
    _fn.__name__ = name
    return _fn


def _resolve_name(name: str) -> str:
    """
    Resuelve alias si existe.
    """
    return _ALIASES.get(name, name)


def _load(name: str) -> Any:
    """
    Carga lazy con cache.
    """
    name = _resolve_name(name)

    if name in _CACHE:
        return _CACHE[name]

    spec = _EXPORTS.get(name)
    if not spec:
        obj = _missing(name)
        _CACHE[name] = obj
        return obj

    module, symbol = spec
    obj = _safe_import(module, symbol)

    if obj is None:
        obj = _missing(name)

    _CACHE[name] = obj
    return obj


# ============================================================
# Lazy exports (PEP 562)
# ============================================================

def __getattr__(name: str) -> Any:
    """
    Se ejecuta cuando se accede a app.utils.<name>.
    """
    return _load(name)


def __dir__() -> list[str]:
    """
    Mejora autocompletado: muestra exports.
    """
    return sorted(set(list(_EXPORTS.keys()) + list(_ALIASES.keys())))


# ============================================================
# Typing helpers (no ejecuta imports en runtime)
# ============================================================

if TYPE_CHECKING:
    # Auth
    from app.utils.auth import (  # noqa: F401
        admin_required,
        admin_creds_ok,
        admin_login,
        admin_logout,
        admin_login_attempt,
        is_admin_logged,
        admin_identity,
        admin_next,
    )

    # Security
    from app.utils.security import safe_next_url, is_safe_url  # noqa: F401

    # Printful
    from app.utils.printful_mapper import map_printful_product, map_printful_variant  # noqa: F401


# ============================================================
# Export público controlado (API estable)
# ============================================================

__all__ = sorted(list(_EXPORTS.keys()) + list(_ALIASES.keys()))
