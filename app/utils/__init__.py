from __future__ import annotations

import importlib
import logging
import os
import threading
from types import ModuleType
from typing import Any, Dict, Tuple, TYPE_CHECKING

log = logging.getLogger("utils")

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off"}


def _env_bool(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    s = v.strip().lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return default


_UTILS_STRICT = _env_bool("UTILS_STRICT", False)

_EXPORTS: Dict[str, Tuple[str, str]] = {
    "admin_required": ("app.utils.auth", "admin_required"),
    "admin_creds_ok": ("app.utils.auth", "admin_creds_ok"),
    "admin_login": ("app.utils.auth", "admin_login"),
    "admin_logout": ("app.utils.auth", "admin_logout"),
    "admin_login_attempt": ("app.utils.auth", "admin_login_attempt"),
    "is_admin_logged": ("app.utils.auth", "is_admin_logged"),
    "admin_identity": ("app.utils.auth", "admin_identity"),
    "admin_next": ("app.utils.auth", "admin_next"),
    "safe_next_url": ("app.utils.security", "safe_next_url"),
    "is_safe_url": ("app.utils.security", "is_safe_url"),
    "map_printful_product": ("app.utils.printful_mapper", "map_printful_product"),
    "map_printful_variant": ("app.utils.printful_mapper", "map_printful_variant"),
}

_ALIASES: Dict[str, str] = {}

_CACHE: Dict[str, Any] = {}
_MODCACHE: Dict[str, ModuleType] = {}
_LOCK = threading.RLock()


def _missing(name: str):
    def _fn(*_a: Any, **_k: Any):
        raise RuntimeError(
            f"Utilidad no disponible: {name}. "
            f"Revisá registry _EXPORTS/_ALIASES o módulos faltantes."
        )

    _fn.__name__ = name
    return _fn


def _resolve_name(name: str) -> str:
    seen = set()
    cur = name
    while cur in _ALIASES and cur not in seen:
        seen.add(cur)
        cur = _ALIASES[cur]
    return cur


def _import_module(module: str) -> ModuleType | None:
    m = _MODCACHE.get(module)
    if m is not None:
        return m
    try:
        m = importlib.import_module(module)
        _MODCACHE[module] = m
        return m
    except Exception as e:
        try:
            log.debug("utils import failed: %s (%s)", module, e)
        except Exception:
            pass
        if _UTILS_STRICT:
            raise RuntimeError(f"Utils strict: no se pudo importar {module}: {e}") from e
        return None


def _safe_getattr(module: str, symbol: str) -> Any | None:
    m = _import_module(module)
    if m is None:
        return None
    try:
        return getattr(m, symbol)
    except Exception as e:
        try:
            log.debug("utils getattr failed: %s.%s (%s)", module, symbol, e)
        except Exception:
            pass
        if _UTILS_STRICT:
            raise RuntimeError(
                f"Utils strict: no se pudo resolver {module}.{symbol}: {e}"
            ) from e
        return None


def _load(name: str) -> Any:
    resolved = _resolve_name(name)

    with _LOCK:
        obj = _CACHE.get(resolved)
        if obj is not None:
            return obj

        spec = _EXPORTS.get(resolved)
        if not spec:
            obj = _missing(resolved)
            _CACHE[resolved] = obj
            return obj

        module, symbol = spec
        obj = _safe_getattr(module, symbol)
        if obj is None:
            obj = _missing(resolved)

        _CACHE[resolved] = obj
        return obj


def __getattr__(name: str) -> Any:
    return _load(name)


def __dir__() -> list[str]:
    return sorted(set(_EXPORTS.keys()) | set(_ALIASES.keys()))


def configure_aliases(mapping: Dict[str, str] | None = None, *, clear_cache: bool = False) -> None:
    if not mapping:
        return
    with _LOCK:
        for k, v in mapping.items():
            if isinstance(k, str) and isinstance(v, str) and k and v and k != v:
                _ALIASES[k] = v
        if clear_cache:
            _CACHE.clear()


def register_export(name: str, module: str, symbol: str, *, replace: bool = True, clear_cache: bool = True) -> None:
    if not (isinstance(name, str) and isinstance(module, str) and isinstance(symbol, str)):
        raise TypeError("register_export espera strings: (name, module, symbol)")
    if not name or not module or not symbol:
        raise ValueError("register_export: parámetros vacíos")
    with _LOCK:
        if (not replace) and (name in _EXPORTS):
            return
        _EXPORTS[name] = (module, symbol)
        if clear_cache:
            _CACHE.pop(name, None)


def clear_utils_cache(*, modules: bool = False) -> None:
    with _LOCK:
        _CACHE.clear()
        if modules:
            _MODCACHE.clear()


def has(name: str) -> bool:
    resolved = _resolve_name(name)
    if resolved not in _EXPORTS:
        return False
    module, symbol = _EXPORTS[resolved]
    return _safe_getattr(module, symbol) is not None


if TYPE_CHECKING:
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
    from app.utils.security import safe_next_url, is_safe_url  # noqa: F401
    from app.utils.printful_mapper import map_printful_product, map_printful_variant  # noqa: F401


__all__ = sorted(set(_EXPORTS.keys()) | set(_ALIASES.keys()))
