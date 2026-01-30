from __future__ import annotations

import importlib
import logging
import os
import threading
from dataclasses import dataclass
from types import ModuleType
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple, TYPE_CHECKING

log = logging.getLogger("utils")

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off", "unchecked"}

__version__ = "4.0.0"

_DEFAULT_EXPORTS: Dict[str, Tuple[str, str]] = {
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

_EXPORTS: Dict[str, Tuple[str, str]] = dict(_DEFAULT_EXPORTS)
_ALIASES: Dict[str, str] = {}

_CACHE: Dict[str, Any] = {}
_MODCACHE: Dict[str, ModuleType] = {}
_MISSCACHE: Dict[str, bool] = {}
_LOCK = threading.RLock()

_ENV_STRICT = "UTILS_STRICT"
_ENV_LOG_IMPORT_ERRORS = "UTILS_LOG_IMPORT_ERRORS"
_ENV_AUTO_ALIASES = "UTILS_AUTO_ALIASES"
_ENV_DISABLE_CACHE = "UTILS_DISABLE_CACHE"
_ENV_PRELOAD = "UTILS_PRELOAD"


@dataclass(frozen=True)
class ResolveResult:
    name: str
    resolved: str
    spec: Optional[Tuple[str, str]]
    exists: bool


def _env_bool(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    s = str(v).strip().lower()
    if not s:
        return default
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return default


_UTILS_STRICT = _env_bool(_ENV_STRICT, False)
_UTILS_LOG_IMPORT_ERRORS = _env_bool(_ENV_LOG_IMPORT_ERRORS, False)
_UTILS_AUTO_ALIASES = _env_bool(_ENV_AUTO_ALIASES, True)
_UTILS_DISABLE_CACHE = _env_bool(_ENV_DISABLE_CACHE, False)


def _canon(v: Any) -> str:
    return str(v or "").strip()


def _norm_key(v: Any) -> str:
    s = _canon(v)
    return s


def _is_missing_obj(obj: Any) -> bool:
    try:
        return bool(getattr(obj, "__dict__", {}).get("_is_utils_missing"))
    except Exception:
        return False


def _missing(name: str):
    def _fn(*_a: Any, **_k: Any):
        raise RuntimeError(
            "Utilidad no disponible: "
            f"{name}. Revisá _EXPORTS/_ALIASES o módulos/símbolos faltantes."
        )

    _fn.__name__ = name or "missing"
    _fn.__qualname__ = _fn.__name__
    try:
        setattr(_fn, "_is_utils_missing", True)
    except Exception:
        pass
    return _fn


def _resolve_name(name: str) -> str:
    cur = _norm_key(name)
    if not cur:
        return ""
    seen: set[str] = set()
    while True:
        nxt = _ALIASES.get(cur)
        if not nxt:
            return cur
        if nxt == cur or cur in seen:
            return cur
        seen.add(cur)
        cur = nxt


def _log_debug(msg: str, *args: Any) -> None:
    if not _UTILS_LOG_IMPORT_ERRORS:
        return
    try:
        log.debug(msg, *args)
    except Exception:
        pass


def _import_module(module: str) -> Optional[ModuleType]:
    modname = _canon(module)
    if not modname:
        return None

    if not _UTILS_DISABLE_CACHE:
        m = _MODCACHE.get(modname)
        if m is not None:
            return m
        if _MISSCACHE.get(modname):
            return None

    try:
        m = importlib.import_module(modname)
        if not _UTILS_DISABLE_CACHE:
            _MODCACHE[modname] = m
        return m
    except Exception as e:
        if not _UTILS_DISABLE_CACHE:
            _MISSCACHE[modname] = True
        _log_debug("utils import failed: %s (%s)", modname, e)
        if _UTILS_STRICT:
            raise RuntimeError(f"Utils strict: no se pudo importar {modname}: {e}") from e
        return None


def _safe_getattr(module: str, symbol: str) -> Any:
    modname = _canon(module)
    sym = _canon(symbol)
    if not modname or not sym:
        return None

    m = _import_module(modname)
    if m is None:
        return None

    try:
        return getattr(m, sym)
    except Exception as e:
        _log_debug("utils getattr failed: %s.%s (%s)", modname, sym, e)
        if _UTILS_STRICT:
            raise RuntimeError(f"Utils strict: no se pudo resolver {modname}.{sym}: {e}") from e
        return None


def _load(name: str) -> Any:
    resolved = _resolve_name(name)
    if not resolved:
        return _missing("")

    with _LOCK:
        if not _UTILS_DISABLE_CACHE and resolved in _CACHE:
            return _CACHE[resolved]

        spec = _EXPORTS.get(resolved)
        if not spec:
            obj = _missing(resolved)
            if not _UTILS_DISABLE_CACHE:
                _CACHE[resolved] = obj
            return obj

        module, symbol = spec
        obj = _safe_getattr(module, symbol)
        if obj is None:
            obj = _missing(resolved)

        if not _UTILS_DISABLE_CACHE:
            _CACHE[resolved] = obj
        return obj


def __getattr__(name: str) -> Any:
    return _load(name)


def __dir__() -> list[str]:
    return sorted(set(_EXPORTS.keys()) | set(_ALIASES.keys()))


def configure_aliases(mapping: Optional[Mapping[str, str]] = None, *, clear_cache: bool = False) -> int:
    if not mapping:
        return 0
    n = 0
    with _LOCK:
        for k, v in mapping.items():
            kk = _norm_key(k)
            vv = _norm_key(v)
            if kk and vv and kk != vv:
                _ALIASES[kk] = vv
                n += 1
        if clear_cache and not _UTILS_DISABLE_CACHE:
            _CACHE.clear()
    return n


def register_alias(name: str, target: str, *, clear_cache: bool = True) -> bool:
    kk = _norm_key(name)
    vv = _norm_key(target)
    if not kk or not vv or kk == vv:
        return False
    with _LOCK:
        _ALIASES[kk] = vv
        if clear_cache and not _UTILS_DISABLE_CACHE:
            _CACHE.pop(kk, None)
    return True


def unregister_alias(name: str, *, clear_cache: bool = True) -> bool:
    kk = _norm_key(name)
    if not kk:
        return False
    with _LOCK:
        existed = kk in _ALIASES
        _ALIASES.pop(kk, None)
        if clear_cache and not _UTILS_DISABLE_CACHE:
            _CACHE.pop(kk, None)
    return existed


def list_aliases() -> Dict[str, str]:
    with _LOCK:
        return dict(_ALIASES)


def register_export(
    name: str,
    module: str,
    symbol: str,
    *,
    replace: bool = True,
    clear_cache: bool = True,
    clear_module_cache: bool = False,
) -> None:
    n = _norm_key(name)
    m = _canon(module)
    s = _canon(symbol)
    if not n or not m or not s:
        raise ValueError("register_export: parámetros vacíos")

    with _LOCK:
        if (not replace) and (n in _EXPORTS):
            return
        _EXPORTS[n] = (m, s)

        if clear_cache and not _UTILS_DISABLE_CACHE:
            _CACHE.pop(n, None)

        if clear_module_cache and not _UTILS_DISABLE_CACHE:
            _MODCACHE.pop(m, None)
            _MISSCACHE.pop(m, None)


def unregister_export(name: str, *, clear_cache: bool = True) -> bool:
    n = _norm_key(name)
    if not n:
        return False
    with _LOCK:
        existed = n in _EXPORTS
        _EXPORTS.pop(n, None)
        if clear_cache and not _UTILS_DISABLE_CACHE:
            _CACHE.pop(n, None)
    return existed


def bulk_register(items: Sequence[Tuple[str, str, str]], *, replace: bool = True) -> int:
    count = 0
    with _LOCK:
        for name, module, symbol in items:
            nn = _norm_key(name)
            mm = _canon(module)
            ss = _canon(symbol)
            if not nn or not mm or not ss:
                continue
            if (not replace) and (nn in _EXPORTS):
                continue
            _EXPORTS[nn] = (mm, ss)
            if not _UTILS_DISABLE_CACHE:
                _CACHE.pop(nn, None)
            count += 1
    return count


def clear_utils_cache(*, exports: bool = False, modules: bool = False, missing: bool = True) -> None:
    with _LOCK:
        if not _UTILS_DISABLE_CACHE:
            _CACHE.clear()
        if modules and not _UTILS_DISABLE_CACHE:
            _MODCACHE.clear()
        if missing and not _UTILS_DISABLE_CACHE:
            _MISSCACHE.clear()
        if exports:
            _EXPORTS.clear()
            _EXPORTS.update(_DEFAULT_EXPORTS)


def has(name: str) -> bool:
    resolved = _resolve_name(name)
    if not resolved:
        return False
    spec = _EXPORTS.get(resolved)
    if not spec:
        return False
    module, symbol = spec
    return _safe_getattr(module, symbol) is not None


def get(name: str, default: Any = None) -> Any:
    try:
        obj = _load(name)
        return default if _is_missing_obj(obj) else obj
    except Exception:
        return default


def resolve(name: str) -> Tuple[str, Optional[Tuple[str, str]]]:
    r = _resolve_name(name)
    return r, _EXPORTS.get(r)


def resolve_detailed(name: str) -> ResolveResult:
    r = _resolve_name(name)
    spec = _EXPORTS.get(r)
    exists = False
    if spec:
        module, symbol = spec
        exists = _safe_getattr(module, symbol) is not None
    return ResolveResult(name=_canon(name), resolved=r, spec=spec, exists=bool(exists))


def list_exports() -> Dict[str, Tuple[str, str]]:
    with _LOCK:
        return dict(_EXPORTS)


def set_strict_mode(enabled: bool, *, clear_cache: bool = False) -> None:
    global _UTILS_STRICT
    _UTILS_STRICT = bool(enabled)
    if clear_cache:
        clear_utils_cache(modules=False, missing=False)


def set_log_import_errors(enabled: bool) -> None:
    global _UTILS_LOG_IMPORT_ERRORS
    _UTILS_LOG_IMPORT_ERRORS = bool(enabled)


def preload(names: Optional[Iterable[str]] = None) -> int:
    if names is None:
        names = list(_EXPORTS.keys())
    loaded = 0
    for n in names:
        try:
            obj = _load(str(n))
            if not _is_missing_obj(obj):
                loaded += 1
        except Exception:
            if _UTILS_STRICT:
                raise
    return loaded


def init_from_env(*, clear_cache: bool = False) -> None:
    if clear_cache:
        clear_utils_cache(modules=True, missing=True)

    if _env_bool(_ENV_PRELOAD, False):
        preload()

    if _UTILS_AUTO_ALIASES:
        try:
            for k in list(_EXPORTS.keys()):
                if "_" in k:
                    register_alias(k.replace("_", "-"), k, clear_cache=False)
        except Exception:
            pass


init_from_env(clear_cache=False)

__all__ = sorted(set(_EXPORTS.keys()) | set(_ALIASES.keys())) + [
    "__version__",
    "ResolveResult",
    "configure_aliases",
    "register_alias",
    "unregister_alias",
    "list_aliases",
    "register_export",
    "unregister_export",
    "bulk_register",
    "clear_utils_cache",
    "has",
    "get",
    "resolve",
    "resolve_detailed",
    "list_exports",
    "set_strict_mode",
    "set_log_import_errors",
    "preload",
    "init_from_env",
]

if TYPE_CHECKING:
    from app.utils.auth import (
        admin_required,
        admin_creds_ok,
        admin_login,
        admin_logout,
        admin_login_attempt,
        is_admin_logged,
        admin_identity,
        admin_next,
    )
    from app.utils.security import is_safe_url, safe_next_url
    from app.utils.printful_mapper import map_printful_product, map_printful_variant
