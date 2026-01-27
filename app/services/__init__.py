
from __future__ import annotations

import importlib
import logging
import os
import threading
from types import ModuleType
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple, TYPE_CHECKING

log = logging.getLogger("services")

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off", "unchecked"}


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


_SERVICES_STRICT = _env_bool("SERVICES_STRICT", False)
_SERVICES_LOG_IMPORT_ERRORS = _env_bool("SERVICES_LOG_IMPORT_ERRORS", False)

__version__ = "3.1.0"

_EXPORTS: Dict[str, Tuple[str, str]] = {
    "checkout_flow": ("app.services.checkout_flow", "checkout_flow"),
    "CommissionService": ("app.services.commission_service", "CommissionService"),
    "DropshippingService": ("app.services.dropshipping_service", "DropshippingService"),
    "EmailService": ("app.services.email_service", "EmailService"),
    "OrderService": ("app.services.order_service", "OrderService"),
    "PaymentsBootstrap": ("app.services.payments_bootstrap", "PaymentsBootstrap"),
    "paypal_capture": ("app.services.paypal_capture", "paypal_capture"),
    "PrintfulService": ("app.services.printful_service", "PrintfulService"),
    "ProductService": ("app.services.product_service", "ProductService"),
}

_ALIASES: Dict[str, str] = {}

_CACHE: Dict[str, Any] = {}
_MODCACHE: Dict[str, ModuleType] = {}
_MISSCACHE: Dict[str, bool] = {}
_LOCK = threading.RLock()


def _canon(v: Any) -> str:
    return str(v or "").strip()


def _missing(name: str):
    def _fn(*_a: Any, **_k: Any):
        raise RuntimeError(
            "Service no disponible: "
            f"{name}. Revisá _EXPORTS/_ALIASES o el módulo/símbolo faltante."
        )

    _fn.__name__ = name
    _fn.__qualname__ = name
    return _fn


def _resolve_name(name: str) -> str:
    cur = _canon(name)
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


def _import_module(module: str) -> Optional[ModuleType]:
    modname = _canon(module)
    if not modname:
        return None

    m = _MODCACHE.get(modname)
    if m is not None:
        return m

    if _MISSCACHE.get(modname):
        return None

    try:
        m = importlib.import_module(modname)
        _MODCACHE[modname] = m
        return m
    except Exception as e:
        _MISSCACHE[modname] = True
        if _SERVICES_LOG_IMPORT_ERRORS:
            try:
                log.debug("services import failed: %s (%s)", modname, e)
            except Exception:
                pass
        if _SERVICES_STRICT:
            raise RuntimeError(f"Services strict: no se pudo importar {modname}: {e}") from e
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
        if _SERVICES_LOG_IMPORT_ERRORS:
            try:
                log.debug("services getattr failed: %s.%s (%s)", modname, sym, e)
            except Exception:
                pass
        if _SERVICES_STRICT:
            raise RuntimeError(f"Services strict: no se pudo resolver {modname}.{sym}: {e}") from e
        return None


def _load(name: str) -> Any:
    resolved = _resolve_name(name)
    if not resolved:
        return _missing("")

    with _LOCK:
        if resolved in _CACHE:
            return _CACHE[resolved]

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


def configure_aliases(mapping: Optional[Mapping[str, str]] = None, *, clear_cache: bool = False) -> None:
    if not mapping:
        return
    with _LOCK:
        for k, v in mapping.items():
            kk = _canon(k)
            vv = _canon(v)
            if kk and vv and kk != vv:
                _ALIASES[kk] = vv
        if clear_cache:
            _CACHE.clear()


def register_export(
    name: str,
    module: str,
    symbol: str,
    *,
    replace: bool = True,
    clear_cache: bool = True,
    clear_module_cache: bool = False,
) -> None:
    n = _canon(name)
    m = _canon(module)
    s = _canon(symbol)
    if not n or not m or not s:
        raise ValueError("register_export: parámetros vacíos")

    with _LOCK:
        if (not replace) and (n in _EXPORTS):
            return
        _EXPORTS[n] = (m, s)
        if clear_cache:
            _CACHE.pop(n, None)
        if clear_module_cache:
            _MODCACHE.pop(m, None)
            _MISSCACHE.pop(m, None)


def bulk_register(items: Sequence[Tuple[str, str, str]], *, replace: bool = True) -> int:
    n = 0
    with _LOCK:
        for name, module, symbol in items:
            nn = _canon(name)
            mm = _canon(module)
            ss = _canon(symbol)
            if not nn or not mm or not ss:
                continue
            if (not replace) and (nn in _EXPORTS):
                continue
            _EXPORTS[nn] = (mm, ss)
            _CACHE.pop(nn, None)
            n += 1
    return n


def clear_services_cache(*, modules: bool = False, missing: bool = True) -> None:
    with _LOCK:
        _CACHE.clear()
        if modules:
            _MODCACHE.clear()
        if missing:
            _MISSCACHE.clear()


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
        return default if obj is None else obj
    except Exception:
        return default


def resolve(name: str) -> Tuple[str, Optional[Tuple[str, str]]]:
    r = _resolve_name(name)
    return r, _EXPORTS.get(r)


if TYPE_CHECKING:
    from app.services.checkout_flow import checkout_flow
    from app.services.commission_service import CommissionService
    from app.services.dropshipping_service import DropshippingService
    from app.services.email_service import EmailService
    from app.services.order_service import OrderService
    from app.services.payments_bootstrap import PaymentsBootstrap
    from app.services.paypal_capture import paypal_capture
    from app.services.printful_service import PrintfulService
    from app.services.product_service import ProductService


__all__ = sorted(set(_EXPORTS.keys()) | set(_ALIASES.keys())) + [
    "__version__",
    "configure_aliases",
    "register_export",
    "bulk_register",
    "clear_services_cache",
    "has",
    "get",
    "resolve",
]
