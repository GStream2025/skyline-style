"""
Skyline Store · Routes Package
BULLETPROOF FINAL / FULL AUTO · vNEXT+ULTRA

Objetivo:
- No falta nada
- No se rompe
- No tocar más
"""

from __future__ import annotations

import fnmatch
import logging
import os
import pkgutil
import threading
import time
from dataclasses import dataclass
from importlib import import_module
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from flask import Flask

log = logging.getLogger("routes")

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off", "unchecked"}

# ─────────────────────────────────────────────────────────────
# Global locks / caches (thread-safe)
# ─────────────────────────────────────────────────────────────
_REGISTER_LOCK = threading.Lock()

_MODULE_CACHE: Dict[str, Any] = {}
_IMPORT_ERRORS: Dict[str, str] = {}
_SCAN_CACHE: Optional[List[str]] = None
_SCAN_CACHE_KEY: Optional[str] = None
_ENV_CACHE_KEY: Optional[str] = None


# ─────────────────────────────────────────────────────────────
# ENV helpers
# ─────────────────────────────────────────────────────────────
def _env_bool(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    s = str(v).strip().lower()
    if not s:
        return default
    if s in _FALSE:
        return False
    return s in _TRUE


def _split_csv(key: str) -> List[str]:
    raw = (os.getenv(key) or "").strip()
    if not raw:
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]


def _routes_debug() -> bool:
    return _env_bool("ROUTES_DEBUG", False)


# ─────────────────────────────────────────────────────────────
# Blueprint detection
# ─────────────────────────────────────────────────────────────
def _is_blueprint(obj: Any) -> bool:
    if obj is None:
        return False
    try:
        from flask.blueprints import Blueprint
        return isinstance(obj, Blueprint)
    except Exception:
        return hasattr(obj, "name") and hasattr(obj, "register")


def _normalize_name(name: str) -> str:
    return (name or "").strip().lower().replace(" ", "_").replace("-", "_")


# ─────────────────────────────────────────────────────────────
# Import helpers
# ─────────────────────────────────────────────────────────────
def _short_exc(e: Exception) -> str:
    return f"{type(e).__name__}: {e}"[:240]


def _safe_import(path: str):
    if path in _MODULE_CACHE:
        return _MODULE_CACHE[path]

    try:
        mod = import_module(path)
        _MODULE_CACHE[path] = mod
        return mod
    except Exception as e:
        _MODULE_CACHE[path] = None
        _IMPORT_ERRORS[path] = _short_exc(e)
        if _routes_debug():
            log.debug("❌ Import failed: %s", path, exc_info=True)
        return None


def _find_blueprints(mod: Any) -> List[Tuple[Any, str]]:
    out: List[Tuple[Any, str]] = []
    if not mod:
        return out

    for attr in sorted(dir(mod)):
        if attr.startswith("_"):
            continue
        try:
            obj = getattr(mod, attr)
        except Exception:
            continue
        if _is_blueprint(obj):
            out.append((obj, attr))

    uniq: Dict[str, Tuple[Any, str]] = {}
    for bp, sym in out:
        name = _normalize_name(getattr(bp, "name", ""))
        if name and name not in uniq:
            uniq[name] = (bp, sym)

    return list(uniq.values())


# ─────────────────────────────────────────────────────────────
# Scan helpers
# ─────────────────────────────────────────────────────────────
def _scan_modules() -> List[str]:
    global _SCAN_CACHE, _SCAN_CACHE_KEY

    key = "|".join([
        os.getenv("ROUTES_SCAN_EXCLUDE", ""),
        os.getenv("ROUTES_SCAN_ONLY_MODULES", ""),
        os.getenv("ROUTES_SCAN_SUBPACKAGES", ""),
    ])

    if _SCAN_CACHE is not None and _SCAN_CACHE_KEY == key:
        return list(_SCAN_CACHE)

    mods: List[str] = []
    try:
        pkg = import_module("app.routes")
        base = pkg.__name__
        excludes = [x.lower() for x in _split_csv("ROUTES_SCAN_EXCLUDE")]

        for m in pkgutil.iter_modules(pkg.__path__, base + "."):
            tail = m.name.split(".")[-1].lower()
            if tail.startswith("_") or tail in {"tests", "test", "conftest"}:
                continue
            if any(fnmatch.fnmatch(m.name.lower(), ex) for ex in excludes):
                continue
            mods.append(m.name)

        mods = sorted(set(mods))
    except Exception:
        mods = []

    _SCAN_CACHE = mods
    _SCAN_CACHE_KEY = key
    return mods


# ─────────────────────────────────────────────────────────────
# Register
# ─────────────────────────────────────────────────────────────
@dataclass
class _Seen:
    names: Set[str]
    ids: Set[int]
    origins: Set[str]


def register_blueprints(app: "Flask") -> Dict[str, Any]:
    """
    Registro FINAL y seguro de blueprints.
    """
    with _REGISTER_LOCK:
        t0 = time.perf_counter()

        report: Dict[str, Any] = {
            "registered": [],
            "disabled": [],
            "duplicates": [],
            "failed": [],
            "imports_failed": [],
            "timing_ms": 0,
            "counts": {},
        }

        seen = _Seen(set(), set(), set())

        # ─────────────────────────────────────────
        # PRIORITY (manual)
        # ─────────────────────────────────────────
        priority = [
            "app.routes.main_routes",
            "app.routes.shop_routes",
            "app.routes.auth_routes",
            "app.routes.account_routes",
            "app.routes.cart_routes",
            "app.routes.checkout_routes",
            "app.routes.api_routes",
            "app.routes.webhook_routes",
            "app.routes.admin_routes",
            "app.routes.printful_routes",
        ]

        disabled = [x.lower() for x in _split_csv("ROUTES_DISABLE")]
        allow = {x.lower() for x in _split_csv("ROUTES_ALLOW")}

        def _try_register(mod_path: str):
            mod = _safe_import(mod_path)
            if not mod:
                report["imports_failed"].append(mod_path)
                return

            for bp, sym in _find_blueprints(mod):
                name = _normalize_name(bp.name)
                origin = f"{mod_path}.{sym}".lower()

                if allow and name not in allow:
                    report["disabled"].append(origin)
                    continue

                if any(fnmatch.fnmatch(origin, pat) for pat in disabled):
                    report["disabled"].append(origin)
                    continue

                if id(bp) in seen.ids or name in seen.names:
                    report["duplicates"].append(origin)
                    continue

                try:
                    app.register_blueprint(bp)
                    seen.ids.add(id(bp))
                    seen.names.add(name)
                    seen.origins.add(origin)
                    report["registered"].append(origin)
                except Exception as e:
                    report["failed"].append(f"{origin} :: {_short_exc(e)}")
                    if _env_bool("ROUTES_STRICT_FORCE", False):
                        raise

        for m in priority:
            _try_register(m)

        # ─────────────────────────────────────────
        # AUTO SCAN
        # ─────────────────────────────────────────
        for m in _scan_modules():
            _try_register(m)

        report["timing_ms"] = int((time.perf_counter() - t0) * 1000)
        report["counts"] = {
            "registered": len(report["registered"]),
            "disabled": len(report["disabled"]),
            "duplicates": len(report["duplicates"]),
            "failed": len(report["failed"]),
            "imports_failed": len(report["imports_failed"]),
        }

        log.info(
            "✅ Routes ready | registered=%d | disabled=%d | dup=%d | failed=%d | %dms",
            report["counts"]["registered"],
            report["counts"]["disabled"],
            report["counts"]["duplicates"],
            report["counts"]["failed"],
            report["timing_ms"],
        )

        return report


__all__ = ["register_blueprints"]
