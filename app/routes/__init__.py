"""
Skyline Store · Routes Package (BULLETPROOF FINAL / FULL AUTO · +20 mejoras)
============================================================================
OBJETIVO: "No falta nada" + "no se rompe" + "no tocar más".

✅ Registro ordenado por prioridad (core -> account -> cart/checkout -> api -> webhooks -> admin -> printful)
✅ Auto-scan del paquete app.routes: registra TODO blueprint encontrado
✅ Soporta múltiples blueprints por módulo (descubre todos los Blueprint del módulo)
✅ Autodiscovery: si símbolo no existe, igual registra los blueprints del módulo
✅ Anti duplicados por name + origin (case-insensitive)
✅ Disable por ENV con wildcard real: ROUTES_DISABLE="admin*,printful,app.routes.debug_routes"
✅ Prefix override por ENV: ROUTES_PREFIX_<bpname>=/algo (bpname normalizado)
✅ Require por ENV: ROUTES_REQUIRE="main,shop,auth,checkout,webhook"
✅ Strict mode:
   - ROUTES_STRICT=1 (solo en dev) -> explota si algo falla
   - ROUTES_STRICT_FORCE=1 -> explota siempre (debug fuerte)
✅ Report dict estable para /health + imports_failed para depurar rápido

NUEVO (+5):
✅ ENV-aware cache busting (si cambia ENV relevante, se rescan/importa de nuevo)
✅ Fallback prefix: usa prefix definido dentro del bp si existe (best-effort)
✅ Normalización fuerte de bpname para ROUTES_PREFIX_ (soporta guiones/espacios)
✅ Report con timing_ms + counts + strict
✅ REQUIRED check con listado "have" y "missing" (incluye scan)
"""

from __future__ import annotations

import fnmatch
import logging
import os
import pkgutil
import time
from importlib import import_module
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from flask import Flask

log = logging.getLogger("routes")

_TRUE = {"1", "true", "yes", "y", "on"}

# cache por proceso
_MODULE_CACHE: Dict[str, Any] = {}
_IMPORT_ERRORS: Dict[str, str] = {}

_SCAN_CACHE: Optional[List[str]] = None
_SCAN_CACHE_KEY: Optional[str] = None

# NUEVO: ENV key (para invalidar caches si cambia config)
_ENV_CACHE_KEY: Optional[str] = None


# =============================================================================
# ENV helpers
# =============================================================================
def _env_bool(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    return str(v).strip().lower() in _TRUE


def _routes_debug() -> bool:
    return _env_bool("ROUTES_DEBUG", False)


def _strict_mode(app: "Flask") -> bool:
    """
    - ROUTES_STRICT_FORCE=1 -> siempre strict
    - ROUTES_STRICT=1 -> strict solo en dev
    """
    if _env_bool("ROUTES_STRICT_FORCE", False):
        return True

    if not _env_bool("ROUTES_STRICT", False):
        return False

    env = ""
    try:
        env = (app.config.get("ENV") or "").strip().lower()
    except Exception:
        env = ""

    if not env:
        env = (os.getenv("ENV") or os.getenv("FLASK_ENV") or "").strip().lower()

    if env:
        return env in {"development", "dev"}

    try:
        return bool(getattr(app, "debug", False))
    except Exception:
        return False


def _split_csv_env(key: str) -> List[str]:
    raw = (os.getenv(key) or "").strip()
    if not raw:
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]


def _disabled_patterns() -> List[str]:
    return [x.lower() for x in _split_csv_env("ROUTES_DISABLE")]


def _required_names() -> Set[str]:
    return {x.lower() for x in _split_csv_env("ROUTES_REQUIRE")}


def _priority_modules() -> List[str]:
    return [x for x in _split_csv_env("ROUTES_PRIORITY") if x]


def _match_any(value: str, patterns: List[str]) -> bool:
    v = (value or "").strip().lower()
    if not v:
        return False

    for p in patterns:
        pat = (p or "").strip().lower()
        if not pat:
            continue
        if "*" in pat or "?" in pat or "[" in pat:
            if fnmatch.fnmatch(v, pat):
                return True
        else:
            if v == pat:
                return True
    return False


def _is_disabled(bp_name: str, sym_tail: str, mod_path: str, patterns: List[str]) -> bool:
    return (
        _match_any(bp_name, patterns)
        or _match_any(sym_tail, patterns)
        or _match_any(mod_path, patterns)
        or _match_any(f"{mod_path}.{sym_tail}", patterns)
    )


def _bp_env_key(bp_name: str) -> str:
    """
    NUEVO: normaliza bp_name para poder usar:
    - admin-panel -> ROUTES_PREFIX_ADMIN_PANEL
    - "admin panel" -> ROUTES_PREFIX_ADMIN_PANEL
    """
    s = (bp_name or "").strip().upper()
    # reemplazos seguros
    s = s.replace("-", "_").replace(" ", "_")
    # colapsar múltiple "_"
    while "__" in s:
        s = s.replace("__", "_")
    return s or "BLUEPRINT"


def _env_prefix_for(bp_name: str) -> Optional[str]:
    key = f"ROUTES_PREFIX_{_bp_env_key(bp_name)}"
    v = (os.getenv(key) or "").strip()
    if not v:
        return None
    if not v.startswith("/"):
        v = "/" + v
    if v != "/" and v.endswith("/"):
        v = v[:-1]
    return v


# =============================================================================
# Cache invalidation (NEW)
# =============================================================================
def _compute_env_cache_key() -> str:
    """
    NUEVO: Si cambia cualquiera de estas ENV, invalidamos scan/import cache.
    """
    keys = [
        "ROUTES_DISABLE",
        "ROUTES_REQUIRE",
        "ROUTES_PRIORITY",
        "ROUTES_SCAN_SUBPACKAGES",
        "ROUTES_SCAN_ONLY",
        "ROUTES_IMPORT_NO_CACHE",
        "ROUTES_DEBUG",
        "ROUTES_STRICT",
        "ROUTES_STRICT_FORCE",
    ]
    # también prefijos por bp: no podemos enumerar todos, pero metemos todo el env con prefijo
    prefix_items = []
    for k, v in os.environ.items():
        if k.startswith("ROUTES_PREFIX_"):
            prefix_items.append(f"{k}={v}")
    prefix_items.sort()

    parts = [f"{k}={(os.getenv(k) or '').strip()}" for k in keys] + prefix_items
    return "|".join(parts)


def _maybe_bust_caches() -> None:
    global _ENV_CACHE_KEY, _SCAN_CACHE, _SCAN_CACHE_KEY, _MODULE_CACHE, _IMPORT_ERRORS

    new_key = _compute_env_cache_key()
    if _ENV_CACHE_KEY == new_key:
        return

    _ENV_CACHE_KEY = new_key

    # bust scan cache
    _SCAN_CACHE = None
    _SCAN_CACHE_KEY = None

    # opcional: bust import cache si el user lo pide
    if _env_bool("ROUTES_BUST_IMPORT_CACHE", False):
        _MODULE_CACHE.clear()
        _IMPORT_ERRORS.clear()


# =============================================================================
# Import helpers
# =============================================================================
def _short_exc(e: Exception) -> str:
    msg = f"{type(e).__name__}: {e}"
    return msg[:260]


def _safe_import_module(path: str):
    no_cache = _env_bool("ROUTES_IMPORT_NO_CACHE", False)
    if not no_cache and path in _MODULE_CACHE:
        return _MODULE_CACHE[path]

    try:
        mod = import_module(path)
        _MODULE_CACHE[path] = mod
        _IMPORT_ERRORS.pop(path, None)
        return mod
    except Exception as e:
        _MODULE_CACHE[path] = None
        _IMPORT_ERRORS[path] = _short_exc(e)
        if _routes_debug():
            log.debug("Import module failed: %s (%s)", path, e)
        return None


def _safe_getattr(mod, name: str):
    try:
        return getattr(mod, name, None)
    except Exception:
        return None


def _is_blueprint(obj: Any) -> bool:
    if obj is None:
        return False
    try:
        from flask.blueprints import Blueprint
        return isinstance(obj, Blueprint)
    except Exception:
        return hasattr(obj, "name") and hasattr(obj, "register")


def _find_blueprints_in_module(mod) -> List[Any]:
    if not mod:
        return []
    out: List[Any] = []
    for k in sorted(dir(mod)):
        if k.startswith("_"):
            continue
        obj = _safe_getattr(mod, k)
        if _is_blueprint(obj):
            out.append(obj)

    uniq: Dict[str, Any] = {}
    for bp in out:
        n = (getattr(bp, "name", "") or "").strip()
        if n and n not in uniq:
            uniq[n] = bp
    return list(uniq.values())


def _import_symbol_or_all(mod_path: str, symbol: Optional[str]) -> Tuple[List[Any], Optional[str]]:
    mod = _safe_import_module(mod_path)
    if not mod:
        return [], _IMPORT_ERRORS.get(mod_path)

    if symbol:
        obj = _safe_getattr(mod, symbol)
        if _is_blueprint(obj):
            return [obj], None

    bps = _find_blueprints_in_module(mod)
    return bps, None


# =============================================================================
# Scan modules
# =============================================================================
def _scan_route_modules() -> List[str]:
    """
    Escanea app.routes y devuelve módulos: app.routes.xxx
    ✅ cache por proceso + invalidación por ENV
    """
    global _SCAN_CACHE, _SCAN_CACHE_KEY

    scan_sub = _env_bool("ROUTES_SCAN_SUBPACKAGES", False)
    key = f"sub={int(scan_sub)}"

    if _SCAN_CACHE is not None and _SCAN_CACHE_KEY == key:
        return list(_SCAN_CACHE)

    try:
        pkg = import_module("app.routes")
        base = pkg.__name__

        mods: List[str] = []
        for m in pkgutil.iter_modules(pkg.__path__, base + "."):
            tail = m.name.split(".")[-1]
            if tail.startswith("_"):
                continue
            mods.append(m.name)

            if scan_sub and m.ispkg:
                try:
                    subpkg = import_module(m.name)
                    for sm in pkgutil.iter_modules(getattr(subpkg, "__path__", []), m.name + "."):
                        stail = sm.name.split(".")[-1]
                        if stail.startswith("_"):
                            continue
                        mods.append(sm.name)
                except Exception:
                    pass

        mods = sorted(set(mods))
        _SCAN_CACHE = mods
        _SCAN_CACHE_KEY = key
        return mods
    except Exception:
        return []


# =============================================================================
# Register helpers
# =============================================================================
def _normalize_origin(origin: str) -> str:
    return (origin or "").strip().lower()


def _normalize_prefix(prefix: Optional[str]) -> Optional[str]:
    if not prefix:
        return None
    p = prefix.strip()
    if not p:
        return None
    if not p.startswith("/"):
        p = "/" + p
    if p != "/" and p.endswith("/"):
        p = p[:-1]
    return p


def _bp_internal_prefix(bp: Any) -> Optional[str]:
    """
    NUEVO: best-effort: si el blueprint trae un prefix interno (poco común),
    lo usamos como fallback, sin romper nada.
    """
    try:
        # algunos proyectos guardan url_prefix custom
        v = getattr(bp, "url_prefix", None) or getattr(bp, "_url_prefix", None)
        return _normalize_prefix(v)
    except Exception:
        return None


def _register_bp(
    app: "Flask",
    bp: Any,
    *,
    origin: str,
    seen_names: Set[str],
    seen_origins: Set[str],
    report: Dict[str, List[str]],
    url_prefix: Optional[str],
    disabled_patterns: List[str],
) -> None:
    if not _is_blueprint(bp):
        report["invalid"].append(origin)
        return

    bp_name = (getattr(bp, "name", "") or "").strip()
    if not bp_name:
        report["invalid"].append(origin)
        return

    mod_path = origin.rsplit(".", 1)[0].strip().lower()
    sym_tail = origin.split(".")[-1].strip().lower()

    if _is_disabled(bp_name.lower(), sym_tail, mod_path, disabled_patterns):
        report["disabled"].append(f"{bp_name} <- {origin}")
        return

    origin_key = _normalize_origin(origin)

    if origin_key in seen_origins:
        report["duplicate"].append(f"(origin) {bp_name} <- {origin}")
        return

    if bp_name in seen_names:
        report["duplicate"].append(f"(name) {bp_name} <- {origin}")
        return

    env_pref = _env_prefix_for(bp_name)
    internal_pref = _bp_internal_prefix(bp)
    final_prefix = _normalize_prefix(env_pref or url_prefix or internal_pref)

    try:
        if final_prefix:
            app.register_blueprint(bp, url_prefix=final_prefix)
        else:
            app.register_blueprint(bp)

        seen_names.add(bp_name)
        seen_origins.add(origin_key)

        report["registered"].append(
            f"{bp_name} <- {origin}" + (f" (prefix={final_prefix})" if final_prefix else "")
        )

    except Exception as e:
        report["failed_register"].append(f"{bp_name} <- {origin} :: {_short_exc(e)}")
        log.warning(
            "⚠️ No se pudo registrar blueprint '%s' (%s): %s",
            bp_name,
            origin,
            e,
            exc_info=_routes_debug(),
        )
        if _strict_mode(app):
            raise


# =============================================================================
# Specs (ajustado a tu repo)
# =============================================================================
def _default_specs() -> List[Tuple[str, Optional[str], Optional[str]]]:
    return [
        # CORE
        ("app.routes.main_routes", "main_bp", None),
        ("app.routes.shop_routes", "shop_bp", None),
        ("app.routes.auth_routes", "auth_bp", None),
        # USER / ACCOUNT
        ("app.routes.account_routes", "account_bp", None),
        ("app.routes.profile_routes", "profile_bp", None),
        ("app.routes.address_routes", "address_bp", None),
        # CART / CHECKOUT
        ("app.routes.cart_routes", "cart_bp", None),
        ("app.routes.checkout_routes", "checkout_bp", None),
        # API / AFFILIATE
        ("app.routes.api_routes", "api_bp", None),
        ("app.routes.affiliate_routes", "affiliate_bp", None),
        # MARKETING
        ("app.routes.marketing_routes", "marketing_bp", None),
        # WEBHOOKS
        ("app.routes.webhook_routes", "webhook_bp", None),
        # ADMIN
        ("app.routes.admin_routes", "admin_bp", None),
        ("app.routes.admin_payments_routes", "admin_payments_bp", None),
        # PRINTFUL
        ("app.routes.printful_routes", "printful_bp", None),
    ]


# =============================================================================
# Public API
# =============================================================================
def register_blueprints(app: "Flask") -> Dict[str, Any]:
    """
    Registro final:
    1) specs prioritarios (orden recomendado)
    2) auto-scan: registra TODO blueprint restante

    Report: dict estable y ampliado (timing/counts/strict).
    """
    t0 = time.perf_counter()

    # NUEVO: bust caches si cambió ENV relevante
    _maybe_bust_caches()

    seen_names: Set[str] = set()
    seen_origins: Set[str] = set()
    disabled_patterns = _disabled_patterns()
    required = _required_names()
    scan_only = _env_bool("ROUTES_SCAN_ONLY", False)
    strict = _strict_mode(app)

    report: Dict[str, Any] = {
        "registered": [],
        "missing": [],
        "invalid": [],
        "duplicate": [],
        "failed_register": [],
        "disabled": [],
        "required_missing": [],
        "scan_registered": [],
        "scan_skipped": [],
        "imports_failed": [],
        # NUEVO
        "timing_ms": 0,
        "counts": {},
        "strict": strict,
    }

    # -----------------------------------------
    # 1) PRIORIDAD
    # -----------------------------------------
    specs = _default_specs()

    # prioridad extra por ENV (se inserta ANTES del scan)
    for m in _priority_modules():
        specs.append((m, None, None))

    if not scan_only:
        for mod, symbol, pref in specs:
            bps, err = _import_symbol_or_all(mod, symbol)
            if not bps:
                report["missing"].append(f"{mod}.{symbol or '*'}" + (f" :: {err}" if err else ""))
                if err:
                    report["imports_failed"].append(f"{mod} :: {err}")
                continue

            for bp in bps:
                origin = f"{mod}.{(symbol or getattr(bp, 'name', 'blueprint'))}"
                _register_bp(
                    app,
                    bp,
                    origin=origin,
                    seen_names=seen_names,
                    seen_origins=seen_origins,
                    report=report,
                    url_prefix=pref,
                    disabled_patterns=disabled_patterns,
                )

    # -----------------------------------------
    # 2) AUTO-SCAN
    # -----------------------------------------
    scan_modules = _scan_route_modules()
    for mod in scan_modules:
        bps, err = _import_symbol_or_all(mod, None)
        if not bps:
            report["scan_skipped"].append(mod + (f" :: {err}" if err else ""))
            if err and _routes_debug():
                report["imports_failed"].append(f"{mod} :: {err}")
            continue

        for bp in bps:
            bp_name = (getattr(bp, "name", "") or "blueprint").strip()
            origin = f"{mod}.{bp_name}"
            before = len(report["registered"])
            _register_bp(
                app,
                bp,
                origin=origin,
                seen_names=seen_names,
                seen_origins=seen_origins,
                report=report,
                url_prefix=None,
                disabled_patterns=disabled_patterns,
            )
            if len(report["registered"]) > before:
                report["scan_registered"].append(origin)

    # -----------------------------------------
    # REQUIRED CHECK (por bp.name, incluye scan)
    # -----------------------------------------
    if required:
        have = {x.split(" <- ", 1)[0].strip().lower() for x in report["registered"]}
        miss = sorted(list(required - have))
        if miss:
            report["required_missing"] = miss
            # NUEVO: lista lo que hay (para debug rápido)
            report["required_have"] = sorted(list(have))
            if strict:
                raise RuntimeError(f"ROUTES_REQUIRE faltantes: {', '.join(miss)}")
            log.warning("⚠️ ROUTES_REQUIRE faltantes: %s", ", ".join(miss))

    # -----------------------------------------
    # LOGS RESUMIDOS
    # -----------------------------------------
    try:
        reg_names = [x.split(" <- ", 1)[0] for x in report["registered"]]
        log.info("✅ Blueprints registrados (%d): %s", len(reg_names), ", ".join(reg_names) if reg_names else "(ninguno)")

        if report["scan_registered"]:
            log.info("🧭 Auto-scan registrados (%d)", len(report["scan_registered"]))

        if report["disabled"]:
            log.info("⛔ Deshabilitados (ENV): %s", ", ".join(report["disabled"]))

        if report["failed_register"]:
            log.warning("⚠️ Fallos al registrar (%d): %s", len(report["failed_register"]), " | ".join(report["failed_register"]))

        if report.get("required_missing"):
            log.warning("⚠️ Required faltantes: %s", ", ".join(report["required_missing"]))

        if _routes_debug():
            if report["missing"]:
                log.debug("ℹ️ Missing (%d): %s", len(report["missing"]), " | ".join(report["missing"]))
            if report["invalid"]:
                log.debug("ℹ️ Invalid (%d): %s", len(report["invalid"]), " | ".join(report["invalid"]))
            if report["duplicate"]:
                log.debug("ℹ️ Duplicados evitados (%d): %s", len(report["duplicate"]), " | ".join(report["duplicate"]))
            if report["scan_skipped"]:
                log.debug("ℹ️ Scan skipped (%d): %s", len(report["scan_skipped"]), " | ".join(report["scan_skipped"]))
            if report["imports_failed"]:
                # dedupe imports_failed
                uniq = sorted(set(report["imports_failed"]))
                report["imports_failed"] = uniq
                log.debug("🧩 Imports fallidos (%d): %s", len(uniq), " | ".join(uniq))
    except Exception:
        pass

    # NUEVO: timing + counts
    dt_ms = int((time.perf_counter() - t0) * 1000)
    report["timing_ms"] = dt_ms
    report["counts"] = {
        "registered": len(report["registered"]),
        "scan_registered": len(report["scan_registered"]),
        "disabled": len(report["disabled"]),
        "failed_register": len(report["failed_register"]),
        "missing": len(report["missing"]),
        "invalid": len(report["invalid"]),
        "duplicate": len(report["duplicate"]),
        "scan_skipped": len(report["scan_skipped"]),
        "imports_failed": len(report["imports_failed"]),
        "required_missing": len(report.get("required_missing") or []),
    }

    return report


__all__ = ["register_blueprints"]
