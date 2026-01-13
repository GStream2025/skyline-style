"""
Skyline Store · Routes Package (BULLETPROOF FINAL / FULL AUTO · vNEXT)
========================================================================
OBJETIVO: "No falta nada" + "no se rompe" + "no tocar más".

✅ Registro por prioridad (core -> account -> cart/checkout -> api -> webhooks -> admin -> printful)
✅ Auto-scan del paquete app.routes: registra TODO blueprint encontrado
✅ Descubre múltiples Blueprints por módulo
✅ Anti duplicados por bp.name (case-insensitive) + ORIGIN + identidad del objeto
✅ Disable por ENV con wildcard: ROUTES_DISABLE="admin*,printful,app.routes.debug_routes"
✅ Allowlist opcional: ROUTES_ALLOW="main,shop,auth,account" (si existe, SOLO esos)
✅ Prefix override por ENV: ROUTES_PREFIX_<bpname>=/algo (bpname normalizado)
✅ Require por ENV: ROUTES_REQUIRE="main,shop,auth,account"
✅ Strict mode:
   - ROUTES_STRICT=1 (solo dev)
   - ROUTES_STRICT_FORCE=1 (siempre)
✅ Report dict estable para debug
"""

from __future__ import annotations

import fnmatch
import logging
import os
import pkgutil
import time
from dataclasses import dataclass
from importlib import import_module
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from flask import Flask

log = logging.getLogger("routes")

# ✅ FIX: faltaba _FALSE (este era el crash que te omitía el registro de blueprints)
_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off", "unchecked"}

# cache por proceso
_MODULE_CACHE: Dict[str, Any] = {}
_IMPORT_ERRORS: Dict[str, str] = {}

_SCAN_CACHE: Optional[List[str]] = None
_SCAN_CACHE_KEY: Optional[str] = None
_ENV_CACHE_KEY: Optional[str] = None


# =============================================================================
# ENV helpers
# =============================================================================
def _env_bool(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    s = str(v).strip().lower()
    if not s:
        return default
    # ✅ Soporta false explícito
    if s in _FALSE:
        return False
    return s in _TRUE


def _routes_debug() -> bool:
    return _env_bool("ROUTES_DEBUG", False)


def _split_csv_env(key: str) -> List[str]:
    raw = (os.getenv(key) or "").strip()
    if not raw:
        return []
    return [x.strip() for x in raw.split(",") if x and x.strip()]


def _disabled_patterns() -> List[str]:
    return [x.lower() for x in _split_csv_env("ROUTES_DISABLE")]


def _scan_exclude_patterns() -> List[str]:
    return [x.lower() for x in _split_csv_env("ROUTES_SCAN_EXCLUDE")]


def _scan_only_modules() -> Set[str]:
    """
    Si definís ROUTES_SCAN_ONLY_MODULES,
    el autoscan solo incluye esos módulos (wildcards permitidos).
    """
    return {x.lower() for x in _split_csv_env("ROUTES_SCAN_ONLY_MODULES")}


def _required_names() -> Set[str]:
    return {x.lower() for x in _split_csv_env("ROUTES_REQUIRE")}


def _allowed_names() -> Set[str]:
    return {x.lower() for x in _split_csv_env("ROUTES_ALLOW")}


def _priority_modules() -> List[str]:
    return [x for x in _split_csv_env("ROUTES_PRIORITY") if x]


def _strict_mode(app: "Flask") -> bool:
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


def _match_any(value: str, patterns: List[str]) -> bool:
    v = (value or "").strip().lower()
    if not v:
        return False
    for p in (patterns or []):
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
    # bp_name/sym_tail/mod_path ya deberían venir lower
    return (
        _match_any(bp_name, patterns)
        or _match_any(sym_tail, patterns)
        or _match_any(mod_path, patterns)
        or _match_any(f"{mod_path}.{sym_tail}", patterns)
        or _match_any(f"{mod_path}.{bp_name}", patterns)
    )


def _bp_env_key(bp_name: str) -> str:
    s = (bp_name or "").strip().upper()
    s = s.replace("-", "_").replace(" ", "_")
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
# Cache invalidation
# =============================================================================
def _compute_env_cache_key() -> str:
    keys = [
        "ROUTES_DISABLE",
        "ROUTES_ALLOW",
        "ROUTES_REQUIRE",
        "ROUTES_PRIORITY",
        "ROUTES_SCAN_SUBPACKAGES",
        "ROUTES_SCAN_ONLY",
        "ROUTES_SCAN_EXCLUDE",
        "ROUTES_SCAN_ONLY_MODULES",
        "ROUTES_IMPORT_NO_CACHE",
        "ROUTES_DEBUG",
        "ROUTES_STRICT",
        "ROUTES_STRICT_FORCE",
        "ROUTES_BUST_IMPORT_CACHE",
        "ROUTES_PRIORITY_DEFAULTS",
    ]
    prefix_items: List[str] = []
    for k, v in os.environ.items():
        if k.startswith("ROUTES_PREFIX_"):
            prefix_items.append(f"{k}={v}")
    prefix_items.sort()

    parts = [f"{k}={(os.getenv(k) or '').strip()}" for k in keys] + prefix_items
    return "|".join(parts)


def _maybe_bust_caches() -> None:
    global _ENV_CACHE_KEY, _SCAN_CACHE, _SCAN_CACHE_KEY
    new_key = _compute_env_cache_key()
    if _ENV_CACHE_KEY == new_key:
        return

    _ENV_CACHE_KEY = new_key
    _SCAN_CACHE = None
    _SCAN_CACHE_KEY = None

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
            log.debug("Import module failed: %s (%s)", path, e, exc_info=True)
        return None


def _safe_getattr(mod: Any, name: str):
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
        # fallback muy raro
        return hasattr(obj, "name") and hasattr(obj, "register")


def _find_blueprints_in_module(mod: Any) -> List[Tuple[Any, str]]:
    """Retorna lista de (blueprint, symbol_name)."""
    if not mod:
        return []
    out: List[Tuple[Any, str]] = []
    for k in sorted(dir(mod)):
        if k.startswith("_"):
            continue
        obj = _safe_getattr(mod, k)
        if _is_blueprint(obj):
            out.append((obj, k))

    # uniq por bp.name (case-insensitive) conservando primer símbolo encontrado
    uniq: Dict[str, Tuple[Any, str]] = {}
    for bp, sym in out:
        n = (getattr(bp, "name", "") or "").strip()
        if not n:
            continue
        nk = n.lower()
        if nk not in uniq:
            uniq[nk] = (bp, sym)
    return list(uniq.values())


def _import_symbol_or_all(mod_path: str, symbol: Optional[str]) -> Tuple[List[Tuple[Any, str]], Optional[str]]:
    mod = _safe_import_module(mod_path)
    if not mod:
        return [], _IMPORT_ERRORS.get(mod_path)

    if symbol:
        obj = _safe_getattr(mod, symbol)
        if _is_blueprint(obj):
            return [(obj, symbol)], None

    # fallback: descubrimos todos
    bps = _find_blueprints_in_module(mod)
    return bps, None


# =============================================================================
# Scan modules
# =============================================================================
def _scan_route_modules(exclude_patterns: List[str], only_modules: Set[str]) -> List[str]:
    global _SCAN_CACHE, _SCAN_CACHE_KEY

    scan_sub = _env_bool("ROUTES_SCAN_SUBPACKAGES", False)
    only_list = sorted(list(only_modules or []))
    key = f"sub={int(scan_sub)}|ex={'/'.join(exclude_patterns or [])}|only={'/'.join(only_list)}"
    if _SCAN_CACHE is not None and _SCAN_CACHE_KEY == key:
        return list(_SCAN_CACHE)

    try:
        pkg = import_module("app.routes")
        base = pkg.__name__

        mods: List[str] = []
        for m in pkgutil.iter_modules(pkg.__path__, base + "."):
            tail = m.name.split(".")[-1]
            # skip ruido típico
            if tail.startswith("_") or tail in {"tests", "test", "conftest", "__init__"}:
                continue

            # exclude global
            if _match_any(m.name.lower(), exclude_patterns) or _match_any(tail.lower(), exclude_patterns):
                continue

            # only filter (NEW) con wildcard
            if only_modules:
                if not _match_any(m.name.lower(), only_list) and not _match_any(tail.lower(), only_list):
                    continue

            mods.append(m.name)

            if scan_sub and m.ispkg:
                try:
                    subpkg = import_module(m.name)
                    for sm in pkgutil.iter_modules(getattr(subpkg, "__path__", []), m.name + "."):
                        stail = sm.name.split(".")[-1]
                        if stail.startswith("_") or stail in {"tests", "test", "conftest", "__init__"}:
                            continue
                        if _match_any(sm.name.lower(), exclude_patterns) or _match_any(stail.lower(), exclude_patterns):
                            continue

                        if only_modules:
                            if not _match_any(sm.name.lower(), only_list) and not _match_any(stail.lower(), only_list):
                                continue

                        mods.append(sm.name)
                except Exception:
                    pass

        mods = sorted(set(mods))  # orden estable
        _SCAN_CACHE = mods
        _SCAN_CACHE_KEY = key
        return mods
    except Exception as e:
        if _routes_debug():
            log.debug("Scan modules failed: %s", e, exc_info=True)
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
    try:
        v = getattr(bp, "url_prefix", None) or getattr(bp, "_url_prefix", None)
        return _normalize_prefix(v)
    except Exception:
        return None


@dataclass(frozen=True)
class _BpKey:
    """Key estable para dedupe extra."""
    bp_id: int
    bp_name: str
    origin: str


def _register_bp(
    app: "Flask",
    bp: Any,
    *,
    origin: str,
    symbol: str,
    seen_names: Set[str],
    seen_origins: Set[str],
    seen_ids: Set[int],
    seen_modsym: Set[str],
    report: Dict[str, Any],
    url_prefix: Optional[str],
    disabled_patterns: List[str],
    allowed_names: Set[str],
) -> None:
    if not _is_blueprint(bp):
        report["invalid"].append(origin)
        return

    bp_name = (getattr(bp, "name", "") or "").strip()
    if not bp_name:
        report["invalid"].append(origin)
        return

    bp_key = bp_name.lower()
    mod_path = origin.rsplit(".", 1)[0].strip().lower()
    sym_tail = (symbol or "").strip().lower() or origin.split(".")[-1].strip().lower()

    # allowlist
    if allowed_names and bp_key not in allowed_names:
        report["disabled"].append(f"{bp_name} <- {origin} (allowlist)")
        return

    if _is_disabled(bp_key, sym_tail, mod_path, disabled_patterns):
        report["disabled"].append(f"{bp_name} <- {origin}")
        return

    # dedupe por identidad
    bp_id = id(bp)
    if bp_id in seen_ids:
        report["duplicate"].append(f"(id) {bp_name} <- {origin}")
        return

    # dedupe por (module,symbol)
    modsym = f"{mod_path}.{sym_tail}".lower()
    if modsym in seen_modsym:
        report["duplicate"].append(f"(modsym) {bp_name} <- {origin}")
        return

    origin_key = _normalize_origin(origin)
    if origin_key in seen_origins:
        report["duplicate"].append(f"(origin) {bp_name} <- {origin}")
        return

    if bp_key in seen_names:
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

        seen_ids.add(bp_id)
        seen_names.add(bp_key)
        seen_origins.add(origin_key)
        seen_modsym.add(modsym)

        report["registered"].append(
            f"{bp_name} <- {origin}" + (f" (prefix={final_prefix})" if final_prefix else "")
        )
        report["map"][bp_name] = {
            "origin": origin,
            "symbol": symbol,
            "prefix": final_prefix or "",
        }
    except Exception as e:
        report["failed_register"].append(f"{bp_name} <- {origin} :: {_short_exc(e)}")
        log.warning(
            "⚠️ No se pudo registrar blueprint '%s' (%s): %s",
            bp_name, origin, e, exc_info=_routes_debug()
        )
        if report["strict"]:
            raise


# =============================================================================
# Specs (ajustado a tu repo)
# =============================================================================
def _default_specs() -> List[Tuple[str, Optional[str], Optional[str]]]:
    # CORE primero
    return [
        ("app.routes.main_routes", None, None),
        ("app.routes.shop_routes", None, None),

        # AUTH unificado
        ("app.routes.auth_routes", None, None),

        # USER / ACCOUNT (panel)
        ("app.routes.account_routes", None, None),

        # CART / CHECKOUT
        ("app.routes.cart_routes", None, None),
        ("app.routes.checkout_routes", None, None),

        # API / AFFILIATE
        ("app.routes.api_routes", None, None),
        ("app.routes.affiliate_routes", None, None),

        # MARKETING
        ("app.routes.marketing_routes", None, None),

        # WEBHOOKS
        ("app.routes.webhook_routes", None, None),

        # ADMIN
        ("app.routes.admin_routes", None, None),
        ("app.routes.admin_payments_routes", None, None),

        # PRINTFUL
        ("app.routes.printful_routes", None, None),
    ]


def _use_default_specs() -> bool:
    """
    ROUTES_PRIORITY_DEFAULTS=0/false/no => no usa _default_specs()
    """
    raw = (os.getenv("ROUTES_PRIORITY_DEFAULTS") or "").strip().lower()
    if raw in _FALSE:
        return False
    return True


# =============================================================================
# Public API
# =============================================================================
def register_blueprints(app: "Flask") -> Dict[str, Any]:
    """
    Registro final:
    1) specs prioritarios (orden recomendado)
    2) auto-scan: registra TODO blueprint restante
    """
    t0 = time.perf_counter()
    _maybe_bust_caches()

    strict = _strict_mode(app)
    disabled_patterns = _disabled_patterns()
    scan_exclude = _scan_exclude_patterns()
    scan_only_mods = _scan_only_modules()
    required = _required_names()
    allowed = _allowed_names()
    scan_only = _env_bool("ROUTES_SCAN_ONLY", False)

    seen_names: Set[str] = set()
    seen_origins: Set[str] = set()
    seen_ids: Set[int] = set()
    seen_modsym: Set[str] = set()

    report: Dict[str, Any] = {
        "registered": [],
        "missing": [],
        "invalid": [],
        "duplicate": [],
        "failed_register": [],
        "disabled": [],
        "required_missing": [],
        "required_have": [],
        "scan_registered": [],
        "scan_skipped": [],
        "imports_failed": [],
        "timing_ms": 0,
        "counts": {},
        "strict": strict,
        "map": {},
    }

    # -----------------------------------------
    # 1) PRIORIDAD
    # -----------------------------------------
    specs: List[Tuple[str, Optional[str], Optional[str]]] = []
    if _use_default_specs():
        specs.extend(_default_specs())

    for m in _priority_modules():
        specs.append((m, None, None))

    if not scan_only:
        for mod, symbol, pref in specs:
            pairs, err = _import_symbol_or_all(mod, symbol)
            if not pairs:
                report["missing"].append(f"{mod}.{symbol or '*'}" + (f" :: {err}" if err else ""))
                if err:
                    report["imports_failed"].append(f"{mod} :: {err}")
                continue

            for bp, sym in pairs:
                origin = f"{mod}.{sym}"
                _register_bp(
                    app,
                    bp,
                    origin=origin,
                    symbol=sym,
                    seen_names=seen_names,
                    seen_origins=seen_origins,
                    seen_ids=seen_ids,
                    seen_modsym=seen_modsym,
                    report=report,
                    url_prefix=pref,
                    disabled_patterns=disabled_patterns,
                    allowed_names=allowed,
                )

    # -----------------------------------------
    # 2) AUTO-SCAN
    # -----------------------------------------
    for mod in _scan_route_modules(scan_exclude, scan_only_mods):
        pairs, err = _import_symbol_or_all(mod, None)
        if not pairs:
            report["scan_skipped"].append(mod + (f" :: {err}" if err else ""))
            if err:
                report["imports_failed"].append(f"{mod} :: {err}")
            continue

        for bp, sym in pairs:
            origin = f"{mod}.{sym}"
            before = len(report["registered"])
            _register_bp(
                app,
                bp,
                origin=origin,
                symbol=sym,
                seen_names=seen_names,
                seen_origins=seen_origins,
                seen_ids=seen_ids,
                seen_modsym=seen_modsym,
                report=report,
                url_prefix=None,
                disabled_patterns=disabled_patterns,
                allowed_names=allowed,
            )
            if len(report["registered"]) > before:
                report["scan_registered"].append(origin)

    # -----------------------------------------
    # REQUIRED CHECK (por bp.name real)
    # -----------------------------------------
    if required:
        have = {x.split(" <- ", 1)[0].strip().lower() for x in report["registered"]}
        report["required_have"] = sorted(have)
        miss = sorted(required - have)
        if miss:
            report["required_missing"] = miss
            if strict:
                raise RuntimeError(f"ROUTES_REQUIRE faltantes: {', '.join(miss)}")
            log.warning("⚠️ ROUTES_REQUIRE faltantes: %s", ", ".join(miss))

    # -----------------------------------------
    # LOGS RESUMIDOS
    # -----------------------------------------
    try:
        reg_names = [x.split(" <- ", 1)[0] for x in report["registered"]]
        log.info(
            "✅ Blueprints registrados (%d): %s",
            len(reg_names),
            ", ".join(reg_names) if reg_names else "(ninguno)",
        )

        if report["scan_registered"]:
            log.info("🧭 Auto-scan registrados (%d)", len(report["scan_registered"]))

        if report["disabled"]:
            log.info("⛔ Disabled (ENV): %d", len(report["disabled"]))

        if report["failed_register"]:
            log.warning("⚠️ Fallos al registrar (%d)", len(report["failed_register"]))

        if report["imports_failed"] and _routes_debug():
            uniq = sorted(set(report["imports_failed"]))
            report["imports_failed"] = uniq
            log.debug("🧩 Imports fallidos (%d): %s", len(uniq), "; ".join(uniq))
    except Exception:
        pass

    report["timing_ms"] = int((time.perf_counter() - t0) * 1000)
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
