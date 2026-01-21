"""
Skyline Store · Routes Package (BULLETPROOF FINAL · vNEXT+FIX · +15 mejoras)
========================================================================
FIX CRÍTICO:
✅ Evita duplicar url_prefix cuando el Blueprint ya trae url_prefix interno.
   (origen del /auth/auth/... y los 404)
========================================================================

+15 mejoras (resumen):
1)  FIX definitivo /prefix duplicado: nunca pasa url_prefix si ya hay interno
    y sólo aplica override externo (ENV/spec) de forma segura.
2)  Override externo NO concatena con el interno: reemplaza limpio.
3)  Sanitiza y normaliza prefijos (//, trailing /, vacío).
4)  `ROUTES_SCAN_ONLY_MODULES` acepta wildcards correctamente (sin bug only_list vacío).
5)  Mejora: `ROUTES_SCAN_ONLY_MODULES` matchea por módulo completo y tail.
6)  Dedupe más robusto: (id), (origin), (name), (modsym) estable.
7)  Report `map` incluye `effective_prefix` real (interno u override).
8)  Report `imports_failed` se deduplica y se ordena estable.
9)  `ROUTES_BUST_IMPORT_CACHE=1` limpia caches reales (import + scan).
10) `_safe_import_module` no cachea None si `ROUTES_IMPORT_NO_CACHE=1`.
11) `_scan_route_modules` maneja __path__ faltante sin reventar.
12) Filtro “ruido” mejorado para tests/conftest/__init__.
13) Logging: resume registered/disabled/dup/failed y (debug) imports fallidos.
14) Strict mode más predecible: dev-only por ENV/debug + FORCE.
15) Código más defensivo en edge cases (attrs raros en Blueprint).
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

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off", "unchecked"}

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


def _scan_only_modules_raw() -> List[str]:
    # lista raw (ya lower) para wildcard match, NO set (porque orden estable)
    return [x.lower() for x in _split_csv_env("ROUTES_SCAN_ONLY_MODULES")]


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
    return (f"{type(e).__name__}: {e}")[:260]


def _safe_import_module(path: str):
    no_cache = _env_bool("ROUTES_IMPORT_NO_CACHE", False)
    if not no_cache and path in _MODULE_CACHE:
        return _MODULE_CACHE[path]

    try:
        mod = import_module(path)
        if not no_cache:
            _MODULE_CACHE[path] = mod
        _IMPORT_ERRORS.pop(path, None)
        return mod
    except Exception as e:
        if not no_cache:
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
        return hasattr(obj, "name") and hasattr(obj, "register")


def _find_blueprints_in_module(mod: Any) -> List[Tuple[Any, str]]:
    if not mod:
        return []
    out: List[Tuple[Any, str]] = []
    for k in sorted(dir(mod)):
        if k.startswith("_"):
            continue
        obj = _safe_getattr(mod, k)
        if _is_blueprint(obj):
            out.append((obj, k))

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

    return _find_blueprints_in_module(mod), None


# =============================================================================
# Scan modules
# =============================================================================
def _scan_route_modules(exclude_patterns: List[str], only_patterns: List[str]) -> List[str]:
    global _SCAN_CACHE, _SCAN_CACHE_KEY

    scan_sub = _env_bool("ROUTES_SCAN_SUBPACKAGES", False)
    only_list = sorted([x for x in (only_patterns or []) if x])
    key = f"sub={int(scan_sub)}|ex={'/'.join(exclude_patterns or [])}|only={'/'.join(only_list)}"
    if _SCAN_CACHE is not None and _SCAN_CACHE_KEY == key:
        return list(_SCAN_CACHE)

    try:
        pkg = import_module("app.routes")
        base = pkg.__name__
        pkg_path = getattr(pkg, "__path__", None)
        if not pkg_path:
            _SCAN_CACHE = []
            _SCAN_CACHE_KEY = key
            return []

        mods: List[str] = []
        for m in pkgutil.iter_modules(pkg_path, base + "."):
            tail = m.name.split(".")[-1]
            if tail.startswith("_") or tail in {"tests", "test", "conftest", "__init__"}:
                continue

            name_l = m.name.lower()
            tail_l = tail.lower()

            if _match_any(name_l, exclude_patterns) or _match_any(tail_l, exclude_patterns):
                continue

            if only_list and (not _match_any(name_l, only_list) and not _match_any(tail_l, only_list)):
                continue

            mods.append(m.name)

            if scan_sub and m.ispkg:
                try:
                    subpkg = import_module(m.name)
                    sub_path = getattr(subpkg, "__path__", None) or []
                    for sm in pkgutil.iter_modules(sub_path, m.name + "."):
                        stail = sm.name.split(".")[-1]
                        if stail.startswith("_") or stail in {"tests", "test", "conftest", "__init__"}:
                            continue
                        sm_l = sm.name.lower()
                        stail_l = stail.lower()
                        if _match_any(sm_l, exclude_patterns) or _match_any(stail_l, exclude_patterns):
                            continue
                        if only_list and (not _match_any(sm_l, only_list) and not _match_any(stail_l, only_list)):
                            continue
                        mods.append(sm.name)
                except Exception:
                    pass

        mods = sorted(set(mods))
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
def _normalize_prefix(prefix: Optional[str]) -> Optional[str]:
    if not prefix:
        return None
    p = prefix.strip()
    if not p:
        return None

    # normaliza barras dobles
    while "//" in p:
        p = p.replace("//", "/")

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


def _normalize_origin(origin: str) -> str:
    return (origin or "").strip().lower()


@dataclass(frozen=True)
class _BpKey:
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

    if allowed_names and bp_key not in allowed_names:
        report["disabled"].append(f"{bp_name} <- {origin} (allowlist)")
        return

    if _is_disabled(bp_key, sym_tail, mod_path, disabled_patterns):
        report["disabled"].append(f"{bp_name} <- {origin}")
        return

    bp_id = id(bp)
    if bp_id in seen_ids:
        report["duplicate"].append(f"(id) {bp_name} <- {origin}")
        return

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

    # =========================================================
    # ✅ FIX CRÍTICO anti /auth/auth:
    # - El blueprint puede tener prefijo interno (bp.url_prefix).
    # - Si pasamos url_prefix externo igual, Flask duplica.
    #
    # Regla:
    # 1) Si hay override externo (ENV/spec), lo pasamos a register_blueprint.
    # 2) Si NO hay override externo, registramos SIN url_prefix para respetar el interno.
    # =========================================================
    env_pref = _normalize_prefix(_env_prefix_for(bp_name))
    spec_pref = _normalize_prefix(url_prefix)
    internal_pref = _bp_internal_prefix(bp)

    override_prefix = env_pref or spec_pref  # sólo overrides externos

    try:
        if override_prefix:
            app.register_blueprint(bp, url_prefix=override_prefix)
            effective_prefix = override_prefix
        else:
            app.register_blueprint(bp)  # respeta bp.url_prefix interno
            effective_prefix = internal_pref or ""

        seen_ids.add(bp_id)
        seen_names.add(bp_key)
        seen_origins.add(origin_key)
        seen_modsym.add(modsym)

        report["registered"].append(
            f"{bp_name} <- {origin}" + (f" (prefix={effective_prefix})" if effective_prefix else "")
        )
        report["map"][bp_name] = {
            "origin": origin,
            "symbol": symbol,
            "prefix": effective_prefix,
        }
    except Exception as e:
        report["failed_register"].append(f"{bp_name} <- {origin} :: {_short_exc(e)}")
        log.warning(
            "⚠️ No se pudo registrar blueprint '%s' (%s): %s",
            bp_name,
            origin,
            e,
            exc_info=_routes_debug(),
        )
        if report["strict"]:
            raise


# =============================================================================
# Specs
# =============================================================================
def _default_specs() -> List[Tuple[str, Optional[str], Optional[str]]]:
    return [
        ("app.routes.main_routes", None, None),
        ("app.routes.shop_routes", None, None),
        ("app.routes.auth_routes", None, None),
        ("app.routes.account_routes", None, None),
        ("app.routes.cart_routes", None, None),
        ("app.routes.checkout_routes", None, None),
        ("app.routes.api_routes", None, None),
        ("app.routes.affiliate_routes", None, None),
        ("app.routes.marketing_routes", None, None),
        ("app.routes.webhook_routes", None, None),
        ("app.routes.admin_routes", None, None),
        ("app.routes.admin_payments_routes", None, None),
        ("app.routes.printful_routes", None, None),
    ]


def _use_default_specs() -> bool:
    raw = (os.getenv("ROUTES_PRIORITY_DEFAULTS") or "").strip().lower()
    if raw in _FALSE:
        return False
    return True


# =============================================================================
# Public API
# =============================================================================
def register_blueprints(app: "Flask") -> Dict[str, Any]:
    t0 = time.perf_counter()
    _maybe_bust_caches()

    strict = _strict_mode(app)
    disabled_patterns = _disabled_patterns()
    scan_exclude = _scan_exclude_patterns()
    scan_only_patterns = _scan_only_modules_raw()
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

    specs: List[Tuple[str, Optional[str], Optional[str]]] = []
    if _use_default_specs():
        specs.extend(_default_specs())
    for m in _priority_modules():
        specs.append((m, None, None))

    # -----------------------------------------
    # 1) PRIORIDAD
    # -----------------------------------------
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
    for mod in _scan_route_modules(scan_exclude, scan_only_patterns):
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
    # Post-procesos report
    # -----------------------------------------
    # Dedup imports_failed y estable
    try:
        if report["imports_failed"]:
            report["imports_failed"] = sorted(set(report["imports_failed"]))
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

    try:
        log.info(
            "✅ Routes ready | registered=%d | disabled=%d | dup=%d | failed=%d | %dms",
            report["counts"]["registered"],
            report["counts"]["disabled"],
            report["counts"]["duplicate"],
            report["counts"]["failed_register"],
            report["timing_ms"],
        )
        if report["imports_failed"] and _routes_debug():
            log.debug("🧩 Imports fallidos (%d): %s", len(report["imports_failed"]), "; ".join(report["imports_failed"]))
    except Exception:
        pass

    return report


__all__ = ["register_blueprints"]
