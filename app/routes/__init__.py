from __future__ import annotations

import fnmatch
import importlib
import logging
import os
import pkgutil
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

log = logging.getLogger("routes")

_TRUE: Set[str] = {"1", "true", "yes", "y", "on", "checked"}
_FALSE: Set[str] = {"0", "false", "no", "n", "off", "unchecked"}

# ✅ ALINEADO con tu tree real: incluye admin_auth_routes
_DEFAULT_SPECS: Tuple[str, ...] = (
    "app.routes.main_routes",
    "app.routes.shop_routes",
    "app.routes.auth_routes",
    "app.routes.account_routes",
    "app.routes.cart_routes",
    "app.routes.checkout_routes",
    "app.routes.api_routes",
    "app.routes.affiliate_routes",
    "app.routes.marketing_routes",
    "app.routes.admin_routes",
    "app.routes.admin_auth_routes",
    "app.routes.admin_payments_routes",
    "app.routes.printful_routes",
    "app.routes.address_routes",
    "app.routes.profile_routes",
    "app.routes.webhook_routes",
)

# ✅ patterns corregidos (sin el punto raro "*.__pycache__*")
_DEFAULT_SCAN_EXCLUDE: Tuple[str, ...] = (
    "*__pycache__*",
    "*migrations*",
    "*tests*",
    "*test_*",
    "*_test*",
)

_ROUTES_PACKAGE = "app.routes"


def _s(v: Any) -> str:
    return "" if v is None else str(v).strip()


def _low(v: Any) -> str:
    return _s(v).lower()


def _env_str(key: str, default: str = "") -> str:
    v = os.getenv(key)
    return _s(v) if v is not None else _s(default)


def _env_bool(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    s = _low(v)
    if not s:
        return default
    if s in _FALSE:
        return False
    if s in _TRUE:
        return True
    return default


def _env_int(key: str, default: int, *, min_value: int = 0, max_value: int = 10_000) -> int:
    raw = _env_str(key, "")
    if not raw:
        return default
    try:
        n = int(raw)
    except Exception:
        return default
    if n < min_value:
        return min_value
    if n > max_value:
        return max_value
    return n


def _split_csv(key: str) -> List[str]:
    raw = _env_str(key, "")
    if not raw:
        return []
    out: List[str] = []
    for x in raw.split(","):
        s = _low(x)
        if s:
            out.append(s)
    return out


def _dedupe_keep_order(items: Iterable[str], *, lower: bool = False) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for x in items:
        s = _s(x)
        if not s:
            continue
        k = s.lower() if lower else s
        if k in seen:
            continue
        seen.add(k)
        out.append(s)
    return out


def _match(value: str, patterns: Iterable[str]) -> bool:
    v = _low(value)
    if not v:
        return False
    for p in patterns:
        pat = _low(p)
        if not pat:
            continue
        try:
            if fnmatch.fnmatch(v, pat):
                return True
        except Exception:
            continue
    return False


def _bp_env_key(bp_name: str) -> str:
    return _s(bp_name or "BLUEPRINT").upper().replace("-", "_").replace(" ", "_")


def _normalize_prefix(prefix: Optional[str]) -> Optional[str]:
    if prefix is None:
        return None
    p = _s(prefix)
    if not p:
        return None
    p = "/" + p.lstrip("/")
    if p != "/":
        p = p.rstrip("/")
    return p


def _env_prefix_for(bp_name: str, *, default_prefix: Optional[str]) -> Optional[str]:
    bp_specific = os.getenv(f"ROUTES_PREFIX_{_bp_env_key(bp_name)}")
    p = _normalize_prefix(bp_specific)
    if p is not None:
        return p
    return _normalize_prefix(default_prefix)


def _is_blueprint(obj: Any) -> bool:
    try:
        from flask.blueprints import Blueprint

        return isinstance(obj, Blueprint)
    except Exception:
        return False


def _import_module(path: str) -> Tuple[Optional[Any], Optional[str]]:
    try:
        return importlib.import_module(path), None
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def _iter_blueprints_in_module(mod: Any) -> Iterable[Tuple[Any, str]]:
    """
    Detecta:
      - blueprint directo
      - lista/tupla/set de blueprints
      - dict con values blueprint
    """
    for name in dir(mod):
        if name.startswith("_"):
            continue
        try:
            obj = getattr(mod, name)
        except Exception:
            continue

        if _is_blueprint(obj):
            yield obj, name
            continue

        if isinstance(obj, dict):
            for k, v in list(obj.items()):
                if _is_blueprint(v):
                    yield v, f"{name}[{_s(k)}]"
            continue

        if isinstance(obj, (list, tuple, set)):
            for i, item in enumerate(list(obj)):
                if _is_blueprint(item):
                    yield item, f"{name}[{i}]"


def _scan_route_modules(exclude: List[str], *, max_modules: int) -> List[str]:
    merged_exclude = _dedupe_keep_order([*(exclude or []), *_DEFAULT_SCAN_EXCLUDE], lower=True)
    out: List[str] = []

    try:
        pkg = importlib.import_module(_ROUTES_PACKAGE)
        pkg_path = getattr(pkg, "__path__", None)
        if not pkg_path:
            return []

        for m in pkgutil.iter_modules(pkg_path, _ROUTES_PACKAGE + "."):
            mod_name = _s(m.name)
            low = mod_name.lower()
            # iter_modules ya devuelve módulos; no hace falta chequear __init__ con ".__init__"
            if not mod_name:
                continue
            if _match(low, merged_exclude):
                continue
            out.append(mod_name)
            if max_modules and len(out) >= max_modules:
                break
    except Exception as e:
        log.error("Route scan failed: %s", e, exc_info=True)

    return sorted(_dedupe_keep_order(out, lower=True))


def _should_skip_module(mod_path: str, disable: List[str], allow_specs: Set[str]) -> bool:
    low = _low(mod_path)
    if not low:
        return True

    # 🔒 Seguridad: solo permitimos módulos dentro de app.routes.*
    if not (low == _ROUTES_PACKAGE or low.startswith(_ROUTES_PACKAGE + ".")):
        return True

    if allow_specs and low not in allow_specs:
        return True

    # allow/disable son patterns: aplicamos sobre el módulo completo
    if _match(low, disable):
        return True

    return False


def _should_skip_bp(bp_name: str, origin: str, disable: List[str], allow_bps: Set[str]) -> bool:
    name_low = _low(bp_name)
    origin_low = _low(origin)
    if not name_low:
        return True

    if allow_bps and name_low not in allow_bps:
        return True

    # disable patterns aplican a: nombre de bp o origen completo (mod.sym)
    if _match(name_low, disable) or _match(origin_low, disable):
        return True

    return False


def _safe_register(app: Any, bp: Any, prefix: Optional[str]) -> Optional[str]:
    try:
        if prefix is None:
            app.register_blueprint(bp)
        else:
            app.register_blueprint(bp, url_prefix=prefix)
        return None
    except Exception as e:
        return f"{type(e).__name__}: {e}"


def _now_ms(start_perf: float) -> int:
    return int((time.perf_counter() - start_perf) * 1000)


def _short_list(items: List[str], limit: int = 12) -> str:
    if not items:
        return "-"
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f" …(+{len(items) - limit})"


@dataclass(frozen=True)
class RoutesReport:
    registered: List[str]
    duplicates: List[str]
    disabled: List[str]
    skipped_no_blueprint: List[str]
    import_failed: List[str]
    register_failed: List[str]
    missing_required: List[str]
    timing_ms: int
    scanned: bool
    specs_count: int
    fail_fast: bool
    strict_require: bool
    errors_total: int
    warnings_total: int
    initial_blueprints: List[str]


def register_blueprints(app: Any) -> Dict[str, Any]:
    """
    Registro robusto de blueprints (app.routes.*) con hardening y observabilidad PRO.

    ENV:
      - ROUTES_DISABLE: csv patterns (aplica a módulos, bp name o origin)
      - ROUTES_ALLOW: csv blueprint names (lower)
      - ROUTES_ALLOW_SPECS: csv module paths (lower)
      - ROUTES_REQUIRE: csv blueprint names (lower)
      - ROUTES_SCAN: true/false
      - ROUTES_SCAN_EXCLUDE: csv patterns
      - ROUTES_SCAN_MAX: int
      - ROUTES_FAIL_FAST: true/false (crashea ante import/register error)
      - ROUTES_STRICT_REQUIRE: true/false (crashea si faltan required)
      - ROUTES_PREFIX_DEFAULT: "/x" (opcional)
      - ROUTES_PREFIX_<BP_NAME>: "/x" (opcional)
      - ROUTES_LOG_LEVEL: debug/info/warning/error/critical (opcional)
      - ROUTES_LOG_SUMMARY: true/false (default true)
    """
    t0 = time.perf_counter()

    # Ajuste de log nivel solo para este logger
    log_level = _env_str("ROUTES_LOG_LEVEL", "").lower()
    if log_level in {"debug", "info", "warning", "error", "critical"}:
        try:
            log.setLevel(getattr(logging, log_level.upper()))
        except Exception:
            pass

    disable = _split_csv("ROUTES_DISABLE")
    allow_bps = {x for x in _split_csv("ROUTES_ALLOW") if x}
    allow_specs = {x for x in _split_csv("ROUTES_ALLOW_SPECS") if x}
    require = {x for x in _split_csv("ROUTES_REQUIRE") if x}

    scan_enabled = _env_bool("ROUTES_SCAN", False)
    scan_exclude = _split_csv("ROUTES_SCAN_EXCLUDE")
    max_scan = _env_int("ROUTES_SCAN_MAX", 250, min_value=0, max_value=5000)

    fail_fast = _env_bool("ROUTES_FAIL_FAST", False)
    strict_require = _env_bool("ROUTES_STRICT_REQUIRE", False)

    prefix_default = _env_str("ROUTES_PREFIX_DEFAULT", "")
    default_prefix_norm = _normalize_prefix(prefix_default)

    # Estado inicial (para report y para dedupe)
    try:
        initial_bp_names = sorted([_s(k) for k in (app.blueprints or {}).keys() if _s(k)])
    except Exception:
        initial_bp_names = []

    seen_bp_low: Set[str] = {x.lower() for x in initial_bp_names if x}

    # Specs base + scan opcional
    specs: List[str] = list(_DEFAULT_SPECS)
    scanned = False
    if scan_enabled:
        scanned = True
        specs.extend(_scan_route_modules(scan_exclude, max_modules=max_scan))
    specs = _dedupe_keep_order(specs, lower=True)

    registered: List[str] = []
    duplicates: List[str] = []
    disabled_out: List[str] = []
    skipped_no_bp: List[str] = []
    import_failed: List[str] = []
    register_failed: List[str] = []

    for mod_path in specs:
        if _should_skip_module(mod_path, disable, allow_specs):
            disabled_out.append(f"{mod_path} :: module-disabled")
            continue

        mod, err = _import_module(mod_path)
        if err or mod is None:
            msg = f"{mod_path} :: {err or 'import failed'}"
            import_failed.append(msg)
            log.error("IMPORT FAILED %s", msg, exc_info=True)
            if fail_fast:
                raise RuntimeError(f"Routes import failed: {msg}")
            continue

        found_any = False

        for bp, sym in _iter_blueprints_in_module(mod):
            found_any = True

            bp_name_real = _s(getattr(bp, "name", "") or "")
            bp_name_low = bp_name_real.lower()
            origin = f"{mod_path}.{sym}"

            if _should_skip_bp(bp_name_real, origin, disable, allow_bps):
                disabled_out.append(origin)
                continue

            if not bp_name_low:
                disabled_out.append(f"{origin} :: empty-blueprint-name")
                continue

            if bp_name_low in seen_bp_low:
                duplicates.append(origin)
                continue

            prefix = _env_prefix_for(bp_name_real, default_prefix=default_prefix_norm)
            reg_err = _safe_register(app, bp, prefix)
            if reg_err:
                msg = f"{origin} :: {reg_err}"
                register_failed.append(msg)
                log.error("REGISTER FAILED %s", msg, exc_info=True)
                if fail_fast:
                    raise RuntimeError(f"Routes register failed: {msg}")
                continue

            seen_bp_low.add(bp_name_low)
            registered.append(origin)

        if not found_any:
            skipped_no_bp.append(f"{mod_path} :: no-blueprint")

    missing_required = sorted(x for x in require if x and x not in seen_bp_low)

    timing_ms = _now_ms(t0)
    errors_total = len(import_failed) + len(register_failed) + len(missing_required)
    warnings_total = len(duplicates) + len(skipped_no_bp)

    summary_on = _env_bool("ROUTES_LOG_SUMMARY", True)

    log.info(
        "✅ Routes ready | reg=%d | dup=%d | disabled=%d | no_bp=%d | import_fail=%d | register_fail=%d | missing_req=%d | scanned=%s | specs=%d | %dms",
        len(registered),
        len(duplicates),
        len(disabled_out),
        len(skipped_no_bp),
        len(import_failed),
        len(register_failed),
        len(missing_required),
        scanned,
        len(specs),
        timing_ms,
    )

    if summary_on:
        if registered:
            log.debug("🧩 Registered: %s", _short_list(registered, 10))
        if duplicates:
            log.warning("⚠ Duplicates (skipped): %s", _short_list(duplicates, 12))
        if skipped_no_bp:
            log.warning("⚠ No blueprint in module: %s", _short_list(skipped_no_bp, 12))
        if import_failed:
            log.error("❌ Import failed: %s", _short_list(import_failed, 8))
        if register_failed:
            log.error("❌ Register failed: %s", _short_list(register_failed, 8))
        if missing_required:
            log.warning("⛔ Missing required: %s", ", ".join(missing_required))

    if strict_require and missing_required:
        raise RuntimeError(f"Missing required blueprints: {', '.join(missing_required)}")

    report = RoutesReport(
        registered=registered,
        duplicates=duplicates,
        disabled=disabled_out,
        skipped_no_blueprint=skipped_no_bp,
        import_failed=import_failed,
        register_failed=register_failed,
        missing_required=missing_required,
        timing_ms=timing_ms,
        scanned=scanned,
        specs_count=len(specs),
        fail_fast=fail_fast,
        strict_require=strict_require,
        errors_total=errors_total,
        warnings_total=warnings_total,
        initial_blueprints=initial_bp_names,
    ).__dict__

    # Guardamos para debugging rápido (sin romper si no existe)
    try:
        ext = getattr(app, "extensions", None)
        if isinstance(ext, dict):
            ext["routes_report"] = report
    except Exception:
        pass

    return report


__all__ = ["register_blueprints"]
