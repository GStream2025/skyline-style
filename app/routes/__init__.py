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
    "app.routes.admin_payments_routes",
    "app.routes.printful_routes",
    "app.routes.address_routes",
    "app.routes.profile_routes",
    "app.routes.webhook_routes",
)

_DEFAULT_SCAN_EXCLUDE: Tuple[str, ...] = (
    "*.__pycache__*",
    "*migrations*",
    "*tests*",
    "*test_*",
    "*_test*",
)

# Seguridad: jamás escaneamos fuera del paquete de routes
_ROUTES_PACKAGE = "app.routes"


def _s(v: Any) -> str:
    return "" if v is None else str(v).strip()


def _env_str(key: str, default: str = "") -> str:
    v = os.getenv(key)
    return _s(v) if v is not None else _s(default)


def _env_bool(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    s = _s(v).lower()
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
        s = _s(x).lower()
        if s:
            out.append(s)
    return out


def _dedupe_keep_order(items: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for x in items:
        s = _s(x)
        if not s:
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def _match(value: str, patterns: Iterable[str]) -> bool:
    v = _s(value).lower()
    if not v:
        return False
    for p in patterns:
        pat = _s(p).lower()
        if not pat:
            continue
        try:
            if fnmatch.fnmatch(v, pat):
                return True
        except Exception:
            # patrón inválido -> lo ignoramos de forma segura
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
    # 1) por-bp: ROUTES_PREFIX_<BP_NAME>
    bp_specific = os.getenv(f"ROUTES_PREFIX_{_bp_env_key(bp_name)}")
    p = _normalize_prefix(bp_specific)
    if p is not None:
        return p
    # 2) global default: ROUTES_PREFIX_DEFAULT (si está)
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
    # Detecta:
    # - blueprint directo: bp
    # - lista/tupla/set de blueprints
    # - dict con valores blueprint
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
    merged_exclude = _dedupe_keep_order([*(exclude or []), *_DEFAULT_SCAN_EXCLUDE])
    out: List[str] = []

    try:
        pkg = importlib.import_module(_ROUTES_PACKAGE)
        pkg_path = getattr(pkg, "__path__", None)
        if not pkg_path:
            return []

        for m in pkgutil.iter_modules(pkg_path, _ROUTES_PACKAGE + "."):
            mod_name = _s(m.name)
            low = mod_name.lower()
            if not mod_name or low.endswith(".__init__"):
                continue
            if _match(low, merged_exclude):
                continue
            out.append(mod_name)
            if max_modules and len(out) >= max_modules:
                break
    except Exception as e:
        log.error("Route scan failed: %s", e, exc_info=True)

    return sorted(_dedupe_keep_order(out))


def _should_skip_module(mod_path: str, disable: List[str], allow_specs: Set[str]) -> bool:
    low = _s(mod_path).lower()
    if not low:
        return True

    # Seguridad: solo permitimos módulos dentro de app.routes.*
    if not (low == _ROUTES_PACKAGE or low.startswith(_ROUTES_PACKAGE + ".")):
        return True

    if allow_specs and low not in allow_specs:
        return True
    if _match(low, disable):
        return True
    return False


def _should_skip_bp(bp_name: str, origin: str, disable: List[str], allow_bps: Set[str]) -> bool:
    name_low = _s(bp_name).lower()
    origin_low = _s(origin).lower()
    if not name_low:
        return True
    if allow_bps and name_low not in allow_bps:
        return True
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


@dataclass(frozen=True)
class RoutesReport:
    registered: List[str]
    duplicates: List[str]
    disabled: List[str]
    skipped_no_blueprint: List[str]
    imports_failed: List[str]
    missing_required: List[str]
    timing_ms: int
    scanned: bool
    specs_count: int
    fail_fast: bool
    strict_require: bool
    errors_total: int


def register_blueprints(app: Any) -> Dict[str, Any]:
    """
    Registra blueprints desde módulos en app.routes.* con hardening:
    - allow/disable/require por env
    - scan opcional + excludes
    - prefijos por blueprint o default
    - modo fail-fast / strict-require opcional
    """
    t0 = time.perf_counter()

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

    specs: List[str] = list(_DEFAULT_SPECS)
    scanned = False
    if scan_enabled:
        scanned = True
        specs.extend(_scan_route_modules(scan_exclude, max_modules=max_scan))

    specs = _dedupe_keep_order(specs)

    registered: List[str] = []
    duplicates: List[str] = []
    disabled_out: List[str] = []
    skipped_no_bp: List[str] = []
    imports_failed: List[str] = []

    # Estado inicial
    try:
        initial_bp_names = set((app.blueprints or {}).keys())
    except Exception:
        initial_bp_names = set()

    # Control interno por lower para evitar bugs de mayúsculas/minúsculas
    seen_bp_real: Set[str] = { _s(x) for x in initial_bp_names if _s(x) }
    seen_bp_low: Set[str] = { x.lower() for x in seen_bp_real }

    for mod_path in specs:
        if _should_skip_module(mod_path, disable, allow_specs):
            disabled_out.append(f"{mod_path} :: module-disabled")
            continue

        mod, err = _import_module(mod_path)
        if err or mod is None:
            msg = f"{mod_path} :: {err or 'import failed'}"
            imports_failed.append(msg)
            log.error("IMPORT FAILED %s", msg, exc_info=False)
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

            # Duplicado por nombre (case-insensitive)
            if bp_name_low in seen_bp_low:
                duplicates.append(origin)
                continue

            prefix = _env_prefix_for(bp_name_real, default_prefix=default_prefix_norm)
            reg_err = _safe_register(app, bp, prefix)
            if reg_err:
                msg = f"{origin} :: {reg_err}"
                imports_failed.append(msg)
                log.error("Blueprint register failed %s", msg, exc_info=False)
                if fail_fast:
                    raise RuntimeError(f"Routes register failed: {msg}")
                continue

            seen_bp_real.add(bp_name_real)
            seen_bp_low.add(bp_name_low)
            registered.append(origin)

        if not found_any:
            skipped_no_bp.append(f"{mod_path} :: no-blueprint")

    missing_required = sorted(x for x in require if x and x not in seen_bp_low)

    timing_ms = int((time.perf_counter() - t0) * 1000)
    errors_total = len(imports_failed) + len(missing_required)

    log.info(
        "✅ Routes ready | registered=%d | dup=%d | disabled=%d | no_bp=%d | imports_failed=%d | missing_required=%d | scanned=%s | specs=%d | %dms",
        len(registered),
        len(duplicates),
        len(disabled_out),
        len(skipped_no_bp),
        len(imports_failed),
        len(missing_required),
        scanned,
        len(specs),
        timing_ms,
    )

    if duplicates:
        log.warning("⚠ Duplicate blueprint names (skipped): %s", ", ".join(duplicates[:15]))
    if skipped_no_bp:
        log.warning("⚠ Modules with no blueprint found: %s", ", ".join(skipped_no_bp[:15]))
    if missing_required:
        log.warning("⚠ Missing required blueprints: %s", ", ".join(missing_required))

    if strict_require and missing_required:
        raise RuntimeError(f"Missing required blueprints: {', '.join(missing_required)}")

    report = RoutesReport(
        registered=registered,
        duplicates=duplicates,
        disabled=disabled_out,
        skipped_no_blueprint=skipped_no_bp,
        imports_failed=imports_failed,
        missing_required=missing_required,
        timing_ms=timing_ms,
        scanned=scanned,
        specs_count=len(specs),
        fail_fast=fail_fast,
        strict_require=strict_require,
        errors_total=errors_total,
    ).__dict__

    # Opcional: lo dejamos accesible desde app.extensions
    try:
        ext = getattr(app, "extensions", None)
        if isinstance(ext, dict):
            ext["routes_report"] = report
    except Exception:
        pass

    return report


__all__ = ["register_blueprints"]
