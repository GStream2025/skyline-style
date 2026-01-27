from __future__ import annotations

import fnmatch
import importlib
import logging
import os
import pkgutil
import time
from dataclasses import dataclass
from typing import Any, Iterable, List, Optional, Set, Tuple

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


def _env_str(key: str, default: str = "") -> str:
    return (os.getenv(key) or default).strip()


def _env_bool(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    s = str(v).strip().lower()
    if not s:
        return default
    if s in _FALSE:
        return False
    if s in _TRUE:
        return True
    return default


def _split_csv(key: str) -> List[str]:
    raw = _env_str(key, "")
    out: List[str] = []
    for x in raw.split(","):
        s = x.strip()
        if s:
            out.append(s.lower())
    return out


def _match(value: str, patterns: List[str]) -> bool:
    v = (value or "").strip().lower()
    if not v or not patterns:
        return False
    for p in patterns:
        try:
            if fnmatch.fnmatch(v, p):
                return True
        except Exception:
            continue
    return False


def _bp_env_key(bp_name: str) -> str:
    return (bp_name or "BLUEPRINT").upper().replace("-", "_").replace(" ", "_")


def _normalize_prefix(prefix: Optional[str]) -> Optional[str]:
    if prefix is None:
        return None
    p = str(prefix).strip()
    if not p:
        return None
    p = "/" + p.lstrip("/")
    if p != "/":
        p = p.rstrip("/")
    return p


def _env_prefix_for(bp_name: str) -> Optional[str]:
    return _normalize_prefix(os.getenv(f"ROUTES_PREFIX_{_bp_env_key(bp_name)}"))


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

        if isinstance(obj, (list, tuple)):
            for i, item in enumerate(obj):
                if _is_blueprint(item):
                    yield item, f"{name}[{i}]"


def _dedupe_keep_order(items: List[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for x in items:
        if not x:
            continue
        if not isinstance(x, str):
            x = str(x)
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def _scan_route_modules(exclude: List[str]) -> List[str]:
    out: Set[str] = set()
    merged_exclude = _dedupe_keep_order([*(exclude or []), *_DEFAULT_SCAN_EXCLUDE])

    try:
        pkg = importlib.import_module("app.routes")
        pkg_path = getattr(pkg, "__path__", None)
        if not pkg_path:
            return []

        for m in pkgutil.iter_modules(pkg_path, "app.routes."):
            mod_name = (m.name or "").strip()
            low = mod_name.lower()
            if not mod_name or low.endswith(".__init__"):
                continue
            if _match(low, merged_exclude):
                continue
            out.add(mod_name)
    except Exception as e:
        log.error("Route scan failed: %s", e)

    return sorted(out)


def _should_skip_module(mod_path: str, disable: List[str], allow_specs: Set[str]) -> bool:
    low = (mod_path or "").strip().lower()
    if not low:
        return True
    if allow_specs and low not in allow_specs:
        return True
    if _match(low, disable):
        return True
    return False


def _should_skip_bp(bp_name: str, origin: str, disable: List[str], allow_bps: Set[str]) -> bool:
    name_low = (bp_name or "").strip().lower()
    origin_low = (origin or "").strip().lower()
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


def register_blueprints(app: Any) -> dict[str, Any]:
    t0 = time.perf_counter()

    disable = _split_csv("ROUTES_DISABLE")
    allow_bps = {x for x in _split_csv("ROUTES_ALLOW") if x}
    allow_specs = {x for x in _split_csv("ROUTES_ALLOW_SPECS") if x}
    require = {x.strip() for x in _split_csv("ROUTES_REQUIRE") if x.strip()}

    scan_enabled = _env_bool("ROUTES_SCAN", False)
    scan_exclude = _split_csv("ROUTES_SCAN_EXCLUDE")

    specs: List[str] = list(_DEFAULT_SPECS)
    scanned = False
    if scan_enabled:
        scanned = True
        specs.extend(_scan_route_modules(scan_exclude))

    specs = _dedupe_keep_order(specs)

    registered: List[str] = []
    duplicates: List[str] = []
    disabled_out: List[str] = []
    skipped_no_bp: List[str] = []
    imports_failed: List[str] = []

    try:
        initial = set((app.blueprints or {}).keys())
    except Exception:
        initial = set()

    seen: Set[str] = {str(x) for x in initial if x}

    for mod_path in specs:
        if _should_skip_module(mod_path, disable, allow_specs):
            disabled_out.append(f"{mod_path} :: module-disabled")
            continue

        mod, err = _import_module(mod_path)
        if err or mod is None:
            msg = f"{mod_path} :: {err or 'import failed'}"
            imports_failed.append(msg)
            log.error("IMPORT FAILED %s", msg)
            continue

        found_any = False
        for bp, sym in _iter_blueprints_in_module(mod):
            found_any = True
            bp_name = str(getattr(bp, "name", "") or "").strip()
            origin = f"{mod_path}.{sym}"

            if _should_skip_bp(bp_name, origin, disable, allow_bps):
                disabled_out.append(origin)
                continue

            if bp_name in seen:
                duplicates.append(origin)
                continue

            prefix = _env_prefix_for(bp_name)
            reg_err = _safe_register(app, bp, prefix)
            if reg_err:
                msg = f"{origin} :: {reg_err}"
                imports_failed.append(msg)
                log.error("Blueprint register failed %s", msg)
                continue

            seen.add(bp_name)
            registered.append(origin)

        if not found_any:
            skipped_no_bp.append(f"{mod_path} :: no-blueprint")

    missing_required = sorted(x for x in require if x and x not in seen)
    timing_ms = int((time.perf_counter() - t0) * 1000)

    log.info(
        "✅ Routes ready | registered=%d | dup=%d | disabled=%d | no_bp=%d | imports_failed=%d | %dms",
        len(registered),
        len(duplicates),
        len(disabled_out),
        len(skipped_no_bp),
        len(imports_failed),
        timing_ms,
    )
    if missing_required:
        log.warning("⚠ Missing required blueprints: %s", ", ".join(missing_required))

    return RoutesReport(
        registered=registered,
        duplicates=duplicates,
        disabled=disabled_out,
        skipped_no_blueprint=skipped_no_bp,
        imports_failed=imports_failed,
        missing_required=missing_required,
        timing_ms=timing_ms,
        scanned=scanned,
        specs_count=len(specs),
    ).__dict__


__all__ = ["register_blueprints"]
