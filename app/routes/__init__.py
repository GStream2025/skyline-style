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

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off", "unchecked"}


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
    return [x.strip().lower() for x in raw.split(",") if x.strip()]


def _match(value: str, patterns: List[str]) -> bool:
    v = (value or "").strip().lower()
    if not v:
        return False
    for p in patterns:
        if fnmatch.fnmatch(v, p):
            return True
    return False


def _bp_env_key(bp_name: str) -> str:
    return (bp_name or "BLUEPRINT").upper().replace("-", "_").replace(" ", "_")


def _normalize_prefix(prefix: Optional[str]) -> Optional[str]:
    if not prefix:
        return None
    p = str(prefix).strip()
    if not p:
        return None
    p = "/" + p.lstrip("/")
    return p.rstrip("/") if p != "/" else p


def _env_prefix_for(bp_name: str) -> Optional[str]:
    return _normalize_prefix(os.getenv(f"ROUTES_PREFIX_{_bp_env_key(bp_name)}"))


def _is_blueprint(obj: Any) -> bool:
    try:
        from flask.blueprints import Blueprint
        return isinstance(obj, Blueprint)
    except Exception:
        return False


def _import_module(path: str):
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


def _default_specs() -> List[str]:
    return [
        "app.routes.main_routes",
        "app.routes.shop_routes",
        "app.routes.auth_routes",
        "app.routes.account_routes",
        "app.routes.cuenta_routes",
        "app.routes.cart_routes",
        "app.routes.checkout_routes",
        "app.routes.api_routes",
        "app.routes.affiliate_routes",
        "app.routes.marketing_routes",
        "app.routes.webhooks_routes",
        "app.routes.admin_routes",
        "app.routes.admin_payments_routes",
        "app.routes.printful_routes",
        "app.routes.address_routes",
        "app.routes.profile_routes",
    ]


def _scan_route_modules(exclude: List[str]) -> List[str]:
    out: Set[str] = set()
    try:
        pkg = importlib.import_module("app.routes")
        for m in pkgutil.iter_modules(pkg.__path__, "app.routes."):
            name = m.name.lower()
            if name.endswith("__init__"):
                continue
            if _match(name, exclude):
                continue
            out.add(m.name)
    except Exception as e:
        log.error("Route scan failed: %s", e)
    return sorted(out)


@dataclass(frozen=True)
class RoutesReport:
    registered: List[str]
    duplicates: List[str]
    disabled: List[str]
    imports_failed: List[str]
    missing_required: List[str]
    timing_ms: int


def register_blueprints(app) -> Dict[str, Any]:
    t0 = time.perf_counter()

    disable = _split_csv("ROUTES_DISABLE")
    allow = set(_split_csv("ROUTES_ALLOW"))
    require = set(_split_csv("ROUTES_REQUIRE"))

    scan_enabled = _env_bool("ROUTES_SCAN", False)
    scan_exclude = _split_csv("ROUTES_SCAN_EXCLUDE")

    specs: List[str] = []
    specs.extend(_default_specs())

    if scan_enabled:
        specs.extend(_scan_route_modules(scan_exclude))

    # 🔒 dedupe real
    specs = list(dict.fromkeys(specs))

    registered, duplicates, disabled_out, imports_failed = [], [], [], []
    seen = set((app.blueprints or {}).keys())

    for mod_path in specs:
        mod, err = _import_module(mod_path)
        if err:
            imports_failed.append(f"{mod_path} :: {err}")
            log.error("IMPORT FAILED %s", err)
            continue

        for bp, sym in _iter_blueprints_in_module(mod):
            name = bp.name
            origin = f"{mod_path}.{sym}"

            if allow and name not in allow:
                disabled_out.append(origin)
                continue

            if _match(name, disable) or _match(origin, disable):
                disabled_out.append(origin)
                continue

            if name in seen:
                duplicates.append(origin)
                continue

            try:
                prefix = _env_prefix_for(name)
                app.register_blueprint(bp, url_prefix=prefix)
                seen.add(name)
                registered.append(origin)
            except Exception as e:
                imports_failed.append(f"{origin} :: {type(e).__name__}: {e}")
                log.exception("Blueprint register failed")

    missing_required = sorted(x for x in require if x not in seen)
    timing_ms = int((time.perf_counter() - t0) * 1000)

    log.info(
        "✅ Routes ready | registered=%d | dup=%d | disabled=%d | imports_failed=%d | %dms",
        len(registered), len(duplicates), len(disabled_out), len(imports_failed), timing_ms
    )

    if missing_required:
        log.warning("⚠ Missing required blueprints: %s", ", ".join(missing_required))

    return RoutesReport(
        registered, duplicates, disabled_out, imports_failed, missing_required, timing_ms
    ).__dict__


__all__ = ["register_blueprints"]
