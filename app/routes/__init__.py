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
    if not raw:
        return []
    return [x.strip() for x in raw.split(",") if x and x.strip()]


def _match(value: str, patterns: List[str]) -> bool:
    v = (value or "").strip().lower()
    if not v:
        return False
    for p in patterns:
        pat = (p or "").strip().lower()
        if not pat:
            continue
        if any(ch in pat for ch in "*?[]"):
            if fnmatch.fnmatch(v, pat):
                return True
        else:
            if v == pat:
                return True
    return False


def _bp_env_key(bp_name: str) -> str:
    s = (bp_name or "").strip().upper().replace("-", "_").replace(" ", "_")
    while "__" in s:
        s = s.replace("__", "_")
    return s or "BLUEPRINT"


def _normalize_prefix(prefix: Optional[str]) -> Optional[str]:
    if not prefix:
        return None
    p = str(prefix).strip()
    if not p:
        return None
    while "//" in p:
        p = p.replace("//", "/")
    if not p.startswith("/"):
        p = "/" + p
    if p != "/" and p.endswith("/"):
        p = p[:-1]
    return p


def _env_prefix_for(bp_name: str) -> Optional[str]:
    v = (os.getenv(f"ROUTES_PREFIX_{_bp_env_key(bp_name)}") or "").strip()
    return _normalize_prefix(v)


def _is_blueprint(obj: Any) -> bool:
    if obj is None:
        return False
    try:
        from flask.blueprints import Blueprint

        return isinstance(obj, Blueprint)
    except Exception:
        return hasattr(obj, "register") and hasattr(obj, "name")


def _import_module(mod_path: str):
    try:
        return importlib.import_module(mod_path), ""
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def _iter_blueprints_in_module(mod: Any) -> Iterable[Tuple[Any, str]]:
    if not mod:
        return
    for k in dir(mod):
        if k.startswith("_"):
            continue
        try:
            obj = getattr(mod, k, None)
        except Exception:
            obj = None
        if _is_blueprint(obj):
            yield obj, k


def _default_specs() -> List[Tuple[str, Optional[str]]]:
    return [
        ("app.routes.main_routes", None),
        ("app.routes.shop_routes", None),
        ("app.routes.auth_routes", None),
        ("app.routes.account_routes", None),
        ("app.routes.cuenta_routes", None),
        ("app.routes.cart_routes", None),
        ("app.routes.checkout_routes", None),
        ("app.routes.api_routes", None),
        ("app.routes.affiliate_routes", None),
        ("app.routes.marketing_routes", None),
        ("app.routes.webhooks_routes", None),
        ("app.routes.admin_routes", None),
        ("app.routes.admin_payments_routes", None),
        ("app.routes.printful_routes", None),
        ("app.routes.address_routes", None),
        ("app.routes.profile_routes", None),
    ]


def _scan_route_modules(exclude: List[str]) -> List[str]:
    try:
        pkg = importlib.import_module("app.routes")
        pkg_path = getattr(pkg, "__path__", None)
        if not pkg_path:
            return []
        out: List[str] = []
        for m in pkgutil.iter_modules(pkg_path, "app.routes."):
            tail = m.name.split(".")[-1].lower()
            if tail.startswith("_") or tail in {"tests", "test", "conftest", "__init__"}:
                continue
            if _match(m.name, exclude) or _match(tail, exclude):
                continue
            out.append(m.name)
        return sorted(set(out))
    except Exception:
        return []


@dataclass(frozen=True)
class RoutesReport:
    registered: List[str]
    duplicates: List[str]
    disabled: List[str]
    imports_failed: List[str]
    missing_required: List[str]
    timing_ms: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "registered": list(self.registered),
            "duplicates": list(self.duplicates),
            "disabled": list(self.disabled),
            "imports_failed": list(self.imports_failed),
            "missing_required": list(self.missing_required),
            "timing_ms": int(self.timing_ms),
        }


def register_blueprints(app) -> Dict[str, Any]:
    t0 = time.perf_counter()

    disable = [x.lower() for x in _split_csv("ROUTES_DISABLE")]
    allow = {x.lower() for x in _split_csv("ROUTES_ALLOW")}
    require = {x.lower() for x in _split_csv("ROUTES_REQUIRE")}

    scan_enabled = _env_bool("ROUTES_SCAN", False)
    scan_exclude = [x.lower() for x in _split_csv("ROUTES_SCAN_EXCLUDE")]

    priority = [x.strip() for x in _split_csv("ROUTES_PRIORITY") if x.strip()]
    specs: List[Tuple[str, Optional[str]]] = []

    specs.extend(_default_specs())

    for item in priority:
        if ":" in item:
            mod, sym = item.split(":", 1)
            mod = mod.strip()
            sym = sym.strip()
            if mod:
                specs.append((mod, sym or None))
        else:
            specs.append((item, None))

    if scan_enabled:
        for mod in _scan_route_modules(scan_exclude):
            specs.append((mod, None))

    registered: List[str] = []
    duplicates: List[str] = []
    disabled_out: List[str] = []
    imports_failed: List[str] = []

    seen_names: Set[str] = set(str(k).lower() for k in (getattr(app, "blueprints", {}) or {}).keys())

    for mod_path, symbol in specs:
        mod, err = _import_module(mod_path)
        if not mod:
            if err:
                imports_failed.append(f"{mod_path} :: {err}")
            continue

        if symbol:
            try:
                obj = getattr(mod, symbol, None)
            except Exception:
                obj = None
            candidates = [(obj, symbol)] if _is_blueprint(obj) else []
        else:
            candidates = list(_iter_blueprints_in_module(mod))

        for bp, sym in candidates:
            bp_name = (getattr(bp, "name", "") or "").strip()
            if not bp_name:
                continue

            name_l = bp_name.lower()
            origin = f"{mod_path}.{sym}"

            if allow and name_l not in allow:
                disabled_out.append(f"{bp_name} <- {origin} (allowlist)")
                continue

            if _match(name_l, disable) or _match(origin.lower(), disable) or _match(str(sym).lower(), disable):
                disabled_out.append(f"{bp_name} <- {origin}")
                continue

            if name_l in seen_names:
                duplicates.append(f"{bp_name} <- {origin}")
                continue

            override = _env_prefix_for(bp_name)
            try:
                if override:
                    app.register_blueprint(bp, url_prefix=override)
                else:
                    app.register_blueprint(bp)
                seen_names.add(name_l)
                registered.append(f"{bp_name} <- {origin}" + (f" (prefix={override})" if override else ""))
            except Exception as e:
                imports_failed.append(f"{origin} :: {type(e).__name__}: {e}")

    missing_required: List[str] = []
    if require:
        have = set(str(k).lower() for k in (getattr(app, "blueprints", {}) or {}).keys())
        missing_required = sorted([x for x in require if x not in have])

    timing_ms = int((time.perf_counter() - t0) * 1000)

    try:
        log.info(
            "✅ Routes ready | registered=%d | dup=%d | disabled=%d | imports_failed=%d | %dms",
            len(registered),
            len(duplicates),
            len(disabled_out),
            len(imports_failed),
            timing_ms,
        )
        if missing_required:
            log.warning("⚠ Missing required blueprints: %s", ", ".join(missing_required))
    except Exception:
        pass

    return RoutesReport(
        registered=registered,
        duplicates=duplicates,
        disabled=disabled_out,
        imports_failed=imports_failed,
        missing_required=missing_required,
        timing_ms=timing_ms,
    ).to_dict()


__all__ = ["register_blueprints"]
