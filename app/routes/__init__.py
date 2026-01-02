# app/routes/__init__.py
"""
Skyline Store · Routes Package (ULTRA PRO MAX++ / BULLETPROOF)

- Safe imports con cache
- Validación real de Blueprint (isinstance) + fallback estructural
- Anti duplicados (por name y por origin)
- Disable por ENV (bp.name, símbolo o módulo) + wildcard (*)
- Strict mode sólo dev (ROUTES_STRICT=1)
- Reporte prolijo (retorna dict)
- Prefijos opcionales por spec + override por ENV: ROUTES_PREFIX_<bpname>=/algo
- Require opcional por ENV: ROUTES_REQUIRE="auth,shop" (para detectar faltantes)
"""

from __future__ import annotations

import os
import logging
from importlib import import_module
from typing import TYPE_CHECKING, Optional, Set, Iterable, Tuple, Dict, List, Any

if TYPE_CHECKING:
    from flask import Flask

log = logging.getLogger("routes")

_TRUE = {"1", "true", "yes", "y", "on"}

_MODULE_CACHE: Dict[str, Any] = {}


# ------------------------------------------------------------
# ENV helpers
# ------------------------------------------------------------
def _env_bool(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    return v.strip().lower() in _TRUE


def _routes_debug() -> bool:
    return _env_bool("ROUTES_DEBUG", False)


def _strict_mode(app: "Flask") -> bool:
    if not _env_bool("ROUTES_STRICT", False):
        return False

    env = ""
    try:
        env = (app.config.get("ENV") or "").strip().lower()
    except Exception:
        env = ""

    if not env:
        env = (os.getenv("FLASK_ENV") or "").strip().lower()

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
    # soporta wildcard: "admin*,printful,app.routes.admin_routes"
    return [x.lower() for x in _split_csv_env("ROUTES_DISABLE")]


def _required_names() -> Set[str]:
    # "auth,shop" -> obliga a que existan (útil para detectar despliegues rotos)
    return {x.lower() for x in _split_csv_env("ROUTES_REQUIRE")}


def _matches_pattern(value: str, pattern: str) -> bool:
    """
    Wildcard simple:
      - "admin*" matchea admin, admin_bp, adminpanel
      - sin '*' compara exacto
    """
    value = value.lower()
    pattern = pattern.lower()
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return value == pattern


def _is_disabled(bp_name: str, sym_tail: str, mod_path: str, patterns: List[str]) -> bool:
    for p in patterns:
        if _matches_pattern(bp_name, p) or _matches_pattern(sym_tail, p) or _matches_pattern(mod_path, p):
            return True
    return False


def _env_prefix_for(bp_name: str) -> Optional[str]:
    """
    Override por ENV:
      ROUTES_PREFIX_admin=/admin
      ROUTES_PREFIX_shop=/tienda
    """
    key = f"ROUTES_PREFIX_{bp_name}".upper()
    v = (os.getenv(key) or "").strip()
    if not v:
        return None
    if not v.startswith("/"):
        v = "/" + v
    return v


# ------------------------------------------------------------
# Import helpers (con cache)
# ------------------------------------------------------------
def _safe_import_module(path: str):
    if path in _MODULE_CACHE:
        return _MODULE_CACHE[path]
    try:
        mod = import_module(path)
        _MODULE_CACHE[path] = mod
        return mod
    except Exception as e:
        _MODULE_CACHE[path] = None
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
        return (
            hasattr(obj, "name")
            and hasattr(obj, "register")
            and hasattr(obj, "deferred_functions")
        )


def _find_single_blueprint_in_module(mod) -> Optional[Any]:
    if not mod:
        return None
    found = []
    for k in dir(mod):
        if k.startswith("_"):
            continue
        obj = _safe_getattr(mod, k)
        if _is_blueprint(obj):
            found.append(obj)
            if len(found) > 1:
                return None
    return found[0] if len(found) == 1 else None


def _safe_import_symbol(mod_path: str, symbol: str) -> Any:
    mod = _safe_import_module(mod_path)
    if not mod:
        return None

    obj = _safe_getattr(mod, symbol)
    if _is_blueprint(obj):
        return obj

    return _find_single_blueprint_in_module(mod)


# ------------------------------------------------------------
# Register helper
# ------------------------------------------------------------
def _register_once(
    app: "Flask",
    bp: Any,
    *,
    seen_names: Set[str],
    seen_origins: Set[str],
    report: Dict[str, List[str]],
    origin: str,
    url_prefix: Optional[str],
    disabled_patterns: List[str],
) -> None:
    if bp is None:
        report["missing"].append(origin)
        return

    if not _is_blueprint(bp):
        report["invalid"].append(origin)
        return

    bp_name = (getattr(bp, "name", "") or "").strip()
    if not bp_name:
        report["invalid"].append(origin)
        return

    mod_path = origin.rsplit(".", 1)[0].strip().lower()
    sym_tail = origin.split(".")[-1].strip().lower()

    if _is_disabled(bp_name, sym_tail, mod_path, disabled_patterns):
        report["disabled"].append(f"{bp_name} <- {origin}")
        return

    if origin in seen_origins:
        report["duplicate"].append(f"(origin) {bp_name} <- {origin}")
        return

    if bp_name in seen_names:
        report["duplicate"].append(f"(name) {bp_name} <- {origin}")
        return

    if not hasattr(app, "register_blueprint"):
        raise RuntimeError("Objeto 'app' inválido: no tiene register_blueprint()")

    # override url_prefix por ENV si existe
    env_pref = _env_prefix_for(bp_name)
    final_prefix = env_pref or url_prefix

    try:
        if final_prefix:
            app.register_blueprint(bp, url_prefix=final_prefix)
        else:
            app.register_blueprint(bp)

        seen_names.add(bp_name)
        seen_origins.add(origin)
        report["registered"].append(f"{bp_name} <- {origin}" + (f" (prefix={final_prefix})" if final_prefix else ""))

    except Exception as e:
        report["failed_register"].append(f"{bp_name} <- {origin} :: {type(e).__name__}: {e}")
        log.warning(
            "⚠️ No se pudo registrar blueprint '%s' (%s): %s",
            bp_name,
            origin,
            e,
            exc_info=_routes_debug(),
        )
        if _strict_mode(app):
            raise


# ------------------------------------------------------------
# Public API
# ------------------------------------------------------------
def register_blueprints(app: "Flask") -> Dict[str, List[str]]:
    """
    Registra todos los blueprints en orden.

    Dev:
      - ROUTES_STRICT=1 -> si algo falla, levanta excepción
    Prod:
      - nunca tumba la app por rutas

    Retorna report dict para /health o debug.
    """
    seen_names: Set[str] = set()
    seen_origins: Set[str] = set()
    disabled_patterns = _disabled_patterns()
    required = _required_names()

    report: Dict[str, List[str]] = {
        "registered": [],
        "missing": [],
        "invalid": [],
        "duplicate": [],
        "failed_register": [],
        "disabled": [],
        "required_missing": [],
    }

    specs: Iterable[Tuple[str, str, Optional[str]]] = (
        # Core
        ("app.routes.main_routes", "main_bp", None),
        ("app.routes.shop_routes", "shop_bp", None),
        ("app.routes.auth_routes", "auth_bp", None),

        # Account
        ("app.routes.account_routes", "account_bp", None),
        ("app.routes.profile_routes", "profile_bp", None),
        ("app.routes.address_routes", "address_bp", None),

        # Cart / Checkout
        ("app.routes.cart_routes", "cart_bp", None),
        ("app.routes.checkout_routes", "checkout_bp", None),

        # Marketing
        ("app.routes.marketing_routes", "marketing_bp", None),

        # Admin / Printful
        ("app.routes.admin_routes", "admin_bp", None),
        ("app.routes.printful_routes", "printful_bp", None),
    )

    for mod, sym, pref in specs:
        origin = f"{mod}.{sym}"
        bp = _safe_import_symbol(mod, sym)
        _register_once(
            app,
            bp,
            seen_names=seen_names,
            seen_origins=seen_origins,
            report=report,
            origin=origin,
            url_prefix=pref,
            disabled_patterns=disabled_patterns,
        )

    # required check (por bp.name)
    if required:
        have = {x.split(" <- ", 1)[0].strip().lower() for x in report["registered"]}
        miss = sorted(list(required - have))
        if miss:
            report["required_missing"] = miss
            # en strict dev, explotamos
            if _strict_mode(app):
                raise RuntimeError(f"ROUTES_REQUIRE faltantes: {', '.join(miss)}")
            log.warning("⚠️ ROUTES_REQUIRE faltantes: %s", ", ".join(miss))

    # Summary logs
    try:
        reg_names = [x.split(" <- ", 1)[0] for x in report["registered"]]
        log.info("✅ Blueprints registrados (%d): %s", len(reg_names), ", ".join(reg_names) if reg_names else "(ninguno)")

        if report["disabled"]:
            log.info("⛔ Deshabilitados (ENV): %s", ", ".join(report["disabled"]))

        if report["failed_register"]:
            log.warning("⚠️ Fallos al registrar (%d): %s", len(report["failed_register"]), " | ".join(report["failed_register"]))

        if report["required_missing"]:
            log.warning("⚠️ Required faltantes: %s", ", ".join(report["required_missing"]))

        if report["missing"]:
            log.debug("ℹ️ No encontrados: %s", ", ".join(report["missing"]))
        if report["invalid"]:
            log.debug("ℹ️ Inválidos: %s", ", ".join(report["invalid"]))
        if report["duplicate"]:
            log.debug("ℹ️ Duplicados evitados: %s", ", ".join(report["duplicate"]))

    except Exception:
        pass

    return report


__all__ = ["register_blueprints"]
