"""
Skyline Store · Routes Package (ULTRA PRO FINAL / FULL AUTO)

OBJETIVO: "No falta nada" + "no se rompe" + "no tocar más".

✅ Registro ordenado por prioridad (core -> checkout -> webhooks -> admin)
✅ Auto-scan del paquete app.routes: registra TODO blueprint encontrado
✅ Soporta múltiples blueprints por módulo
✅ Autodiscovery: si símbolo no existe, igual registra los blueprints del módulo
✅ Anti duplicados por name + origin
✅ Disable por ENV con wildcard: ROUTES_DISABLE="admin*,printful,app.routes.debug_routes"
✅ Prefix override por ENV: ROUTES_PREFIX_<bpname>=/algo
✅ Require por ENV: ROUTES_REQUIRE="main,shop,auth,checkout,webhook"
✅ Strict mode:
   - ROUTES_STRICT=1 (solo en dev) -> explota si algo falla
   - ROUTES_STRICT_FORCE=1 -> explota siempre (usar solo para debug fuerte)
✅ Report dict estable para /health
"""

from __future__ import annotations

import os
import logging
import pkgutil
from importlib import import_module
from typing import TYPE_CHECKING, Optional, Set, Iterable, Tuple, Dict, List, Any

if TYPE_CHECKING:
    from flask import Flask

log = logging.getLogger("routes")

_TRUE = {"1", "true", "yes", "y", "on"}

# cache por proceso
_MODULE_CACHE: Dict[str, Any] = {}
_IMPORT_ERRORS: Dict[str, str] = {}

# --------------------------------------------------------------------------------------
# ENV helpers
# --------------------------------------------------------------------------------------
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


def _matches_pattern(value: str, pattern: str) -> bool:
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
    key = f"ROUTES_PREFIX_{bp_name}".upper()
    v = (os.getenv(key) or "").strip()
    if not v:
        return None
    if not v.startswith("/"):
        v = "/" + v
    return v


# --------------------------------------------------------------------------------------
# Import helpers
# --------------------------------------------------------------------------------------
def _short_exc(e: Exception) -> str:
    msg = f"{type(e).__name__}: {e}"
    return msg[:240]


def _safe_import_module(path: str):
    if path in _MODULE_CACHE:
        return _MODULE_CACHE[path]

    try:
        mod = import_module(path)
        _MODULE_CACHE[path] = mod
        _IMPORT_ERRORS.pop(path, None)
        return mod
    except Exception as e:
        _MODULE_CACHE[path] = None
        _IMPORT_ERRORS[path] = _short_exc(e)
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
        # fallback estructural
        return (
            hasattr(obj, "name")
            and hasattr(obj, "register")
            and hasattr(obj, "deferred_functions")
        )


def _find_blueprints_in_module(mod) -> List[Any]:
    if not mod:
        return []
    out: List[Any] = []
    for k in dir(mod):
        if k.startswith("_"):
            continue
        obj = _safe_getattr(mod, k)
        if _is_blueprint(obj):
            out.append(obj)
    # dedupe por name dentro del módulo
    uniq: Dict[str, Any] = {}
    for bp in out:
        n = (getattr(bp, "name", "") or "").strip()
        if n and n not in uniq:
            uniq[n] = bp
    return list(uniq.values())


def _import_symbol_or_all(mod_path: str, symbol: Optional[str]) -> Tuple[List[Any], Optional[str]]:
    """
    Retorna (blueprints, err)
    - si symbol existe y es bp -> [bp]
    - si no, retorna todos los blueprints del módulo
    """
    mod = _safe_import_module(mod_path)
    if not mod:
        return [], _IMPORT_ERRORS.get(mod_path)

    if symbol:
        obj = _safe_getattr(mod, symbol)
        if _is_blueprint(obj):
            return [obj], None

    # fallback: todos los bps del módulo
    bps = _find_blueprints_in_module(mod)
    return bps, None


# --------------------------------------------------------------------------------------
# Register
# --------------------------------------------------------------------------------------
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

    if _is_disabled(bp_name, sym_tail, mod_path, disabled_patterns):
        report["disabled"].append(f"{bp_name} <- {origin}")
        return

    # origin: evitamos duplicar exacto el mismo origen
    if origin in seen_origins:
        report["duplicate"].append(f"(origin) {bp_name} <- {origin}")
        return

    # name: evitamos registrar 2 bps con mismo name
    if bp_name in seen_names:
        report["duplicate"].append(f"(name) {bp_name} <- {origin}")
        return

    env_pref = _env_prefix_for(bp_name)
    final_prefix = env_pref or url_prefix

    try:
        if final_prefix:
            app.register_blueprint(bp, url_prefix=final_prefix)
        else:
            app.register_blueprint(bp)

        seen_names.add(bp_name)
        seen_origins.add(origin)
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


def _scan_route_modules() -> List[str]:
    """
    Escanea el paquete app.routes y devuelve módulos: app.routes.xxx
    No incluye __init__.
    """
    try:
        pkg = import_module("app.routes")
        base = pkg.__name__
        mods: List[str] = []
        for m in pkgutil.iter_modules(pkg.__path__, base + "."):
            if m.name.endswith(".__init__"):
                continue
            # ignorar pyc / cosas raras
            if m.name.split(".")[-1].startswith("_"):
                continue
            mods.append(m.name)
        return sorted(mods)
    except Exception:
        return []


# --------------------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------------------
def register_blueprints(app: "Flask") -> Dict[str, List[str]]:
    """
    Registro final:
    1) specs prioritarios (orden recomendado)
    2) auto-scan: registra TODO blueprint restante
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
        "scan_registered": [],
        "scan_skipped": [],
    }

    # -----------------------------------------
    # 1) REGISTRO PRIORITARIO (orden pro)
    # -----------------------------------------
    specs: Iterable[Tuple[str, Optional[str], Optional[str]]] = (
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

        # Webhooks (pagos)
        ("app.routes.webhook_routes", "webhook_bp", None),

        # Marketing
        ("app.routes.marketing_routes", "marketing_bp", None),

        # Affiliate / API (vos los tenés en el árbol)
        ("app.routes.affiliate_routes", None, None),
        ("app.routes.api_routes", None, None),

        # Admin / Printful
        ("app.routes.admin_routes", "admin_bp", None),
        ("app.routes.printful_routes", "printful_bp", None),
    )

    for mod, symbol, pref in specs:
        bps, err = _import_symbol_or_all(mod, symbol)
        if not bps:
            report["missing"].append(f"{mod}.{symbol or '*'}" + (f" :: {err}" if err else ""))
            continue
        for bp in bps:
            origin = f"{mod}.{symbol or getattr(bp, 'name', 'blueprint')}"
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
    # 2) AUTO-SCAN: REGISTRA TODO lo demás
    # -----------------------------------------
    scan_modules = _scan_route_modules()
    for mod in scan_modules:
        # ya intentado arriba? igual está ok: anti-duplicate por origin/name
        bps, err = _import_symbol_or_all(mod, None)
        if not bps:
            # no lo marcamos como missing fuerte; solo debug
            report["scan_skipped"].append(mod + (f" :: {err}" if err else ""))
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
            after = len(report["registered"])
            if after > before:
                report["scan_registered"].append(origin)

    # -----------------------------------------
    # REQUIRED CHECK (por bp.name)
    # -----------------------------------------
    if required:
        have = {x.split(" <- ", 1)[0].strip().lower() for x in report["registered"]}
        miss = sorted(list(required - have))
        if miss:
            report["required_missing"] = miss
            if _strict_mode(app):
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

        if report["required_missing"]:
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

    except Exception:
        pass

    return report


__all__ = ["register_blueprints"]
