# app/routes/__init__.py
"""
Skyline Store · Routes Package (ULTRA PRO - FINAL / BULLETPROOF)

Centraliza y registra todos los blueprints:
✅ Safe-import con importlib
✅ Valida Blueprint real
✅ Anti-duplicados por name
✅ Registro robusto (si falla NO tumba prod)
✅ Report final prolijo
✅ Modo estricto opcional en dev (ROUTES_STRICT=1)

EXTRAS PRO:
- ROUTES_DISABLE="admin,printful" -> desactiva blueprints por env
- url_prefix opcional por spec (si querés forzar)
- fallback: si el símbolo no existe pero el módulo trae 1 blueprint, lo detecta
"""

from __future__ import annotations

import os
import logging
from importlib import import_module
from typing import TYPE_CHECKING, Optional, Set, Iterable, Tuple, Dict, List, Any

if TYPE_CHECKING:
    from flask import Flask
    from flask.blueprints import Blueprint

log = logging.getLogger("routes")

_TRUE = {"1", "true", "yes", "y", "on"}


# ------------------------------------------------------------
# Strict mode (solo dev)
# ------------------------------------------------------------
def _strict_mode(app: "Flask") -> bool:
    """
    En dev, si ROUTES_STRICT=1 -> explota para detectar rápido errores.
    En prod, nunca debería explotar por rutas.
    """
    v = (os.getenv("ROUTES_STRICT") or "").strip().lower()
    if v not in _TRUE:
        return False

    # Detecta env lo más robusto posible
    env = ""
    try:
        env = (app.config.get("ENV") or "").strip().lower()
    except Exception:
        env = ""

    # soporte alternativo (FLASK_ENV / app.debug)
    if not env:
        env = (os.getenv("FLASK_ENV") or "").strip().lower()

    if env:
        return env in {"development", "dev"}
    try:
        return bool(getattr(app, "debug", False))
    except Exception:
        return False


# ------------------------------------------------------------
# Disable list by ENV
# ------------------------------------------------------------
def _disabled_set() -> Set[str]:
    """
    ROUTES_DISABLE="admin,printful,marketing"
    Compara contra bp.name y/o símbolo.
    """
    raw = (os.getenv("ROUTES_DISABLE") or "").strip().lower()
    if not raw:
        return set()
    items = {x.strip() for x in raw.split(",") if x.strip()}
    return items


# ------------------------------------------------------------
# Import helpers
# ------------------------------------------------------------
def _safe_import_module(path: str):
    try:
        return import_module(path)
    except Exception as e:
        log.debug("Import module failed: %s (%s)", path, e)
        return None


def _safe_getattr(mod, name: str):
    try:
        return getattr(mod, name, None)
    except Exception:
        return None


def _is_blueprint(obj: Any) -> bool:
    """
    Validación flexible y segura:
    - no importa Flask en runtime
    - chequea estructura típica
    """
    if obj is None:
        return False
    if obj.__class__.__name__ != "Blueprint":
        return False
    if not hasattr(obj, "name"):
        return False
    if not hasattr(obj, "register"):
        return False
    return True


def _find_single_blueprint_in_module(mod) -> Optional[Any]:
    """
    Fallback: si no existe el símbolo, pero el módulo define 1 blueprint,
    lo usamos. Si hay 0 o >1, no adivinamos.
    """
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


def _safe_import_symbol(path: str, name: str) -> Any:
    """
    Importa mod + símbolo. Si no existe, intenta fallback por 1 blueprint.
    """
    mod = _safe_import_module(path)
    if not mod:
        return None

    obj = _safe_getattr(mod, name)
    if _is_blueprint(obj):
        return obj

    # fallback: auto-detect 1 blueprint
    auto_bp = _find_single_blueprint_in_module(mod)
    return auto_bp


# ------------------------------------------------------------
# Register
# ------------------------------------------------------------
def _register_once(
    app: "Flask",
    bp: Any,
    *,
    seen: Set[str],
    report: Dict[str, List[str]],
    origin: str,
    url_prefix: Optional[str] = None,
    disabled: Set[str],
) -> None:
    """
    Registra blueprint evitando duplicados.
    - no rompe en prod
    - en strict dev levanta error
    """
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

    # disable by env (acepta bp.name o símbolo)
    origin_tail = origin.split(".")[-1].strip().lower()
    if bp_name.lower() in disabled or origin_tail in disabled:
        report["disabled"].append(f"{bp_name} <- {origin}")
        return

    if bp_name in seen:
        report["duplicate"].append(f"{bp_name} <- {origin}")
        return

    try:
        if url_prefix:
            # forzar prefijo si lo pedís en specs
            app.register_blueprint(bp, url_prefix=url_prefix)
        else:
            app.register_blueprint(bp)
        seen.add(bp_name)
        report["registered"].append(bp_name)

    except Exception as e:
        # no ensucia prod con stack
        msg = f"{bp_name} <- {origin} :: {e}"
        report["failed_register"].append(msg)
        log.warning("⚠️ No se pudo registrar blueprint '%s' (%s): %s", bp_name, origin, e, exc_info=False)
        if _strict_mode(app):
            raise


# ------------------------------------------------------------
# Public API
# ------------------------------------------------------------
def register_blueprints(app: "Flask") -> None:
    """
    Registra TODOS los blueprints en orden marketplace.
    Si algo falta o rompe, NO tumba la app (salvo strict dev).
    """
    seen: Set[str] = set()
    disabled = _disabled_set()

    report: Dict[str, List[str]] = {
        "registered": [],
        "missing": [],
        "invalid": [],
        "duplicate": [],
        "failed_register": [],
        "disabled": [],
    }

    # Specs:
    # (module, symbol, url_prefix_override)
    specs: Iterable[Tuple[str, str, Optional[str]]] = (
        # Core
        ("app.routes.main_routes", "main_bp", None),
        ("app.routes.shop_routes", "shop_bp", None),
        ("app.routes.auth_routes", "auth_bp", None),

        # Account
        ("app.routes.account_routes", "account_bp", None),
        ("app.routes.account_routes", "cuenta_bp", None),
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
            seen=seen,
            report=report,
            origin=origin,
            url_prefix=pref,
            disabled=disabled,
        )

    # -------- Summary logs (limpios) --------
    try:
        log.info("✅ Blueprints registrados (%d): %s", len(seen), ", ".join(sorted(seen)) if seen else "(ninguno)")

        # solo si hay ruido
        if report["disabled"]:
            log.info("⛔ Blueprints deshabilitados por ENV: %s", ", ".join(report["disabled"]))

        if report["missing"]:
            log.debug("ℹ️ Blueprints no encontrados: %s", ", ".join(report["missing"]))

        if report["invalid"]:
            log.warning("⚠️ Blueprints inválidos (no Blueprint): %s", ", ".join(report["invalid"]))

        if report["duplicate"]:
            log.debug("ℹ️ Duplicados evitados: %s", ", ".join(report["duplicate"]))

        if report["failed_register"]:
            log.warning("⚠️ Fallos al registrar: %s", " | ".join(report["failed_register"]))
    except Exception:
        pass


__all__ = ["register_blueprints"]
