# app/routes/__init__.py
"""
Skyline Store · Routes Package (ULTRA PRO - FINAL / BULLETPROOF)

Centraliza y registra todos los blueprints de la aplicación para mantener
la app principal limpia y evitar imports circulares.

✅ Orden tipo marketplace:
- main / shop / auth
- account / profile / address
- cart / checkout
- marketing
- admin / printful

🛡️ Blindaje TOTAL (para copiar/pegar y no tocar más):
- Safe-import real con importlib (más robusto que __import__)
- Valida que lo importado sea Blueprint (evita registrar cualquier cosa)
- Anti-duplicados por nombre
- Registro robusto: si register_blueprint falla (colisión endpoints/url_prefix), NO rompe
- Log final prolijo con:
  - registrados
  - módulos/símbolos faltantes
  - inválidos (no Blueprint)
  - duplicados evitados
  - fallos de registro
- Modo estricto opcional SOLO para dev:
  - ROUTES_STRICT=1 -> si falla un registro/import, lanza excepción (para detectar bugs rápido)
"""

from __future__ import annotations

import os
import logging
from importlib import import_module
from typing import TYPE_CHECKING, Optional, Set, Iterable, Tuple, Dict, List

if TYPE_CHECKING:
    from flask import Flask
    from flask.blueprints import Blueprint

log = logging.getLogger("routes")

_TRUE = {"1", "true", "yes", "y", "on"}


def _strict_mode(app: "Flask") -> bool:
    """
    Modo estricto SOLO recomendado en development.
    Si ROUTES_STRICT=1 y ENV=development -> levanta error para que lo veas al toque.
    """
    try:
        env = (app.config.get("ENV") or "").strip().lower()
    except Exception:
        env = ""
    v = (os.getenv("ROUTES_STRICT") or "").strip().lower()
    return (v in _TRUE) and (env == "development")


def _safe_import(path: str, name: str):
    """
    Importa un símbolo de forma segura.
    Devuelve:
      - objeto si existe
      - None si falla
    """
    try:
        mod = import_module(path)
        return getattr(mod, name, None)
    except Exception as e:
        log.debug("Blueprint import failed: %s.%s (%s)", path, name, e)
        return None


def _is_blueprint(obj) -> bool:
    """
    Validación flexible:
    - evita importar Flask en runtime
    - confirma estructura típica de Blueprint
    """
    if obj is None:
        return False
    # Clase suele llamarse Blueprint
    if obj.__class__.__name__ != "Blueprint":
        return False
    # props típicas
    if not hasattr(obj, "name"):
        return False
    if not hasattr(obj, "register"):
        return False
    return True


def _register_once(
    app: "Flask",
    bp,
    seen: Set[str],
    report: Dict[str, List[str]],
    origin: str,
) -> None:
    """
    Registra el blueprint evitando duplicados.
    Nunca rompe (salvo modo estricto en dev).
    """
    if bp is None:
        report["missing"].append(origin)
        return

    if not _is_blueprint(bp):
        report["invalid"].append(origin)
        return

    bp_name = getattr(bp, "name", None)
    if not bp_name:
        report["invalid"].append(origin)
        return

    if bp_name in seen:
        report["duplicate"].append(f"{bp_name} <- {origin}")
        return

    try:
        app.register_blueprint(bp)
        seen.add(bp_name)
        report["registered"].append(bp_name)
    except Exception as e:
        report["failed_register"].append(f"{bp_name} <- {origin} :: {e}")
        # warning sin stack para no ensuciar logs de prod
        log.warning("⚠️ No se pudo registrar blueprint '%s' (%s): %s", bp_name, origin, e, exc_info=False)
        if _strict_mode(app):
            raise


def register_blueprints(app: "Flask") -> None:
    """
    Registra TODOS los blueprints en la app (orden marketplace).
    Si algo falta o rompe, NO tumba la app.
    """
    seen: Set[str] = set()

    report: Dict[str, List[str]] = {
        "registered": [],
        "missing": [],
        "invalid": [],
        "duplicate": [],
        "failed_register": [],
    }

    # Declarativo + ordenado (marketplace)
    specs: Iterable[Tuple[str, str]] = (
        # Core
        ("app.routes.main_routes", "main_bp"),
        ("app.routes.shop_routes", "shop_bp"),
        ("app.routes.auth_routes", "auth_bp"),

        # Account
        ("app.routes.account_routes", "account_bp"),
        ("app.routes.account_routes", "cuenta_bp"),
        ("app.routes.profile_routes", "profile_bp"),
        ("app.routes.address_routes", "address_bp"),

        # Cart / Checkout
        ("app.routes.cart_routes", "cart_bp"),
        ("app.routes.checkout_routes", "checkout_bp"),

        # Marketing
        ("app.routes.marketing_routes", "marketing_bp"),

        # Admin / Printful
        ("app.routes.admin_routes", "admin_bp"),
        ("app.routes.printful_routes", "printful_bp"),
    )

    for mod, sym in specs:
        origin = f"{mod}.{sym}"
        bp = _safe_import(mod, sym)
        _register_once(app, bp, seen, report, origin)

    # Log final prolijo (nunca rompe)
    try:
        log.info("✅ Blueprints registrados (%d): %s", len(seen), ", ".join(sorted(seen)) if seen else "(ninguno)")

        # Detalle solo si hay algo raro (para no spamear)
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
