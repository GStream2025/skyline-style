"""
Skyline Style — Utils Hub (ULTRA PRO / BULLETPROOF)
--------------------------------------------------
Punto único de entrada para utilidades compartidas.

Reglas:
- NO lógica de negocio acá
- SOLO exports públicos
- IMPORTS LAZY (evita circular imports)
- Si falta un módulo -> NO rompe la app (fallback seguro)

Tips:
- Importá siempre desde `app.utils` en vez de submódulos para estabilidad.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional, Tuple, Dict

log = logging.getLogger("utils")

# ============================================================
# Helpers internos (safe import + fallback)
# ============================================================

def _safe_import(module: str, symbol: str):
    """
    Importa símbolo de forma segura.
    Si falla -> None (no rompe producción).
    """
    try:
        mod = __import__(module, fromlist=[symbol])
        return getattr(mod, symbol, None)
    except Exception as e:
        # debug only (no ensucia prod)
        try:
            log.debug("utils import failed: %s.%s (%s)", module, symbol, e)
        except Exception:
            pass
        return None


def _missing(name: str):
    """
    Crea un stub que falla con error claro SOLO cuando se usa.
    (Así la app inicia y vos ves el error al usar esa función)
    """
    def _fn(*_a: Any, **_k: Any):
        raise RuntimeError(f"Utilidad no disponible: {name}. Revisá imports/archivo faltante.")
    _fn.__name__ = name
    return _fn


# ============================================================
# Auth / Seguridad (ADMIN)
# ============================================================

admin_required = _safe_import("app.utils.auth", "admin_required") or _missing("admin_required")
admin_creds_ok = _safe_import("app.utils.auth", "admin_creds_ok") or _missing("admin_creds_ok")

# Recomendadas (de tu auth mejorado)
admin_login = _safe_import("app.utils.auth", "admin_login") or _missing("admin_login")
admin_logout = _safe_import("app.utils.auth", "admin_logout") or _missing("admin_logout")
admin_login_attempt = _safe_import("app.utils.auth", "admin_login_attempt") or _missing("admin_login_attempt")
is_admin_logged = _safe_import("app.utils.auth", "is_admin_logged") or _missing("is_admin_logged")
admin_identity = _safe_import("app.utils.auth", "admin_identity") or _missing("admin_identity")


# ============================================================
# Seguridad general (URLs, redirects)
# ============================================================

safe_next_url = _safe_import("app.utils.security", "safe_next_url") or _missing("safe_next_url")
is_safe_url = _safe_import("app.utils.security", "is_safe_url") or _missing("is_safe_url")


# ============================================================
# Integraciones externas (Printful)
# ============================================================

map_printful_product = _safe_import("app.utils.printful_mapper", "map_printful_product") or _missing("map_printful_product")
map_printful_variant = _safe_import("app.utils.printful_mapper", "map_printful_variant") or _missing("map_printful_variant")


# ============================================================
# Export público controlado (API estable)
# ============================================================

__all__ = [
    # auth
    "admin_required",
    "admin_creds_ok",
    "admin_login",
    "admin_logout",
    "admin_login_attempt",
    "is_admin_logged",
    "admin_identity",

    # security
    "safe_next_url",
    "is_safe_url",

    # printful
    "map_printful_product",
    "map_printful_variant",
]
