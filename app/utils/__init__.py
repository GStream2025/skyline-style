
"""
Skyline Style — Utils Hub
-------------------------
Punto único de entrada para utilidades compartidas.

Reglas:
- NO lógica de negocio acá
- SOLO imports limpios y explícitos
- Evita imports circulares
"""

from __future__ import annotations

# =========================
# Auth / Seguridad
# =========================
from app.utils.auth import admin_required, admin_creds_ok

# =========================
# Seguridad general
# =========================
from app.utils.security import (
    safe_next_url,
    is_safe_url,
)

# =========================
# Integraciones externas
# =========================
from app.utils.printful_mapper import (
    map_printful_product,
    map_printful_variant,
)

# =========================
# Export público controlado
# =========================
__all__ = [
    # auth
    "admin_required",
    "admin_creds_ok",

    # security
    "safe_next_url",
    "is_safe_url",

    # printful
    "map_printful_product",
    "map_printful_variant",
]
