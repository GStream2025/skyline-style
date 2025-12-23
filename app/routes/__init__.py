"""
Skyline Style · Routes Package

Este paquete centraliza todos los blueprints de la aplicación
para facilitar su registro en la app principal (Flask).

Cada blueprint encapsula un dominio funcional:
- main_bp      → páginas públicas (home, shop, marca, etc.)
- auth_bp      → autenticación y usuarios
- printful_bp  → integración y visualización de productos Printful
"""

from __future__ import annotations

# Blueprints principales
from .main_routes import main_bp
from .auth_routes import auth_bp
from .printful_routes import printful_bp

__all__ = [
    "main_bp",
    "auth_bp",
    "printful_bp",
]
