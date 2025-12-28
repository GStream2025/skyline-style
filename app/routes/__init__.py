"""Skyline Style · Routes Package

Este paquete centraliza todos los blueprints de la aplicación
para facilitar su registro en la app principal (Flask).

Cada blueprint encapsula un dominio funcional:
- main_bp      → páginas públicas (home, marca, etc.)
- shop_bp      → catálogo/tienda
- auth_bp      → autenticación y usuarios
- admin_bp     → panel admin (CRUD productos/categorías/ofertas)
- printful_bp  → integración Printful
"""

from __future__ import annotations

from .main_routes import main_bp
from .shop_routes import shop_bp
from .auth_routes import auth_bp
from .admin_routes import admin_bp
from .printful_routes import printful_bp

__all__ = ["main_bp", "shop_bp", "auth_bp", "admin_bp", "printful_bp"]
