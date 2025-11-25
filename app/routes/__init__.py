# app/routes/__init__.py
"""
Paquete de rutas de Skyline Style Store.
Expone los blueprints principales para que puedan ser registrados en la app.
"""

from .main_routes import main_bp
from .auth_routes import auth_bp
from .printful_routes import printful_bp
