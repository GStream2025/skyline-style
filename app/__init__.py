# app/__init__.py

from flask import Flask
from app.config import Config


def create_app():
    """
    Crea y configura la aplicación Flask principal de Skyline Style Store.
    Carga configuración, registra los blueprints y prepara la app.
    """
    app = Flask(
        __name__,
        static_folder="static",
        template_folder="templates"
    )

    # ============================
    #      CONFIGURACIÓN
    # ============================
    app.config.from_object(Config)

    # ============================
    #      BLUEPRINTS
    # ============================
    try:
        # Home, shop, producto individual
        from app.routes import main_bp

        # Login, registro
        from app.routes.auth_routes import auth_bp

        # Integración con Printful
        from app.routes.printful_routes import printful_bp

        # Registrar blueprints
        app.register_blueprint(main_bp)
        app.register_blueprint(auth_bp)
        app.register_blueprint(printful_bp)

    except Exception as e:
        print("\n❌ ERROR AL REGISTRAR BLUEPRINTS")
        print(f"Detalles: {e}")
        print("\nVerifica que las rutas estén dentro de:")
        print("   app/routes/main_routes.py")
        print("   app/routes/auth_routes.py")
        print("   app/routes/printful_routes.py")
        raise

    # ============================
    #  MENSAJE DE CONFIRMACIÓN
    # ============================
    print("\n----------------------------------------")
    print("  ✅ Skyline Style Store cargada con éxito")
    print("----------------------------------------\n")

    return app
