from flask import Flask

def create_app():
    # Creamos la app con rutas de static y templates correctas
    app = Flask(
        __name__,
        static_folder="static",
        template_folder="templates"
    )

    # Clave para sesiones, login, formularios, etc.
    app.config['SECRET_KEY'] = 'supersecretkey'

    # ---- Importación de blueprints ----
    try:
        from app.routes import main_bp
        app.register_blueprint(main_bp)
    except Exception as e:
        print("⚠ Error cargando main_bp:", e)

    try:
        from app.auth_routes import auth_bp
        app.register_blueprint(auth_bp)
    except Exception as e:
        print("⚠ Error cargando auth_bp:", e)

    print("✅ Skyline Style Store cargada correctamente")

    return app
