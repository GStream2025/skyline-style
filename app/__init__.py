"""
app/__init__.py — Skyline Style (Factory PRO)

✅ App Factory create_app() lista para Gunicorn/Render
✅ Config por ENV + soporte DATABASE_URL (Render Postgres)
✅ SQLAlchemy + Migrations opcionales (si las usás)
✅ Compress + Talisman + Caching + Minify (si están instalados)
✅ Blueprints seguros (no revienta si falta alguno)
✅ Logging claro
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

from flask import Flask

# Core ext
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def _bool_env(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}


def _normalize_database_url(url: str | None) -> str | None:
    """
    Render suele dar postgres:// pero SQLAlchemy prefiere postgresql://
    """
    if not url:
        return None
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql://", 1)
    return url


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")

    # -----------------------
    # Config básica
    # -----------------------
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")

    # Database (opcional)
    db_url = _normalize_database_url(os.getenv("DATABASE_URL"))
    if db_url:
        app.config["SQLALCHEMY_DATABASE_URI"] = db_url
        app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    else:
        # fallback local (sqlite)
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///skyline.db"
        app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Inicializar SQLAlchemy
    db.init_app(app)

    # -----------------------
    # Extensiones opcionales
    # (NO rompen si no están)
    # -----------------------
    # Flask-Compress
    try:
        from flask_compress import Compress

        Compress(app)
    except Exception:
        pass

    # Flask-Talisman (headers seguridad)
    try:
        from flask_talisman import Talisman

        # Si usás CDN/3rd party scripts, ajustamos CSP.
        # En modo simple: fuerza HTTPS si Render está en HTTPS.
        Talisman(
            app,
            force_https=_bool_env("FORCE_HTTPS", False),
            content_security_policy=None,
        )
    except Exception:
        pass

    # Flask-Caching
    try:
        from flask_caching import Cache

        cache_config = {
            "CACHE_TYPE": os.getenv("CACHE_TYPE", "SimpleCache"),
            "CACHE_DEFAULT_TIMEOUT": int(os.getenv("CACHE_DEFAULT_TIMEOUT", "300")),
        }
        Cache(app, config=cache_config)
    except Exception:
        pass

    # Flask-Minify (minifica HTML/JS/CSS)
    try:
        from flask_minify import Minify

        Minify(app=app, html=True, js=True, cssless=True)
    except Exception:
        pass

    # WhiteNoise (static en prod sin nginx)
    try:
        from whitenoise import WhiteNoise

        app.wsgi_app = WhiteNoise(app.wsgi_app, root="app/static/", prefix="static/")
    except Exception:
        pass

    # -----------------------
    # Blueprints
    # -----------------------
    # Main
    try:
        from app.routes.main_routes import main_bp

        app.register_blueprint(main_bp)
    except Exception:
        # Fallback si tu blueprint está en otro path
        try:
            from app.routes import main_bp  # type: ignore

            app.register_blueprint(main_bp)
        except Exception:
            pass

    # Auth
    try:
        from app.routes.auth_routes import auth_bp

        app.register_blueprint(auth_bp)
    except Exception:
        try:
            from app.auth_routes import auth_bp  # type: ignore

            app.register_blueprint(auth_bp)
        except Exception:
            pass

    # Printful (si existe)
    try:
        from app.routes.printful_routes import printful_bp

        app.register_blueprint(printful_bp, url_prefix="/printful")
    except Exception:
        pass

    # Admin (si existe)
    try:
        from app.routes.admin_routes import admin_bp

        app.register_blueprint(admin_bp, url_prefix="/admin")
    except Exception:
        pass

    # -----------------------
    # Healthcheck
    # -----------------------
    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app
