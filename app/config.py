from __future__ import annotations

import os
from urllib.parse import urlparse


def _truthy(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _normalize_database_url(raw: str | None) -> str:
    """
    Render suele entregar DATABASE_URL con 'postgres://'
    SQLAlchemy (psycopg2) espera 'postgresql://'
    """
    if not raw:
        return "sqlite:///skyline_local.db"

    raw = raw.strip()
    if raw.startswith("postgres://"):
        raw = raw.replace("postgres://", "postgresql://", 1)

    return raw


class BaseConfig:
    """
    Configuración base (común a todos los entornos).
    Se extiende con DevelopmentConfig y ProductionConfig.
    """

    # -------------------------------------------------------------------------
    # Entorno
    # -------------------------------------------------------------------------
    ENV = os.getenv("FLASK_ENV", "production").lower()
    DEBUG = False

    # -------------------------------------------------------------------------
    # App / servidor
    # -------------------------------------------------------------------------
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", "5000"))

    # URL pública del sitio (opcional, útil para links absolutos / emails)
    SITE_URL = os.getenv("SITE_URL", "").rstrip("/")  # ej: https://skyline-style.onrender.com

    # Server Name (opcional) - NO lo setees si te da problemas con subdominios
    SERVER_NAME = os.getenv("SERVER_NAME", "")

    # -------------------------------------------------------------------------
    # Seguridad / cookies
    # -------------------------------------------------------------------------
    SECRET_KEY = os.getenv("SECRET_KEY") or "dev_skyline_fallback"

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")

    # En prod: secure cookies por defecto
    SESSION_COOKIE_SECURE = _truthy(os.getenv("SESSION_COOKIE_SECURE"), default=(ENV == "production"))

    # Si estás detrás de proxy (Render), esto ayuda a URLs https correctas
    PREFERRED_URL_SCHEME = "https" if ENV == "production" else "http"
    TRUST_PROXY_HEADERS = _truthy(os.getenv("TRUST_PROXY_HEADERS"), default=(ENV == "production"))

    # Opcional: duración de sesión (segundos). Ej 7 días = 604800
    PERMANENT_SESSION_LIFETIME = int(os.getenv("PERMANENT_SESSION_LIFETIME", "604800"))

    # -------------------------------------------------------------------------
    # Logs
    # -------------------------------------------------------------------------
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

    # -------------------------------------------------------------------------
    # Base de datos (SQLAlchemy)
    # -------------------------------------------------------------------------
    DATABASE_URL = _normalize_database_url(os.getenv("DATABASE_URL"))
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Engine options pro (especialmente para Postgres en Render)
    # - pool_pre_ping: evita conexiones muertas
    # - pool_recycle: recicla conexiones viejas (Render a veces corta)
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": int(os.getenv("DB_POOL_RECYCLE", "280")),
        "pool_size": int(os.getenv("DB_POOL_SIZE", "5")),
        "max_overflow": int(os.getenv("DB_MAX_OVERFLOW", "10")),
    }

    # -------------------------------------------------------------------------
    # Compresión / minify / cache
    # -------------------------------------------------------------------------
    ENABLE_MINIFY = _truthy(os.getenv("ENABLE_MINIFY"), default=True)
    ENABLE_COMPRESS = _truthy(os.getenv("ENABLE_COMPRESS"), default=True)

    # Cache (Flask-Caching) — simple por defecto
    CACHE_TYPE = os.getenv("CACHE_TYPE", "SimpleCache")
    CACHE_DEFAULT_TIMEOUT = int(os.getenv("CACHE_DEFAULT_TIMEOUT", "300"))

    # -------------------------------------------------------------------------
    # Printful
    # -------------------------------------------------------------------------
    # Acepta ambos nombres para que no se rompa si cambiaste la env var
    PRINTFUL_KEY = os.getenv("PRINTFUL_KEY") or os.getenv("PRINTFUL_API_KEY", "")
    PRINTFUL_STORE_ID = os.getenv("PRINTFUL_STORE_ID", "")

    # -------------------------------------------------------------------------
    # Mercado Pago
    # -------------------------------------------------------------------------
    MP_PUBLIC_KEY = os.getenv("MP_PUBLIC_KEY", "")
    MP_ACCESS_TOKEN = os.getenv("MP_ACCESS_TOKEN", "")

    # -------------------------------------------------------------------------
    # Stripe
    # -------------------------------------------------------------------------
    STRIPE_PUBLIC_KEY = os.getenv("STRIPE_PUBLIC_KEY", "")
    STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")

    # -------------------------------------------------------------------------
    # PayPal
    # -------------------------------------------------------------------------
    PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID", "")
    PAYPAL_SECRET = os.getenv("PAYPAL_SECRET", "")

    # -------------------------------------------------------------------------
    # Seguridad avanzada (opcional para Flask-Talisman)
    # -------------------------------------------------------------------------
    ENABLE_TALISMAN = _truthy(os.getenv("ENABLE_TALISMAN"), default=(ENV == "production"))
    FORCE_HTTPS = _truthy(os.getenv("FORCE_HTTPS"), default=(ENV == "production"))

    # CSP básica (si activás Talisman)
    # Nota: ajustala si cargas recursos externos (fonts, CDNs, etc.)
    CONTENT_SECURITY_POLICY = {
        "default-src": ["'self'"],
        "img-src": ["'self'", "data:", "https:"],
        "style-src": ["'self'", "'unsafe-inline'", "https:"],
        "script-src": ["'self'", "'unsafe-inline'", "https:"],
    }

    # -------------------------------------------------------------------------
    # Email (si usás Flask-Mail) — opcional
    # -------------------------------------------------------------------------
    MAIL_SERVER = os.getenv("MAIL_SERVER", "")
    MAIL_PORT = int(os.getenv("MAIL_PORT", "587"))
    MAIL_USE_TLS = _truthy(os.getenv("MAIL_USE_TLS"), default=True)
    MAIL_USE_SSL = _truthy(os.getenv("MAIL_USE_SSL"), default=False)
    MAIL_USERNAME = os.getenv("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER", "")

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------
    @classmethod
    def is_production(cls) -> bool:
        return cls.ENV == "production"

    @classmethod
    def is_development(cls) -> bool:
        return cls.ENV == "development"


class DevelopmentConfig(BaseConfig):
    """Configuración para desarrollo (local)."""
    ENV = "development"
    DEBUG = True
    LOG_LEVEL = os.getenv("LOG_LEVEL", "DEBUG").upper()

    # En dev permitimos cookies no-secure
    SESSION_COOKIE_SECURE = False
    PREFERRED_URL_SCHEME = "http"

    # En dev normalmente querés menos pool (sqlite no lo necesita)
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True
    }


class ProductionConfig(BaseConfig):
    """Configuración para producción (Render)."""
    ENV = "production"
    DEBUG = False
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

    # En producción: SI o SI secret key definida
    SECRET_KEY = os.getenv("SECRET_KEY") or ""  # no fallback real en producción


def get_config():
    """
    Devuelve la clase de configuración correcta según FLASK_ENV.
    """
    env = os.getenv("FLASK_ENV", "production").lower()
    if env == "development":
        return DevelopmentConfig
    return ProductionConfig


# Diccionario opcional por compatibilidad
config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
}
