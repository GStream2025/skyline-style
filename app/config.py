from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, Optional


# =============================================================================
# Utils
# =============================================================================

_TRUTHY = {"1", "true", "yes", "y", "on"}
_FALSY = {"0", "false", "no", "n", "off"}


def truthy(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    v = value.strip().lower()
    if v in _TRUTHY:
        return True
    if v in _FALSY:
        return False
    return default


def env_str(key: str, default: str = "") -> str:
    return (os.getenv(key) or default).strip()


def env_int(key: str, default: int) -> int:
    raw = os.getenv(key)
    if raw is None:
        return default
    try:
        return int(raw.strip())
    except ValueError:
        return default


def normalize_database_url(raw: Optional[str]) -> str:
    """
    Render suele entregar DATABASE_URL con 'postgres://'
    SQLAlchemy espera 'postgresql://'
    """
    if not raw or not raw.strip():
        return "sqlite:///skyline_local.db"

    url = raw.strip()
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)

    return url


def csp_for_tailwind_cdn() -> Dict[str, list]:
    """
    CSP compatible con Tailwind CDN + Google Fonts + imágenes externas.
    Si después eliminás CDN y usás assets locales, se puede endurecer.
    """
    return {
        "default-src": ["'self'"],
        "base-uri": ["'self'"],
        "form-action": ["'self'"],
        "frame-ancestors": ["'none'"],
        "object-src": ["'none'"],

        # Imágenes (incluye data: para svg/base64)
        "img-src": ["'self'", "data:", "https:"],

        # Estilos (Tailwind inline + Google Fonts)
        "style-src": ["'self'", "'unsafe-inline'", "https:"],

        # Scripts (Tailwind CDN usa inline + https)
        "script-src": ["'self'", "'unsafe-inline'", "https:"],

        # Fuentes
        "font-src": ["'self'", "data:", "https:"],

        # Conexiones (si usás APIs externas)
        "connect-src": ["'self'", "https:"],
    }


# =============================================================================
# Config Base
# =============================================================================

class BaseConfig:
    """
    Configuración base Skyline Store (Flask 3 / Render ready).
    - Segura por defecto
    - Ajustable por env vars
    """

    # -------------------------------------------------------------------------
    # Entorno
    # -------------------------------------------------------------------------
    ENV: str = env_str("FLASK_ENV", "production").lower()
    DEBUG: bool = False
    TESTING: bool = False

    # -------------------------------------------------------------------------
    # App / Server
    # -------------------------------------------------------------------------
    HOST: str = env_str("HOST", "0.0.0.0")
    PORT: int = env_int("PORT", 5000)

    # URL pública (útil para links absolutos, canonical, mails, etc.)
    SITE_URL: str = env_str("SITE_URL", "").rstrip("/")

    # Si te rompe subdominios, dejalo vacío
    SERVER_NAME: str = env_str("SERVER_NAME", "")

    # Preferencia de esquema (ProxyFix/Talisman ayudan)
    PREFERRED_URL_SCHEME: str = "https" if ENV == "production" else "http"
    TRUST_PROXY_HEADERS: bool = truthy(os.getenv("TRUST_PROXY_HEADERS"), default=(ENV == "production"))

    # -------------------------------------------------------------------------
    # Seguridad / Sesión / Cookies
    # -------------------------------------------------------------------------
    # En prod NO queremos fallback “dev”
    SECRET_KEY: str = env_str("SECRET_KEY", "dev_skyline_fallback")

    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = env_str("SESSION_COOKIE_SAMESITE", "Lax")

    # En prod: secure cookies por defecto
    SESSION_COOKIE_SECURE: bool = truthy(os.getenv("SESSION_COOKIE_SECURE"), default=(ENV == "production"))

    # Duración de sesión (segundos) — default 7 días
    PERMANENT_SESSION_LIFETIME: int = env_int("PERMANENT_SESSION_LIFETIME", 604800)

    # -------------------------------------------------------------------------
    # Logging
    # -------------------------------------------------------------------------
    LOG_LEVEL: str = env_str("LOG_LEVEL", "INFO").upper()

    # -------------------------------------------------------------------------
    # Database (SQLAlchemy)
    # -------------------------------------------------------------------------
    DATABASE_URL: str = normalize_database_url(os.getenv("DATABASE_URL"))
    SQLALCHEMY_DATABASE_URI: str = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False

    # Engine options (Postgres en Render)
    # Nota: para SQLite, pool_size/max_overflow pueden no aplicar, pero no rompe.
    SQLALCHEMY_ENGINE_OPTIONS: Dict[str, Any] = {
        "pool_pre_ping": True,
        "pool_recycle": env_int("DB_POOL_RECYCLE", 280),
        "pool_size": env_int("DB_POOL_SIZE", 5),
        "max_overflow": env_int("DB_MAX_OVERFLOW", 10),
    }

    # -------------------------------------------------------------------------
    # Performance: minify / compress / caching
    # -------------------------------------------------------------------------
    ENABLE_MINIFY: bool = truthy(os.getenv("ENABLE_MINIFY"), default=(ENV == "production"))
    ENABLE_COMPRESS: bool = truthy(os.getenv("ENABLE_COMPRESS"), default=True)

    # Cache
    CACHE_TYPE: str = env_str("CACHE_TYPE", "SimpleCache")
    CACHE_DEFAULT_TIMEOUT: int = env_int("CACHE_DEFAULT_TIMEOUT", 300)

    # -------------------------------------------------------------------------
    # Printful / Dropshipping
    # -------------------------------------------------------------------------
    # ✅ Estándar recomendado: PRINTFUL_API_KEY
    # Acepta alias viejo para no romper despliegues.
    PRINTFUL_API_KEY: str = env_str("PRINTFUL_API_KEY", env_str("PRINTFUL_KEY", ""))
    PRINTFUL_STORE_ID: str = env_str("PRINTFUL_STORE_ID", "")
    PRINTFUL_CACHE_TTL: int = env_int("PRINTFUL_CACHE_TTL", 300)

    # -------------------------------------------------------------------------
    # Mercado Pago
    # -------------------------------------------------------------------------
    MP_PUBLIC_KEY: str = env_str("MP_PUBLIC_KEY", "")
    MP_ACCESS_TOKEN: str = env_str("MP_ACCESS_TOKEN", "")

    # -------------------------------------------------------------------------
    # Stripe
    # -------------------------------------------------------------------------
    STRIPE_PUBLIC_KEY: str = env_str("STRIPE_PUBLIC_KEY", "")
    STRIPE_SECRET_KEY: str = env_str("STRIPE_SECRET_KEY", "")

    # -------------------------------------------------------------------------
    # PayPal
    # -------------------------------------------------------------------------
    PAYPAL_CLIENT_ID: str = env_str("PAYPAL_CLIENT_ID", "")
    PAYPAL_SECRET: str = env_str("PAYPAL_SECRET", "")

    # -------------------------------------------------------------------------
    # Seguridad avanzada (Flask-Talisman)
    # -------------------------------------------------------------------------
    ENABLE_TALISMAN: bool = truthy(os.getenv("ENABLE_TALISMAN"), default=(ENV == "production"))
    FORCE_HTTPS: bool = truthy(os.getenv("FORCE_HTTPS"), default=(ENV == "production"))
    HSTS: bool = truthy(os.getenv("HSTS"), default=(ENV == "production"))

    # CSP lista para tu setup actual (Tailwind CDN, Google Fonts)
    CONTENT_SECURITY_POLICY: Dict[str, list] = csp_for_tailwind_cdn()

    # -------------------------------------------------------------------------
    # Email (opcional)
    # -------------------------------------------------------------------------
    MAIL_SERVER: str = env_str("MAIL_SERVER", "")
    MAIL_PORT: int = env_int("MAIL_PORT", 587)
    MAIL_USE_TLS: bool = truthy(os.getenv("MAIL_USE_TLS"), default=True)
    MAIL_USE_SSL: bool = truthy(os.getenv("MAIL_USE_SSL"), default=False)
    MAIL_USERNAME: str = env_str("MAIL_USERNAME", "")
    MAIL_PASSWORD: str = env_str("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER: str = env_str("MAIL_DEFAULT_SENDER", "")

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
    ENV = "development"
    DEBUG = True
    LOG_LEVEL = env_str("LOG_LEVEL", "DEBUG").upper()

    # En dev no forzamos secure cookies
    SESSION_COOKIE_SECURE = False
    PREFERRED_URL_SCHEME = "http"

    # SQLite/Dev: pool simple
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

    # En dev normalmente NO queremos minify (para debug)
    ENABLE_MINIFY = truthy(os.getenv("ENABLE_MINIFY"), default=False)


class ProductionConfig(BaseConfig):
    ENV = "production"
    DEBUG = False
    LOG_LEVEL = env_str("LOG_LEVEL", "INFO").upper()

    # En producción: secret key real (sin fallback)
    SECRET_KEY = env_str("SECRET_KEY", "")

    # En prod endurecemos cookies
    SESSION_COOKIE_SECURE = truthy(os.getenv("SESSION_COOKIE_SECURE"), default=True)
    SESSION_COOKIE_SAMESITE = env_str("SESSION_COOKIE_SAMESITE", "Lax")

    ENABLE_MINIFY = truthy(os.getenv("ENABLE_MINIFY"), default=True)


def get_config(env_name: Optional[str] = None):
    """
    Devuelve la clase correcta.
    Prioridad:
      1) parámetro env_name
      2) FLASK_ENV
    """
    env = (env_name or env_str("FLASK_ENV", "production")).lower()
    if env == "development":
        return DevelopmentConfig
    return ProductionConfig


# Compat opcional
config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
}
