from __future__ import annotations

import os
from datetime import timedelta
from typing import Any, Dict, Optional


# =============================================================================
# Utils (env parsing) — robusto
# =============================================================================

_TRUE = {"1", "true", "yes", "y", "on"}
_FALSE = {"0", "false", "no", "n", "off"}


def env_str(key: str, default: str = "") -> str:
    v = os.getenv(key)
    return (default if v is None else str(v)).strip()


def env_int(key: str, default: int) -> int:
    v = os.getenv(key)
    if v is None:
        return default
    try:
        return int(str(v).strip())
    except Exception:
        return default


def env_bool(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    s = str(v).strip().lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return default


def normalize_database_url(raw: Optional[str]) -> str:
    """
    Render suele entregar DATABASE_URL con 'postgres://'
    SQLAlchemy espera 'postgresql://'
    """
    if not raw or not str(raw).strip():
        return "sqlite:///skyline_local.db"

    url = str(raw).strip()
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    return url


def normalize_samesite(raw: str, default: str = "Lax") -> str:
    s = (raw or default).strip()
    if s not in {"Lax", "Strict", "None"}:
        return default
    return s


def _is_sqlite(uri: str) -> bool:
    u = (uri or "").strip().lower()
    return u.startswith("sqlite:")


def csp_for_tailwind_cdn() -> Dict[str, list]:
    """
    CSP compatible con Tailwind CDN + Google Fonts + imágenes externas.
    Si luego eliminás CDN y usás assets locales, se puede endurecer.
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
    Skyline Store — Config PRO / Bulletproof

    Mejores prácticas:
    - No rompe en local
    - Render/Postgres listo
    - Seguridad razonable por defecto
    - Producción sin SECRET_KEY => error (en ProductionConfig)
    """

    # -----------------------------
    # Environment detection
    # -----------------------------
    FLASK_ENV: str = env_str("FLASK_ENV", env_str("ENV", "production")).lower()
    DEBUG: bool = env_bool("DEBUG", env_bool("FLASK_DEBUG", False))
    TESTING: bool = env_bool("TESTING", False)

    # Normalizamos ENV final
    ENV: str = (
        "development" if FLASK_ENV in {"dev", "development"} or DEBUG else "production"
    )

    # -----------------------------
    # Server / URL
    # -----------------------------
    HOST: str = env_str("HOST", "0.0.0.0")
    PORT: int = env_int("PORT", 5000)

    SITE_URL: str = env_str("SITE_URL", "").rstrip("/")
    SERVER_NAME: str = env_str("SERVER_NAME", "")
    PREFERRED_URL_SCHEME: str = "https" if ENV == "production" else "http"

    TRUST_PROXY_HEADERS: bool = env_bool(
        "TRUST_PROXY_HEADERS", default=(ENV == "production")
    )

    # -----------------------------
    # Security / Sessions / Cookies
    # -----------------------------
    # DEV fallback permitido solo en Base/Dev
    SECRET_KEY: str = env_str("SECRET_KEY", "dev_skyline_fallback_change_me")

    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = normalize_samesite(
        env_str("SESSION_COOKIE_SAMESITE", env_str("SESSION_SAMESITE", "Lax")), "Lax"
    )
    SESSION_COOKIE_SECURE: bool = env_bool(
        "SESSION_COOKIE_SECURE",
        env_bool("COOKIE_SECURE", default=(ENV == "production")),
    )

    # 7 días por defecto
    SESSION_DAYS: int = max(1, env_int("SESSION_DAYS", 7))
    PERMANENT_SESSION_LIFETIME = timedelta(days=SESSION_DAYS)

    # -----------------------------
    # Uploads / Limits
    # -----------------------------
    UPLOADS_DIR: str = env_str("UPLOADS_DIR", "static/uploads")
    MAX_UPLOAD_MB: int = max(1, env_int("MAX_UPLOAD_MB", 20))
    MAX_CONTENT_LENGTH: int = MAX_UPLOAD_MB * 1024 * 1024  # bytes

    # -----------------------------
    # Logging
    # -----------------------------
    LOG_LEVEL: str = env_str("LOG_LEVEL", "DEBUG" if DEBUG else "INFO").upper()

    # -----------------------------
    # Database / SQLAlchemy
    # -----------------------------
    DATABASE_URL: str = normalize_database_url(os.getenv("DATABASE_URL"))
    SQLALCHEMY_DATABASE_URI: str = env_str("SQLALCHEMY_DATABASE_URI", DATABASE_URL)
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False

    # Engine options:
    # - Para Postgres (Render): pool_pre_ping + recycle + pool sizes
    # - Para SQLite: dejamos solo pool_pre_ping (lo demás puede molestar)
    DB_POOL_RECYCLE: int = max(30, env_int("DB_POOL_RECYCLE", 280))
    DB_POOL_SIZE: int = max(1, env_int("DB_POOL_SIZE", 5))
    DB_MAX_OVERFLOW: int = max(0, env_int("DB_MAX_OVERFLOW", 10))

    @classmethod
    def _engine_options(cls) -> Dict[str, Any]:
        uri = cls.SQLALCHEMY_DATABASE_URI
        if _is_sqlite(uri):
            return {"pool_pre_ping": True}
        return {
            "pool_pre_ping": True,
            "pool_recycle": cls.DB_POOL_RECYCLE,
            "pool_size": cls.DB_POOL_SIZE,
            "max_overflow": cls.DB_MAX_OVERFLOW,
        }

    SQLALCHEMY_ENGINE_OPTIONS: Dict[str, Any] = {}  # se setea en as_flask_config()

    # -----------------------------
    # Performance / Cache
    # -----------------------------
    ENABLE_MINIFY: bool = env_bool("ENABLE_MINIFY", default=(ENV == "production"))
    ENABLE_COMPRESS: bool = env_bool("ENABLE_COMPRESS", default=True)

    CACHE_TYPE: str = env_str("CACHE_TYPE", "SimpleCache")
    CACHE_DEFAULT_TIMEOUT: int = max(10, env_int("CACHE_DEFAULT_TIMEOUT", 300))

    # -----------------------------
    # Printful / Dropshipping
    # -----------------------------
    PRINTFUL_API_KEY: str = env_str(
        "PRINTFUL_API_KEY", env_str("PRINTFUL_KEY", env_str("PRINTFUL_API_TOKEN", ""))
    )
    PRINTFUL_STORE_ID: str = env_str("PRINTFUL_STORE_ID", "")
    PRINTFUL_CACHE_TTL: int = max(30, env_int("PRINTFUL_CACHE_TTL", 300))
    ENABLE_PRINTFUL: bool = env_bool("ENABLE_PRINTFUL", default=bool(PRINTFUL_API_KEY))

    # -----------------------------
    # Payments
    # -----------------------------
    MP_PUBLIC_KEY: str = env_str("MP_PUBLIC_KEY", "")
    MP_ACCESS_TOKEN: str = env_str("MP_ACCESS_TOKEN", "")
    ENABLE_PAYMENTS: bool = env_bool("ENABLE_PAYMENTS", default=False)

    STRIPE_PUBLIC_KEY: str = env_str("STRIPE_PUBLIC_KEY", "")
    STRIPE_SECRET_KEY: str = env_str("STRIPE_SECRET_KEY", "")

    PAYPAL_CLIENT_ID: str = env_str("PAYPAL_CLIENT_ID", "")
    PAYPAL_SECRET: str = env_str("PAYPAL_SECRET", "")

    # -----------------------------
    # Talisman / CSP
    # -----------------------------
    ENABLE_TALISMAN: bool = env_bool("ENABLE_TALISMAN", default=(ENV == "production"))
    FORCE_HTTPS: bool = env_bool("FORCE_HTTPS", default=(ENV == "production"))
    HSTS: bool = env_bool("HSTS", default=(ENV == "production"))

    CONTENT_SECURITY_POLICY: Dict[str, list] = csp_for_tailwind_cdn()

    # -----------------------------
    # Email (opcional)
    # -----------------------------
    MAIL_SERVER: str = env_str("MAIL_SERVER", "")
    MAIL_PORT: int = env_int("MAIL_PORT", 587)
    MAIL_USE_TLS: bool = env_bool("MAIL_USE_TLS", default=True)
    MAIL_USE_SSL: bool = env_bool("MAIL_USE_SSL", default=False)
    MAIL_USERNAME: str = env_str("MAIL_USERNAME", "")
    MAIL_PASSWORD: str = env_str("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER: str = env_str("MAIL_DEFAULT_SENDER", "")

    # -----------------------------
    # Helpers
    # -----------------------------
    @classmethod
    def is_production(cls) -> bool:
        return cls.ENV == "production"

    @classmethod
    def is_development(cls) -> bool:
        return cls.ENV == "development"

    @classmethod
    def as_flask_config(cls) -> Dict[str, Any]:
        """
        Devuelve un dict listo para app.config.update(...)
        (y evita edge-cases de atributos calculados).
        """
        cfg: Dict[str, Any] = {}

        # Copiamos solo UPPERCASE
        for k, v in cls.__dict__.items():
            if k.isupper():
                cfg[k] = v

        # Calculados
        cfg["SQLALCHEMY_ENGINE_OPTIONS"] = cls._engine_options()
        cfg["PERMANENT_SESSION_LIFETIME"] = cls.PERMANENT_SESSION_LIFETIME
        cfg["MAX_CONTENT_LENGTH"] = cls.MAX_CONTENT_LENGTH

        # Limpieza SERVER_NAME (si vacío -> no setear)
        if not cfg.get("SERVER_NAME"):
            cfg.pop("SERVER_NAME", None)

        return cfg


class DevelopmentConfig(BaseConfig):
    ENV = "development"
    DEBUG = True
    LOG_LEVEL = env_str("LOG_LEVEL", "DEBUG").upper()

    SESSION_COOKIE_SECURE = False
    PREFERRED_URL_SCHEME = "http"

    ENABLE_MINIFY = env_bool("ENABLE_MINIFY", default=False)


class ProductionConfig(BaseConfig):
    ENV = "production"
    DEBUG = False
    LOG_LEVEL = env_str("LOG_LEVEL", "INFO").upper()

    # En prod: SECRET_KEY real obligatorio
    SECRET_KEY = env_str("SECRET_KEY", "").strip()
    if not SECRET_KEY:
        # OJO: no levantamos error en import (para tooling),
        # lo validás en create_app() o al cargar config.
        pass

    SESSION_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE", default=True)
    SESSION_COOKIE_SAMESITE = normalize_samesite(
        env_str("SESSION_COOKIE_SAMESITE", "Lax"), "Lax"
    )

    ENABLE_MINIFY = env_bool("ENABLE_MINIFY", default=True)


def get_config(env_name: Optional[str] = None):
    """
    Devuelve la clase correcta.

    Prioridad:
      1) env_name explícito
      2) FLASK_ENV / ENV
      3) DEBUG/FLASK_DEBUG
    """
    if env_name:
        e = str(env_name).strip().lower()
    else:
        e = env_str("FLASK_ENV", env_str("ENV", "")).lower()

    debug = env_bool("DEBUG", env_bool("FLASK_DEBUG", False))

    if e in {"development", "dev"} or debug:
        return DevelopmentConfig
    return ProductionConfig


# Compat opcional
config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
}
