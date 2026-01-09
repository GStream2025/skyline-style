from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Dict, Optional, Type


# =============================================================================
# Env parsing — robusto + seguro
# =============================================================================

_TRUE = {"1", "true", "yes", "y", "on"}
_FALSE = {"0", "false", "no", "n", "off"}


def env_str(key: str, default: str = "") -> str:
    v = os.getenv(key)
    return (default if v is None else str(v)).strip()


def env_int(key: str, default: int, *, min_v: Optional[int] = None, max_v: Optional[int] = None) -> int:
    s = env_str(key, "")
    if not s:
        v = default
    else:
        try:
            v = int(s)
        except Exception:
            v = default
    if min_v is not None:
        v = max(min_v, v)
    if max_v is not None:
        v = min(max_v, v)
    return v


def env_bool(key: str, default: bool = False) -> bool:
    s = env_str(key, "")
    if not s:
        return default
    s = s.lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return default


def normalize_database_url(raw: Optional[str]) -> str:
    """
    Render suele dar DATABASE_URL con postgres://
    SQLAlchemy espera postgresql://
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
    return (uri or "").strip().lower().startswith("sqlite:")


def csp_for_tailwind_cdn() -> Dict[str, list]:
    """
    CSP compatible con Tailwind CDN + Google Fonts + imágenes externas.
    Si luego eliminás CDN, podés endurecer (quitar unsafe-inline).
    """
    return {
        "default-src": ["'self'"],
        "base-uri": ["'self'"],
        "form-action": ["'self'"],
        "frame-ancestors": ["'none'"],
        "object-src": ["'none'"],
        "img-src": ["'self'", "data:", "https:"],
        "style-src": ["'self'", "'unsafe-inline'", "https:"],
        "script-src": ["'self'", "'unsafe-inline'", "https:"],
        "font-src": ["'self'", "data:", "https:"],
        "connect-src": ["'self'", "https:"],
    }


# =============================================================================
# Config Base — PRO / Bulletproof
# =============================================================================

@dataclass(frozen=True)
class BaseConfig:
    """
    Skyline Store — Config PRO / Bulletproof

    10 mejoras aplicadas:
    1) SECRET_KEY: fallback seguro solo local + guard fuerte en producción
    2) CSRF estable: WTF_CSRF_TIME_LIMIT configurable (default 3600)
    3) Cookies: Secure/SameSite/HttpOnly consistentes (evita token mismatch)
    4) SESSION cookie prefix + lifetime robusto
    5) DB normalizada (postgres:// -> postgresql://) + engine options seguros
    6) Validación fuerte de valores (rangos para upload/cache/pools)
    7) SERVER_NAME no se setea si está vacío (evita bugs raros)
    8) Prefer scheme auto (http dev / https prod)
    9) Flags “Render/Proxy” por defecto sensatos
    10) as_flask_config() copia solo UPPERCASE + calculados (sin edge cases)
    """

    # -----------------------------
    # Environment detection
    # -----------------------------
    FLASK_ENV: str = env_str("FLASK_ENV", env_str("ENV", "production")).lower()
    DEBUG: bool = env_bool("DEBUG", env_bool("FLASK_DEBUG", False))
    TESTING: bool = env_bool("TESTING", False)

    # ENV final (si DEBUG => development)
    ENV: str = "development" if (FLASK_ENV in {"dev", "development"} or DEBUG) else "production"

    # -----------------------------
    # Server / URL
    # -----------------------------
    HOST: str = env_str("HOST", "0.0.0.0")
    PORT: int = env_int("PORT", 5000, min_v=1, max_v=65535)

    SITE_URL: str = env_str("SITE_URL", "").rstrip("/")
    SERVER_NAME: str = env_str("SERVER_NAME", "")
    PREFERRED_URL_SCHEME: str = "https" if ENV == "production" else "http"

    # Render/ProxyFix friendly
    TRUST_PROXY_HEADERS: bool = env_bool("TRUST_PROXY_HEADERS", default=(ENV == "production"))

    # -----------------------------
    # Security / Sessions / Cookies
    # -----------------------------
    # En base: fallback SOLO local (producción lo valida abajo en ProductionConfig)
    SECRET_KEY: str = env_str("SECRET_KEY", "dev_skyline_fallback_change_me")

    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = normalize_samesite(
        env_str("SESSION_COOKIE_SAMESITE", env_str("SESSION_SAMESITE", "Lax")),
        "Lax",
    )
    SESSION_COOKIE_SECURE: bool = env_bool(
        "SESSION_COOKIE_SECURE",
        env_bool("COOKIE_SECURE", default=(ENV == "production")),
    )

    # nombre cookie estable (evita choques entre apps)
    SESSION_COOKIE_NAME: str = env_str("SESSION_COOKIE_NAME", "skyline_session")

    # Lifetime
    SESSION_DAYS: int = env_int("SESSION_DAYS", 7, min_v=1, max_v=90)
    PERMANENT_SESSION_LIFETIME = timedelta(days=SESSION_DAYS)

    # -----------------------------
    # CSRF (Flask-WTF)
    # -----------------------------
    WTF_CSRF_ENABLED: bool = True
    WTF_CSRF_TIME_LIMIT: int = env_int("WTF_CSRF_TIME_LIMIT", 3600, min_v=300, max_v=86400)

    # -----------------------------
    # Uploads / Limits
    # -----------------------------
    UPLOADS_DIR: str = env_str("UPLOADS_DIR", "static/uploads")
    MAX_UPLOAD_MB: int = env_int("MAX_UPLOAD_MB", 20, min_v=1, max_v=200)
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

    # pool values (Render/Postgres friendly)
    DB_POOL_RECYCLE: int = env_int("DB_POOL_RECYCLE", 280, min_v=30, max_v=3600)
    DB_POOL_SIZE: int = env_int("DB_POOL_SIZE", 5, min_v=1, max_v=20)
    DB_MAX_OVERFLOW: int = env_int("DB_MAX_OVERFLOW", 10, min_v=0, max_v=50)

    # se setea en as_flask_config()
    SQLALCHEMY_ENGINE_OPTIONS: Dict[str, Any] = None  # type: ignore[assignment]

    # -----------------------------
    # Performance / Cache
    # -----------------------------
    ENABLE_MINIFY: bool = env_bool("ENABLE_MINIFY", default=(ENV == "production"))
    ENABLE_COMPRESS: bool = env_bool("ENABLE_COMPRESS", default=True)

    CACHE_TYPE: str = env_str("CACHE_TYPE", "SimpleCache")
    CACHE_DEFAULT_TIMEOUT: int = env_int("CACHE_DEFAULT_TIMEOUT", 300, min_v=10, max_v=86400)

    # -----------------------------
    # Printful
    # -----------------------------
    PRINTFUL_API_KEY: str = env_str(
        "PRINTFUL_API_KEY",
        env_str("PRINTFUL_KEY", env_str("PRINTFUL_API_TOKEN", "")),
    )
    PRINTFUL_STORE_ID: str = env_str("PRINTFUL_STORE_ID", "")
    PRINTFUL_CACHE_TTL: int = env_int("PRINTFUL_CACHE_TTL", 300, min_v=30, max_v=86400)
    ENABLE_PRINTFUL: bool = env_bool("ENABLE_PRINTFUL", default=bool(PRINTFUL_API_KEY))

    # -----------------------------
    # Payments (flags)
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
    MAIL_PORT: int = env_int("MAIL_PORT", 587, min_v=1, max_v=65535)
    MAIL_USE_TLS: bool = env_bool("MAIL_USE_TLS", default=True)
    MAIL_USE_SSL: bool = env_bool("MAIL_USE_SSL", default=False)
    MAIL_USERNAME: str = env_str("MAIL_USERNAME", "")
    MAIL_PASSWORD: str = env_str("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER: str = env_str("MAIL_DEFAULT_SENDER", "")

    # -----------------------------
    # Internal helpers
    # -----------------------------
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

    @classmethod
    def as_flask_config(cls) -> Dict[str, Any]:
        cfg: Dict[str, Any] = {}

        # Copiamos solo UPPERCASE
        for k, v in cls.__dict__.items():
            if k.isupper():
                cfg[k] = v

        # Calculados / overrides seguros
        cfg["SQLALCHEMY_ENGINE_OPTIONS"] = cls._engine_options()
        cfg["PERMANENT_SESSION_LIFETIME"] = cls.PERMANENT_SESSION_LIFETIME
        cfg["MAX_CONTENT_LENGTH"] = cls.MAX_CONTENT_LENGTH

        # Si SERVER_NAME vacío => no setear (evita problemas)
        if not cfg.get("SERVER_NAME"):
            cfg.pop("SERVER_NAME", None)

        return cfg


# =============================================================================
# Environments
# =============================================================================

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

    # En prod: SECRET_KEY obligatorio (si falta => error en validate_required())
    SECRET_KEY = env_str("SECRET_KEY", "").strip()

    SESSION_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE", default=True)
    SESSION_COOKIE_SAMESITE = normalize_samesite(env_str("SESSION_COOKIE_SAMESITE", "Lax"), "Lax")

    ENABLE_MINIFY = env_bool("ENABLE_MINIFY", default=True)

    @classmethod
    def validate_required(cls) -> None:
        """
        Llamar 1 vez en create_app() en producción.
        Esto corta el problema de 'token no coincide' por SECRET_KEY vacío/cambiante.
        """
        if not cls.SECRET_KEY or len(cls.SECRET_KEY) < 32:
            raise RuntimeError(
                "ProductionConfig: SECRET_KEY faltante o muy corto. "
                "Setealo fijo en Render (>=32 chars) para evitar CSRF/session invalid."
            )


# =============================================================================
# Selector
# =============================================================================

def get_config(env_name: Optional[str] = None) -> Type[BaseConfig]:
    """
    Prioridad:
      1) env_name explícito
      2) FLASK_ENV / ENV
      3) DEBUG/FLASK_DEBUG
    """
    e = (str(env_name).strip().lower() if env_name else env_str("FLASK_ENV", env_str("ENV", "")).lower())
    debug = env_bool("DEBUG", env_bool("FLASK_DEBUG", False))

    if e in {"development", "dev"} or debug:
        return DevelopmentConfig
    return ProductionConfig


# Compat opcional
config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
}
