# app/config.py — Skyline Store (ULTRA PRO MAX · FINAL · Render-proof · NO BREAK)
from __future__ import annotations

import os
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


def env_opt_int(
    key: str,
    default: Optional[int],
    *,
    min_v: Optional[int] = None,
    max_v: Optional[int] = None,
) -> Optional[int]:
    """
    Permite valores vacíos -> None (útil para WTF_CSRF_TIME_LIMIT=None).
    """
    s = env_str(key, "")
    if not s:
        return default
    try:
        v = int(s)
    except Exception:
        return default
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


# =============================================================================
# Normalizers
# =============================================================================

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


def normalize_db_any(raw: Optional[str]) -> str:
    """
    Normaliza tanto DATABASE_URL como SQLALCHEMY_DATABASE_URI.
    Si viene vacío, devuelve "" (NO aplica fallback acá).
    """
    if not raw:
        return ""
    u = str(raw).strip()
    if not u:
        return ""
    if u.startswith("postgres://"):
        u = u.replace("postgres://", "postgresql://", 1)
    return u


def normalize_samesite(raw: str, default: str = "Lax") -> str:
    s = (raw or default).strip()
    if s not in {"Lax", "Strict", "None"}:
        return default
    return s


def normalize_scheme(raw: str, default: str = "http") -> str:
    s = (raw or default).strip().lower()
    return "https" if s == "https" else "http"


def _is_sqlite(uri: str) -> bool:
    return (uri or "").strip().lower().startswith("sqlite:")


def _is_prod(env_value: str) -> bool:
    return (env_value or "").strip().lower() == "production"


def csp_for_tailwind_cdn() -> Dict[str, list]:
    """
    CSP compatible con Tailwind CDN + Google Fonts + imágenes externas.
    IMPORTANTE: retorna un dict NUEVO cada vez (no compartido).
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

class BaseConfig:
    """
    Skyline Store — Config PRO / Bulletproof (NO BREAK / Render-safe)

    FIX CRÍTICO:
    - as_flask_config() incluye heredados (BaseConfig) + overrides (Production/Dev)
      usando MRO. Esto evita DB=None, CSRF_TTL=None, etc. en Render.
    """

    # -----------------------------
    # Environment detection
    # -----------------------------
    FLASK_ENV: str = env_str("FLASK_ENV", env_str("ENV", "production")).lower()
    DEBUG: bool = env_bool("DEBUG", env_bool("FLASK_DEBUG", False))
    TESTING: bool = env_bool("TESTING", False)

    ENV: str = "development" if (FLASK_ENV in {"dev", "development"} or DEBUG) else "production"
    IS_PROD: bool = _is_prod(ENV)

    # -----------------------------
    # App identity / URL
    # -----------------------------
    APP_NAME: str = env_str("APP_NAME", "Skyline Store")
    APP_URL: str = env_str("APP_URL", env_str("SITE_URL", "")).rstrip("/")
    SITE_URL: str = APP_URL

    HOST: str = env_str("HOST", "0.0.0.0")
    PORT: int = env_int("PORT", 5000, min_v=1, max_v=65535)

    SERVER_NAME: str = env_str("SERVER_NAME", "")
    PREFERRED_URL_SCHEME: str = normalize_scheme(env_str("PREFERRED_URL_SCHEME", ("https" if IS_PROD else "http")))

    TRUST_PROXY_HEADERS: bool = env_bool("TRUST_PROXY_HEADERS", default=IS_PROD)

    # -----------------------------
    # Security / Sessions / Cookies
    # -----------------------------
    SECRET_KEY: str = env_str("SECRET_KEY", "dev_skyline_fallback_change_me")

    SESSION_COOKIE_NAME: str = env_str("SESSION_COOKIE_NAME", "skyline_session")
    SESSION_COOKIE_HTTPONLY: bool = env_bool("SESSION_COOKIE_HTTPONLY", True)
    SESSION_COOKIE_SAMESITE: str = normalize_samesite(
        env_str("SESSION_COOKIE_SAMESITE", env_str("SESSION_SAMESITE", "Lax")),
        "Lax",
    )
    SESSION_COOKIE_SECURE: bool = env_bool("SESSION_COOKIE_SECURE", env_bool("COOKIE_SECURE", default=IS_PROD))

    SESSION_DAYS: int = env_int("SESSION_DAYS", 7, min_v=1, max_v=90)
    PERMANENT_SESSION_LIFETIME = timedelta(days=SESSION_DAYS)

    # -----------------------------
    # CSRF (Flask-WTF)
    # -----------------------------
    WTF_CSRF_ENABLED: bool = env_bool("WTF_CSRF_ENABLED", True)

    # vacío => None (sin expiración)
    WTF_CSRF_TIME_LIMIT: Optional[int] = env_opt_int("WTF_CSRF_TIME_LIMIT", 3600, min_v=300, max_v=86400)

    # Default tolerante (Render detrás de proxy); tu create_app también lo setea
    WTF_CSRF_SSL_STRICT: bool = env_bool("WTF_CSRF_SSL_STRICT", default=False)

    # si vacío, Flask-WTF usa SECRET_KEY (ideal si es estable)
    WTF_CSRF_SECRET_KEY: str = env_str("WTF_CSRF_SECRET_KEY", "")

    # -----------------------------
    # Uploads / Limits
    # -----------------------------
    UPLOADS_DIR: str = env_str("UPLOADS_DIR", "static/uploads")
    MAX_UPLOAD_MB: int = env_int("MAX_UPLOAD_MB", 20, min_v=1, max_v=200)
    MAX_CONTENT_LENGTH: int = MAX_UPLOAD_MB * 1024 * 1024

    # -----------------------------
    # Logging
    # -----------------------------
    LOG_LEVEL: str = env_str("LOG_LEVEL", "DEBUG" if DEBUG else "INFO").upper()

    # -----------------------------
    # Database / SQLAlchemy
    # -----------------------------
    DATABASE_URL: str = normalize_database_url(os.getenv("DATABASE_URL"))
    SQLALCHEMY_DATABASE_URI: str = normalize_db_any(env_str("SQLALCHEMY_DATABASE_URI", DATABASE_URL))
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False

    DB_POOL_RECYCLE: int = env_int("DB_POOL_RECYCLE", 280, min_v=30, max_v=3600)
    DB_POOL_SIZE: int = env_int("DB_POOL_SIZE", 5, min_v=1, max_v=30)
    DB_MAX_OVERFLOW: int = env_int("DB_MAX_OVERFLOW", 10, min_v=0, max_v=80)

    # -----------------------------
    # Performance / Cache
    # -----------------------------
    ENABLE_MINIFY: bool = env_bool("ENABLE_MINIFY", default=IS_PROD)
    ENABLE_COMPRESS: bool = env_bool("ENABLE_COMPRESS", default=True)

    CACHE_TYPE: str = env_str("CACHE_TYPE", "SimpleCache")
    CACHE_DEFAULT_TIMEOUT: int = env_int("CACHE_DEFAULT_TIMEOUT", 300, min_v=10, max_v=86400)

    # -----------------------------
    # Printful
    # -----------------------------
    PRINTFUL_API_KEY: str = env_str("PRINTFUL_API_KEY", env_str("PRINTFUL_KEY", env_str("PRINTFUL_API_TOKEN", "")))
    PRINTFUL_STORE_ID: str = env_str("PRINTFUL_STORE_ID", "")
    PRINTFUL_CACHE_TTL: int = env_int("PRINTFUL_CACHE_TTL", 300, min_v=30, max_v=86400)
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
    ENABLE_TALISMAN: bool = env_bool("ENABLE_TALISMAN", default=IS_PROD)
    FORCE_HTTPS: bool = env_bool("FORCE_HTTPS", default=IS_PROD)
    HSTS: bool = env_bool("HSTS", default=IS_PROD)

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
        """
        ✅ FIX CRÍTICO: incluye heredados + overrides usando MRO.
        Si usás cls.__dict__ solo, perdés BaseConfig en ProductionConfig/DevelopmentConfig.
        """
        cfg: Dict[str, Any] = {}

        # BaseConfig -> Subclase (subclase pisa)
        for base in reversed(cls.mro()):
            for k, v in getattr(base, "__dict__", {}).items():
                if k.isupper():
                    cfg[k] = v

        # Calculados
        cfg["SQLALCHEMY_ENGINE_OPTIONS"] = cls._engine_options()
        cfg["PERMANENT_SESSION_LIFETIME"] = cls.PERMANENT_SESSION_LIFETIME
        cfg["MAX_CONTENT_LENGTH"] = cls.MAX_CONTENT_LENGTH

        # CSP siempre nuevo
        cfg["CONTENT_SECURITY_POLICY"] = csp_for_tailwind_cdn()

        # Limpieza / normalizaciones
        if not str(cfg.get("SERVER_NAME") or "").strip():
            cfg.pop("SERVER_NAME", None)

        if not str(cfg.get("WTF_CSRF_SECRET_KEY") or "").strip():
            cfg.pop("WTF_CSRF_SECRET_KEY", None)

        cfg["SESSION_COOKIE_SAMESITE"] = normalize_samesite(str(cfg.get("SESSION_COOKIE_SAMESITE") or "Lax"), "Lax")
        cfg["PREFERRED_URL_SCHEME"] = normalize_scheme(str(cfg.get("PREFERRED_URL_SCHEME") or ("https" if cls.IS_PROD else "http")))

        # DB: normalizar de nuevo por si vino sobreescrito
        cfg["SQLALCHEMY_DATABASE_URI"] = normalize_db_any(str(cfg.get("SQLALCHEMY_DATABASE_URI") or ""))

        return cfg


# =============================================================================
# Environments
# =============================================================================

class DevelopmentConfig(BaseConfig):
    ENV = "development"
    IS_PROD = False
    DEBUG = True
    LOG_LEVEL = env_str("LOG_LEVEL", "DEBUG").upper()

    SESSION_COOKIE_SECURE = False
    PREFERRED_URL_SCHEME = normalize_scheme(env_str("PREFERRED_URL_SCHEME", "http"))

    WTF_CSRF_SSL_STRICT = env_bool("WTF_CSRF_SSL_STRICT", default=False)
    ENABLE_MINIFY = env_bool("ENABLE_MINIFY", default=False)


class ProductionConfig(BaseConfig):
    ENV = "production"
    IS_PROD = True
    DEBUG = False
    LOG_LEVEL = env_str("LOG_LEVEL", "INFO").upper()

    SECRET_KEY = env_str("SECRET_KEY", "").strip()

    SESSION_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE", default=True)
    SESSION_COOKIE_SAMESITE = normalize_samesite(env_str("SESSION_COOKIE_SAMESITE", "Lax"), "Lax")

    ENABLE_MINIFY = env_bool("ENABLE_MINIFY", default=True)

    @classmethod
    def validate_required(cls) -> None:
        if not cls.SECRET_KEY or len(cls.SECRET_KEY) < 32:
            raise RuntimeError(
                "ProductionConfig: SECRET_KEY faltante o muy corto (>=32). "
                "Setealo fijo en Render para evitar CSRF/session invalid."
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


config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
}
