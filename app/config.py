from __future__ import annotations

import os
import re
import secrets
from datetime import timedelta
from typing import Any, Dict, Optional, Type
from urllib.parse import urlparse

_TRUE = {"1", "true", "yes", "y", "on", "checked", "enable", "enabled"}
_FALSE = {"0", "false", "no", "n", "off", "disable", "disabled"}


def env_str(key: str, default: str = "") -> str:
    v = os.getenv(key)
    return (default if v is None else str(v)).strip()


def env_int(key: str, default: int, *, min_v: int = 0, max_v: int = 10**9) -> int:
    s = env_str(key, "")
    try:
        v = int(s) if s else int(default)
    except Exception:
        v = int(default)
    return min(max(v, min_v), max_v)


def env_opt_int(
    key: str,
    default: Optional[int],
    *,
    min_v: Optional[int] = None,
    max_v: Optional[int] = None,
) -> Optional[int]:
    s = env_str(key, "")
    if not s:
        return default
    try:
        v = int(s)
    except Exception:
        return default
    if min_v is not None:
        v = max(v, min_v)
    if max_v is not None:
        v = min(v, max_v)
    return v


def env_bool(key: str, default: bool = False) -> bool:
    s = env_str(key, "")
    if not s:
        return default
    s = s.lower().strip()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return default


def _slug(s: str, fallback: str = "skyline") -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return (s or fallback)[:64]


def normalize_db_any(raw: Optional[str]) -> str:
    if not raw:
        return ""
    u = str(raw).strip()
    if not u:
        return ""
    if u.startswith("postgres://"):
        u = u.replace("postgres://", "postgresql://", 1)
    return u


def normalize_database_url(raw: Optional[str]) -> str:
    u = normalize_db_any(raw)
    return u or "sqlite:///skyline_local.db"


def normalize_samesite(raw: str, default: str = "Lax") -> str:
    s = (raw or default).strip().title()
    return s if s in {"Lax", "Strict", "None"} else default


def normalize_scheme(raw: str, default: str = "http") -> str:
    s = (raw or default).strip().lower()
    return "https" if s == "https" else "http"


def normalize_site_url(raw: str) -> str:
    s = (raw or "").strip()
    if not s:
        return ""
    s = s.rstrip("/")
    if not s:
        return ""
    if not s.startswith(("http://", "https://")):
        s = "https://" + s
    p = urlparse(s)
    if not p.netloc:
        return ""
    scheme = "https" if p.scheme == "https" else "http"
    return f"{scheme}://{p.netloc}".rstrip("/")


def _is_sqlite(uri: str) -> bool:
    return (uri or "").strip().lower().startswith("sqlite:")


def _is_prod(env_value: str) -> bool:
    return (env_value or "").strip().lower() == "production"


def csp_for_tailwind_cdn() -> Dict[str, list]:
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
        "frame-src": ["'self'", "https:"],
        "worker-src": ["'self'", "blob:"],
    }


def _computed_env() -> str:
    flask_env = env_str("FLASK_ENV", env_str("ENV", "production")).lower()
    debug = env_bool("DEBUG", env_bool("FLASK_DEBUG", False))
    return "development" if (flask_env in {"dev", "development"} or debug) else "production"


class BaseConfig:
    @classmethod
    def env_name(cls) -> str:
        return _computed_env()

    @classmethod
    def is_prod(cls) -> bool:
        return _is_prod(cls.env_name())

    @classmethod
    def debug(cls) -> bool:
        return env_bool("DEBUG", env_bool("FLASK_DEBUG", False))

    @classmethod
    def testing(cls) -> bool:
        return env_bool("TESTING", False)

    @classmethod
    def site_url(cls) -> str:
        raw = env_str("SITE_URL", env_str("APP_URL", env_str("RENDER_EXTERNAL_URL", "")))
        return normalize_site_url(raw)

    @classmethod
    def preferred_url_scheme(cls) -> str:
        prod = cls.is_prod()
        site = cls.site_url()
        forced = env_bool("FORCE_HTTPS", default=prod)
        scheme = normalize_scheme(
            env_str("PREFERRED_URL_SCHEME", "https" if (prod or site.startswith("https://")) else "http")
        )
        if forced or site.startswith("https://"):
            scheme = "https"
        return scheme

    @classmethod
    def secret_key(cls) -> str:
        k = env_str("SECRET_KEY", "").strip()
        if k:
            return k
        if cls.is_prod():
            return ""
        return env_str("DEV_SECRET_KEY", "dev_skyline_fallback_change_me")

    @classmethod
    def session_cookie_domain(cls) -> str:
        d = env_str("SESSION_COOKIE_DOMAIN", "").strip()
        if not d:
            return ""
        if d in {"localhost", "127.0.0.1"}:
            return ""
        return d

    @classmethod
    def database_uri(cls) -> str:
        db_url = normalize_database_url(os.getenv("DATABASE_URL"))
        uri = normalize_db_any(env_str("SQLALCHEMY_DATABASE_URI", db_url)) or db_url
        return uri

    @classmethod
    def engine_options(cls) -> Dict[str, Any]:
        uri = cls.database_uri()
        if _is_sqlite(uri):
            return {"pool_pre_ping": True}
        return {
            "pool_pre_ping": True,
            "pool_recycle": env_int("DB_POOL_RECYCLE", 280, min_v=30, max_v=3600),
            "pool_size": env_int("DB_POOL_SIZE", 5, min_v=1, max_v=30),
            "max_overflow": env_int("DB_MAX_OVERFLOW", 10, min_v=0, max_v=80),
        }

    @classmethod
    def validate_required(cls) -> None:
        if cls.is_prod():
            k = cls.secret_key()
            if not k or len(k) < 32:
                raise RuntimeError("SECRET_KEY faltante o muy corto (>=32). Setealo en Render.")
            if not cls.site_url():
                raise RuntimeError("SITE_URL faltante. Setealo en Render (ej: https://tu-app.onrender.com).")

    @classmethod
    def as_flask_config(cls) -> Dict[str, Any]:
        env_name = cls.env_name()
        is_prod = cls.is_prod()
        debug = cls.debug()
        testing = cls.testing()
        site = cls.site_url()
        scheme = cls.preferred_url_scheme()

        app_name = env_str("APP_NAME", "Skyline Store")
        host = env_str("HOST", "0.0.0.0")
        port = env_int("PORT", 5000, min_v=1, max_v=65535)

        session_days = env_int("SESSION_DAYS", 7, min_v=1, max_v=90)
        max_upload_mb = env_int("MAX_UPLOAD_MB", 20, min_v=1, max_v=200)

        mp_public = env_str("MP_PUBLIC_KEY", "")
        mp_token = env_str("MP_ACCESS_TOKEN", "")
        stripe_pk = env_str("STRIPE_PUBLIC_KEY", "")
        stripe_sk = env_str("STRIPE_SECRET_KEY", "")
        paypal_id = env_str("PAYPAL_CLIENT_ID", "")
        paypal_secret = env_str("PAYPAL_SECRET", "")

        enable_payments = env_bool(
            "ENABLE_PAYMENTS",
            default=bool(mp_token or stripe_sk or paypal_secret),
        )

        printful_key = env_str("PRINTFUL_API_KEY", env_str("PRINTFUL_KEY", env_str("PRINTFUL_API_TOKEN", "")))
        enable_printful = env_bool("ENABLE_PRINTFUL", default=bool(printful_key))

        cache_prefix = _slug(env_str("CACHE_KEY_PREFIX", env_str("APP_NAME", "skyline")), "skyline")

        server_name = env_str("SERVER_NAME", "").strip()
        cookie_domain = cls.session_cookie_domain()

        csrf_secret = env_str("WTF_CSRF_SECRET_KEY", "").strip()
        if not csrf_secret and not is_prod:
            csrf_secret = secrets.token_urlsafe(24)

        cfg: Dict[str, Any] = {
            "ENV": env_name,
            "DEBUG": debug,
            "TESTING": testing,
            "FLASK_ENV": env_str("FLASK_ENV", env_str("ENV", env_name)).lower(),
            "APP_NAME": app_name,
            "SITE_URL": site,
            "APP_URL": site,
            "HOST": host,
            "PORT": port,
            "PREFERRED_URL_SCHEME": scheme,
            "SECRET_KEY": cls.secret_key(),
            "TRUST_PROXY_HEADERS": env_bool("TRUST_PROXY_HEADERS", default=is_prod),
            "FORCE_HTTPS": env_bool("FORCE_HTTPS", default=is_prod),
            "HSTS": env_bool("HSTS", default=is_prod),
            "SESSION_COOKIE_NAME": env_str("SESSION_COOKIE_NAME", "skyline_session"),
            "SESSION_COOKIE_HTTPONLY": env_bool("SESSION_COOKIE_HTTPONLY", True),
            "SESSION_COOKIE_SAMESITE": normalize_samesite(
                env_str("SESSION_COOKIE_SAMESITE", env_str("SESSION_SAMESITE", "Lax")),
                "Lax",
            ),
            "SESSION_COOKIE_SECURE": env_bool("SESSION_COOKIE_SECURE", env_bool("COOKIE_SECURE", default=is_prod)),
            "PERMANENT_SESSION_LIFETIME": timedelta(days=session_days),
            "SESSION_REFRESH_EACH_REQUEST": env_bool("SESSION_REFRESH_EACH_REQUEST", default=not is_prod),
            "MAX_CONTENT_LENGTH": int(max_upload_mb) * 1024 * 1024,
            "UPLOADS_DIR": env_str("UPLOADS_DIR", "static/uploads"),
            "WTF_CSRF_ENABLED": env_bool("WTF_CSRF_ENABLED", True),
            "WTF_CSRF_TIME_LIMIT": env_opt_int("WTF_CSRF_TIME_LIMIT", 3600, min_v=300, max_v=86400),
            "WTF_CSRF_SSL_STRICT": env_bool("WTF_CSRF_SSL_STRICT", default=False),
            "WTF_CSRF_SECRET_KEY": csrf_secret or None,
            "SQLALCHEMY_DATABASE_URI": cls.database_uri(),
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "SQLALCHEMY_ECHO": env_bool("SQLALCHEMY_ECHO", default=False),
            "SQLALCHEMY_ENGINE_OPTIONS": cls.engine_options(),
            "ENABLE_MINIFY": env_bool("ENABLE_MINIFY", default=is_prod),
            "ENABLE_COMPRESS": env_bool("ENABLE_COMPRESS", default=True),
            "CACHE_TYPE": env_str("CACHE_TYPE", "SimpleCache"),
            "CACHE_DEFAULT_TIMEOUT": env_int("CACHE_DEFAULT_TIMEOUT", 300, min_v=10, max_v=86400),
            "CACHE_KEY_PREFIX": cache_prefix,
            "SEO_TITLE": env_str("SEO_TITLE", "Skyline Store · Tech + Streetwear premium"),
            "SEO_DESCRIPTION": env_str(
                "SEO_DESCRIPTION",
                "Comprá moda urbana, accesorios y tecnología en un solo lugar. Envíos rápidos y pagos seguros.",
            ),
            "OG_IMAGE": env_str("OG_IMAGE", "img/og/og-home.png"),
            "PRINTFUL_API_KEY": printful_key,
            "PRINTFUL_STORE_ID": env_str("PRINTFUL_STORE_ID", ""),
            "PRINTFUL_CACHE_TTL": env_int("PRINTFUL_CACHE_TTL", 300, min_v=30, max_v=86400),
            "ENABLE_PRINTFUL": enable_printful,
            "MP_PUBLIC_KEY": mp_public,
            "MP_ACCESS_TOKEN": mp_token,
            "STRIPE_PUBLIC_KEY": stripe_pk,
            "STRIPE_SECRET_KEY": stripe_sk,
            "PAYPAL_CLIENT_ID": paypal_id,
            "PAYPAL_SECRET": paypal_secret,
            "ENABLE_PAYMENTS": enable_payments,
            "MAIL_SERVER": env_str("MAIL_SERVER", ""),
            "MAIL_PORT": env_int("MAIL_PORT", 587, min_v=1, max_v=65535),
            "MAIL_USE_TLS": env_bool("MAIL_USE_TLS", default=True),
            "MAIL_USE_SSL": env_bool("MAIL_USE_SSL", default=False),
            "MAIL_USERNAME": env_str("MAIL_USERNAME", ""),
            "MAIL_PASSWORD": env_str("MAIL_PASSWORD", ""),
            "MAIL_DEFAULT_SENDER": env_str("MAIL_DEFAULT_SENDER", ""),
            "CONTENT_SECURITY_POLICY": csp_for_tailwind_cdn(),
            "JSON_SORT_KEYS": env_bool("JSON_SORT_KEYS", default=False),
            "TEMPLATES_AUTO_RELOAD": env_bool("TEMPLATES_AUTO_RELOAD", default=debug),
        }

        # -----------------------------
        # AUTH (común) - login/register
        # -----------------------------
        cfg.update(
            {
                "AUTH_HEADERS_STRICT": env_bool("AUTH_HEADERS_STRICT", default=is_prod),
                "AUTH_RL_WINDOW_SEC": env_int("AUTH_RL_WINDOW_SEC", 60, min_v=10, max_v=600),
                "AUTH_RL_MAX": env_int("AUTH_RL_MAX", 8, min_v=3, max_v=60),
                "AUTH_VERIFY_TTL_MIN": env_int("AUTH_VERIFY_TTL_MIN", 30, min_v=5, max_v=180),
                "AUTH_VERIFY_RL_SEC": env_int("AUTH_VERIFY_RL_SEC", 60, min_v=10, max_v=600),
            }
        )

        # -----------------------------
        # ADMIN AUTH (panel)
        # -----------------------------
        allowed_roles_raw = env_str("ADMIN_ALLOWED_ROLES", "admin,staff")
        allowed_roles = {x.strip().lower() for x in allowed_roles_raw.split(",") if x.strip()} or {"admin", "staff"}

        cfg.update(
            {
                "ADMIN_HEADERS_STRICT": env_bool("ADMIN_HEADERS_STRICT", default=is_prod),
                "ADMIN_LOGIN_ENDPOINT": env_str("ADMIN_LOGIN_ENDPOINT", "admin.login"),
                "ADMIN_REGISTER_ENDPOINT": env_str("ADMIN_REGISTER_ENDPOINT", "admin.register"),
                "ADMIN_LOGIN_FALLBACK_PATH": env_str("ADMIN_LOGIN_FALLBACK_PATH", "/admin/login"),
                "ADMIN_REGISTER_FALLBACK_PATH": env_str("ADMIN_REGISTER_FALLBACK_PATH", "/admin/register"),
                "ADMIN_SESSION_KEY": env_str("ADMIN_SESSION_KEY", "admin_logged_in"),
                "ADMIN_DEFAULT_NEXT": env_str("ADMIN_DEFAULT_NEXT", "/admin"),
                "ADMIN_ABORT_CODE_JSON": env_int("ADMIN_ABORT_CODE_JSON", 401, min_v=401, max_v=403),
                "ADMIN_ABORT_CODE_HTML": env_opt_int("ADMIN_ABORT_CODE_HTML", None, min_v=401, max_v=403),
                "ADMIN_ROLE_KEY": env_str("ADMIN_ROLE_KEY", "role"),
                "ADMIN_ALLOWED_ROLES": allowed_roles,
                "ADMIN_BYPASS": env_bool(
                    "ADMIN_BYPASS", default=(not is_prod and env_bool("DEV_ADMIN_BYPASS", False))
                ),
                "ADMIN_EMAIL": env_str("ADMIN_EMAIL", ""),
                "ADMIN_EMAILS": env_str("ADMIN_EMAILS", ""),
                "ADMIN_PASSWORD": env_str("ADMIN_PASSWORD", ""),
                "ADMIN_PASSWORD_HASH": env_str("ADMIN_PASSWORD_HASH", ""),
                "ADMIN_ALLOW_REGISTER": env_bool("ADMIN_ALLOW_REGISTER", default=not is_prod),
                "ADMIN_REGISTER_CODE": env_str("ADMIN_REGISTER_CODE", ""),
            }
        )

        if server_name:
            cfg["SERVER_NAME"] = server_name
        if cookie_domain:
            cfg["SESSION_COOKIE_DOMAIN"] = cookie_domain

        if not cfg.get("WTF_CSRF_SECRET_KEY"):
            cfg.pop("WTF_CSRF_SECRET_KEY", None)
        if not cfg.get("SERVER_NAME"):
            cfg.pop("SERVER_NAME", None)

        return cfg


class DevelopmentConfig(BaseConfig):
    @classmethod
    def env_name(cls) -> str:
        return "development"

    @classmethod
    def is_prod(cls) -> bool:
        return False

    @classmethod
    def debug(cls) -> bool:
        return env_bool("DEBUG", True)


class ProductionConfig(BaseConfig):
    @classmethod
    def env_name(cls) -> str:
        return "production"

    @classmethod
    def is_prod(cls) -> bool:
        return True

    @classmethod
    def debug(cls) -> bool:
        return env_bool("DEBUG", False)


def get_config(env_name: Optional[str] = None) -> Type[BaseConfig]:
    e = (env_name or env_str("FLASK_ENV", env_str("ENV", "")) or "").strip().lower()
    debug = env_bool("DEBUG", env_bool("FLASK_DEBUG", False))
    if e in {"development", "dev"} or debug:
        return DevelopmentConfig
    return ProductionConfig


config: Dict[str, Type[BaseConfig]] = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
}
