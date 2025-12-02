import os


class BaseConfig:
    """
    Configuración base (común a todos los entornos).
    Se extiende con DevelopmentConfig y ProductionConfig.
    """

    # === CLAVE SECRETA ===
    SECRET_KEY = os.getenv("SECRET_KEY", "dev_skyline_fallback")

    # === ENTORNO ===
    FLASK_ENV = os.getenv("FLASK_ENV", "production")

    # === SERVIDOR ===
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", "5000"))

    # === LOGS ===
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

    # === PRINTFUL ===
    PRINTFUL_API_KEY = os.getenv("PRINTFUL_API_KEY", "")
    PRINTFUL_STORE_ID = os.getenv("PRINTFUL_STORE_ID", "")

    # === BASE DE DATOS ===
    # Render agrega DATABASE_URL automáticamente cuando usás Postgres
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///skyline_local.db")
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # === MERCADO PAGO ===
    MP_PUBLIC_KEY = os.getenv("MP_PUBLIC_KEY", "")
    MP_ACCESS_TOKEN = os.getenv("MP_ACCESS_TOKEN", "")

    # === STRIPE ===
    STRIPE_PUBLIC_KEY = os.getenv("STRIPE_PUBLIC_KEY", "")
    STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")

    # === PAYPAL ===
    PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID", "")
    PAYPAL_SECRET = os.getenv("PAYPAL_SECRET", "")

    # === OPCIONES DE SEGURIDAD ===
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("FLASK_ENV") == "production"

    # === MINIFICACIÓN / COMPRESIÓN ===
    ENABLE_MINIFY = True
    ENABLE_COMPRESS = True


class DevelopmentConfig(BaseConfig):
    """Configuración para desarrollo (local)."""

    DEBUG = True
    FLASK_ENV = "development"

    # En desarrollo es normal permitir más logs
    LOG_LEVEL = "DEBUG"


class ProductionConfig(BaseConfig):
    """Configuración para producción (Render)."""

    DEBUG = False
    FLASK_ENV = "production"

    # Log más limpio en producción
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")


# Diccionario para selección automática
config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
}
