import os


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev_skyline_fallback")
    FLASK_ENV = os.environ.get("FLASK_ENV", "production")
