import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "cambia-esto-por-una-clave-segura")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{os.path.join(BASE_DIR, 'skyline_store.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
