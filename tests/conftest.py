from __future__ import annotations

import os

import pytest
from sqlalchemy.pool import StaticPool
from werkzeug.security import generate_password_hash

from app import create_app
from app.models import User, db


@pytest.fixture(scope="session")
def _env():
    os.environ.setdefault("ENV", "testing")
    os.environ.setdefault("FLASK_ENV", "testing")
    os.environ.setdefault("SECRET_KEY", "dev-secret")
    os.environ.setdefault("PYTHONPATH", os.getcwd())
    yield


def _bool_env(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    s = str(v).strip().lower()
    return s in {"1", "true", "yes", "y", "on", "enable", "enabled"}


@pytest.fixture()
def app(_env):
    """
    Test app fixture:
    - Default: SQLite ultra estable (StaticPool) => rápido y sin flakes
    - Opcional: Neon/Postgres real si seteás NEON_DATABASE_URL_TEST
      (solo recomendado para tests marcados como integration)
    """
    app = create_app()

    neon_url = os.getenv("NEON_DATABASE_URL_TEST", "").strip()

    if neon_url:
        # ✅ Modo integración (Postgres/Neon)
        app.config.update(
            TESTING=True,
            SERVER_NAME="localhost",
            PROPAGATE_EXCEPTIONS=True,
            WTF_CSRF_ENABLED=False,  # tus rutas usan csrf_token propio de sesión
            SQLALCHEMY_DATABASE_URI=neon_url,
        )
    else:
        # ✅ Modo unit/local (SQLite ultra estable)
        app.config.update(
            TESTING=True,
            SERVER_NAME="localhost",
            PROPAGATE_EXCEPTIONS=True,
            WTF_CSRF_ENABLED=False,  # tus rutas usan csrf_token propio de sesión
            SQLALCHEMY_DATABASE_URI="sqlite://",
            SQLALCHEMY_ENGINE_OPTIONS={
                "connect_args": {"check_same_thread": False},
                "poolclass": StaticPool,
            },
        )

    with app.app_context():
        # ✅ Reset de sesión por si create_app tocó metadata
        try:
            db.session.rollback()
        except Exception:
            pass

        # ✅ Si corrés contra Postgres real, es más seguro NO dropear todo
        #    a menos que vos explícitamente lo permitas.
        allow_drop = _bool_env("TEST_DB_ALLOW_DROP_ALL", default=False)

        if neon_url and not allow_drop:
            # Asumimos que tu DB de tests ya tiene schema/migraciones aplicadas.
            # Si no, habilitá TEST_DB_ALLOW_DROP_ALL=1 y asegurate que sea una DB de TEST.
            try:
                db.session.execute(db.text("select 1"))
            except Exception:
                # fallback si db.text no está (según SQLAlchemy), no rompemos
                pass
        else:
            # SQLite (o DB test explícita) => recreamos schema
            db.drop_all()
            db.create_all()

        yield app

        # teardown limpio
        try:
            db.session.rollback()
        except Exception:
            pass
        db.session.remove()

        if neon_url and not allow_drop:
            # No tocamos schema
            return

        try:
            db.drop_all()
        except Exception:
            pass


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def user(app):
    """
    Usuario base para tests de login.
    Importante:
    - email_verified=True para que login no redirija a verify/send
      (si REQUIRE_EMAIL_VERIFICATION está activado)
    """
    with app.app_context():
        u = User(
            email="test@example.com",
            password_hash=generate_password_hash("password123"),
        )

        # setea solo si existen en tu modelo
        if hasattr(u, "email_verified"):
            setattr(u, "email_verified", True)
        if hasattr(u, "is_active"):
            setattr(u, "is_active", True)
        if hasattr(u, "role"):
            setattr(u, "role", "customer")

        db.session.add(u)
        db.session.commit()
        return u
