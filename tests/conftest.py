from __future__ import annotations

import os

import pytest
from werkzeug.security import generate_password_hash

from sqlalchemy.pool import StaticPool

from app import create_app
from app.models import User, db


@pytest.fixture(scope="session")
def _env():
    os.environ.setdefault("ENV", "testing")
    os.environ.setdefault("FLASK_ENV", "testing")
    os.environ.setdefault("SECRET_KEY", "dev-secret")
    os.environ.setdefault("PYTHONPATH", os.getcwd())
    yield


@pytest.fixture()
def app(_env):
    app = create_app()

    # ✅ DB de tests ultra estable:
    # - sqlite:// (sin :memory:) + StaticPool => una sola conexión viva
    # - evita inconsistencias de DDL + "index already exists" raros
    app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        SQLALCHEMY_DATABASE_URI="sqlite://",
        SQLALCHEMY_ENGINE_OPTIONS={
            "connect_args": {"check_same_thread": False},
            "poolclass": StaticPool,
        },
        SERVER_NAME="localhost",
        PROPAGATE_EXCEPTIONS=True,
    )

    with app.app_context():
        # ✅ Limpieza fuerte ANTES: si create_app o imports tocaron metadata/DDL, acá lo reseteamos
        try:
            db.session.rollback()
        except Exception:
            pass
        db.drop_all()
        db.create_all()

        yield app

        # ✅ teardown limpio
        try:
            db.session.rollback()
        except Exception:
            pass
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def user(app):
    u = User(
        email="test@example.com",
        password_hash=generate_password_hash("password123"),
        email_verified=True,
        is_active=True,
        role="customer",
        # ✅ si tu modelo no tiene defaults y te explota en prepare():
        # failed_login_count=0,
    )
    db.session.add(u)
    db.session.commit()
    return u
