from __future__ import annotations

import os

import pytest
from werkzeug.security import generate_password_hash

from app import create_app
from app.models import User, db


@pytest.fixture(scope="session")
def _env():
    # Evita errores de import / path en Windows + pytest
    os.environ.setdefault("ENV", "testing")
    os.environ.setdefault("FLASK_ENV", "testing")
    os.environ.setdefault("SECRET_KEY", "dev-secret")
    # Si no seteaste PYTHONPATH en consola, esto suele ayudar igual
    os.environ.setdefault("PYTHONPATH", os.getcwd())
    yield


@pytest.fixture()
def app(_env):
    app = create_app()

    # Override de config para tests (tu create_app no recibe dict)
    app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
        SERVER_NAME="localhost",
        # Calidad de tests: no ruidos ni redirects raros
        PROPAGATE_EXCEPTIONS=True,
    )

    with app.app_context():
        db.create_all()
        yield app
        # cleanup fuerte y seguro
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
    # Importante: este fixture depende del app_context y de la DB creada
    u = User(
        email="test@example.com",
        password_hash=generate_password_hash("password123"),
        email_verified=True,
        is_active=True,
        role="customer",
    )
    db.session.add(u)
    db.session.commit()
    return u
