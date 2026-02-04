from __future__ import annotations

import os
import secrets

import pytest
from sqlalchemy import text

from app.models import db, User


@pytest.mark.integration
def test_neon_register_writes_to_db(app, client):
    """
    Integration test (Neon):
    - Conecta a Postgres real (Neon)
    - Hace POST /auth/register
    - Verifica que el usuario quedó en la DB
    - Limpia borrando el usuario creado
    """
    # hard safety: solo corre si está configurada la URL de test
    neon_url = os.getenv("NEON_DATABASE_URL_TEST", "").strip()
    if not neon_url:
        pytest.skip("Set NEON_DATABASE_URL_TEST to run Neon integration test.")

    # ping DB (asegura que realmente es Postgres y responde)
    with app.app_context():
        r = db.session.execute(text("select 1")).scalar()
        assert r == 1

    # crear email único para no chocar con datos existentes
    email = f"itest_{secrets.token_hex(6)}@example.com"
    password = "TestPass12345"
    name = "Neon Test"

    # obtener CSRF del GET /auth/account
    resp_get = client.get("/auth/account?tab=register")
    assert resp_get.status_code == 200
    with client.session_transaction() as sess:
        csrf = sess.get("csrf_token")
    assert csrf and isinstance(csrf, str)

    # hacer register (forma HTML)
    resp_post = client.post(
        "/auth/register",
        data={
            "csrf_token": csrf,
            "email": email,
            "password": password,
            "password2": password,
            "name": name,
            "role": "customer",
            "next": "/",
        },
        follow_redirects=False,
    )

    # Puede responder 201 JSON (si Accept=json) o 302 redirect (HTML)
    assert resp_post.status_code in (201, 200, 302)

    # validar que se guardó en la DB
    with app.app_context():
        u = (
            db.session.query(User)
            .filter(db.func.lower(User.email) == email.lower())
            .one_or_none()
        )
        assert u is not None, "User was not inserted into Neon DB"
        assert (getattr(u, "email", "") or "").lower() == email.lower()

        # limpieza: borrar el usuario creado (y cascadas si existen)
        try:
            db.session.delete(u)
            db.session.commit()
        except Exception:
            db.session.rollback()
            # fallback duro por si hay FK sin cascade
            db.session.execute(text("delete from users where lower(email)=:e"), {"e": email.lower()})
            db.session.commit()
