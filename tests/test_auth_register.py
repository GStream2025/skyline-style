def test_register_ok(client):
    email = "new@example.com"

    r = client.post(
        "/auth/register",
        data={
            "email": email,
            "password": "password123",
            "password2": "password123",
        },
        headers={
            "Accept": "application/json",
            "X-Requested-With": "XMLHttpRequest",
        },
        follow_redirects=False,
    )

    # Registro exitoso → JSON + 201
    assert r.status_code == 201
    assert r.is_json is True

    data = r.get_json()
    assert data and data.get("ok") is True
    assert isinstance(data.get("message"), str)

    # Debe sugerir verificación
    assert "verificar" in data["message"].lower() or "email" in data["message"].lower()

    # El usuario debe existir en la DB
    from app.models import User, db

    u = db.session.execute(
        db.select(User).where(User.email == email)
    ).scalar_one_or_none()

    assert u is not None
    assert u.email == email
    assert u.email_verified is False
