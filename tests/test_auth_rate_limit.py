def test_login_ok(client, user):
    r = client.post(
        "/auth/login",
        data={
            "email": user.email,
            "password": "password123",
        },
        follow_redirects=False,
    )

    # Puede devolver:
    # - 200 (JSON)
    # - 302 (redirect a / o a verify)
    assert r.status_code in (200, 302)

    # Si es JSON, validamos estructura
    if r.is_json:
        data = r.get_json()
        assert data["ok"] is True
        assert "message" in data


def test_login_bad_password(client, user):
    r = client.post(
        "/auth/login",
        data={
            "email": user.email,
            "password": "wrong",
        },
        follow_redirects=False,
    )

    # Por diseño de seguridad:
    # - 401 (JSON)
    # - 302 (redirect con flash)
    assert r.status_code in (401, 302)

    if r.is_json:
        data = r.get_json()
        assert data["ok"] is False
        assert "message" in data
