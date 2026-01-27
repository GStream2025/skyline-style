from __future__ import annotations

from urllib.parse import urlparse

import pytest

from app.models import User, db


# ----------------------------
# Helpers
# ----------------------------

def _is_safe_relative_url(loc: str) -> bool:
    if not loc:
        return False
    if not loc.startswith("/") or loc.startswith("//"):
        return False
    p = urlparse(loc)
    return not p.scheme and not p.netloc


def _assert_redirect(resp, *, expected_prefix: str = "/auth"):
    assert resp.status_code in (301, 302, 303, 307, 308)
    loc = resp.headers.get("Location")
    assert loc, "Redirect sin Location header"
    assert _is_safe_relative_url(loc), f"Redirect inseguro: {loc}"
    assert loc.startswith(expected_prefix), f"Redirect inesperado: {loc}"
    return loc


# ----------------------------
# Fixtures
# ----------------------------

@pytest.fixture()
def protected_user(app):
    with app.app_context():
        u = User(
            email="protected@example.com",
            email_verified=True,
            is_active=True,
            role="customer",
        )
        db.session.add(u)
        db.session.commit()
        return u


# ----------------------------
# Tests
# ----------------------------

def test_account_redirects_if_not_logged(client):
    """
    /auth/account NO debe ser accesible sin login
    """
    r = client.get("/auth/account", follow_redirects=False)
    _assert_redirect(r, expected_prefix="/auth")


def test_account_accessible_when_logged(client, protected_user):
    """
    /auth/account debe abrir si el usuario está logueado
    """
    with client.session_transaction() as s:
        s["user_id"] = protected_user.id
        s["user_email"] = protected_user.email
        s["email_verified"] = True

    r = client.get("/auth/account", follow_redirects=False)
    assert r.status_code == 200
    assert b"Mi cuenta" in r.data or b"Cuenta" in r.data


def test_logout_clears_session(client, protected_user):
    """
    Logout debe limpiar la sesión
    """
    with client.session_transaction() as s:
        s["user_id"] = protected_user.id
        s["user_email"] = protected_user.email

    r = client.get("/auth/logout", follow_redirects=False)
    assert r.status_code in (200, 302)

    with client.session_transaction() as s:
        assert "user_id" not in s
        assert "user_email" not in s


def test_logout_json(client, protected_user):
    """
    Logout con Accept: application/json devuelve JSON
    """
    with client.session_transaction() as s:
        s["user_id"] = protected_user.id
        s["user_email"] = protected_user.email

    r = client.post(
        "/auth/logout",
        headers={"Accept": "application/json"},
    )

    assert r.status_code == 200
    assert r.is_json
    data = r.get_json()
    assert data["ok"] is True
    assert "redirect" in data


def test_protected_route_respects_next(client):
    """
    Si se pasa ?next=/shop debe preservarse
    """
    r = client.get("/auth/account?next=/shop", follow_redirects=False)
    loc = _assert_redirect(r, expected_prefix="/auth")
    assert "next=%2Fshop" in loc or "next=/shop" in loc


def test_protected_route_blocks_external_next(client):
    """
    next=https://evil.com NO debe aceptarse
    """
    r = client.get(
        "/auth/account?next=https://evil.com",
        follow_redirects=False,
    )
    loc = _assert_redirect(r, expected_prefix="/auth")
    assert "evil.com" not in loc


def test_login_aliases_redirect(client):
    """
    /auth/login y /auth/register aliases funcionan
    """
    r1 = client.get("/auth/login", follow_redirects=False)
    r2 = client.get("/auth/register", follow_redirects=False)

    assert r1.status_code in (301, 302)
    assert r2.status_code in (301, 302)


def test_compat_signup_signin_aliases(client):
    """
    /auth/signup y /auth/signin redirigen correctamente
    """
    r1 = client.get("/auth/signup", follow_redirects=False)
    r2 = client.get("/auth/signin", follow_redirects=False)

    assert r1.status_code in (301, 302)
    assert r2.status_code in (301, 302)
