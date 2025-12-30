# app/routes/account_routes.py
from __future__ import annotations

from urllib.parse import urlparse, urljoin

from flask import Blueprint, render_template, redirect, url_for, session, request, abort

account_bp = Blueprint("account", __name__)


# -----------------------------
# Helpers
# -----------------------------
def _is_safe_next(target: str) -> bool:
    """
    Evita open-redirect (que te manden a otra web).
    Solo permite redirects dentro del mismo host.
    """
    if not target:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return (test_url.scheme, test_url.netloc) == (ref_url.scheme, ref_url.netloc)


def _is_logged_in() -> bool:
    return bool(session.get("user_id"))


def _is_admin() -> bool:
    # Soporta session["is_admin"] y también casos raros donde venga como "1"/"true"
    v = session.get("is_admin", False)
    if isinstance(v, str):
        return v.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(v)


# -----------------------------
# Routes
# -----------------------------
@account_bp.get("/account")
@account_bp.get("/cuenta")  # alias en español
def account():
    """
    /account o /cuenta
    - Sin sesión: muestra botones Login/Registro
    - Con sesión:
        - Admin -> /admin (o next si es seguro)
        - User  -> /profile (o next si es seguro)
    """
    # next opcional: /account?next=/checkout
    nxt = (request.args.get("next") or "").strip()

    # No logueado => UI de cuenta
    if not _is_logged_in():
        # Pasamos next al template para que lo reenvíe a /login y /register
        return render_template("account.html", next=nxt)

    # Logueado => redirección inteligente
    if nxt and _is_safe_next(nxt):
        return redirect(nxt)

    if _is_admin():
        # endpoint de tu admin blueprint: admin.dashboard
        return redirect(url_for("admin.dashboard"))

    # endpoint típico: auth.profile (si no existe, cambia a tu endpoint real)
    try:
        return redirect(url_for("auth.profile"))
    except Exception:
        # fallback si aún no tenés profile route
        return redirect(url_for("main.home"))
