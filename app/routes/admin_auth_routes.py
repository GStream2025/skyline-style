from __future__ import annotations

import secrets
import time
from typing import Any, Dict, Optional

from flask import Blueprint, flash, make_response, redirect, render_template, request, session, url_for

from app.utils.admin_gate import (
    ADMIN_NEXT_PARAM_DEFAULT,
    ADMIN_SESSION_KEY_DEFAULT,
    admin_creds_ok,
    build_admin_login_url,
    build_admin_register_url,
)

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")
admin_bp.strict_slashes = False

# Config opcional:
# ADMIN_ALLOW_REGISTER = False (default)
# ADMIN_REGISTER_CODE = "INVITE123" (opcional, para permitir alta)
# ADMIN_DEFAULT_NEXT = "/admin"


def _safe_str(v: Any, *, max_len: int = 400) -> str:
    if v is None:
        return ""
    s = str(v).replace("\x00", "").strip()
    return s[:max_len]


def _clean_next(next_raw: Optional[str], *, fallback: str = "/admin") -> str:
    p = _safe_str(next_raw, max_len=256)
    if not p or not p.startswith("/") or p.startswith("//") or "://" in p or "\\" in p or ".." in p:
        return fallback
    if "?" in p:
        p = p.split("?", 1)[0]
    if "#" in p:
        p = p.split("#", 1)[0]
    if p.startswith("/admin/login") or p.startswith("/admin/register"):
        return fallback
    return p or fallback


def _ensure_csrf() -> str:
    tok = session.get("csrf_token")
    if not isinstance(tok, str) or len(tok) < 16:
        tok = secrets.token_urlsafe(32)
        session["csrf_token"] = tok
        session.modified = True
    return tok


def _csrf_ok() -> bool:
    if request.method != "POST":
        return True
    sess = _safe_str(session.get("csrf_token") or "", max_len=2048)
    sent = _safe_str(request.form.get("csrf_token") or "", max_len=2048)
    if not sess or not sent:
        return False
    try:
        return secrets.compare_digest(sess, sent)
    except Exception:
        return False


def _set_admin_session(email: str) -> None:
    # anti-session fixation: rotamos nonce/flags y marcamos login
    session[ADMIN_SESSION_KEY_DEFAULT] = True
    session["is_admin"] = True
    session["admin_email"] = email.lower()
    session["admin_login_at"] = int(time.time())
    session["admin_nonce"] = secrets.token_urlsafe(16)
    session.permanent = True
    session.modified = True


@admin_bp.get("/login")
@admin_bp.get("/login/")
def login():
    nxt = _clean_next(request.args.get(ADMIN_NEXT_PARAM_DEFAULT), fallback="/admin")
    if session.get(ADMIN_SESSION_KEY_DEFAULT) or session.get("is_admin"):
        return redirect(nxt or "/admin", code=302)

    csrf = _ensure_csrf()
    return make_response(
        render_template(
            "admin/login.html",
            next=nxt,
            csrf_token=csrf,
            register_url=build_admin_register_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt),
        ),
        200,
    )


@admin_bp.post("/login")
@admin_bp.post("/login/")
def login_post():
    nxt = _clean_next(request.form.get("next") or request.args.get("next"), fallback="/admin")
    _ensure_csrf()

    if not _csrf_ok():
        flash("CSRF inválido. Reintentá.", "danger")
        return redirect(build_admin_login_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt), code=302)

    email = _safe_str(request.form.get("email"), max_len=200).lower()
    password = _safe_str(request.form.get("password"), max_len=500)

    if not admin_creds_ok(email, password):
        flash("Credenciales incorrectas.", "danger")
        return redirect(build_admin_login_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt), code=302)

    _set_admin_session(email)
    flash("Bienvenido al panel ✅", "success")
    return redirect(nxt or "/admin", code=302)


@admin_bp.get("/logout")
@admin_bp.post("/logout")
def logout():
    # opcional: validar CSRF en POST si querés más estricto
    session.pop(ADMIN_SESSION_KEY_DEFAULT, None)
    session.pop("is_admin", None)
    session.pop("admin_email", None)
    session.pop("admin_login_at", None)
    session.pop("admin_nonce", None)
    session.modified = True
    flash("Sesión cerrada.", "info")
    return redirect("/admin/login", code=302)


@admin_bp.get("/register")
@admin_bp.get("/register/")
def register():
    allow = bool(current_app.config.get("ADMIN_ALLOW_REGISTER", False))  # type: ignore[name-defined]
    nxt = _clean_next(request.args.get("next"), fallback="/admin")
    csrf = _ensure_csrf()

    return make_response(
        render_template(
            "admin/register.html",
            next=nxt,
            csrf_token=csrf,
            allow_register=allow,
            login_url=build_admin_login_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt),
        ),
        200,
    )


@admin_bp.post("/register")
@admin_bp.post("/register/")
def register_post():
    allow = bool(current_app.config.get("ADMIN_ALLOW_REGISTER", False))  # type: ignore[name-defined]
    nxt = _clean_next(request.form.get("next") or request.args.get("next"), fallback="/admin")
    _ensure_csrf()

    if not _csrf_ok():
        flash("CSRF inválido. Reintentá.", "danger")
        return redirect(build_admin_register_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt), code=302)

    if not allow:
        flash("Registro admin deshabilitado.", "warning")
        return redirect(build_admin_login_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt), code=302)

    # Registro “preparado”: por seguridad, pedimos un código de invitación
    invite = _safe_str(request.form.get("invite_code"), max_len=80)
    expected = _safe_str(current_app.config.get("ADMIN_REGISTER_CODE", ""), max_len=80)  # type: ignore[name-defined]
    if not expected or not secrets.compare_digest(invite, expected):
        flash("Código de invitación inválido.", "danger")
        return redirect(build_admin_register_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt), code=302)

    # En este punto, conectás con tu User model/DB para crear admin real.
    # Como tu proyecto puede variar, dejamos listo el flujo sin asumir tu DB.
    flash("Registro preparado ✅ Ahora conectá este POST a tu modelo User/Admin.", "success")
    return redirect(build_admin_login_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt), code=302)
