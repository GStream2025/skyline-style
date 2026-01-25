from __future__ import annotations

import logging
import re
import secrets
import time
from typing import Optional, Set
from urllib.parse import urlencode, urlparse

from flask import Blueprint, flash, jsonify, make_response, redirect, render_template, request, session, url_for
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.models import User, db

try:
    from flask_login import login_user as _login_user, logout_user as _logout_user  # type: ignore
except Exception:
    _login_user = None  # type: ignore
    _logout_user = None  # type: ignore

try:
    from app.models import AffiliateProfile  # type: ignore
except Exception:
    AffiliateProfile = None  # type: ignore

log = logging.getLogger("auth_routes")

auth_bp = Blueprint(
    "auth",
    __name__,
    url_prefix="/auth",
    template_folder="../templates",
)

_TRUE: Set[str] = {"1", "true", "yes", "y", "on", "checked"}
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_ALLOWED_PUBLIC_ROLES: Set[str] = {"customer", "affiliate"}

_RL_LOGIN_KEY = "rl:login"
_RL_REG_KEY = "rl:register"
_RL_WINDOW_SEC = 60
_RL_MAX = 8


def _now() -> int:
    return int(time.time())


def _norm(v: str) -> str:
    return (v or "").strip()


def _safe_email(v: str) -> str:
    return _norm(v).lower()


def _valid_email(v: str) -> bool:
    v = _safe_email(v)
    return bool(v and _EMAIL_RE.match(v))


def _safe_next(nxt: str) -> str:
    nxt = _norm(nxt)
    if not nxt or not nxt.startswith("/") or nxt.startswith("//"):
        return ""
    if any(c in nxt for c in ("\x00", "\r", "\n", "\\")):
        return ""
    p = urlparse(nxt)
    return nxt if not p.scheme and not p.netloc else ""


def _wants_json() -> bool:
    accept = request.headers.get("Accept") or ""
    return (
        request.headers.get("X-Requested-With") == "XMLHttpRequest"
        or "application/json" in accept
        or (request.content_type or "").startswith("application/json")
    )


def _rate_limit(key: str) -> bool:
    now = _now()
    bucket = session.get(key)
    if not isinstance(bucket, dict):
        session[key] = {"t": now, "n": 1}
        session.modified = True
        return True

    t0 = int(bucket.get("t", now))
    n = int(bucket.get("n", 0))

    if now - t0 >= _RL_WINDOW_SEC:
        session[key] = {"t": now, "n": 1}
        session.modified = True
        return True

    if n >= _RL_MAX:
        return False

    bucket["n"] = n + 1
    session[key] = bucket
    session.modified = True
    return True


def _clear_auth_session() -> None:
    keep = set()
    for k in list(session.keys()):
        if k.startswith("rl:"):
            session.pop(k, None)
            continue
        if k in {"user_id", "user_email", "is_admin", "login_at", "login_nonce"}:
            session.pop(k, None)
            continue
        if k in keep:
            continue
    session.modified = True


def _set_user_session(user: User) -> None:
    _clear_auth_session()
    session["user_id"] = int(user.id)
    session["user_email"] = (getattr(user, "email", "") or "").lower()
    session["is_admin"] = bool(getattr(user, "is_admin", False))
    session["login_at"] = _now()
    session["login_nonce"] = secrets.token_urlsafe(16)
    session.permanent = True
    session.modified = True

    if _login_user:
        try:
            _login_user(user, remember=False)
        except Exception:
            log.exception("flask_login login_user failed")


def _get_user_by_email(email: str) -> Optional[User]:
    email = _safe_email(email)
    if not email:
        return None
    try:
        return db.session.execute(select(User).where(func.lower(User.email) == email)).scalar_one_or_none()
    except Exception:
        log.exception("get_user_by_email failed")
        return None


def _json_or_redirect(
    message: str,
    category: str,
    *,
    tab: str,
    nxt: str,
    redirect_to: str = "",
    status_ok: int = 200,
    status_err: int = 400,
):
    ok = category != "error"

    if _wants_json():
        return jsonify({"ok": ok, "message": message, "tab": tab}), (status_ok if ok else status_err)

    flash(message, "success" if ok else category)

    if redirect_to:
        return redirect(redirect_to)

    qs = urlencode({"tab": tab, "next": nxt})
    return redirect(url_for("auth.account") + f"?{qs}")


def _parse_bool(v: str) -> bool:
    return _norm(v).lower() in _TRUE


def _extract_role() -> str:
    role = _norm(request.form.get("role", "")).lower()
    if role in _ALLOWED_PUBLIC_ROLES:
        return role
    if _parse_bool(request.form.get("want_affiliate", "")):
        return "affiliate"
    return "customer"


def _normalize_name(name: str) -> str:
    name = re.sub(r"\s+", " ", _norm(name))
    return name[:120]


def _is_honeypot_triggered() -> bool:
    return bool(_norm(request.form.get("website", "")))


def _bad_auth_response(tab: str, nxt: str):
    msg = "Credenciales incorrectas." if tab == "login" else "No se pudo crear la cuenta."
    return _json_or_redirect(msg, "error", tab=tab, nxt=nxt)


@auth_bp.get("/account")
def account():
    if session.get("user_id"):
        return redirect(_safe_next(request.args.get("next", "")) or "/")

    tab = _norm(request.args.get("tab", "login")).lower()
    if tab not in {"login", "register"}:
        tab = "login"

    nxt = _safe_next(request.args.get("next", ""))
    prefill_email = _safe_email(request.args.get("email", ""))

    return make_response(
        render_template(
            "auth/account.html",
            active_tab=tab,
            next=nxt,
            prefill_email=prefill_email,
        ),
        200,
        {"Cache-Control": "no-store"},
    )


@auth_bp.get("/login")
@auth_bp.get("/login/")
def login_get():
    qs = urlencode({"tab": "login", "next": _safe_next(request.args.get("next", ""))})
    return redirect(url_for("auth.account") + f"?{qs}", code=302)


@auth_bp.get("/register")
@auth_bp.get("/register/")
def register_get():
    qs = urlencode({"tab": "register", "next": _safe_next(request.args.get("next", ""))})
    return redirect(url_for("auth.account") + f"?{qs}", code=302)


@auth_bp.post("/login")
def login():
    nxt = _safe_next(request.form.get("next", ""))

    if not _rate_limit(_RL_LOGIN_KEY) or _is_honeypot_triggered():
        return _bad_auth_response("login", nxt)

    email = _safe_email(request.form.get("email", ""))
    password = request.form.get("password", "") or ""
    if not email or not password:
        return _bad_auth_response("login", nxt)

    user = _get_user_by_email(email)

    ok = False
    try:
        ok = bool(user and user.check_password(password))  # type: ignore[attr-defined]
    except Exception:
        ok = False

    if not ok:
        return _bad_auth_response("login", nxt)

    if hasattr(user, "is_active") and not bool(getattr(user, "is_active", True)):
        return _bad_auth_response("login", nxt)

    _set_user_session(user)  # type: ignore[arg-type]
    return _json_or_redirect("Bienvenido 👋", "success", tab="login", nxt=nxt, redirect_to=nxt or "/")


@auth_bp.post("/register")
def register():
    nxt = _safe_next(request.form.get("next", ""))

    if not _rate_limit(_RL_REG_KEY) or _is_honeypot_triggered():
        return _bad_auth_response("register", nxt)

    email = _safe_email(request.form.get("email", ""))
    password = request.form.get("password", "") or ""
    password2 = request.form.get("password2", "") or ""
    name = _normalize_name(request.form.get("name", ""))

    if not _valid_email(email) or len(password) < 8 or password != password2:
        return _json_or_redirect("Datos inválidos.", "error", tab="register", nxt=nxt)

    existing = _get_user_by_email(email)
    if existing:
        return _json_or_redirect("Ese email ya existe.", "error", tab="login", nxt=nxt)

    role = _extract_role()
    user = User(email=email)

    if hasattr(user, "name"):
        setattr(user, "name", name)
    if hasattr(user, "is_active"):
        setattr(user, "is_active", True)
    if hasattr(user, "email_verified"):
        setattr(user, "email_verified", False)
    if hasattr(user, "role"):
        setattr(user, "role", role)

    try:
        user.set_password(password)  # type: ignore[attr-defined]
    except Exception:
        return _bad_auth_response("register", nxt)

    try:
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return _json_or_redirect("Ese email ya existe.", "error", tab="login", nxt=nxt)
    except Exception:
        db.session.rollback()
        log.exception("register commit failed")
        return _bad_auth_response("register", nxt)

    if role == "affiliate" and AffiliateProfile is not None:
        try:
            db.session.add(AffiliateProfile(user_id=int(user.id), status="pending"))
            db.session.commit()
        except Exception:
            db.session.rollback()

    _set_user_session(user)
    return _json_or_redirect("Cuenta creada con éxito ✅", "success", tab="register", nxt=nxt, redirect_to=nxt or "/")


@auth_bp.route("/logout", methods=["GET", "POST"])
def logout():
    nxt = _safe_next(request.values.get("next", ""))
    _clear_auth_session()

    if _logout_user:
        try:
            _logout_user()
        except Exception:
            log.exception("flask_login logout_user failed")

    flash("Sesión cerrada.", "info")
    return redirect(nxt or "/")


__all__ = ["auth_bp"]
