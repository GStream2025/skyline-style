from __future__ import annotations

import logging
import re
import secrets
import time
from typing import Optional, Set
from urllib.parse import urlencode, urlparse

from flask import (
    Blueprint,
    flash,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.models import User, db

try:
    from flask_login import login_user, logout_user  # type: ignore
except Exception:
    login_user = None  # type: ignore
    logout_user = None  # type: ignore

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
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

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
    return bool(v and EMAIL_RE.match(v))


def _safe_next(nxt: str) -> str:
    nxt = _norm(nxt)
    if not nxt or not nxt.startswith("/") or nxt.startswith("//"):
        return ""
    if any(c in nxt for c in ("\x00", "\r", "\n", "\\")):
        return ""
    p = urlparse(nxt)
    return nxt if not p.scheme and not p.netloc else ""


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
    for k in list(session.keys()):
        if k.startswith("rl:") or k in {
            "user_id",
            "user_email",
            "is_admin",
            "login_at",
            "login_nonce",
        }:
            session.pop(k, None)
    session.modified = True


def _set_user_session(user: User) -> None:
    _clear_auth_session()
    session["user_id"] = int(user.id)
    session["user_email"] = (user.email or "").lower()
    session["is_admin"] = bool(getattr(user, "is_admin", False))
    session["login_at"] = _now()
    session["login_nonce"] = secrets.token_urlsafe(16)
    session.permanent = True
    session.modified = True

    if login_user:
        try:
            login_user(user, remember=False)
        except Exception:
            log.exception("login_user failed")


def _get_user_by_email(email: str) -> Optional[User]:
    email = _safe_email(email)
    if not email:
        return None
    try:
        return db.session.execute(
            select(User).where(func.lower(User.email) == email)
        ).scalar_one_or_none()
    except Exception:
        log.exception("get_user_by_email failed")
        return None


def _wants_json() -> bool:
    return (
        request.headers.get("X-Requested-With") == "XMLHttpRequest"
        or "application/json" in (request.headers.get("Accept") or "")
        or (request.content_type or "").startswith("application/json")
    )


def _json_or_redirect(message: str, category: str, *, tab: str, nxt: str, redirect_to: str = ""):
    ok = category != "error"

    if _wants_json():
        return jsonify({"ok": ok, "message": message, "tab": tab}), (200 if ok else 400)

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
    return re.sub(r"\s+", " ", _norm(name))[:120]


def _is_honeypot_triggered() -> bool:
    return bool(_norm(request.form.get("website", "")))


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
def login_get():
    qs = urlencode({"tab": "login", "next": _safe_next(request.args.get("next", ""))})
    return redirect(url_for("auth.account") + f"?{qs}")


@auth_bp.get("/register")
def register_get():
    qs = urlencode({"tab": "register", "next": _safe_next(request.args.get("next", ""))})
    return redirect(url_for("auth.account") + f"?{qs}")


@auth_bp.post("/login")
def login():
    if not _rate_limit(_RL_LOGIN_KEY) or _is_honeypot_triggered():
        return _json_or_redirect("Credenciales incorrectas.", "error", tab="login", nxt="")

    email = _safe_email(request.form.get("email", ""))
    password = request.form.get("password", "") or ""
    nxt = _safe_next(request.form.get("next", ""))

    user = _get_user_by_email(email)
    ok = False
    try:
        ok = bool(user and user.check_password(password))  # type: ignore
    except Exception:
        ok = False

    if not ok or (hasattr(user, "is_active") and not user.is_active):
        return _json_or_redirect("Credenciales incorrectas.", "error", tab="login", nxt=nxt)

    _set_user_session(user)  # type: ignore[arg-type]
    return _json_or_redirect("Bienvenido 👋", "success", tab="login", nxt=nxt, redirect_to=nxt or "/")


@auth_bp.post("/register")
def register():
    if not _rate_limit(_RL_REG_KEY) or _is_honeypot_triggered():
        return _json_or_redirect("No se pudo crear la cuenta.", "error", tab="register", nxt="")

    email = _safe_email(request.form.get("email", ""))
    password = request.form.get("password", "") or ""
    password2 = request.form.get("password2", "") or ""
    name = _normalize_name(request.form.get("name", ""))
    nxt = _safe_next(request.form.get("next", ""))

    if not _valid_email(email) or password != password2 or len(password) < 8:
        return _json_or_redirect("Datos inválidos.", "error", tab="register", nxt=nxt)

    if _get_user_by_email(email):
        return _json_or_redirect("Ese email ya existe.", "error", tab="login", nxt=nxt)

    role = _extract_role()
    user = User(email=email)

    if hasattr(user, "name"):
        user.name = name
    if hasattr(user, "is_active"):
        user.is_active = True
    if hasattr(user, "email_verified"):
        user.email_verified = False
    if hasattr(user, "role"):
        user.role = role

    try:
        user.set_password(password)  # type: ignore
    except Exception:
        return _json_or_redirect("No se pudo crear la cuenta.", "error", tab="register", nxt=nxt)

    try:
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return _json_or_redirect("Ese email ya existe.", "error", tab="login", nxt=nxt)
    except Exception:
        db.session.rollback()
        log.exception("register failed")
        return _json_or_redirect("No se pudo crear la cuenta.", "error", tab="register", nxt=nxt)

    if role == "affiliate" and AffiliateProfile:
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

    if logout_user:
        try:
            logout_user()
        except Exception:
            log.exception("logout_user failed")

    flash("Sesión cerrada.", "info")
    return redirect(nxt or "/")


__all__ = ["auth_bp"]
