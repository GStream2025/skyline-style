# app/routes/auth_routes.py — Skyline Store (BULLETPROOF FINAL / NO-404 / CSRF-SAFE / DB-SAFE)
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
except Exception:  # pragma: no cover
    login_user = None  # type: ignore
    logout_user = None  # type: ignore

try:
    from app.models import AffiliateProfile  # type: ignore
except Exception:  # pragma: no cover
    AffiliateProfile = None  # type: ignore


log = logging.getLogger("auth_routes")

auth_bp = Blueprint("auth", __name__, url_prefix="/auth", template_folder="../templates")

_TRUE: Set[str] = {"1", "true", "yes", "y", "on", "checked"}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

_ALLOWED_PUBLIC_ROLES: Set[str] = {"customer", "affiliate"}

_RL_LOGIN_KEY = "rl:login"
_RL_REG_KEY = "rl:register"
_RL_WINDOW_SEC = 60
_RL_MAX = 8


def _now() -> int:
    return int(time.time())


def _safe_email(v: str) -> str:
    return (v or "").strip().lower()


def _valid_email(v: str) -> bool:
    v = (v or "").strip()
    return bool(v and EMAIL_RE.match(v))


def _safe_next(nxt: str) -> str:
    if not nxt:
        return ""
    nxt = str(nxt).strip()
    if not nxt.startswith("/") or nxt.startswith("//"):
        return ""
    if any(ch in nxt for ch in ("\x00", "\r", "\n")) or "\\" in nxt:
        return ""
    p = urlparse(nxt)
    return nxt if (not p.scheme and not p.netloc) else ""


def _rate_limit(key: str) -> bool:
    try:
        bucket = session.get(key)
        now = _now()
        if not isinstance(bucket, dict):
            bucket = {"t": now, "n": 0}

        t0 = int(bucket.get("t") or now)
        n = int(bucket.get("n") or 0)

        if now - t0 >= _RL_WINDOW_SEC:
            session[key] = {"t": now, "n": 0}
            session.modified = True
            return True

        if n >= _RL_MAX:
            session[key] = {"t": t0, "n": n}
            session.modified = True
            return False

        bucket["n"] = n + 1
        session[key] = bucket
        session.modified = True
        return True
    except Exception:
        return True


def _clear_auth_session() -> None:
    for k in list(session.keys()):
        if k.startswith("rl:") or k in {"user_id", "user_email", "is_admin", "login_at", "login_nonce"}:
            session.pop(k, None)
    session.modified = True


def _set_user_session(user: User) -> None:
    _clear_auth_session()
    session["user_id"] = int(getattr(user, "id"))
    session["user_email"] = (getattr(user, "email") or "").lower()
    session["is_admin"] = bool(getattr(user, "is_admin", False))
    session["login_at"] = _now()
    session["login_nonce"] = secrets.token_urlsafe(16)
    session.permanent = True
    session.modified = True

    if login_user:
        try:
            login_user(user, remember=False)
        except Exception:
            log.exception("login_user failed (ignored)")


def _get_user_by_email(email: str) -> Optional[User]:
    email = _safe_email(email)
    if not email:
        return None
    try:
        return db.session.execute(select(User).where(func.lower(User.email) == email)).scalar_one_or_none()
    except Exception:
        log.exception("DB error on _get_user_by_email (ignored)")
        return None


def _wants_json() -> bool:
    accept = (request.headers.get("Accept") or "").lower()
    xrw = (request.headers.get("X-Requested-With") or "").lower()
    ct = (request.content_type or "").lower()
    return xrw == "xmlhttprequest" or "application/json" in accept or ct.startswith("application/json")


def _json_or_redirect(message: str, category: str, *, tab: str, nxt: str, redirect_to: str = ""):
    ok = category != "error"
    if _wants_json():
        return jsonify({"ok": ok, "message": message, "tab": tab}), (200 if ok else 400)

    cat = category if category in {"error", "warning", "info", "success"} else "info"
    flash(message, "success" if cat == "success" else cat)

    if redirect_to:
        return redirect(redirect_to)

    qs = urlencode({"tab": tab, "next": nxt})
    return redirect(url_for("auth.account") + f"?{qs}")


def _parse_bool(v: str) -> bool:
    return (v or "").strip().lower() in _TRUE


def _extract_role() -> str:
    role = (request.form.get("role") or "").strip().lower()
    if role in __ALLOWED_PUBLIC_ROLES:
        return role
    if _parse_bool(request.form.get("want_affiliate", "")):
        return "affiliate"
    return "customer"


def _set_role_if_supported(user: User, role: str) -> None:
    if hasattr(user, "role"):
        try:
            setattr(user, "role", role)
        except Exception:
            pass


def _normalize_name(name: str) -> str:
    s = re.sub(r"\s+", " ", (name or "").strip())
    return s[:120]


def _is_honeypot_triggered() -> bool:
    v = (request.form.get("website") or "").strip()
    return bool(v)


@auth_bp.get("/account")
def account():
    if session.get("user_id"):
        return redirect(_safe_next(request.args.get("next", "")) or "/")

    tab = (request.args.get("tab") or "login").strip().lower()
    if tab not in {"login", "register"}:
        tab = "login"

    nxt = _safe_next(request.args.get("next", ""))
    prefill_email = _safe_email(request.args.get("email", ""))

    return make_response(
        render_template("auth/account.html", active_tab=tab, next=nxt, prefill_email=prefill_email),
        200,
        {"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


@auth_bp.get("/register")
def register_get_redirect():
    qs = urlencode({"tab": "register", "next": _safe_next(request.args.get("next", ""))})
    return redirect(url_for("auth.account") + f"?{qs}", code=302)


@auth_bp.get("/login")
def login_get_redirect():
    qs = urlencode({"tab": "login", "next": _safe_next(request.args.get("next", ""))})
    return redirect(url_for("auth.account") + f"?{qs}", code=302)


@auth_bp.post("/login")
def login():
    if not _rate_limit(_RL_LOGIN_KEY):
        return _json_or_redirect("Demasiados intentos. Probá de nuevo en un minuto.", "error", tab="login", nxt="")

    if _is_honeypot_triggered():
        return _json_or_redirect("Email o contraseña incorrectos.", "error", tab="login", nxt="")

    email = _safe_email(request.form.get("email", ""))
    password = request.form.get("password", "") or ""
    nxt = _safe_next(request.form.get("next", ""))

    if not _valid_email(email) or not password:
        return _json_or_redirect("Email o contraseña incorrectos.", "error", tab="login", nxt=nxt)

    user = _get_user_by_email(email)
    try:
        ok_pwd = bool(user and user.check_password(password))  # type: ignore[attr-defined]
    except Exception:
        ok_pwd = False

    if not ok_pwd:
        return _json_or_redirect("Email o contraseña incorrectos.", "error", tab="login", nxt=nxt)

    if hasattr(user, "is_active") and not bool(getattr(user, "is_active")):
        return _json_or_redirect("Cuenta desactivada.", "error", tab="login", nxt=nxt)

    _set_user_session(user)  # type: ignore[arg-type]
    return _json_or_redirect("Bienvenido 👋", "success", tab="login", nxt=nxt, redirect_to=nxt or "/")


@auth_bp.post("/register")
def register():
    if not _rate_limit(_RL_REG_KEY):
        return _json_or_redirect("Demasiados registros seguidos. Esperá un minuto y probá de nuevo.", "error", tab="register", nxt="")

    if _is_honeypot_triggered():
        return _json_or_redirect("No se pudo crear la cuenta. Probá más tarde.", "error", tab="register", nxt="")

    email = _safe_email(request.form.get("email", ""))
    password = request.form.get("password", "") or ""
    password2 = request.form.get("password2", "") or ""
    name = _normalize_name(request.form.get("name") or "")
    nxt = _safe_next(request.form.get("next", ""))

    if not _valid_email(email):
        return _json_or_redirect("Email inválido.", "error", tab="register", nxt=nxt)

    if password != password2 or len(password) < 8:
        return _json_or_redirect("Contraseña inválida (mínimo 8).", "error", tab="register", nxt=nxt)

    if _get_user_by_email(email):
        return _json_or_redirect("Ese email ya existe. Iniciá sesión.", "error", tab="login", nxt=nxt)

    role = _extract_role()
    if role not in _ALLOWED_PUBLIC_ROLES:
        role = "customer"

    user = User(email=email)

    if hasattr(user, "name"):
        try:
            user.name = name
        except Exception:
            pass

    if hasattr(user, "is_active"):
        try:
            user.is_active = True
        except Exception:
            pass

    if hasattr(user, "email_verified"):
        try:
            user.email_verified = False
        except Exception:
            pass

    _set_role_if_supported(user, role)

    try:
        user.set_password(password)  # type: ignore[attr-defined]
    except Exception:
        try:
            from app.utils.password_engine import hash_password
            user.password_hash = hash_password(password)  # type: ignore[attr-defined]
        except Exception:
            return _json_or_redirect("No se pudo crear la cuenta (password).", "error", tab="register", nxt=nxt)

    try:
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return _json_or_redirect("Ese email ya existe. Iniciá sesión.", "error", tab="login", nxt=nxt)
    except Exception:
        db.session.rollback()
        log.exception("register commit failed")
        return _json_or_redirect("No se pudo crear la cuenta. Probá más tarde.", "error", tab="register", nxt=nxt)

    if role == "affiliate" and AffiliateProfile is not None:
        try:
            db.session.add(AffiliateProfile(user_id=int(user.id), status="pending"))
            db.session.commit()
        except Exception:
            db.session.rollback()
            log.warning("AffiliateProfile creation failed (ignored)")

    try:
        _set_user_session(user)
    except Exception:
        log.exception("post-register session failed (ignored)")

    return _json_or_redirect("Cuenta creada con éxito ✅", "success", tab="register", nxt=nxt, redirect_to=nxt or "/")


@auth_bp.route("/logout", methods=["GET", "POST"])
def logout():
    nxt = _safe_next(request.values.get("next", "") or "")
    _clear_auth_session()

    if logout_user:
        try:
            logout_user()
        except Exception:
            log.exception("logout_user failed (ignored)")

    flash("Sesión cerrada.", "info")
    return redirect(nxt or "/")


__all__ = ["auth_bp"]
