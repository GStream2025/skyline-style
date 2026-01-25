from __future__ import annotations

import logging
import re
import secrets
import time
from typing import Any, Dict, Optional, Set
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
    from flask_login import current_user as _current_user  # type: ignore
    from flask_login import login_user as _login_user  # type: ignore
    from flask_login import logout_user as _logout_user  # type: ignore
except Exception:
    _current_user = None  # type: ignore
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
auth_bp.strict_slashes = False

_TRUE: Set[str] = {"1", "true", "yes", "y", "on", "checked"}
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_ALLOWED_PUBLIC_ROLES: Set[str] = {"customer", "affiliate"}

TAB_LOGIN = "login"
TAB_REGISTER = "register"
_VALID_TABS: Set[str] = {TAB_LOGIN, TAB_REGISTER}

_RL_LOGIN_KEY = "rl:login"
_RL_REG_KEY = "rl:register"
_RL_WINDOW_SEC = 60
_RL_MAX = 8

_MIN_PASS_LEN = 8


def _now() -> int:
    return int(time.time())


def _norm(v: Any) -> str:
    return (str(v) if v is not None else "").strip()


def _safe_email(v: Any) -> str:
    return _norm(v).lower()


def _valid_email(v: str) -> bool:
    v = _safe_email(v)
    return bool(v and _EMAIL_RE.match(v))


def _parse_bool(v: Any) -> bool:
    return _norm(v).lower() in _TRUE


def _safe_next(nxt: Any) -> str:
    nxt_s = _norm(nxt)
    if not nxt_s or not nxt_s.startswith("/") or nxt_s.startswith("//"):
        return ""
    if any(c in nxt_s for c in ("\x00", "\r", "\n", "\\")):
        return ""
    p = urlparse(nxt_s)
    return nxt_s if (not p.scheme and not p.netloc) else ""


def _wants_json() -> bool:
    if request.is_json:
        return True
    accept = (request.headers.get("Accept") or "").lower()
    xrw = (request.headers.get("X-Requested-With") or "").lower()
    return ("application/json" in accept) or (xrw == "xmlhttprequest")


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


def _is_honeypot_triggered() -> bool:
    return bool(_norm(request.form.get("website", "")))


def _normalize_name(name: Any) -> str:
    v = re.sub(r"\s+", " ", _norm(name))
    return v[:120]


def _extract_role() -> str:
    role = _norm(request.form.get("role", "")).lower()
    if role in _ALLOWED_PUBLIC_ROLES:
        return role
    if _parse_bool(request.form.get("want_affiliate", "")):
        return "affiliate"
    return "customer"


def _account_url() -> str:
    try:
        return url_for("auth.account")
    except Exception:
        return "/auth/account"


def _json(ok: bool, payload: Dict[str, Any], status: int):
    data = {"ok": ok, **payload}
    return jsonify(data), status


def _json_or_redirect(
    *,
    ok: bool,
    message: str,
    tab: str,
    nxt: str,
    redirect_to: str = "",
    status_ok: int = 200,
    status_err: int = 400,
):
    if _wants_json():
        status = status_ok if ok else status_err
        return _json(ok, {"message": message, "tab": tab, "redirect": redirect_to or ""}, status)

    flash(message, "success" if ok else "error")

    if redirect_to:
        return redirect(redirect_to, code=302)

    qs = urlencode({"tab": tab, "next": nxt})
    return redirect(_account_url() + f"?{qs}", code=302)


def _bad_auth(tab: str, nxt: str):
    msg = "Credenciales incorrectas." if tab == TAB_LOGIN else "No se pudo crear la cuenta."
    return _json_or_redirect(ok=False, message=msg, tab=tab, nxt=nxt, status_err=401)


def _clear_auth_session() -> None:
    keep_prefixes = {"rl:"}
    keep_keys: Set[str] = set()

    for k in list(session.keys()):
        ks = str(k)
        if any(ks.startswith(p) for p in keep_prefixes):
            continue
        if ks in keep_keys:
            continue
        session.pop(k, None)

    session.modified = True


def _set_user_session(user: User) -> None:
    _clear_auth_session()
    session["user_id"] = int(getattr(user, "id", 0) or 0)
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


def _is_authenticated() -> bool:
    try:
        if _current_user is not None and getattr(_current_user, "is_authenticated", False):
            return True
    except Exception:
        pass
    return bool(session.get("user_id"))


def _get_user_by_email(email: str) -> Optional[User]:
    email = _safe_email(email)
    if not email:
        return None
    try:
        return db.session.execute(select(User).where(func.lower(User.email) == email)).scalar_one_or_none()
    except Exception:
        log.exception("get_user_by_email failed")
        return None


def _no_store(resp):
    try:
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Pragma"] = "no-cache"
    except Exception:
        pass
    return resp


@auth_bp.get("/account")
def account():
    if _is_authenticated():
        return redirect(_safe_next(request.args.get("next", "")) or "/", code=302)

    tab = _norm(request.args.get("tab", TAB_LOGIN)).lower()
    if tab not in _VALID_TABS:
        tab = TAB_LOGIN

    nxt = _safe_next(request.args.get("next", ""))
    prefill_email = _safe_email(request.args.get("email", ""))

    resp = make_response(
        render_template(
            "auth/account.html",
            active_tab=tab,
            next=nxt,
            prefill_email=prefill_email,
        ),
        200,
    )
    return _no_store(resp)


@auth_bp.get("/login")
@auth_bp.get("/login/")
def login_get():
    nxt = _safe_next(request.args.get("next", ""))
    qs = urlencode({"tab": TAB_LOGIN, "next": nxt})
    return redirect(_account_url() + f"?{qs}", code=302)


@auth_bp.get("/register")
@auth_bp.get("/register/")
def register_get():
    nxt = _safe_next(request.args.get("next", ""))
    qs = urlencode({"tab": TAB_REGISTER, "next": nxt})
    return redirect(_account_url() + f"?{qs}", code=302)


@auth_bp.get("/signup")
@auth_bp.get("/signin")
def compat_aliases():
    p = (request.path or "").lower()
    if p.endswith("/signup"):
        return redirect("/auth/register", code=302)
    return redirect("/auth/login", code=302)


@auth_bp.post("/login")
def login():
    nxt = _safe_next(request.form.get("next", ""))

    if (not _rate_limit(_RL_LOGIN_KEY)) or _is_honeypot_triggered():
        return _bad_auth(TAB_LOGIN, nxt)

    email = _safe_email(request.form.get("email", ""))
    password = _norm(request.form.get("password", ""))

    if not email or not password:
        return _bad_auth(TAB_LOGIN, nxt)

    user = _get_user_by_email(email)

    ok = False
    try:
        ok = bool(user and user.check_password(password))  # type: ignore[attr-defined]
    except Exception:
        ok = False

    if not ok:
        return _bad_auth(TAB_LOGIN, nxt)

    if hasattr(user, "is_active") and not bool(getattr(user, "is_active", True)):
        return _bad_auth(TAB_LOGIN, nxt)

    _set_user_session(user)  # type: ignore[arg-type]
    return _json_or_redirect(ok=True, message="Bienvenido 👋", tab=TAB_LOGIN, nxt=nxt, redirect_to=nxt or "/")


@auth_bp.post("/register")
def register():
    nxt = _safe_next(request.form.get("next", ""))

    if (not _rate_limit(_RL_REG_KEY)) or _is_honeypot_triggered():
        return _bad_auth(TAB_REGISTER, nxt)

    email = _safe_email(request.form.get("email", ""))
    password = _norm(request.form.get("password", ""))
    password2 = _norm(request.form.get("password2", ""))
    name = _normalize_name(request.form.get("name", ""))

    if (not _valid_email(email)) or (len(password) < _MIN_PASS_LEN) or (password != password2):
        return _json_or_redirect(ok=False, message="Datos inválidos.", tab=TAB_REGISTER, nxt=nxt)

    if _get_user_by_email(email):
        return _json_or_redirect(ok=False, message="Ese email ya existe.", tab=TAB_LOGIN, nxt=nxt)

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
        return _bad_auth(TAB_REGISTER, nxt)

    try:
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return _json_or_redirect(ok=False, message="Ese email ya existe.", tab=TAB_LOGIN, nxt=nxt)
    except Exception:
        db.session.rollback()
        log.exception("register commit failed")
        return _bad_auth(TAB_REGISTER, nxt)

    if role == "affiliate" and AffiliateProfile is not None:
        try:
            db.session.add(AffiliateProfile(user_id=int(user.id), status="pending"))
            db.session.commit()
        except Exception:
            db.session.rollback()

    _set_user_session(user)
    return _json_or_redirect(ok=True, message="Cuenta creada con éxito ✅", tab=TAB_REGISTER, nxt=nxt, redirect_to=nxt or "/")


@auth_bp.route("/logout", methods=["GET", "POST"])
def logout():
    nxt = _safe_next(request.values.get("next", ""))
    _clear_auth_session()

    if _logout_user:
        try:
            _logout_user()
        except Exception:
            log.exception("flask_login logout_user failed")

    if _wants_json():
        return _json(True, {"message": "Sesión cerrada.", "redirect": nxt or "/"}, 200)

    flash("Sesión cerrada.", "info")
    return redirect(nxt or "/", code=302)


__all__ = ["auth_bp"]
