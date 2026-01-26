from __future__ import annotations

import logging
import re
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set, Tuple
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
from werkzeug.security import check_password_hash, generate_password_hash

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

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")
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

_VERIFY_TTL_MIN = 30
_VERIFY_RL_SEC = 60


def _now() -> int:
    return int(time.time())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _norm(v: Any, *, max_len: int = 2000) -> str:
    s = v if isinstance(v, str) else (str(v) if v is not None else "")
    s = s.replace("\x00", "").strip()
    if "\n" in s or "\r" in s:
        s = s.replace("\n", "").replace("\r", "")
    return s[:max_len]


def _safe_email(v: Any) -> str:
    return _norm(v, max_len=254).lower()


def _valid_email(v: str) -> bool:
    e = _safe_email(v)
    return bool(e and _EMAIL_RE.match(e) and len(e) <= 254)


def _parse_bool(v: Any) -> bool:
    return _norm(v, max_len=32).lower() in _TRUE


def _safe_next(nxt: Any) -> str:
    s = _norm(nxt, max_len=500)
    if not s or not s.startswith("/") or s.startswith("//"):
        return ""
    if "\\" in s or "\x00" in s:
        return ""
    try:
        p = urlparse(s)
        return s if (not p.scheme and not p.netloc) else ""
    except Exception:
        return ""


def _wants_json() -> bool:
    try:
        if request.is_json:
            return True
    except Exception:
        pass
    accept = (_norm(request.headers.get("Accept") or "", max_len=200)).lower()
    xrw = (_norm(request.headers.get("X-Requested-With") or "", max_len=60)).lower()
    fmt = (_norm(request.args.get("format") or "", max_len=40)).lower()
    return ("application/json" in accept) or (xrw == "xmlhttprequest") or (fmt == "json")


def _client_fingerprint() -> str:
    xff = _norm(request.headers.get("X-Forwarded-For") or "", max_len=400)
    ip = (xff.split(",")[0].strip() if xff else (_norm(request.remote_addr or "unknown", max_len=80)))
    ua = _norm(request.headers.get("User-Agent") or "", max_len=140)
    return f"{ip[:80]}|{ua[:120]}"


def _rate_limit(key: str) -> bool:
    now = _now()
    fp = _client_fingerprint()
    bucket_key = f"{key}:{fp}"

    store = session.get(key)
    if not isinstance(store, dict):
        store = {}

    bucket = store.get(bucket_key)
    if not isinstance(bucket, dict):
        store[bucket_key] = {"t": now, "n": 1}
        session[key] = store
        session.modified = True
        return True

    t0 = int(bucket.get("t", now))
    n = int(bucket.get("n", 0))

    if now - t0 >= _RL_WINDOW_SEC:
        store[bucket_key] = {"t": now, "n": 1}
        session[key] = store
        session.modified = True
        return True

    if n >= _RL_MAX:
        return False

    bucket["n"] = n + 1
    store[bucket_key] = bucket
    session[key] = store
    session.modified = True
    return True


def _is_honeypot_triggered() -> bool:
    return bool(_norm(request.form.get("website", ""), max_len=120))


def _normalize_name(name: Any) -> str:
    v = re.sub(r"\s+", " ", _norm(name, max_len=180))
    return v[:120]


def _extract_role() -> str:
    role = _norm(request.form.get("role", ""), max_len=24).lower()
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
    return jsonify({"ok": ok, **payload}), status


def _flash(level: str, msg: str) -> None:
    cat = "success" if level == "success" else ("info" if level == "info" else "danger")
    try:
        flash(msg, cat)
    except Exception:
        pass


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

    _flash("success" if ok else "danger", message)

    if redirect_to:
        return redirect(redirect_to, code=302)

    qs = urlencode({k: v for k, v in {"tab": tab, "next": nxt}.items() if v})
    return redirect(_account_url() + (f"?{qs}" if qs else ""), code=302)


def _bad_auth(tab: str, nxt: str):
    msg = "Credenciales incorrectas." if tab == TAB_LOGIN else "No se pudo crear la cuenta."
    return _json_or_redirect(ok=False, message=msg, tab=tab, nxt=nxt, status_err=401)


def _clear_auth_session() -> None:
    keep_prefix = ("rl:",)
    keep_exact = {_RL_LOGIN_KEY, _RL_REG_KEY}
    for k in list(session.keys()):
        ks = str(k)
        if ks in keep_exact or any(ks.startswith(p) for p in keep_prefix):
            continue
        session.pop(k, None)
    session.modified = True


def _user_password_check(user: Any, password: str) -> bool:
    pw = password or ""
    if not pw:
        return False

    try:
        fn = getattr(user, "check_password", None)
        if callable(fn):
            return bool(fn(pw))
    except Exception:
        pass

    ph = ""
    try:
        ph = str(getattr(user, "password_hash", "") or getattr(user, "password", "") or "")
    except Exception:
        ph = ""

    if not ph:
        return False

    try:
        return bool(check_password_hash(ph, pw))
    except Exception:
        return False


def _user_password_set(user: Any, password: str) -> bool:
    pw = password or ""
    if len(pw) < _MIN_PASS_LEN:
        return False

    try:
        fn = getattr(user, "set_password", None)
        if callable(fn):
            fn(pw)
            return True
    except Exception:
        pass

    ph = generate_password_hash(pw)
    try:
        if hasattr(user, "password_hash"):
            setattr(user, "password_hash", ph)
            return True
        if hasattr(user, "password"):
            setattr(user, "password", ph)
            return True
        setattr(user, "password_hash", ph)
        return True
    except Exception:
        return False


def _set_user_session(user: User) -> None:
    _clear_auth_session()
    session["user_id"] = int(getattr(user, "id", 0) or 0)
    session["user_email"] = (getattr(user, "email", "") or "").lower()
    session["is_admin"] = bool(getattr(user, "is_admin", False))
    session["role"] = str(getattr(user, "role", "") or getattr(user, "user_role", "") or "customer")
    session["email_verified"] = bool(getattr(user, "email_verified", False) or getattr(user, "is_verified", False))
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
    e = _safe_email(email)
    if not e:
        return None
    try:
        stmt = select(User).where(func.lower(User.email) == e)
        return db.session.execute(stmt).scalar_one_or_none()
    except Exception:
        log.exception("get_user_by_email failed")
        return None


def _no_store(resp):
    try:
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Pragma"] = "no-cache"
        resp.headers.setdefault("Vary", "Cookie")
    except Exception:
        pass
    return resp


def _verify_rate_limited(email: str) -> bool:
    key = f"verify_rl:{email}"
    now = _now()
    last = int(session.get(key) or 0)
    if last and (now - last) < _VERIFY_RL_SEC:
        return True
    session[key] = now
    session.modified = True
    return False


def _make_verify_token() -> str:
    return secrets.token_urlsafe(48)


def _send_verify_email(email: str, verify_url: str) -> None:
    try:
        current_app.logger.info("VERIFY_EMAIL to=%s url=%s", email, verify_url)
    except Exception:
        pass


@auth_bp.get("/account")
def account():
    if _is_authenticated():
        return redirect(_safe_next(request.args.get("next", "")) or "/", code=302)

    tab = _norm(request.args.get("tab", TAB_LOGIN), max_len=24).lower()
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
    qs = urlencode({k: v for k, v in {"tab": TAB_LOGIN, "next": nxt}.items() if v})
    return redirect(_account_url() + (f"?{qs}" if qs else ""), code=302)


@auth_bp.get("/register")
@auth_bp.get("/register/")
def register_get():
    nxt = _safe_next(request.args.get("next", ""))
    qs = urlencode({k: v for k, v in {"tab": TAB_REGISTER, "next": nxt}.items() if v})
    return redirect(_account_url() + (f"?{qs}" if qs else ""), code=302)


@auth_bp.get("/signup")
@auth_bp.get("/signin")
def compat_aliases():
    p = (_norm(request.path or "", max_len=40)).lower()
    if p.endswith("/signup"):
        return redirect("/auth/register", code=302)
    return redirect("/auth/login", code=302)


@auth_bp.post("/login")
def login():
    nxt = _safe_next(request.form.get("next", ""))

    if (not _rate_limit(_RL_LOGIN_KEY)) or _is_honeypot_triggered():
        return _bad_auth(TAB_LOGIN, nxt)

    email = _safe_email(request.form.get("email", ""))
    password = _norm(request.form.get("password", ""), max_len=512)

    if not _valid_email(email) or not password:
        return _bad_auth(TAB_LOGIN, nxt)

    user = _get_user_by_email(email)

    ok = False
    try:
        ok = bool(user and _user_password_check(user, password))
    except Exception:
        ok = False

    if not ok:
        return _bad_auth(TAB_LOGIN, nxt)

    try:
        if hasattr(user, "is_active") and not bool(getattr(user, "is_active", True)):
            return _bad_auth(TAB_LOGIN, nxt)
    except Exception:
        return _bad_auth(TAB_LOGIN, nxt)

    _set_user_session(user)  # type: ignore[arg-type]

    verified = bool(getattr(user, "email_verified", False) or getattr(user, "is_verified", False))
    if not verified:
        return _json_or_redirect(
            ok=True,
            message="Sesión iniciada. Te enviamos un email para verificar tu cuenta.",
            tab=TAB_LOGIN,
            nxt=nxt,
            redirect_to=url_for("auth.verify_send", next=nxt or "/"),
            status_ok=200,
        )

    return _json_or_redirect(ok=True, message="Bienvenido 👋", tab=TAB_LOGIN, nxt=nxt, redirect_to=nxt or "/")


@auth_bp.post("/register")
def register():
    nxt = _safe_next(request.form.get("next", ""))

    if (not _rate_limit(_RL_REG_KEY)) or _is_honeypot_triggered():
        return _bad_auth(TAB_REGISTER, nxt)

    email = _safe_email(request.form.get("email", ""))
    password = _norm(request.form.get("password", ""), max_len=512)
    password2 = _norm(request.form.get("password2", ""), max_len=512)
    name = _normalize_name(request.form.get("name", ""))

    if (not _valid_email(email)) or (len(password) < _MIN_PASS_LEN) or (password != password2):
        return _json_or_redirect(ok=False, message="Datos inválidos.", tab=TAB_REGISTER, nxt=nxt)

    if _get_user_by_email(email):
        return _json_or_redirect(ok=False, message="Ese email ya existe.", tab=TAB_LOGIN, nxt=nxt, status_err=409)

    role = _extract_role()
    user = User(email=email)

    try:
        if hasattr(user, "name"):
            setattr(user, "name", name)
        if hasattr(user, "is_active"):
            setattr(user, "is_active", True)
        if hasattr(user, "email_verified"):
            setattr(user, "email_verified", False)
        if hasattr(user, "role"):
            setattr(user, "role", role)
        if hasattr(user, "created_at"):
            setattr(user, "created_at", _utcnow())
    except Exception:
        pass

    if not _user_password_set(user, password):
        return _json_or_redirect(ok=False, message="No se pudo crear la cuenta.", tab=TAB_REGISTER, nxt=nxt, status_err=400)

    try:
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return _json_or_redirect(ok=False, message="Ese email ya existe.", tab=TAB_LOGIN, nxt=nxt, status_err=409)
    except Exception:
        db.session.rollback()
        log.exception("register commit failed")
        return _bad_auth(TAB_REGISTER, nxt)

    if role == "affiliate" and AffiliateProfile is not None:
        try:
            db.session.add(AffiliateProfile(user_id=int(user.id), status="pending"))  # type: ignore[arg-type]
            db.session.commit()
        except Exception:
            try:
                db.session.rollback()
            except Exception:
                pass

    _set_user_session(user)  # type: ignore[arg-type]
    return _json_or_redirect(
        ok=True,
        message="Cuenta creada con éxito ✅ Te enviamos un email para verificar.",
        tab=TAB_REGISTER,
        nxt=nxt,
        redirect_to=url_for("auth.verify_send", next=nxt or "/"),
        status_ok=201,
    )


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

    _flash("info", "Sesión cerrada.")
    return redirect(nxt or "/", code=302)


@auth_bp.get("/verify/send")
def verify_send():
    nxt = _safe_next(request.args.get("next", "")) or "/"
    uid = int(session.get("user_id") or 0)
    email = _safe_email(session.get("user_email") or "")
    if not uid or not email:
        return redirect(_account_url() + "?" + urlencode({"tab": TAB_LOGIN, "next": nxt}), code=302)

    user = db.session.get(User, uid)
    if not user:
        _clear_auth_session()
        return redirect(_account_url() + "?" + urlencode({"tab": TAB_LOGIN, "next": nxt}), code=302)

    if bool(getattr(user, "email_verified", False) or getattr(user, "is_verified", False)):
        session["email_verified"] = True
        session.modified = True
        _flash("success", "Tu cuenta ya está verificada ✅")
        return redirect(nxt, code=302)

    if _verify_rate_limited(email):
        _flash("info", "Ya enviamos un email recién. Esperá 1 minuto y reintentá.")
        return redirect(_account_url() + "?" + urlencode({"tab": TAB_LOGIN, "next": nxt}), code=302)

    token = _make_verify_token()
    session["verify_token"] = token
    session["verify_token_ts"] = _now()
    session.modified = True

    verify_url = url_for("auth.verify", token=token, _external=True)
    _send_verify_email(email, verify_url)

    _flash("success", "Email de verificación enviado ✅")
    return redirect(_account_url() + "?" + urlencode({"tab": TAB_LOGIN, "next": nxt}), code=302)


@auth_bp.get("/verify/<token>")
def verify(token: str):
    token = _norm(token, max_len=300)
    uid = int(session.get("user_id") or 0)
    email = _safe_email(session.get("user_email") or "")

    if not uid or not email:
        _flash("danger", "Iniciá sesión para verificar tu cuenta.")
        return redirect(_account_url() + "?" + urlencode({"tab": TAB_LOGIN}), code=302)

    st = _norm(session.get("verify_token") or "", max_len=300)
    ts = int(session.get("verify_token_ts") or 0)
    if not st or st != token:
        _flash("danger", "Token inválido.")
        return redirect(_account_url() + "?" + urlencode({"tab": TAB_LOGIN}), code=302)

    if not ts or (_now() - ts) > (_VERIFY_TTL_MIN * 60):
        _flash("danger", "Token vencido. Pedí otro email.")
        return redirect(url_for("auth.verify_send"), code=302)

    user = db.session.get(User, uid)
    if not user:
        _flash("danger", "Usuario no encontrado.")
        return redirect(_account_url() + "?" + urlencode({"tab": TAB_LOGIN}), code=302)

    try:
        if hasattr(user, "email_verified"):
            setattr(user, "email_verified", True)
        elif hasattr(user, "is_verified"):
            setattr(user, "is_verified", True)
        db.session.add(user)
        db.session.commit()
    except Exception:
        db.session.rollback()
        _flash("danger", "No se pudo verificar. Reintentá.")
        return redirect(_account_url() + "?" + urlencode({"tab": TAB_LOGIN}), code=302)

    session["email_verified"] = True
    session.pop("verify_token", None)
    session.pop("verify_token_ts", None)
    session.modified = True

    _flash("success", "Cuenta verificada ✅")
    return redirect(_safe_next(request.args.get("next", "")) or "/", code=302)


__all__ = ["auth_bp"]
