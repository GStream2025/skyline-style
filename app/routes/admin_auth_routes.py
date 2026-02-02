from __future__ import annotations

import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

from flask import (
    Blueprint,
    current_app,
    flash,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from app.models import db
from app.utils.admin_gate import (
    ADMIN_NEXT_PARAM_DEFAULT,
    ADMIN_SESSION_KEY_DEFAULT,
    build_admin_login_url,
    build_admin_register_url,
)

admin_auth_bp = Blueprint("admin_auth", __name__, url_prefix="/admin")
admin_auth_bp.strict_slashes = False

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off", "unchecked"}

_CSRF_KEY = "csrf_token"
_RL_KEY = "_admin_auth_rl"

_VERIFY_TOKEN = "_admin_verify_token"
_VERIFY_TS = "_admin_verify_ts"
_VERIFY_EMAIL = "_admin_verify_email"

_DEFAULT_NEXT = "/admin/dashboard"
_VERIFY_TTL_MIN = 45
_RL_TTL = 60 * 30
_RL_CAP = 400


def _now() -> int:
    return int(time.time())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _s(v: Any, n: int = 500) -> str:
    if v is None:
        return ""
    s = str(v).replace("\x00", "").replace("\u200b", "").strip()
    return s[:n]


def _cfg_bool(name: str, default: bool = False) -> bool:
    v = current_app.config.get(name, default)
    if isinstance(v, bool):
        return v
    s = _s(v, 32).lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return default


def _cfg_int(name: str, default: int, *, min_v: int, max_v: int) -> int:
    try:
        v = int(current_app.config.get(name, default))
    except Exception:
        v = default
    return max(min_v, min(max_v, v))


def _clean_next(raw: Any, *, fallback: str) -> str:
    s = _s(raw, 700)
    if not s or "://" in s or "\\" in s or ".." in s:
        return fallback
    if not s.startswith("/") or s.startswith("//"):
        return fallback
    try:
        p = urlparse(s)
        if p.scheme or p.netloc:
            return fallback
        if p.path.startswith(("/admin/login", "/admin/register", "/admin/logout")):
            return fallback
        return p.path or fallback
    except Exception:
        return fallback


def _csrf_get() -> str:
    tok = session.get(_CSRF_KEY)
    if not isinstance(tok, str) or len(tok) < 24:
        tok = secrets.token_urlsafe(32)
        session[_CSRF_KEY] = tok
        session.modified = True
    return tok


def _csrf_ok() -> bool:
    if request.method != "POST":
        return True
    a = _s(session.get(_CSRF_KEY), 2048)
    b = _s(request.form.get("csrf_token"), 2048)
    if not a or not b:
        return False
    try:
        return secrets.compare_digest(a, b)
    except Exception:
        return False


def _rotate_csrf() -> None:
    session[_CSRF_KEY] = secrets.token_urlsafe(32)
    session.modified = True


def _rate(bucket: str, *, window: int, max_hits: int) -> tuple[bool, int]:
    now = _now()
    store = session.get(_RL_KEY) or {}
    cutoff = now - _RL_TTL

    for k in list(store.keys()):
        if store[k]["t"] < cutoff:
            store.pop(k, None)

    key = f"{bucket}"
    b = store.get(key)

    if not b or (now - b["t"]) >= window:
        store[key] = {"t": now, "n": 1}
        session[_RL_KEY] = store
        session.modified = True
        return True, 0

    if b["n"] >= max_hits:
        return False, int(window - (now - b["t"]))

    b["n"] += 1
    store[key] = b
    session[_RL_KEY] = store
    session.modified = True
    return True, 0


def _set_admin_session(uid: int, email: str) -> None:
    keep = {k: session.get(k) for k in (_CSRF_KEY, _RL_KEY) if k in session}
    session.clear()
    session.update(keep)

    session[ADMIN_SESSION_KEY_DEFAULT] = True
    session["is_admin"] = True
    session["admin_user_id"] = uid
    session["admin_email"] = email.lower()
    session["admin_login_at"] = _now()
    session["admin_nonce"] = secrets.token_urlsafe(16)

    ttl = _cfg_int("ADMIN_SESSION_TTL_MINUTES", 480, min_v=10, max_v=10080)
    session.permanent = True
    current_app.permanent_session_lifetime = timedelta(minutes=ttl)

    _rotate_csrf()


def _is_admin() -> bool:
    v = session.get("is_admin") or session.get(ADMIN_SESSION_KEY_DEFAULT)
    if isinstance(v, str):
        return v.lower() in _TRUE
    return bool(v)


def _get_user():
    try:
        from app.models import User
        return User
    except Exception:
        return None


def _find_admin(email: str):
    User = _get_user()
    if not User:
        return None
    try:
        return (
            db.session.execute(
                select(User).where(func.lower(User.email) == email.lower())
            )
            .scalar_one_or_none()
        )
    except Exception:
        db.session.rollback()
        return None


def _verify_password(user: Any, password: str) -> bool:
    try:
        from app.utils.password_engine import verify_and_maybe_rehash

        ok, new = verify_and_maybe_rehash(user.password_hash, password)
        if ok and new:
            user.password_hash = new
            db.session.commit()
        return bool(ok)
    except Exception:
        return False


def _admin_register_enabled() -> bool:
    return _cfg_bool("ADMIN_ALLOW_REGISTER", False)


def _invite_ok(code: str) -> bool:
    expected = _s(current_app.config.get("ADMIN_REGISTER_CODE"), 140)
    return bool(expected and secrets.compare_digest(expected, _s(code, 140)))


def _start_verify(email: str, next_path: str) -> None:
    token = secrets.token_urlsafe(48)
    session[_VERIFY_TOKEN] = token
    session[_VERIFY_TS] = _now()
    session[_VERIFY_EMAIL] = email
    session.modified = True

    url = url_for(
        "admin_auth.verify",
        token=token,
        email=email,
        next=next_path,
        _external=True,
    )

    try:
        from app.services.email_service import send_admin_verify

        send_admin_verify(email=email, verify_url=url)
    except Exception:
        current_app.logger.info("ADMIN_VERIFY %s %s", email, url)


def _verify_token_ok(token: str) -> bool:
    if not secrets.compare_digest(_s(session.get(_VERIFY_TOKEN)), _s(token)):
        return False
    ts = int(session.get(_VERIFY_TS) or 0)
    return (_now() - ts) <= (_VERIFY_TTL_MIN * 60)


@admin_auth_bp.before_request
def _before():
    _csrf_get()


@admin_auth_bp.after_request
def _after(resp):
    resp.headers.setdefault("Cache-Control", "no-store")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    return resp


@admin_auth_bp.get("/login")
def login_get():
    nxt = _clean_next(request.args.get("next"), fallback=_DEFAULT_NEXT)
    if _is_admin():
        return redirect(nxt, 302)
    return render_template(
        "admin/login.html",
        next=nxt,
        csrf_token=_csrf_get(),
        allow_register=_admin_register_enabled(),
    )


@admin_auth_bp.post("/login")
def login_post():
    ok, retry = _rate(
        "login",
        window=_cfg_int("ADMIN_RL_WINDOW", 15, min_v=5, max_v=600),
        max_hits=_cfg_int("ADMIN_RL_LOGIN_MAX", 10, min_v=3, max_v=50),
    )

    nxt = _clean_next(request.form.get("next"), fallback=_DEFAULT_NEXT)

    if not ok:
        flash(f"Demasiados intentos. Esperá {retry}s.", "warning")
        return redirect(build_admin_login_url(next_path=nxt), 302)

    if not _csrf_ok():
        flash("CSRF inválido.", "danger")
        return redirect(build_admin_login_url(next_path=nxt), 302)

    email = _s(request.form.get("email"), 254).lower()
    password = _s(request.form.get("password"), 512)

    user = _find_admin(email)
    if not user or not getattr(user, "is_admin", False) or not _verify_password(user, password):
        time.sleep(0.2)
        flash("Credenciales incorrectas.", "danger")
        return redirect(build_admin_login_url(next_path=nxt), 302)

    if hasattr(user, "email_verified") and not user.email_verified:
        _start_verify(email, nxt)
        flash("Verificá tu email.", "warning")
        return redirect(build_admin_login_url(next_path=nxt), 302)

    _set_admin_session(user.id, email)
    flash("Bienvenido al panel.", "success")
    return redirect(nxt, 302)


@admin_auth_bp.get("/logout")
def logout():
    session.clear()
    flash("Sesión cerrada.", "info")
    return redirect("/admin/login", 302)


@admin_auth_bp.get("/verify/<token>")
def verify(token: str):
    nxt = _clean_next(request.args.get("next"), fallback=_DEFAULT_NEXT)

    if not _verify_token_ok(token):
        flash("Token inválido o vencido.", "danger")
        return redirect("/admin/login", 302)

    email = _s(request.args.get("email") or session.get(_VERIFY_EMAIL), 254).lower()
    user = _find_admin(email)

    if not user:
        flash("Usuario no encontrado.", "danger")
        return redirect("/admin/login", 302)

    try:
        user.email_verified = True
        db.session.commit()
    except Exception:
        db.session.rollback()
        flash("No se pudo verificar.", "danger")
        return redirect("/admin/login", 302)

    session.pop(_VERIFY_TOKEN, None)
    session.pop(_VERIFY_TS, None)
    session.pop(_VERIFY_EMAIL, None)

    flash("Email verificado.", "success")
    return redirect("/admin/login", 302)


__all__ = ["admin_auth_bp"]
