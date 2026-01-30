from __future__ import annotations

import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from flask import Blueprint, current_app, flash, make_response, redirect, render_template, request, session, url_for
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from app.models import db
from app.utils.admin_gate import (
    ADMIN_NEXT_PARAM_DEFAULT,
    ADMIN_SESSION_KEY_DEFAULT,
    build_admin_login_url,
    build_admin_register_url,
)

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")
admin_bp.strict_slashes = False

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off"}
_CSRF_KEY = "csrf_token"
_RL_KEY = "_admin_rl_v2"

_VERIFY_TOKEN_KEY = "_admin_verify_token"
_VERIFY_TOKEN_TS_KEY = "_admin_verify_ts"

_DEFAULT_NEXT = "/admin/dashboard"
_VERIFY_TTL_MIN = 45


def _now() -> int:
    return int(time.time())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _safe_str(v: Any, *, max_len: int = 500) -> str:
    if v is None:
        return ""
    s = v if isinstance(v, str) else str(v)
    s = s.replace("\x00", "").strip().replace("\r", "").replace("\n", "")
    return s[:max_len]


def _cfg_bool(name: str, default: bool = False) -> bool:
    v = current_app.config.get(name, default)
    if isinstance(v, bool):
        return v
    s = _safe_str(v, max_len=32).lower()
    if not s:
        return default
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return default


def _clean_next(nxt: Any, *, fallback: str) -> str:
    p = _safe_str(nxt, max_len=512)
    if not p or not p.startswith("/") or p.startswith("//") or "://" in p or "\\" in p or ".." in p:
        return fallback
    if "?" in p:
        p = p.split("?", 1)[0]
    if "#" in p:
        p = p.split("#", 1)[0]
    if p.startswith("/admin/login") or p.startswith("/admin/register") or p.startswith("/admin/logout"):
        return fallback
    return p or fallback


def _client_fp() -> str:
    xff = _safe_str(request.headers.get("X-Forwarded-For") or "", max_len=200)
    ip = (xff.split(",")[0].strip() if xff else _safe_str(request.remote_addr or "0.0.0.0", max_len=80))
    ua = _safe_str(request.headers.get("User-Agent") or "", max_len=200)[:120]
    return f"{ip}|{ua}"


def _rate_limit(bucket: str, *, window_sec: int, max_hits: int) -> tuple[bool, int]:
    now = _now()
    fp = _client_fp()
    key = f"{bucket}:{fp}"

    store = session.get(_RL_KEY)
    if not isinstance(store, dict):
        store = {}

    b = store.get(key)
    if not isinstance(b, dict):
        store[key] = {"t": now, "n": 1}
        session[_RL_KEY] = store
        session.modified = True
        return True, 0

    t0 = int(b.get("t") or now)
    n = int(b.get("n") or 0)

    if now - t0 >= window_sec:
        store[key] = {"t": now, "n": 1}
        session[_RL_KEY] = store
        session.modified = True
        return True, 0

    if n >= max_hits:
        retry = int(max(1, window_sec - (now - t0)))
        return False, retry

    b["n"] = n + 1
    store[key] = b
    session[_RL_KEY] = store
    session.modified = True
    return True, 0


def _csrf_issue() -> str:
    tok = session.get(_CSRF_KEY)
    if not isinstance(tok, str) or len(tok) < 24:
        tok = secrets.token_urlsafe(32)
        session[_CSRF_KEY] = tok
        session.modified = True
    return tok


def _csrf_ok_form() -> bool:
    if request.method != "POST":
        return True

    sess = _safe_str(session.get(_CSRF_KEY) or "", max_len=2048)
    sent = _safe_str(request.form.get("csrf_token") or "", max_len=2048)

    if not sess or not sent:
        return False
    try:
        return secrets.compare_digest(sess, sent)
    except Exception:
        return False


def _session_hard_reset(preserve: tuple[str, ...] = (_CSRF_KEY, _RL_KEY)) -> None:
    keep: dict[str, Any] = {}
    for k in preserve:
        if k in session:
            keep[k] = session.get(k)
    session.clear()
    for k, v in keep.items():
        session[k] = v
    session.modified = True


def _set_admin_session(user_id: int, email: str) -> None:
    _session_hard_reset()
    session[ADMIN_SESSION_KEY_DEFAULT] = True
    session["is_admin"] = True
    session["admin_user_id"] = int(user_id)
    session["admin_email"] = email.lower()
    session["admin_login_at"] = _now()
    session["admin_nonce"] = secrets.token_urlsafe(16)
    session.permanent = True
    session.modified = True
    _csrf_issue()


def _is_admin_session() -> bool:
    v = session.get("is_admin") or session.get(ADMIN_SESSION_KEY_DEFAULT)
    if isinstance(v, str):
        return v.strip().lower() in _TRUE
    return bool(v)


def _admin_default_next() -> str:
    raw = _safe_str(current_app.config.get("ADMIN_DEFAULT_NEXT", _DEFAULT_NEXT), max_len=120)
    return _clean_next(raw, fallback=_DEFAULT_NEXT)


def _get_user_model():
    try:
        from app.models import User  # type: ignore
        return User
    except Exception:
        return None


def _find_admin_user(email: str):
    User = _get_user_model()
    if User is None:
        return None
    e = _safe_str(email, max_len=254).lower()
    if not e or "@" not in e:
        return None
    try:
        stmt = select(User).where(func.lower(User.email) == e)
        user = db.session.execute(stmt).scalar_one_or_none()
        if not user:
            return None
        if hasattr(user, "is_admin") and not bool(getattr(user, "is_admin", False)):
            return None
        if hasattr(user, "active") and not bool(getattr(user, "active", True)):
            return None
        return user
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        return None


def _verify_password(user: Any, password: str) -> bool:
    pw = _safe_str(password, max_len=512)
    if not pw:
        return False

    try:
        from app.utils.password_engine import verify_and_maybe_rehash  # type: ignore
        stored = _safe_str(getattr(user, "password_hash", "") or getattr(user, "password", ""), max_len=2048)
        ok, new_hash = verify_and_maybe_rehash(stored, pw)
        if ok and new_hash and hasattr(user, "password_hash"):
            try:
                setattr(user, "password_hash", new_hash)
                db.session.commit()
            except Exception:
                try:
                    db.session.rollback()
                except Exception:
                    pass
        return bool(ok)
    except Exception:
        pass

    try:
        from werkzeug.security import check_password_hash  # type: ignore
        stored = _safe_str(getattr(user, "password_hash", "") or getattr(user, "password", ""), max_len=2048)
        return bool(stored) and bool(check_password_hash(stored, pw))
    except Exception:
        return False


def _set_password(user: Any, password: str) -> bool:
    pw = _safe_str(password, max_len=512)
    min_len = int(current_app.config.get("ADMIN_MIN_PASSWORD_LEN", 10) or 10)
    if len(pw) < min_len:
        return False
    try:
        from app.utils.password_engine import hash_password  # type: ignore
        h = hash_password(pw)
    except Exception:
        try:
            from werkzeug.security import generate_password_hash  # type: ignore
            h = generate_password_hash(pw)
        except Exception:
            return False

    if hasattr(user, "password_hash"):
        setattr(user, "password_hash", h)
        return True
    if hasattr(user, "password"):
        setattr(user, "password", h)
        return True
    setattr(user, "password_hash", h)
    return True


def _admin_register_enabled() -> bool:
    return _cfg_bool("ADMIN_ALLOW_REGISTER", False)


def _invite_ok(invite_code: str) -> bool:
    expected = _safe_str(current_app.config.get("ADMIN_REGISTER_CODE", ""), max_len=120)
    given = _safe_str(invite_code, max_len=120)
    if not expected:
        return False
    try:
        return secrets.compare_digest(given, expected)
    except Exception:
        return False


def _send_email(kind: str, *, email: str, url: str) -> None:
    try:
        from app.services.email_service import send_admin_verify  # type: ignore
        if callable(send_admin_verify):
            send_admin_verify(email=email, verify_url=url)
            return
    except Exception:
        pass
    try:
        current_app.logger.info("%s to=%s url=%s", kind, email, url)
    except Exception:
        pass


def _make_verify_token() -> str:
    return secrets.token_urlsafe(48)


def _start_admin_verify_flow(email: str) -> None:
    token = _make_verify_token()
    session[_VERIFY_TOKEN_KEY] = token
    session[_VERIFY_TOKEN_TS_KEY] = _now()
    session.modified = True
    verify_url = url_for("admin.verify", token=token, _external=True)
    _send_email("ADMIN_VERIFY_EMAIL", email=email, url=verify_url)


def _verify_token_ok(token: str) -> bool:
    tok = _safe_str(token, max_len=300)
    st = _safe_str(session.get(_VERIFY_TOKEN_KEY) or "", max_len=300)
    if not st or not tok:
        return False
    try:
        if not secrets.compare_digest(st, tok):
            return False
    except Exception:
        return False
    try:
        ts = int(session.get(_VERIFY_TOKEN_TS_KEY) or 0)
    except Exception:
        ts = 0
    if not ts:
        return False
    return (_now() - ts) <= (_VERIFY_TTL_MIN * 60)


@admin_bp.before_request
def _before():
    _csrf_issue()


@admin_bp.get("/")
def index():
    if not _is_admin_session():
        return redirect(build_admin_login_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=_admin_default_next()), code=302)
    return redirect(_admin_default_next(), code=302)


@admin_bp.get("/login")
@admin_bp.get("/login/")
def login_get():
    nxt = _clean_next(request.args.get(ADMIN_NEXT_PARAM_DEFAULT), fallback=_admin_default_next())
    if _is_admin_session():
        return redirect(nxt, code=302)

    return make_response(
        render_template(
            "admin/login.html",
            next=nxt,
            csrf_token=_csrf_issue(),
            register_url=build_admin_register_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt),
        ),
        200,
    )


@admin_bp.post("/login")
@admin_bp.post("/login/")
def login_post():
    ok, retry = _rate_limit("login", window_sec=int(current_app.config.get("ADMIN_RL_WINDOW", 15) or 15), max_hits=int(current_app.config.get("ADMIN_RL_LOGIN_MAX", 10) or 10))
    nxt = _clean_next(request.form.get("next") or request.args.get("next"), fallback=_admin_default_next())

    if not ok:
        flash(f"Demasiados intentos. Probá en {retry}s.", "warning")
        r = redirect(build_admin_login_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt), code=302)
        try:
            r.headers["Retry-After"] = str(int(retry))
        except Exception:
            pass
        return r

    if not _csrf_ok_form():
        flash("CSRF inválido. Reintentá.", "danger")
        return redirect(build_admin_login_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt), code=302)

    email = _safe_str(request.form.get("email"), max_len=254).lower()
    password = _safe_str(request.form.get("password"), max_len=512)

    user = _find_admin_user(email)
    if not user or not _verify_password(user, password):
        time.sleep(0.18)
        flash("Credenciales incorrectas.", "danger")
        return redirect(build_admin_login_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt), code=302)

    if hasattr(user, "email_verified") and not bool(getattr(user, "email_verified", True)):
        flash("Verificá tu email para entrar al panel.", "warning")
        try:
            _start_admin_verify_flow(email)
        except Exception:
            pass
        return redirect(build_admin_login_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt), code=302)

    uid = int(getattr(user, "id", 0) or 0)
    if not uid:
        flash("No se pudo iniciar sesión. (ID inválido)", "danger")
        return redirect(build_admin_login_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt), code=302)

    _set_admin_session(uid, email)
    flash("Bienvenido al panel ✅", "success")
    return redirect(nxt, code=302)


@admin_bp.route("/logout", methods=["GET", "POST"])
def logout():
    if request.method == "POST" and not _csrf_ok_form():
        flash("CSRF inválido.", "danger")
        return redirect("/admin/login", code=302)

    keep = session.get(_CSRF_KEY)
    session.clear()
    if keep:
        session[_CSRF_KEY] = keep
    session.modified = True
    flash("Sesión cerrada.", "info")
    return redirect("/admin/login", code=302)


@admin_bp.get("/register")
@admin_bp.get("/register/")
def register_get():
    nxt = _clean_next(request.args.get("next"), fallback=_admin_default_next())
    allow = _admin_register_enabled()
    return make_response(
        render_template(
            "admin/register.html",
            next=nxt,
            csrf_token=_csrf_issue(),
            allow_register=allow,
            login_url=build_admin_login_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt),
        ),
        200,
    )


@admin_bp.post("/register")
@admin_bp.post("/register/")
def register_post():
    ok, retry = _rate_limit("register", window_sec=int(current_app.config.get("ADMIN_RL_WINDOW_REG", 25) or 25), max_hits=int(current_app.config.get("ADMIN_RL_REGISTER_MAX", 6) or 6))
    nxt = _clean_next(request.form.get("next") or request.args.get("next"), fallback=_admin_default_next())

    if not ok:
        flash(f"Demasiados intentos. Probá en {retry}s.", "warning")
        r = redirect(build_admin_register_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt), code=302)
        try:
            r.headers["Retry-After"] = str(int(retry))
        except Exception:
            pass
        return r

    if not _csrf_ok_form():
        flash("CSRF inválido. Reintentá.", "danger")
        return redirect(build_admin_register_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt), code=302)

    if not _admin_register_enabled():
        flash("Registro admin deshabilitado.", "warning")
        return redirect(build_admin_login_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt), code=302)

    invite = _safe_str(request.form.get("invite_code"), max_len=120)
    if not _invite_ok(invite):
        flash("Código de invitación inválido.", "danger")
        return redirect(build_admin_register_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt), code=302)

    email = _safe_str(request.form.get("email"), max_len=254).lower()
    password = _safe_str(request.form.get("password"), max_len=512)

    if not email or "@" not in email or "." not in email:
        flash("Email inválido.", "danger")
        return redirect(build_admin_register_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt), code=302)

    User = _get_user_model()
    if User is None:
        flash("Modelo User no disponible.", "danger")
        return redirect(build_admin_register_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt), code=302)

    try:
        existing = db.session.execute(select(User).where(func.lower(User.email) == email)).scalar_one_or_none()
        if existing:
            flash("Ese email ya existe.", "warning")
            return redirect(build_admin_login_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt), code=302)

        user = User(email=email)
        if hasattr(user, "is_admin"):
            setattr(user, "is_admin", True)
        if hasattr(user, "active"):
            setattr(user, "active", True)
        if hasattr(user, "email_verified"):
            setattr(user, "email_verified", False)
        if hasattr(user, "created_at") and getattr(user, "created_at", None) is None:
            setattr(user, "created_at", _utcnow())

        if not _set_password(user, password):
            flash("Contraseña inválida.", "danger")
            return redirect(build_admin_register_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt), code=302)

        db.session.add(user)
        db.session.commit()

    except SQLAlchemyError:
        try:
            db.session.rollback()
        except Exception:
            pass
        flash("Error DB. No se pudo crear el admin.", "danger")
        return redirect(build_admin_register_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt), code=302)

    try:
        _start_admin_verify_flow(email)
    except Exception:
        pass

    flash("Admin creado ✅ Revisá tu email para verificar.", "success")
    return redirect(build_admin_login_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt), code=302)


@admin_bp.get("/verify/<token>")
def verify(token: str):
    nxt = _clean_next(request.args.get("next"), fallback=_admin_default_next())

    if not _verify_token_ok(token):
        flash("Token inválido o vencido.", "danger")
        return redirect(build_admin_login_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt), code=302)

    email = _safe_str(request.args.get("email") or session.get("admin_email") or "", max_len=254).lower()
    if not email:
        flash("Email inválido.", "danger")
        return redirect(build_admin_login_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt), code=302)

    user = _find_admin_user(email)
    if not user:
        flash("Usuario no encontrado.", "danger")
        return redirect(build_admin_login_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt), code=302)

    try:
        if hasattr(user, "email_verified"):
            setattr(user, "email_verified", True)
        db.session.add(user)
        db.session.commit()
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        flash("No se pudo verificar. Reintentá.", "danger")
        return redirect(build_admin_login_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt), code=302)

    session.pop(_VERIFY_TOKEN_KEY, None)
    session.pop(_VERIFY_TOKEN_TS_KEY, None)
    session.modified = True

    flash("Email verificado ✅ Ya podés entrar.", "success")
    return redirect(build_admin_login_url(next_param=ADMIN_NEXT_PARAM_DEFAULT, next_path=nxt), code=302)


__all__ = ["admin_bp"]
