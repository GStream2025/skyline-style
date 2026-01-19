# app/routes/auth_routes.py — Skyline Store (ULTRA PRO / NO-404 / CSRF-SAFE / v6.0)
from __future__ import annotations

import logging
import os
import re
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set
from urllib.parse import urlparse, urlunparse

from flask import (
    Blueprint,
    current_app,
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
from werkzeug.routing import BuildError

from app.models import User, db

# Afiliados (opcional)
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

# ─────────────────────────────────────────────────────────────
# ENV helpers
# ─────────────────────────────────────────────────────────────
def _env_str(name: str, default: str = "") -> str:
    v = os.getenv(name)
    return (default if v is None else str(v)).strip()


def _env_flag(name: str, default: bool = False) -> bool:
    v = _env_str(name, "")
    return (v.lower() in _TRUE) if v else default


def _env_int(name: str, default: int, *, min_v: int, max_v: int) -> int:
    s = _env_str(name, "")
    try:
        n = int(s) if s else int(default)
    except Exception:
        n = int(default)
    return max(min_v, min(max_v, n))


def _env_float(name: str, default: float, *, min_v: float, max_v: float) -> float:
    s = _env_str(name, "")
    try:
        n = float(s) if s else float(default)
    except Exception:
        n = float(default)
    return max(min_v, min(max_v, n))


# ─────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────
AUTH_RATE_LIMIT_SECONDS = _env_float("AUTH_RATE_LIMIT_SECONDS", 1.8, min_v=0.2, max_v=30.0)
CANONICAL_HOST_ENFORCE = _env_flag("CANONICAL_HOST_ENFORCE", True)

# Si querés “auto login” luego de register:
AUTO_LOGIN_AFTER_REGISTER = _env_flag("AUTO_LOGIN_AFTER_REGISTER", True)

# ─────────────────────────────────────────────────────────────
# Session keys owned (NO borrar csrf/session interna)
# ─────────────────────────────────────────────────────────────
_SESSION_KEYS_OWNED = (
    "user_id",
    "user_email",
    "user_role",
    "is_admin",
    "login_at",
)

# ─────────────────────────────────────────────────────────────
# Utils
# ─────────────────────────────────────────────────────────────
def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _safe_url_for(endpoint: str, **kwargs) -> Optional[str]:
    try:
        return url_for(endpoint, **kwargs)
    except BuildError:
        return None
    except Exception:
        return None


def _is_production() -> bool:
    try:
        if bool(current_app.debug) or bool(current_app.config.get("DEBUG")):
            return False
    except Exception:
        pass
    env = (current_app.config.get("ENV") or _env_str("ENV", "production")).lower().strip()
    return (env or "production") == "production"


def _canonical_redirect_if_needed():
    if not CANONICAL_HOST_ENFORCE or not _is_production():
        return None

    app_url = (_env_str("APP_URL", "") or str(current_app.config.get("APP_URL") or "")).strip()
    if not app_url:
        return None

    try:
        target = urlparse(app_url)
        cur = urlparse(request.url)
        if not target.scheme or not target.netloc:
            return None
        if cur.scheme == target.scheme and cur.netloc == target.netloc:
            return None
        if request.method not in {"GET", "HEAD"}:
            return None
        new = cur._replace(scheme=target.scheme, netloc=target.netloc)
        return redirect(urlunparse(new), code=301)
    except Exception:
        return None


def _wants_json() -> bool:
    if request.is_json:
        return True
    accept = (request.headers.get("Accept") or "").lower()
    if "application/json" in accept:
        return True
    if (request.headers.get("X-Requested-With") or "").lower() == "xmlhttprequest":
        return True
    if (request.args.get("format") or "").lower().strip() == "json":
        return True
    if (request.args.get("json") or "").lower().strip() in _TRUE:
        return True
    return False


def _safe_get_json() -> Dict[str, Any]:
    try:
        if request.is_json:
            d = request.get_json(silent=True) or {}
            return d if isinstance(d, dict) else {}
    except Exception:
        pass
    return {}


def _client_ip() -> str:
    xf = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    if xf:
        return xf[:64]
    xr = (request.headers.get("X-Real-IP") or "").strip()
    if xr:
        return xr[:64]
    return (request.remote_addr or "0.0.0.0")[:64]


def _rl_key(prefix: str) -> str:
    return f"rl:{prefix}:{_client_ip()}"


def _rate_limit_ok(prefix: str, cooldown_sec: float) -> bool:
    key = _rl_key(prefix)
    now = time.time()
    last = session.get(key, 0)
    try:
        last_f = float(last)
    except Exception:
        last_f = 0.0

    if (now - last_f) < float(cooldown_sec):
        return False

    session[key] = now
    session.modified = True
    return True


def _safe_email(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""
    # si tu User trae normalize_email, úsalo
    try:
        if hasattr(User, "normalize_email"):
            return str(User.normalize_email(raw))  # type: ignore[attr-defined]
    except Exception:
        pass
    return raw.lower().strip()


def _valid_email(email: str) -> bool:
    if not email or len(email) > 254:
        return False
    return bool(EMAIL_RE.match(email))


def _is_safe_next(nxt: str) -> bool:
    if not nxt:
        return False
    nxt = nxt.strip()
    if not nxt.startswith("/") or nxt.startswith("//"):
        return False
    p = urlparse(nxt)
    return (p.scheme == "" and p.netloc == "")


def _next_url(default: str) -> str:
    nxt = (request.args.get("next") or request.form.get("next") or "").strip()
    return nxt if _is_safe_next(nxt) else default


def _commit_safe() -> bool:
    try:
        db.session.commit()
        return True
    except Exception:
        db.session.rollback()
        log.exception("DB commit failed")
        return False


def _csrf_token_value() -> str:
    """
    Para tu template account.html (meta + hidden input).
    Si no hay Flask-WTF, devuelve "" y no rompe.
    """
    try:
        from flask_wtf.csrf import generate_csrf  # type: ignore
        return generate_csrf()
    except Exception:
        return ""


def _clear_auth_session_only() -> None:
    """NO borra toda la sesión (evita romper CSRF)."""
    for k in _SESSION_KEYS_OWNED:
        session.pop(k, None)
    session.modified = True


def _set_session_user(user: User) -> None:
    _clear_auth_session_only()
    session["user_id"] = int(getattr(user, "id"))
    session["user_email"] = (getattr(user, "email", "") or "").lower().strip()
    session["login_at"] = int(time.time())
    session.permanent = True
    session.modified = True


def _get_current_user() -> Optional[User]:
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        uid_int = int(uid)
    except Exception:
        return None
    try:
        return db.session.get(User, uid_int)
    except Exception:
        return None


def _get_user_by_email(email: str) -> Optional[User]:
    email = (email or "").strip().lower()
    if not email:
        return None
    try:
        return db.session.execute(
            select(User).where(func.lower(User.email) == email)
        ).scalar_one_or_none()
    except Exception:
        return None


def _check_password(user: User, password: str) -> bool:
    try:
        fn = getattr(user, "check_password", None)
        if callable(fn):
            return bool(fn(password))
    except Exception:
        pass
    return False


def _set_password(user: User, password: str) -> bool:
    try:
        fn = getattr(user, "set_password", None)
        if callable(fn):
            fn(password)
            return True
    except Exception:
        pass
    return False


def _redirect_response(message: str, category: str, *, tab: str, next_url: str, success_redirect: Optional[str] = None):
    """
    - En HTML: flash + redirect
    - En JSON: payload con redirect si corresponde
    """
    if _wants_json():
        ok = category not in {"error", "warning"}
        status = 200 if ok else 400
        payload: Dict[str, Any] = {"ok": ok, "message": message, "category": category}
        if success_redirect:
            payload["redirect"] = success_redirect
        return jsonify(payload), status

    flash(message, category)
    if success_redirect:
        return redirect(success_redirect)

    # volver a account conservando tab y next
    return redirect(_safe_url_for("auth.account", tab=tab, next=next_url) or "/auth/account")


# ─────────────────────────────────────────────────────────────
# Hooks
# ─────────────────────────────────────────────────────────────
@auth_bp.before_request
def _before_auth():
    red = _canonical_redirect_if_needed()
    if red is not None:
        return red
    return None


@auth_bp.after_request
def _after_auth(resp):
    # cache-control para pantallas de auth
    if request.method == "GET":
        resp.headers.setdefault("Cache-Control", "no-store")
        resp.headers.setdefault("Pragma", "no-cache")
        resp.headers.setdefault("Vary", "Cookie")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return resp


# ─────────────────────────────────────────────────────────────
# Legacy routes: nunca más 404
# ─────────────────────────────────────────────────────────────
@auth_bp.get("/login")
def legacy_login_get():
    nxt = _next_url(_safe_url_for("shop.shop") or "/")
    return redirect(_safe_url_for("auth.account", tab="login", next=nxt) or f"/auth/account?tab=login&next={nxt}")


@auth_bp.get("/register")
def legacy_register_get():
    nxt = _next_url(_safe_url_for("shop.shop") or "/")
    return redirect(_safe_url_for("auth.account", tab="register", next=nxt) or f"/auth/account?tab=register&next={nxt}")


# ─────────────────────────────────────────────────────────────
# Account (tabs)
# ─────────────────────────────────────────────────────────────
@auth_bp.get("/account")
def account():
    # si ya está logueado, mandalo al next o a shop
    u = _get_current_user()
    default_next = _safe_url_for("shop.shop") or _safe_url_for("main.home") or "/"
    nxt = _next_url(default_next)

    if u:
        return redirect(nxt or default_next)

    tab = (request.args.get("tab") or "login").strip().lower()
    if tab not in {"login", "register"}:
        tab = "login"

    resp = make_response(
        render_template(
            "auth/account.html",
            active_tab=tab,
            next=nxt,
            csrf_token_value=_csrf_token_value(),
        ),
        200,
    )
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ─────────────────────────────────────────────────────────────
# Login
# ─────────────────────────────────────────────────────────────
@auth_bp.post("/login")
def login():
    default_next = _safe_url_for("shop.shop") or _safe_url_for("main.home") or "/"
    nxt = _next_url(default_next)

    # honeypot
    if (request.form.get("website") or "").strip():
        return _redirect_response("Solicitud inválida.", "error", tab="login", next_url=nxt)

    # rate limit
    if not _rate_limit_ok("login", AUTH_RATE_LIMIT_SECONDS):
        return _redirect_response("Demasiados intentos. Esperá un momento y reintentá.", "warning", tab="login", next_url=nxt)

    data = _safe_get_json()
    email = _safe_email((request.form.get("email") or "") or str(data.get("email") or ""))
    password = ((request.form.get("password") or "") or str(data.get("password") or "")).strip()

    if not _valid_email(email) or not password:
        return _redirect_response("Email o contraseña incorrectos.", "error", tab="login", next_url=nxt)

    user = _get_user_by_email(email)
    if not user or not _check_password(user, password):
        return _redirect_response("Email o contraseña incorrectos.", "error", tab="login", next_url=nxt)

    # is_active (si existe)
    try:
        if hasattr(user, "is_active") and not bool(getattr(user, "is_active")):
            return _redirect_response("Tu cuenta está desactivada.", "error", tab="login", next_url=nxt)
    except Exception:
        pass

    _set_session_user(user)

    # redirect final
    success_redir = nxt or default_next
    return _redirect_response("Bienvenido 👋", "success", tab="login", next_url=nxt, success_redirect=success_redir)


# ─────────────────────────────────────────────────────────────
# Register
# ─────────────────────────────────────────────────────────────
@auth_bp.post("/register")
def register():
    default_next = _safe_url_for("shop.shop") or _safe_url_for("main.home") or "/"
    nxt = _next_url(default_next)

    # honeypot
    if (request.form.get("website") or "").strip():
        return _redirect_response("Solicitud inválida.", "error", tab="register", next_url=nxt)

    # rate limit
    if not _rate_limit_ok("register", AUTH_RATE_LIMIT_SECONDS):
        return _redirect_response("Esperá un momento y reintentá.", "warning", tab="register", next_url=nxt)

    data = _safe_get_json()
    email = _safe_email((request.form.get("email") or "") or str(data.get("email") or ""))
    password = ((request.form.get("password") or "") or str(data.get("password") or "")).strip()
    password2 = ((request.form.get("password2") or "") or str(data.get("password2") or "")).strip()
    name = ((request.form.get("name") or "") or str(data.get("name") or "")).strip()

    if not _valid_email(email):
        return _redirect_response("Email inválido.", "warning", tab="register", next_url=nxt)

    if len(password) < 8:
        return _redirect_response("La contraseña debe tener al menos 8 caracteres.", "warning", tab="register", next_url=nxt)

    # si mandan confirmación, debe coincidir
    if password2 and password2 != password:
        return _redirect_response("Las contraseñas no coinciden.", "warning", tab="register", next_url=nxt)

    # ya existe?
    if _get_user_by_email(email):
        # llevamos a login tab
        return _redirect_response("Ese email ya está registrado. Iniciá sesión.", "info", tab="login", next_url=nxt)

    # crear user (compat con modelos distintos)
    try:
        user = User(email=email)  # type: ignore[call-arg]
    except Exception:
        user = User()  # type: ignore[call-arg]
        try:
            setattr(user, "email", email)
        except Exception:
            return _redirect_response("No se pudo crear la cuenta.", "error", tab="register", next_url=nxt)

    if name:
        try:
            if hasattr(user, "name"):
                setattr(user, "name", name)
        except Exception:
            pass

    if not _set_password(user, password):
        return _redirect_response("No se pudo crear la cuenta (password engine).", "error", tab="register", next_url=nxt)

    # defaults suaves
    for attr, val in (("is_active", True), ("is_admin", False)):
        try:
            if hasattr(user, attr):
                setattr(user, attr, val)
        except Exception:
            pass

    try:
        db.session.add(user)
        db.session.flush()  # asegura ID sin commit todavía
    except Exception:
        db.session.rollback()
        return _redirect_response("Error creando la cuenta. Probá de nuevo.", "error", tab="register", next_url=nxt)

    # afiliado opcional (si existe)
    try:
        want_affiliate = (request.form.get("want_affiliate") or "").strip().lower() in _TRUE
        if want_affiliate and AffiliateProfile is not None:
            prof = AffiliateProfile(  # type: ignore[call-arg]
                user_id=int(getattr(user, "id")),
                status="pending",
                display_name=(request.form.get("affiliate_display_name") or name or "").strip()[:120],
                instagram=(request.form.get("affiliate_instagram") or "").strip()[:120],
            )
            db.session.add(prof)
    except Exception:
        log.exception("AffiliateProfile creation failed (ignored).")

    if not _commit_safe():
        return _redirect_response("Error guardando la cuenta. Probá de nuevo.", "error", tab="register", next_url=nxt)

    # auto login (recomendado para UX)
    if AUTO_LOGIN_AFTER_REGISTER:
        _set_session_user(user)
        success_redir = nxt or default_next
        return _redirect_response("Cuenta creada con éxito ✅", "success", tab="register", next_url=nxt, success_redirect=success_redir)

    # si no auto-login, mandamos al login tab
    return _redirect_response("Cuenta creada ✅ Ahora iniciá sesión.", "success", tab="login", next_url=nxt)


# ─────────────────────────────────────────────────────────────
# Logout
# ─────────────────────────────────────────────────────────────
@auth_bp.get("/logout")
def logout():
    _clear_auth_session_only()
    if _wants_json():
        return jsonify({"ok": True}), 200
    flash("Sesión cerrada.", "info")
    return redirect(_safe_url_for("main.home") or _safe_url_for("shop.shop") or "/")


__all__ = ["auth_bp"]
