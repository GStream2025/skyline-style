from __future__ import annotations

import logging
import os
import re
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set, Tuple
from urllib.parse import urlparse, urlunparse

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
    make_response,
)
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import select, func
from werkzeug.routing import BuildError

from app.models import User, db

# ─────────────────────────────────────────────────────────────
# Opcional: afiliados
# ─────────────────────────────────────────────────────────────
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
# ENV helpers (safe + bounded)
# ─────────────────────────────────────────────────────────────

def _env_str(name: str, default: str = "") -> str:
    v = os.getenv(name)
    return (default if v is None else str(v)).strip()


def _env_flag(name: str, default: bool = False) -> bool:
    v = _env_str(name, "")
    return v.lower() in _TRUE if v else default


def _env_int(name: str, default: int, *, min_v: int, max_v: int) -> int:
    try:
        n = int(_env_str(name, default))
    except Exception:
        n = default
    return max(min_v, min(max_v, n))


def _env_float(name: str, default: float, *, min_v: float, max_v: float) -> float:
    try:
        n = float(_env_str(name, default))
    except Exception:
        n = default
    return max(min_v, min(max_v, n))


# ─────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────

AUTH_RATE_LIMIT_SECONDS = _env_float("AUTH_RATE_LIMIT_SECONDS", 2.0, min_v=0.2, max_v=30.0)

VERIFY_EMAIL_REQUIRED = _env_flag("VERIFY_EMAIL_REQUIRED", True)
VERIFY_ADMIN_TOO = _env_flag("VERIFY_ADMIN_TOO", False)
VERIFY_TOKEN_MAX_AGE_SEC = _env_int(
    "VERIFY_TOKEN_MAX_AGE_SEC",
    60 * 60 * 24,
    min_v=60,
    max_v=60 * 60 * 24 * 14,
)
RESEND_VERIFY_COOLDOWN_SEC = _env_int(
    "RESEND_VERIFY_COOLDOWN_SEC",
    60,
    min_v=10,
    max_v=3600,
)

FORM_NONCE_TTL = _env_int("AUTH_FORM_NONCE_TTL", 20 * 60, min_v=30, max_v=3600)
CANONICAL_HOST_ENFORCE = _env_flag("CANONICAL_HOST_ENFORCE", True)

# Admin bootstrap (opcional)
BOOTSTRAP_ADMIN = _env_flag("BOOTSTRAP_ADMIN", True)
ADMIN_EMAIL = _env_str("ADMIN_EMAIL", "")
ADMIN_PASSWORD = _env_str("ADMIN_PASSWORD", "")
ADMIN_NAME = _env_str("ADMIN_NAME", "Admin")

# ─────────────────────────────────────────────────────────────
# Utils generales
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


def _wants_json() -> bool:
    if request.is_json:
        return True
    if (request.headers.get("Accept") or "").lower().find("application/json") >= 0:
        return True
    if (request.headers.get("X-Requested-With") or "").lower() == "xmlhttprequest":
        return True
    return False


def _safe_get_json() -> Dict[str, Any]:
    try:
        if request.is_json:
            d = request.get_json(silent=True)
            return d if isinstance(d, dict) else {}
    except Exception:
        pass
    return {}


def _json_or_redirect(message: str, category: str, endpoint: str, **kwargs):
    if _wants_json():
        ok = category not in {"error", "warning"}
        status = 200 if ok else 400
        payload: Dict[str, Any] = {
            "ok": ok,
            "message": message,
            "category": category,
        }
        red = kwargs.pop("_redirect", None)
        if red:
            payload["redirect"] = red
        return jsonify(payload), status

    flash(message, category)
    return redirect(_safe_url_for(endpoint, **kwargs) or "/")


def _is_safe_next(nxt: str) -> bool:
    if not nxt or not nxt.startswith("/") or nxt.startswith("//"):
        return False
    p = urlparse(nxt)
    return p.scheme == "" and p.netloc == ""


def _next_url(default: str) -> str:
    nxt = (request.args.get("next") or request.form.get("next") or "").strip()
    return nxt if _is_safe_next(nxt) else default


def _client_ip() -> str:
    return (
        (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        or (request.headers.get("X-Real-IP") or "").strip()
        or (request.remote_addr or "0.0.0.0")
    )[:64]


def _safe_email(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""
    try:
        if hasattr(User, "normalize_email"):
            return str(User.normalize_email(raw))  # type: ignore
    except Exception:
        pass
    return raw.lower()


def _valid_email(email: str) -> bool:
    return bool(email) and len(email) <= 254 and EMAIL_RE.match(email)


def _commit_safe() -> bool:
    try:
        db.session.commit()
        return True
    except Exception:
        db.session.rollback()
        log.exception("DB commit failed")
        return False


# ─────────────────────────────────────────────────────────────
# CSRF token helper (para templates)
# ─────────────────────────────────────────────────────────────

def _csrf_token_value() -> str:
    try:
        from flask_wtf.csrf import generate_csrf
        return generate_csrf()
    except Exception:
        return ""


# ─────────────────────────────────────────────────────────────
# Canonical host (anti split cookies)
# ─────────────────────────────────────────────────────────────

def _is_production() -> bool:
    try:
        if current_app.debug:
            return False
    except Exception:
        pass
    env = (current_app.config.get("ENV") or "production").lower()
    return env == "production"


def _canonical_redirect_if_needed():
    if not CANONICAL_HOST_ENFORCE or not _is_production():
        return None

    app_url = _env_str("APP_URL", "") or str(current_app.config.get("APP_URL") or "")
    if not app_url:
        return None

    try:
        target = urlparse(app_url)
        cur = urlparse(request.url)
        if target.scheme and target.netloc and (
            cur.scheme != target.scheme or cur.netloc != target.netloc
        ):
            if request.method in {"GET", "HEAD"}:
                return redirect(
                    urlunparse(cur._replace(scheme=target.scheme, netloc=target.netloc)),
                    code=301,
                )
    except Exception:
        pass
    return None


@auth_bp.before_request
def _before_auth():
    return _canonical_redirect_if_needed()


@auth_bp.after_request
def _after_auth(resp):
    if request.method == "GET":
        resp.headers.setdefault("Cache-Control", "no-store")
        resp.headers.setdefault("Pragma", "no-cache")
        resp.headers.setdefault("Vary", "Cookie")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return resp


# ─────────────────────────────────────────────────────────────
# Account (tabs)
# ─────────────────────────────────────────────────────────────

@auth_bp.get("/account")
def account():
    user_id = session.get("user_id")
    if user_id:
        for ep in ("main.home", "shop.shop"):
            u = _safe_url_for(ep)
            if u:
                return redirect(u)

    default_next = _safe_url_for("shop.shop") or "/"
    nxt = _next_url(default_next)

    tab = (request.args.get("tab") or "login").lower()
    if tab not in {"login", "register"}:
        tab = "login"

    return render_template(
        "auth/account.html",
        active_tab=tab,
        next=nxt,
        csrf_token_value=_csrf_token_value(),
    )


# ─────────────────────────────────────────────────────────────
# Login
# ─────────────────────────────────────────────────────────────

@auth_bp.post("/login")
def login():
    default_next = _safe_url_for("shop.shop") or "/"
    nxt = _next_url(default_next)

    if (request.form.get("website") or "").strip():
        return _json_or_redirect("Solicitud inválida.", "error", "auth.account", tab="login")

    email = _safe_email(request.form.get("email", ""))
    password = (request.form.get("password") or "").strip()

    if not _valid_email(email) or not password:
        return _json_or_redirect("Email o contraseña incorrectos.", "error", "auth.account", tab="login")

    user = db.session.execute(
        select(User).where(func.lower(User.email) == email)
    ).scalar_one_or_none()

    if not user or not getattr(user, "check_password", lambda _: False)(password):
        return _json_or_redirect("Email o contraseña incorrectos.", "error", "auth.account", tab="login")

    session.clear()
    session["user_id"] = int(user.id)
    session.permanent = True

    return _json_or_redirect("Bienvenido 👋", "success", "shop.shop", _redirect=nxt)


# ─────────────────────────────────────────────────────────────
# Register
# ─────────────────────────────────────────────────────────────

@auth_bp.post("/register")
def register():
    default_next = _safe_url_for("shop.shop") or "/"
    nxt = _next_url(default_next)

    if (request.form.get("website") or "").strip():
        return _json_or_redirect("Solicitud inválida.", "error", "auth.account", tab="register")

    email = _safe_email(request.form.get("email", ""))
    password = (request.form.get("password") or "").strip()
    password2 = (request.form.get("password2") or "").strip()
    name = (request.form.get("name") or "").strip()

    if not _valid_email(email):
        return _json_or_redirect("Email inválido.", "warning", "auth.account", tab="register")

    if len(password) < 8 or (password2 and password != password2):
        return _json_or_redirect("Contraseña inválida.", "warning", "auth.account", tab="register")

    if db.session.execute(
        select(User).where(func.lower(User.email) == email)
    ).scalar_one_or_none():
        return _json_or_redirect("Ese email ya existe. Iniciá sesión.", "info", "auth.account", tab="login")

    user = User(email=email)  # type: ignore
    if hasattr(user, "set_password"):
        user.set_password(password)  # type: ignore

    if hasattr(user, "name") and name:
        user.name = name  # type: ignore

    db.session.add(user)
    if not _commit_safe():
        return _json_or_redirect("Error creando la cuenta.", "error", "auth.account", tab="register")

    return _json_or_redirect("Cuenta creada con éxito ✅", "success", "shop.shop", _redirect=nxt)


# ─────────────────────────────────────────────────────────────
# Logout
# ─────────────────────────────────────────────────────────────

@auth_bp.get("/logout")
def logout():
    session.clear()
    if _wants_json():
        return jsonify({"ok": True}), 200
    flash("Sesión cerrada.", "info")
    return redirect(_safe_url_for("main.home") or "/")


__all__ = ["auth_bp"]
