# app/routes/auth_routes.py — Skyline Store (ULTRA PRO++++ / NO-404 / CSRF-SAFE / EMAIL-VERIFY / v7.1 BULLETPROOF)
from __future__ import annotations

import logging
import os
import re
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set, Tuple
from urllib.parse import urlencode, urlparse, urlunparse

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
from werkzeug.exceptions import BadRequest
from werkzeug.routing import BuildError

from app.models import User, db

# Flask-Login (opcional) — conecta con todo si lo tenés habilitado
try:
    from flask_login import login_user as _login_user, logout_user as _logout_user  # type: ignore
except Exception:  # pragma: no cover
    _login_user = None  # type: ignore
    _logout_user = None  # type: ignore

# Afiliados (opcional)
try:
    from app.models import AffiliateProfile  # type: ignore
except Exception:  # pragma: no cover
    AffiliateProfile = None  # type: ignore

# Mailer (SMTP robusto). Si no existe, no rompe.
try:
    from app.utils.mailer import send_email  # type: ignore
except Exception:  # pragma: no cover
    send_email = None  # type: ignore

log = logging.getLogger("auth_routes")

auth_bp = Blueprint(
    "auth",
    __name__,
    url_prefix="/auth",
    template_folder="../templates",
)

# ─────────────────────────────────────────────────────────────
# Constants / Regex
# ─────────────────────────────────────────────────────────────
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
# Config (tunable)
# ─────────────────────────────────────────────────────────────
AUTH_RATE_LIMIT_SECONDS = _env_float("AUTH_RATE_LIMIT_SECONDS", 1.6, min_v=0.2, max_v=30.0)
AUTH_RATE_LIMIT_BURST = _env_int("AUTH_RATE_LIMIT_BURST", 7, min_v=2, max_v=50)
AUTH_RATE_LIMIT_WINDOW = _env_int("AUTH_RATE_LIMIT_WINDOW", 60, min_v=10, max_v=600)

CANONICAL_HOST_ENFORCE = _env_flag("CANONICAL_HOST_ENFORCE", True)
AUTO_LOGIN_AFTER_REGISTER = _env_flag("AUTO_LOGIN_AFTER_REGISTER", True)

VERIFY_EMAIL_ENABLED = _env_flag("VERIFY_EMAIL_ENABLED", True)
VERIFY_EMAIL_BLOCK_ADMIN = _env_flag("VERIFY_EMAIL_BLOCK_ADMIN", False)
VERIFY_EMAIL_COOLDOWN_SEC = _env_float("VERIFY_EMAIL_COOLDOWN_SEC", 30.0, min_v=5.0, max_v=3600.0)

# Diseño/UX (5 mejoras) — mensajes / rutas
AUTH_BRAND_NAME = _env_str("APP_NAME", "") or "Skyline Store"
AUTH_SUPPORT_EMAIL = _env_str("SUPPORT_EMAIL", "")  # opcional, sólo para UX en mensajes
AUTH_SUCCESS_FLASH = _env_flag("AUTH_SUCCESS_FLASH", True)  # si querés apagar flashes “success”
AUTH_NO_CACHE_GET = _env_flag("AUTH_NO_CACHE_GET", True)  # headers anti-cache en GET

# Seguridad extra
AUTH_SESSION_ROTATE = _env_flag("AUTH_SESSION_ROTATE", True)  # “rotate” session keys owned
AUTH_LOGIN_AUDIT = _env_flag("AUTH_LOGIN_AUDIT", True)  # toca touch_login si existe

# ─────────────────────────────────────────────────────────────
# Session keys owned (NO tocar csrf/session interna)
# ─────────────────────────────────────────────────────────────
_SESSION_KEYS_OWNED: Tuple[str, ...] = (
    "user_id",
    "user_email",
    "user_role",
    "is_admin",
    "login_at",
    "login_nonce",
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
    """
    Fuerza host/scheme según APP_URL sólo en GET/HEAD y en prod.
    Mantiene path + query actuales.
    """
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


def _rl_key(prefix: str, extra: str = "") -> str:
    extra = (extra or "").strip().lower()[:64]
    return f"rl:{prefix}:{_client_ip()}:{extra}"


def _rate_limit_ok(prefix: str, cooldown_sec: float, *, extra: str = "") -> bool:
    """
    Rate limit simple (session):
    - cooldown mínimo entre requests
    - burst limit dentro de una ventana
    """
    now = time.time()

    k_cd = _rl_key(prefix, extra=extra) + ":cd"
    last = session.get(k_cd, 0)
    try:
        last_f = float(last)
    except Exception:
        last_f = 0.0
    if (now - last_f) < float(cooldown_sec):
        return False
    session[k_cd] = now

    k_b = _rl_key(prefix, extra=extra) + ":b"
    bucket = session.get(k_b)
    if not isinstance(bucket, dict):
        bucket = {"t0": now, "n": 0}

    try:
        t0 = float(bucket.get("t0", now))
        n = int(bucket.get("n", 0))
    except Exception:
        t0, n = now, 0

    if (now - t0) > float(AUTH_RATE_LIMIT_WINDOW):
        t0, n = now, 0

    n += 1
    bucket["t0"] = t0
    bucket["n"] = n
    session[k_b] = bucket

    session.modified = True
    return n <= int(AUTH_RATE_LIMIT_BURST)


def _safe_email(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""
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
    try:
        from flask_wtf.csrf import generate_csrf  # type: ignore
        return str(generate_csrf() or "")
    except Exception:
        return ""


def _clear_auth_session_only() -> None:
    for k in _SESSION_KEYS_OWNED:
        session.pop(k, None)
    session.modified = True


def _set_session_user(user: User) -> None:
    # Mejora extra: rotate keys owned (reduce estados raros)
    if AUTH_SESSION_ROTATE:
        _clear_auth_session_only()

    try:
        session["user_id"] = int(getattr(user, "id"))
    except Exception:
        session["user_id"] = None

    session["user_email"] = (getattr(user, "email", "") or "").lower().strip()
    session["login_at"] = int(time.time())
    session["login_nonce"] = secrets.token_urlsafe(16)

    try:
        role = getattr(user, "role", None)
        if role is not None:
            session["user_role"] = str(role)
    except Exception:
        pass

    try:
        if hasattr(user, "is_admin"):
            session["is_admin"] = bool(getattr(user, "is_admin"))
    except Exception:
        pass

    session.permanent = True
    session.modified = True

    # Flask-Login (si existe)
    try:
        if _login_user is not None:
            _login_user(user)  # type: ignore[misc]
    except Exception:
        log.exception("flask_login.login_user failed (ignored).")


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
        return db.session.execute(select(User).where(func.lower(User.email) == email)).scalar_one_or_none()
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


def _flash_safe(msg: str, cat: str) -> None:
    # Mejora diseño: controlar flashes success
    if cat == "success" and not AUTH_SUCCESS_FLASH:
        return
    try:
        flash(msg, cat)
    except Exception:
        pass


def _json_or_html(
    message: str,
    category: str,
    *,
    tab: str,
    next_url: str,
    success_redirect: Optional[str] = None,
    status_ok: int = 200,
    status_err: int = 400,
):
    if _wants_json():
        ok = category not in {"error", "warning"}
        status = status_ok if ok else status_err
        payload: Dict[str, Any] = {"ok": ok, "message": message, "category": category}
        if success_redirect:
            payload["redirect"] = success_redirect
        return jsonify(payload), status

    _flash_safe(message, category)

    if success_redirect:
        return redirect(success_redirect)

    back = _safe_url_for("auth.account", tab=tab, next=next_url)
    return redirect(back or "/auth/account")


def _redirect_account_tab(tab: str, nxt: str) -> Any:
    tab = (tab or "login").strip().lower()
    if tab not in {"login", "register"}:
        tab = "login"
    if not _is_safe_next(nxt):
        nxt = _safe_url_for("shop.shop") or _safe_url_for("main.home") or "/"
    url = _safe_url_for("auth.account", tab=tab, next=nxt)
    if url:
        return redirect(url)
    qs = urlencode({"tab": tab, "next": nxt})
    return redirect(f"/auth/account?{qs}")


def _app_base_url() -> str:
    """
    Base URL confiable para armar links de email.
    Prioridad:
    1) APP_URL env/config
    2) request.host_url
    """
    app_url = (_env_str("APP_URL", "") or str(current_app.config.get("APP_URL") or "")).strip()
    if app_url:
        return app_url.rstrip("/")
    return (request.host_url or "").rstrip("/")


def _send_verification_email(user: User) -> bool:
    """
    Envía el link de verificación usando token DB (email_verify_token).
    No rompe si SMTP no está configurado.
    """
    if not VERIFY_EMAIL_ENABLED:
        return False

    # cooldown por sesión (evita spam)
    if not _rate_limit_ok("verify_send", float(VERIFY_EMAIL_COOLDOWN_SEC), extra=(getattr(user, "email", "") or "")):
        return False

    try:
        if getattr(user, "email_verified", False):
            return True
    except Exception:
        pass

    # token DB
    try:
        token = user.ensure_email_verify_token()  # type: ignore[attr-defined]
    except Exception:
        token = None

    if not token:
        return False

    # persist token si no estaba
    try:
        db.session.add(user)
        db.session.commit()
    except Exception:
        db.session.rollback()
        pass

    path = _safe_url_for("auth.verify_email", token=token) or f"/auth/verify-email/{token}"
    link = _app_base_url() + path

    subject = f"Verificá tu email — {AUTH_BRAND_NAME}"
    support = f"<br><small style='color:#6b7280'>Soporte: {AUTH_SUPPORT_EMAIL}</small>" if AUTH_SUPPORT_EMAIL else ""

    html = f"""
    <div style="font-family:Arial,sans-serif;line-height:1.55">
      <h2 style="margin:0 0 10px">Confirmá tu email</h2>
      <p style="margin:0 0 10px">Gracias por registrarte en <b>{AUTH_BRAND_NAME}</b>.</p>
      <p style="margin:0 0 14px">Para verificar tu cuenta, hacé click:</p>
      <p style="margin:0 0 14px">
        <a href="{link}" style="display:inline-block;padding:12px 16px;border-radius:12px;background:#2563eb;color:#fff;text-decoration:none">
          Verificar email
        </a>
      </p>
      <p style="margin:0;color:#6b7280">Si no fuiste vos, ignorá este email.{support}</p>
      <p style="margin:12px 0 0;color:#9ca3af;font-size:12px">Link: {link}</p>
    </div>
    """.strip()

    text = f"Verificá tu email: {link}"

    if send_email is None:
        log.warning("send_email no disponible: no se envió verificación.")
        return False

    try:
        return bool(send_email(str(getattr(user, "email", "")), subject, html, text=text))
    except Exception:
        log.exception("send_email failed")
        return False


def _login_warning_if_unverified(user: User) -> None:
    if not VERIFY_EMAIL_ENABLED:
        return
    try:
        if getattr(user, "email_verified", False):
            return
    except Exception:
        return

    # UX pro: mensaje más claro
    msg = "Tu email aún no está verificado. Te enviamos un link para confirmarlo."
    try:
        if hasattr(user, "masked_email"):
            msg = f"Tu email ({getattr(user, 'masked_email')}) aún no está verificado. Te enviamos un link para confirmarlo."
    except Exception:
        pass

    _flash_safe(msg, "warning")

    # intentar enviar (no bloquea)
    try:
        _send_verification_email(user)
    except Exception:
        pass


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
    # Mejora extra: no cache GET auth (evita forms viejos / back button raro)
    if request.method == "GET" and AUTH_NO_CACHE_GET:
        resp.headers.setdefault("Cache-Control", "no-store")
        resp.headers.setdefault("Pragma", "no-cache")
        resp.headers.setdefault("Vary", "Cookie")

    # Seguridad headers
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    return resp


# ─────────────────────────────────────────────────────────────
# Legacy routes: nunca más 404
# ─────────────────────────────────────────────────────────────
@auth_bp.get("/login")
def legacy_login_get():
    nxt = _next_url(_safe_url_for("shop.shop") or _safe_url_for("main.home") or "/")
    return _redirect_account_tab("login", nxt)


@auth_bp.get("/register")
def legacy_register_get():
    nxt = _next_url(_safe_url_for("shop.shop") or _safe_url_for("main.home") or "/")
    return _redirect_account_tab("register", nxt)


# ─────────────────────────────────────────────────────────────
# Account (tabs) — SINGLE UI
# ─────────────────────────────────────────────────────────────
@auth_bp.get("/account")
def account():
    u = _get_current_user()
    default_next = _safe_url_for("shop.shop") or _safe_url_for("main.home") or "/"
    nxt = _next_url(default_next)

    # ya logueado -> al destino
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
# Verify email
# ─────────────────────────────────────────────────────────────
@auth_bp.get("/verify-email/<token>")
def verify_email(token: str):
    token = (token or "").strip()
    if not token or len(token) < 32:
        return _json_or_html("Link inválido.", "error", tab="login", next_url=_safe_url_for("shop.shop") or "/")

    try:
        user = db.session.execute(select(User).where(User.email_verify_token == token)).scalar_one_or_none()
    except Exception:
        user = None

    if not user:
        return _json_or_html(
            "El link expiró o ya fue usado.",
            "warning",
            tab="login",
            next_url=_safe_url_for("shop.shop") or "/",
        )

    try:
        # Mejora: tolera método verify_email o flags directos
        if hasattr(user, "verify_email") and callable(getattr(user, "verify_email")):
            user.verify_email()  # type: ignore[attr-defined]
        else:
            if hasattr(user, "email_verified"):
                setattr(user, "email_verified", True)
            if hasattr(user, "email_verify_token"):
                setattr(user, "email_verify_token", None)
        db.session.add(user)
        if not _commit_safe():
            return _json_or_html("No se pudo verificar. Probá de nuevo.", "error", tab="login", next_url=_safe_url_for("shop.shop") or "/")
    except Exception:
        db.session.rollback()
        log.exception("verify_email failed")
        return _json_or_html("No se pudo verificar. Probá de nuevo.", "error", tab="login", next_url=_safe_url_for("shop.shop") or "/")

    success = _safe_url_for("admin.dashboard") or _safe_url_for("shop.shop") or "/"
    return _json_or_html("Email verificado ✅", "success", tab="login", next_url=success, success_redirect=success)


# ─────────────────────────────────────────────────────────────
# Resend verification (anti-enumeración)
# ─────────────────────────────────────────────────────────────
@auth_bp.post("/resend-verification")
def resend_verification():
    default_next = _safe_url_for("shop.shop") or _safe_url_for("main.home") or "/"
    nxt = _next_url(default_next)

    if not _rate_limit_ok("resend_verif", max(2.0, AUTH_RATE_LIMIT_SECONDS), extra=""):
        return _json_or_html("Esperá un momento y reintentá.", "warning", tab="login", next_url=nxt)

    data = _safe_get_json()
    email = _safe_email((request.form.get("email") or "") or str(data.get("email") or ""))

    neutral = "Si el email está registrado, te enviamos un link de verificación."

    if not _valid_email(email):
        return _json_or_html(neutral, "info", tab="login", next_url=nxt)

    user = _get_user_by_email(email)
    if user:
        try:
            if getattr(user, "email_verified", False):
                return _json_or_html("Tu email ya está verificado ✅", "success", tab="login", next_url=nxt)
        except Exception:
            pass
        try:
            _send_verification_email(user)
        except Exception:
            pass

    return _json_or_html(neutral, "info", tab="login", next_url=nxt)


# ─────────────────────────────────────────────────────────────
# Login
# ─────────────────────────────────────────────────────────────
@auth_bp.post("/login")
def login():
    default_next = _safe_url_for("shop.shop") or _safe_url_for("main.home") or "/"
    nxt = _next_url(default_next)

    # honeypot (anti-bots)
    if (request.form.get("website") or "").strip():
        return _json_or_html("Solicitud inválida.", "error", tab="login", next_url=nxt)

    data = _safe_get_json()
    email = _safe_email((request.form.get("email") or "") or str(data.get("email") or ""))
    password = ((request.form.get("password") or "") or str(data.get("password") or "")).strip()

    if not _rate_limit_ok("login", AUTH_RATE_LIMIT_SECONDS, extra=email or "noemail"):
        return _json_or_html("Demasiados intentos. Esperá un momento y reintentá.", "warning", tab="login", next_url=nxt)

    if not _valid_email(email) or not password:
        return _json_or_html("Email o contraseña incorrectos.", "error", tab="login", next_url=nxt)

    user = _get_user_by_email(email)
    if not user or not _check_password(user, password):
        return _json_or_html("Email o contraseña incorrectos.", "error", tab="login", next_url=nxt)

    # is_active
    try:
        if hasattr(user, "is_active") and not bool(getattr(user, "is_active")):
            return _json_or_html("Tu cuenta está desactivada.", "error", tab="login", next_url=nxt)
    except Exception:
        pass

    # bloquear admin sin verificación si querés
    if VERIFY_EMAIL_ENABLED and VERIFY_EMAIL_BLOCK_ADMIN:
        try:
            if bool(getattr(user, "is_admin", False)) and not bool(getattr(user, "email_verified", False)):
                return _json_or_html("Verificá tu email para acceder al panel admin.", "warning", tab="login", next_url=nxt)
        except Exception:
            pass

    # set session
    _set_session_user(user)

    # audit opcional (si existe)
    if AUTH_LOGIN_AUDIT:
        try:
            if hasattr(user, "touch_login"):
                user.touch_login(ip=_client_ip())  # type: ignore[attr-defined]
                db.session.add(user)
                db.session.commit()
        except Exception:
            db.session.rollback()

    # UX: aviso si no verificado + enviar link
    try:
        _login_warning_if_unverified(user)
    except Exception:
        pass

    success_redir = nxt if _is_safe_next(nxt) else default_next
    return _json_or_html("Bienvenido 👋", "success", tab="login", next_url=nxt, success_redirect=success_redir)


# ─────────────────────────────────────────────────────────────
# Register
# ─────────────────────────────────────────────────────────────
@auth_bp.post("/register")
def register():
    default_next = _safe_url_for("shop.shop") or _safe_url_for("main.home") or "/"
    nxt = _next_url(default_next)

    # honeypot
    if (request.form.get("website") or "").strip():
        return _json_or_html("Solicitud inválida.", "error", tab="register", next_url=nxt)

    data = _safe_get_json()
    email = _safe_email((request.form.get("email") or "") or str(data.get("email") or ""))
    password = ((request.form.get("password") or "") or str(data.get("password") or "")).strip()
    password2 = ((request.form.get("password2") or "") or str(data.get("password2") or "")).strip()
    name = ((request.form.get("name") or "") or str(data.get("name") or "")).strip()

    if not _rate_limit_ok("register", AUTH_RATE_LIMIT_SECONDS, extra=email or "noemail"):
        return _json_or_html("Esperá un momento y reintentá.", "warning", tab="register", next_url=nxt)

    if not _valid_email(email):
        return _json_or_html("Email inválido.", "warning", tab="register", next_url=nxt)

    # Mejora extra: password mínimo configurable
    min_len = _env_int("MIN_PASSWORD_LEN", 8, min_v=6, max_v=128)
    if len(password) < min_len:
        return _json_or_html(f"La contraseña debe tener al menos {min_len} caracteres.", "warning", tab="register", next_url=nxt)

    if password2 and password2 != password:
        return _json_or_html("Las contraseñas no coinciden.", "warning", tab="register", next_url=nxt)

    # existe?
    if _get_user_by_email(email):
        return _json_or_html("Ese email ya está registrado. Iniciá sesión.", "info", tab="login", next_url=nxt)

    # crear user (compat)
    try:
        user = User(email=email)  # type: ignore[call-arg]
    except Exception:
        user = User()  # type: ignore[call-arg]
        try:
            setattr(user, "email", email)
        except Exception:
            return _json_or_html("No se pudo crear la cuenta.", "error", tab="register", next_url=nxt)

    if name:
        try:
            if hasattr(user, "name"):
                setattr(user, "name", name[:120])
        except Exception:
            pass

    if not _set_password(user, password):
        return _json_or_html("No se pudo crear la cuenta (password engine).", "error", tab="register", next_url=nxt)

    # defaults safe
    for attr, val in (("is_active", True), ("is_admin", False), ("email_verified", False)):
        try:
            if hasattr(user, attr):
                setattr(user, attr, val)
        except Exception:
            pass

    if VERIFY_EMAIL_ENABLED:
        try:
            user.ensure_email_verify_token()  # type: ignore[attr-defined]
        except Exception:
            pass

    # guardar + flush id
    try:
        db.session.add(user)
        db.session.flush()
    except Exception:
        db.session.rollback()
        return _json_or_html("Error creando la cuenta. Probá de nuevo.", "error", tab="register", next_url=nxt)

    # afiliado opcional
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
        return _json_or_html("Error guardando la cuenta. Probá de nuevo.", "error", tab="register", next_url=nxt)

    # enviar verificación (no bloquea)
    if VERIFY_EMAIL_ENABLED:
        try:
            _send_verification_email(user)
        except Exception:
            pass

    # auto login
    if AUTO_LOGIN_AFTER_REGISTER:
        _set_session_user(user)
        try:
            _login_warning_if_unverified(user)
        except Exception:
            pass
        success_redir = nxt if _is_safe_next(nxt) else default_next
        return _json_or_html("Cuenta creada con éxito ✅", "success", tab="register", next_url=nxt, success_redirect=success_redir)

    return _json_or_html("Cuenta creada ✅ Ahora iniciá sesión.", "success", tab="login", next_url=nxt)


# ─────────────────────────────────────────────────────────────
# Logout (GET + POST)
# ─────────────────────────────────────────────────────────────
@auth_bp.route("/logout", methods=["GET", "POST"])
def logout():
    _clear_auth_session_only()

    try:
        if _logout_user is not None:
            _logout_user()  # type: ignore[misc]
    except Exception:
        log.exception("flask_login.logout_user failed (ignored).")

    if _wants_json():
        return jsonify({"ok": True}), 200

    _flash_safe("Sesión cerrada.", "info")
    return redirect(_safe_url_for("main.home") or _safe_url_for("shop.shop") or "/")


__all__ = ["auth_bp"]
