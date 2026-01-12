# app/routes/auth_routes.py — Skyline Store (ULTRA PRO / CSRF-SAFE / v4.1 FINAL)
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
from sqlalchemy import select
from werkzeug.routing import BuildError

from app.models import User, db

# Afiliados (opcional)
try:
    from app.models import AffiliateProfile  # type: ignore
except Exception:
    AffiliateProfile = None  # type: ignore

log = logging.getLogger("auth_routes")
auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

_TRUE: Set[str] = {"1", "true", "yes", "y", "on", "checked"}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# =============================================================================
# ENV helpers
# =============================================================================

def _env_str(name: str, default: str = "") -> str:
    v = os.getenv(name)
    return (default if v is None else str(v)).strip()


def _env_flag(name: str, default: bool = False) -> bool:
    v = _env_str(name, "")
    if not v:
        return default
    return v.lower() in _TRUE


def _env_int(name: str, default: int, *, min_v: int = 0, max_v: int = 10_000_000) -> int:
    s = _env_str(name, "")
    try:
        n = int(s) if s else int(default)
    except Exception:
        n = int(default)
    return max(min_v, min(max_v, n))


def _env_float(name: str, default: float, *, min_v: float = 0.0, max_v: float = 3600.0) -> float:
    s = _env_str(name, "")
    try:
        n = float(s) if s else float(default)
    except Exception:
        n = float(default)
    return max(min_v, min(max_v, n))


AUTH_RATE_LIMIT_SECONDS = _env_float("AUTH_RATE_LIMIT_SECONDS", 2.0, min_v=0.1, max_v=30.0)
VERIFY_EMAIL_REQUIRED = _env_flag("VERIFY_EMAIL_REQUIRED", True)
VERIFY_ADMIN_TOO = _env_flag("VERIFY_ADMIN_TOO", False)
VERIFY_TOKEN_MAX_AGE_SEC = _env_int("VERIFY_TOKEN_MAX_AGE_SEC", 60 * 60 * 24, min_v=60, max_v=60 * 60 * 24 * 14)
RESEND_VERIFY_COOLDOWN_SEC = _env_int("RESEND_VERIFY_COOLDOWN_SEC", 60, min_v=10, max_v=3600)

FORM_NONCE_TTL = _env_int("AUTH_FORM_NONCE_TTL", 20 * 60, min_v=30, max_v=60 * 60)
CANONICAL_HOST_ENFORCE = _env_flag("CANONICAL_HOST_ENFORCE", True)

# =============================================================================
# Helpers generales
# =============================================================================

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _safe_url_for(endpoint: str, **kwargs) -> Optional[str]:
    try:
        return url_for(endpoint, **kwargs)
    except BuildError:
        return None
    except Exception:
        return None


def _safe_get_json() -> Dict[str, Any]:
    try:
        if request.is_json:
            data = request.get_json(silent=True) or {}
            return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}


def _wants_json() -> bool:
    if (request.args.get("format") or "").strip().lower() == "json":
        return True
    if (request.args.get("json") or "").strip().lower() in _TRUE:
        return True
    if request.is_json:
        return True
    accept = (request.headers.get("Accept") or "").lower()
    if "application/json" in accept:
        return True
    if (request.headers.get("X-Requested-With") or "").lower() == "xmlhttprequest":
        return True
    return False


def _json_or_redirect(message: str, category: str, endpoint: str, **kwargs):
    if _wants_json():
        ok = category not in {"error", "warning"}
        status = 400 if not ok else 200
        payload: Dict[str, Any] = {"ok": ok, "message": message, "category": category}
        redir = kwargs.pop("_redirect", None)
        if redir:
            payload["redirect"] = redir
        return jsonify(payload), status

    flash(message, category)
    u = _safe_url_for(endpoint, **kwargs)
    return redirect(u or "/")


def _is_safe_next(nxt: str) -> bool:
    if not nxt:
        return False
    nxt = nxt.strip()
    if not nxt.startswith("/") or nxt.startswith("//"):
        return False
    p = urlparse(nxt)
    return (p.scheme == "" and p.netloc == "")


def _next_url(default_url: str) -> str:
    nxt = (request.args.get("next") or request.form.get("next") or "").strip()
    return nxt if _is_safe_next(nxt) else default_url


def _client_ip() -> str:
    xf = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    if xf:
        return xf[:64]
    xr = (request.headers.get("X-Real-IP") or "").strip()
    if xr:
        return xr[:64]
    return (request.remote_addr or "0.0.0.0")[:64]


def _commit_safe() -> bool:
    try:
        db.session.commit()
        return True
    except Exception:
        db.session.rollback()
        log.exception("DB commit failed")
        return False


def _safe_email(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""
    if hasattr(User, "normalize_email"):
        try:
            return str(User.normalize_email(raw))  # type: ignore[attr-defined]
        except Exception:
            pass
    return raw.lower().strip()


def _valid_email(email: str) -> bool:
    return bool(email) and len(email) <= 254 and bool(EMAIL_RE.match(email))


def _safe_str_field(name: str, max_len: int = 200) -> str:
    return (request.form.get(name) or "").strip()[:max_len]


def _read_bool_field(name: str) -> bool:
    v = (request.form.get(name) or "").strip().lower()
    return v in _TRUE


# =============================================================================
# Canonical host (anti cookie split)
# =============================================================================

def _is_production() -> bool:
    try:
        if bool(current_app.debug) or bool(current_app.config.get("DEBUG")):
            return False
    except Exception:
        pass
    env = (current_app.config.get("ENV") or current_app.config.get("ENVIRONMENT") or _env_str("ENV", "")).lower().strip()
    return (env or "production") == "production"


def _canonical_redirect_if_needed() -> Optional[Any]:
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

        # ya coincide
        if cur.netloc == target.netloc and cur.scheme == target.scheme:
            return None

        # SOLO GET/HEAD
        if request.method not in {"GET", "HEAD"}:
            return None

        new = cur._replace(scheme=target.scheme, netloc=target.netloc)
        return redirect(urlunparse(new), code=301)
    except Exception:
        return None


@auth_bp.before_request
def _before_auth():
    red = _canonical_redirect_if_needed()
    if red is not None:
        return red
    return None


@auth_bp.after_request
def _after_auth(resp):
    if request.path.startswith(("/auth/login", "/auth/register", "/auth/verify-notice")) and request.method == "GET":
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Vary"] = "Cookie"
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return resp


# =============================================================================
# Nonce anti replay/doble submit
# =============================================================================

def _new_form_nonce(key: str) -> str:
    tok = secrets.token_urlsafe(20)
    session[f"nonce:{key}"] = {"v": tok, "ts": int(time.time())}
    session.modified = True
    return tok


def _check_form_nonce(key: str) -> bool:
    raw = session.get(f"nonce:{key}") or {}
    if not isinstance(raw, dict):
        return False

    expected = str(raw.get("v") or "")
    ts = raw.get("ts") or 0
    try:
        ts = int(ts)
    except Exception:
        ts = 0

    got = (request.form.get("nonce") or "").strip()
    if not expected or not got:
        return False
    if not secrets.compare_digest(expected, got):
        return False
    if (int(time.time()) - ts) > FORM_NONCE_TTL:
        return False

    session.pop(f"nonce:{key}", None)
    session.modified = True
    return True


# =============================================================================
# Rate limit
# =============================================================================

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


def _rate_limit_email_ok(prefix: str, email: str, cooldown: int) -> Tuple[bool, int]:
    e = (email or "").strip().lower()
    if not e:
        return False, cooldown

    key = f"{_rl_key(prefix)}:{e}"
    now = time.time()
    last = session.get(key, 0)
    try:
        last_f = float(last)
    except Exception:
        last_f = 0.0

    left = int(max(0, float(cooldown) - (now - last_f)))
    if left > 0:
        return False, left

    session[key] = now
    session.modified = True
    return True, 0


# =============================================================================
# Session helpers (NO tocan CSRF interno)
# =============================================================================

_SESSION_KEYS_OWNED = (
    "user_id",
    "user_email",
    "is_admin",
    "login_at",
)


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


def _clear_auth_session_only() -> None:
    """✅ Limpia SOLO tus keys (no borra csrf/session interna)."""
    try:
        for k in _SESSION_KEYS_OWNED:
            session.pop(k, None)
    except Exception:
        pass
    session.modified = True


def _set_session_user(user: User) -> None:
    # Evita fixation sin romper CSRF: limpiamos solo nuestras keys
    _clear_auth_session_only()

    session["user_id"] = int(getattr(user, "id"))
    session["user_email"] = (getattr(user, "email", "") or "").lower()
    session["is_admin"] = bool(getattr(user, "is_admin", False))
    session["login_at"] = int(time.time())
    session.permanent = True
    session.modified = True


def _post_login_redirect(user: User) -> str:
    try:
        if bool(getattr(user, "is_admin", False)) or bool(getattr(user, "is_owner", False)):
            u = _safe_url_for("admin.dashboard")
            if u:
                return u
    except Exception:
        pass

    for ep in ("account.account_home", "shop.shop", "main.index", "main.home"):
        u = _safe_url_for(ep)
        if u:
            return u
    return "/"


# =============================================================================
# Email verification
# =============================================================================

def _serializer() -> URLSafeTimedSerializer:
    secret = (current_app.config.get("SECRET_KEY") or _env_str("SECRET_KEY", "")).strip()
    if not secret:
        secret = "dev-secret"
    return URLSafeTimedSerializer(secret_key=secret, salt="skyline-email-verify-v1")


def _user_is_verified(user: User) -> bool:
    if hasattr(user, "email_verified"):
        try:
            return bool(getattr(user, "email_verified"))
        except Exception:
            return False
    return True


def _set_user_verified(user: User) -> None:
    if hasattr(user, "verify_email"):
        try:
            user.verify_email()  # type: ignore[attr-defined]
            return
        except Exception:
            pass

    if hasattr(user, "email_verified"):
        try:
            setattr(user, "email_verified", True)
        except Exception:
            pass

    if hasattr(user, "email_verified_at"):
        try:
            setattr(user, "email_verified_at", _utcnow())
        except Exception:
            pass


def _make_verify_token(user: User) -> str:
    data = {"uid": int(getattr(user, "id")), "email": (getattr(user, "email", "") or "").lower(), "v": 1}
    return _serializer().dumps(data)


def _read_verify_token(token: str, max_age: int) -> Tuple[Optional[Dict[str, Any]], str]:
    try:
        data = _serializer().loads(token, max_age=max_age)
        if isinstance(data, dict) and "uid" in data and "email" in data:
            return data, ""
        return None, "invalid"
    except SignatureExpired:
        return None, "expired"
    except BadSignature:
        return None, "invalid"
    except Exception:
        return None, "invalid"


def _app_url() -> str:
    base = (_env_str("APP_URL", "") or str(current_app.config.get("APP_URL") or "")).strip()
    if base:
        return base.rstrip("/")
    try:
        return request.host_url.rstrip("/")
    except Exception:
        return "http://127.0.0.1:5000"


def _emails_enabled() -> bool:
    return _env_flag("ENABLE_EMAILS", False)


def _send_email_verify(user: User, *, force: bool = False) -> bool:
    if not _emails_enabled():
        return False

    if not force:
        ok_rl, _left = _rate_limit_email_ok("verify", getattr(user, "email", "") or "", RESEND_VERIFY_COOLDOWN_SEC)
        if not ok_rl:
            return False

    token = _make_verify_token(user)
    verify_path = _safe_url_for("auth.verify_email", token=token) or f"/auth/verify-email/{token}"
    verify_url = f"{_app_url()}{verify_path}"

    try:
        html = render_template(
            "emails/welcome_verify.html",
            name=getattr(user, "name", None),
            email=getattr(user, "email", ""),
            verify_url=verify_url,
            year=_utcnow().year,
        )
    except Exception:
        html = ""

    text = (
        "Confirmá tu cuenta en Skyline Store\n\n"
        f"Abrí este enlace para verificar tu email:\n{verify_url}\n\n"
        "Si no fuiste vos, ignorá este mensaje."
    )

    EmailService = None
    try:
        mod = __import__("app.services.email_service", fromlist=["EmailService"])
        EmailService = getattr(mod, "EmailService", None)
    except Exception:
        EmailService = None

    if not EmailService:
        log.warning("EmailService no encontrado. No se envía (no rompe).")
        return False

    try:
        svc = EmailService()
        if hasattr(svc, "send_html"):
            return bool(
                svc.send_html(
                    to_email=getattr(user, "email", ""),
                    subject="Confirmá tu cuenta · Skyline Store",
                    html=html,
                    text=text,
                )
            )
        if hasattr(svc, "send"):
            return bool(
                svc.send(
                    to=getattr(user, "email", ""),
                    subject="Confirmá tu cuenta · Skyline Store",
                    html=html,
                    text=text,
                )
            )
        log.warning("EmailService existe pero no tiene send_html/send.")
        return False
    except Exception:
        log.exception("Falló el envío de verificación.")
        return False


def _needs_verify_gate(user: User) -> bool:
    if not VERIFY_EMAIL_REQUIRED:
        return False
    is_admin = bool(getattr(user, "is_admin", False))
    is_owner = bool(getattr(user, "is_owner", False))
    if (is_admin or is_owner) and not VERIFY_ADMIN_TOO:
        return False
    return not _user_is_verified(user)


# =============================================================================
# DB helper
# =============================================================================

def _get_user_by_email(email: str) -> Optional[User]:
    try:
        return db.session.execute(select(User).where(User.email == email)).scalar_one_or_none()
    except Exception:
        return None


def _check_password(user: User, password: str) -> bool:
    try:
        fn = getattr(user, "check_password", None)
        return bool(callable(fn) and fn(password))
    except Exception:
        return False


# =============================================================================
# Routes
# =============================================================================

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    u = _get_current_user()
    if u:
        return redirect(_post_login_redirect(u))

    default_next = _safe_url_for("shop.shop") or _safe_url_for("main.index") or _safe_url_for("main.home") or "/"
    nxt = _next_url(default_next)

    if request.method == "GET":
        nonce = _new_form_nonce("login")
        resp = make_response(render_template("auth/login.html", next=nxt, nonce=nonce), 200)
        resp.headers["Cache-Control"] = "no-store"
        return resp

    # Honeypot
    if (request.form.get("website") or "").strip():
        return _json_or_redirect("Solicitud inválida.", "error", "auth.login", next=nxt)

    # Nonce (replay)
    if not _check_form_nonce("login"):
        flash("Solicitud inválida. Recargá e intentá de nuevo.", "error")
        return redirect(_safe_url_for("auth.login", next=nxt) or "/auth/login")

    if not _rate_limit_ok("login", AUTH_RATE_LIMIT_SECONDS):
        return _json_or_redirect("Demasiados intentos. Esperá un momento y reintentá.", "warning", "auth.login", next=nxt)

    data = _safe_get_json()
    email = _safe_email(_safe_str_field("email", 255) or str(data.get("email") or ""))
    password = (_safe_str_field("password", 256) or str(data.get("password") or "")).strip()
    nxt_safe = _next_url("")

    if not _valid_email(email) or not password:
        return _json_or_redirect("Email o contraseña incorrectos.", "error", "auth.login", next=nxt_safe)

    user = _get_user_by_email(email)
    if not user or not _check_password(user, password):
        return _json_or_redirect("Email o contraseña incorrectos.", "error", "auth.login", next=nxt_safe)

    try:
        if hasattr(user, "is_active") and not bool(getattr(user, "is_active")):
            return _json_or_redirect("Tu cuenta está desactivada.", "error", "auth.login", next=nxt_safe)
    except Exception:
        pass

    if _needs_verify_gate(user):
        _send_email_verify(user, force=False)
        red = _safe_url_for("auth.verify_notice", email=getattr(user, "email", "")) or "/auth/verify-notice"
        if _wants_json():
            return jsonify({"ok": False, "needs_verify": True, "redirect": red, "message": "Verificá tu email para continuar."}), 403
        flash("Verificá tu email para continuar.", "warning")
        return redirect(red)

    _set_session_user(user)
    redir = nxt_safe or _post_login_redirect(user)

    if _wants_json():
        return jsonify({"ok": True, "redirect": redir}), 200

    flash("Bienvenido 👋", "success")
    return redirect(redir)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    u = _get_current_user()
    if u:
        return redirect(_post_login_redirect(u))

    default_next = _safe_url_for("shop.shop") or _safe_url_for("main.index") or _safe_url_for("main.home") or "/"
    nxt = _next_url(default_next)

    if request.method == "GET":
        nonce = _new_form_nonce("register")
        resp = make_response(render_template("auth/register.html", next=nxt, nonce=nonce), 200)
        resp.headers["Cache-Control"] = "no-store"
        return resp

    if (request.form.get("website") or "").strip():
        return _json_or_redirect("Solicitud inválida.", "error", "auth.register", next=nxt)

    if not _check_form_nonce("register"):
        flash("Solicitud inválida. Recargá e intentá de nuevo.", "error")
        return redirect(_safe_url_for("auth.register", next=nxt) or "/auth/register")

    if not _rate_limit_ok("register", AUTH_RATE_LIMIT_SECONDS):
        return _json_or_redirect("Esperá un momento y reintentá.", "warning", "auth.register", next=nxt)

    data = _safe_get_json()
    email = _safe_email(_safe_str_field("email", 255) or str(data.get("email") or ""))
    password = (_safe_str_field("password", 256) or str(data.get("password") or "")).strip()
    password2 = (_safe_str_field("password2", 256) or str(data.get("password2") or "")).strip()
    name = (_safe_str_field("name", 120) or str(data.get("name") or "")).strip()
    nxt_safe = _next_url("")

    if not _valid_email(email):
        return _json_or_redirect("Email inválido.", "warning", "auth.register", next=nxt_safe)

    if len(password) < 8:
        return _json_or_redirect("La contraseña debe tener al menos 8 caracteres.", "warning", "auth.register", next=nxt_safe)

    if password2 and password2 != password:
        return _json_or_redirect("Las contraseñas no coinciden.", "warning", "auth.register", next=nxt_safe)

    if _get_user_by_email(email):
        return _json_or_redirect("Ese email ya está registrado. Iniciá sesión.", "info", "auth.login", next=nxt_safe)

    want_affiliate = _read_bool_field("want_affiliate") or (str(data.get("want_affiliate") or "").strip().lower() in _TRUE)

    try:
        user = User(email=email)  # type: ignore[call-arg]
    except Exception:
        user = User()  # type: ignore[call-arg]
        try:
            setattr(user, "email", email)
        except Exception:
            return _json_or_redirect("No se pudo asignar el email al usuario.", "error", "auth.register", next=nxt_safe)

    try:
        if hasattr(user, "name") and name:
            setattr(user, "name", name)
    except Exception:
        pass

    for attr, val in (("is_admin", False), ("is_active", True), ("email_verified", False)):
        try:
            if hasattr(user, attr):
                setattr(user, attr, val)
        except Exception:
            pass

    try:
        role = "affiliate" if want_affiliate else "customer"
        if hasattr(user, "set_role_safe") and callable(getattr(user, "set_role_safe")):
            user.set_role_safe(role)  # type: ignore[attr-defined]
        elif hasattr(user, "role"):
            setattr(user, "role", role)
    except Exception:
        pass

    try:
        if hasattr(user, "set_password") and callable(getattr(user, "set_password")):
            user.set_password(password)  # type: ignore[attr-defined]
        else:
            return _json_or_redirect("El modelo User no tiene set_password().", "error", "auth.register", next=nxt_safe)
    except Exception:
        return _json_or_redirect("No se pudo crear la cuenta (password inválida).", "error", "auth.register", next=nxt_safe)

    try:
        db.session.add(user)
        db.session.flush()
    except Exception:
        db.session.rollback()
        return _json_or_redirect("Error creando la cuenta. Probá de nuevo.", "error", "auth.register", next=nxt_safe)

    if want_affiliate and AffiliateProfile is not None:
        try:
            display_name = (_safe_str_field("affiliate_display_name", 120) or str(data.get("affiliate_display_name") or "")).strip() or name
            instagram = (_safe_str_field("affiliate_instagram", 120) or str(data.get("affiliate_instagram") or "")).strip()

            if hasattr(AffiliateProfile, "create_for_user") and callable(getattr(AffiliateProfile, "create_for_user")):
                prof = AffiliateProfile.create_for_user(  # type: ignore[attr-defined]
                    user.id,
                    display_name=display_name,
                    instagram=instagram,
                )
            else:
                prof = AffiliateProfile(  # type: ignore[call-arg]
                    user_id=int(user.id),
                    status="pending",
                    display_name=display_name,
                    instagram=instagram,
                )
            db.session.add(prof)
        except Exception:
            log.exception("AffiliateProfile creation failed (ignored).")

    if not _commit_safe():
        return _json_or_redirect("Error creando la cuenta. Probá de nuevo.", "error", "auth.register", next=nxt_safe)

    if VERIFY_EMAIL_REQUIRED and not bool(getattr(user, "is_admin", False)) and not bool(getattr(user, "is_owner", False)):
        _send_email_verify(user, force=True)
        red = _safe_url_for("auth.verify_notice", email=getattr(user, "email", "")) or "/auth/verify-notice"
        if _wants_json():
            return jsonify({"ok": True, "redirect": red}), 200
        return redirect(red)

    _set_session_user(user)
    redir = nxt_safe or _post_login_redirect(user)

    if _wants_json():
        return jsonify({"ok": True, "redirect": redir}), 200

    flash("Cuenta creada con éxito ✅", "success")
    return redirect(redir)


@auth_bp.get("/verify-notice")
def verify_notice():
    email = (request.args.get("email") or "").strip() or (session.get("user_email") or "").strip()
    resp = make_response(render_template("auth/verify_email.html", email=email), 200)
    resp.headers["Cache-Control"] = "no-store"
    return resp


@auth_bp.post("/resend-verification")
def resend_verification():
    data = _safe_get_json()
    email = _safe_email(_safe_str_field("email", 255) or str(data.get("email") or ""))

    if not _valid_email(email):
        return _json_or_redirect("Email inválido.", "error", "auth.verify_notice", email="")

    ok_rl, left = _rate_limit_email_ok("resend", email, RESEND_VERIFY_COOLDOWN_SEC)
    if not ok_rl:
        if _wants_json():
            resp = jsonify({"ok": False, "message": f"Esperá {left}s y reintentá.", "retry_after": left})
            resp.status_code = 429
            resp.headers["Retry-After"] = str(left)
            return resp
        flash("Te lo enviamos hace poco. Esperá un minuto y reintentá.", "warning")
        return redirect(_safe_url_for("auth.verify_notice", email=email) or "/auth/verify-notice")

    user = _get_user_by_email(email)
    if not user:
        return _json_or_redirect("Si el email existe, te enviamos el enlace.", "info", "auth.verify_notice", email=email)

    if _user_is_verified(user):
        return _json_or_redirect("Tu email ya está verificado ✅ Ya podés iniciar sesión.", "success", "auth.login")

    ok = _send_email_verify(user, force=True)
    if not ok:
        return _json_or_redirect("No se pudo reenviar ahora. Probá más tarde.", "warning", "auth.verify_notice", email=email)

    return _json_or_redirect("Listo ✅ Te reenviamos el enlace de verificación.", "success", "auth.verify_notice", email=email)


@auth_bp.get("/verify-email/<token>")
def verify_email(token: str):
    data, reason = _read_verify_token(token or "", max_age=VERIFY_TOKEN_MAX_AGE_SEC)
    if not data:
        flash("El enlace expiró. Pedí uno nuevo." if reason == "expired" else "El enlace es inválido. Pedí uno nuevo.", "error")
        return redirect(_safe_url_for("auth.verify_notice") or "/auth/verify-notice")

    uid = data.get("uid")
    email = (data.get("email") or "").lower().strip()

    try:
        uid_int = int(uid)
    except Exception:
        flash("Enlace inválido. Pedí uno nuevo.", "error")
        return redirect(_safe_url_for("auth.verify_notice", email=email) or "/auth/verify-notice")

    user = db.session.get(User, uid_int)
    if not user or (getattr(user, "email", "") or "").lower().strip() != email:
        flash("Enlace inválido. Pedí uno nuevo.", "error")
        return redirect(_safe_url_for("auth.verify_notice", email=email) or "/auth/verify-notice")

    if _user_is_verified(user):
        flash("Tu email ya estaba verificado ✅", "success")
        return redirect(_safe_url_for("auth.login") or "/auth/login")

    _set_user_verified(user)
    _commit_safe()

    flash("Email verificado ✅ Ya podés iniciar sesión.", "success")
    return redirect(_safe_url_for("auth.login") or "/auth/login")


@auth_bp.get("/logout")
def logout():
    _clear_auth_session_only()
    if _wants_json():
        return jsonify({"ok": True}), 200
    flash("Sesión cerrada.", "info")
    for ep in ("main.index", "main.home", "shop.shop"):
        u = _safe_url_for(ep)
        if u:
            return redirect(u)
    return redirect("/")


__all__ = ["auth_bp"]
