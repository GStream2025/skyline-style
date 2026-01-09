# app/routes/auth_routes.py — Skyline Store (ULTRA PRO / FINAL / NO BREAK)
from __future__ import annotations

import logging
import os
import re
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

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

log = logging.getLogger(__name__)
auth_bp = Blueprint("auth", __name__)


# ============================================================
# Config (ENV overrides) — robusto
# ============================================================

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def _env_flag(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in _TRUE

def _env_int(name: str, default: int, *, min_v: int = 0, max_v: int = 10_000_000) -> int:
    v = os.getenv(name)
    if v is None:
        return default
    try:
        n = int(str(v).strip())
    except Exception:
        return default
    return max(min_v, min(max_v, n))

def _env_float(name: str, default: float, *, min_v: float = 0.0, max_v: float = 3600.0) -> float:
    v = os.getenv(name)
    if v is None:
        return default
    try:
        n = float(str(v).strip())
    except Exception:
        return default
    return max(min_v, min(max_v, n))

AUTH_RATE_LIMIT_SECONDS = _env_float("AUTH_RATE_LIMIT_SECONDS", 2.0, min_v=0.1, max_v=30.0)
AUTH_MAX_LOGIN_ATTEMPTS = _env_int("AUTH_MAX_LOGIN_ATTEMPTS", 8, min_v=1, max_v=50)
AUTH_LOCK_MINUTES = _env_int("AUTH_LOCK_MINUTES", 15, min_v=1, max_v=240)

VERIFY_EMAIL_REQUIRED = _env_flag("VERIFY_EMAIL_REQUIRED", True)
VERIFY_ADMIN_TOO = _env_flag("VERIFY_ADMIN_TOO", False)
VERIFY_TOKEN_MAX_AGE_SEC = _env_int("VERIFY_TOKEN_MAX_AGE_SEC", 60 * 60 * 24, min_v=60, max_v=60 * 60 * 24 * 14)
RESEND_VERIFY_COOLDOWN_SEC = _env_int("RESEND_VERIFY_COOLDOWN_SEC", 60, min_v=10, max_v=3600)


# ============================================================
# Helpers (time / json / url / session)
# ============================================================

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
    p = (request.path or "").lower()
    if p.startswith("/api/"):
        return True
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
    """
    Dual response:
    - JSON => {"ok", "message", "redirect?"}
    - HTML => flash + redirect
    """
    if _wants_json():
        ok = category not in {"error", "warning"}
        status = 400 if not ok else 200
        payload: Dict[str, Any] = {"ok": ok, "message": message}
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
    if not nxt.startswith("/"):
        return False
    p = urlparse(nxt)
    return p.scheme == "" and p.netloc == ""

def _next_url(default_url: str) -> str:
    nxt = (request.args.get("next") or request.form.get("next") or "").strip()
    return nxt if _is_safe_next(nxt) else default_url

def _safe_fallback_shop() -> str:
    for ep in ("shop.shop", "main.home"):
        u = _safe_url_for(ep)
        if u:
            return u
    return "/"

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
    # si tu User tiene normalize_email(), lo usamos
    if hasattr(User, "normalize_email"):
        try:
            return str(User.normalize_email(raw))  # type: ignore[attr-defined]
        except Exception:
            pass
    return raw.lower().strip()

def _valid_email(email: str) -> bool:
    if not email or len(email) > 254:
        return False
    return bool(EMAIL_RE.match(email))

def _safe_str_field(name: str, max_len: int = 200) -> str:
    return (request.form.get(name) or "").strip()[:max_len]

def _read_bool_field(name: str) -> bool:
    v = (request.form.get(name) or "").strip().lower()
    return v in _TRUE


# ============================================================
# Rate limiting (session + ip) — simple y estable
# ============================================================

def _rl_key(prefix: str) -> str:
    return f"rl:{prefix}:{_client_ip()}"

def _rate_limit_ok(prefix: str, cooldown_sec: float) -> bool:
    """
    cooldown simple por IP (en session)
    """
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
    """
    cooldown por IP + email en session.
    Retorna (ok, retry_after)
    """
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


# ============================================================
# Session user (tu sistema actual: session["user_id"])
# ============================================================

def _clear_session_keep_csrf() -> None:
    # si usás CSRFProtect (Flask-WTF) no depende de session["csrf_token"],
    # pero preservamos por compat con tu base.
    keep = session.get("csrf_token")
    session.clear()
    if keep:
        session["csrf_token"] = keep

def _get_current_user() -> Optional[User]:
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        uid_int = int(uid)
    except Exception:
        _clear_session_keep_csrf()
        return None
    try:
        return db.session.get(User, uid_int)
    except Exception:
        return None

def _set_session_user(user: User) -> None:
    keep = session.get("csrf_token")
    session.clear()
    if keep:
        session["csrf_token"] = keep

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

    for ep in ("account.account_home", "shop.shop", "main.home"):
        u = _safe_url_for(ep)
        if u:
            return u
    return "/"


# ============================================================
# Email verification (signed token) — seguro y estable
# ============================================================

def _serializer() -> URLSafeTimedSerializer:
    secret = (current_app.config.get("SECRET_KEY") or os.getenv("SECRET_KEY") or "").strip()
    # en prod nunca debería faltar (tu create_app ya obliga)
    if not secret:
        secret = "dev-secret"
    return URLSafeTimedSerializer(secret_key=secret, salt="skyline-email-verify-v1")

def _user_is_verified(user: User) -> bool:
    if hasattr(user, "email_verified"):
        try:
            return bool(getattr(user, "email_verified"))
        except Exception:
            return False
    return True  # si tu modelo no tiene verificación, no bloqueamos

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
    data = {
        "uid": int(getattr(user, "id")),
        "email": (getattr(user, "email", "") or "").lower(),
        "v": 1,
    }
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
    base = (os.getenv("APP_URL") or "").strip()
    if base:
        return base.rstrip("/")
    try:
        return request.host_url.rstrip("/")
    except Exception:
        return "http://127.0.0.1:5000"

def _emails_enabled() -> bool:
    return _env_flag("ENABLE_EMAILS", False)

def _send_email_verify(user: User, *, force: bool = False) -> bool:
    """
    Envia email de verificación si hay EmailService.
    No rompe si no existe.
    """
    if not _emails_enabled():
        return False

    if not force:
        ok_rl, _left = _rate_limit_email_ok(
            "verify",
            getattr(user, "email", "") or "",
            RESEND_VERIFY_COOLDOWN_SEC,
        )
        if not ok_rl:
            return False

    token = _make_verify_token(user)
    verify_path = _safe_url_for("auth.verify_email", token=token) or f"/verify-email/{token}"
    verify_url = f"{_app_url()}{verify_path}"

    html = render_template(
        "emails/welcome_verify.html",
        name=getattr(user, "name", None),
        email=getattr(user, "email", ""),
        verify_url=verify_url,
        year=_utcnow().year,
    )
    text = (
        "Confirmá tu cuenta en Skyline Store\n\n"
        f"Abrí este enlace para verificar tu email:\n{verify_url}\n\n"
        "Si no fuiste vos, ignorá este mensaje."
    )

    EmailService = None
    for path in ("app.services.email_service", "app.email_service", "app.utils.email_service"):
        try:
            mod = __import__(path, fromlist=["EmailService"])
            EmailService = getattr(mod, "EmailService", None)
            if EmailService:
                break
        except Exception:
            continue

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


# ============================================================
# DB helpers
# ============================================================

def _get_user_by_email(email: str) -> Optional[User]:
    try:
        return db.session.execute(select(User).where(User.email == email)).scalar_one_or_none()
    except Exception:
        return None


# ============================================================
# Routes
# ============================================================

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    u = _get_current_user()
    if u:
        return redirect(_post_login_redirect(u))

    default_next = _safe_fallback_shop()
    nxt = _next_url(default_next)

    if request.method == "GET":
        return render_template("auth/login.html", next=nxt)

    # POST (CSRFProtect ya valida antes de entrar acá)
    if not _rate_limit_ok("login", AUTH_RATE_LIMIT_SECONDS):
        return _json_or_redirect(
            "Demasiados intentos. Esperá un momento y reintentá.",
            "warning",
            "auth.login",
            next=nxt,
        )

    email = _safe_email(_safe_str_field("email", 255))
    password = (_safe_str_field("password", 256)).strip()
    nxt_safe = _next_url("")

    if not _valid_email(email) or not password:
        return _json_or_redirect("Email o contraseña incorrectos.", "error", "auth.login", next=nxt_safe)

    user = _get_user_by_email(email)

    # gate opcional: can_login()
    if user and hasattr(user, "can_login"):
        try:
            if not user.can_login():  # type: ignore[attr-defined]
                return _json_or_redirect(
                    "Cuenta temporalmente bloqueada. Intentá más tarde.",
                    "error",
                    "auth.login",
                    next=nxt_safe,
                )
        except Exception:
            pass

    # password check
    if not user or not getattr(user, "check_password", None) or not user.check_password(password):  # type: ignore[truthy-function]
        if user:
            try:
                if hasattr(user, "mark_failed_login"):
                    user.mark_failed_login(lock_after=AUTH_MAX_LOGIN_ATTEMPTS, lock_minutes=AUTH_LOCK_MINUTES)  # type: ignore[attr-defined]
                    _commit_safe()
            except Exception:
                pass
        return _json_or_redirect("Email o contraseña incorrectos.", "error", "auth.login", next=nxt_safe)

    # active?
    try:
        if hasattr(user, "is_active") and not bool(getattr(user, "is_active")):
            return _json_or_redirect("Tu cuenta está desactivada.", "error", "auth.login", next=nxt_safe)
    except Exception:
        pass

    # verify gate
    if _needs_verify_gate(user):
        _send_email_verify(user, force=False)
        red = _safe_url_for("auth.verify_notice", email=getattr(user, "email", "")) or "/verify-notice"
        if _wants_json():
            return jsonify({"ok": False, "needs_verify": True, "redirect": red, "message": "Verificá tu email para continuar."}), 403
        flash("Verificá tu email para continuar. Te reenviamos el enlace si era necesario.", "warning")
        return redirect(red)

    # success: touch login info
    try:
        ip = _client_ip()
        if hasattr(user, "touch_login"):
            user.touch_login(ip=ip)  # type: ignore[attr-defined]
        else:
            if hasattr(user, "last_login_at"):
                setattr(user, "last_login_at", _utcnow())
            if hasattr(user, "failed_login_count"):
                setattr(user, "failed_login_count", 0)
            if hasattr(user, "locked_until"):
                setattr(user, "locked_until", None)
            if hasattr(user, "last_login_ip"):
                setattr(user, "last_login_ip", ip)
    except Exception:
        pass
    _commit_safe()

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

    default_next = _safe_fallback_shop()
    nxt = _next_url(default_next)

    if request.method == "GET":
        return render_template("auth/register.html", next=nxt)

    # POST
    if not _rate_limit_ok("register", AUTH_RATE_LIMIT_SECONDS):
        return _json_or_redirect("Esperá un momento y reintentá.", "warning", "auth.register", next=nxt)

    email = _safe_email(_safe_str_field("email", 255))
    password = (_safe_str_field("password", 256)).strip()
    name = _safe_str_field("name", 120)
    nxt_safe = _next_url("")

    if not _valid_email(email):
        return _json_or_redirect("Email inválido.", "warning", "auth.register", next=nxt_safe)

    if len(password) < 8:
        return _json_or_redirect("La contraseña debe tener al menos 8 caracteres.", "warning", "auth.register", next=nxt_safe)

    if _get_user_by_email(email):
        return _json_or_redirect("Ese email ya está registrado. Iniciá sesión.", "info", "auth.login", next=nxt_safe)

    want_affiliate = _read_bool_field("want_affiliate")

    user = User(email=email)
    # set name
    try:
        if hasattr(user, "name") and name:
            setattr(user, "name", name)
    except Exception:
        pass

    # role
    try:
        if want_affiliate:
            if hasattr(user, "set_role_safe"):
                user.set_role_safe("affiliate")  # type: ignore[attr-defined]
            else:
                setattr(user, "role", "affiliate")
        else:
            if hasattr(user, "set_role_safe"):
                user.set_role_safe("customer")  # type: ignore[attr-defined]
            else:
                setattr(user, "role", "customer")
    except Exception:
        pass

    # not admin
    try:
        if hasattr(user, "is_admin"):
            setattr(user, "is_admin", False)
    except Exception:
        pass

    # active default
    try:
        if hasattr(user, "is_active"):
            setattr(user, "is_active", True)
    except Exception:
        pass

    # email_verified default false if exists
    try:
        if hasattr(user, "email_verified"):
            setattr(user, "email_verified", False)
    except Exception:
        pass

    # set password
    try:
        if hasattr(user, "set_password"):
            user.set_password(password)  # type: ignore[attr-defined]
        else:
            return _json_or_redirect("El modelo User no tiene set_password().", "error", "auth.register", next=nxt_safe)
    except Exception:
        return _json_or_redirect("No se pudo crear la cuenta (password inválida). Probá otra.", "error", "auth.register", next=nxt_safe)

    try:
        db.session.add(user)
        db.session.flush()  # obtiene user.id
    except Exception:
        db.session.rollback()
        return _json_or_redirect("Error creando la cuenta. Probá de nuevo.", "error", "auth.register", next=nxt_safe)

    # affiliate profile optional
    if want_affiliate and AffiliateProfile is not None:
        try:
            display_name = _safe_str_field("affiliate_display_name", 120) or name
            phone = _safe_str_field("affiliate_phone", 40)
            instagram = _safe_str_field("affiliate_instagram", 120)
            tiktok = _safe_str_field("affiliate_tiktok", 120)
            website = _safe_str_field("affiliate_website", 200)
            payout_method = _safe_str_field("affiliate_payout_method", 40)
            payout_details = _safe_str_field("affiliate_payout_details", 4000)

            if hasattr(AffiliateProfile, "create_for_user"):
                prof = AffiliateProfile.create_for_user(  # type: ignore[attr-defined]
                    user.id,
                    display_name=display_name,
                    phone=phone,
                    instagram=instagram,
                    tiktok=tiktok,
                    website=website,
                    payout_method=payout_method,
                    payout_details=payout_details,
                )
            else:
                prof = AffiliateProfile(  # type: ignore[call-arg]
                    user_id=int(user.id),
                    status="pending",
                    display_name=display_name,
                    phone=phone,
                    instagram=instagram,
                    tiktok=tiktok,
                    website=website,
                    payout_method=payout_method,
                    payout_details=payout_details,
                )
            db.session.add(prof)
        except Exception:
            # no rompemos el registro por esto
            log.exception("AffiliateProfile creation failed (ignored).")

    if not _commit_safe():
        return _json_or_redirect("Error creando la cuenta. Probá de nuevo.", "error", "auth.register", next=nxt_safe)

    # verify email flow
    if VERIFY_EMAIL_REQUIRED and not bool(getattr(user, "is_admin", False)) and not bool(getattr(user, "is_owner", False)):
        _send_email_verify(user, force=True)
        red = _safe_url_for("auth.verify_notice", email=getattr(user, "email", "")) or "/verify-notice"
        if _wants_json():
            return jsonify({"ok": True, "redirect": red}), 200
        return redirect(red)

    # auto login
    _set_session_user(user)
    redir = nxt_safe or _post_login_redirect(user)
    if _wants_json():
        return jsonify({"ok": True, "redirect": redir}), 200

    flash("Cuenta creada con éxito ✅", "success")
    return redirect(redir)


@auth_bp.get("/verify-notice")
def verify_notice():
    email = (request.args.get("email") or "").strip()
    if not email:
        email = (session.get("user_email") or "").strip()
    return render_template("auth/verify_notice.html", email=email)


@auth_bp.post("/resend-verification")
def resend_verification():
    """
    CSRFProtect valida esto automáticamente:
    - Form: csrf_token hidden
    - JSON: header X-CSRF-Token o X-CSRFToken (recomendado)
    """
    data = _safe_get_json()
    email = _safe_email(_safe_str_field("email", 255) or str(data.get("email") or ""))

    if not _valid_email(email):
        return _json_or_redirect("Email inválido.", "error", "auth.verify_notice", email="")

    ok_rl, left = _rate_limit_email_ok("resend", email, RESEND_VERIFY_COOLDOWN_SEC)
    if not ok_rl:
        if _wants_json():
            return jsonify({"ok": False, "message": f"Esperá {left}s y reintentá.", "retry_after": left}), 429
        return _json_or_redirect("Te lo enviamos hace poco. Esperá 1 minuto y reintentá.", "warning", "auth.verify_notice", email=email)

    user = _get_user_by_email(email)
    if not user:
        # respuesta neutra (no filtra existencia)
        return _json_or_redirect("Si el email existe, te enviamos el enlace.", "info", "auth.verify_notice", email=email)

    if _user_is_verified(user):
        return _json_or_redirect("Tu email ya está verificado ✅ Ya podés iniciar sesión.", "success", "auth.login")

    ok = _send_email_verify(user, force=True)
    if not ok:
        return _json_or_redirect("No se pudo reenviar ahora. Probá de nuevo más tarde.", "warning", "auth.verify_notice", email=email)

    return _json_or_redirect("Listo ✅ Te reenviamos el enlace de verificación.", "success", "auth.verify_notice", email=email)


@auth_bp.get("/verify-email/<token>")
def verify_email(token: str):
    data, reason = _read_verify_token(token or "", max_age=VERIFY_TOKEN_MAX_AGE_SEC)
    if not data:
        flash("El enlace expiró. Pedí uno nuevo." if reason == "expired" else "El enlace es inválido. Pedí uno nuevo.", "error")
        return redirect(_safe_url_for("auth.verify_notice") or "/verify-notice")

    uid = data.get("uid")
    email = (data.get("email") or "").lower().strip()

    try:
        uid_int = int(uid)
    except Exception:
        flash("Enlace inválido. Pedí uno nuevo.", "error")
        return redirect(_safe_url_for("auth.verify_notice", email=email) or "/verify-notice")

    user = db.session.get(User, uid_int)
    if not user or (getattr(user, "email", "") or "").lower().strip() != email:
        flash("Enlace inválido. Pedí uno nuevo.", "error")
        return redirect(_safe_url_for("auth.verify_notice", email=email) or "/verify-notice")

    if _user_is_verified(user):
        flash("Tu email ya estaba verificado ✅", "success")
        return redirect(_safe_url_for("auth.login") or "/login")

    _set_user_verified(user)
    _commit_safe()

    flash("Email verificado ✅ Ya podés iniciar sesión.", "success")
    return redirect(_safe_url_for("auth.login") or "/login")


@auth_bp.get("/logout")
def logout():
    _clear_session_keep_csrf()
    if _wants_json():
        return jsonify({"ok": True}), 200
    flash("Sesión cerrada.", "info")
    for ep in ("main.home", "shop.shop"):
        u = _safe_url_for(ep)
        if u:
            return redirect(u)
    return redirect("/")


__all__ = ["auth_bp"]
