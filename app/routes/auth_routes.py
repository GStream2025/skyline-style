# app/routes/auth_routes.py — Skyline Store (ULTRA PRO / FINAL / NO BREAK / ALL-IN-ONE)
from __future__ import annotations

import os
import re
import time
import secrets
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Optional, Any, Dict, Tuple

from flask import (
    Blueprint, flash, redirect, render_template, request, session,
    url_for, jsonify, current_app
)
from werkzeug.routing import BuildError
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from app.models import db, User

# ✅ Afiliados (si el modelo existe)
try:
    from app.models import AffiliateProfile  # type: ignore
except Exception:
    AffiliateProfile = None  # type: ignore

logger = logging.getLogger(__name__)
auth_bp = Blueprint("auth", __name__)

# ============================================================
# Config (ENV overrides) — NO rompe si faltan
# ============================================================

def _env_flag(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}

def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None:
        return default
    try:
        return int(v)
    except Exception:
        return default

def _env_float(name: str, default: float) -> float:
    v = os.getenv(name)
    if v is None:
        return default
    try:
        return float(v)
    except Exception:
        return default

RATE_LIMIT_SECONDS = _env_float("AUTH_RATE_LIMIT_SECONDS", 2.0)
FORM_NONCE_TTL = _env_int("AUTH_FORM_NONCE_TTL", 20 * 60)
MAX_LOGIN_ATTEMPTS = _env_int("AUTH_MAX_LOGIN_ATTEMPTS", 8)
LOCK_MINUTES = _env_int("AUTH_LOCK_MINUTES", 15)

VERIFY_EMAIL_REQUIRED = _env_flag("VERIFY_EMAIL_REQUIRED", True)
VERIFY_TOKEN_MAX_AGE_SEC = _env_int("VERIFY_TOKEN_MAX_AGE_SEC", 60 * 60 * 24)  # 24h
RESEND_VERIFY_COOLDOWN_SEC = _env_int("RESEND_VERIFY_COOLDOWN_SEC", 60)        # 60s

# Opcional: si querés que ADMIN también requiera verify, ponelo en 1
VERIFY_ADMIN_TOO = _env_flag("VERIFY_ADMIN_TOO", False)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ============================================================
# Helpers
# ============================================================

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _wants_json() -> bool:
    p = (request.path or "").lower()
    if p.startswith("/api/"):
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
        return jsonify({"ok": ok, "message": message}), status
    flash(message, category)
    return redirect(url_for(endpoint, **kwargs))

def _is_safe_next(nxt: str) -> bool:
    if not nxt:
        return False
    nxt = nxt.strip()
    if not nxt.startswith("/"):
        return False
    p = urlparse(nxt)
    return p.scheme == "" and p.netloc == ""

def _next_url(default: str) -> str:
    nxt = (request.args.get("next") or request.form.get("next") or "").strip()
    return nxt if _is_safe_next(nxt) else default

def _safe_fallback_shop() -> str:
    for ep in ("shop.shop", "main.home"):
        try:
            return url_for(ep)
        except BuildError:
            continue
    return "/"

def _clear_session_keep_csrf() -> None:
    csrf = session.get("csrf_token")
    session.clear()
    if csrf:
        session["csrf_token"] = csrf

def _safe_email(email_raw: str) -> str:
    email_raw = (email_raw or "").strip()
    if not email_raw:
        return ""
    if hasattr(User, "normalize_email"):
        try:
            return str(User.normalize_email(email_raw))  # type: ignore[attr-defined]
        except Exception:
            pass
    return email_raw.lower().strip()

def _valid_email(email: str) -> bool:
    if not email or len(email) > 254:
        return False
    return bool(EMAIL_RE.match(email))

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
        logger.exception("DB commit failed.")
        return False

def _rate_limit_ok(key: str) -> bool:
    now = time.time()
    last = session.get(key, 0)
    try:
        last = float(last)
    except Exception:
        last = 0.0
    if (now - last) < RATE_LIMIT_SECONDS:
        return False
    session[key] = now
    return True

def _rate_limit_email_ok(prefix: str, email: str, cooldown: int) -> bool:
    """
    ✅ Cooldown por email sin DB: guarda timestamp en session.
    Sirve para resend-verification y anti spam.
    """
    e = (email or "").strip().lower()
    if not e:
        return False
    k = f"{prefix}:{e}"
    now = time.time()
    last = session.get(k, 0)
    try:
        last = float(last)
    except Exception:
        last = 0.0
    if (now - last) < float(cooldown):
        return False
    session[k] = now
    return True

# ---------- Nonce anti double submit ----------
def _new_form_nonce(key: str) -> str:
    tok = secrets.token_urlsafe(20)
    session[f"nonce:{key}"] = {"v": tok, "ts": int(time.time())}
    return tok

def _check_form_nonce(key: str) -> bool:
    raw = session.get(f"nonce:{key}") or {}
    if not isinstance(raw, dict):
        return False

    v = (raw.get("v") or "").strip()
    ts = raw.get("ts") or 0
    try:
        ts = int(ts)
    except Exception:
        ts = 0

    token = (request.form.get("nonce") or "").strip()
    if not v or not token:
        return False
    if not secrets.compare_digest(v, token):
        return False
    if (int(time.time()) - ts) > FORM_NONCE_TTL:
        return False

    session.pop(f"nonce:{key}", None)
    return True

# ---------- Session user ----------
def _get_current_user() -> Optional[User]:
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        uid_int = int(uid)
    except Exception:
        _clear_session_keep_csrf()
        return None
    u = db.session.get(User, uid_int)
    if not u:
        _clear_session_keep_csrf()
        return None
    return u

def _set_session_user(user: User) -> None:
    csrf = session.get("csrf_token")
    session.clear()
    if csrf:
        session["csrf_token"] = csrf

    session["user_id"] = int(user.id)
    session["user_email"] = (getattr(user, "email", "") or "").lower()
    session["is_admin"] = bool(getattr(user, "is_admin", False))
    session["login_at"] = int(time.time())
    session.permanent = True

def _post_login_redirect(user: User) -> str:
    # Si hay endpoints, los usamos. Si no, fallback.
    try:
        if bool(getattr(user, "is_admin", False)) or bool(getattr(user, "is_owner", False)):
            return url_for("admin.dashboard")
    except Exception:
        pass

    for ep in ("account.account_home", "shop.shop", "main.home"):
        try:
            return url_for(ep)
        except BuildError:
            continue
    return "/"

def _read_bool_field(name: str) -> bool:
    v = (request.form.get(name) or "").strip().lower()
    return v in {"1", "true", "yes", "y", "on", "checked"}

def _safe_str_field(name: str, max_len: int = 200) -> str:
    return (request.form.get(name) or "").strip()[:max_len]


# ============================================================
# Email verification engine (signed token)
# ============================================================

def _serializer() -> URLSafeTimedSerializer:
    secret = (current_app.config.get("SECRET_KEY") or os.getenv("SECRET_KEY") or "").strip()
    if not secret:
        # No rompe en dev, pero en prod DEBE existir
        secret = "dev-secret"
    return URLSafeTimedSerializer(secret_key=secret, salt="skyline-email-verify-v1")

def _user_is_verified(user: User) -> bool:
    if hasattr(user, "email_verified"):
        try:
            return bool(getattr(user, "email_verified"))
        except Exception:
            return False
    return True  # si tu DB vieja no tiene el campo, no rompemos

def _set_user_verified(user: User) -> None:
    if hasattr(user, "verify_email"):
        try:
            user.verify_email()  # usa tu método pro del modelo si existe
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
        "uid": int(user.id),
        "email": (getattr(user, "email", "") or "").lower(),
        "v": 1,
    }
    return _serializer().dumps(data)

def _read_verify_token(token: str, max_age: int) -> Optional[Dict[str, Any]]:
    try:
        data = _serializer().loads(token, max_age=max_age)
        if isinstance(data, dict) and "uid" in data and "email" in data:
            return data
        return None
    except SignatureExpired:
        return None
    except BadSignature:
        return None
    except Exception:
        return None

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
    Envía emails/welcome_verify.html con link firmado.
    NO rompe si EmailService no existe.
    Cooldown por session+email para evitar spam.
    """
    if not _emails_enabled():
        logger.info("ENABLE_EMAILS=0 -> no se envía verificación.")
        return False

    # cooldown global por email (session)
    if not force:
        ok_rl = _rate_limit_email_ok("rl:verify", getattr(user, "email", ""), RESEND_VERIFY_COOLDOWN_SEC)
        if not ok_rl:
            return False

    token = _make_verify_token(user)
    verify_url = f"{_app_url()}{url_for('auth.verify_email', token=token)}"

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

    # Intentar localizar EmailService en varias rutas (sin romper)
    EmailService = None
    for path in (
        "app.services.email_service",
        "app.email_service",
        "app.utils.email_service",
    ):
        try:
            mod = __import__(path, fromlist=["EmailService"])
            EmailService = getattr(mod, "EmailService", None)
            if EmailService:
                break
        except Exception:
            continue

    if not EmailService:
        logger.warning("EmailService no encontrado. No se envía email (pero no rompe).")
        return False

    try:
        svc = EmailService()
        # soporta distintos nombres de método
        if hasattr(svc, "send_html"):
            return bool(svc.send_html(
                to_email=getattr(user, "email", ""),
                subject="Confirmá tu cuenta · Skyline Store",
                html=html,
                text=text,
            ))
        if hasattr(svc, "send"):
            # fallback
            return bool(svc.send(
                to=getattr(user, "email", ""),
                subject="Confirmá tu cuenta · Skyline Store",
                html=html,
                text=text,
            ))
        logger.warning("EmailService existe pero no tiene send_html/send.")
        return False
    except Exception:
        logger.exception("Falló el envío de verificación.")
        return False

def _needs_verify_gate(user: User) -> bool:
    """
    Decide si bloqueamos login por no estar verificado.
    - si VERIFY_EMAIL_REQUIRED=0 -> nunca
    - si es admin/owner -> depende de VERIFY_ADMIN_TOO
    """
    if not VERIFY_EMAIL_REQUIRED:
        return False

    # admins/owners
    is_admin = bool(getattr(user, "is_admin", False))
    is_owner = bool(getattr(user, "is_owner", False))
    if (is_admin or is_owner) and not VERIFY_ADMIN_TOO:
        return False

    return not _user_is_verified(user)


# ============================================================
# Routes
# ============================================================

@auth_bp.get("/login")
def login():
    u = _get_current_user()
    if u:
        return redirect(_post_login_redirect(u))

    nxt = _next_url(_safe_fallback_shop())
    nonce = _new_form_nonce("login")
    return render_template("auth/login.html", next=nxt, nonce=nonce)

@auth_bp.post("/login")
def login_post():
    if not _check_form_nonce("login"):
        return _json_or_redirect(
            "Solicitud inválida. Recargá la página e intentá de nuevo.",
            "error", "auth.login",
            next=_next_url(_safe_fallback_shop()),
        )

    if not _rate_limit_ok("rl:login"):
        return _json_or_redirect(
            "Demasiados intentos. Esperá un momento y reintentá.",
            "warning", "auth.login",
            next=_next_url(_safe_fallback_shop()),
        )

    email = _safe_email(_safe_str_field("email", 255))
    password = (_safe_str_field("password", 256)).strip()
    nxt_safe = _next_url("")

    # Mensaje neutro (no filtra si existe el email)
    if not _valid_email(email) or not password:
        return _json_or_redirect("Email o contraseña incorrectos.", "error", "auth.login", next=nxt_safe)

    user = db.session.query(User).filter(User.email == email).first()

    # Lockouts pro (si el modelo trae can_login)
    if user and hasattr(user, "can_login"):
        try:
            if not user.can_login():
                return _json_or_redirect("Cuenta temporalmente bloqueada. Intentá más tarde.", "error", "auth.login", next=nxt_safe)
        except Exception:
            pass

    # Check password
    if not user or not user.check_password(password):
        if user:
            try:
                if hasattr(user, "mark_failed_login"):
                    user.mark_failed_login(lock_after=MAX_LOGIN_ATTEMPTS, lock_minutes=LOCK_MINUTES)
            except Exception:
                pass
            _commit_safe()
        return _json_or_redirect("Email o contraseña incorrectos.", "error", "auth.login", next=nxt_safe)

    # is_active
    try:
        if hasattr(user, "is_active") and not bool(getattr(user, "is_active")):
            return _json_or_redirect("Tu cuenta está desactivada.", "error", "auth.login", next=nxt_safe)
    except Exception:
        pass

    # ✅ Verify gate (PRO)
    if _needs_verify_gate(user):
        _send_email_verify(user, force=False)
        if _wants_json():
            return jsonify({
                "ok": False,
                "needs_verify": True,
                "redirect": url_for("auth.verify_notice", email=user.email),
                "message": "Verificá tu email para continuar.",
            }), 403
        flash("Verificá tu email para continuar. Te reenviamos el enlace si era necesario.", "warning")
        return redirect(url_for("auth.verify_notice", email=user.email))

    # Login OK
    try:
        ip = _client_ip()
        if hasattr(user, "touch_login"):
            user.touch_login(ip=ip)
        else:
            if hasattr(user, "last_login_at"):
                user.last_login_at = _utcnow()
            if hasattr(user, "failed_login_count"):
                user.failed_login_count = 0
            if hasattr(user, "locked_until"):
                user.locked_until = None
            if hasattr(user, "last_login_ip"):
                user.last_login_ip = ip
    except Exception:
        pass
    _commit_safe()

    _set_session_user(user)

    if _wants_json():
        return jsonify({"ok": True, "redirect": (nxt_safe or _post_login_redirect(user))}), 200

    flash("Bienvenido 👋", "success")
    return redirect(nxt_safe or _post_login_redirect(user))


# ------------------------------
# Register
# ------------------------------
@auth_bp.get("/register")
def register():
    u = _get_current_user()
    if u:
        return redirect(_post_login_redirect(u))

    nxt = _next_url(_safe_fallback_shop())
    nonce = _new_form_nonce("register")
    return render_template("auth/register.html", next=nxt, nonce=nonce)

@auth_bp.post("/register")
def register_post():
    if not _check_form_nonce("register"):
        return _json_or_redirect(
            "Solicitud inválida. Recargá la página e intentá de nuevo.",
            "error", "auth.register",
            next=_next_url(_safe_fallback_shop()),
        )

    email = _safe_email(_safe_str_field("email", 255))
    password = (_safe_str_field("password", 256)).strip()
    name = _safe_str_field("name", 120)
    nxt_safe = _next_url("")

    if not _valid_email(email):
        return _json_or_redirect("Email inválido.", "warning", "auth.register", next=nxt_safe)

    if len(password) < 8:
        return _json_or_redirect("La contraseña debe tener al menos 8 caracteres.", "warning", "auth.register", next=nxt_safe)

    if db.session.query(User).filter(User.email == email).first():
        return _json_or_redirect("Ese email ya está registrado. Iniciá sesión.", "info", "auth.login", next=nxt_safe)

    want_affiliate = _read_bool_field("want_affiliate")

    user = User(email=email)
    try:
        if hasattr(user, "name") and name:
            user.name = name
    except Exception:
        pass

    # nadie se crea admin desde register (owner se fuerza en modelo igual)
    try:
        if hasattr(user, "is_admin"):
            user.is_admin = False
    except Exception:
        pass

    # rol seguro
    try:
        if want_affiliate:
            if hasattr(user, "set_role_safe"):
                user.set_role_safe("affiliate")
            else:
                user.role = "affiliate"
        else:
            if hasattr(user, "set_role_safe"):
                user.set_role_safe("customer")
            else:
                user.role = "customer"
    except Exception:
        pass

    # password (usa tu policy pro del modelo)
    try:
        user.set_password(password)
    except Exception:
        return _json_or_redirect("No se pudo crear la cuenta (password inválida). Probá otra.", "error", "auth.register", next=nxt_safe)

    # flags base
    try:
        if hasattr(user, "is_active"):
            user.is_active = True
    except Exception:
        pass

    # NO verificado por defecto si existe el campo
    if hasattr(user, "email_verified"):
        try:
            user.email_verified = False
        except Exception:
            pass

    # Save
    try:
        db.session.add(user)
        db.session.flush()
    except Exception:
        db.session.rollback()
        return _json_or_redirect("Error creando la cuenta. Probá de nuevo.", "error", "auth.register", next=nxt_safe)

    # Affiliate profile pending (si existe modelo)
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
            pass

    if not _commit_safe():
        return _json_or_redirect("Error creando la cuenta. Probá de nuevo.", "error", "auth.register", next=nxt_safe)

    # ✅ si requiere verificación: mandar verify y pantalla verify
    if VERIFY_EMAIL_REQUIRED and not bool(getattr(user, "is_admin", False)) and not bool(getattr(user, "is_owner", False)):
        _send_email_verify(user, force=True)
        if _wants_json():
            return jsonify({"ok": True, "redirect": url_for("auth.verify_notice", email=user.email)}), 200
        return redirect(url_for("auth.verify_notice", email=user.email))

    # si no requiere verificación -> login normal
    _set_session_user(user)

    if _wants_json():
        return jsonify({"ok": True, "redirect": (nxt_safe or _post_login_redirect(user))}), 200

    flash("Cuenta creada con éxito ✅", "success")
    return redirect(nxt_safe or _post_login_redirect(user))


# ------------------------------
# Verify notice screen
# ------------------------------
@auth_bp.get("/verify-notice")
def verify_notice():
    email = (request.args.get("email") or "").strip()
    return render_template("auth/verify_notice.html", email=email)

# ------------------------------
# Resend verification
# ------------------------------
@auth_bp.post("/resend-verification")
def resend_verification():
    email = _safe_email(_safe_str_field("email", 255))
    if not _valid_email(email):
        return _json_or_redirect("Email inválido.", "error", "auth.verify_notice", email="")

    # cooldown por email en session (anti spam real)
    if not _rate_limit_email_ok("rl:resend", email, RESEND_VERIFY_COOLDOWN_SEC):
        return _json_or_redirect("Te lo enviamos hace poco. Esperá 1 minuto y reintentá.", "warning", "auth.verify_notice", email=email)

    user = db.session.query(User).filter(User.email == email).first()

    # respuesta neutra (no filtra si existe)
    if not user:
        return _json_or_redirect("Si el email existe, te enviamos el enlace.", "info", "auth.verify_notice", email=email)

    if _user_is_verified(user):
        return _json_or_redirect("Tu email ya está verificado ✅ Ya podés iniciar sesión.", "success", "auth.login")

    ok = _send_email_verify(user, force=True)
    if not ok:
        return _json_or_redirect("No se pudo reenviar ahora. Probá de nuevo en 1 minuto.", "warning", "auth.verify_notice", email=email)

    return _json_or_redirect("Listo ✅ Te reenviamos el enlace de verificación.", "success", "auth.verify_notice", email=email)

# ------------------------------
# Verify email token
# ------------------------------
@auth_bp.get("/verify-email/<token>")
def verify_email(token: str):
    data = _read_verify_token(token or "", max_age=VERIFY_TOKEN_MAX_AGE_SEC)
    if not data:
        flash("El enlace es inválido o expiró. Pedí uno nuevo.", "error")
        return redirect(url_for("auth.verify_notice"))

    uid = data.get("uid")
    email = (data.get("email") or "").lower().strip()

    try:
        uid_int = int(uid)
    except Exception:
        flash("Enlace inválido. Pedí uno nuevo.", "error")
        return redirect(url_for("auth.verify_notice", email=email))

    user = db.session.get(User, uid_int)
    if not user or (getattr(user, "email", "") or "").lower().strip() != email:
        flash("Enlace inválido. Pedí uno nuevo.", "error")
        return redirect(url_for("auth.verify_notice", email=email))

    if _user_is_verified(user):
        flash("Tu email ya estaba verificado ✅", "success")
        return redirect(url_for("auth.login"))

    _set_user_verified(user)
    _commit_safe()

    flash("Email verificado ✅ Ya podés iniciar sesión.", "success")
    return redirect(url_for("auth.login"))

# ------------------------------
# Logout
# ------------------------------
@auth_bp.get("/logout")
def logout():
    _clear_session_keep_csrf()
    if _wants_json():
        return jsonify({"ok": True}), 200
    flash("Sesión cerrada.", "info")
    for ep in ("main.home", "shop.shop"):
        try:
            return redirect(url_for(ep))
        except BuildError:
            continue
    return redirect("/")


__all__ = ["auth_bp"]
