# app/routes/auth_routes.py — Skyline Store (ULTRA PRO++ / FINAL / NO BREAK / ALL-IN-ONE)
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
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
    jsonify,
    current_app,
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
RESEND_VERIFY_COOLDOWN_SEC = _env_int("RESEND_VERIFY_COOLDOWN_SEC", 60)  # 60s

# Opcional: si querés que ADMIN también requiera verify, ponelo en 1
VERIFY_ADMIN_TOO = _env_flag("VERIFY_ADMIN_TOO", False)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# si querés forzar CSRF en JSON (fetch), activalo
ENFORCE_JSON_CSRF = _env_flag("AUTH_ENFORCE_JSON_CSRF", False)


# ============================================================
# Helpers
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
    # No rompe si body no es JSON válido
    try:
        if request.is_json:
            data = request.get_json(silent=True) or {}
            return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}


def _wants_json() -> bool:
    # Mejor: detecta fetch/json + query param
    p = (request.path or "").lower()
    if p.startswith("/api/"):
        return True
    if (request.args.get("json") or "").strip() in {"1", "true", "yes"}:
        return True
    fmt = (request.args.get("format") or "").strip().lower()
    if fmt == "json":
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
    Respuesta dual:
    - JSON (si wants_json) con ok/message (+ redirect opcional)
    - o flash + redirect
    """
    if _wants_json():
        ok = category not in {"error", "warning"}
        status = 400 if not ok else 200
        payload: Dict[str, Any] = {"ok": ok, "message": message}
        # si nos pasaron redirect explícito
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


def _next_url(default: str) -> str:
    nxt = (request.args.get("next") or request.form.get("next") or "").strip()
    return nxt if _is_safe_next(nxt) else default


def _safe_fallback_shop() -> str:
    for ep in ("shop.shop", "main.home"):
        u = _safe_url_for(ep)
        if u:
            return u
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
    """
    Rate limit general (por sesión + ip).
    """
    now = time.time()
    ip = _client_ip()
    k = f"{key}:{ip}"
    last = session.get(k, 0)
    try:
        last = float(last)
    except Exception:
        last = 0.0
    if (now - last) < RATE_LIMIT_SECONDS:
        return False
    session[k] = now
    session.modified = True
    return True


def _rate_limit_email_ok(prefix: str, email: str, cooldown: int) -> Tuple[bool, int]:
    """
    Cooldown por email + ip en session.
    Devuelve (ok, retry_after_seconds).
    """
    e = (email or "").strip().lower()
    if not e:
        return False, cooldown

    ip = _client_ip()
    k = f"{prefix}:{ip}:{e}"
    now = time.time()
    last = session.get(k, 0)
    try:
        last = float(last)
    except Exception:
        last = 0.0

    left = int(max(0, float(cooldown) - (now - last)))
    if left > 0:
        return False, left

    session[k] = now
    session.modified = True
    return True, 0


# ---------- Nonce anti double submit ----------
def _new_form_nonce(key: str) -> str:
    tok = secrets.token_urlsafe(20)
    session[f"nonce:{key}"] = {"v": tok, "ts": int(time.time())}
    session.modified = True
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
    session.modified = True
    return True


# ---------- CSRF para JSON (fetch) ----------
def _csrf_ok_for_json() -> bool:
    """
    Si ENFORCE_JSON_CSRF=1:
      - Acepta header X-CSRF-Token
      - o campo csrf_token en JSON
      - o csrf_token form (fallback)
    Si no hay csrf_token en session, no rompe.
    """
    if not ENFORCE_JSON_CSRF:
        return True

    expected = (session.get("csrf_token") or "").strip()
    if not expected:
        return True  # no rompemos dev / setups sin CSRF

    got = (request.headers.get("X-CSRF-Token") or "").strip()
    if got and secrets.compare_digest(expected, got):
        return True

    data = _safe_get_json()
    got2 = (str(data.get("csrf_token") or "")).strip()
    if got2 and secrets.compare_digest(expected, got2):
        return True

    got3 = (request.form.get("csrf_token") or "").strip()
    if got3 and secrets.compare_digest(expected, got3):
        return True

    return False


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
    session.modified = True


def _post_login_redirect(user: User) -> str:
    u = None
    try:
        if bool(getattr(user, "is_admin", False)) or bool(
            getattr(user, "is_owner", False)
        ):
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


def _read_bool_field(name: str) -> bool:
    v = (request.form.get(name) or "").strip().lower()
    return v in {"1", "true", "yes", "y", "on", "checked"}


def _safe_str_field(name: str, max_len: int = 200) -> str:
    return (request.form.get(name) or "").strip()[:max_len]


# ============================================================
# Email verification engine (signed token)
# ============================================================


def _serializer() -> URLSafeTimedSerializer:
    secret = (
        current_app.config.get("SECRET_KEY") or os.getenv("SECRET_KEY") or ""
    ).strip()
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
            user.verify_email()
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


def _read_verify_token(
    token: str, max_age: int
) -> Tuple[Optional[Dict[str, Any]], str]:
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
    Envía emails/welcome_verify.html con link firmado.
    NO rompe si EmailService no existe.
    Cooldown por session+email para evitar spam.
    """
    if not _emails_enabled():
        logger.info("ENABLE_EMAILS=0 -> no se envía verificación.")
        return False

    if not force:
        ok_rl, _left = _rate_limit_email_ok(
            "rl:verify", getattr(user, "email", ""), RESEND_VERIFY_COOLDOWN_SEC
        )
        if not ok_rl:
            return False

    token = _make_verify_token(user)
    verify_path = (
        _safe_url_for("auth.verify_email", token=token) or f"/verify-email/{token}"
    )
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
        logger.warning("EmailService existe pero no tiene send_html/send.")
        return False
    except Exception:
        logger.exception("Falló el envío de verificación.")
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
            "error",
            "auth.login",
            next=_next_url(_safe_fallback_shop()),
        )

    if not _rate_limit_ok("rl:login"):
        return _json_or_redirect(
            "Demasiados intentos. Esperá un momento y reintentá.",
            "warning",
            "auth.login",
            next=_next_url(_safe_fallback_shop()),
        )

    email = _safe_email(_safe_str_field("email", 255))
    password = (_safe_str_field("password", 256)).strip()
    nxt_safe = _next_url("")

    if not _valid_email(email) or not password:
        return _json_or_redirect(
            "Email o contraseña incorrectos.", "error", "auth.login", next=nxt_safe
        )

    user = db.session.query(User).filter(User.email == email).first()

    if user and hasattr(user, "can_login"):
        try:
            if not user.can_login():
                return _json_or_redirect(
                    "Cuenta temporalmente bloqueada. Intentá más tarde.",
                    "error",
                    "auth.login",
                    next=nxt_safe,
                )
        except Exception:
            pass

    if not user or not user.check_password(password):
        if user:
            try:
                if hasattr(user, "mark_failed_login"):
                    user.mark_failed_login(
                        lock_after=MAX_LOGIN_ATTEMPTS, lock_minutes=LOCK_MINUTES
                    )
            except Exception:
                pass
            _commit_safe()
        return _json_or_redirect(
            "Email o contraseña incorrectos.", "error", "auth.login", next=nxt_safe
        )

    try:
        if hasattr(user, "is_active") and not bool(getattr(user, "is_active")):
            return _json_or_redirect(
                "Tu cuenta está desactivada.", "error", "auth.login", next=nxt_safe
            )
    except Exception:
        pass

    if _needs_verify_gate(user):
        _send_email_verify(user, force=False)
        if _wants_json():
            return (
                jsonify(
                    {
                        "ok": False,
                        "needs_verify": True,
                        "redirect": (
                            _safe_url_for("auth.verify_notice", email=user.email)
                            or "/verify-notice"
                        ),
                        "message": "Verificá tu email para continuar.",
                    }
                ),
                403,
            )
        flash(
            "Verificá tu email para continuar. Te reenviamos el enlace si era necesario.",
            "warning",
        )
        return redirect(
            _safe_url_for("auth.verify_notice", email=user.email) or "/verify-notice"
        )

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
        return (
            jsonify({"ok": True, "redirect": (nxt_safe or _post_login_redirect(user))}),
            200,
        )

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
            "error",
            "auth.register",
            next=_next_url(_safe_fallback_shop()),
        )

    email = _safe_email(_safe_str_field("email", 255))
    password = (_safe_str_field("password", 256)).strip()
    name = _safe_str_field("name", 120)
    nxt_safe = _next_url("")

    if not _valid_email(email):
        return _json_or_redirect(
            "Email inválido.", "warning", "auth.register", next=nxt_safe
        )

    if len(password) < 8:
        return _json_or_redirect(
            "La contraseña debe tener al menos 8 caracteres.",
            "warning",
            "auth.register",
            next=nxt_safe,
        )

    if db.session.query(User).filter(User.email == email).first():
        return _json_or_redirect(
            "Ese email ya está registrado. Iniciá sesión.",
            "info",
            "auth.login",
            next=nxt_safe,
        )

    want_affiliate = _read_bool_field("want_affiliate")

    user = User(email=email)
    try:
        if hasattr(user, "name") and name:
            user.name = name
    except Exception:
        pass

    try:
        if hasattr(user, "is_admin"):
            user.is_admin = False
    except Exception:
        pass

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

    try:
        user.set_password(password)
    except Exception:
        return _json_or_redirect(
            "No se pudo crear la cuenta (password inválida). Probá otra.",
            "error",
            "auth.register",
            next=nxt_safe,
        )

    try:
        if hasattr(user, "is_active"):
            user.is_active = True
    except Exception:
        pass

    if hasattr(user, "email_verified"):
        try:
            user.email_verified = False
        except Exception:
            pass

    try:
        db.session.add(user)
        db.session.flush()
    except Exception:
        db.session.rollback()
        return _json_or_redirect(
            "Error creando la cuenta. Probá de nuevo.",
            "error",
            "auth.register",
            next=nxt_safe,
        )

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
        return _json_or_redirect(
            "Error creando la cuenta. Probá de nuevo.",
            "error",
            "auth.register",
            next=nxt_safe,
        )

    if (
        VERIFY_EMAIL_REQUIRED
        and not bool(getattr(user, "is_admin", False))
        and not bool(getattr(user, "is_owner", False))
    ):
        _send_email_verify(user, force=True)
        if _wants_json():
            return (
                jsonify(
                    {
                        "ok": True,
                        "redirect": (
                            _safe_url_for("auth.verify_notice", email=user.email)
                            or "/verify-notice"
                        ),
                    }
                ),
                200,
            )
        return redirect(
            _safe_url_for("auth.verify_notice", email=user.email) or "/verify-notice"
        )

    _set_session_user(user)

    if _wants_json():
        return (
            jsonify({"ok": True, "redirect": (nxt_safe or _post_login_redirect(user))}),
            200,
        )

    flash("Cuenta creada con éxito ✅", "success")
    return redirect(nxt_safe or _post_login_redirect(user))


# ------------------------------
# Verify notice screen
# ------------------------------
@auth_bp.get("/verify-notice")
def verify_notice():
    email = (request.args.get("email") or "").strip()
    if not email:
        email = (session.get("user_email") or "").strip()
    return render_template("auth/verify_notice.html", email=email)


# ------------------------------
# Resend verification (HTML/JSON)
# ------------------------------
@auth_bp.post("/resend-verification")
def resend_verification():
    if not _csrf_ok_for_json():
        return _json_or_redirect(
            "Solicitud inválida (CSRF). Recargá e intentá de nuevo.",
            "error",
            "auth.verify_notice",
            email="",
        )

    data = _safe_get_json()
    email = _safe_email(_safe_str_field("email", 255) or str(data.get("email") or ""))

    if not _valid_email(email):
        return _json_or_redirect(
            "Email inválido.", "error", "auth.verify_notice", email=""
        )

    ok_rl, left = _rate_limit_email_ok("rl:resend", email, RESEND_VERIFY_COOLDOWN_SEC)
    if not ok_rl:
        if _wants_json():
            return (
                jsonify(
                    {
                        "ok": False,
                        "message": f"Te lo enviamos hace poco. Esperá {left}s y reintentá.",
                        "retry_after": left,
                    }
                ),
                429,
            )
        return _json_or_redirect(
            "Te lo enviamos hace poco. Esperá 1 minuto y reintentá.",
            "warning",
            "auth.verify_notice",
            email=email,
        )

    user = db.session.query(User).filter(User.email == email).first()

    if not user:
        # neutro (no filtra)
        return _json_or_redirect(
            "Si el email existe, te enviamos el enlace.",
            "info",
            "auth.verify_notice",
            email=email,
        )

    if _user_is_verified(user):
        return _json_or_redirect(
            "Tu email ya está verificado ✅ Ya podés iniciar sesión.",
            "success",
            "auth.login",
        )

    ok = _send_email_verify(user, force=True)
    if not ok:
        return _json_or_redirect(
            "No se pudo reenviar ahora. Probá de nuevo en 1 minuto.",
            "warning",
            "auth.verify_notice",
            email=email,
        )

    return _json_or_redirect(
        "Listo ✅ Te reenviamos el enlace de verificación.",
        "success",
        "auth.verify_notice",
        email=email,
    )


# ------------------------------
# Resend verification (JSON-only)
# ------------------------------
@auth_bp.post("/resend-verification-json")
def resend_verification_json():
    # Fuerza JSON siempre
    if not _csrf_ok_for_json():
        return jsonify({"ok": False, "message": "Solicitud inválida (CSRF)."}), 400

    data = _safe_get_json()
    email = _safe_email(str(data.get("email") or ""))

    if not _valid_email(email):
        return jsonify({"ok": False, "message": "Email inválido."}), 400

    ok_rl, left = _rate_limit_email_ok("rl:resend", email, RESEND_VERIFY_COOLDOWN_SEC)
    if not ok_rl:
        return (
            jsonify(
                {
                    "ok": False,
                    "message": f"Te lo enviamos hace poco. Esperá {left}s y reintentá.",
                    "retry_after": left,
                }
            ),
            429,
        )

    user = db.session.query(User).filter(User.email == email).first()

    if not user:
        return (
            jsonify(
                {"ok": True, "message": "Si el email existe, te enviamos el enlace."}
            ),
            200,
        )

    if _user_is_verified(user):
        return (
            jsonify(
                {
                    "ok": True,
                    "message": "Tu email ya está verificado ✅ Ya podés iniciar sesión.",
                }
            ),
            200,
        )

    ok = _send_email_verify(user, force=True)
    if not ok:
        return (
            jsonify(
                {"ok": False, "message": "No se pudo reenviar ahora. Probá más tarde."}
            ),
            503,
        )

    return (
        jsonify(
            {
                "ok": True,
                "message": "Listo ✅ Te reenviamos el enlace de verificación.",
                "retry_after": RESEND_VERIFY_COOLDOWN_SEC,
            }
        ),
        200,
    )


# ------------------------------
# Verify email token
# ------------------------------
@auth_bp.get("/verify-email/<token>")
def verify_email(token: str):
    data, reason = _read_verify_token(token or "", max_age=VERIFY_TOKEN_MAX_AGE_SEC)
    if not data:
        if reason == "expired":
            flash("El enlace expiró. Pedí uno nuevo.", "error")
        else:
            flash("El enlace es inválido. Pedí uno nuevo.", "error")
        return redirect(_safe_url_for("auth.verify_notice") or "/verify-notice")

    uid = data.get("uid")
    email = (data.get("email") or "").lower().strip()

    try:
        uid_int = int(uid)
    except Exception:
        flash("Enlace inválido. Pedí uno nuevo.", "error")
        return redirect(
            _safe_url_for("auth.verify_notice", email=email) or "/verify-notice"
        )

    user = db.session.get(User, uid_int)
    if not user or (getattr(user, "email", "") or "").lower().strip() != email:
        flash("Enlace inválido. Pedí uno nuevo.", "error")
        return redirect(
            _safe_url_for("auth.verify_notice", email=email) or "/verify-notice"
        )

    if _user_is_verified(user):
        flash("Tu email ya estaba verificado ✅", "success")
        return redirect(_safe_url_for("auth.login") or "/login")

    _set_user_verified(user)
    _commit_safe()

    flash("Email verificado ✅ Ya podés iniciar sesión.", "success")
    return redirect(_safe_url_for("auth.login") or "/login")


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
        u = _safe_url_for(ep)
        if u:
            return redirect(u)
    return redirect("/")


__all__ = ["auth_bp"]
