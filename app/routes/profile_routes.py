# app/routes/profile_routes.py
from __future__ import annotations

import re
import secrets
import time
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple, Callable

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
    current_app,
    jsonify,
)

from app.models import db, User  # ✅ HUB único


# ============================================================
# Blueprint
# ============================================================

profile_bp = Blueprint(
    "profile",
    __name__,
    url_prefix="/account",
    template_folder="../templates",
)

# ============================================================
# Consts / Regex
# ============================================================

_TRUE = {"1", "true", "yes", "y", "on"}
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PHONE_RE = re.compile(r"^[0-9+() \-]{6,40}$")

# rate limit
RL_PROFILE_LIMIT = 20     # hits
RL_PROFILE_WINDOW = 60    # seconds
RL_EMAIL_LIMIT = 8
RL_EMAIL_WINDOW = 60
RL_PASSWORD_LIMIT = 6
RL_PASSWORD_WINDOW = 120


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ============================================================
# Content negotiation
# ============================================================

def _wants_json() -> bool:
    accept = (request.headers.get("Accept") or "").lower()
    fmt = (request.args.get("format") or "").lower()
    xrw = (request.headers.get("X-Requested-With") or "").lower()
    ctype = (request.headers.get("Content-Type") or "").lower()
    return (
        "application/json" in accept
        or fmt == "json"
        or xrw == "xmlhttprequest"
        or ctype.startswith("application/json")
    )


def _json(payload: Dict[str, Any], status: int = 200):
    return jsonify(payload), status


def _json_or_redirect(payload: Dict[str, Any], endpoint: str, **kwargs):
    if _wants_json():
        return _json(payload, int(payload.get("status", 200)))
    return redirect(url_for(endpoint, **kwargs))


# ============================================================
# Rate limit (sin dependencias)
# ============================================================

def _client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _rl_store() -> Dict[str, Tuple[float, int]]:
    ext = current_app.extensions.setdefault("profile_rl", {})
    if not isinstance(ext, dict):
        current_app.extensions["profile_rl"] = {}
    return current_app.extensions["profile_rl"]  # type: ignore


def _rate_limit(key: str, limit: int, window_seconds: int) -> bool:
    store = _rl_store()
    now = time.time()
    reset_ts, count = store.get(key, (now + window_seconds, 0))

    if now > reset_ts:
        reset_ts, count = now + window_seconds, 0

    count += 1
    store[key] = (reset_ts, count)
    return count <= limit


def _rate_limit_or_429(bucket: str, limit: int, window_seconds: int):
    ip = _client_ip()
    uid = session.get("user_id") or "anon"
    key = f"{bucket}:{ip}:{uid}"
    if _rate_limit(key, limit=limit, window_seconds=window_seconds):
        return None
    return _json({"ok": False, "error": "too_many_requests"}, 429) if _wants_json() else (
        flash("Demasiados intentos. Esperá un minuto y probá de nuevo.", "warning") or redirect(url_for("profile.profile_home"))
    )


# ============================================================
# Auth helpers
# ============================================================

def _login_required() -> Optional[Any]:
    if session.get("user_id"):
        return None
    if _wants_json():
        return _json({"ok": False, "error": "auth_required"}, 401)
    flash("Iniciá sesión para continuar.", "warning")
    return redirect(url_for("auth.login", next=request.path))


def _current_user() -> Optional[User]:
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        return db.session.get(User, int(uid))
    except Exception:
        return None


def _is_admin_session() -> bool:
    v = session.get("is_admin", False)
    if isinstance(v, str):
        return v.strip().lower() in _TRUE
    return bool(v)


def _soft_logout() -> None:
    """
    No borra TODO el session, solo lo necesario para que no quede roto.
    """
    for k in ("user_id", "user_email", "is_admin"):
        session.pop(k, None)


# ============================================================
# CSRF (sin Flask-WTF)
# ============================================================

def _ensure_csrf() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def _check_csrf() -> bool:
    token = (session.get("csrf_token") or "").strip()
    got = (
        (request.headers.get("X-CSRF-Token") or "")
        or (request.form.get("csrf_token") or "")
        or ((request.get_json(silent=True) or {}).get("csrf_token") if request.is_json else "")
        or ""
    )
    got = str(got).strip()
    return bool(token) and bool(got) and secrets.compare_digest(token, got)


def _csrf_required() -> Optional[Any]:
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if not _check_csrf():
            if _wants_json():
                return _json({"ok": False, "error": "csrf_invalid"}, 400)
            flash("Token inválido. Recargá la página e intentá de nuevo.", "warning")
            return redirect(url_for("profile.profile_home"))
    return None


# ============================================================
# Sanitizers / Validators
# ============================================================

def _clean_str(v: Optional[str], max_len: int) -> Optional[str]:
    if v is None:
        return None
    v = v.strip()
    if not v:
        return None
    return v[:max_len]


def _clean_country(v: Optional[str]) -> Optional[str]:
    if not v:
        return None
    v = v.strip().upper()
    return v[:2] if len(v) >= 2 else None


def _validate_email(v: str) -> Tuple[bool, str]:
    v = (v or "").strip().lower()
    if not v:
        return False, "Email requerido."
    if len(v) > 254:
        return False, "Email demasiado largo."
    if not EMAIL_RE.match(v):
        return False, "Email inválido."
    return True, v[:255]


def _validate_phone(v: Optional[str]) -> Optional[str]:
    if not v:
        return None
    v = v.strip()
    if not v:
        return None
    if not PHONE_RE.match(v):
        return v[:40]
    return v[:40]


def _read_payload() -> Dict[str, Any]:
    """
    Si viene JSON, usamos JSON. Sino form.
    Evita mezclar.
    """
    if (request.headers.get("Content-Type") or "").lower().startswith("application/json"):
        return request.get_json(silent=True) or {}
    return dict(request.form or {})


def _commit_or_fail(log_label: str) -> bool:
    try:
        db.session.commit()
        return True
    except Exception as exc:
        current_app.logger.exception("%s: commit failed: %s", log_label, exc)
        db.session.rollback()
        return False


def _set_if_has(obj: Any, attr: str, value: Any) -> bool:
    """
    Setea si existe y si cambia.
    Devuelve True si hubo cambio.
    """
    if not hasattr(obj, attr):
        return False
    cur = getattr(obj, attr, None)
    if cur == value:
        return False
    setattr(obj, attr, value)
    return True


# ============================================================
# Routes
# ============================================================

@profile_bp.get("/profile")
def profile_home():
    guard = _login_required()
    if guard:
        return guard

    user = _current_user()
    if not user:
        _soft_logout()
        flash("Sesión inválida. Volvé a iniciar sesión.", "warning")
        return redirect(url_for("auth.login", next=request.path))

    csrf = _ensure_csrf()

    return render_template(
        "account/profile.html",
        user=user,
        csrf_token=csrf,
        is_admin=_is_admin_session(),
    )


@profile_bp.post("/profile/update")
def profile_update():
    guard = _login_required()
    if guard:
        return guard

    rl = _rate_limit_or_429("profile_update", RL_PROFILE_LIMIT, RL_PROFILE_WINDOW)
    if rl:
        return rl

    gate = _csrf_required()
    if gate:
        return gate

    user = _current_user()
    if not user:
        _soft_logout()
        return _json_or_redirect({"ok": False, "error": "session_invalid", "status": 401}, "auth.login")

    payload = _read_payload()

    name = _clean_str(payload.get("name"), 120)
    phone = _validate_phone(payload.get("phone"))
    country = _clean_country(payload.get("country"))
    city = _clean_str(payload.get("city"), 80)

    email_opt_in_raw = payload.get("email_opt_in")
    email_opt_in: Optional[bool] = None
    if email_opt_in_raw is not None:
        if isinstance(email_opt_in_raw, bool):
            email_opt_in = email_opt_in_raw
        else:
            email_opt_in = str(email_opt_in_raw).strip().lower() in _TRUE

    changed = False
    changed |= _set_if_has(user, "name", name)
    changed |= _set_if_has(user, "phone", phone)
    changed |= _set_if_has(user, "country", country)
    changed |= _set_if_has(user, "city", city)

    if email_opt_in is not None and hasattr(user, "email_opt_in"):
        changed |= _set_if_has(user, "email_opt_in", bool(email_opt_in))
        if bool(email_opt_in) and hasattr(user, "email_opt_in_at"):
            _set_if_has(user, "email_opt_in_at", _utcnow())

    # auditoría opcional
    if changed and hasattr(user, "updated_at"):
        _set_if_has(user, "updated_at", _utcnow())

    if not changed:
        if _wants_json():
            return _json({"ok": True, "updated": False, "message": "no_changes"})
        flash("No había cambios para guardar.", "info")
        return redirect(url_for("profile.profile_home"))

    if not _commit_or_fail("profile_update"):
        return _json_or_redirect({"ok": False, "error": "save_failed", "status": 500}, "profile.profile_home")

    if _wants_json():
        return _json({"ok": True, "updated": True})

    flash("Perfil actualizado ✅", "success")
    return redirect(url_for("profile.profile_home"))


@profile_bp.post("/profile/email")
def profile_change_email():
    guard = _login_required()
    if guard:
        return guard

    rl = _rate_limit_or_429("profile_email", RL_EMAIL_LIMIT, RL_EMAIL_WINDOW)
    if rl:
        return rl

    gate = _csrf_required()
    if gate:
        return gate

    user = _current_user()
    if not user:
        _soft_logout()
        return _json_or_redirect({"ok": False, "error": "session_invalid", "status": 401}, "auth.login")

    payload = _read_payload()
    new_email_raw = str(payload.get("email") or "").strip()

    ok, out = _validate_email(new_email_raw)
    if not ok:
        return _json_or_redirect({"ok": False, "error": out, "status": 400}, "profile.profile_home")

    new_email = out

    if (user.email or "").lower() == new_email:
        return _json_or_redirect({"ok": True, "message": "same_email", "status": 200}, "profile.profile_home")

    # duplicado
    try:
        exists = db.session.query(User).filter(User.email == new_email).first()
    except Exception:
        current_app.logger.exception("Email change: query failed")
        return _json_or_redirect({"ok": False, "error": "query_failed", "status": 500}, "profile.profile_home")

    if exists:
        return _json_or_redirect({"ok": False, "error": "Ese email ya está en uso.", "status": 409}, "profile.profile_home")

    _set_if_has(user, "email", new_email)

    if not _commit_or_fail("profile_email"):
        return _json_or_redirect({"ok": False, "error": "save_failed", "status": 500}, "profile.profile_home")

    session["user_email"] = new_email

    if _wants_json():
        return _json({"ok": True, "email_updated": True})

    flash("Email actualizado ✅", "success")
    return redirect(url_for("profile.profile_home"))


@profile_bp.post("/profile/password")
def profile_change_password():
    guard = _login_required()
    if guard:
        return guard

    # Más estricto para password
    rl = _rate_limit_or_429("profile_password", RL_PASSWORD_LIMIT, RL_PASSWORD_WINDOW)
    if rl:
        return rl

    gate = _csrf_required()
    if gate:
        return gate

    user = _current_user()
    if not user:
        _soft_logout()
        return _json_or_redirect({"ok": False, "error": "session_invalid", "status": 401}, "auth.login")

    payload = _read_payload()
    current_pw = str(payload.get("current_password") or "").strip()
    new_pw = str(payload.get("new_password") or "").strip()
    new_pw2 = str(payload.get("new_password_2") or "").strip()

    if not current_pw or not user.check_password(current_pw):
        return _json_or_redirect({"ok": False, "error": "Tu contraseña actual no coincide.", "status": 400}, "profile.profile_home")

    if len(new_pw) < 8:
        return _json_or_redirect({"ok": False, "error": "La nueva contraseña debe tener al menos 8 caracteres.", "status": 400}, "profile.profile_home")

    if new_pw != new_pw2:
        return _json_or_redirect({"ok": False, "error": "La confirmación no coincide.", "status": 400}, "profile.profile_home")

    if user.check_password(new_pw):
        return _json_or_redirect({"ok": False, "error": "La nueva contraseña no puede ser igual a la anterior.", "status": 400}, "profile.profile_home")

    user.set_password(new_pw)

    if not _commit_or_fail("profile_password"):
        return _json_or_redirect({"ok": False, "error": "save_failed", "status": 500}, "profile.profile_home")

    if _wants_json():
        return _json({"ok": True, "password_updated": True})

    flash("Contraseña actualizada ✅", "success")
    return redirect(url_for("profile.profile_home"))


@profile_bp.get("/profile/csrf")
def profile_csrf_token():
    guard = _login_required()
    if guard:
        return guard
    token = _ensure_csrf()
    return _json({"ok": True, "csrf_token": token})


__all__ = ["profile_bp"]
