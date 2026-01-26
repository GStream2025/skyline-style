from __future__ import annotations

import re
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional, Tuple

from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, session, url_for

from app.models import User, db

profile_bp = Blueprint("profile", __name__, url_prefix="/account", template_folder="../templates")

_TRUE = {"1", "true", "yes", "y", "on"}
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PHONE_RE = re.compile(r"^[0-9+() \-]{6,40}$")

RL_PROFILE_LIMIT = 20
RL_PROFILE_WINDOW = 60
RL_EMAIL_LIMIT = 8
RL_EMAIL_WINDOW = 60
RL_PASSWORD_LIMIT = 6
RL_PASSWORD_WINDOW = 120

CSRF_SESSION_KEY = "csrf_token"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


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
    resp = jsonify(payload)
    resp.status_code = int(status)
    return resp


def _json_or_redirect(payload: Dict[str, Any], endpoint: str, **kwargs):
    if _wants_json():
        return _json(payload, int(payload.get("status", 200)))
    return redirect(url_for(endpoint, **kwargs))


def _client_ip() -> str:
    xff = (request.headers.get("X-Forwarded-For") or "").strip()
    if xff:
        return xff.split(",")[0].strip()[:80] or "unknown"
    return (request.remote_addr or "unknown")[:80]


def _rl_store() -> Dict[str, Tuple[float, int]]:
    ext = current_app.extensions.get("profile_rl")
    if not isinstance(ext, dict):
        ext = {}
        current_app.extensions["profile_rl"] = ext
    return ext  # type: ignore[return-value]


def _rate_limit(key: str, limit: int, window_seconds: int) -> bool:
    store = _rl_store()
    now = time.time()
    reset_ts, count = store.get(key, (now + float(window_seconds), 0))

    try:
        reset_ts_f = float(reset_ts)
        count_i = int(count)
    except Exception:
        reset_ts_f, count_i = now + float(window_seconds), 0

    if now > reset_ts_f:
        reset_ts_f, count_i = now + float(window_seconds), 0

    count_i += 1
    store[key] = (reset_ts_f, count_i)
    return count_i <= int(limit)


def _rate_limit_or_429(bucket: str, limit: int, window_seconds: int):
    ip = _client_ip()
    uid = session.get("user_id") or "anon"
    key = f"{bucket}:{ip}:{uid}"
    if _rate_limit(key, limit=limit, window_seconds=window_seconds):
        return None

    if _wants_json():
        return _json({"ok": False, "error": "too_many_requests"}, 429)

    flash("Demasiados intentos. Esperá un minuto y probá de nuevo.", "warning")
    return redirect(url_for("profile.profile_home"))


def _soft_logout() -> None:
    for k in ("user_id", "user_email", "is_admin"):
        session.pop(k, None)
    session.modified = True


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


def _ensure_csrf() -> str:
    tok = session.get(CSRF_SESSION_KEY)
    if isinstance(tok, str) and tok.strip():
        return tok.strip()
    tok = secrets.token_urlsafe(32)
    session[CSRF_SESSION_KEY] = tok
    session.modified = True
    return tok


def _check_csrf() -> bool:
    token = (session.get(CSRF_SESSION_KEY) or "").strip()
    if not token:
        return False

    got = (
        (request.headers.get("X-CSRF-Token") or "")
        or (request.form.get("csrf_token") or "")
        or ((request.get_json(silent=True) or {}).get("csrf_token") if request.is_json else "")
        or ""
    )
    got = str(got).strip()
    if not got:
        return False

    try:
        return secrets.compare_digest(token, got)
    except Exception:
        return token == got


def _csrf_required() -> Optional[Any]:
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if not _check_csrf():
            if _wants_json():
                return _json({"ok": False, "error": "csrf_invalid"}, 400)
            flash("Token inválido. Recargá la página e intentá de nuevo.", "warning")
            return redirect(url_for("profile.profile_home"))
    return None


def _clean_str(v: Any, max_len: int) -> Optional[str]:
    if v is None:
        return None
    s = v.strip() if isinstance(v, str) else str(v).strip()
    if not s:
        return None
    return s[:max_len]


def _clean_country(v: Any) -> Optional[str]:
    s = _clean_str(v, 8)
    if not s:
        return None
    s = s.upper()
    return s[:2] if len(s) >= 2 else None


def _validate_email(v: Any) -> Tuple[bool, str]:
    s = ("" if v is None else str(v)).strip().lower()
    if not s:
        return False, "Email requerido."
    if len(s) > 254:
        return False, "Email demasiado largo."
    if not EMAIL_RE.match(s):
        return False, "Email inválido."
    return True, s[:255]


def _validate_phone(v: Any) -> Optional[str]:
    s = _clean_str(v, 80)
    if not s:
        return None
    s = s[:40]
    if PHONE_RE.match(s):
        return s
    return s


def _read_payload() -> Dict[str, Any]:
    ctype = (request.headers.get("Content-Type") or "").lower()
    if ctype.startswith("application/json"):
        data = request.get_json(silent=True)
        return dict(data) if isinstance(data, Mapping) else {}
    return {k: v for k, v in (request.form or {}).items()}


def _commit_or_fail(label: str) -> bool:
    try:
        db.session.commit()
        return True
    except Exception as exc:
        current_app.logger.exception("%s commit failed: %s", label, exc)
        try:
            db.session.rollback()
        except Exception:
            pass
        return False


def _set_if_has(obj: Any, attr: str, value: Any) -> bool:
    if not hasattr(obj, attr):
        return False
    cur = getattr(obj, attr, None)
    if cur == value:
        return False
    setattr(obj, attr, value)
    return True


def _bool_from_any(v: Any) -> Optional[bool]:
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if not s:
        return None
    if s in _TRUE:
        return True
    if s in {"0", "false", "no", "n", "off"}:
        return False
    return None


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
    return render_template("account/profile.html", user=user, csrf_token=csrf, is_admin=_is_admin_session())


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

    email_opt_in = _bool_from_any(payload.get("email_opt_in"))

    changed = False
    changed |= _set_if_has(user, "name", name)
    changed |= _set_if_has(user, "phone", phone)
    changed |= _set_if_has(user, "country", country)
    changed |= _set_if_has(user, "city", city)

    if email_opt_in is not None and hasattr(user, "email_opt_in"):
        changed |= _set_if_has(user, "email_opt_in", bool(email_opt_in))
        if bool(email_opt_in) and hasattr(user, "email_opt_in_at"):
            _set_if_has(user, "email_opt_in_at", _utcnow())

    if changed and hasattr(user, "updated_at"):
        _set_if_has(user, "updated_at", _utcnow())

    if not changed:
        if _wants_json():
            return _json({"ok": True, "updated": False, "message": "no_changes"}, 200)
        flash("No había cambios para guardar.", "info")
        return redirect(url_for("profile.profile_home"))

    if not _commit_or_fail("profile_update"):
        return _json_or_redirect({"ok": False, "error": "save_failed", "status": 500}, "profile.profile_home")

    if _wants_json():
        return _json({"ok": True, "updated": True}, 200)

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
    ok, out = _validate_email(payload.get("email"))
    if not ok:
        return _json_or_redirect({"ok": False, "error": out, "status": 400}, "profile.profile_home")

    new_email = out
    cur_email = (getattr(user, "email", "") or "").strip().lower()
    if cur_email == new_email:
        return _json_or_redirect({"ok": True, "message": "same_email", "status": 200}, "profile.profile_home")

    try:
        exists = db.session.query(User).filter(User.email == new_email).first()
    except Exception:
        current_app.logger.exception("profile_email: query failed")
        return _json_or_redirect({"ok": False, "error": "query_failed", "status": 500}, "profile.profile_home")

    if exists:
        return _json_or_redirect({"ok": False, "error": "Ese email ya está en uso.", "status": 409}, "profile.profile_home")

    _set_if_has(user, "email", new_email)
    if hasattr(user, "updated_at"):
        _set_if_has(user, "updated_at", _utcnow())

    if not _commit_or_fail("profile_email"):
        return _json_or_redirect({"ok": False, "error": "save_failed", "status": 500}, "profile.profile_home")

    session["user_email"] = new_email
    session.modified = True

    if _wants_json():
        return _json({"ok": True, "email_updated": True}, 200)

    flash("Email actualizado ✅", "success")
    return redirect(url_for("profile.profile_home"))


@profile_bp.post("/profile/password")
def profile_change_password():
    guard = _login_required()
    if guard:
        return guard

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
    current_pw = (payload.get("current_password") or "").strip() if isinstance(payload.get("current_password"), str) else str(payload.get("current_password") or "").strip()
    new_pw = (payload.get("new_password") or "").strip() if isinstance(payload.get("new_password"), str) else str(payload.get("new_password") or "").strip()
    new_pw2 = (payload.get("new_password_2") or "").strip() if isinstance(payload.get("new_password_2"), str) else str(payload.get("new_password_2") or "").strip()

    if not current_pw:
        return _json_or_redirect({"ok": False, "error": "Ingresá tu contraseña actual.", "status": 400}, "profile.profile_home")

    try:
        ok_cur = bool(user.check_password(current_pw))
    except Exception:
        ok_cur = False

    if not ok_cur:
        return _json_or_redirect({"ok": False, "error": "Tu contraseña actual no coincide.", "status": 400}, "profile.profile_home")

    if len(new_pw) < 8:
        return _json_or_redirect({"ok": False, "error": "La nueva contraseña debe tener al menos 8 caracteres.", "status": 400}, "profile.profile_home")

    if new_pw != new_pw2:
        return _json_or_redirect({"ok": False, "error": "La confirmación no coincide.", "status": 400}, "profile.profile_home")

    try:
        if bool(user.check_password(new_pw)):
            return _json_or_redirect({"ok": False, "error": "La nueva contraseña no puede ser igual a la anterior.", "status": 400}, "profile.profile_home")
    except Exception:
        pass

    try:
        user.set_password(new_pw)
    except Exception:
        return _json_or_redirect({"ok": False, "error": "No se pudo actualizar la contraseña.", "status": 500}, "profile.profile_home")

    if hasattr(user, "updated_at"):
        _set_if_has(user, "updated_at", _utcnow())

    if not _commit_or_fail("profile_password"):
        return _json_or_redirect({"ok": False, "error": "save_failed", "status": 500}, "profile.profile_home")

    if _wants_json():
        return _json({"ok": True, "password_updated": True}, 200)

    flash("Contraseña actualizada ✅", "success")
    return redirect(url_for("profile.profile_home"))


@profile_bp.get("/profile/csrf")
def profile_csrf_token():
    guard = _login_required()
    if guard:
        return guard
    token = _ensure_csrf()
    return _json({"ok": True, "csrf_token": token}, 200)


__all__ = ["profile_bp"]
