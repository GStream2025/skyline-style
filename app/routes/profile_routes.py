from __future__ import annotations

import re
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional, Tuple

from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, session, url_for
from sqlalchemy import func, select

from app.models import User, db

profile_bp = Blueprint("profile", __name__, url_prefix="/account", template_folder="../templates")
profile_bp.strict_slashes = False

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off"}

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PHONE_RE = re.compile(r"^[0-9+() \-]{6,40}$")

RL_PROFILE_LIMIT = 20
RL_PROFILE_WINDOW = 60
RL_EMAIL_LIMIT = 8
RL_EMAIL_WINDOW = 60
RL_PASSWORD_LIMIT = 6
RL_PASSWORD_WINDOW = 120

CSRF_SESSION_KEY = "csrf_token"
_RL_SESSION_KEY = "profile_rl_v1"
_MAX_RL_KEYS = 200


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _now() -> int:
    return int(time.time())


def _safe_str(v: Any, *, max_len: int = 500) -> str:
    if v is None:
        return ""
    s = v.strip() if isinstance(v, str) else str(v).strip()
    s = s.replace("\x00", "").replace("\u200b", "").replace("\r", "").replace("\n", "")
    return s[:max_len]


def _wants_json() -> bool:
    try:
        if request.is_json:
            return True
    except Exception:
        pass
    accept = _safe_str(request.headers.get("Accept") or "", max_len=200).lower()
    fmt = _safe_str(request.args.get("format") or "", max_len=40).lower()
    xrw = _safe_str(request.headers.get("X-Requested-With") or "", max_len=60).lower()
    ctype = _safe_str(request.headers.get("Content-Type") or "", max_len=120).lower()
    return (
        "application/json" in accept
        or "text/json" in accept
        or fmt == "json"
        or xrw == "xmlhttprequest"
        or ctype.startswith("application/json")
    )


def _json(payload: Dict[str, Any], status: int = 200):
    resp = jsonify(payload)
    resp.status_code = int(status)
    if resp.status_code == 429 and "retry_after" in payload:
        try:
            resp.headers["Retry-After"] = str(int(payload.get("retry_after") or 0))
        except Exception:
            pass
    return resp


def _json_or_redirect(payload: Dict[str, Any], endpoint: str, **kwargs):
    if _wants_json():
        return _json(payload, int(payload.get("status", 200)))
    return redirect(url_for(endpoint, **kwargs), code=302)


def _no_store(resp):
    try:
        resp.headers.setdefault("Cache-Control", "no-store, max-age=0, must-revalidate")
        resp.headers.setdefault("Pragma", "no-cache")
        resp.headers.setdefault("Expires", "0")
        resp.headers.setdefault("Vary", "Cookie")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("X-Frame-Options", "DENY")
    except Exception:
        pass
    return resp


def _client_ip() -> str:
    xff = _safe_str(request.headers.get("X-Forwarded-For") or "", max_len=400)
    if xff:
        return _safe_str(xff.split(",")[0].strip(), max_len=80) or "unknown"
    return _safe_str(request.remote_addr or "unknown", max_len=80) or "unknown"


def _rl_store() -> Dict[str, Dict[str, Any]]:
    store = session.get(_RL_SESSION_KEY)
    if not isinstance(store, dict):
        store = {}
    # limpieza rápida para evitar crecimiento
    if len(store) > _MAX_RL_KEYS:
        items = []
        for k, v in list(store.items()):
            if isinstance(v, dict):
                try:
                    items.append((int(v.get("t") or 0), str(k)))
                except Exception:
                    items.append((0, str(k)))
        items.sort()
        for _, k in items[: max(0, len(store) - _MAX_RL_KEYS)]:
            store.pop(k, None)
    session[_RL_SESSION_KEY] = store
    session.modified = True
    return store  # type: ignore[return-value]


def _rate_limit(bucket: str, limit: int, window_seconds: int) -> Tuple[bool, int]:
    now = _now()
    ip = _client_ip()
    uid = str(session.get("user_id") or "anon")
    key = f"{bucket}:{ip}:{uid}"

    store = _rl_store()
    b = store.get(key)
    if not isinstance(b, dict):
        store[key] = {"t": now, "n": 1}
        session[_RL_SESSION_KEY] = store
        session.modified = True
        return True, 0

    try:
        t0 = int(b.get("t", now) or now)
    except Exception:
        t0 = now
    try:
        n = int(b.get("n", 0) or 0)
    except Exception:
        n = 0

    elapsed = now - t0
    if elapsed >= int(window_seconds):
        store[key] = {"t": now, "n": 1}
        session[_RL_SESSION_KEY] = store
        session.modified = True
        return True, 0

    if n >= int(limit):
        retry = int(max(1, int(window_seconds) - elapsed))
        return False, retry

    b["n"] = n + 1
    store[key] = b
    session[_RL_SESSION_KEY] = store
    session.modified = True
    return True, 0


def _rate_limit_or_429(bucket: str, limit: int, window_seconds: int):
    ok, retry = _rate_limit(bucket, limit=limit, window_seconds=window_seconds)
    if ok:
        return None

    if _wants_json():
        return _json({"ok": False, "error": "too_many_requests", "retry_after": retry}, 429)

    flash("Demasiados intentos. Esperá un minuto y probá de nuevo.", "warning")
    r = redirect(url_for("profile.profile_home"), code=302)
    try:
        r.headers["Retry-After"] = str(int(retry))
    except Exception:
        pass
    return r


def _soft_logout() -> None:
    for k in ("user_id", "user_email", "is_admin", "role", "email_verified", "login_at", "login_nonce"):
        session.pop(k, None)
    session.modified = True


def _login_required() -> Optional[Any]:
    if session.get("user_id"):
        return None
    if _wants_json():
        return _json({"ok": False, "error": "auth_required"}, 401)
    flash("Iniciá sesión para continuar.", "warning")
    nxt = _safe_str(request.path or "/account/profile", max_len=300)
    # conectamos al GET correcto del módulo auth
    try:
        return redirect(url_for("auth.login_get", next=nxt), code=302)
    except Exception:
        return redirect(f"/auth/login?next={nxt}", code=302)


def _current_user() -> Optional[User]:
    try:
        uid = int(session.get("user_id") or 0)
    except Exception:
        uid = 0
    if uid <= 0:
        return None
    try:
        return db.session.get(User, uid)
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        return None


def _is_admin_session() -> bool:
    v = session.get("is_admin", False)
    if isinstance(v, str):
        return v.strip().lower() in _TRUE
    return bool(v)


def _ensure_csrf() -> str:
    tok = session.get(CSRF_SESSION_KEY)
    if isinstance(tok, str) and len(tok.strip()) >= 16:
        return tok.strip()
    tok = secrets.token_urlsafe(32)
    session[CSRF_SESSION_KEY] = tok
    session.modified = True
    return tok


def _rotate_csrf() -> None:
    try:
        session[CSRF_SESSION_KEY] = secrets.token_urlsafe(32)
        session.modified = True
    except Exception:
        pass


def _check_csrf() -> bool:
    token = _safe_str(session.get(CSRF_SESSION_KEY) or "", max_len=2048)
    if not token:
        return False

    got = _safe_str(request.headers.get("X-CSRF-Token") or "", max_len=2048)
    if not got:
        got = _safe_str(request.form.get("csrf_token") or "", max_len=2048)
    if not got:
        try:
            if request.is_json:
                j = request.get_json(silent=True) or {}
                if isinstance(j, dict):
                    got = _safe_str(j.get("csrf_token") or "", max_len=2048)
        except Exception:
            got = ""
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
            return redirect(url_for("profile.profile_home"), code=302)
    return None


def _clean_str(v: Any, max_len: int) -> Optional[str]:
    s = _safe_str(v, max_len=max_len)
    return s if s else None


def _clean_country(v: Any) -> Optional[str]:
    s = _clean_str(v, 8)
    if not s:
        return None
    s = s.upper()
    return s[:2] if len(s) >= 2 else None


def _validate_email(v: Any) -> Tuple[bool, str]:
    s = _safe_str(v, max_len=400).lower()
    if not s:
        return False, "Email requerido."
    if len(s) > 254:
        return False, "Email demasiado largo."
    if not EMAIL_RE.match(s):
        return False, "Email inválido."
    return True, s[:254]


def _validate_phone(v: Any) -> Optional[str]:
    s = _clean_str(v, 80)
    if not s:
        return None
    s = s[:40]
    if PHONE_RE.match(s):
        return s
    # si no matchea, igual guardamos versión “suave” (no rompe UX)
    return s


def _read_payload() -> Dict[str, Any]:
    ctype = _safe_str(request.headers.get("Content-Type") or "", max_len=120).lower()
    if ctype.startswith("application/json"):
        try:
            data = request.get_json(silent=True)
            return dict(data) if isinstance(data, Mapping) else {}
        except Exception:
            return {}
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
    s = _safe_str(v, max_len=32).lower()
    if not s:
        return None
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return None


def _user_password_check(user: Any, password: str) -> bool:
    pw = password or ""
    if not pw:
        return False
    try:
        fn = getattr(user, "check_password", None)
        if callable(fn):
            return bool(fn(pw))
    except Exception:
        pass
    try:
        from app.utils.password_engine import verify_and_maybe_rehash  # type: ignore
        stored = _safe_str(getattr(user, "password_hash", "") or getattr(user, "password", ""), max_len=4096)
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
        stored = _safe_str(getattr(user, "password_hash", "") or getattr(user, "password", ""), max_len=4096)
        return bool(stored) and bool(check_password_hash(stored, pw))
    except Exception:
        return False


def _user_password_set(user: Any, password: str) -> bool:
    pw = password or ""
    if len(pw) < 8 or len(pw) > 256:
        return False
    try:
        fn = getattr(user, "set_password", None)
        if callable(fn):
            fn(pw)
            return True
    except Exception:
        pass
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


@profile_bp.before_request
def _before():
    # asegura CSRF para forms
    _ensure_csrf()
    # POST/PUT/etc deben validarlo
    gate = _csrf_required()
    return gate


@profile_bp.after_request
def _after(resp):
    return _no_store(resp)


@profile_bp.get("/profile")
def profile_home():
    guard = _login_required()
    if guard:
        return guard

    user = _current_user()
    if not user:
        _soft_logout()
        flash("Sesión inválida. Volvé a iniciar sesión.", "warning")
        return _login_required()  # ya redirige correcto

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

    user = _current_user()
    if not user:
        _soft_logout()
        return _json_or_redirect({"ok": False, "error": "session_invalid", "status": 401}, "auth.login_get")

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
        return redirect(url_for("profile.profile_home"), code=302)

    if not _commit_or_fail("profile_update"):
        return _json_or_redirect({"ok": False, "error": "save_failed", "status": 500}, "profile.profile_home")

    if _wants_json():
        return _json({"ok": True, "updated": True}, 200)

    flash("Perfil actualizado ✅", "success")
    return redirect(url_for("profile.profile_home"), code=302)


@profile_bp.post("/profile/email")
def profile_change_email():
    guard = _login_required()
    if guard:
        return guard

    rl = _rate_limit_or_429("profile_email", RL_EMAIL_LIMIT, RL_EMAIL_WINDOW)
    if rl:
        return rl

    user = _current_user()
    if not user:
        _soft_logout()
        return _json_or_redirect({"ok": False, "error": "session_invalid", "status": 401}, "auth.login_get")

    payload = _read_payload()
    ok, out = _validate_email(payload.get("email"))
    if not ok:
        return _json_or_redirect({"ok": False, "error": out, "status": 400}, "profile.profile_home")

    new_email = out
    cur_email = _safe_str(getattr(user, "email", "") or "", max_len=254).lower()
    if cur_email == new_email:
        return _json_or_redirect({"ok": True, "message": "same_email", "status": 200}, "profile.profile_home")

    # existencia (case-insensitive)
    try:
        stmt = select(User.id).where(func.lower(User.email) == new_email)
        exists_id = db.session.execute(stmt).scalar_one_or_none()
    except Exception:
        current_app.logger.exception("profile_email: query failed")
        return _json_or_redirect({"ok": False, "error": "query_failed", "status": 500}, "profile.profile_home")

    if exists_id:
        return _json_or_redirect({"ok": False, "error": "Ese email ya está en uso.", "status": 409}, "profile.profile_home")

    _set_if_has(user, "email", new_email)
    if hasattr(user, "email_verified"):
        _set_if_has(user, "email_verified", False)
    if hasattr(user, "updated_at"):
        _set_if_has(user, "updated_at", _utcnow())

    if not _commit_or_fail("profile_email"):
        return _json_or_redirect({"ok": False, "error": "save_failed", "status": 500}, "profile.profile_home")

    session["user_email"] = new_email
    session.modified = True
    _rotate_csrf()

    if _wants_json():
        return _json({"ok": True, "email_updated": True}, 200)

    flash("Email actualizado ✅", "success")
    return redirect(url_for("profile.profile_home"), code=302)


@profile_bp.post("/profile/password")
def profile_change_password():
    guard = _login_required()
    if guard:
        return guard

    rl = _rate_limit_or_429("profile_password", RL_PASSWORD_LIMIT, RL_PASSWORD_WINDOW)
    if rl:
        return rl

    user = _current_user()
    if not user:
        _soft_logout()
        return _json_or_redirect({"ok": False, "error": "session_invalid", "status": 401}, "auth.login_get")

    payload = _read_payload()
    current_pw = _safe_str(payload.get("current_password") or "", max_len=512)
    new_pw = _safe_str(payload.get("new_password") or "", max_len=512)
    new_pw2 = _safe_str(payload.get("new_password_2") or "", max_len=512)

    if not current_pw:
        return _json_or_redirect({"ok": False, "error": "Ingresá tu contraseña actual.", "status": 400}, "profile.profile_home")

    if not _user_password_check(user, current_pw):
        return _json_or_redirect({"ok": False, "error": "Tu contraseña actual no coincide.", "status": 400}, "profile.profile_home")

    if len(new_pw) < 10:
        return _json_or_redirect({"ok": False, "error": "La nueva contraseña debe tener al menos 10 caracteres.", "status": 400}, "profile.profile_home")

    if new_pw != new_pw2:
        return _json_or_redirect({"ok": False, "error": "La confirmación no coincide.", "status": 400}, "profile.profile_home")

    # evita reusar misma contraseña (best-effort)
    try:
        if _user_password_check(user, new_pw):
            return _json_or_redirect({"ok": False, "error": "La nueva contraseña no puede ser igual a la anterior.", "status": 400}, "profile.profile_home")
    except Exception:
        pass

    if not _user_password_set(user, new_pw):
        return _json_or_redirect({"ok": False, "error": "No se pudo actualizar la contraseña.", "status": 500}, "profile.profile_home")

    if hasattr(user, "updated_at"):
        _set_if_has(user, "updated_at", _utcnow())

    if not _commit_or_fail("profile_password"):
        return _json_or_redirect({"ok": False, "error": "save_failed", "status": 500}, "profile.profile_home")

    _rotate_csrf()

    if _wants_json():
        return _json({"ok": True, "password_updated": True}, 200)

    flash("Contraseña actualizada ✅", "success")
    return redirect(url_for("profile.profile_home"), code=302)


@profile_bp.get("/profile/csrf")
def profile_csrf_token():
    guard = _login_required()
    if guard:
        return guard
    token = _ensure_csrf()
    return _json({"ok": True, "csrf_token": token}, 200)


__all__ = ["profile_bp"]
