from __future__ import annotations

import re
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional, Tuple, cast

from flask import Blueprint, Response, current_app, flash, jsonify, redirect, render_template, request, session, url_for
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from app.models import User, db

log = current_app.logger if hasattr(current_app, "logger") else None  # type: ignore

profile_bp = Blueprint("profile", __name__, url_prefix="/account", template_folder="../templates")
profile_bp.strict_slashes = False

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off", "unchecked"}

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_PHONE_RE = re.compile(r"^[0-9+() \-]{6,40}$")

CSRF_SESSION_KEY = "csrf_token"
_RL_SESSION_KEY = "profile_rl_v2"
_MAX_RL_KEYS = 220

RL_PROFILE_LIMIT = 20
RL_PROFILE_WINDOW = 60
RL_EMAIL_LIMIT = 8
RL_EMAIL_WINDOW = 60
RL_PASSWORD_LIMIT = 6
RL_PASSWORD_WINDOW = 120

_MAX_STR_80 = 80
_MAX_STR_120 = 120
_MAX_STR_254 = 254
_MAX_STR_512 = 512
_MAX_STR_2048 = 2048

_NO_STORE_HEADERS = {
    "Cache-Control": "no-store, max-age=0, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
    "Vary": "Cookie, Accept",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _now() -> int:
    return int(time.time())


def _norm(v: Any, *, max_len: int) -> str:
    if v is None:
        return ""
    s = v if isinstance(v, str) else str(v)
    s = s.replace("\x00", "").replace("\u200b", "").strip()
    s = s.replace("\r", "").replace("\n", "")
    if max_len <= 0:
        return s
    return s[:max_len]


def _bool(v: Any) -> Optional[bool]:
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    s = _norm(v, max_len=32).lower()
    if not s:
        return None
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return None


def _wants_json() -> bool:
    try:
        if request.is_json:
            return True
    except Exception:
        pass

    fmt = _norm(request.args.get("format") or "", max_len=16).lower()
    if fmt == "json":
        return True

    accept = _norm(request.headers.get("Accept") or "", max_len=200).lower()
    if "application/json" in accept or "text/json" in accept:
        return True

    xrw = _norm(request.headers.get("X-Requested-With") or "", max_len=60).lower()
    if xrw == "xmlhttprequest":
        return True

    ctype = _norm(request.headers.get("Content-Type") or "", max_len=120).lower()
    if ctype.startswith("application/json"):
        return True

    try:
        best = request.accept_mimetypes.best_match(["application/json", "text/html"])
        if best == "application/json" and request.accept_mimetypes[best] > request.accept_mimetypes["text/html"]:
            return True
    except Exception:
        pass
    return False


def _json(payload: Dict[str, Any], status: int = 200) -> Response:
    resp = jsonify(payload)
    resp.status_code = int(status)
    if resp.status_code == 429 and "retry_after" in payload:
        try:
            resp.headers["Retry-After"] = str(int(payload.get("retry_after") or 0))
        except Exception:
            pass
    return resp


def _flash(category: str, msg: str) -> None:
    try:
        flash(_norm(msg, max_len=220) or "OK", category)
    except Exception:
        pass


def _no_store(resp: Response) -> Response:
    try:
        for k, v in _NO_STORE_HEADERS.items():
            resp.headers.setdefault(k, v)
    except Exception:
        pass
    return resp


def _client_ip() -> str:
    xff = _norm(request.headers.get("X-Forwarded-For") or "", max_len=400)
    ip = ""
    if xff:
        ip = _norm(xff.split(",")[0].strip(), max_len=80)
    if not ip:
        ip = _norm(request.remote_addr or "unknown", max_len=80)
    return ip or "unknown"


def _rl_store() -> Dict[str, Dict[str, Any]]:
    store = session.get(_RL_SESSION_KEY)
    if not isinstance(store, dict):
        store = {}

    if store:
        cutoff = _now() - max(RL_PASSWORD_WINDOW, RL_PROFILE_WINDOW, RL_EMAIL_WINDOW) * 3
        for k in list(store.keys()):
            v = store.get(k)
            if not isinstance(v, dict):
                store.pop(k, None)
                continue
            try:
                t0 = int(v.get("t") or 0)
            except Exception:
                t0 = 0
            if t0 and t0 < cutoff:
                store.pop(k, None)

    if len(store) > _MAX_RL_KEYS:
        items: list[tuple[int, str]] = []
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
    return cast(Dict[str, Dict[str, Any]], store)


def _rate_limit(bucket: str, limit: int, window_seconds: int) -> Tuple[bool, int]:
    now = _now()
    uid = str(session.get("user_id") or "anon")
    key = f"{bucket}:{_client_ip()}:{uid}"

    store = _rl_store()
    b = store.get(key)
    if not isinstance(b, dict):
        store[key] = {"t": now, "n": 1}
        session.modified = True
        return True, 0

    try:
        t0 = int(b.get("t") or now)
    except Exception:
        t0 = now
    try:
        n = int(b.get("n") or 0)
    except Exception:
        n = 0

    elapsed = now - t0
    if elapsed >= int(window_seconds) or elapsed < 0:
        store[key] = {"t": now, "n": 1}
        session.modified = True
        return True, 0

    if n >= int(limit):
        retry = int(max(1, int(window_seconds) - elapsed))
        return False, retry

    b["n"] = n + 1
    store[key] = b
    session.modified = True
    return True, 0


def _rate_limit_or_fail(bucket: str, limit: int, window_seconds: int):
    ok, retry = _rate_limit(bucket, limit=limit, window_seconds=window_seconds)
    if ok:
        return None

    if _wants_json():
        return _json({"ok": False, "error": "too_many_requests", "retry_after": retry}, 429)

    _flash("warning", "Demasiados intentos. Esperá un minuto y probá de nuevo.")
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


def _login_required():
    uid = session.get("user_id")
    if uid:
        return None
    if _wants_json():
        return _json({"ok": False, "error": "auth_required"}, 401)

    _flash("warning", "Iniciá sesión para continuar.")
    nxt = _norm(request.path or "/account/profile", max_len=300)
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
    if isinstance(tok, str) and len(tok.strip()) >= 24:
        return tok.strip()
    tok = secrets.token_urlsafe(32)
    session[CSRF_SESSION_KEY] = tok
    session.modified = True
    return tok


def _rotate_csrf() -> None:
    session[CSRF_SESSION_KEY] = secrets.token_urlsafe(32)
    session.modified = True


def _safe_get_json() -> Dict[str, Any]:
    try:
        if request.is_json:
            j = request.get_json(silent=True) or {}
            return dict(j) if isinstance(j, Mapping) else {}
    except Exception:
        pass
    return {}


def _check_csrf() -> bool:
    token = _norm(session.get(CSRF_SESSION_KEY) or "", max_len=_MAX_STR_2048)
    if not token:
        return False

    got = _norm(request.headers.get("X-CSRF-Token") or "", max_len=_MAX_STR_2048)
    if not got:
        got = _norm(request.form.get("csrf_token") or "", max_len=_MAX_STR_2048)
    if not got:
        got = _norm(_safe_get_json().get("csrf_token") or "", max_len=_MAX_STR_2048)
    if not got:
        return False

    try:
        return secrets.compare_digest(token, got)
    except Exception:
        return token == got


def _csrf_required():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if not _check_csrf():
            if _wants_json():
                return _json({"ok": False, "error": "csrf_invalid"}, 400)
            _flash("warning", "Token inválido. Recargá la página e intentá de nuevo.")
            return redirect(url_for("profile.profile_home"), code=302)
    return None


def _read_payload() -> Dict[str, Any]:
    ctype = _norm(request.headers.get("Content-Type") or "", max_len=120).lower()
    if ctype.startswith("application/json"):
        return _safe_get_json()
    try:
        return {k: v for k, v in (request.form or {}).items()}
    except Exception:
        return {}


def _commit(label: str) -> bool:
    try:
        db.session.commit()
        return True
    except Exception as exc:
        try:
            current_app.logger.exception("%s commit failed: %s", label, exc)
        except Exception:
            pass
        try:
            db.session.rollback()
        except Exception:
            pass
        return False


def _set_if_has(obj: Any, attr: str, value: Any) -> bool:
    if not hasattr(obj, attr):
        return False
    try:
        cur = getattr(obj, attr, None)
        if cur == value:
            return False
        setattr(obj, attr, value)
        return True
    except Exception:
        return False


def _clean_str(v: Any, max_len: int) -> Optional[str]:
    s = _norm(v, max_len=max_len)
    return s if s else None


def _clean_country(v: Any) -> Optional[str]:
    s = _clean_str(v, 8)
    if not s:
        return None
    s2 = s.upper()
    if len(s2) < 2:
        return None
    return s2[:2]


def _validate_email(v: Any) -> Tuple[bool, str]:
    s = _norm(v, max_len=400).lower()
    if not s:
        return False, "Email requerido."
    if len(s) > _MAX_STR_254:
        return False, "Email demasiado largo."
    if not _EMAIL_RE.match(s):
        return False, "Email inválido."
    return True, s[:_MAX_STR_254]


def _validate_phone(v: Any) -> Optional[str]:
    s = _clean_str(v, 80)
    if not s:
        return None
    s2 = s[:40]
    if _PHONE_RE.match(s2):
        return s2
    return s2


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

        stored = _norm(getattr(user, "password_hash", "") or getattr(user, "password", ""), max_len=4096)
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
        try:
            secrets.compare_digest("a", "a" if ok else "b")
        except Exception:
            pass
        return bool(ok)
    except Exception:
        pass

    try:
        from werkzeug.security import check_password_hash  # type: ignore

        stored = _norm(getattr(user, "password_hash", "") or getattr(user, "password", ""), max_len=4096)
        ok = bool(stored) and bool(check_password_hash(stored, pw))
        try:
            secrets.compare_digest("a", "a" if ok else "b")
        except Exception:
            pass
        return ok
    except Exception:
        return False


def _user_password_set(user: Any, password: str) -> bool:
    pw = password or ""
    min_len = 10
    max_len = 256
    if len(pw) < min_len or len(pw) > max_len:
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

    try:
        if hasattr(user, "password_hash"):
            setattr(user, "password_hash", h)
            return True
        if hasattr(user, "password"):
            setattr(user, "password", h)
            return True
        setattr(user, "password_hash", h)
        return True
    except Exception:
        return False


def _password_is_reasonable(pw: str) -> bool:
    s = pw or ""
    if len(s) < 10 or len(s) > 256:
        return False
    bad = {"password", "password123", "12345678", "qwerty123", "admin12345"}
    if s.lower() in bad:
        return False
    has_letter = any(c.isalpha() for c in s)
    has_digit = any(c.isdigit() for c in s)
    return has_letter and has_digit


def _render_safe(template: str, **ctx: Any):
    try:
        return render_template(template, **ctx)
    except Exception:
        try:
            current_app.logger.exception("Template render failed: %s", template)
        except Exception:
            pass
        title = _norm(ctx.get("title") or "Perfil", max_len=80) or "Perfil"
        body = (
            "<!doctype html><html lang='es'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{title}</title></head>"
            "<body style='font-family:system-ui;padding:24px;max-width:920px;margin:0 auto'>"
            f"<h1 style='margin:0 0 10px'>{title}</h1>"
            "<p style='opacity:.75;margin:0'>No se pudo renderizar el template. Revisá logs.</p>"
            "</body></html>"
        )
        return body, 200, {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store"}


@profile_bp.before_request
def _before():
    _ensure_csrf()
    return _csrf_required()


@profile_bp.after_request
def _after(resp: Response):
    return _no_store(resp)


@profile_bp.get("/profile")
def profile_home():
    guard = _login_required()
    if guard:
        return guard

    user = _current_user()
    if not user:
        _soft_logout()
        _flash("warning", "Sesión inválida. Volvé a iniciar sesión.")
        return _login_required()

    return _render_safe(
        "account/profile.html",
        user=user,
        csrf_token=_ensure_csrf(),
        is_admin=_is_admin_session(),
    )


@profile_bp.post("/profile/update")
def profile_update():
    guard = _login_required()
    if guard:
        return guard

    rl = _rate_limit_or_fail("profile_update", RL_PROFILE_LIMIT, RL_PROFILE_WINDOW)
    if rl:
        return rl

    user = _current_user()
    if not user:
        _soft_logout()
        if _wants_json():
            return _json({"ok": False, "error": "session_invalid"}, 401)
        return redirect(url_for("auth.login_get"), code=302)

    payload = _read_payload()

    name = _clean_str(payload.get("name"), _MAX_STR_120)
    phone = _validate_phone(payload.get("phone"))
    country = _clean_country(payload.get("country"))
    city = _clean_str(payload.get("city"), _MAX_STR_80)
    email_opt_in = _bool(payload.get("email_opt_in"))

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
        _flash("info", "No había cambios para guardar.")
        return redirect(url_for("profile.profile_home"), code=302)

    if not _commit("profile_update"):
        if _wants_json():
            return _json({"ok": False, "error": "save_failed"}, 500)
        _flash("error", "No se pudo guardar. Reintentá.")
        return redirect(url_for("profile.profile_home"), code=302)

    _rotate_csrf()

    if _wants_json():
        return _json({"ok": True, "updated": True}, 200)

    _flash("success", "Perfil actualizado ✅")
    return redirect(url_for("profile.profile_home"), code=302)


@profile_bp.post("/profile/email")
def profile_change_email():
    guard = _login_required()
    if guard:
        return guard

    rl = _rate_limit_or_fail("profile_email", RL_EMAIL_LIMIT, RL_EMAIL_WINDOW)
    if rl:
        return rl

    user = _current_user()
    if not user:
        _soft_logout()
        if _wants_json():
            return _json({"ok": False, "error": "session_invalid"}, 401)
        return redirect(url_for("auth.login_get"), code=302)

    payload = _read_payload()
    ok, out = _validate_email(payload.get("email"))
    if not ok:
        if _wants_json():
            return _json({"ok": False, "error": out}, 400)
        _flash("warning", out)
        return redirect(url_for("profile.profile_home"), code=302)

    new_email = out
    cur_email = _norm(getattr(user, "email", "") or "", max_len=_MAX_STR_254).lower()
    if cur_email == new_email:
        if _wants_json():
            return _json({"ok": True, "message": "same_email"}, 200)
        _flash("info", "Ese ya era tu email.")
        return redirect(url_for("profile.profile_home"), code=302)

    try:
        stmt = select(User.id).where(func.lower(User.email) == new_email)
        exists_id = db.session.execute(stmt).scalar_one_or_none()
    except SQLAlchemyError:
        try:
            db.session.rollback()
        except Exception:
            pass
        if _wants_json():
            return _json({"ok": False, "error": "query_failed"}, 500)
        _flash("error", "No se pudo validar el email. Reintentá.")
        return redirect(url_for("profile.profile_home"), code=302)

    if exists_id:
        if _wants_json():
            return _json({"ok": False, "error": "email_in_use"}, 409)
        _flash("warning", "Ese email ya está en uso.")
        return redirect(url_for("profile.profile_home"), code=302)

    _set_if_has(user, "email", new_email)
    if hasattr(user, "email_verified"):
        _set_if_has(user, "email_verified", False)
    if hasattr(user, "updated_at"):
        _set_if_has(user, "updated_at", _utcnow())

    if not _commit("profile_email"):
        if _wants_json():
            return _json({"ok": False, "error": "save_failed"}, 500)
        _flash("error", "No se pudo guardar. Reintentá.")
        return redirect(url_for("profile.profile_home"), code=302)

    session["user_email"] = new_email
    session.modified = True
    _rotate_csrf()

    if _wants_json():
        return _json({"ok": True, "email_updated": True}, 200)

    _flash("success", "Email actualizado ✅")
    return redirect(url_for("profile.profile_home"), code=302)


@profile_bp.post("/profile/password")
def profile_change_password():
    guard = _login_required()
    if guard:
        return guard

    rl = _rate_limit_or_fail("profile_password", RL_PASSWORD_LIMIT, RL_PASSWORD_WINDOW)
    if rl:
        return rl

    user = _current_user()
    if not user:
        _soft_logout()
        if _wants_json():
            return _json({"ok": False, "error": "session_invalid"}, 401)
        return redirect(url_for("auth.login_get"), code=302)

    payload = _read_payload()
    current_pw = _norm(payload.get("current_password") or "", max_len=_MAX_STR_512)
    new_pw = _norm(payload.get("new_password") or "", max_len=_MAX_STR_512)
    new_pw2 = _norm(payload.get("new_password_2") or "", max_len=_MAX_STR_512)

    if not current_pw:
        if _wants_json():
            return _json({"ok": False, "error": "missing_current_password"}, 400)
        _flash("warning", "Ingresá tu contraseña actual.")
        return redirect(url_for("profile.profile_home"), code=302)

    if not _user_password_check(user, current_pw):
        if _wants_json():
            return _json({"ok": False, "error": "wrong_password"}, 400)
        _flash("warning", "Tu contraseña actual no coincide.")
        return redirect(url_for("profile.profile_home"), code=302)

    if not _password_is_reasonable(new_pw):
        if _wants_json():
            return _json({"ok": False, "error": "weak_password"}, 400)
        _flash("warning", "La nueva contraseña debe tener mínimo 10 y letras+números.")
        return redirect(url_for("profile.profile_home"), code=302)

    if new_pw != new_pw2:
        if _wants_json():
            return _json({"ok": False, "error": "password_mismatch"}, 400)
        _flash("warning", "La confirmación no coincide.")
        return redirect(url_for("profile.profile_home"), code=302)

    try:
        if _user_password_check(user, new_pw):
            if _wants_json():
                return _json({"ok": False, "error": "password_reuse"}, 400)
            _flash("warning", "La nueva contraseña no puede ser igual a la anterior.")
            return redirect(url_for("profile.profile_home"), code=302)
    except Exception:
        pass

    if not _user_password_set(user, new_pw):
        if _wants_json():
            return _json({"ok": False, "error": "password_set_failed"}, 500)
        _flash("error", "No se pudo actualizar la contraseña.")
        return redirect(url_for("profile.profile_home"), code=302)

    if hasattr(user, "updated_at"):
        _set_if_has(user, "updated_at", _utcnow())

    if not _commit("profile_password"):
        if _wants_json():
            return _json({"ok": False, "error": "save_failed"}, 500)
        _flash("error", "No se pudo guardar. Reintentá.")
        return redirect(url_for("profile.profile_home"), code=302)

    _rotate_csrf()

    if _wants_json():
        return _json({"ok": True, "password_updated": True}, 200)

    _flash("success", "Contraseña actualizada ✅")
    return redirect(url_for("profile.profile_home"), code=302)


@profile_bp.get("/profile/csrf")
def profile_csrf_token():
    guard = _login_required()
    if guard:
        return guard
    return _json({"ok": True, "csrf_token": _ensure_csrf()}, 200)


__all__ = ["profile_bp"]
