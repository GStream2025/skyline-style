# app/routes/auth_routes.py — Skyline Store (FINAL / PROD SAFE / NO ACCOUNT PAGE)
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Set, Tuple
from urllib.parse import urlparse

from flask import (
    Blueprint,
    Response,
    current_app,
    flash,
    g,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_wtf.csrf import CSRFError, generate_csrf, validate_csrf
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.security import check_password_hash, generate_password_hash

from app.models import User, db

try:
    from flask_login import current_user as _fl_current_user  # type: ignore
    from flask_login import login_user as _fl_login_user  # type: ignore
    from flask_login import logout_user as _fl_logout_user  # type: ignore
except Exception:  # pragma: no cover
    _fl_current_user = None  # type: ignore
    _fl_login_user = None  # type: ignore
    _fl_logout_user = None  # type: ignore

try:
    from app.models import AffiliateProfile  # type: ignore
except Exception:  # pragma: no cover
    AffiliateProfile = None  # type: ignore


log = logging.getLogger("auth_routes")

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")
auth_bp.strict_slashes = False

_TRUE: Set[str] = {"1", "true", "yes", "y", "on", "checked", "enable", "enabled"}
_FALSE: Set[str] = {"0", "false", "no", "n", "off", "unchecked", "disable", "disabled"}

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_ALLOWED_PUBLIC_ROLES: Set[str] = {"customer", "affiliate"}

# Session-based rate limit (soft anti-bot)
_RL_WINDOW_SEC = 60
_RL_MAX = 8
_RL_STORE_CAP = 250
_RL_STORE_TTL_SEC = 60 * 25
_RL_STORE_SESSION_KEY = "rl_store_v10"

_RL_LOGIN_KEY = "login"
_RL_REG_KEY = "register"
_RL_VERIFY_SEND_KEY = "verify_send"

_MIN_PASS_LEN = 8
_MAX_PASS_LEN = 256

_VERIFY_TTL_MIN = 45
_VERIFY_RL_SEC = 60

_MAX_NEXT_LEN = 512
_MAX_EMAIL_LEN = 254

_VERIFY_TOKEN_SESSION_KEY = "verify_token"
_VERIFY_TOKEN_TS_SESSION_KEY = "verify_token_ts"

_HONEYPOT_FIELD = "website"

# No queremos que "next" vaya a auth/admin para evitar loops
_BLOCKED_NEXT_PREFIXES = ("/auth/", "/admin/")
_ALLOWED_NEXT_PREFIXES = ("/",)

_VALIDATE_TIMEOUT_SEC = 6


# ------------------------
# basics / helpers
# ------------------------
def _now() -> int:
    return int(time.time())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _cfg_bool(key: str, default: bool) -> bool:
    try:
        v = current_app.config.get(key, default)
    except Exception:
        return default
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if not s:
        return default
    if s in _FALSE:
        return False
    return s in _TRUE


def _cfg_int(key: str, default: int, *, min_v: int = 0, max_v: int = 10**9) -> int:
    try:
        raw = current_app.config.get(key, default)
        v = int(raw) if raw is not None else int(default)
    except Exception:
        v = default
    return max(min_v, min(max_v, v))


def _env_str(key: str, default: str = "") -> str:
    try:
        return (os.getenv(key) or default).strip()
    except Exception:
        return default


def _norm(v: Any, *, max_len: int = 2000) -> str:
    if v is None:
        return ""
    s = v if isinstance(v, str) else str(v)
    s = s.replace("\x00", "").replace("\u200b", "").strip()
    s = s.replace("\r", "").replace("\n", "")
    return s if max_len <= 0 else s[:max_len]


def _safe_email(v: Any) -> str:
    return _norm(v, max_len=_MAX_EMAIL_LEN).lower()


def _valid_email(v: Any) -> bool:
    e = _safe_email(v)
    return bool(e and len(e) <= _MAX_EMAIL_LEN and _EMAIL_RE.match(e))


def _parse_bool(v: Any) -> bool:
    s = _norm(v, max_len=32).lower()
    if not s:
        return False
    if s in _FALSE:
        return False
    return s in _TRUE


def _safe_next(nxt: Any) -> str:
    s = _norm(nxt, max_len=_MAX_NEXT_LEN)
    if not s:
        return ""
    if not s.startswith(_ALLOWED_NEXT_PREFIXES):
        return ""
    if any(c in s for c in ("\x00", "\\", "\r", "\n", "\t", " ")):
        return ""
    if "://" in s or s.startswith("//"):
        return ""
    if ".." in s:
        return ""
    try:
        p = urlparse(s)
        if p.scheme or p.netloc:
            return ""
        clean = (p.path or "").strip() or "/"
        if not clean.startswith("/") or clean.startswith("//"):
            return ""
        clean = clean[:_MAX_NEXT_LEN]
        if any(clean.startswith(pref) for pref in _BLOCKED_NEXT_PREFIXES):
            return ""
        return clean
    except Exception:
        return ""


def _wants_json() -> bool:
    try:
        if request.is_json:
            return True
    except Exception:
        pass

    accept = _norm(request.headers.get("Accept") or "", max_len=200).lower()
    xrw = _norm(request.headers.get("X-Requested-With") or "", max_len=60).lower()
    fmt = _norm(request.args.get("format") or "", max_len=40).lower()

    if "application/json" in accept or "text/json" in accept:
        return True
    if xrw == "xmlhttprequest":
        return True
    if fmt == "json":
        return True

    try:
        best = request.accept_mimetypes.best_match(["application/json", "text/html"])
        if best == "application/json" and request.accept_mimetypes[best] >= request.accept_mimetypes["text/html"]:
            return True
    except Exception:
        pass

    return False


def _endpoint_exists(endpoint: str) -> bool:
    try:
        return endpoint in (current_app.view_functions or {})
    except Exception:
        return False


def _url_for_safe(endpoint: str, **values: Any) -> str:
    try:
        if _endpoint_exists(endpoint):
            return url_for(endpoint, **values)
    except Exception:
        pass
    return ""


def _normalize_name(name: Any) -> str:
    v = re.sub(r"\s+", " ", _norm(name, max_len=180)).strip()
    return v[:120]


def _extract_role() -> str:
    role = _norm(request.form.get("role", ""), max_len=24).lower()
    if role in _ALLOWED_PUBLIC_ROLES:
        return role
    if _parse_bool(request.form.get("want_affiliate", "")):
        return "affiliate"
    return "customer"


def _home_after_login(user: Any, nxt: str) -> str:
    # 1) next seguro si viene
    nxt_clean = _safe_next(nxt)
    if nxt_clean:
        return nxt_clean

    # 2) si es admin, dashboard admin si existe
    try:
        if bool(getattr(user, "is_admin", False)):
            u = _url_for_safe("admin.dashboard")
            if u:
                return u
            return "/admin"
    except Exception:
        pass

    # 3) preferir profile/dashboard si existe, si no home/shop
    for ep in ("profile.dashboard", "main.index", "shop.shop"):
        u = _url_for_safe(ep)
        if u:
            return u
    return "/"


def _login_url(nxt: str = "", email: str = "") -> str:
    params: Dict[str, Any] = {}
    nxt_clean = _safe_next(nxt)
    if nxt_clean:
        params["next"] = nxt_clean
    if email:
        params["email"] = _safe_email(email)

    u = _url_for_safe("auth.login_get", **params)
    if u:
        return u

    qs = urllib.parse.urlencode({k: v for k, v in params.items() if str(v)}, doseq=False)
    return "/auth/login" + (("?" + qs) if qs else "")


def _register_url(nxt: str = "", email: str = "", name: str = "") -> str:
    params: Dict[str, Any] = {}
    nxt_clean = _safe_next(nxt)
    if nxt_clean:
        params["next"] = nxt_clean
    if email:
        params["email"] = _safe_email(email)
    if name:
        params["name"] = _normalize_name(name)

    u = _url_for_safe("auth.register_get", **params)
    if u:
        return u

    qs = urllib.parse.urlencode({k: v for k, v in params.items() if str(v)}, doseq=False)
    return "/auth/register" + (("?" + qs) if qs else "")


def _client_ip() -> str:
    xff = _norm(request.headers.get("X-Forwarded-For") or "", max_len=400)
    if xff:
        return _norm(xff.split(",")[0].strip(), max_len=80) or "unknown"
    return _norm(request.remote_addr or "unknown", max_len=80) or "unknown"


def _client_fp() -> str:
    ip = _client_ip()
    ua = _norm(request.headers.get("User-Agent") or "", max_len=200)[:120]
    salt = _norm(current_app.config.get("FP_SALT") or "", max_len=64)
    raw = f"{ip}|{ua}|{salt}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _rate_limit(bucket: str) -> Tuple[bool, int]:
    now = _now()
    fp = _client_fp()
    bucket_key = f"{bucket}:{fp}"

    store = session.get(_RL_STORE_SESSION_KEY)
    if not isinstance(store, dict):
        store = {}

    # TTL cleanup
    if store:
        cutoff = now - _RL_STORE_TTL_SEC
        for k in list(store.keys()):
            v = store.get(k)
            if not isinstance(v, dict):
                store.pop(k, None)
                continue
            try:
                t0 = int(v.get("t", 0) or 0)
            except Exception:
                t0 = 0
            if t0 and t0 < cutoff:
                store.pop(k, None)

    # hard cap
    if len(store) > _RL_STORE_CAP:
        items: list[tuple[int, str]] = []
        for k, v in list(store.items()):
            if isinstance(v, dict):
                try:
                    t0 = int(v.get("t", 0) or 0)
                except Exception:
                    t0 = 0
                items.append((t0, str(k)))
        items.sort()
        for _, k in items[: max(0, len(store) - _RL_STORE_CAP)]:
            store.pop(k, None)

    b = store.get(bucket_key)
    if not isinstance(b, dict):
        store[bucket_key] = {"t": now, "n": 1}
        session[_RL_STORE_SESSION_KEY] = store
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
    if elapsed >= _RL_WINDOW_SEC or elapsed < 0:
        store[bucket_key] = {"t": now, "n": 1}
        session[_RL_STORE_SESSION_KEY] = store
        session.modified = True
        return True, 0

    if n >= _RL_MAX:
        return False, int(max(1, _RL_WINDOW_SEC - elapsed))

    b["n"] = n + 1
    store[bucket_key] = b
    session[_RL_STORE_SESSION_KEY] = store
    session.modified = True
    return True, 0


def _is_honeypot_triggered() -> bool:
    try:
        return bool(_norm(request.form.get(_HONEYPOT_FIELD, ""), max_len=120))
    except Exception:
        return False


def _json(ok: bool, payload: Dict[str, Any], status: int):
    resp = jsonify({"ok": ok, **payload})
    if status == 429 and "retry_after" in payload:
        try:
            resp.headers["Retry-After"] = str(int(payload.get("retry_after") or 0))
        except Exception:
            pass
    return resp, int(status)


def _flash(level: str, msg: str) -> None:
    cat = "success" if level == "success" else ("info" if level == "info" else "danger")
    try:
        flash(_norm(msg, max_len=300) or "OK", cat)
    except Exception:
        pass


def _no_store(resp: Response) -> Response:
    # evita cache del HTML con CSRF viejo
    try:
        resp.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
        resp.headers.setdefault("Pragma", "no-cache")
        resp.headers.setdefault("Expires", "0")
        resp.headers.setdefault("Vary", "Cookie")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        resp.headers.setdefault("X-Frame-Options", "DENY")
    except Exception:
        pass
    return resp


def _require_wtf_csrf_or_fail(*, redirect_url: str, status_err: int = 400):
    tok = _norm(request.form.get("csrf_token") or "", max_len=4096)
    if not tok:
        return _json_or_redirect(
            ok=False,
            message="Solicitud inválida. Recargá la página.",
            redirect_to=redirect_url,
            status_err=status_err,
        )
    try:
        validate_csrf(tok)
    except Exception:
        return _json_or_redirect(
            ok=False,
            message="Solicitud inválida. Recargá la página.",
            redirect_to=redirect_url,
            status_err=status_err,
        )
    return None


def _rotate_wtf_csrf() -> None:
    # regeneración segura
    try:
        session.pop("csrf_token", None)
        generate_csrf()
        session.modified = True
    except Exception:
        pass


def _db_rollback_quiet() -> None:
    try:
        db.session.rollback()
    except Exception:
        pass


def _clear_auth_session() -> None:
    # mantenemos rate-limit + csrf + verify
    keep_exact = {_RL_STORE_SESSION_KEY, "csrf_token", _VERIFY_TOKEN_SESSION_KEY, _VERIFY_TOKEN_TS_SESSION_KEY}
    keep_prefix = ("verify_rl:",)
    for k in list(session.keys()):
        ks = str(k)
        if ks in keep_exact or any(ks.startswith(p) for p in keep_prefix):
            continue
        session.pop(k, None)
    session.modified = True


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
        ph = str(getattr(user, "password_hash", "") or getattr(user, "password", "") or "")
    except Exception:
        ph = ""

    if not ph:
        return False

    try:
        ok = bool(check_password_hash(ph, pw))
    except Exception:
        ok = False

    # micro-hardening timing
    try:
        secrets.compare_digest("a", "a" if ok else "b")
    except Exception:
        pass

    return ok


def _user_password_set(user: Any, password: str) -> bool:
    pw = password or ""
    if len(pw) < _MIN_PASS_LEN or len(pw) > _MAX_PASS_LEN:
        return False

    try:
        fn = getattr(user, "set_password", None)
        if callable(fn):
            fn(pw)
            return True
    except Exception:
        pass

    ph = generate_password_hash(pw)
    try:
        if hasattr(user, "password_hash"):
            setattr(user, "password_hash", ph)
            return True
        if hasattr(user, "password"):
            setattr(user, "password", ph)
            return True
        setattr(user, "password_hash", ph)
        return True
    except Exception:
        return False


def _set_user_session(user: User) -> None:
    _clear_auth_session()

    session["user_id"] = int(getattr(user, "id", 0) or 0)
    session["user_email"] = (getattr(user, "email", "") or "").lower()
    session["is_admin"] = bool(getattr(user, "is_admin", False))
    session["role"] = str(getattr(user, "role", "") or getattr(user, "user_role", "") or "customer")
    session["email_verified"] = bool(getattr(user, "email_verified", False) or getattr(user, "is_verified", False))
    session["login_at"] = _now()
    session["login_nonce"] = secrets.token_urlsafe(16)

    ttl_min = _cfg_int("SESSION_TTL_MINUTES", 60 * 24 * 7, min_v=5, max_v=60 * 24 * 90)
    session.permanent = True
    try:
        current_app.permanent_session_lifetime = timedelta(minutes=ttl_min)
    except Exception:
        pass

    session.modified = True
    _rotate_wtf_csrf()

    if _fl_login_user:
        try:
            _fl_login_user(user, remember=False)  # type: ignore[misc]
        except Exception:
            log.exception("flask_login login_user failed")


def _is_authenticated() -> bool:
    try:
        if _fl_current_user is not None and getattr(_fl_current_user, "is_authenticated", False):
            return True
    except Exception:
        pass
    return bool(session.get("user_id"))


def _get_user_by_email(email: str) -> Optional[User]:
    e = _safe_email(email)
    if not e:
        return None
    try:
        stmt = select(User).where(func.lower(User.email) == e)
        return db.session.execute(stmt).scalar_one_or_none()
    except Exception:
        _db_rollback_quiet()
        log.exception("get_user_by_email failed")
        return None


def _verify_rate_limited(email: str) -> bool:
    key = f"verify_rl:{email}"
    now = _now()
    try:
        last = int(session.get(key) or 0)
    except Exception:
        last = 0
    if last and (now - last) < _VERIFY_RL_SEC:
        return True
    session[key] = now
    session.modified = True
    return False


def _hash_token(token: str) -> str:
    sk = (current_app.config.get("SECRET_KEY") or "").encode("utf-8")
    t = token.encode("utf-8")
    if not sk:
        return hashlib.sha256(t).hexdigest()
    return hmac.new(sk, t, hashlib.sha256).hexdigest()


def _make_verify_token() -> str:
    return secrets.token_urlsafe(48)


def _save_verify_token_db(user: User, token: str) -> bool:
    token_hash = _hash_token(token)
    exp = _utcnow() + timedelta(minutes=_VERIFY_TTL_MIN)

    candidates_hash = ("email_verify_token_hash", "verify_token_hash", "email_token_hash")
    candidates_exp = ("email_verify_expires_at", "verify_expires_at", "email_token_expires_at")

    hash_field = next((f for f in candidates_hash if hasattr(user, f)), "")
    exp_field = next((f for f in candidates_exp if hasattr(user, f)), "")

    if not hash_field or not exp_field:
        return False

    try:
        setattr(user, hash_field, token_hash)
        setattr(user, exp_field, exp)
        if hasattr(user, "email_verified"):
            setattr(user, "email_verified", False)
        db.session.add(user)
        db.session.commit()
        return True
    except Exception:
        _db_rollback_quiet()
        return False


def _best_scheme() -> str:
    preferred = _norm(
        current_app.config.get("PREFERRED_URL_SCHEME") or _env_str("PREFERRED_URL_SCHEME") or "",
        max_len=10,
    ).lower()
    if preferred in {"http", "https"}:
        return preferred
    if _cfg_bool("FORCE_HTTPS", True) or _parse_bool(_env_str("FORCE_HTTPS", "1")):
        return "https"
    try:
        xf = (request.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
        if xf in {"http", "https"}:
            return xf
    except Exception:
        pass
    try:
        return (request.scheme or "https").lower()
    except Exception:
        return "https"


def _site_base_url() -> str:
    raw = _norm(
        current_app.config.get("APP_URL")
        or current_app.config.get("SITE_URL")
        or _env_str("APP_URL")
        or _env_str("SITE_URL")
        or "",
        max_len=300,
    ).rstrip("/")

    if raw.startswith("http://") or raw.startswith("https://"):
        return raw

    try:
        scheme = _best_scheme()
        host = (request.headers.get("X-Forwarded-Host") or request.host or "").strip()
        if host:
            return f"{scheme}://{host}".rstrip("/")
    except Exception:
        pass

    return ""


def _absolute_url(path: str) -> str:
    base = _site_base_url()
    if not base:
        return ""
    p = "/" + (path.lstrip("/"))
    return base + p


def _send_verify_email(email: str, verify_url: str) -> None:
    send_email = None
    try:
        from app.services.email_service import send_email as _send_email  # type: ignore

        send_email = _send_email
    except Exception:
        send_email = None

    subj = current_app.config.get("EMAIL_VERIFY_SUBJECT") or "Verificá tu cuenta"
    app_name = current_app.config.get("APP_NAME") or "Skyline Store"

    if callable(send_email):
        try:
            html = render_template("emails/welcome_verify.html", app_name=app_name, verify_url=verify_url)
            send_email(to=email, subject=subj, html=html)  # type: ignore[misc]
            return
        except Exception:
            log.exception("send_email failed")

    # fallback: log para debug (no rompe)
    try:
        rid = _norm(request.headers.get("X-Request-Id") or "", max_len=80)
        current_app.logger.info("VERIFY_EMAIL rid=%s to=%s url=%s", rid or "-", email, verify_url)
    except Exception:
        pass


def _bad_auth(*, redirect_to: str, retry_after: int = 0, generic: str = "Credenciales incorrectas."):
    try:
        time.sleep(0.12)
    except Exception:
        pass
    return _json_or_redirect(
        ok=False,
        message=generic,
        redirect_to=redirect_to,
        status_err=401,
        retry_after=retry_after,
    )


def _is_password_reasonable(pw: str) -> bool:
    s = pw or ""
    if len(s) < _MIN_PASS_LEN or len(s) > _MAX_PASS_LEN:
        return False
    bad = {"password", "password123", "12345678", "qwerty123", "abc123", "admin12345"}
    if s.lower() in bad:
        return False
    has_letter = any(c.isalpha() for c in s)
    has_digit = any(c.isdigit() for c in s)
    return has_letter and has_digit


# ------------------------
# External email validation (best-effort)
# ------------------------
def _email_validation_provider() -> str:
    p = _norm(
        current_app.config.get("EMAIL_VALIDATION_PROVIDER") or _env_str("EMAIL_VALIDATION_PROVIDER") or "",
        max_len=40,
    ).lower()
    return p or "none"


def _mailboxvalidator_key() -> str:
    return _norm(
        current_app.config.get("MAILBOXVALIDATOR_API_KEY") or _env_str("MAILBOXVALIDATOR_API_KEY") or "",
        max_len=128,
    )


def _validate_email_external(email: str) -> Tuple[bool, str]:
    email = _safe_email(email)
    if not _valid_email(email):
        return False, "Email inválido."

    if not _cfg_bool("VALIDATE_EMAIL_ON_REGISTER", True):
        return True, "skip"

    provider = _email_validation_provider()
    if provider in {"", "none", "off", "disabled"}:
        return True, "skip"

    if provider == "mailboxvalidator":
        key = _mailboxvalidator_key()
        if not key:
            return True, "no_key"

        strict = _cfg_bool("EMAIL_VALIDATION_STRICT", False)
        url = (
            "https://api.mailboxvalidator.com/v1/validation/single?"
            + urllib.parse.urlencode({"key": key, "email": email, "format": "json"})
        )

        try:
            req = urllib.request.Request(
                url,
                method="GET",
                headers={"Accept": "application/json", "User-Agent": "SkylineStore/1.0"},
            )
            with urllib.request.urlopen(req, timeout=_VALIDATE_TIMEOUT_SEC) as resp:
                raw = resp.read().decode("utf-8", "replace")
            data = json.loads(raw) if raw else {}
            if not isinstance(data, dict):
                return (True, "api_bad_payload") if not strict else (False, "No se pudo verificar el email.")

            status = _norm(data.get("status") or "", max_len=20).lower()
            is_disposable = _norm(
                data.get("is_disposable") or data.get("is_disposable_email") or "",
                max_len=20,
            ).lower()

            if status in {"false", "invalid"}:
                return False, "Email inválido."
            if is_disposable in {"true", "yes", "1"} and _cfg_bool("BLOCK_DISPOSABLE_EMAILS", True):
                return False, "No se permiten emails temporales."

            return True, "ok"

        except Exception:
            return (True, "api_error") if not strict else (False, "No se pudo verificar el email. Reintentá.")

    return True, "skip"


# ------------------------
# json/redirect helpers
# ------------------------
def _json_or_redirect(
    *,
    ok: bool,
    message: str,
    redirect_to: str,
    status_ok: int = 200,
    status_err: int = 400,
    retry_after: int = 0,
):
    if _wants_json():
        status = status_ok if ok else status_err
        payload: Dict[str, Any] = {"message": message, "redirect": redirect_to or ""}
        if retry_after:
            payload["retry_after"] = int(retry_after)
        return _json(ok, payload, status)

    _flash("success" if ok else "danger", message)
    return redirect(redirect_to or "/", code=302)


# ------------------------
# hooks
# ------------------------
@auth_bp.before_request
def _auth_before_request():
    # genera token para templates (GET), sin explotar
    try:
        g.csrf_token = generate_csrf()
    except Exception:
        g.csrf_token = ""


@auth_bp.after_request
def _auth_after_request(resp: Response):
    return _no_store(resp)


@auth_bp.app_errorhandler(CSRFError)
def _handle_csrf_error(e):
    _ = e
    nxt = _safe_next(request.args.get("next", "")) or "/"
    if _wants_json():
        return jsonify({"ok": False, "message": "Solicitud inválida. Recargá la página.", "redirect": ""}), 400
    flash("Solicitud inválida. Recargá la página e intentá nuevamente.", "danger")
    return redirect(_login_url(nxt=nxt), code=302)


# =========================================================
# Views (NO account page)
# =========================================================
@auth_bp.get("/login")
@auth_bp.get("/login/")
def login_get():
    if _is_authenticated():
        nxt = _safe_next(request.args.get("next", "")) or "/"
        return redirect(nxt, code=302)

    nxt = _safe_next(request.args.get("next", ""))
    email = _safe_email(request.args.get("email", ""))
    tok = getattr(g, "csrf_token", "") or generate_csrf()

    return make_response(
        render_template(
            "auth/login.html",
            next=nxt,
            prefill_email=email,
            csrf_token_value=tok,
        ),
        200,
    )


@auth_bp.get("/register")
@auth_bp.get("/register/")
def register_get():
    if _is_authenticated():
        nxt = _safe_next(request.args.get("next", "")) or "/"
        return redirect(nxt, code=302)

    nxt = _safe_next(request.args.get("next", ""))
    email = _safe_email(request.args.get("email", ""))
    name = _normalize_name(request.args.get("name", ""))

    tok = getattr(g, "csrf_token", "") or generate_csrf()

    return make_response(
        render_template(
            "auth/register.html",
            next=nxt,
            prefill_email=email,
            prefill_name=name,
            csrf_token_value=tok,
        ),
        200,
    )


@auth_bp.get("/signup")
@auth_bp.get("/signin")
def compat_aliases():
    p = _norm(request.path or "", max_len=40).lower()
    if p.endswith("/signup"):
        return redirect(_register_url(), code=302)
    return redirect(_login_url(), code=302)


@auth_bp.post("/login")
def login_post():
    nxt = _safe_next(request.form.get("next", "")) or _safe_next(request.args.get("next", ""))

    ok_rl, retry = _rate_limit(_RL_LOGIN_KEY)
    if (not ok_rl) or _is_honeypot_triggered():
        return _bad_auth(redirect_to=_login_url(nxt=nxt), retry_after=retry, generic="Credenciales incorrectas.")

    csrf_fail = _require_wtf_csrf_or_fail(redirect_url=_login_url(nxt=nxt), status_err=400)
    if csrf_fail is not None:
        return csrf_fail

    email = _safe_email(request.form.get("email", ""))
    password = _norm(request.form.get("password", ""), max_len=512)

    if not _valid_email(email) or not password:
        return _bad_auth(redirect_to=_login_url(nxt=nxt, email=email), generic="Credenciales incorrectas.")

    user = _get_user_by_email(email)

    ok = False
    try:
        ok = bool(user and _user_password_check(user, password))
    except Exception:
        ok = False

    if not ok:
        return _bad_auth(redirect_to=_login_url(nxt=nxt, email=email), generic="Credenciales incorrectas.")

    try:
        if hasattr(user, "is_active") and not bool(getattr(user, "is_active", True)):
            return _bad_auth(redirect_to=_login_url(nxt=nxt, email=email), generic="No se pudo iniciar sesión.")
    except Exception:
        return _bad_auth(redirect_to=_login_url(nxt=nxt, email=email), generic="No se pudo iniciar sesión.")

    # actualizar last login (best-effort)
    try:
        if hasattr(user, "last_login_at"):
            setattr(user, "last_login_at", _utcnow())
        if hasattr(user, "last_login_ip"):
            setattr(user, "last_login_ip", _client_ip())
        db.session.add(user)
        db.session.commit()
    except Exception:
        _db_rollback_quiet()

    _set_user_session(user)  # type: ignore[arg-type]

    verified = bool(getattr(user, "email_verified", False) or getattr(user, "is_verified", False))
    require_verify = _cfg_bool("REQUIRE_EMAIL_VERIFICATION", True)

    if require_verify and not verified:
        return _json_or_redirect(
            ok=True,
            message="Sesión iniciada. Te enviamos un email para verificar tu cuenta.",
            redirect_to=_url_for_safe("auth.verify_send", next=(nxt or "/"))
            or f"/auth/verify/send?next={urllib.parse.quote(nxt or '/')}",
            status_ok=200,
        )

    dest = _home_after_login(user, nxt)
    return _json_or_redirect(ok=True, message="Bienvenido 👋", redirect_to=dest, status_ok=200)


@auth_bp.post("/register", endpoint="register")
def register():
    nxt = _safe_next(request.form.get("next", "")) or _safe_next(request.args.get("next", ""))

    ok_rl, retry = _rate_limit(_RL_REG_KEY)
    if (not ok_rl) or _is_honeypot_triggered():
        return _bad_auth(redirect_to=_register_url(nxt=nxt), retry_after=retry, generic="No se pudo crear la cuenta.")

    csrf_fail = _require_wtf_csrf_or_fail(redirect_url=_register_url(nxt=nxt), status_err=400)
    if csrf_fail is not None:
        return csrf_fail

    email = _safe_email(request.form.get("email", ""))
    password = _norm(request.form.get("password", ""), max_len=512)
    password2 = _norm(request.form.get("password2", ""), max_len=512)
    name = _normalize_name(request.form.get("name", ""))

    if not _valid_email(email):
        return _json_or_redirect(
            ok=False,
            message="Email inválido.",
            redirect_to=_register_url(nxt=nxt, email=email, name=name),
            status_err=400,
        )
    if password != password2:
        return _json_or_redirect(
            ok=False,
            message="Las contraseñas no coinciden.",
            redirect_to=_register_url(nxt=nxt, email=email, name=name),
            status_err=400,
        )
    if not _is_password_reasonable(password):
        return _json_or_redirect(
            ok=False,
            message=f"Contraseña inválida (mín {_MIN_PASS_LEN} y con letras+números).",
            redirect_to=_register_url(nxt=nxt, email=email, name=name),
            status_err=400,
        )

    ok_ext, reason = _validate_email_external(email)
    if not ok_ext:
        return _json_or_redirect(
            ok=False,
            message=reason,
            redirect_to=_register_url(nxt=nxt, email=email, name=name),
            status_err=400,
        )

    if _get_user_by_email(email):
        return _json_or_redirect(
            ok=False,
            message="Ese email ya existe. Iniciá sesión.",
            redirect_to=_login_url(nxt=nxt, email=email),
            status_err=409,
        )

    role = _extract_role()
    user = User(email=email)

    # set attrs best-effort
    try:
        if hasattr(user, "name"):
            setattr(user, "name", name)
        if hasattr(user, "is_active"):
            setattr(user, "is_active", True)
        if hasattr(user, "email_verified"):
            setattr(user, "email_verified", False)
        if hasattr(user, "role"):
            setattr(user, "role", role)
        if hasattr(user, "created_at"):
            setattr(user, "created_at", _utcnow())
    except Exception:
        pass

    if not _user_password_set(user, password):
        return _json_or_redirect(
            ok=False,
            message="No pudimos crear la cuenta. Reintentá.",
            redirect_to=_register_url(nxt=nxt, email=email, name=name),
            status_err=400,
        )

    try:
        db.session.add(user)
        db.session.flush()

        if role == "affiliate" and AffiliateProfile is not None:
            try:
                db.session.add(AffiliateProfile(user_id=int(getattr(user, "id", 0) or 0), status="pending"))  # type: ignore[arg-type]
            except Exception:
                pass

        db.session.commit()

    except IntegrityError:
        _db_rollback_quiet()
        return _json_or_redirect(
            ok=False,
            message="Ese email ya existe. Iniciá sesión.",
            redirect_to=_login_url(nxt=nxt, email=email),
            status_err=409,
        )
    except SQLAlchemyError:
        _db_rollback_quiet()
        log.exception("register SQLAlchemyError")
        return _bad_auth(redirect_to=_register_url(nxt=nxt), generic="No se pudo crear la cuenta.")
    except Exception:
        _db_rollback_quiet()
        log.exception("register commit failed")
        return _bad_auth(redirect_to=_register_url(nxt=nxt), generic="No se pudo crear la cuenta.")

    _set_user_session(user)  # type: ignore[arg-type]

    require_verify = _cfg_bool("REQUIRE_EMAIL_VERIFICATION", True)
    if require_verify:
        return _json_or_redirect(
            ok=True,
            message="Cuenta creada ✅ Te enviamos un email para verificar.",
            redirect_to=_url_for_safe("auth.verify_send", next=(nxt or "/"))
            or f"/auth/verify/send?next={urllib.parse.quote(nxt or '/')}",
            status_ok=201,
        )

    # si no requiere verify, marca verified
    try:
        if hasattr(user, "email_verified"):
            setattr(user, "email_verified", True)
            db.session.add(user)
            db.session.commit()
        session["email_verified"] = True
        session.modified = True
    except Exception:
        _db_rollback_quiet()

    dest = _home_after_login(user, nxt)
    return _json_or_redirect(ok=True, message="Cuenta creada ✅", redirect_to=dest, status_ok=201)


@auth_bp.route("/logout", methods=["GET", "POST"])
def logout():
    nxt = _safe_next(request.values.get("next", "")) or "/"

    if request.method == "POST":
        csrf_fail = _require_wtf_csrf_or_fail(redirect_url=_login_url(nxt=nxt), status_err=400)
        if csrf_fail is not None:
            return csrf_fail

    _clear_auth_session()
    _rotate_wtf_csrf()

    if _fl_logout_user:
        try:
            _fl_logout_user()  # type: ignore[misc]
        except Exception:
            log.exception("flask_login logout_user failed")

    if _wants_json():
        return _json(True, {"message": "Sesión cerrada.", "redirect": nxt}, 200)

    _flash("info", "Sesión cerrada.")
    return redirect(nxt, code=302)


# ------------------------
# verify email flow
# ------------------------
@auth_bp.get("/verify/send")
def verify_send():
    nxt = _safe_next(request.args.get("next", "")) or "/"
    uid = int(session.get("user_id") or 0)
    email = _safe_email(session.get("user_email") or "")

    if not uid or not email:
        _flash("danger", "Iniciá sesión para verificar tu cuenta.")
        return redirect(_login_url(nxt=nxt, email=email), code=302)

    user = db.session.get(User, uid)
    if not user:
        _clear_auth_session()
        _flash("danger", "Iniciá sesión nuevamente.")
        return redirect(_login_url(nxt=nxt, email=email), code=302)

    if bool(getattr(user, "email_verified", False) or getattr(user, "is_verified", False)):
        session["email_verified"] = True
        session.modified = True
        _flash("success", "Tu cuenta ya está verificada ✅")
        return redirect(_home_after_login(user, nxt), code=302)

    if _verify_rate_limited(email):
        _flash("info", "Ya enviamos un email recién. Esperá 1 minuto y reintentá.")
        return redirect(_login_url(nxt=nxt, email=email), code=302)

    token = _make_verify_token()
    saved_db = _save_verify_token_db(user, token)
    if not saved_db:
        session[_VERIFY_TOKEN_SESSION_KEY] = token
        session[_VERIFY_TOKEN_TS_SESSION_KEY] = _now()
        session.modified = True

    rel = _url_for_safe("auth.verify", token=token, next=nxt) or f"/auth/verify/{token}?next={urllib.parse.quote(nxt)}"
    verify_url = _absolute_url(rel) or url_for("auth.verify", token=token, _external=True, _scheme=_best_scheme(), next=nxt)

    _send_verify_email(email, verify_url)

    # si existe template de confirmación, mostrala
    try:
        return make_response(render_template("auth/verify_email.html", next=nxt, email=email), 200)
    except Exception:
        _flash("success", "Email de verificación enviado ✅")
        return redirect(_login_url(nxt=nxt, email=email), code=302)


@auth_bp.post("/resend-verification")
def resend_verification():
    nxt = _safe_next(request.form.get("next", "")) or _safe_next(request.args.get("next", "")) or "/"

    ok_rl, retry = _rate_limit(_RL_VERIFY_SEND_KEY)
    if (not ok_rl) or _is_honeypot_triggered():
        _flash("info", "Esperá un momento y reintentá.")
        r = redirect(_login_url(nxt=nxt), code=302)
        if retry:
            try:
                r.headers["Retry-After"] = str(int(retry))
            except Exception:
                pass
        return r

    csrf_fail = _require_wtf_csrf_or_fail(redirect_url=_login_url(nxt=nxt), status_err=400)
    if csrf_fail is not None:
        return csrf_fail

    uid = int(session.get("user_id") or 0)
    email = _safe_email(session.get("user_email") or request.form.get("email") or "")

    if not uid or not email:
        _flash("danger", "Iniciá sesión para reenviar el email.")
        return redirect(_login_url(nxt=nxt, email=email), code=302)

    user = db.session.get(User, uid)
    if not user:
        _clear_auth_session()
        _flash("danger", "Iniciá sesión nuevamente.")
        return redirect(_login_url(nxt=nxt, email=email), code=302)

    if bool(getattr(user, "email_verified", False) or getattr(user, "is_verified", False)):
        session["email_verified"] = True
        session.modified = True
        _flash("success", "Tu cuenta ya está verificada ✅")
        return redirect(_home_after_login(user, nxt), code=302)

    if _verify_rate_limited(email):
        _flash("info", "Ya enviamos un email recién. Esperá 1 minuto y reintentá.")
        return redirect(_login_url(nxt=nxt, email=email), code=302)

    token = _make_verify_token()
    saved_db = _save_verify_token_db(user, token)
    if not saved_db:
        session[_VERIFY_TOKEN_SESSION_KEY] = token
        session[_VERIFY_TOKEN_TS_SESSION_KEY] = _now()
        session.modified = True

    rel = _url_for_safe("auth.verify", token=token, next=nxt) or f"/auth/verify/{token}?next={urllib.parse.quote(nxt)}"
    verify_url = _absolute_url(rel) or url_for("auth.verify", token=token, _external=True, _scheme=_best_scheme(), next=nxt)

    _send_verify_email(email, verify_url)
    _flash("success", "Correo reenviado ✅ Revisá tu email.")
    return redirect(_login_url(nxt=nxt, email=email), code=302)


@auth_bp.get("/verify/<token>")
def verify(token: str):
    token = _norm(token, max_len=300)
    nxt = _safe_next(request.args.get("next", "")) or "/"

    uid = int(session.get("user_id") or 0)
    if not uid:
        _flash("danger", "Iniciá sesión para verificar tu cuenta.")
        return redirect(_login_url(nxt=nxt), code=302)

    user = db.session.get(User, uid)
    if not user:
        _flash("danger", "Usuario no encontrado.")
        return redirect(_login_url(nxt=nxt), code=302)

    if bool(getattr(user, "email_verified", False) or getattr(user, "is_verified", False)):
        session["email_verified"] = True
        session.modified = True
        _flash("success", "Tu cuenta ya está verificada ✅")
        return redirect(_home_after_login(user, nxt), code=302)

    token_hash = _hash_token(token)

    ok_db = False
    try:
        hash_field = next((f for f in ("email_verify_token_hash", "verify_token_hash", "email_token_hash") if hasattr(user, f)), "")
        exp_field = next((f for f in ("email_verify_expires_at", "verify_expires_at", "email_token_expires_at") if hasattr(user, f)), "")

        if hash_field and exp_field:
            db_hash = _norm(getattr(user, hash_field, "") or "", max_len=200)
            exp = getattr(user, exp_field, None)
            if db_hash and isinstance(exp, datetime):
                if secrets.compare_digest(db_hash, token_hash) and _utcnow() <= exp:
                    ok_db = True
    except Exception:
        ok_db = False

    ok_session = False
    if not ok_db:
        st = _norm(session.get(_VERIFY_TOKEN_SESSION_KEY) or "", max_len=300)
        try:
            ts = int(session.get(_VERIFY_TOKEN_TS_SESSION_KEY) or 0)
        except Exception:
            ts = 0
        if st and ts and (_now() - ts) <= (_VERIFY_TTL_MIN * 60):
            try:
                ok_session = secrets.compare_digest(st, token)
            except Exception:
                ok_session = False

    if not ok_db and not ok_session:
        _flash("danger", "Token inválido o vencido. Pedí otro email.")
        return redirect(
            _url_for_safe("auth.verify_send", next=nxt) or f"/auth/verify/send?next={urllib.parse.quote(nxt)}",
            code=302,
        )

    try:
        if hasattr(user, "email_verified"):
            setattr(user, "email_verified", True)
        elif hasattr(user, "is_verified"):
            setattr(user, "is_verified", True)

        for f in ("email_verify_token_hash", "verify_token_hash", "email_token_hash"):
            if hasattr(user, f):
                setattr(user, f, None)
        for f in ("email_verify_expires_at", "verify_expires_at", "email_token_expires_at"):
            if hasattr(user, f):
                setattr(user, f, None)

        db.session.add(user)
        db.session.commit()
    except Exception:
        _db_rollback_quiet()
        _flash("danger", "No se pudo verificar. Reintentá.")
        return redirect(_login_url(nxt=nxt), code=302)

    session["email_verified"] = True
    session.pop(_VERIFY_TOKEN_SESSION_KEY, None)
    session.pop(_VERIFY_TOKEN_TS_SESSION_KEY, None)
    session.modified = True
    _rotate_wtf_csrf()

    _flash("success", "Cuenta verificada ✅")
    return redirect(_home_after_login(user, nxt), code=302)


__all__ = ["auth_bp"]
