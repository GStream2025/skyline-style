from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple, TypeVar
from urllib.parse import quote

from flask import abort, current_app, flash, jsonify, redirect, request, session, url_for

F = TypeVar("F", bound=Callable[..., Any])
AdminCredsFn = Callable[[str, str], bool]

CFG_AUTH_SECRET = "AUTH_SECRET"
CFG_AUTH_AUDIT_CALLBACK = "AUTH_AUDIT_CALLBACK"

CFG_AUTH_NEXT_PARAM = "AUTH_NEXT_PARAM"
CFG_AUTH_DEFAULT_NEXT = "AUTH_DEFAULT_NEXT"

CFG_AUTH_SOFT_RL_WINDOW_S = "AUTH_SOFT_RL_WINDOW_S"
CFG_AUTH_SOFT_RL_MAX = "AUTH_SOFT_RL_MAX"

CFG_VERIFY_TTL_S = "AUTH_VERIFY_TTL_S"
CFG_RESET_TTL_S = "AUTH_RESET_TTL_S"

CFG_REQUIRE_EMAIL_VERIFIED = "AUTH_REQUIRE_EMAIL_VERIFIED"

CFG_AUTH_TOKEN_LEN_MAX = "AUTH_TOKEN_LEN_MAX"
CFG_AUTH_PAYLOAD_LEN_MAX = "AUTH_PAYLOAD_LEN_MAX"
CFG_AUTH_IP_LEN_MAX = "AUTH_IP_LEN_MAX"
CFG_AUTH_UA_LEN_MAX = "AUTH_UA_LEN_MAX"
CFG_AUTH_EMAIL_LEN_MAX = "AUTH_EMAIL_LEN_MAX"

CFG_AUTH_VERIFY_BIND_UA = "AUTH_VERIFY_BIND_UA"
CFG_AUTH_VERIFY_BIND_IP = "AUTH_VERIFY_BIND_IP"

CFG_AUTH_DISABLE_FLASH = "AUTH_DISABLE_FLASH"
CFG_AUTH_REDIRECT_CODE = "AUTH_REDIRECT_CODE"

DEFAULT_NEXT_PARAM = "next"
DEFAULT_DEFAULT_NEXT = "/account"

_NO_STORE_HEADERS: Dict[str, str] = {
    "Cache-Control": "no-store, max-age=0, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off", "unchecked"}

_ADMIN_CREDS_FALLBACK: AdminCredsFn


def _admin_creds_false(_: str, __: str) -> bool:
    return False


try:
    from app.utils.admin_gate import admin_creds_ok as admin_creds_ok  # type: ignore
except Exception:
    admin_creds_ok = _admin_creds_false  # type: ignore


@dataclass(frozen=True)
class TokenDecision:
    ok: bool
    reason: str
    payload: Optional[Dict[str, Any]] = None


def _cfg(name: str, default: Any) -> Any:
    try:
        return current_app.config.get(name, default)
    except Exception:
        return default


def _cfg_int(name: str, default: int, *, min_v: int, max_v: int) -> int:
    try:
        v = int(_cfg(name, default) or default)
    except Exception:
        v = default
    if v < min_v:
        return min_v
    if v > max_v:
        return max_v
    return v


def _cfg_bool(name: str, default: bool = False) -> bool:
    v = _cfg(name, default)
    if v is True or v is False:
        return bool(v)
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, str):
        s = v.strip().lower()
        if not s:
            return default
        if s in _TRUE:
            return True
        if s in _FALSE:
            return False
    return default


def _safe_str(v: Any, *, max_len: int = 512) -> str:
    if v is None:
        return ""
    s = str(v).replace("\x00", "").replace("\u200b", "").strip()
    if "\r" in s or "\n" in s:
        s = s.replace("\r", "").replace("\n", "")
    if "\t" in s:
        s = s.replace("\t", " ")
    if max_len > 0 and len(s) > max_len:
        s = s[:max_len]
    return s


def _is_truthy(v: Any) -> bool:
    if v is True:
        return True
    if v is False or v is None:
        return False
    if isinstance(v, (int, float)):
        return v == 1
    if isinstance(v, str):
        s = v.strip().lower()
        if not s or s in _FALSE:
            return False
        return s in _TRUE or s == "1"
    return False


def _client_ip() -> str:
    max_len = _cfg_int(CFG_AUTH_IP_LEN_MAX, 64, min_v=16, max_v=256)
    try:
        fwd = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        if fwd:
            return fwd[:max_len]
    except Exception:
        pass
    try:
        return (request.remote_addr or "")[:max_len]
    except Exception:
        return ""


def _client_ua() -> str:
    max_len = _cfg_int(CFG_AUTH_UA_LEN_MAX, 180, min_v=60, max_v=512)
    try:
        return _safe_str(request.headers.get("User-Agent") or "", max_len=max_len)
    except Exception:
        return ""


def _is_json_like_request() -> bool:
    try:
        if request.is_json:
            return True
    except Exception:
        pass

    accept = (request.headers.get("Accept") or "").lower()
    if "application/json" in accept or "text/json" in accept:
        return True

    ctype = (request.headers.get("Content-Type") or "").lower()
    if "application/json" in ctype:
        return True

    xrw = (request.headers.get("X-Requested-With") or "").lower()
    if xrw == "xmlhttprequest":
        return True

    try:
        best = request.accept_mimetypes.best_match(["application/json", "text/html"])
        if best == "application/json" and request.accept_mimetypes[best] >= request.accept_mimetypes["text/html"]:
            return True
    except Exception:
        pass

    return False


def _audit(event: Dict[str, Any]) -> None:
    e = dict(event or {})
    e.setdefault("ip", _client_ip())
    e.setdefault("ua", _client_ua())
    e.setdefault("ts", int(time.time()))

    try:
        cb = _cfg(CFG_AUTH_AUDIT_CALLBACK, None)
        if callable(cb):
            cb(e)
    except Exception:
        pass

    try:
        if current_app and getattr(current_app, "debug", False):
            current_app.logger.debug("auth_audit %s", e)
    except Exception:
        pass


def _soft_rate_limit(bucket: str) -> Tuple[bool, int]:
    window_s = _cfg_int(CFG_AUTH_SOFT_RL_WINDOW_S, 10, min_v=1, max_v=600)
    max_hits = _cfg_int(CFG_AUTH_SOFT_RL_MAX, 25, min_v=1, max_v=1000)

    key = f"_rl:{_safe_str(bucket, max_len=48)}"
    try:
        now = int(time.time())
        data = session.get(key)
        if not isinstance(data, dict):
            data = {}

        start = int(data.get("start") or 0)
        hits = int(data.get("hits") or 0)

        if start <= 0 or now - start >= window_s:
            start = now
            hits = 0

        hits += 1
        session[key] = {"start": start, "hits": hits}
        session.modified = True

        remaining = max(0, max_hits - hits)
        return (hits <= max_hits, remaining)
    except Exception:
        return (True, max_hits)


def normalize_email(email: Any) -> str:
    max_len = _cfg_int(CFG_AUTH_EMAIL_LEN_MAX, 254, min_v=64, max_v=320)
    s = _safe_str(email, max_len=max_len).lower()
    s = s.replace(" ", "")
    return s


def email_is_valid(email: Any) -> bool:
    e = normalize_email(email)
    if not e or len(e) > 254:
        return False
    return bool(_EMAIL_RE.match(e))


def _clean_next_path(raw: Optional[str], *, default_path: str) -> str:
    p = (raw or "").strip()
    if not p:
        return default_path

    pl = p.lower()
    if (
        not p.startswith("/")
        or p.startswith("//")
        or "://" in p
        or "\\" in p
        or "\n" in p
        or "\r" in p
        or "\t" in p
        or " " in p
        or ".." in p
        or pl.startswith("/%5c")
        or pl.startswith("/%2f%2f")
        or pl.startswith("/%2f%5c")
        or pl.startswith("/%2f%2f")
        or pl.startswith("/%5c%5c")
    ):
        return default_path

    if "?" in p:
        p = p.split("?", 1)[0]
    if "#" in p:
        p = p.split("#", 1)[0]

    if not p.startswith("/"):
        return default_path

    return p or default_path


def resolve_next_path(*, default_next: Optional[str] = None) -> str:
    next_param = _safe_str(_cfg(CFG_AUTH_NEXT_PARAM, DEFAULT_NEXT_PARAM), max_len=32) or DEFAULT_NEXT_PARAM
    dnext = _safe_str(_cfg(CFG_AUTH_DEFAULT_NEXT, default_next or DEFAULT_DEFAULT_NEXT), max_len=256) or DEFAULT_DEFAULT_NEXT

    raw = None
    try:
        raw = request.args.get(next_param)
    except Exception:
        raw = None

    try:
        fallback = request.path or dnext
    except Exception:
        fallback = dnext

    out = _clean_next_path(raw, default_path=_clean_next_path(fallback, default_path=dnext))
    if out.startswith("/auth/login") or out.startswith("/auth/register") or out.startswith("/admin/login") or out.startswith("/admin/register"):
        out = dnext
    return out


def _safe_url_for(endpoint: str, **values: Any) -> Optional[str]:
    try:
        return url_for(endpoint, **values)
    except Exception:
        return None


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64u_dec(s: str) -> Optional[bytes]:
    try:
        pad = "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode((s + pad).encode("ascii"))
    except Exception:
        return None


def _auth_secret() -> bytes:
    cfg = _safe_str(_cfg(CFG_AUTH_SECRET, ""), max_len=256)
    env = _safe_str(os.getenv("AUTH_SECRET"), max_len=256)
    raw = cfg or env
    if raw:
        return raw.encode("utf-8")
    try:
        sk = getattr(current_app, "secret_key", None)
        if isinstance(sk, str) and sk:
            return sk.encode("utf-8")
    except Exception:
        pass
    return b"change-me"


def _sign(data: bytes) -> str:
    sig = hmac.new(_auth_secret(), data, hashlib.sha256).digest()
    return _b64u(sig)


def _payload_json(payload: Dict[str, Any]) -> bytes:
    max_len = _cfg_int(CFG_AUTH_PAYLOAD_LEN_MAX, 4000, min_v=256, max_v=20000)
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(raw) > max_len:
        raw = raw[:max_len]
    return raw


def _make_token(payload: Dict[str, Any], *, ttl_s: int) -> str:
    now = int(time.time())
    body = dict(payload or {})
    body["iat"] = now
    body["exp"] = now + max(60, int(ttl_s))

    if _cfg_bool(CFG_AUTH_VERIFY_BIND_IP, False):
        body["ip"] = _client_ip()

    if _cfg_bool(CFG_AUTH_VERIFY_BIND_UA, False):
        body["ua"] = hashlib.sha256(_client_ua().encode("utf-8")).hexdigest()[:24]

    raw = _payload_json(body)
    mac = _sign(raw)
    return f"{_b64u(raw)}.{mac}"


def _read_token(token: str) -> TokenDecision:
    tmax = _cfg_int(CFG_AUTH_TOKEN_LEN_MAX, 4096, min_v=512, max_v=20000)
    t = _safe_str(token, max_len=tmax)
    if not t or "." not in t:
        return TokenDecision(False, "bad_format")

    a, b = t.split(".", 1)
    raw = _b64u_dec(a)
    if raw is None:
        return TokenDecision(False, "bad_b64")

    expected = _sign(raw)
    try:
        ok_sig = secrets.compare_digest(expected, b)
    except Exception:
        ok_sig = hmac.compare_digest(expected, b)
    if not ok_sig:
        return TokenDecision(False, "bad_sig")

    try:
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            return TokenDecision(False, "bad_payload")
    except Exception:
        return TokenDecision(False, "bad_payload")

    now = int(time.time())
    exp = int(payload.get("exp") or 0)
    if exp <= 0 or now > exp:
        return TokenDecision(False, "expired")

    if _cfg_bool(CFG_AUTH_VERIFY_BIND_IP, False):
        ip = _safe_str(payload.get("ip"), max_len=256)
        if ip and ip != _client_ip():
            return TokenDecision(False, "ip_mismatch")

    if _cfg_bool(CFG_AUTH_VERIFY_BIND_UA, False):
        ua = _safe_str(payload.get("ua"), max_len=64)
        cur = hashlib.sha256(_client_ua().encode("utf-8")).hexdigest()[:24]
        if ua and ua != cur:
            return TokenDecision(False, "ua_mismatch")

    return TokenDecision(True, "ok", payload)


def make_verify_email_token(*, user_id: Any, email: Any, ttl_s: Optional[int] = None) -> str:
    ttl = _cfg_int(CFG_VERIFY_TTL_S, int(ttl_s or 60 * 60 * 24), min_v=300, max_v=60 * 60 * 24 * 30)
    return _make_token({"typ": "verify", "uid": str(user_id), "email": normalize_email(email)}, ttl_s=ttl)


def make_password_reset_token(*, user_id: Any, email: Any, ttl_s: Optional[int] = None) -> str:
    ttl = _cfg_int(CFG_RESET_TTL_S, int(ttl_s or 60 * 60), min_v=300, max_v=60 * 60 * 24 * 7)
    return _make_token({"typ": "reset", "uid": str(user_id), "email": normalize_email(email)}, ttl_s=ttl)


def verify_token(token: str, *, expected_type: str) -> TokenDecision:
    d = _read_token(token)
    if not d.ok:
        return d

    payload = d.payload or {}
    typ = _safe_str(payload.get("typ"), max_len=16)
    if typ != expected_type:
        return TokenDecision(False, "wrong_type")

    uid = _safe_str(payload.get("uid"), max_len=128)
    email = _safe_str(payload.get("email"), max_len=254).lower()
    if not uid or not email or not email_is_valid(email):
        return TokenDecision(False, "bad_claims")

    return d


def load_user_by_email(email: str) -> Optional[Any]:
    try:
        from app.models import User, db  # type: ignore
    except Exception:
        return None

    e = normalize_email(email)
    if not email_is_valid(e):
        return None

    try:
        q = getattr(User, "query", None)
        if q is not None:
            return q.filter_by(email=e).first()
    except Exception:
        pass

    try:
        return db.session.query(User).filter(User.email == e).first()  # type: ignore[attr-defined]
    except Exception:
        return None


def load_user_by_id(user_id: Any) -> Optional[Any]:
    try:
        from app.models import User, db  # type: ignore
    except Exception:
        return None

    uid = _safe_str(user_id, max_len=128)
    if not uid:
        return None

    for attr in ("id", "user_id", "uuid"):
        try:
            col = getattr(User, attr, None)
            if col is not None:
                return db.session.query(User).filter(col == uid).first()  # type: ignore[attr-defined]
        except Exception:
            continue

    try:
        return getattr(User, "query").get(uid)  # type: ignore[attr-defined]
    except Exception:
        return None


def mark_email_verified(user: Any) -> bool:
    try:
        from app.models import db  # type: ignore
    except Exception:
        db = None  # type: ignore

    changed = False
    for flag in ("email_verified", "is_email_verified", "verified"):
        if hasattr(user, flag):
            try:
                if not _is_truthy(getattr(user, flag)):
                    setattr(user, flag, True)
                    changed = True
            except Exception:
                pass

    for ts in ("email_verified_at", "verified_at"):
        if hasattr(user, ts):
            try:
                if getattr(user, ts, None) is None:
                    setattr(user, ts, int(time.time()))
                    changed = True
            except Exception:
                pass

    if not changed:
        return True

    try:
        if db is not None:
            db.session.add(user)
            db.session.commit()
            return True
    except Exception:
        try:
            if db is not None:
                db.session.rollback()
        except Exception:
            pass
    return False


def require_verified_email(user: Any) -> bool:
    if not _cfg_bool(CFG_REQUIRE_EMAIL_VERIFIED, False):
        return True

    for flag in ("email_verified", "is_email_verified", "verified"):
        try:
            if hasattr(user, flag) and _is_truthy(getattr(user, flag)):
                return True
        except Exception:
            pass
    return False


def auth_rate_limit_or_429(bucket: str) -> Optional[Any]:
    ok, remaining = _soft_rate_limit(bucket)
    if ok:
        return None

    _audit({"type": "auth_rl", "ok": False, "bucket": _safe_str(bucket, max_len=48), "remaining": remaining})

    if _is_json_like_request():
        return jsonify({"ok": False, "error": "rate_limited", "message": "Demasiados intentos. Probá más tarde."}), 429

    if not _cfg_bool(CFG_AUTH_DISABLE_FLASH, False):
        try:
            flash("Demasiados intentos. Probá más tarde.", "warning")
        except Exception:
            pass

    abort(429)


def redirect_with_no_store(url: str):
    resp = redirect(url, code=_cfg_int(CFG_AUTH_REDIRECT_CODE, 302, min_v=301, max_v=308))
    try:
        for k, v in _NO_STORE_HEADERS.items():
            resp.headers[k] = v
        resp.headers.setdefault("Vary", "Cookie")
    except Exception:
        pass
    return resp


def safe_redirect_to(endpoint: str, *, next_path: Optional[str] = None, default_next: Optional[str] = None) -> Any:
    np = next_path or resolve_next_path(default_next=default_next)
    u = _safe_url_for(endpoint, next=np) or f"{endpoint}?next={quote(np, safe='/')}"
    return redirect_with_no_store(u)


__all__ = [
    "TokenDecision",
    "normalize_email",
    "email_is_valid",
    "resolve_next_path",
    "make_verify_email_token",
    "make_password_reset_token",
    "verify_token",
    "load_user_by_email",
    "load_user_by_id",
    "mark_email_verified",
    "require_verified_email",
    "auth_rate_limit_or_429",
    "redirect_with_no_store",
    "safe_redirect_to",
    "admin_creds_ok",
]
from __future__ import annotations

from functools import wraps
from typing import Any, Callable, Optional, TypeVar, cast

from flask import abort, current_app, flash, redirect, request, session, url_for

F = TypeVar("F", bound=Callable[..., Any])

_TRUE = {"1", "true", "yes", "y", "on", "checked"}


def _is_admin_session() -> bool:
    try:
        v = session.get("is_admin") or session.get("ADMIN_SESSION") or session.get("admin")
        if isinstance(v, str):
            return v.strip().lower() in _TRUE
        return bool(v)
    except Exception:
        return False


def _clean_next(raw: Optional[str], *, fallback: str = "/admin") -> str:
    p = (raw or "").strip()
    if not p or not p.startswith("/") or p.startswith("//") or "://" in p or "\\" in p or ".." in p:
        return fallback
    if "?" in p:
        p = p.split("?", 1)[0]
    if "#" in p:
        p = p.split("#", 1)[0]
    if p.startswith("/admin/login") or p.startswith("/admin/register") or p.startswith("/admin/logout"):
        return fallback
    return p or fallback


def admin_required(fn: F) -> F:
    @wraps(fn)
    def _wrap(*args: Any, **kwargs: Any):
        if _is_admin_session():
            return fn(*args, **kwargs)

        try:
            if request.accept_mimetypes.best == "application/json" or request.is_json:
                abort(401)
        except Exception:
            pass

        try:
            flash("Necesitás iniciar sesión como admin.", "warning")
        except Exception:
            pass

        try:
            nxt = _clean_next(request.full_path or request.path, fallback="/admin")
        except Exception:
            nxt = "/admin"

        try:
            ep = current_app.config.get("ADMIN_LOGIN_ENDPOINT", "admin.login")
            return redirect(url_for(ep, next=nxt), code=302)
        except Exception:
            return redirect(f"/admin/login?next={nxt}", code=302)

    return cast(F, _wrap)


try:
    from app.utils.admin_gate import admin_creds_ok  # type: ignore
except Exception:
    def admin_creds_ok(*args: Any, **kwargs: Any) -> bool:  # type: ignore
        return False


__all__ = [
    *(__all__ if "__all__" in globals() else []),
    "admin_required",
    "admin_creds_ok",
]
