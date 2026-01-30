from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Set, Tuple, TypeVar, cast
from urllib.parse import quote

from flask import abort, current_app, flash, jsonify, redirect, request, session, url_for

F = TypeVar("F", bound=Callable[..., Any])

ADMIN_SESSION_KEY_DEFAULT = "admin_logged_in"
ADMIN_NEXT_PARAM_DEFAULT = "next"
ADMIN_LOGIN_ENDPOINT_DEFAULT = "admin.login"
ADMIN_REGISTER_ENDPOINT_DEFAULT = "admin.register"
ADMIN_LOGIN_FALLBACK_PATH_DEFAULT = "/admin/login"
ADMIN_REGISTER_FALLBACK_PATH_DEFAULT = "/admin/register"

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off", "unchecked"}

_NO_STORE_HEADERS: Dict[str, str] = {
    "Cache-Control": "no-store, max-age=0, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}

_DEFAULT_ALLOWED_ROLES = {"admin", "staff"}
_DEFAULT_MAX_STR = 512


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    reason: str
    login_url: Optional[str] = None
    next_path: Optional[str] = None


def _cfg(name: str, default: Any) -> Any:
    try:
        cfg = current_app.config  # type: ignore[attr-defined]
        return cfg.get(name, default)
    except Exception:
        return default


def _cfg_int(name: str, default: int, *, min_v: int, max_v: int) -> int:
    try:
        raw = _cfg(name, default)
        v = int(raw) if raw is not None else int(default)
    except Exception:
        v = int(default)
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


def _env(name: str, default: str = "", *, max_len: int = _DEFAULT_MAX_STR) -> str:
    v = os.getenv(name)
    return _safe_str(default if v is None else v, max_len=max_len)


def _safe_str(v: Any, *, max_len: int = _DEFAULT_MAX_STR) -> str:
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
        return v == 1 or v == 1.0
    if isinstance(v, str):
        s = v.strip().lower()
        if not s or s in _FALSE:
            return False
        return s in _TRUE or s == "1"
    return bool(v)


def _is_json_like_request() -> bool:
    try:
        if request.is_json:
            return True
    except Exception:
        pass

    accept = (request.headers.get("Accept") or "").lower()
    ctype = (request.headers.get("Content-Type") or "").lower()
    xrw = (request.headers.get("X-Requested-With") or "").lower()

    if "application/json" in accept or "text/json" in accept:
        return True
    if "application/json" in ctype:
        return True
    if xrw == "xmlhttprequest":
        return True

    try:
        best = request.accept_mimetypes.best_match(["application/json", "text/html"])
        if best == "application/json" and request.accept_mimetypes[best] >= request.accept_mimetypes["text/html"]:
            return True
    except Exception:
        pass

    return False


def _clean_next_path(raw: Optional[str], *, default_path: str = "/admin") -> str:
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
        or pl.startswith("/%5c%5c")
    ):
        return default_path

    if "?" in p:
        p = p.split("?", 1)[0]
    if "#" in p:
        p = p.split("#", 1)[0]

    return p if p.startswith("/") and p else default_path


def _safe_url_for(endpoint: str, **values: Any) -> Optional[str]:
    try:
        return url_for(endpoint, **values)
    except Exception:
        return None


def _no_store_headers(resp: Any) -> Any:
    try:
        for k, v in _NO_STORE_HEADERS.items():
            resp.headers[k] = v
        resp.headers.setdefault("Vary", "Cookie")
    except Exception:
        pass
    return resp


def _resolve_admin_endpoint(cfg_key: str, default_endpoint: str) -> str:
    ep = _safe_str(_cfg(cfg_key, default_endpoint), max_len=128)
    return ep or default_endpoint


def _resolve_admin_fallback_path(cfg_key: str, default_path: str) -> str:
    p = _safe_str(_cfg(cfg_key, default_path), max_len=240)
    if not p:
        return default_path
    if not p.startswith("/"):
        return default_path
    if "://" in p or "\\" in p or p.startswith("//"):
        return default_path
    return p.split("?", 1)[0].split("#", 1)[0] or default_path


def _build_url_with_next(base: str, *, next_param: str, next_path: str) -> str:
    base_clean = _safe_str(base, max_len=300)
    if not base_clean:
        base_clean = "/"
    if "?" in base_clean:
        base_clean = base_clean.split("?", 1)[0]
    if "#" in base_clean:
        base_clean = base_clean.split("#", 1)[0]
    sep = "&" if "?" in base else "?"
    return f"{base_clean}{sep}{quote(next_param, safe='')}={quote(next_path, safe='/')}"


def build_admin_login_url(*, next_param: str = ADMIN_NEXT_PARAM_DEFAULT, next_path: str = "/admin") -> str:
    nxt = _clean_next_path(next_path, default_path="/admin")
    ep = _resolve_admin_endpoint("ADMIN_LOGIN_ENDPOINT", ADMIN_LOGIN_ENDPOINT_DEFAULT)
    u = _safe_url_for(ep, **{next_param: nxt})
    if u:
        return u
    fallback = _resolve_admin_fallback_path("ADMIN_LOGIN_FALLBACK_PATH", ADMIN_LOGIN_FALLBACK_PATH_DEFAULT)
    return _build_url_with_next(fallback, next_param=next_param, next_path=nxt)


def build_admin_register_url(*, next_param: str = ADMIN_NEXT_PARAM_DEFAULT, next_path: str = "/admin") -> str:
    nxt = _clean_next_path(next_path, default_path="/admin")
    ep = _resolve_admin_endpoint("ADMIN_REGISTER_ENDPOINT", ADMIN_REGISTER_ENDPOINT_DEFAULT)
    u = _safe_url_for(ep, **{next_param: nxt})
    if u:
        return u
    fallback = _resolve_admin_fallback_path("ADMIN_REGISTER_FALLBACK_PATH", ADMIN_REGISTER_FALLBACK_PATH_DEFAULT)
    return _build_url_with_next(fallback, next_param=next_param, next_path=nxt)


def _allowed_by_session(session_key: str) -> bool:
    try:
        if _is_truthy(session.get(session_key)) or _is_truthy(session.get("is_admin")):
            return True
    except Exception:
        pass
    return False


def _session_role_ok() -> bool:
    role_key = _safe_str(_cfg("ADMIN_ROLE_KEY", "role"), max_len=64) or "role"
    allowed = _cfg("ADMIN_ALLOWED_ROLES", _DEFAULT_ALLOWED_ROLES)
    try:
        allowed_set: Set[str] = set(allowed) if allowed else set(_DEFAULT_ALLOWED_ROLES)
    except Exception:
        allowed_set = set(_DEFAULT_ALLOWED_ROLES)

    try:
        role = session.get(role_key)
    except Exception:
        return True

    if role is None:
        return True

    return _safe_str(role, max_len=32).lower() in {r.lower() for r in allowed_set}


def _parse_admin_emails(v: Any) -> Set[str]:
    if v is None:
        return set()
    if isinstance(v, (set, list, tuple)):
        out = {str(x).strip().lower() for x in v if x}
        return {x for x in out if "@" in x}
    s = str(v).strip()
    if not s:
        return set()
    parts = [p.strip().lower() for p in s.replace(";", ",").split(",")]
    return {p for p in parts if p and "@" in p}


def _constant_time_eq(a: str, b: str) -> bool:
    try:
        return secrets.compare_digest(a, b)
    except Exception:
        return hmac.compare_digest(a, b)


def _check_password_hash_if_possible(pwhash: str, password: str) -> Optional[bool]:
    pwhash_s = _safe_str(pwhash, max_len=512)
    if not pwhash_s:
        return None
    try:
        from werkzeug.security import check_password_hash  # type: ignore

        return bool(check_password_hash(pwhash_s, password))
    except Exception:
        return None


def admin_creds_ok(email: str, password: str) -> bool:
    email_s = _safe_str(email, max_len=200).lower()
    password_s = _safe_str(password, max_len=500)
    if not email_s or not password_s:
        return False

    cfg_emails = _parse_admin_emails(_cfg("ADMIN_EMAILS", None))
    env_email = _env("ADMIN_EMAIL", "", max_len=220).lower()
    if env_email:
        cfg_emails.add(env_email)

    if cfg_emails and email_s not in cfg_emails:
        return False

    pw_hash = _safe_str(_cfg("ADMIN_PASSWORD_HASH", ""), max_len=512) or _env("ADMIN_PASSWORD_HASH", "", max_len=512)
    if pw_hash:
        checked = _check_password_hash_if_possible(pw_hash, password_s)
        if checked is not None:
            return checked
        return _constant_time_eq(pw_hash, password_s)

    pw_plain = _safe_str(_cfg("ADMIN_PASSWORD", ""), max_len=500) or _env("ADMIN_PASSWORD", "", max_len=500)
    if not pw_plain:
        return False
    return _constant_time_eq(pw_plain, password_s)


def _gate_decision(
    *,
    session_key: str,
    next_param: str,
    default_next: str,
    raw_next: Optional[str],
    fallback_next: str,
) -> GateDecision:
    if _allowed_by_session(session_key) and _session_role_ok():
        return GateDecision(True, "ok")

    dnext = _safe_str(_cfg("ADMIN_DEFAULT_NEXT", default_next), max_len=256) or default_next
    base_fallback = _clean_next_path(fallback_next, default_path=dnext)
    nxt = _clean_next_path(raw_next, default_path=base_fallback)
    if nxt.startswith(("/admin/login", "/admin/register", "/admin/logout")):
        nxt = _clean_next_path(dnext, default_path="/admin")

    return GateDecision(
        allowed=False,
        reason="login_required",
        login_url=build_admin_login_url(next_param=next_param, next_path=nxt),
        next_path=nxt,
    )


def gate_admin_or_redirect(
    *,
    session_key: str = ADMIN_SESSION_KEY_DEFAULT,
    next_param: str = ADMIN_NEXT_PARAM_DEFAULT,
    default_next: str = "/admin",
) -> Optional[Any]:
    sess_key = _safe_str(_cfg("ADMIN_SESSION_KEY", session_key), max_len=64) or session_key
    try:
        raw_next = request.args.get(next_param)
    except Exception:
        raw_next = None
    try:
        fallback_next = request.path or "/"
    except Exception:
        fallback_next = "/"

    d = _gate_decision(
        session_key=sess_key,
        next_param=next_param,
        default_next=default_next,
        raw_next=raw_next,
        fallback_next=fallback_next,
    )
    if d.allowed:
        return None
    return _no_store_headers(redirect(d.login_url or build_admin_login_url(next_param=next_param, next_path="/admin"), code=302))


def gate_admin_or_abort(
    *,
    session_key: str = ADMIN_SESSION_KEY_DEFAULT,
    next_param: str = ADMIN_NEXT_PARAM_DEFAULT,
    default_next: str = "/admin",
    abort_code_json: int = 401,
    abort_code_html: int = 403,
) -> None:
    resp = gate_admin_or_redirect(session_key=session_key, next_param=next_param, default_next=default_next)
    if resp is None:
        return
    if _is_json_like_request():
        abort(int(_cfg("ADMIN_ABORT_CODE_JSON", abort_code_json) or abort_code_json))
    abort(int(_cfg("ADMIN_ABORT_CODE_HTML", abort_code_html) or abort_code_html))


def admin_required(
    view: Optional[F] = None,
    *,
    session_key: str = ADMIN_SESSION_KEY_DEFAULT,
    next_param: str = ADMIN_NEXT_PARAM_DEFAULT,
    default_next: str = "/admin",
    abort_code_json: int = 401,
    abort_code_html: Optional[int] = None,
    flash_message: str = "Tenés que iniciar sesión como admin.",
    flash_category: str = "warning",
) -> Any:
    def decorator(fn: F) -> F:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any):
            sess_key = _safe_str(_cfg("ADMIN_SESSION_KEY", session_key), max_len=64) or session_key
            dnext = _safe_str(_cfg("ADMIN_DEFAULT_NEXT", default_next), max_len=256) or default_next
            acj = int(_cfg("ADMIN_ABORT_CODE_JSON", abort_code_json) or abort_code_json)
            ach_cfg = _cfg("ADMIN_ABORT_CODE_HTML", abort_code_html)
            ach: Optional[int]
            try:
                ach = None if ach_cfg is None else int(ach_cfg)
            except Exception:
                ach = abort_code_html

            if _allowed_by_session(sess_key) and _session_role_ok():
                return fn(*args, **kwargs)

            if _is_json_like_request():
                abort(acj)

            msg = _safe_str(_cfg("ADMIN_FLASH_MESSAGE", flash_message), max_len=180) or flash_message
            cat = _safe_str(_cfg("ADMIN_FLASH_CATEGORY", flash_category), max_len=32) or flash_category
            try:
                if msg and not _cfg_bool("ADMIN_DISABLE_FLASH", False):
                    flash(msg, cat)
            except Exception:
                pass

            if ach is not None:
                abort(ach)

            try:
                raw_next = request.args.get(next_param)
            except Exception:
                raw_next = None
            try:
                fallback_next = request.path or "/"
            except Exception:
                fallback_next = "/"

            next_path = _clean_next_path(raw_next, default_path=_clean_next_path(fallback_next, default_path=dnext))
            if next_path.startswith(("/admin/login", "/admin/register", "/admin/logout")):
                next_path = _clean_next_path(dnext, default_path="/admin")

            resp = redirect(build_admin_login_url(next_param=next_param, next_path=next_path), code=302)
            return _no_store_headers(resp)

        return cast(F, wrapper)

    if view is None:
        return decorator
    return decorator(view)


def admin_login_success(
    *,
    session_key: str = ADMIN_SESSION_KEY_DEFAULT,
    role: Optional[str] = None,
    persist_seconds: Optional[int] = None,
) -> None:
    key = _safe_str(_cfg("ADMIN_SESSION_KEY", session_key), max_len=64) or session_key
    try:
        session[key] = True
        session["is_admin"] = True
        if role:
            session[_safe_str(_cfg("ADMIN_ROLE_KEY", "role"), max_len=64) or "role"] = _safe_str(role, max_len=32).lower()
        if persist_seconds is not None:
            s = _cfg_int("ADMIN_SESSION_TTL_S", int(persist_seconds), min_v=60, max_v=60 * 60 * 24 * 30)
            session.permanent = True
            try:
                current_app.permanent_session_lifetime = s  # type: ignore[attr-defined]
            except Exception:
                pass
        session.modified = True
    except Exception:
        pass


def admin_logout_success(*, session_key: str = ADMIN_SESSION_KEY_DEFAULT, clear_all: bool = False) -> None:
    key = _safe_str(_cfg("ADMIN_SESSION_KEY", session_key), max_len=64) or session_key
    try:
        if clear_all:
            session.clear()
        else:
            session.pop(key, None)
            session.pop("is_admin", None)
            rk = _safe_str(_cfg("ADMIN_ROLE_KEY", "role"), max_len=64) or "role"
            session.pop(rk, None)
        session.modified = True
    except Exception:
        pass


def json_gate_response(decision: GateDecision, *, status: int = 401) -> Tuple[Any, int]:
    return jsonify(
        {
            "ok": bool(decision.allowed),
            "reason": decision.reason,
            "login_url": decision.login_url,
            "next": decision.next_path,
        }
    ), int(status)


def gate_admin_json_or_none(
    *,
    session_key: str = ADMIN_SESSION_KEY_DEFAULT,
    next_param: str = ADMIN_NEXT_PARAM_DEFAULT,
    default_next: str = "/admin",
    status: int = 401,
) -> Optional[Tuple[Any, int]]:
    sess_key = _safe_str(_cfg("ADMIN_SESSION_KEY", session_key), max_len=64) or session_key
    try:
        raw_next = request.args.get(next_param)
    except Exception:
        raw_next = None
    try:
        fallback_next = request.path or "/"
    except Exception:
        fallback_next = "/"

    d = _gate_decision(
        session_key=sess_key,
        next_param=next_param,
        default_next=default_next,
        raw_next=raw_next,
        fallback_next=fallback_next,
    )
    if d.allowed:
        return None
    return json_gate_response(d, status=status)


def get_admin_role(*, default: Optional[str] = None) -> Optional[str]:
    rk = _safe_str(_cfg("ADMIN_ROLE_KEY", "role"), max_len=64) or "role"
    try:
        v = session.get(rk)
    except Exception:
        return default
    s = _safe_str(v, max_len=32).lower()
    return s or default


def is_admin_logged_in(*, session_key: str = ADMIN_SESSION_KEY_DEFAULT) -> bool:
    key = _safe_str(_cfg("ADMIN_SESSION_KEY", session_key), max_len=64) or session_key
    return _allowed_by_session(key) and _session_role_ok()


def get_admin_next_param() -> str:
    return _safe_str(_cfg("ADMIN_NEXT_PARAM", ADMIN_NEXT_PARAM_DEFAULT), max_len=32) or ADMIN_NEXT_PARAM_DEFAULT


def get_admin_default_next() -> str:
    return _safe_str(_cfg("ADMIN_DEFAULT_NEXT", "/admin"), max_len=256) or "/admin"


def get_admin_login_endpoint() -> str:
    return _resolve_admin_endpoint("ADMIN_LOGIN_ENDPOINT", ADMIN_LOGIN_ENDPOINT_DEFAULT)


def get_admin_register_endpoint() -> str:
    return _resolve_admin_endpoint("ADMIN_REGISTER_ENDPOINT", ADMIN_REGISTER_ENDPOINT_DEFAULT)


def get_admin_login_fallback_path() -> str:
    return _resolve_admin_fallback_path("ADMIN_LOGIN_FALLBACK_PATH", ADMIN_LOGIN_FALLBACK_PATH_DEFAULT)


def get_admin_register_fallback_path() -> str:
    return _resolve_admin_fallback_path("ADMIN_REGISTER_FALLBACK_PATH", ADMIN_REGISTER_FALLBACK_PATH_DEFAULT)


def set_admin_allowed_roles(roles: Sequence[str]) -> None:
    try:
        current_app.config["ADMIN_ALLOWED_ROLES"] = list({str(r).strip().lower() for r in roles if r})  # type: ignore[attr-defined]
    except Exception:
        pass


def set_admin_role_key(key: str) -> None:
    k = _safe_str(key, max_len=64)
    if not k:
        return
    try:
        current_app.config["ADMIN_ROLE_KEY"] = k  # type: ignore[attr-defined]
    except Exception:
        pass


def set_admin_session_key(key: str) -> None:
    k = _safe_str(key, max_len=64)
    if not k:
        return
    try:
        current_app.config["ADMIN_SESSION_KEY"] = k  # type: ignore[attr-defined]
    except Exception:
        pass


def set_admin_next_param(param: str) -> None:
    p = _safe_str(param, max_len=32)
    if not p:
        return
    try:
        current_app.config["ADMIN_NEXT_PARAM"] = p  # type: ignore[attr-defined]
    except Exception:
        pass


def set_admin_default_next(path: str) -> None:
    p = _clean_next_path(path, default_path="/admin")
    try:
        current_app.config["ADMIN_DEFAULT_NEXT"] = p  # type: ignore[attr-defined]
    except Exception:
        pass


def set_admin_flash(message: str, category: str = "warning") -> None:
    try:
        current_app.config["ADMIN_FLASH_MESSAGE"] = _safe_str(message, max_len=180)  # type: ignore[attr-defined]
        current_app.config["ADMIN_FLASH_CATEGORY"] = _safe_str(category, max_len=32)  # type: ignore[attr-defined]
    except Exception:
        pass


def set_admin_abort_codes(*, json_code: int = 401, html_code: int = 403) -> None:
    try:
        current_app.config["ADMIN_ABORT_CODE_JSON"] = int(json_code)  # type: ignore[attr-defined]
        current_app.config["ADMIN_ABORT_CODE_HTML"] = int(html_code)  # type: ignore[attr-defined]
    except Exception:
        pass


def get_no_store_headers() -> Dict[str, str]:
    return dict(_NO_STORE_HEADERS)


def apply_no_store_headers(headers: Mapping[str, str]) -> None:
    try:
        for k, v in dict(headers).items():
            if k and v is not None:
                _NO_STORE_HEADERS[str(k)] = str(v)
    except Exception:
        pass


def admin_audit_event(event: Mapping[str, Any]) -> None:
    cb = _cfg("ADMIN_AUDIT_CALLBACK", None)
    if callable(cb):
        try:
            cb(dict(event))
        except Exception:
            pass


def admin_login_audit(ok: bool, *, email: Optional[str] = None, reason: str = "login") -> None:
    admin_audit_event(
        {
            "type": "admin_login",
            "ok": bool(ok),
            "reason": _safe_str(reason, max_len=64),
            "email": _safe_str(email, max_len=220).lower() if email else None,
            "ip": _safe_str((request.headers.get("X-Forwarded-For") or "").split(",", 1)[0].strip() or request.remote_addr, max_len=64),
            "ua": _safe_str(request.headers.get("User-Agent") or "", max_len=220),
            "ts": int(time.time()),
        }
    )


def hash_admin_password(password: str, *, salt: Optional[str] = None, rounds: int = 120_000) -> str:
    pwd = _safe_str(password, max_len=500)
    s = _safe_str(salt or _env("ADMIN_PW_SALT", ""), max_len=200) or secrets.token_hex(8)
    r = int(rounds) if int(rounds) > 10_000 else 120_000
    dk = hashlib.pbkdf2_hmac("sha256", pwd.encode("utf-8"), s.encode("utf-8"), r, dklen=32)
    return f"pbkdf2_sha256${r}${s}${dk.hex()}"


def verify_admin_password_hash(stored: str, password: str) -> bool:
    st = _safe_str(stored, max_len=600)
    if not st.startswith("pbkdf2_sha256$"):
        return False
    try:
        _, rounds_s, salt, hexv = st.split("$", 3)
        rounds = int(rounds_s)
    except Exception:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", _safe_str(password, max_len=500).encode("utf-8"), salt.encode("utf-8"), rounds, dklen=32)
    return _constant_time_eq(dk.hex(), hexv)


__all__ = [
    "admin_required",
    "admin_creds_ok",
    "GateDecision",
    "ADMIN_SESSION_KEY_DEFAULT",
    "ADMIN_NEXT_PARAM_DEFAULT",
    "ADMIN_LOGIN_ENDPOINT_DEFAULT",
    "ADMIN_REGISTER_ENDPOINT_DEFAULT",
    "ADMIN_LOGIN_FALLBACK_PATH_DEFAULT",
    "ADMIN_REGISTER_FALLBACK_PATH_DEFAULT",
    "build_admin_login_url",
    "build_admin_register_url",
    "gate_admin_or_redirect",
    "gate_admin_or_abort",
    "gate_admin_json_or_none",
    "json_gate_response",
    "admin_login_success",
    "admin_logout_success",
    "is_admin_logged_in",
    "get_admin_role",
    "get_admin_next_param",
    "get_admin_default_next",
    "get_admin_login_endpoint",
    "get_admin_register_endpoint",
    "get_admin_login_fallback_path",
    "get_admin_register_fallback_path",
    "set_admin_allowed_roles",
    "set_admin_role_key",
    "set_admin_session_key",
    "set_admin_next_param",
    "set_admin_default_next",
    "set_admin_flash",
    "set_admin_abort_codes",
    "get_no_store_headers",
    "apply_no_store_headers",
    "admin_audit_event",
    "admin_login_audit",
    "hash_admin_password",
    "verify_admin_password_hash",
]
