from __future__ import annotations

import hmac
import os
import secrets
import time
from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable, Dict, Optional, Set, Tuple, TypeVar, cast
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


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    reason: str
    login_url: Optional[str] = None
    next_path: Optional[str] = None


def _cfg(name: str, default: Any) -> Any:
    try:
        return current_app.config.get(name, default)
    except Exception:
        return default


def _env(name: str, default: str = "") -> str:
    v = os.getenv(name)
    return (default if v is None else str(v)).strip()


def _safe_str(v: Any, *, max_len: int = 512) -> str:
    if v is None:
        return ""
    s = str(v).replace("\x00", "").replace("\u200b", "").strip()
    return s[:max_len] if max_len > 0 else s


def _is_truthy(v: Any) -> bool:
    if v is True:
        return True
    if isinstance(v, (int, float)) and v == 1:
        return True
    if isinstance(v, str):
        s = v.strip().lower()
        if not s or s in _FALSE:
            return False
        return s in _TRUE or s == "1"
    return False


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
    ):
        return default_path
    if "?" in p:
        p = p.split("?", 1)[0]
    if "#" in p:
        p = p.split("#", 1)[0]
    return p or default_path


def _safe_url_for(endpoint: str, **values: Any) -> Optional[str]:
    try:
        return url_for(endpoint, **values)
    except Exception:
        return None


def _resolve_login_url(*, endpoint: str, next_param: str, next_path: str) -> str:
    ep = _safe_str(_cfg("ADMIN_LOGIN_ENDPOINT", endpoint), max_len=128) or endpoint
    u = _safe_url_for(ep, **{next_param: next_path})
    if u:
        return u
    fallback = _safe_str(_cfg("ADMIN_LOGIN_FALLBACK_PATH", ADMIN_LOGIN_FALLBACK_PATH_DEFAULT), max_len=240) or (
        ADMIN_LOGIN_FALLBACK_PATH_DEFAULT
    )
    sep = "&" if "?" in fallback else "?"
    return f"{fallback}{sep}{next_param}={quote(next_path, safe='/')}"


def _resolve_register_url(*, endpoint: str, next_param: str, next_path: str) -> str:
    ep = _safe_str(_cfg("ADMIN_REGISTER_ENDPOINT", endpoint), max_len=128) or endpoint
    u = _safe_url_for(ep, **{next_param: next_path})
    if u:
        return u
    fallback = _safe_str(_cfg("ADMIN_REGISTER_FALLBACK_PATH", ADMIN_REGISTER_FALLBACK_PATH_DEFAULT), max_len=240) or (
        ADMIN_REGISTER_FALLBACK_PATH_DEFAULT
    )
    sep = "&" if "?" in fallback else "?"
    return f"{fallback}{sep}{next_param}={quote(next_path, safe='/')}"


def build_admin_login_url(*, next_param: str = ADMIN_NEXT_PARAM_DEFAULT, next_path: str = "/admin") -> str:
    return _resolve_login_url(endpoint=ADMIN_LOGIN_ENDPOINT_DEFAULT, next_param=next_param, next_path=_clean_next_path(next_path))


def build_admin_register_url(*, next_param: str = ADMIN_NEXT_PARAM_DEFAULT, next_path: str = "/admin") -> str:
    return _resolve_register_url(
        endpoint=ADMIN_REGISTER_ENDPOINT_DEFAULT, next_param=next_param, next_path=_clean_next_path(next_path)
    )


def _session_role_ok() -> bool:
    role_key = _safe_str(_cfg("ADMIN_ROLE_KEY", "role"), max_len=64) or "role"
    allowed = _cfg("ADMIN_ALLOWED_ROLES", {"admin", "staff"})
    try:
        allowed_set: Set[str] = set(allowed) if allowed else {"admin", "staff"}
    except Exception:
        allowed_set = {"admin", "staff"}

    try:
        role = session.get(role_key)
    except Exception:
        return True
    if role is None:
        return True
    return _safe_str(role, max_len=32).lower() in allowed_set


def _allowed_by_session(session_key: str) -> bool:
    try:
        if _is_truthy(session.get(session_key)) or _is_truthy(session.get("is_admin")):
            return True
    except Exception:
        pass
    return False


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


def _check_password_hash_if_possible(pwhash: str, password: str) -> Optional[bool]:
    pwhash = _safe_str(pwhash, max_len=512)
    if not pwhash:
        return None
    try:
        from werkzeug.security import check_password_hash  # type: ignore

        return bool(check_password_hash(pwhash, password))
    except Exception:
        return None


def admin_creds_ok(email: str, password: str) -> bool:
    email_s = _safe_str(email, max_len=200).lower()
    password_s = _safe_str(password, max_len=500)
    if not email_s or not password_s:
        return False

    cfg_emails = _parse_admin_emails(_cfg("ADMIN_EMAILS", None))
    env_email = _env("ADMIN_EMAIL", "")
    if env_email:
        cfg_emails.add(env_email.strip().lower())
    if cfg_emails and email_s not in cfg_emails:
        return False

    pw_hash = _safe_str(_cfg("ADMIN_PASSWORD_HASH", ""), max_len=512) or _env("ADMIN_PASSWORD_HASH", "")
    if pw_hash:
        checked = _check_password_hash_if_possible(pw_hash, password_s)
        if checked is not None:
            return checked
        try:
            return secrets.compare_digest(pw_hash, password_s)
        except Exception:
            return hmac.compare_digest(pw_hash, password_s)

    pw_plain = _safe_str(_cfg("ADMIN_PASSWORD", ""), max_len=500) or _env("ADMIN_PASSWORD", "")
    if not pw_plain:
        return False
    try:
        return secrets.compare_digest(pw_plain, password_s)
    except Exception:
        return hmac.compare_digest(pw_plain, password_s)


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
            ach = _cfg("ADMIN_ABORT_CODE_HTML", abort_code_html)

            if _allowed_by_session(sess_key) and _session_role_ok():
                return fn(*args, **kwargs)

            if _is_json_like_request():
                abort(acj)

            msg = _safe_str(_cfg("ADMIN_FLASH_MESSAGE", flash_message), max_len=180) or flash_message
            cat = _safe_str(_cfg("ADMIN_FLASH_CATEGORY", flash_category), max_len=32) or flash_category
            try:
                if msg:
                    flash(msg, cat)
            except Exception:
                pass

            if ach is not None:
                try:
                    abort(int(ach))
                except Exception:
                    abort(403)

            raw_next = None
            try:
                raw_next = request.args.get(next_param)
            except Exception:
                raw_next = None
            try:
                fallback_next = request.path or "/"
            except Exception:
                fallback_next = "/"

            next_path = _clean_next_path(raw_next, default_path=_clean_next_path(fallback_next, default_path=dnext))
            if next_path.startswith("/admin/login") or next_path.startswith("/admin/register"):
                next_path = _clean_next_path(dnext, default_path="/admin")

            resp = redirect(build_admin_login_url(next_param=next_param, next_path=next_path))
            try:
                resp.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
                resp.headers["Pragma"] = "no-cache"
                resp.headers["Expires"] = "0"
                resp.headers.setdefault("Vary", "Cookie")
            except Exception:
                pass
            return resp

        return cast(F, wrapper)

    if view is None:
        return decorator
    return decorator(view)


__all__ = [
    "admin_required",
    "admin_creds_ok",
    "GateDecision",
    "ADMIN_SESSION_KEY_DEFAULT",
    "ADMIN_NEXT_PARAM_DEFAULT",
    "build_admin_login_url",
    "build_admin_register_url",
]
