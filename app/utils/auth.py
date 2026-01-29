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
ADMIN_LOGIN_FALLBACK_PATH_DEFAULT = "/admin/login"

DEFAULT_FLASH_CATEGORY = "warning"
DEFAULT_FLASH_MESSAGE = "Tenés que iniciar sesión como admin."

CFG_ADMIN_EMAIL = "ADMIN_EMAIL"
CFG_ADMIN_PASSWORD = "ADMIN_PASSWORD"
CFG_ADMIN_PASSWORD_HASH = "ADMIN_PASSWORD_HASH"
CFG_ADMIN_EMAILS = "ADMIN_EMAILS"

CFG_ADMIN_SESSION_KEY = "ADMIN_SESSION_KEY"
CFG_ADMIN_LOGIN_ENDPOINT = "ADMIN_LOGIN_ENDPOINT"
CFG_ADMIN_LOGIN_FALLBACK = "ADMIN_LOGIN_FALLBACK_PATH"
CFG_ADMIN_DEFAULT_NEXT = "ADMIN_DEFAULT_NEXT"
CFG_ADMIN_ABORT_JSON = "ADMIN_ABORT_CODE_JSON"
CFG_ADMIN_ABORT_HTML = "ADMIN_ABORT_CODE_HTML"
CFG_ADMIN_FLASH_MESSAGE = "ADMIN_FLASH_MESSAGE"
CFG_ADMIN_FLASH_CATEGORY = "ADMIN_FLASH_CATEGORY"
CFG_ADMIN_BYPASS = "ADMIN_BYPASS"

CFG_ADMIN_ROLE_KEY = "ADMIN_ROLE_KEY"
CFG_ADMIN_ALLOWED_ROLES = "ADMIN_ALLOWED_ROLES"

CFG_MAINTENANCE_MODE = "MAINTENANCE_MODE"
CFG_MAINTENANCE_ALLOW_READONLY = "MAINTENANCE_ALLOW_READONLY"
CFG_MAINTENANCE_MESSAGE = "MAINTENANCE_MESSAGE"

CFG_AUTH_AUDIT_CALLBACK = "AUTH_AUDIT_CALLBACK"

CFG_ADMIN_SOFT_RL_WINDOW_S = "ADMIN_SOFT_RL_WINDOW_S"
CFG_ADMIN_SOFT_RL_MAX = "ADMIN_SOFT_RL_MAX"

_NO_STORE_HEADERS: Dict[str, str] = {
    "Cache-Control": "no-store, max-age=0, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}

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
    if v is None:
        return default
    return str(v).strip()


def _safe_str(v: Any, *, max_len: int = 512) -> str:
    if v is None:
        return ""
    s = str(v).replace("\x00", "").replace("\u200b", "").strip()
    if max_len > 0 and len(s) > max_len:
        s = s[:max_len]
    return s


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


def _client_ip() -> str:
    try:
        fwd = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        if fwd:
            return fwd[:64]
    except Exception:
        pass
    try:
        return (request.remote_addr or "")[:64]
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
    candidates = (
        endpoint,
        _safe_str(_cfg(CFG_ADMIN_LOGIN_ENDPOINT, endpoint), max_len=128) or endpoint,
        "admin_routes.login",
        "admin.login_admin",
        "admin_routes.admin_login",
    )
    for ep in candidates:
        if not ep:
            continue
        u = _safe_url_for(ep, **{next_param: next_path})
        if u:
            return u

    fallback = _safe_str(_cfg(CFG_ADMIN_LOGIN_FALLBACK, ADMIN_LOGIN_FALLBACK_PATH_DEFAULT), max_len=240) or (
        ADMIN_LOGIN_FALLBACK_PATH_DEFAULT
    )
    sep = "&" if "?" in fallback else "?"
    return f"{fallback}{sep}{next_param}={quote(next_path, safe='/')}"


def _audit(event: Dict[str, Any]) -> None:
    event = dict(event or {})
    event.setdefault("ip", _client_ip())
    try:
        event.setdefault("ua", _safe_str(request.headers.get("User-Agent"), max_len=160))
    except Exception:
        pass

    try:
        cb = _cfg(CFG_AUTH_AUDIT_CALLBACK, None)
        if callable(cb):
            cb(event)
    except Exception:
        pass

    try:
        if current_app and current_app.debug:
            current_app.logger.debug("auth_audit %s", event)
    except Exception:
        pass


def _soft_rate_limit(bucket: str) -> Tuple[bool, int]:
    window_s = int(_cfg(CFG_ADMIN_SOFT_RL_WINDOW_S, 10) or 10)
    max_hits = int(_cfg(CFG_ADMIN_SOFT_RL_MAX, 25) or 25)
    window_s = max(1, window_s)
    max_hits = max(1, max_hits)

    key = f"_rl:{bucket}"
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


def _maintenance_block() -> Optional[str]:
    if not bool(_cfg(CFG_MAINTENANCE_MODE, False)):
        return None

    allow_readonly = bool(_cfg(CFG_MAINTENANCE_ALLOW_READONLY, False))
    if allow_readonly and request.method in ("GET", "HEAD", "OPTIONS"):
        return None

    msg = _safe_str(_cfg(CFG_MAINTENANCE_MESSAGE, "Sistema en mantenimiento. Probá más tarde."), max_len=180)
    return msg or "Sistema en mantenimiento."


def _session_role_ok() -> bool:
    role_key = _safe_str(_cfg(CFG_ADMIN_ROLE_KEY, "role"), max_len=64) or "role"
    allowed = _cfg(CFG_ADMIN_ALLOWED_ROLES, {"admin", "staff"})

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

    role_s = _safe_str(role, max_len=32).lower()
    return role_s in allowed_set


def _current_user_is_admin() -> bool:
    try:
        from flask_login import current_user  # type: ignore
    except Exception:
        return False

    try:
        if not current_user or not getattr(current_user, "is_authenticated", False):
            return False
    except Exception:
        return False

    for attr in ("is_admin", "admin", "is_staff"):
        try:
            if _is_truthy(getattr(current_user, attr, False)):
                return True
        except Exception:
            pass

    try:
        roles = getattr(current_user, "roles", None)
        if isinstance(roles, (set, list, tuple)):
            roles_s = {str(x).strip().lower() for x in roles if x is not None}
            return bool({"admin", "staff"} & roles_s)
    except Exception:
        pass

    return False


def _allowed_by_session(session_key: str) -> bool:
    try:
        if _is_truthy(session.get(session_key)):
            return True
    except Exception:
        pass

    try:
        if _is_truthy(session.get("is_admin")):
            return True
    except Exception:
        pass

    return _current_user_is_admin()


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

        try:
            return bool(check_password_hash(pwhash, password))
        except Exception:
            return None
    except Exception:
        return None


def admin_creds_ok(email: str, password: str) -> bool:
    email_s = _safe_str(email, max_len=200).lower()
    password_s = _safe_str(password, max_len=500)

    if not email_s or not password_s:
        return False

    cfg_emails = _parse_admin_emails(_cfg(CFG_ADMIN_EMAILS, None))
    env_email = _env(CFG_ADMIN_EMAIL, "")
    if env_email:
        cfg_emails.add(env_email.strip().lower())

    if cfg_emails and email_s not in cfg_emails:
        return False

    pw_hash = _safe_str(_cfg(CFG_ADMIN_PASSWORD_HASH, ""), max_len=512) or _env(CFG_ADMIN_PASSWORD_HASH, "")
    if pw_hash:
        checked = _check_password_hash_if_possible(pw_hash, password_s)
        if checked is not None:
            return checked
        # si NO es hash (misconfig), igual comparamos en constant-time
        try:
            return secrets.compare_digest(pw_hash, password_s)
        except Exception:
            return hmac.compare_digest(pw_hash, password_s)

    pw_plain = _safe_str(_cfg(CFG_ADMIN_PASSWORD, ""), max_len=500) or _env(CFG_ADMIN_PASSWORD, "")
    if not pw_plain:
        return False

    try:
        return secrets.compare_digest(pw_plain, password_s)
    except Exception:
        return hmac.compare_digest(pw_plain, password_s)


def _decide_admin_gate(
    *,
    session_key: str,
    login_endpoint: str,
    next_param: str,
    default_next: str,
) -> GateDecision:
    mm = _maintenance_block()
    if mm:
        return GateDecision(False, "maintenance")

    ok_rl, remaining = _soft_rate_limit("admin_required")
    if not ok_rl:
        _audit(
            {
                "type": "admin_gate",
                "ok": False,
                "reason": "rate_limited",
                "path": _safe_str(getattr(request, "path", ""), max_len=200),
                "method": _safe_str(getattr(request, "method", ""), max_len=16),
                "remaining": remaining,
                "is_json": _is_json_like_request(),
            }
        )
        return GateDecision(False, "rate_limited")

    if bool(_cfg(CFG_ADMIN_BYPASS, False)):
        return GateDecision(True, "bypass")

    if not _allowed_by_session(session_key):
        try:
            raw_next = request.args.get(next_param)
        except Exception:
            raw_next = None

        try:
            fallback_next = request.path or "/"
        except Exception:
            fallback_next = "/"

        next_path = _clean_next_path(raw_next, default_path=_clean_next_path(fallback_next, default_path=default_next))
        if next_path.startswith("/admin/login"):
            next_path = _clean_next_path(default_next, default_path="/admin")

        login_url = _resolve_login_url(endpoint=login_endpoint, next_param=next_param, next_path=next_path)
        return GateDecision(False, "not_logged_in", login_url, next_path)

    if not _session_role_ok():
        return GateDecision(False, "role_denied")

    return GateDecision(True, "ok")


def admin_required(
    view: Optional[F] = None,
    *,
    session_key: str = ADMIN_SESSION_KEY_DEFAULT,
    login_endpoint: str = ADMIN_LOGIN_ENDPOINT_DEFAULT,
    next_param: str = ADMIN_NEXT_PARAM_DEFAULT,
    default_next: str = "/admin",
    flash_message: str = DEFAULT_FLASH_MESSAGE,
    flash_category: str = DEFAULT_FLASH_CATEGORY,
    abort_code_json: int = 401,
    abort_code_html: Optional[int] = None,
) -> Any:
    def decorator(fn: F) -> F:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any):
            sess_key = _safe_str(_cfg(CFG_ADMIN_SESSION_KEY, session_key), max_len=64) or session_key
            login_ep = _safe_str(_cfg(CFG_ADMIN_LOGIN_ENDPOINT, login_endpoint), max_len=128) or login_endpoint
            dnext = _safe_str(_cfg(CFG_ADMIN_DEFAULT_NEXT, default_next), max_len=256) or default_next
            acj = int(_cfg(CFG_ADMIN_ABORT_JSON, abort_code_json) or abort_code_json)
            ach = _cfg(CFG_ADMIN_ABORT_HTML, abort_code_html)

            decision = _decide_admin_gate(
                session_key=sess_key,
                login_endpoint=login_ep,
                next_param=next_param,
                default_next=dnext,
            )

            _audit(
                {
                    "type": "admin_gate",
                    "ok": decision.allowed,
                    "reason": decision.reason,
                    "path": _safe_str(getattr(request, "path", ""), max_len=200),
                    "method": _safe_str(getattr(request, "method", ""), max_len=16),
                    "is_json": _is_json_like_request(),
                    "next": decision.next_path,
                }
            )

            if decision.allowed:
                return fn(*args, **kwargs)

            if decision.reason == "maintenance":
                msg = _safe_str(_cfg(CFG_MAINTENANCE_MESSAGE, "Sistema en mantenimiento."), max_len=200)
                if _is_json_like_request():
                    return jsonify({"ok": False, "error": "maintenance", "message": msg}), 503
                try:
                    flash(msg, "info")
                except Exception:
                    pass
                abort(503)

            if decision.reason == "rate_limited":
                msg = "Demasiados intentos. Esperá un momento y probá de nuevo."
                if _is_json_like_request():
                    return jsonify({"ok": False, "error": "rate_limited", "message": msg}), 429
                try:
                    flash(msg, "warning")
                except Exception:
                    pass
                abort(429)

            if decision.reason == "role_denied":
                msg = "No tenés permisos para acceder al panel."
                if _is_json_like_request():
                    return jsonify({"ok": False, "error": "forbidden", "message": msg}), 403
                try:
                    flash(msg, "error")
                except Exception:
                    pass
                abort(403)

            if _is_json_like_request():
                abort(acj)

            msg = _safe_str(_cfg(CFG_ADMIN_FLASH_MESSAGE, flash_message), max_len=180) or DEFAULT_FLASH_MESSAGE
            cat = _safe_str(_cfg(CFG_ADMIN_FLASH_CATEGORY, flash_category), max_len=32) or DEFAULT_FLASH_CATEGORY

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

            login_url = decision.login_url or _resolve_login_url(
                endpoint=login_ep,
                next_param=next_param,
                next_path=_clean_next_path(None, default_path=dnext),
            )

            resp = redirect(login_url)
            try:
                for k, v in _NO_STORE_HEADERS.items():
                    resp.headers[k] = v
                resp.headers.setdefault("Vary", "Cookie")
                resp.headers["X-Admin-Gate"] = decision.reason
            except Exception:
                pass

            return resp

        return cast(F, wrapper)

    if view is None:
        return decorator
    return decorator(view)


__all__ = ["admin_required", "admin_creds_ok", "GateDecision"]
