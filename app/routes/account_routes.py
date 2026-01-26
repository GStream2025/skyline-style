from __future__ import annotations

import logging
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlencode, urljoin, urlparse

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy import select

from app.models import db, Order, User, UserAddress

log = logging.getLogger("account_routes")

# ============================================================
# Blueprints
# ============================================================
account_bp = Blueprint(
    "account",
    __name__,
    url_prefix="/account",
    template_folder="../templates",
)

cuenta_bp = Blueprint("cuenta", __name__)

# ============================================================
# ENV helpers
# ============================================================
_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off", "unchecked"}


def _env_str(name: str, default: str = "") -> str:
    v = os.getenv(name)
    return (default if v is None else str(v)).strip()


def _env_bool(name: str, default: bool = False) -> bool:
    v = _env_str(name, "")
    if not v:
        return default
    s = v.lower()
    if s in _FALSE:
        return False
    return s in _TRUE


def _env_int(name: str, default: int, *, min_v: int, max_v: int) -> int:
    try:
        n = int(_env_str(name, default))
    except Exception:
        n = default
    return max(min_v, min(max_v, n))


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ============================================================
# Config
# ============================================================
ACCOUNT_ALLOW_JSON = _env_bool("ACCOUNT_ALLOW_JSON", True)
REQUIRE_CSRF_FALLBACK = _env_bool("REQUIRE_CSRF", True)

MAX_BODY_BYTES = _env_int("ACCOUNT_MAX_BODY_BYTES", 120_000, min_v=20_000, max_v=500_000)
RL_COOLDOWN_SEC = float(_env_str("ACCOUNT_RATE_LIMIT_SECONDS", "1.2"))
RL_BURST = _env_int("ACCOUNT_RATE_LIMIT_BURST", 12, min_v=3, max_v=60)
RL_WINDOW = _env_int("ACCOUNT_RATE_LIMIT_WINDOW", 60, min_v=10, max_v=600)

# ============================================================
# Helpers
# ============================================================
def _template_exists(name: str) -> bool:
    try:
        current_app.jinja_env.get_template(name)
        return True
    except Exception:
        return False


def _safe_url_for(endpoint: str, **kwargs) -> Optional[str]:
    try:
        return url_for(endpoint, **kwargs)
    except Exception:
        return None


def _wants_json() -> bool:
    if not ACCOUNT_ALLOW_JSON:
        return False
    if request.is_json:
        return True
    if (request.args.get("format") or "").lower() == "json":
        return True
    accept = (request.headers.get("Accept") or "").lower()
    return "application/json" in accept


def _safe_get_json() -> Dict[str, Any]:
    try:
        if request.content_length and request.content_length > MAX_BODY_BYTES:
            return {}
        if request.is_json:
            data = request.get_json(silent=True)
            return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}


def _no_store(resp):
    resp.headers.setdefault("Cache-Control", "no-store")
    resp.headers.setdefault("Pragma", "no-cache")
    resp.headers.setdefault("Vary", "Cookie")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    return resp


def _json_or_html(payload: Dict[str, Any], html_fn):
    return jsonify(payload) if _wants_json() else html_fn()


def _is_safe_next(target: Optional[str]) -> bool:
    if not target or not target.startswith("/") or target.startswith("//"):
        return False
    try:
        ref = urlparse(request.host_url)
        test = urlparse(urljoin(request.host_url, target))
        return test.scheme == ref.scheme and test.netloc == ref.netloc
    except Exception:
        return False


def _next_url(default: str = "/account") -> str:
    nxt = (request.args.get("next") or request.form.get("next") or "").strip()
    return nxt if _is_safe_next(nxt) else default


def _redirect_auth_account(tab: str, nxt: str):
    tab = tab if tab in {"login", "register"} else "login"
    nxt = nxt if _is_safe_next(nxt) else "/account"
    try:
        return redirect(url_for("auth.account", tab=tab, next=nxt))
    except Exception:
        return redirect(f"/auth/account?{urlencode({'tab': tab, 'next': nxt})}")


def _ensure_csrf_token() -> str:
    tok = session.get("csrf_token")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf_token"] = tok
    return tok


def _csrf_ok_fallback() -> bool:
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return True
    if not REQUIRE_CSRF_FALLBACK:
        return True
    sent = (
        request.form.get("csrf_token")
        or request.headers.get("X-CSRF-Token")
        or _safe_get_json().get("csrf_token")
    )
    return bool(sent and secrets.compare_digest(str(sent), session.get("csrf_token", "")))


def _rate_limit_ok(key: str) -> bool:
    now = time.time()
    last = session.get(key, 0.0)
    if (now - float(last)) < RL_COOLDOWN_SEC:
        return False
    session[key] = now
    return True


def _get_current_user() -> Optional[User]:
    try:
        uid = int(session.get("user_id", 0))
        return db.session.execute(select(User).where(User.id == uid)).scalar_one_or_none()
    except Exception:
        return None


def _require_login():
    return None if _get_current_user() else _redirect_auth_account("login", _next_url())


# ============================================================
# Hooks
# ============================================================
@account_bp.before_request
def _before_account():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if not _rate_limit_ok("acct_write"):
            return jsonify({"ok": False, "error": "rate_limited"}), 429
        if not _csrf_ok_fallback():
            return jsonify({"ok": False, "error": "csrf_failed"}), 400
    return None


@account_bp.after_request
def _after_account(resp):
    return _no_store(resp)


# ============================================================
# Routes
# ============================================================
@account_bp.get("/")
def account_home():
    _ensure_csrf_token()
    guard = _require_login()
    if guard:
        return guard

    u = _get_current_user()
    tpl = "account/dashboard.html" if _template_exists("account/dashboard.html") else "account/account.html"

    return _json_or_html(
        {"ok": True, "user_id": u.id},
        lambda: render_template(tpl, user=u, csrf_token_value=session.get("csrf_token")),
    )


__all__ = ["account_bp", "cuenta_bp"]
