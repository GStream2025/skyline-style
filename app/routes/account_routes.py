# app/routes/account_routes.py — Skyline Store (ULTRA PRO++++ / FINAL / NO BREAK)
from __future__ import annotations

import logging
import os
import re
import secrets
import time
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

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

from sqlalchemy import select, func

from app.models import db, User, UserAddress, Order

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

# Alias /cuenta (sin url_prefix)
cuenta_bp = Blueprint("cuenta", __name__)

# ============================================================
# Flags / Config
# ============================================================

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off"}

def _env_flag(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in _TRUE

def _env_int(name: str, default: int, *, min_v: int, max_v: int) -> int:
    v = os.getenv(name)
    if v is None:
        return default
    try:
        n = int(str(v).strip())
    except Exception:
        return default
    return max(min_v, min(max_v, n))

def _env_float(name: str, default: float, *, min_v: float, max_v: float) -> float:
    v = os.getenv(name)
    if v is None:
        return default
    try:
        n = float(str(v).strip())
    except Exception:
        return default
    return max(min_v, min(max_v, n))

REQUIRE_CSRF = _env_flag("REQUIRE_CSRF", True)
ACCOUNT_ALLOW_JSON = _env_flag("ACCOUNT_ALLOW_JSON", True)

MIN_AGE = _env_int("MIN_AGE", 18, min_v=13, max_v=120)
PROFILE_MAX_LEN = _env_int("PROFILE_MAX_LEN", 120, min_v=40, max_v=500)

ACCOUNT_RATE_LIMIT_SECONDS = _env_float("ACCOUNT_RATE_LIMIT_SECONDS", 1.2, min_v=0.2, max_v=10.0)
MAX_BODY_BYTES = _env_int("ACCOUNT_MAX_BODY_BYTES", 120000, min_v=20_000, max_v=500_000)

# ============================================================
# Regex / Normalización
# ============================================================

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_\.]{3,24}$")
_PHONE_CLEAN_RE = re.compile(r"[^0-9\+\-\(\)\s]")

# ============================================================
# Helpers — Time / JSON / Templates / Seguridad
# ============================================================

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _safe_get_json() -> Dict[str, Any]:
    """No rompe si el body no es JSON válido. Limita size."""
    try:
        cl = request.content_length
        if cl is not None and int(cl) > MAX_BODY_BYTES:
            return {}
    except Exception:
        pass

    try:
        if request.is_json:
            data = request.get_json(silent=True) or {}
            return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}

def _wants_json() -> bool:
    if not ACCOUNT_ALLOW_JSON:
        return False
    fmt = (request.args.get("format") or "").strip().lower()
    if fmt == "json":
        return True
    if request.is_json:
        return True
    accept = (request.headers.get("Accept") or "").lower()
    xr = (request.headers.get("X-Requested-With") or "").lower()
    return ("application/json" in accept) or (xr == "xmlhttprequest")

def _json_or_html(payload: Dict[str, Any], html_fn):
    if _wants_json():
        return jsonify(payload)
    return html_fn()

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

def _is_safe_next(target: Optional[str]) -> bool:
    """Evita open-redirect: solo rutas internas del mismo host."""
    if not target:
        return False
    target = target.strip()
    if not target.startswith("/"):
        return False
    try:
        ref = urlparse(request.host_url)
        test = urlparse(urljoin(request.host_url, target))
        return (test.scheme == ref.scheme) and (test.netloc == ref.netloc)
    except Exception:
        return False

def _next_url(default: str = "/account") -> str:
    nxt = (request.args.get("next") or request.form.get("next") or "").strip()
    return nxt if _is_safe_next(nxt) else default

def _no_store(resp):
    """Evita cache de páginas sensibles."""
    try:
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Pragma"] = "no-cache"
    except Exception:
        pass
    return resp

def _safe_redirect_back(default_url: str):
    """Vuelve por referrer solo si es mismo host."""
    ref = request.referrer or ""
    if ref:
        try:
            u = urlparse(ref)
            if u.scheme and u.netloc and u.netloc == urlparse(request.host_url).netloc:
                return redirect(ref)
        except Exception:
            pass
    return redirect(default_url)

# ============================================================
# CSRF (compat con tus templates + Render)
# ============================================================

def _ensure_csrf_token() -> str:
    tok = session.get("csrf_token")
    if not tok or not isinstance(tok, str) or len(tok) < 16:
        tok = secrets.token_urlsafe(32)
        session["csrf_token"] = tok
        session.modified = True
    return tok

def _csrf_ok() -> bool:
    """
    ✅ CSRF real (cuando REQUIRE_CSRF=1)
    - Form: csrf_token
    - Header: X-CSRF-Token
    - JSON: {"csrf_token": "..."}
    """
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return True
    if not REQUIRE_CSRF:
        return True

    stored = (session.get("csrf_token") or "").strip()
    if not stored:
        return False

    sent = (request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or "").strip()
    if sent and secrets.compare_digest(sent, stored):
        return True

    data = _safe_get_json()
    sent2 = (str(data.get("csrf_token") or "")).strip()
    return bool(sent2) and secrets.compare_digest(sent2, stored)

def _rate_limit_ok(key: str) -> bool:
    """Rate-limit simple por sesión (evita spam en writes)."""
    now = time.time()
    k = f"rl:{key}"
    last = session.get(k, 0)
    try:
        last_f = float(last)
    except Exception:
        last_f = 0.0
    if (now - last_f) < ACCOUNT_RATE_LIMIT_SECONDS:
        return False
    session[k] = now
    session.modified = True
    return True

# ============================================================
# DB helpers
# ============================================================

def _commit_or_rollback() -> bool:
    try:
        db.session.commit()
        return True
    except Exception:
        db.session.rollback()
        log.exception("DB commit failed")
        return False

# ============================================================
# Session user helpers
# ============================================================

def _clear_session_keep_csrf() -> None:
    csrf = session.get("csrf_token")
    try:
        session.clear()
    except Exception:
        for k in list(session.keys()):
            session.pop(k, None)
    if csrf:
        session["csrf_token"] = csrf

def _get_current_user() -> Optional[User]:
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        uid_int = int(uid)
