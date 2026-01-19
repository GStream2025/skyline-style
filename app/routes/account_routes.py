# app/routes/account_routes.py — Skyline Store (ULTRA PRO++++ / FINAL / NO BREAK / Unified Account v2 BULLETPROOF)
from __future__ import annotations

import logging
import os
import re
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlencode, urljoin, urlparse

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy import select

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

# Alias /cuenta (sin url_prefix) — compat legacy
cuenta_bp = Blueprint("cuenta", __name__)

# ============================================================
# Flags / Config
# ============================================================
_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off"}

def _env_str(name: str, default: str = "") -> str:
    v = os.getenv(name)
    return (default if v is None else str(v)).strip()

def _env_flag(name: str, default: bool) -> bool:
    v = _env_str(name, "")
    return (v.lower() in _TRUE) if v else default

def _env_int(name: str, default: int, *, min_v: int, max_v: int) -> int:
    s = _env_str(name, "")
    try:
        n = int(s) if s else int(default)
    except Exception:
        n = int(default)
    return max(min_v, min(max_v, n))

def _env_float(name: str, default: float, *, min_v: float, max_v: float) -> float:
    s = _env_str(name, "")
    try:
        n = float(s) if s else float(default)
    except Exception:
        n = float(default)
    return max(min_v, min(max_v, n))

# ✅ Si tenés Flask-WTF CSRFProtect, esto queda como “fallback” (no rompe)
REQUIRE_CSRF_FALLBACK = _env_flag("REQUIRE_CSRF", True)
ACCOUNT_ALLOW_JSON = _env_flag("ACCOUNT_ALLOW_JSON", True)

MIN_AGE = _env_int("MIN_AGE", 18, min_v=13, max_v=120)
PROFILE_MAX_LEN = _env_int("PROFILE_MAX_LEN", 120, min_v=40, max_v=500)

ACCOUNT_RATE_LIMIT_SECONDS = _env_float("ACCOUNT_RATE_LIMIT_SECONDS", 1.2, min_v=0.2, max_v=10.0)
ACCOUNT_RATE_LIMIT_BURST = _env_int("ACCOUNT_RATE_LIMIT_BURST", 12, min_v=3, max_v=60)
ACCOUNT_RATE_LIMIT_WINDOW = _env_int("ACCOUNT_RATE_LIMIT_WINDOW", 60, min_v=10, max_v=600)

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
    fmt = (request.args.get("format") or "").strip().lower()
    if fmt == "json":
        return True
    accept = (request.headers.get("Accept") or "").lower()
    xr = (request.headers.get("X-Requested-With") or "").lower()
    return ("application/json" in accept) or (xr == "xmlhttprequest")

def _safe_get_json() -> Dict[str, Any]:
    """No rompe si body no es JSON. Limita size."""
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

def _json_or_html(payload: Dict[str, Any], html_fn):
    if _wants_json():
        return jsonify(payload)
    return html_fn()

def _no_store(resp):
    """Evita cache de páginas sensibles."""
    try:
        resp.headers.setdefault("Cache-Control", "no-store")
        resp.headers.setdefault("Pragma", "no-cache")
        resp.headers.setdefault("Vary", "Cookie")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("X-Frame-Options", "DENY")
    except Exception:
        pass
    return resp

def _is_safe_next(target: Optional[str]) -> bool:
    """Evita open-redirect: solo rutas internas del mismo host."""
    if not target:
        return False
    target = target.strip()
    if not target.startswith("/") or target.startswith("//"):
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

def _redirect_auth_account(tab: str, nxt: str) -> Any:
    """Redirect robusto hacia /auth/account sin romper encoding."""
    tab = (tab or "login").strip().lower()
    if tab not in {"login", "register"}:
        tab = "login"
    if not _is_safe_next(nxt):
        nxt = "/account"
    # endpoint preferido
    try:
        return redirect(url_for("auth.account", tab=tab, next=nxt))
    except Exception:
        qs = urlencode({"tab": tab, "next": nxt})
        return redirect(f"/auth/account?{qs}")

def _client_ip() -> str:
    xf = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    if xf:
        return xf[:64]
    xr = (request.headers.get("X-Real-IP") or "").strip()
    if xr:
        return xr[:64]
    return (request.remote_addr or "0.0.0.0")[:64]

def _rl_key(action: str) -> str:
    return f"rl:acct:{action}:{_client_ip()}"

def _rate_limit_ok(action: str) -> bool:
    """Rate-limit por IP+session (cooldown + burst)."""
    now = time.time()

    # cooldown
    k_cd = _rl_key(action) + ":cd"
    last = session.get(k_cd, 0)
    try:
        last_f = float(last)
    except Exception:
        last_f = 0.0
    if (now - last_f) < float(ACCOUNT_RATE_LIMIT_SECONDS):
        return False
    session[k_cd] = now

    # burst window
    k_b = _rl_key(action) + ":b"
    bucket = session.get(k_b)
    if not isinstance(bucket, dict):
        bucket = {"t0": now, "n": 0}
    try:
        t0 = float(bucket.get("t0", now))
        n = int(bucket.get("n", 0))
    except Exception:
        t0, n = now, 0
    if (now - t0) > float(ACCOUNT_RATE_LIMIT_WINDOW):
        t0, n = now, 0
    n += 1
    bucket["t0"] = t0
    bucket["n"] = n
    session[k_b] = bucket

    session.modified = True
    return n <= int(ACCOUNT_RATE_LIMIT_BURST)

# ============================================================
# CSRF fallback (NO pisa Flask-WTF CSRFProtect)
# ============================================================
def _ensure_csrf_token() -> str:
    tok = session.get("csrf_token")
    if not tok or not isinstance(tok, str) or len(tok) < 16:
        tok = secrets.token_urlsafe(32)
        session["csrf_token"] = tok
        session.modified = True
    return tok

def _csrf_ok_fallback() -> bool:
    """
    Fallback para endpoints JSON/POST si NO llega a actuar CSRFProtect por alguna razón.
    Si CSRFProtect está activo, normalmente este check ni hace falta.
    """
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return True
    if not REQUIRE_CSRF_FALLBACK:
        return True

    stored = (session.get("csrf_token") or "").strip()
    if not stored:
        return False

    sent = (
        (request.form.get("csrf_token") or "").strip()
        or (request.headers.get("X-CSRF-Token") or "").strip()
        or (request.headers.get("X-CSRFToken") or "").strip()
    )
    if sent and secrets.compare_digest(sent, stored):
        return True

    data = _safe_get_json()
    sent2 = (str(data.get("csrf_token") or "")).strip()
    return bool(sent2) and secrets.compare_digest(sent2, stored)

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
def _get_current_user() -> Optional[User]:
    """
    Ultra-safe:
    - si user_id no existe o no es int -> None
    - SQLAlchemy execute select -> scalar_one_or_none
    """
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        uid_int = int(uid)
    except Exception:
        return None
    try:
        return db.session.execute(select(User).where(User.id == uid_int)).scalar_one_or_none()
    except Exception:
        log.exception("failed to load current user")
        return None

def _require_login() -> Optional[Any]:
    """
    ✅ Unified: si no está logueado -> /auth/account?tab=login&next=...
    """
    u = _get_current_user()
    if u:
        return None
    nxt = _next_url(default="/account")
    return _redirect_auth_account("login", nxt)

# ============================================================
# Hooks
# ============================================================
@account_bp.before_request
def _before_account():
    # 1) Body size hard guard (evita requests gigantes en POST/PUT)
    try:
        cl = request.content_length
        if cl is not None and int(cl) > MAX_BODY_BYTES:
            if _wants_json():
                return jsonify({"ok": False, "error": "payload_too_large"}), 413
            flash("Solicitud demasiado grande.", "error")
            return redirect(_safe_url_for("account.account_home") or "/account")
    except Exception:
        pass

    # 2) Endpoints write: rate limit + csrf fallback (no rompe si ya lo valida CSRFProtect)
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if not _rate_limit_ok("write"):
            if _wants_json():
                return jsonify({"ok": False, "error": "rate_limited"}), 429
            flash("Demasiadas acciones seguidas. Esperá un momento.", "warning")
            return redirect(_safe_url_for("account.account_home") or "/account")

        if not _csrf_ok_fallback():
            if _wants_json():
                return jsonify({"ok": False, "error": "csrf_failed"}), 400
            flash("Token de seguridad inválido. Recargá la página.", "error")
            return redirect(_safe_url_for("account.account_home") or "/account")

    return None

@account_bp.after_request
def _after_account(resp):
    # evita cache de /account en general
    return _no_store(resp)

# ============================================================
# Unified entrypoints (compat) — /account y /cuenta
# ============================================================
@account_bp.get("/")
def account_home():
    """
    /account
    - Logueado: dashboard
    - No logueado: redirect unified auth
    """
    _ensure_csrf_token()
    guard = _require_login()
    if guard:
        return guard

    u = _get_current_user()
    if not u:
        return _redirect_auth_account("login", "/account")

    # template selection ultra-safe
    tpl = "account/dashboard.html"
    if not _template_exists(tpl):
        tpl = "account/index.html" if _template_exists("account/index.html") else "account/account.html"

    def _html():
        return render_template(
            tpl,
            csrf_token_value=session.get("csrf_token", ""),
            user=u,
        )

    return _json_or_html({"ok": True, "user_id": getattr(u, "id", None)}, _html)

@account_bp.get("/login")
def account_login_compat():
    nxt = _next_url(default="/account")
    return _redirect_auth_account("login", nxt)

@account_bp.get("/register")
def account_register_compat():
    nxt = _next_url(default="/account")
    return _redirect_auth_account("register", nxt)

@cuenta_bp.get("/cuenta")
def cuenta_home():
    return redirect("/account")

@cuenta_bp.get("/cuenta/login")
def cuenta_login():
    nxt = _next_url(default="/account")
    return _redirect_auth_account("login", nxt)

@cuenta_bp.get("/cuenta/register")
def cuenta_register():
    nxt = _next_url(default="/account")
    return _redirect_auth_account("register", nxt)

# ============================================================
# Orders
# ============================================================
@account_bp.get("/orders")
def account_orders():
    _ensure_csrf_token()
    guard = _require_login()
    if guard:
        return guard

    u = _get_current_user()
    if not u:
        return _redirect_auth_account("login", "/account/orders")

    # carga segura
    try:
        rows = (
            db.session.execute(
                select(Order).where(Order.user_id == u.id).order_by(Order.id.desc()).limit(50)
            )
            .scalars()
            .all()
        )
    except Exception:
        log.exception("failed to load orders")
        rows = []

    def _html():
        tpl = "account/orders.html"
        if not _template_exists(tpl):
            tpl = "account/orders_fallback.html" if _template_exists("account/orders_fallback.html") else "account/account.html"
        return render_template(
            tpl,
            csrf_token_value=session.get("csrf_token", ""),
            user=u,
            orders=rows,
        )

    payload = {
        "ok": True,
        "user_id": getattr(u, "id", None),
        "orders": [{"id": getattr(o, "id", None)} for o in rows],
    }
    return _json_or_html(payload, _html)

# ============================================================
# Addresses (list + add minimal) — ultra-safe base
# ============================================================
@account_bp.get("/addresses")
def addresses_list():
    _ensure_csrf_token()
    guard = _require_login()
    if guard:
        return guard

    u = _get_current_user()
    if not u:
        return _redirect_auth_account("login", "/account/addresses")

    try:
        addrs = (
            db.session.execute(select(UserAddress).where(UserAddress.user_id == u.id).order_by(UserAddress.id.desc()))
            .scalars()
            .all()
        )
    except Exception:
        log.exception("failed to load addresses")
        addrs = []

    def _html():
        tpl = "account/addresses.html"
        if not _template_exists(tpl):
            tpl = "account/account.html"
        return render_template(
            tpl,
            csrf_token_value=session.get("csrf_token", ""),
            user=u,
            addresses=addrs,
        )

    payload = {
        "ok": True,
        "addresses": [{"id": getattr(a, "id", None)} for a in addrs],
    }
    return _json_or_html(payload, _html)

@account_bp.post("/addresses/add")
def addresses_add():
    _ensure_csrf_token()
    guard = _require_login()
    if guard:
        return guard

    u = _get_current_user()
    if not u:
        return _redirect_auth_account("login", "/account/addresses")

    data = _safe_get_json()

    # acepta form o json
    line1 = ((request.form.get("line1") or "") or str(data.get("line1") or "")).strip()[:200]
    city = ((request.form.get("city") or "") or str(data.get("city") or "")).strip()[:120]
    country = ((request.form.get("country") or "") or str(data.get("country") or "")).strip()[:120]

    if not line1 or not city:
        if _wants_json():
            return jsonify({"ok": False, "error": "invalid_address"}), 400
        flash("Dirección inválida.", "error")
        return redirect(_safe_url_for("account.addresses_list") or "/account/addresses")

    try:
        addr = UserAddress(  # type: ignore[call-arg]
            user_id=u.id,
            line1=line1,
            city=city,
            country=country or "UY",
        )
        db.session.add(addr)
    except Exception:
        db.session.rollback()
        log.exception("failed to create address")
        if _wants_json():
            return jsonify({"ok": False, "error": "create_failed"}), 500
        flash("No se pudo guardar la dirección.", "error")
        return redirect(_safe_url_for("account.addresses_list") or "/account/addresses")

    if not _commit_or_rollback():
        if _wants_json():
            return jsonify({"ok": False, "error": "db_failed"}), 500
        flash("Error guardando la dirección.", "error")
        return redirect(_safe_url_for("account.addresses_list") or "/account/addresses")

    if _wants_json():
        return jsonify({"ok": True, "id": getattr(addr, "id", None)}), 200

    flash("Dirección guardada ✅", "success")
    return redirect(_safe_url_for("account.addresses_list") or "/account/addresses")


__all__ = ["account_bp", "cuenta_bp"]
