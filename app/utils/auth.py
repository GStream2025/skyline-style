from __future__ import annotations

import time
from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable, Dict, Iterable, Optional, Set, Tuple, TypeVar, cast
from urllib.parse import quote

from flask import abort, current_app, flash, jsonify, redirect, request, session, url_for

F = TypeVar("F", bound=Callable[..., Any])

# -----------------------------
# Defaults (compat con tu tienda)
# -----------------------------
DEFAULT_ADMIN_SESSION_KEY = "admin_logged_in"
DEFAULT_ADMIN_LOGIN_ENDPOINT = "admin.login"
DEFAULT_ADMIN_LOGIN_FALLBACK_PATH = "/admin/login"
DEFAULT_NEXT_PARAM = "next"

DEFAULT_FLASH_CATEGORY = "warning"
DEFAULT_FLASH_MESSAGE = "Tenés que iniciar sesión como admin."

DEFAULT_ROLE_KEY_SESSION = "role"
DEFAULT_ALLOWED_ADMIN_ROLES = {"admin", "staff"}

# “Áreas” de riesgo (tu tienda: pagos/comisiones/webhooks)
SENSITIVE_PREFIXES_DEFAULT = ("/admin", "/admin/payments", "/webhooks", "/api/admin", "/affiliate/admin")
FINANCIAL_PREFIXES_DEFAULT = ("/admin/payments", "/admin/commissions", "/admin/payouts", "/checkout", "/webhooks")

# Cache headers para evitar back-button mostrando contenido privado
_NO_STORE_HEADERS = {
    "Cache-Control": "no-store, max-age=0, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}

# -----------------------------
# Config keys (no obligatorios)
# -----------------------------
CFG_ADMIN_BYPASS = "ADMIN_BYPASS"  # bool (emergencia)
CFG_ADMIN_SESSION_KEY = "ADMIN_SESSION_KEY"  # str
CFG_ADMIN_ROLE_KEY = "ADMIN_ROLE_KEY"  # str
CFG_ADMIN_ALLOWED_ROLES = "ADMIN_ALLOWED_ROLES"  # set[str]
CFG_ADMIN_LOGIN_ENDPOINT = "ADMIN_LOGIN_ENDPOINT"  # str
CFG_ADMIN_LOGIN_FALLBACK_PATH = "ADMIN_LOGIN_FALLBACK_PATH"  # str
CFG_ADMIN_DEFAULT_NEXT = "ADMIN_DEFAULT_NEXT"  # str

CFG_ADMIN_ABORT_CODE_JSON = "ADMIN_ABORT_CODE_JSON"  # int
CFG_ADMIN_ABORT_CODE_HTML = "ADMIN_ABORT_CODE_HTML"  # int|None

CFG_ADMIN_FLASH_MESSAGE = "ADMIN_FLASH_MESSAGE"
CFG_ADMIN_FLASH_CATEGORY = "ADMIN_FLASH_CATEGORY"

CFG_AUTH_AUDIT_CALLBACK = "AUTH_AUDIT_CALLBACK"  # callable(event: dict) -> None
CFG_AUTH_CONTEXT_CALLBACK = "AUTH_CONTEXT_CALLBACK"  # callable() -> dict (agrega data de tienda)

CFG_MAINTENANCE_MODE = "MAINTENANCE_MODE"  # bool
CFG_MAINTENANCE_ALLOW_READONLY = "MAINTENANCE_ALLOW_READONLY"  # bool
CFG_MAINTENANCE_MESSAGE = "MAINTENANCE_MESSAGE"  # str

CFG_SOFT_RL_WINDOW_S = "AUTH_SOFT_RL_WINDOW_S"  # int
CFG_SOFT_RL_MAX = "AUTH_SOFT_RL_MAX"  # int

CFG_SENSITIVE_PREFIXES = "AUTH_SENSITIVE_PREFIXES"  # tuple[str,...]
CFG_FINANCIAL_PREFIXES = "AUTH_FINANCIAL_PREFIXES"  # tuple[str,...]

CFG_REQUIRE_CSRF_FOR_MUTATIONS = "AUTH_REQUIRE_CSRF_FOR_MUTATIONS"  # bool
CFG_CSRF_HEADER_NAMES = "AUTH_CSRF_HEADER_NAMES"  # tuple[str,...]
CFG_CSRF_FORM_NAMES = "AUTH_CSRF_FORM_NAMES"  # tuple[str,...]

CFG_LOGIN_REDIRECT_STATUS = "AUTH_LOGIN_REDIRECT_STATUS"  # 302/303 (default 302)
CFG_JSON_ERROR_SHAPE = "AUTH_JSON_ERROR_SHAPE"  # "simple" | "oauth" (default simple)


# -----------------------------
# Core dataclasses
# -----------------------------
@dataclass(frozen=True)
class AuthUser:
    """
    Vista mínima de usuario, sin acoplar a tu modelo.
    Se obtiene desde Flask-Login si está, o desde session.
    """
    id: Optional[str]
    email: Optional[str]
    role: Optional[str]
    is_authenticated: bool
    is_admin: bool
    is_staff: bool
    is_active: Optional[bool] = None
    email_verified: Optional[bool] = None


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    reason: str
    status_code: int
    login_url: Optional[str] = None
    next_path: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None


# -----------------------------
# Small helpers (robustos)
# -----------------------------
def _cfg(name: str, default: Any) -> Any:
    try:
        return current_app.config.get(name, default)
    except Exception:
        return default


def _s(v: Any, max_len: int = 256) -> str:
    s = "" if v is None else str(v)
    s = s.replace("\u200b", "").strip()
    if len(s) > max_len:
        s = s[:max_len]
    return s


def _is_truthy(v: Any) -> bool:
    return v is True or (isinstance(v, (int, float)) and v == 1)


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
    return xrw == "xmlhttprequest"


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


def _resolve_login_url(*, endpoint: str, fallback_path: str, next_param: str, next_path: str) -> str:
    # No rompe si el endpoint no existe
    candidates = (endpoint, "admin_routes.login", "admin.login_admin", "admin_routes.admin_login")
    for ep in candidates:
        if not ep:
            continue
        u = _safe_url_for(ep, **{next_param: next_path})
        if u:
            return u

    sep = "&" if "?" in fallback_path else "?"
    return f"{fallback_path}{sep}{next_param}={quote(next_path, safe='/')}"


def _json_error_payload(code: int, reason: str, message: str, *, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    shape = _s(_cfg(CFG_JSON_ERROR_SHAPE, "simple"), 24).lower()
    base: Dict[str, Any]
    if shape == "oauth":
        base = {"error": reason, "error_description": message, "status": code}
    else:
        base = {"ok": False, "error": reason, "message": message, "status": code}
    if extra:
        base.update(extra)
    return base


def _set_no_store_headers(resp) -> None:
    try:
        for k, v in _NO_STORE_HEADERS.items():
            resp.headers[k] = v
        resp.headers["Vary"] = "Cookie"
    except Exception:
        pass


# -----------------------------
# Hooks / contexto de tienda
# -----------------------------
def _extra_context() -> Dict[str, Any]:
    """
    Hook para conectar con tu tienda sin acoplar:
    - podés setear AUTH_CONTEXT_CALLBACK en config para agregar: store_id, tenant, app_version, etc.
    """
    ctx: Dict[str, Any] = {}
    try:
        cb = _cfg(CFG_AUTH_CONTEXT_CALLBACK, None)
        if callable(cb):
            data = cb()
            if isinstance(data, dict):
                ctx.update(data)
    except Exception:
        pass
    return ctx


def _audit(event: Dict[str, Any]) -> None:
    """
    Auditoría: útil para admin panel, comisiones, afiliados, pagos, webhooks.
    """
    event = dict(event)
    event.setdefault("ip", _client_ip())
    event.setdefault("path", _s(getattr(request, "path", ""), 200))
    event.setdefault("method", _s(getattr(request, "method", ""), 12))
    event.setdefault("is_json", _is_json_like_request())
    event.setdefault("ts", int(time.time()))
    event.update(_extra_context())

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


# -----------------------------
# User resolver (conecta con Flask-Login + session + tu User model si existe)
# -----------------------------
def _resolve_current_user() -> AuthUser:
    """
    Orden:
    1) Flask-Login current_user (si existe)
    2) session (role/email/id si guardás)
    3) defaults seguros
    """
    # Flask-Login
    try:
        from flask_login import current_user  # type: ignore

        cu = current_user
        is_auth = bool(getattr(cu, "is_authenticated", False))
        uid = _s(getattr(cu, "get_id", lambda: None)(), 64) if hasattr(cu, "get_id") else _s(getattr(cu, "id", None), 64)
        email = _s(getattr(cu, "email", None), 254) or None
        role = _s(getattr(cu, "role_effective", None), 20) or _s(getattr(cu, "role", None), 20) or None

        is_admin = bool(getattr(cu, "is_admin", False)) or (role == "admin")
        is_staff = (role == "staff")
        is_active = getattr(cu, "is_active", None)
        email_verified = getattr(cu, "email_verified", None)

        return AuthUser(
            id=uid or None,
            email=email,
            role=role,
            is_authenticated=is_auth,
            is_admin=is_admin,
            is_staff=is_staff,
            is_active=bool(is_active) if is_active is not None else None,
            email_verified=bool(email_verified) if email_verified is not None else None,
        )
    except Exception:
        pass

    # session fallback
    try:
        uid = _s(session.get("user_id"), 64) or None
        email = _s(session.get("user_email"), 254) or None
        role = _s(session.get(_s(_cfg(CFG_ADMIN_ROLE_KEY, DEFAULT_ROLE_KEY_SESSION), 64) or DEFAULT_ROLE_KEY_SESSION), 20) or None
    except Exception:
        uid, email, role = None, None, None

    return AuthUser(
        id=uid,
        email=email,
        role=role,
        is_authenticated=False,
        is_admin=False,
        is_staff=False,
        is_active=None,
        email_verified=None,
    )


# -----------------------------
# CSRF check (opcional, pro)
# -----------------------------
def _csrf_present() -> bool:
    """
    No valida token cryptográficamente (eso lo hace Flask-WTF).
    Esto sólo evita requests mutantes sin ningún token presente.
    """
    header_names: Tuple[str, ...] = tuple(_cfg(CFG_CSRF_HEADER_NAMES, ("X-CSRF-Token", "X-CSRFToken", "X-CSRF")))
    form_names: Tuple[str, ...] = tuple(_cfg(CFG_CSRF_FORM_NAMES, ("csrf_token", "csrf", "_csrf")))

    try:
        for hn in header_names:
            if request.headers.get(hn):
                return True
    except Exception:
        pass

    try:
        if request.form:
            for fn in form_names:
                if request.form.get(fn):
                    return True
    except Exception:
        pass

    return False


# -----------------------------
# Soft rate-limit por sesión (anti abuso en admin/pagos/affiliate)
# -----------------------------
def _soft_rate_limit(bucket: str) -> Tuple[bool, int]:
    window_s = int(_cfg(CFG_SOFT_RL_WINDOW_S, 10) or 10)
    max_hits = int(_cfg(CFG_SOFT_RL_MAX, 30) or 30)
    if window_s < 1:
        window_s = 1
    if max_hits < 1:
        max_hits = 1

    key = f"_rl:{bucket}"
    try:
        now = int(time.time())
        data = session.get(key) or {}
        start = int(data.get("start") or 0)
        hits = int(data.get("hits") or 0)

        if start <= 0 or now - start >= window_s:
            start = now
            hits = 0

        hits += 1
        session[key] = {"start": start, "hits": hits}
        remaining = max(0, max_hits - hits)
        return (hits <= max_hits, remaining)
    except Exception:
        return (True, max_hits)


# -----------------------------
# Maintenance gate (útil cuando tocás comisiones/pagos)
# -----------------------------
def _maintenance_blocked() -> Optional[str]:
    if not bool(_cfg(CFG_MAINTENANCE_MODE, False)):
        return None

    allow_readonly = bool(_cfg(CFG_MAINTENANCE_ALLOW_READONLY, False))
    if allow_readonly and request.method in ("GET", "HEAD", "OPTIONS"):
        return None

    msg = _s(_cfg(CFG_MAINTENANCE_MESSAGE, "Sistema en mantenimiento. Probá más tarde."), 180)
    return msg or "Sistema en mantenimiento."


def _path_starts_with_any(path: str, prefixes: Iterable[str]) -> bool:
    p = path or ""
    for pref in prefixes:
        if pref and p.startswith(pref):
            return True
    return False


# -----------------------------
# Gate engine (conectado a tu tienda)
# -----------------------------
def _decide_admin_gate(
    *,
    session_key: str,
    login_endpoint: str,
    login_fallback_path: str,
    next_param: str,
    default_next: str,
    allowed_roles: Set[str],
) -> GateDecision:
    # 1) maintenance
    mm = _maintenance_blocked()
    if mm:
        return GateDecision(False, "maintenance", 503, payload={"message": mm})

    # 2) RL (más estricto si ruta financiera)
    path = _s(getattr(request, "path", ""), 200)
    financial_prefixes = tuple(_cfg(CFG_FINANCIAL_PREFIXES, FINANCIAL_PREFIXES_DEFAULT))
    bucket = "admin_financial" if _path_starts_with_any(path, financial_prefixes) else "admin"
    ok_rl, remaining = _soft_rate_limit(bucket)
    if not ok_rl:
        return GateDecision(False, "rate_limited", 429, payload={"remaining": remaining})

    # 3) bypass emergencia
    if bool(_cfg(CFG_ADMIN_BYPASS, False)):
        return GateDecision(True, "bypass", 200)

    # 4) compat: session flag
    try:
        if not _is_truthy(session.get(session_key)):
            # next robusto
            raw_next = None
            try:
                raw_next = request.args.get(next_param)
            except Exception:
                raw_next = None

            fallback_next = "/"
            try:
                fallback_next = request.path or "/"
            except Exception:
                fallback_next = "/"

            next_path = _clean_next_path(raw_next, default_path=_clean_next_path(fallback_next, default_path=default_next))
            if next_path.startswith("/admin/login"):
                next_path = _clean_next_path(default_next, default_path="/admin")

            login_url = _resolve_login_url(
                endpoint=login_endpoint,
                fallback_path=login_fallback_path,
                next_param=next_param,
                next_path=next_path,
            )
            return GateDecision(False, "not_logged_in", 401, login_url=login_url, next_path=next_path)
    except Exception:
        return GateDecision(False, "not_logged_in", 401)

    # 5) roles/scopes (si existe role)
    u = _resolve_current_user()
    role = (u.role or _s(session.get(_s(_cfg(CFG_ADMIN_ROLE_KEY, DEFAULT_ROLE_KEY_SESSION), 64) or DEFAULT_ROLE_KEY_SESSION), 20) or "").lower()
    if role and allowed_roles and role not in allowed_roles:
        return GateDecision(False, "role_denied", 403, payload={"role": role})

    # 6) activo/verificado (si existe; no rompe si no)
    if u.is_active is False:
        return GateDecision(False, "inactive", 403)
    # Para admin/pagos podrías exigir verificación de email si lo usás:
    # if _path_starts_with_any(path, financial_prefixes) and u.email_verified is False:
    #     return GateDecision(False, "email_not_verified", 403)

    # 7) CSRF “presence” para mutaciones sensibles (no reemplaza Flask-WTF, suma seguridad)
    require_csrf = bool(_cfg(CFG_REQUIRE_CSRF_FOR_MUTATIONS, True))
    if require_csrf and request.method not in ("GET", "HEAD", "OPTIONS"):
        if not _csrf_present():
            return GateDecision(False, "csrf_missing", 400)

    return GateDecision(True, "ok", 200)


# -----------------------------
# Unified responders (premium)
# -----------------------------
def _respond_denied(decision: GateDecision, *, flash_message: str, flash_category: str, abort_code_json: int, abort_code_html: Optional[int]):
    reason = decision.reason
    code = int(decision.status_code or 403)

    # JSON/AJAX
    if _is_json_like_request():
        if reason == "not_logged_in":
            abort(int(_cfg(CFG_ADMIN_ABORT_CODE_JSON, abort_code_json) or abort_code_json))

        msg_map = {
            "maintenance": "Sistema en mantenimiento.",
            "rate_limited": "Demasiados intentos. Probá más tarde.",
            "role_denied": "No tenés permisos.",
            "inactive": "Usuario inactivo.",
            "csrf_missing": "CSRF faltante.",
        }
        msg = (decision.payload or {}).get("message") or msg_map.get(reason, "Acceso denegado.")
        payload = _json_error_payload(code, reason, _s(msg, 220), extra=decision.payload or None)
        return jsonify(payload), code

    # HTML
    if reason == "maintenance":
        msg = (decision.payload or {}).get("message") or _s(_cfg(CFG_MAINTENANCE_MESSAGE, "Sistema en mantenimiento."), 180)
        try:
            flash(msg, "info")
        except Exception:
            pass
        abort(503)

    if reason == "rate_limited":
        try:
            flash("Demasiados intentos. Esperá un momento.", "warning")
        except Exception:
            pass
        abort(429)

    if reason == "role_denied":
        try:
            flash("No tenés permisos para acceder al panel.", "error")
        except Exception:
            pass
        abort(403)

    if reason == "csrf_missing":
        try:
            flash("Sesión expirada o CSRF faltante. Recargá y probá de nuevo.", "warning")
        except Exception:
            pass
        abort(400)

    if abort_code_html is not None:
        abort(int(abort_code_html))

    # not_logged_in: flash + redirect
    msg = _s(_cfg(CFG_ADMIN_FLASH_MESSAGE, flash_message), 180) or DEFAULT_FLASH_MESSAGE
    cat = _s(_cfg(CFG_ADMIN_FLASH_CATEGORY, flash_category), 32) or DEFAULT_FLASH_CATEGORY
    try:
        if msg:
            flash(msg, cat)
    except Exception:
        pass

    login_url = decision.login_url or _resolve_login_url(
        endpoint=_s(_cfg(CFG_ADMIN_LOGIN_ENDPOINT, DEFAULT_ADMIN_LOGIN_ENDPOINT), 128) or DEFAULT_ADMIN_LOGIN_ENDPOINT,
        fallback_path=_s(_cfg(CFG_ADMIN_LOGIN_FALLBACK_PATH, DEFAULT_ADMIN_LOGIN_FALLBACK_PATH), 200) or DEFAULT_ADMIN_LOGIN_FALLBACK_PATH,
        next_param=_s(_cfg("ADMIN_NEXT_PARAM", DEFAULT_NEXT_PARAM), 32) or DEFAULT_NEXT_PARAM,
        next_path=_clean_next_path(None, default_path=_s(_cfg(CFG_ADMIN_DEFAULT_NEXT, "/admin"), 200) or "/admin"),
    )

    status = int(_cfg(CFG_LOGIN_REDIRECT_STATUS, 302) or 302)
    resp = redirect(login_url, code=303 if status == 303 else 302)
    _set_no_store_headers(resp)
    try:
        resp.headers["X-Auth-Gate"] = reason
    except Exception:
        pass
    return resp


# -----------------------------
# Decorators (tu tienda completa)
# -----------------------------
def admin_required(
    view: Optional[F] = None,
    *,
    session_key: str = DEFAULT_ADMIN_SESSION_KEY,
    login_endpoint: str = DEFAULT_ADMIN_LOGIN_ENDPOINT,
    next_param: str = DEFAULT_NEXT_PARAM,
    default_next: str = "/admin",
    flash_message: str = DEFAULT_FLASH_MESSAGE,
    flash_category: str = DEFAULT_FLASH_CATEGORY,
    abort_code_json: int = 401,
    abort_code_html: Optional[int] = None,
    allowed_roles: Optional[Set[str]] = None,
) -> Any:
    """
    Admin gate PRO:
    - Compat: session["admin_logged_in"]=True
    - Roles opcional: {"admin","staff"}
    - Anti open-redirect + no-store
    - Maintenance + RL + CSRF presence en mutaciones
    - JSON/AJAX devuelve errores “limpios”
    """
    def decorator(fn: F) -> F:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any):
            sess_key = _s(_cfg(CFG_ADMIN_SESSION_KEY, session_key), 64) or session_key
            role_key = _s(_cfg(CFG_ADMIN_ROLE_KEY, DEFAULT_ROLE_KEY_SESSION), 64) or DEFAULT_ROLE_KEY_SESSION
            login_ep = _s(_cfg(CFG_ADMIN_LOGIN_ENDPOINT, login_endpoint), 128) or login_endpoint
            fallback = _s(_cfg(CFG_ADMIN_LOGIN_FALLBACK_PATH, DEFAULT_ADMIN_LOGIN_FALLBACK_PATH), 200) or DEFAULT_ADMIN_LOGIN_FALLBACK_PATH
            dnext = _s(_cfg(CFG_ADMIN_DEFAULT_NEXT, default_next), 200) or default_next

            allowed = allowed_roles
            if allowed is None:
                cfg_allowed = _cfg(CFG_ADMIN_ALLOWED_ROLES, DEFAULT_ALLOWED_ADMIN_ROLES)
                try:
                    allowed = set(cfg_allowed) if cfg_allowed else set(DEFAULT_ALLOWED_ADMIN_ROLES)
                except Exception:
                    allowed = set(DEFAULT_ALLOWED_ADMIN_ROLES)

            decision = _decide_admin_gate(
                session_key=sess_key,
                login_endpoint=login_ep,
                login_fallback_path=fallback,
                next_param=next_param,
                default_next=dnext,
                allowed_roles=allowed,
            )

            _audit(
                {
                    "type": "gate.admin",
                    "ok": decision.allowed,
                    "reason": decision.reason,
                    "user": _resolve_current_user().__dict__,
                    "session_key": sess_key,
                    "role_key": role_key,
                }
            )

            if decision.allowed:
                return fn(*args, **kwargs)

            return _respond_denied(
                decision,
                flash_message=flash_message,
                flash_category=flash_category,
                abort_code_json=abort_code_json,
                abort_code_html=abort_code_html,
            )

        return cast(F, wrapper)

    if view is None:
        return decorator
    return decorator(view)


def staff_required(view: Optional[F] = None, **kw: Any) -> Any:
    """
    Staff/admin gate: útil para soporte, moderación, gestión de pedidos,
    sin acceso a pagos/settlements si vos no querés.
    """
    roles = {"admin", "staff"}
    return admin_required(view, allowed_roles=roles, **kw)


def owner_required(view: Optional[F] = None, **kw: Any) -> Any:
    """
    Owner gate (si tu app marca owner en user.role_effective='admin' y/o role='admin').
    Este gate es “más estricto”: solo 'admin'.
    """
    roles = {"admin"}
    return admin_required(view, allowed_roles=roles, **kw)


def financial_required(view: Optional[F] = None, **kw: Any) -> Any:
    """
    Gate especial para rutas de dinero:
    - pensado para comisiones, payouts, payments, webhooks admin tools.
    - más estricto por diseño (admin-only por default).
    """
    roles = {"admin"}
    return admin_required(view, allowed_roles=roles, **kw)


# -----------------------------
# Helpers extra para tu tienda (premium DX)
# -----------------------------
def mark_admin_logged_in(*, role: str = "admin") -> None:
    """
    Helper para tu login admin:
      - session['admin_logged_in']=True
      - setea role (si tu tienda lo usa)
    """
    sk = _s(_cfg(CFG_ADMIN_SESSION_KEY, DEFAULT_ADMIN_SESSION_KEY), 64) or DEFAULT_ADMIN_SESSION_KEY
    rk = _s(_cfg(CFG_ADMIN_ROLE_KEY, DEFAULT_ROLE_KEY_SESSION), 64) or DEFAULT_ROLE_KEY_SESSION
    try:
        session[sk] = True
        if role:
            session[rk] = _s(role, 20).lower()
    except Exception:
        pass


def mark_admin_logged_out() -> None:
    sk = _s(_cfg(CFG_ADMIN_SESSION_KEY, DEFAULT_ADMIN_SESSION_KEY), 64) or DEFAULT_ADMIN_SESSION_KEY
    try:
        session.pop(sk, None)
    except Exception:
        pass


def is_admin_session() -> bool:
    sk = _s(_cfg(CFG_ADMIN_SESSION_KEY, DEFAULT_ADMIN_SESSION_KEY), 64) or DEFAULT_ADMIN_SESSION_KEY
    try:
        return _is_truthy(session.get(sk))
    except Exception:
        return False


def require_internal_webhook_signature(
    *,
    header_name: str = "X-Skyline-Signature",
    secret_env: str = "WEBHOOK_SECRET",
    algo: str = "sha256",
) -> None:
    """
    Helper para webhooks internos si los tenés (ej: Printful, MP, etc).
    NO implementa HMAC completo acá para no acoplar; solo asegura presencia.
    Podés extenderlo para validar firma real.
    """
    sig = _s(request.headers.get(header_name), 512)
    if not sig:
        _audit({"type": "webhook.sig", "ok": False, "reason": "missing_signature", "header": header_name})
        abort(401)

    secret = _s(current_app.config.get(secret_env) or "", 256)
    if not secret:
        # si no hay secret configurado, al menos registramos y bloqueamos en prod
        if not current_app.debug:
            _audit({"type": "webhook.sig", "ok": False, "reason": "secret_missing", "env": secret_env})
            abort(500)


__all__ = [
    "AuthUser",
    "GateDecision",
    "admin_required",
    "staff_required",
    "owner_required",
    "financial_required",
    "mark_admin_logged_in",
    "mark_admin_logged_out",
    "is_admin_session",
    "require_internal_webhook_signature",
]
