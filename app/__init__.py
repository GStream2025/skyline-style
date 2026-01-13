# app/__init__.py — Skyline Store (ULTRA PRO / NO BREAK / Render-safe) — vNEXT FIX
from __future__ import annotations

import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Type

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from app.config import ProductionConfig, get_config
from app.models import db, init_models

# ✅ compat (no rompe si no existe)
try:
    from app.models import create_admin_if_missing  # type: ignore
except Exception:  # pragma: no cover
    create_admin_if_missing = None  # type: ignore


# =============================================================================
# Helpers
# =============================================================================

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off"}


def _env_str(name: str, default: str = "") -> str:
    v = os.getenv(name)
    return (default if v is None else str(v)).strip()


def _env_bool(name: str, default: bool = False) -> bool:
    v = _env_str(name, "")
    if not v:
        return default
    vv = v.lower()
    if vv in _TRUE:
        return True
    if vv in _FALSE:
        return False
    return default


def _env_int(name: str, default: int, min_v: Optional[int] = None, max_v: Optional[int] = None) -> int:
    s = _env_str(name, "")
    try:
        v = int(s) if s else int(default)
    except Exception:
        v = int(default)
    if min_v is not None:
        v = max(min_v, v)
    if max_v is not None:
        v = min(max_v, v)
    return v


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _env_name(app: Flask) -> str:
    candidates = [
        app.config.get("ENV"),
        app.config.get("ENVIRONMENT"),
        _env_str("ENV"),
        _env_str("FLASK_ENV"),
        _env_str("ENVIRONMENT"),
    ]
    for c in candidates:
        if c:
            return str(c).lower().strip()
    return "production"


def _is_prod(app: Flask) -> bool:
    if bool(app.config.get("DEBUG")) or bool(getattr(app, "debug", False)):
        return False
    return _env_name(app) == "production"


def _want_verbose_logs(app: Flask) -> bool:
    """
    ✅ Para poder depurar en Render sin prender DEBUG=True
    Setear: VERBOSE_REQUEST_LOGS=1
    """
    if bool(getattr(app, "debug", False)):
        return True
    return _env_bool("VERBOSE_REQUEST_LOGS", False)


def wants_json() -> bool:
    p = (request.path or "").lower()
    if p.startswith("/api/") or p.startswith("/webhooks/") or p.startswith("/webhook"):
        return True
    if (_env_str("FORCE_JSON_ERRORS", "") or "").lower() in _TRUE:
        return True
    if (request.args.get("format") or "").lower() == "json":
        return True
    accept = (request.headers.get("Accept") or "").lower()
    if "application/json" in accept:
        return True
    if (request.headers.get("X-Requested-With") or "").lower() == "xmlhttprequest":
        return True
    return False


def resp_error(status: int, code: str, message: str):
    if wants_json():
        return jsonify({"ok": False, "error": code, "message": message, "status": status}), status

    # ✅ Nunca rompas por templates faltantes
    for tpl in (f"errors/{status}.html", "error.html"):
        try:
            return render_template(tpl, message=message, status=status, code=code), status
        except Exception:
            continue

    # ✅ Fallback ultra simple
    return (message or "Error"), status


def setup_logging(app: Flask) -> None:
    """Idempotente: no duplica handlers en gunicorn."""
    lvl = (_env_str("LOG_LEVEL", "")).upper().strip()
    if lvl in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}:
        level = getattr(logging, lvl)
    else:
        level = logging.DEBUG if bool(getattr(app, "debug", False)) else logging.INFO

    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(
            level=level,
            format="%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d - %(message)s",
        )
    root.setLevel(level)
    app.logger.setLevel(level)


def safe_init(app: Flask, label: str, fn: Callable[[], Any]) -> Any:
    try:
        out = fn()
        app.logger.info("✅ %s inicializado", label)
        return out
    except Exception as e:
        app.logger.warning(⚠️ %s omitido: %s", label, e, exc_info=_want_verbose_logs(app))
        return None


def critical_init(app: Flask, label: str, fn: Callable[[], Any]) -> Any:
    try:
        out = fn()
        app.logger.info("✅ %s inicializado", label)
        return out
    except Exception as e:
        app.logger.exception("🔥 %s falló (CRÍTICO): %s", label, e)
        raise


def has_endpoint(app: Flask, endpoint: str) -> bool:
    try:
        return bool(endpoint) and (endpoint in app.view_functions)
    except Exception:
        return False


def current_user_from_session() -> Any:
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        from app.models import User  # lazy import
        return db.session.get(User, int(uid))
    except Exception:
        return None


def _require_secret_key_prod(app: Flask) -> None:
    if not _is_prod(app):
        return
    sk = (app.config.get("SECRET_KEY") or "").strip()
    if (not sk) or (len(sk) < 32):
        raise RuntimeError(
            "SECRET_KEY requerido en producción (>=32 chars). "
            "Si no, CSRF y sesiones fallan (token mismatch)."
        )


def _ensure_secret_key_dev(app: Flask) -> None:
    if _is_prod(app):
        return
    if not (app.config.get("SECRET_KEY") or "").strip():
        app.config["SECRET_KEY"] = secrets.token_urlsafe(32)


def _mask_db_url(uri: Any) -> str:
    s = str(uri or "")
    if not s:
        return ""
    try:
        if "://" in s and "@" in s and ":" in s.split("://", 1)[1].split("@", 1)[0]:
            left, right = s.split("://", 1)
            creds, rest = right.split("@", 1)
            user = creds.split(":", 1)[0]
            return f"{left}://{user}:***@{rest}"
    except Exception:
        pass
    return s


# =============================================================================
# CSRF (Flask-WTF)
# =============================================================================

def init_csrf(app: Flask) -> None:
    from flask_wtf import CSRFProtect
    from flask_wtf.csrf import CSRFError

    csrf = CSRFProtect()
    csrf.init_app(app)

    exempt_prefixes: Set[str] = {
        "/webhook",
        "/webhooks",
        "/api/webhook",
        "/api/webhooks",
    }

    extra = _env_str("CSRF_EXEMPT_PREFIXES", "")
    if extra:
        for pref in [x.strip() for x in extra.split(",") if x.strip()]:
            exempt_prefixes.add(pref)

    exempted_endpoints: Set[str] = set()

    @app.before_request
    def _csrf_exempt_by_prefix():
        if request.method in {"GET", "HEAD", "OPTIONS"}:
            return None
        p = (request.path or "")
        if not p:
            return None

        for pref in exempt_prefixes:
            if p.startswith(pref):
                ep = request.endpoint or ""
                if ep and ep not in exempted_endpoints:
                    vf = app.view_functions.get(ep)
                    if vf:
                        try:
                            csrf.exempt(vf)
                            exempted_endpoints.add(ep)
                        except Exception:
                            pass
                break
        return None

    @app.errorhandler(CSRFError)
    def _handle_csrf_error(_e: CSRFError):
        return resp_error(
            400,
            "csrf_failed",
            "Solicitud inválida. El formulario expiró o el token de seguridad no coincide. "
            "Recargá la página e intentá nuevamente.",
        )


# =============================================================================
# Optional extensions (no-break)
# =============================================================================

def init_compress(app: Flask) -> None:
    from flask_compress import Compress
    Compress(app)


def init_talisman(app: Flask) -> None:
    from flask_talisman import Talisman

    force_https = bool(app.config.get("FORCE_HTTPS", _is_prod(app)))
    csp = app.config.get("CONTENT_SECURITY_POLICY", None)

    Talisman(
        app,
        force_https=force_https,
        content_security_policy=csp if isinstance(csp, dict) else None,
    )


def init_migrate(app: Flask) -> None:
    from flask_migrate import Migrate
    Migrate(app, db)


def init_limiter(app: Flask) -> None:
    try:
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
    except Exception as e:
        raise RuntimeError(f"flask_limiter missing ({e})")

    storage = _env_str("RATE_LIMIT_STORAGE_URI", "memory://")
    default_limit = _env_str("RATE_LIMIT_DEFAULT", "300 per hour")
    Limiter(get_remote_address, app=app, storage_uri=storage, default_limits=[default_limit])


# =============================================================================
# Cookies/sesión (Render-proof + Flask 3-proof)
# =============================================================================

def _configure_session_cookies(app: Flask) -> None:
    allow_domain = _env_bool("ALLOW_COOKIE_DOMAIN", False)

    if not allow_domain:
        app.config["SESSION_COOKIE_DOMAIN"] = None
    else:
        app.config.setdefault("SESSION_COOKIE_DOMAIN", None)

    app.config.setdefault("SESSION_COOKIE_PATH", "/")
    app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)

    samesite = str(app.config.get("SESSION_COOKIE_SAMESITE") or "Lax").strip()
    samesite_norm = samesite[:1].upper() + samesite[1:].lower() if samesite else "Lax"
    if samesite_norm not in {"Lax", "Strict", "None"}:
        samesite_norm = "Lax"
    app.config["SESSION_COOKIE_SAMESITE"] = samesite_norm

    if _is_prod(app):
        app.config.setdefault("SESSION_COOKIE_SECURE", True)
    else:
        app.config.setdefault("SESSION_COOKIE_SECURE", False)

    if app.config.get("SESSION_COOKIE_SAMESITE") == "None":
        app.config["SESSION_COOKIE_SECURE"] = True

    app.config.setdefault("SESSION_REFRESH_EACH_REQUEST", False)

    days = _env_int("SESSION_DAYS", int(app.config.get("SESSION_DAYS", 7) or 7), min_v=1, max_v=90)
    app.config.setdefault("PERMANENT_SESSION_LIFETIME", timedelta(days=days))

    app.config.setdefault("PREFERRED_URL_SCHEME", "https" if _is_prod(app) else "http")


# =============================================================================
# App Factory
# =============================================================================

def create_app() -> Flask:
    cfg_cls: Type = get_config()  # ✅ CLASE

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
        instance_relative_config=True,
    )

    # 1) Config primero (CRÍTICO)
    app.config.from_mapping(cfg_cls.as_flask_config())

    # 2) Logging idempotente
    setup_logging(app)

    # 3) Secret key guard (prod estricta, dev auto)
    _ensure_secret_key_dev(app)
    _require_secret_key_prod(app)

    # ✅ valida required en prod
    if isinstance(cfg_cls, type) and issubclass(cfg_cls, ProductionConfig):
        ProductionConfig.validate_required()

    # 4) ProxyFix (Render) — idempotente
    if bool(app.config.get("TRUST_PROXY_HEADERS", True)) and not getattr(app, "_proxyfix_applied", False):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)
        setattr(app, "_proxyfix_applied", True)

    # 5) Cookies/sesión
    _configure_session_cookies(app)

    # 6) CSRF defaults
    app.config.setdefault("WTF_CSRF_SSL_STRICT", _env_bool("WTF_CSRF_SSL_STRICT", default=False))
    app.config.setdefault("WTF_CSRF_TIME_LIMIT", _env_int("WTF_CSRF_TIME_LIMIT", 3600, min_v=60, max_v=24 * 3600))

    # ✅ Multi-worker: mantener secreto igual en todos los workers.
    if _is_prod(app):
        app.config.setdefault("WTF_CSRF_SECRET_KEY", app.config.get("SECRET_KEY"))

    app.logger.info(
        "🚀 create_app ENV=%s DEBUG=%s DB=%s SECURE=%s SAMESITE=%s CSRF_TTL=%s COOKIE_DOMAIN=%s",
        _env_name(app),
        bool(getattr(app, "debug", False)),
        _mask_db_url(app.config.get("SQLALCHEMY_DATABASE_URI")),
        app.config.get("SESSION_COOKIE_SECURE"),
        app.config.get("SESSION_COOKIE_SAMESITE"),
        app.config.get("WTF_CSRF_TIME_LIMIT"),
        app.config.get("SESSION_COOKIE_DOMAIN"),
    )

    # =============================================================================
    # ✅ Request logging (NO rompe) — te muestra el GET real en Render
    # =============================================================================
    @app.before_request
    def _reqlog_in():
        try:
            request._t0 = time.time()  # type: ignore[attr-defined]
        except Exception:
            pass
        if _want_verbose_logs(app):
            app.logger.info("➡️ %s %s", request.method, request.full_path)

    @app.after_request
    def _reqlog_out(resp):
        if _want_verbose_logs(app):
            try:
                dt = int((time.time() - getattr(request, "_t0", time.time())) * 1000)
            except Exception:
                dt = -1
            app.logger.info("⬅️ %s %s -> %s (%sms)", request.method, request.path, resp.status_code, dt)
        return resp

    # =============================================================================
    # Init extensiones (orden importante)
    # =============================================================================
    critical_init(app, "CSRFProtect", lambda: init_csrf(app))
    safe_init(app, "Flask-Compress", lambda: init_compress(app) if app.config.get("ENABLE_COMPRESS", True) else None)
    safe_init(app, "Flask-Talisman", lambda: init_talisman(app) if app.config.get("ENABLE_TALISMAN", False) else None)

    # ✅ MODELS HUB (CRÍTICO)
    critical_init(app, "Models hub", lambda: init_models(app, create_admin=True, log_loaded_models=True, ping_db=True))

    # ✅ Migrate / Limiter DESPUÉS de DB lista
    safe_init(app, "Flask-Migrate", lambda: init_migrate(app))
    safe_init(app, "Flask-Limiter", lambda: init_limiter(app))

    # =============================================================================
    # Jinja Globals
    # =============================================================================
    app.jinja_env.globals["has_endpoint"] = (lambda ep: has_endpoint(app, ep))

    # =============================================================================
    # Un SOLO pipeline before_request / after_request (evita duplicados)
    # =============================================================================
    registered: List[str] = []

    @app.before_request
    def _pipeline_before_request():
        rid = request.headers.get("X-Request-Id") or secrets.token_urlsafe(10)
        try:
            request._request_id = rid  # type: ignore[attr-defined]
        except Exception:
            pass

        if _env_bool("ADMIN_NO_CACHE", True) and (request.path or "").startswith("/admin"):
            try:
                request._admin_no_cache = True  # type: ignore[attr-defined]
            except Exception:
                pass

        if _env_bool("SESSION_PERMANENT_DEFAULT", True):
            try:
                session.permanent = True
            except Exception:
                pass

        # Unified Account redirects (solo GET/HEAD)
        if request.method in {"GET", "HEAD"}:
            p = (request.path or "")
            if not p.startswith("/auth/account"):
                nxt = (request.args.get("next") or "").strip()
                if not (nxt.startswith("/") and not nxt.startswith("//")):
                    nxt = ""

                def _redir(tab: str):
                    try:
                        if "main.account" in app.view_functions:
                            if nxt:
                                return redirect(url_for("main.account", tab=tab, next=nxt))
                            return redirect(url_for("main.account", tab=tab))
                    except Exception:
                        pass
                    q = f"?tab={tab}"
                    if nxt:
                        q += f"&next={nxt}"
                    return redirect("/account" + q)

                if p in {"/auth/login", "/login", "/account/login", "/cuenta/login"}:
                    return _redir("login")
                if p in {"/auth/register", "/register", "/account/register", "/cuenta/register"}:
                    return _redir("register")

        return None

    @app.after_request
    def _pipeline_after_request(resp):
        try:
            rid = getattr(request, "_request_id", None)
            if rid:
                resp.headers.setdefault("X-Request-Id", str(rid))
        except Exception:
            pass

        try:
            if getattr(request, "_admin_no_cache", False):
                resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
                resp.headers["Pragma"] = "no-cache"
        except Exception:
            pass

        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

        if _is_prod(app) and bool(app.config.get("FORCE_HTTPS", True)):
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

        rel = _env_str("RELEASE", "")
        if rel:
            resp.headers.setdefault("X-App-Release", rel)

        return resp

    # =============================================================================
    # Template globals (CSRF definitivo)
    # =============================================================================
    @app.context_processor
    def inject_globals() -> Dict[str, Any]:
        cu = None
        try:
            from flask_login import current_user as fl_current_user  # type: ignore
            if getattr(fl_current_user, "is_authenticated", False):
                cu = fl_current_user
        except Exception:
            cu = None

        if cu is None:
            cu = current_user_from_session()

        csrf_value = ""
        try:
            from flask_wtf.csrf import generate_csrf
            csrf_value = str(generate_csrf() or "")
        except Exception:
            csrf_value = ""

        csp_nonce = ""
        try:
            csp_nonce = str(getattr(request, "csp_nonce", "") or "")
        except Exception:
            csp_nonce = ""

        return {
            "APP_NAME": app.config.get("APP_NAME", "Skyline Store"),
            "APP_URL": app.config.get("APP_URL", ""),
            "ENV": _env_name(app),
            "now_utc": utcnow(),
            "request_id": getattr(request, "_request_id", None),
            "current_user": cu,
            "is_logged_in": bool(getattr(cu, "id", None)) if cu else False,
            "is_admin": bool(getattr(cu, "is_admin", False)) if cu else bool(session.get("is_admin")),
            "view_functions": app.view_functions,
            # ✅ USAR EN base.html: <meta name="csrf-token" content="{{ csrf_token_value }}">
            "csrf_token_value": csrf_value,
            "csp_nonce": csp_nonce,
        }

    # =============================================================================
    # Blueprints
    # =============================================================================
    def _register_all_routes():
        from app.routes import register_blueprints
        register_blueprints(app)
        registered[:] = sorted(app.blueprints.keys())
        return True

    if _env_bool("ROUTES_STRICT", False):
        critical_init(app, "Register Blueprints", _register_all_routes)
    else:
        safe_init(app, "Register Blueprints", _register_all_routes)

    # =============================================================================
    # ✅ ROOT SAFETY: que "/" nunca quede “huérfano”
    # =============================================================================
    if "main.root" not in app.view_functions:
        @app.get("/")
        def root_fallback():
            # 1) si existe main.home -> redirect
            try:
                if "main.home" in app.view_functions:
                    return redirect(url_for("main.home"))
            except Exception:
                pass
            # 2) si existe shop.shop -> redirect
            try:
                if "shop.shop" in app.view_functions:
                    return redirect(url_for("shop.shop"))
            except Exception:
                pass
            # 3) fallback
            return resp_error(200, "ok", "Skyline Store — online")

    # =============================================================================
    # Health / Ready
    # =============================================================================
    def _db_check() -> Tuple[bool, str]:
        if not _env_bool("HEALTH_DB_CHECK", False):
            return True, "skipped"
        try:
            from sqlalchemy import text
            db.session.execute(text("SELECT 1"))
            return True, "ok"
        except Exception as e:
            return False, (str(e) or "db_error")[:240]

    @app.get("/health")
    def health():
        ok_db, db_msg = _db_check()
        return {
            "status": "ok" if ok_db else "degraded",
            "env": _env_name(app),
            "debug": bool(getattr(app, "debug", False)),
            "blueprints": registered,
            "db": db_msg,
            "app": app.config.get("APP_NAME", "Skyline Store"),
            "ts": int(time.time()),
            "request_id": getattr(request, "_request_id", None),
        }

    @app.get("/ready")
    def ready():
        ok_db, db_msg = _db_check()
        return jsonify({"ok": bool(ok_db), "db": db_msg}), (200 if ok_db else 503)

    # ✅ Ping simple para aislar problemas de templates/rutas
    @app.get("/__ping")
    def __ping():
        return "ok", 200

    # =============================================================================
    # Error handlers (con logs SIEMPRE)
    # =============================================================================
    @app.errorhandler(HTTPException)
    def http_error(e: HTTPException):
        code = int(e.code or 500)
        name = (e.name or "http_error").lower().replace(" ", "_")
        # ✅ log mínimo si es 4xx/5xx
        if _want_verbose_logs(app) or code >= 500:
            app.logger.warning("HTTP %s %s: %s", code, request.path, name)
        return resp_error(code, name, e.description)

    @app.errorhandler(Exception)
    def unhandled_error(e: Exception):
        if isinstance(e, HTTPException):
            return e
        # ✅ SIEMPRE stacktrace para 500
        app.logger.exception("🔥 Unhandled error on %s %s: %s", request.method, request.path, e)
        return resp_error(500, "server_error", "Error interno del servidor.")

    # =============================================================================
    # CLI útiles
    # =============================================================================
    @app.cli.command("create-admin")
    def cli_create_admin():
        if not create_admin_if_missing:
            print("create_admin_if_missing no está disponible en app.models")
            return
        out = create_admin_if_missing(app)  # type: ignore[misc]
        print(out)

    @app.cli.command("seed")
    def cli_seed():
        if not create_admin_if_missing:
            print("create_admin_if_missing no está disponible en app.models")
            return
        with app.app_context():
            print(create_admin_if_missing(app))  # type: ignore[misc]

    return app


__all__ = ["create_app", "db"]
