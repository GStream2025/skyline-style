from __future__ import annotations

import json
import logging
import os
import secrets
import tempfile
import time
from datetime import timedelta
from pathlib import Path
from typing import Optional, Callable, Any, Dict, List, Tuple

from flask import Flask, jsonify, render_template, request, session
from werkzeug.middleware.proxy_fix import ProxyFix

from app.models import db, init_models, create_admin_if_missing


# ============================================================
# ENV helpers
# ============================================================

_TRUE = {"1", "true", "yes", "y", "on"}
_FALSE = {"0", "false", "no", "n", "off"}


def _bool_env(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    s = str(v).strip().lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return default


def _int_env(key: str, default: int) -> int:
    v = os.getenv(key)
    if v is None:
        return default
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def _str_env(key: str, default: str = "") -> str:
    v = os.getenv(key)
    return default if v is None else str(v)


def _normalize_database_url(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    u = str(url).strip()
    if u.startswith("postgres://"):
        return u.replace("postgres://", "postgresql://", 1)
    return u


def _is_production(env: str) -> bool:
    env = (env or "").strip().lower()
    return env in {"prod", "production"}


def _detect_env() -> str:
    """
    Render/Flask: pueden venir como ENV o FLASK_ENV.
    Dejamos un env canónico: 'production' o 'development'
    """
    raw = (os.getenv("ENV") or os.getenv("FLASK_ENV") or "production").strip().lower()
    if raw in {"dev", "development"}:
        return "development"
    return "production"


def _secure_secret_key(env: str) -> str:
    """
    ✅ En production: EXIGE SECRET_KEY (para evitar invalidación de sesión/CSRF)
    ✅ En development: permite fallback local
    """
    env_secret = (os.getenv("SECRET_KEY") or "").strip()
    if env_secret:
        return env_secret
    if _is_production(env):
        raise RuntimeError("Falta SECRET_KEY en producción. Configurala en Render (Environment).")
    return "dev-secret-change-me"


def _wants_json() -> bool:
    p = (request.path or "").lower()
    if p.startswith("/api/"):
        return True
    accept = (request.headers.get("Accept") or "").lower()
    if "application/json" in accept:
        return True
    if (request.headers.get("X-Requested-With") or "").lower() == "xmlhttprequest":
        return True
    return False


# ============================================================
# Logging
# ============================================================

def _setup_logging(app: Flask) -> None:
    lvl = (os.getenv("LOG_LEVEL") or "").strip().upper()
    if lvl in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}:
        level = getattr(logging, lvl)
    else:
        level = logging.DEBUG if app.debug else logging.INFO

    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(
            level=level,
            format="%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d - %(message)s",
        )
    root.setLevel(level)
    app.logger.setLevel(level)


def _safe_init(app: Flask, label: str, fn: Callable[[], Any]) -> Any:
    try:
        out = fn()
        app.logger.info("✅ %s inicializado", label)
        return out
    except Exception as e:
        app.logger.warning("⚠️ %s no pudo inicializarse: %s", label, e, exc_info=bool(app.debug))
        return None


def _critical_init(app: Flask, label: str, fn: Callable[[], Any]) -> Any:
    try:
        out = fn()
        app.logger.info("✅ %s inicializado", label)
        return out
    except Exception as e:
        app.logger.exception("🔥 %s falló (CRÍTICO): %s", label, e)
        raise


# ============================================================
# Auth helpers
# ============================================================

def _get_current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        from app.models import User
        return db.session.get(User, int(uid))
    except Exception:
        return None


# ============================================================
# Payments Settings (JSON en instance/)
# ============================================================

def _payments_defaults() -> Dict[str, Any]:
    return {
        "mp_uy": {"active": False, "link": "", "note": ""},
        "mp_ar": {"active": False, "link": "", "note": ""},
        "paypal": {"active": False, "user": "", "email": "", "mode": "live"},
        "transfer": {"active": False, "info": ""},
        "wise": {"active": False, "link": "", "note": ""},
        "payoneer": {"active": False, "link": "", "note": ""},
        "paxum": {"active": False, "link": "", "note": ""},
    }


def _settings_dir(app: Flask) -> Path:
    p = Path(app.instance_path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def payments_path(app: Flask) -> Path:
    return _settings_dir(app) / "payments_settings.json"


def _merge_dict(base: Dict[str, Any], raw: Any) -> Dict[str, Any]:
    out = dict(base)
    if isinstance(raw, dict):
        for k, v in raw.items():
            if k in out and isinstance(out.get(k), dict) and isinstance(v, dict):
                out[k].update(v)
    return out


def load_payments(app: Flask) -> Dict[str, Any]:
    data = _payments_defaults()
    path = payments_path(app)
    if not path.exists():
        return data
    try:
        raw = json.loads(path.read_text("utf-8"))
        return _merge_dict(data, raw)
    except Exception:
        return data


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, str(path))
    finally:
        try:
            if os.path.exists(tmp_name):
                os.remove(tmp_name)
        except Exception:
            pass


def save_payments(app: Flask, data: Dict[str, Any]) -> None:
    base = _payments_defaults()
    safe = _merge_dict(base, data)
    _atomic_write_text(payments_path(app), json.dumps(safe, ensure_ascii=False, indent=2))


# ============================================================
# CSRF (robusto)
# - soporta: form field, header, JSON body
# ============================================================

def _ensure_csrf_token() -> str:
    tok = session.get("csrf_token")
    if not tok or not isinstance(tok, str) or len(tok) < 16:
        tok = secrets.token_urlsafe(32)
        session["csrf_token"] = tok
    return tok


def _extract_csrf_from_request() -> str:
    ht = (request.headers.get("X-CSRF-Token") or "").strip()
    if ht:
        return ht

    ft = (request.form.get("csrf_token") or "").strip()
    if ft:
        return ft

    # JSON body
    try:
        if request.is_json:
            data = request.get_json(silent=True) or {}
            jt = str(data.get("csrf_token") or "").strip()
            if jt:
                return jt
    except Exception:
        pass

    return ""


def _csrf_ok() -> bool:
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return True
    st = session.get("csrf_token") or ""
    token = _extract_csrf_from_request()
    return bool(st) and bool(token) and secrets.compare_digest(str(st), str(token))


# ============================================================
# App Factory (FINAL)
# ============================================================

def create_app() -> Flask:
    env = _detect_env()
    debug = _bool_env("DEBUG", env == "development") or _bool_env("FLASK_DEBUG", False)

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
        instance_relative_config=True,
    )

    # ProxyFix (Render)
    if _bool_env("TRUST_PROXY_HEADERS", True):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    # Database
    db_url = _normalize_database_url(os.getenv("DATABASE_URL"))
    db_uri = (db_url or os.getenv("SQLALCHEMY_DATABASE_URI") or "sqlite:///skyline.db").strip()

    # Seguridad cookies
    cookie_secure = _bool_env("COOKIE_SECURE", _is_production(env))
    session_samesite = (_str_env("SESSION_SAMESITE", "Lax") or "Lax").strip()
    if session_samesite not in {"Lax", "Strict", "None"}:
        session_samesite = "Lax"

    max_mb = max(1, _int_env("MAX_UPLOAD_MB", 20))
    secret = _secure_secret_key(env)

    engine_opts: Dict[str, Any] = {
        "pool_pre_ping": True,
        "pool_recycle": _int_env("DB_POOL_RECYCLE", 280),
    }

    app.config.update(
        SECRET_KEY=secret,
        ENV=env,
        DEBUG=debug,

        SQLALCHEMY_DATABASE_URI=db_uri,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SQLALCHEMY_ENGINE_OPTIONS=engine_opts,

        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE=session_samesite,
        SESSION_COOKIE_SECURE=cookie_secure,

        PERMANENT_SESSION_LIFETIME=timedelta(days=_int_env("SESSION_DAYS", 14)),
        PREFERRED_URL_SCHEME="https" if _is_production(env) else "http",

        JSON_SORT_KEYS=False,

        UPLOADS_DIR=(os.getenv("UPLOADS_DIR") or "").strip(),
        APP_NAME=os.getenv("APP_NAME", "Skyline Store"),
        CURRENCY=os.getenv("CURRENCY", "UYU"),

        MAX_CONTENT_LENGTH=max_mb * 1024 * 1024,
    )

    _setup_logging(app)

    app.logger.info(
        "🚀 create_app() ENV=%s DEBUG=%s DB=%s COOKIE_SECURE=%s SAMESITE=%s",
        app.config["ENV"],
        bool(app.debug),
        app.config["SQLALCHEMY_DATABASE_URI"],
        app.config["SESSION_COOKIE_SECURE"],
        app.config["SESSION_COOKIE_SAMESITE"],
    )

    if _is_production(env) and db_uri.startswith("sqlite"):
        app.logger.warning("⚠️ Producción con SQLite detectado. Recomendado Postgres en Render.")

    # Extensiones opcionales
    _safe_init(app, "Flask-Compress", lambda: __import__("flask_compress").flask_compress.Compress(app))  # type: ignore

    def _talisman():
        from flask_talisman import Talisman
        force_https = _bool_env("FORCE_HTTPS", _is_production(env))
        Talisman(app, force_https=force_https, content_security_policy=None)
    _safe_init(app, "Flask-Talisman", _talisman)

    def _cache():
        from flask_caching import Cache
        cache = Cache(config={
            "CACHE_TYPE": os.getenv("CACHE_TYPE", "SimpleCache"),
            "CACHE_DEFAULT_TIMEOUT": _int_env("CACHE_DEFAULT_TIMEOUT", 300),
        })
        cache.init_app(app)
        return cache
    _safe_init(app, "Flask-Caching", _cache)

    def _minify():
        from flask_minify import Minify
        if not app.debug and _bool_env("MINIFY", True):
            Minify(app=app, html=True, js=True, cssless=True)
    _safe_init(app, "Flask-Minify", _minify)

    def _migrate():
        from flask_migrate import Migrate
        Migrate(app, db)
    _safe_init(app, "Flask-Migrate", _migrate)

    def _limiter():
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
        return Limiter(
            get_remote_address,
            app=app,
            default_limits=[os.getenv("RATE_LIMIT_DEFAULT", "200 per hour")],
            storage_uri=os.getenv("RATE_LIMIT_STORAGE_URI", "memory://"),
        )
    _safe_init(app, "Flask-Limiter", _limiter)

    # Models hub (CRÍTICO)
    _critical_init(app, "Models hub", lambda: init_models(app, create_admin=True, auto_create_tables=None, log_loaded_models=True))

    # Requests
    @app.before_request
    def _before_request():
        # CSRF token siempre presente en session
        try:
            _ensure_csrf_token()
        except Exception:
            pass

        # CSRF en mutaciones (excepto health y webhooks)
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            p = request.path or ""
            if p != "/health" and not p.startswith("/webhook"):
                if not _csrf_ok():
                    if _wants_json():
                        return jsonify({"error": "csrf_failed"}), 400
                    try:
                        return render_template("errors/400.html"), 400
                    except Exception:
                        return render_template("error.html", message="Solicitud inválida. Recargá la página e intentá nuevamente."), 400

        # No-cache admin
        if _bool_env("ADMIN_NO_CACHE", True) and (request.path or "").startswith("/admin"):
            try:
                request._admin_no_cache = True  # type: ignore[attr-defined]
            except Exception:
                pass

    @app.after_request
    def _after_request(resp):
        # No cache admin
        try:
            if getattr(request, "_admin_no_cache", False):
                resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
                resp.headers["Pragma"] = "no-cache"
        except Exception:
            pass

        # Security headers base
        try:
            resp.headers.setdefault("X-Content-Type-Options", "nosniff")
            resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        except Exception:
            pass

        return resp

    # Template globals
    @app.context_processor
    def inject_globals() -> Dict[str, Any]:
        u = _get_current_user()
        return {
            "current_user": u,
            "is_logged_in": bool(u),
            "is_admin": bool(getattr(u, "is_admin", False)) if u else bool(session.get("is_admin")),
            "APP_NAME": app.config.get("APP_NAME", "Skyline Store"),
            "ENV": app.config.get("ENV"),
            "CURRENCY": app.config.get("CURRENCY", "UYU"),
            "csrf_token": session.get("csrf_token", ""),
        }

    # Blueprints
    registered: List[str] = []

    def _register_all_routes():
        from app.routes import register_blueprints
        register_blueprints(app)
        registered[:] = sorted(app.blueprints.keys())
        return True

    if _bool_env("ROUTES_STRICT", False):
        _critical_init(app, "Register Blueprints", _register_all_routes)
    else:
        _safe_init(app, "Register Blueprints", _register_all_routes)

    # Health + errors
    def _db_check() -> Tuple[bool, str]:
        if not _bool_env("HEALTH_DB_CHECK", False):
            return True, "skipped"
        try:
            db.session.execute(db.text("SELECT 1"))
            return True, "ok"
        except Exception as e:
            return False, str(e)

    @app.get("/health")
    def health():
        ok_db, db_msg = _db_check()
        return {
            "status": "ok" if ok_db else "degraded",
            "env": app.config["ENV"],
            "debug": bool(app.debug),
            "blueprints": registered,
            "db": db_msg,
            "app": app.config.get("APP_NAME", "Skyline Store"),
            "ts": int(time.time()),
        }

    @app.errorhandler(404)
    def not_found(_e):
        if _wants_json():
            return jsonify({"error": "not_found", "path": request.path}), 404
        try:
            return render_template("errors/404.html"), 404
        except Exception:
            return jsonify({"error": "not_found", "path": request.path}), 404

    @app.errorhandler(500)
    def server_error(e):
        app.logger.exception("🔥 Error 500: %s", e)
        if _wants_json():
            return jsonify({"error": "server_error"}), 500
        try:
            return render_template("errors/500.html"), 500
        except Exception:
            return jsonify({"error": "server_error"}), 500

    # CLI
    @app.cli.command("create-admin")
    def cli_create_admin():
        out = create_admin_if_missing(app)
        print(out)

    @app.cli.command("create-tables")
    def cli_create_tables():
        with app.app_context():
            db.create_all()
            print("✅ Tablas creadas")

    @app.cli.command("seed")
    def cli_seed():
        with app.app_context():
            print(create_admin_if_missing(app))

    return app


__all__ = ["create_app", "db", "load_payments", "save_payments"]
