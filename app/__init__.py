from __future__ import annotations

import json
import logging
import os
import secrets
from pathlib import Path
from typing import Optional, Callable, Any, Dict, List

from flask import Flask, jsonify, render_template, request, session
from werkzeug.middleware.proxy_fix import ProxyFix

# ✅ Usamos el db único del hub de modelos
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
    s = v.strip().lower()
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
        return int(v)
    except (TypeError, ValueError):
        return default


def _normalize_database_url(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    # Heroku legacy
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql://", 1)
    return url


def _env_name(debug: bool) -> str:
    """
    Normaliza ENV final.
    - Si debug: development
    - Si no: production
    """
    return "development" if debug else "production"


def _secure_default_secret(debug: bool) -> str:
    """
    - En prod: si no hay SECRET_KEY, generamos una aleatoria en runtime (no rompe deploy)
      (pero reinicios invalidan sesiones; ideal setear SECRET_KEY en Render).
    - En dev: dejamos una fija.
    """
    env_secret = os.getenv("SECRET_KEY")
    if env_secret:
        return env_secret
    if debug:
        return "dev-secret-change-me"
    return secrets.token_urlsafe(48)


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
    app.logger.setLevel(level)


def _safe_init(app: Flask, label: str, fn: Callable[[], Any]) -> Any:
    try:
        out = fn()
        app.logger.info("✅ %s inicializado", label)
        return out
    except Exception as e:
        # no rompe deploy, deja rastros claros
        app.logger.warning("⚠️ %s no pudo inicializarse: %s", label, e, exc_info=app.debug)
        return None


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
# Payments Settings (MP UY/AR, PayPal, Transfer)
# - sin DB, sin migraciones: JSON en instance/
# ============================================================

def _payments_defaults() -> Dict[str, Any]:
    return {
        "mp_uy": {"active": False, "link": "", "note": ""},
        "mp_ar": {"active": False, "link": "", "note": ""},
        "paypal": {"active": False, "user": "", "email": ""},
        "transfer": {"active": False, "info": ""},
    }


def _settings_dir(app: Flask) -> Path:
    p = Path(app.instance_path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def payments_path(app: Flask) -> Path:
    return _settings_dir(app) / "payments_settings.json"


def load_payments(app: Flask) -> Dict[str, Any]:
    data = _payments_defaults()
    path = payments_path(app)
    if path.exists():
        try:
            raw = json.loads(path.read_text("utf-8"))
            if isinstance(raw, dict):
                for k in data.keys():
                    if isinstance(raw.get(k), dict):
                        data[k].update(raw[k])
        except Exception:
            pass
    return data


def save_payments(app: Flask, data: Dict[str, Any]) -> None:
    path = payments_path(app)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), "utf-8")


# ============================================================
# App Factory (ULTRA PRO FINAL)
# ============================================================

def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")

    # -------------------------
    # Env / debug (fuente única)
    # -------------------------
    env_raw = (os.getenv("ENV") or os.getenv("FLASK_ENV") or "production").strip().lower()
    debug = _bool_env("DEBUG", env_raw in {"dev", "development"}) or _bool_env("FLASK_DEBUG", False)

    # ProxyFix (Render / reverse proxy)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    # -------------------------
    # Core config (blindado)
    # -------------------------
    app_env = _env_name(debug)
    cookie_secure = _bool_env("COOKIE_SECURE", not debug)

    # Database URI
    db_url = _normalize_database_url(os.getenv("DATABASE_URL"))
    db_uri = db_url or os.getenv("SQLALCHEMY_DATABASE_URI") or "sqlite:///skyline.db"

    app.config.update(
        SECRET_KEY=_secure_default_secret(debug),
        ENV=app_env,
        DEBUG=debug,

        SQLALCHEMY_DATABASE_URI=db_uri,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,

        # Cookies hardening
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE=os.getenv("SESSION_SAMESITE", "Lax"),
        SESSION_COOKIE_SECURE=cookie_secure,

        # JSON
        JSON_SORT_KEYS=False,

        # Upload base
        UPLOADS_DIR=os.getenv("UPLOADS_DIR") or "",

        # Shop config
        APP_NAME=os.getenv("APP_NAME", "Skyline Store"),
        CURRENCY=os.getenv("CURRENCY", "UYU"),
    )
    app.debug = debug

    _setup_logging(app)
    app.logger.info("🚀 create_app() ENV=%s DEBUG=%s DB=%s", app.config["ENV"], app.config["DEBUG"], app.config["SQLALCHEMY_DATABASE_URI"])

    # -------------------------
    # Extensions (opcionales y safe)
    # -------------------------
    def _compress():
        from flask_compress import Compress
        Compress(app)

    _safe_init(app, "Flask-Compress", _compress)

    def _talisman():
        from flask_talisman import Talisman
        force_https = _bool_env("FORCE_HTTPS", app.config["ENV"] == "production")
        # CSP None para no romper assets / inline scripts (tu tienda usa bastante UI)
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
        if not app.debug:
            Minify(app=app, html=True, js=True, cssless=True)

    _safe_init(app, "Flask-Minify", _minify)

    def _migrate():
        from flask_migrate import Migrate
        Migrate(app, db)

    _safe_init(app, "Flask-Migrate", _migrate)

    # -------------------------
    # Models hub (ÚNICA fuente de create_all + admin)
    # - NO duplicar create_all acá
    # -------------------------
    def _models_bootstrap():
        # En dev/local puede crear tablas automáticamente si AUTO_CREATE_TABLES=1 (default)
        # En prod, por defecto NO crea tablas.
        out = init_models(app, create_admin=True, auto_create_tables=None)
        return out

    _safe_init(app, "Models hub", _models_bootstrap)

    # -------------------------
    # Template globals
    # -------------------------
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
        }

    # -------------------------
    # Blueprints (centralizados)
    # -------------------------
    registered: List[str] = []

    def _register_all_routes():
        from app.routes import register_blueprints  # routes/__init__.py
        register_blueprints(app)
        registered[:] = sorted(app.blueprints.keys())

    _safe_init(app, "Register Blueprints", _register_all_routes)

    # -------------------------
    # Health + error pages
    # -------------------------
    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "env": app.config["ENV"],
            "debug": bool(app.debug),
            "blueprints": registered,
            "db": (app.config.get("SQLALCHEMY_DATABASE_URI") or ""),
            "app": app.config.get("APP_NAME", "Skyline Store"),
        }

    @app.errorhandler(404)
    def not_found(_e):
        wants_json = "application/json" in (request.headers.get("Accept") or "").lower()
        if wants_json:
            return jsonify({"error": "not_found", "path": request.path}), 404
        try:
            return render_template("404.html"), 404
        except Exception:
            return jsonify({"error": "not_found", "path": request.path}), 404

    @app.errorhandler(500)
    def server_error(e):
        app.logger.exception("🔥 Error 500: %s", e)
        wants_json = "application/json" in (request.headers.get("Accept") or "").lower()
        if wants_json:
            return jsonify({"error": "server_error"}), 500
        try:
            return render_template("500.html"), 500
        except Exception:
            return jsonify({"error": "server_error"}), 500

    # -------------------------
    # CLI helpers (seguros)
    # -------------------------
    @app.cli.command("create-admin")
    def cli_create_admin():
        """Crea/actualiza admin desde ENV ADMIN_EMAIL/ADMIN_PASSWORD."""
        out = create_admin_if_missing(app)
        print(out)

    @app.cli.command("create-tables")
    def cli_create_tables():
        """Crea tablas en DB (solo local/dev recomendado)."""
        with app.app_context():
            db.create_all()
            print("✅ Tablas creadas")

    @app.cli.command("seed")
    def cli_seed():
        """Seed mínimo (admin)."""
        with app.app_context():
            print(create_admin_if_missing(app))

    return app


__all__ = ["create_app", "db", "load_payments", "save_payments"]
