from __future__ import annotations

import importlib
import logging
import os
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, Optional, Set
from urllib.parse import urlparse, urlunparse

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text as sa_text
from sqlalchemy.exc import OperationalError, ProgrammingError, SQLAlchemyError

log = logging.getLogger("models")

# -----------------------------------------------------------------------------
# SQLAlchemy single instance (global)
# -----------------------------------------------------------------------------
db = SQLAlchemy()

# -----------------------------------------------------------------------------
# Constants / helpers
# -----------------------------------------------------------------------------
_TRUE = {"1", "true", "yes", "y", "on", "checked", "enable", "enabled"}
_FALSE = {"0", "false", "no", "n", "off", "disable", "disabled"}

_INIT_LOCK = threading.RLock()
_LOADED_MODELS: Optional[Dict[str, Any]] = None
_BOOTSTRAP_DONE = False  # admin bootstrap once per process

_SQLA_EXT_KEY = "sqlalchemy"
_LOCAL_SQLITE_FALLBACK = "sqlite:///skyline_local.db"

_MAX_EMAIL_LEN = 254
_EMAIL_SIMPLE_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

_PG_PREFIX_OLD = "postgres://"
_PG_PREFIX_NEW = "postgresql://"

_ENV_MAX_LEN = 4096


def text(sql: str):
    """Use models.text('SQL') consistently everywhere."""
    return sa_text(sql)


def _env_flag(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    s = str(v).strip().lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return default


def _env_str(name: str, default: str = "", *, max_len: int = _ENV_MAX_LEN) -> str:
    v = os.getenv(name)
    s = (default if v is None else str(v)).strip()
    if max_len > 0 and len(s) > max_len:
        s = s[:max_len]
    return s


def _app_env(app: Flask) -> str:
    """
    Canonical env name across the project.
    NOTE: avoids relying on Flask's deprecated ENV behavior.
    """
    env = (
        (app.config.get("ENV") or "")
        or (app.config.get("ENVIRONMENT") or "")
        or (os.getenv("ENV") or "")
        or (os.getenv("FLASK_ENV") or "")
    )
    env = str(env).lower().strip()
    if env in {"prod", "production"}:
        return "production"
    if env in {"test", "testing"}:
        return "testing"
    if env in {"dev", "development"}:
        return "development"
    if bool(app.config.get("TESTING")):
        return "testing"
    if bool(app.config.get("DEBUG")):
        return "development"
    return "production"


def _is_production(app: Flask) -> bool:
    return _app_env(app) == "production"


def _is_testing(app: Flask) -> bool:
    return bool(app.config.get("TESTING")) or _app_env(app) == "testing"


def _normalize_db_url(raw: str) -> str:
    u = (raw or "").strip()
    if not u:
        return ""
    if u.startswith(_PG_PREFIX_OLD):
        u = u.replace(_PG_PREFIX_OLD, _PG_PREFIX_NEW, 1)
    return u


def _is_sqlite(uri: str) -> bool:
    return (uri or "").strip().lower().startswith("sqlite:")


def _has_hostname(uri: str) -> bool:
    try:
        p = urlparse(uri)
        return bool(p.hostname)
    except Exception:
        return False


def _maybe_force_sslmode_require(uri: str, *, is_prod: bool) -> str:
    if not is_prod or not uri or _is_sqlite(uri):
        return uri

    try:
        p = urlparse(uri)
        q = p.query or ""
        if "sslmode=" in q.lower():
            return uri
        new_q = (q + "&" if q else "") + "sslmode=require"
        return urlunparse(p._replace(query=new_q))
    except Exception:
        return uri


def _mask_db_uri(uri: str) -> str:
    """
    Avoid leaking credentials in logs/health payloads.
    Keep scheme/host/dbname if possible.
    """
    u = (uri or "").strip()
    if not u:
        return ""
    try:
        p = urlparse(u)
        host = p.hostname or ""
        dbn = (p.path or "").lstrip("/")
        scheme = p.scheme or ""
        if not scheme:
            return ""
        if host:
            if dbn:
                return f"{scheme}://{host}/{dbn}"
            return f"{scheme}://{host}"
        if _is_sqlite(u):
            return "sqlite://"
        return scheme + "://"
    except Exception:
        return "sqlite:// " if _is_sqlite(u) else ""


def _ensure_db_uri(app: Flask) -> str:
    """
    SINGLE SOURCE OF TRUTH (safe + test-proof):
    - TESTING: respect app.config['SQLALCHEMY_DATABASE_URI'] if present, else sqlite://
      and DO NOT use DATABASE_URL.
    - PROD: prefer DATABASE_URL, fallback to config SQLALCHEMY_DATABASE_URI.
    - DEV: config SQLALCHEMY_DATABASE_URI, then env SQLALCHEMY_DATABASE_URI, then DATABASE_URL, then sqlite fallback.
    """
    # ✅ TESTS: never pick up DATABASE_URL
    if _is_testing(app):
        uri = _normalize_db_url(str(app.config.get("SQLALCHEMY_DATABASE_URI") or "sqlite://").strip())
        if not uri:
            uri = "sqlite://"
        app.config["SQLALCHEMY_DATABASE_URI"] = uri
        return uri

    # 1) App config
    uri = _normalize_db_url(str(app.config.get("SQLALCHEMY_DATABASE_URI") or ""))
    if uri:
        uri = _maybe_force_sslmode_require(uri, is_prod=_is_production(app))
        app.config["SQLALCHEMY_DATABASE_URI"] = uri
        return uri

    # 2) Env explicit SQLALCHEMY_DATABASE_URI
    env_uri = _normalize_db_url(_env_str("SQLALCHEMY_DATABASE_URI", ""))
    if env_uri:
        env_uri = _maybe_force_sslmode_require(env_uri, is_prod=_is_production(app))
        app.config["SQLALCHEMY_DATABASE_URI"] = env_uri
        return env_uri

    # 3) DATABASE_URL
    db_url = _normalize_db_url(_env_str("DATABASE_URL", ""))
    if db_url:
        db_url = _maybe_force_sslmode_require(db_url, is_prod=_is_production(app))
        app.config["SQLALCHEMY_DATABASE_URI"] = db_url
        return db_url

    # 4) Local fallback (dev only)
    if not _is_production(app):
        app.config["SQLALCHEMY_DATABASE_URI"] = _LOCAL_SQLITE_FALLBACK
        return _LOCAL_SQLITE_FALLBACK

    return ""


def _db_uri(app: Flask) -> str:
    return str(app.config.get("SQLALCHEMY_DATABASE_URI") or "").strip()


def _db_tables_not_ready_error(e: Exception) -> bool:
    msg = str(e).lower()
    return (
        "no such table" in msg
        or "does not exist" in msg
        or "undefined table" in msg
        or ("relation" in msg and "does not exist" in msg)
        or "invalid catalog name" in msg
        or "database does not exist" in msg
    )


def _ensure_db_registered(app: Flask) -> None:
    """
    Ensure one SQLAlchemy instance is registered and engine options are sane.
    Prevent accidental double-initialization.
    """
    app.config.setdefault("SQLALCHEMY_TRACK_MODIFICATIONS", False)

    engine_opts = dict(app.config.get("SQLALCHEMY_ENGINE_OPTIONS") or {})
    engine_opts.setdefault("pool_pre_ping", True)
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = engine_opts

    if _is_testing(app):
        sess_opts = dict(app.config.get("SQLALCHEMY_SESSION_OPTIONS") or {})
        sess_opts.setdefault("expire_on_commit", False)
        app.config["SQLALCHEMY_SESSION_OPTIONS"] = sess_opts

    ext = app.extensions.get(_SQLA_EXT_KEY)
    if ext is db:
        return

    db.init_app(app)

    if app.extensions.get(_SQLA_EXT_KEY) is not db:
        raise RuntimeError("Multiple SQLAlchemy instances detected (db.init_app called twice?)")


def _import_required(module: str, name: str) -> Any:
    try:
        mod = importlib.import_module(module)
        obj = getattr(mod, name)
        if obj is None:
            raise AttributeError(name)
        return obj
    except Exception as e:
        raise RuntimeError(f"Failed to import required model {module}:{name}") from e


def _import_optional(module: str, name: str) -> Optional[Any]:
    try:
        mod = importlib.import_module(module)
        obj = getattr(mod, name)
        return obj
    except Exception:
        return None


def _load_models(*, force: bool = False) -> Dict[str, Any]:
    """
    Import models exactly once so SQLAlchemy metadata is populated.
    """
    global _LOADED_MODELS
    with _INIT_LOCK:
        if _LOADED_MODELS is not None and not force:
            return _LOADED_MODELS

        models: Dict[str, Any] = {
            "User": _import_required("app.models.user", "User"),
            "UserAddress": _import_required("app.models.user", "UserAddress"),
            "Category": _import_required("app.models.category", "Category"),
            "Product": _import_required("app.models.product", "Product"),
            "ProductMedia": _import_optional("app.models.product", "ProductMedia"),
            "Tag": _import_optional("app.models.product", "Tag"),
            "Order": _import_required("app.models.order", "Order"),
            "OrderItem": _import_required("app.models.order", "OrderItem"),
            "Offer": _import_optional("app.models.offer", "Offer"),
            "Media": _import_optional("app.models.media", "Media"),
            "Event": _import_optional("app.models.event", "Event"),
            "Campaign": _import_optional("app.models.campaign", "Campaign"),
            "CampaignSend": _import_optional("app.models.campaign", "CampaignSend"),
            "CommissionLedgerEntry": _import_optional("app.models.commission_ledger", "CommissionLedgerEntry"),
            "CommissionPayout": _import_optional("app.models.commission_ledger", "CommissionPayout"),
        }

        _LOADED_MODELS = {k: v for k, v in models.items() if v is not None}
        return _LOADED_MODELS


class _ModelProxy:
    """
    Lightweight proxy to use User/Category/etc without importing everything.
    Requires init_models(app) beforehand.
    """

    __slots__ = ("_name",)

    def __init__(self, name: str):
        self._name = name

    def _resolve(self) -> Any:
        loaded = _LOADED_MODELS
        if not loaded or self._name not in loaded:
            raise RuntimeError(f"Model '{self._name}' not loaded. Call init_models(app) before using model proxies.")
        return loaded[self._name]

    def __clause_element__(self):
        return self._resolve().__table__

    def __sa_inspect__(self):
        from sqlalchemy.inspection import inspect as _inspect

        return _inspect(self._resolve())

    @property
    def __mapper__(self):
        return self.__sa_inspect__().mapper

    def __getattr__(self, item: str):
        return getattr(self._resolve(), item)

    def __call__(self, *a, **kw):
        return self._resolve()(*a, **kw)

    def __repr__(self) -> str:
        return f"<ModelProxy {self._name}>"


User = _ModelProxy("User")
UserAddress = _ModelProxy("UserAddress")
Category = _ModelProxy("Category")
Product = _ModelProxy("Product")
ProductMedia = _ModelProxy("ProductMedia")
Tag = _ModelProxy("Tag")
Order = _ModelProxy("Order")
OrderItem = _ModelProxy("OrderItem")
Offer = _ModelProxy("Offer")
Media = _ModelProxy("Media")
Event = _ModelProxy("Event")
Campaign = _ModelProxy("Campaign")
CampaignSend = _ModelProxy("CampaignSend")
CommissionLedgerEntry = _ModelProxy("CommissionLedgerEntry")
CommissionPayout = _ModelProxy("CommissionPayout")


def _ping_db(app: Flask) -> None:
    """
    Smoke test: validates connection.
    Always rollback to keep session clean.
    """
    with app.app_context():
        _ensure_db_registered(app)
        try:
            db.session.execute(text("SELECT 1"))
        finally:
            db.session.rollback()


def _looks_like_email(email: str) -> bool:
    e = (email or "").strip().lower()
    if not e or len(e) > _MAX_EMAIL_LEN:
        return False
    return bool(_EMAIL_SIMPLE_RE.match(e))


@dataclass(frozen=True)
class AdminBootstrap:
    email: str
    password: str
    name: str


def _get_admin_bootstrap(app: Flask) -> Optional[AdminBootstrap]:
    """
    Admin bootstrap (optional):
    - Disabled in TESTING or when SKIP_ADMIN_BOOTSTRAP=1
    - In prod requires password >= 12
    - In dev requires password >= 8
    """
    if _is_testing(app) or _env_flag("SKIP_ADMIN_BOOTSTRAP", False):
        return None

    email = _env_str("ADMIN_EMAIL", "").lower()
    password = _env_str("ADMIN_PASSWORD", "")
    name = _env_str("ADMIN_NAME", "Admin")

    if not _looks_like_email(email):
        return None
    if _is_production(app) and len(password) < 12:
        return None
    if len(password) < 8:
        return None
    return AdminBootstrap(email=email, password=password, name=name)


def create_admin_owner_guard(app: Flask) -> Dict[str, Any]:
    """
    Ensure configured ADMIN_EMAIL exists and is marked admin/active/verified.
    Safe to call multiple times. Skips cleanly when DB/tables aren't ready.
    """
    loaded = _LOADED_MODELS or {}
    UserModel = loaded.get("User")
    if not UserModel:
        return {"ok": False, "reason": "User model not loaded"}

    bootstrap = _get_admin_bootstrap(app)
    if bootstrap is None:
        return {"skipped": True}

    with app.app_context():
        try:
            _ensure_db_registered(app)
            existing = db.session.query(UserModel).filter_by(email=bootstrap.email).first()
        except (OperationalError, ProgrammingError) as e:
            db.session.rollback()
            if _db_tables_not_ready_error(e):
                return {"skipped": True}
            return {"ok": False, "reason": "db error"}
        except SQLAlchemyError:
            db.session.rollback()
            return {"ok": False, "reason": "db error"}

        if existing:
            changed = False
            for f in ("is_admin", "is_active", "email_verified"):
                if hasattr(existing, f) and getattr(existing, f) is not True:
                    setattr(existing, f, True)
                    changed = True

            if changed:
                try:
                    db.session.commit()
                except SQLAlchemyError:
                    db.session.rollback()
                    raise
            else:
                db.session.rollback()
            return {"ok": True, "created": False}

        u = UserModel(name=bootstrap.name, email=bootstrap.email)
        if hasattr(u, "set_password"):
            u.set_password(bootstrap.password)
        for f, v in (("is_admin", True), ("is_active", True), ("email_verified", True)):
            if hasattr(u, f):
                setattr(u, f, v)

        db.session.add(u)
        try:
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()
            raise

        return {"ok": True, "created": True}


def ensure_schema_created(app: Flask) -> Dict[str, Any]:
    """
    Optional helper: creates tables for empty DB (prefer migrations in prod).
    """
    with app.app_context():
        _ensure_db_registered(app)
        _load_models(force=False)
        try:
            db.create_all()
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            return {"ok": False, "reason": "create_all failed", "error": str(e)}
        return {"ok": True}


def init_models(
    app: Flask,
    *,
    create_admin: bool = True,
    force_reload_models: bool = False,
    log_loaded_models: bool = False,
    ping_db: bool = True,
    create_schema_if_missing: bool = False,
) -> Dict[str, Any]:
    """
    Init flow:
    1) Resolve DB URI (Render/Neon compatible + tests never use DATABASE_URL)
    2) Register SQLAlchemy once
    3) Import models once to populate metadata
    4) Optional: ping DB
    5) Optional: create schema (fresh DB only)
    6) Optional: bootstrap admin ONLY when SEED=1 (and not in tests)
    """
    global _BOOTSTRAP_DONE

    with _INIT_LOCK:
        uri = _ensure_db_uri(app)
        if not uri:
            raise RuntimeError("SQLALCHEMY_DATABASE_URI missing (set DATABASE_URL in Render/Neon)")

        if _is_production(app) and _is_sqlite(uri):
            raise RuntimeError("Production DB cannot be SQLite; set DATABASE_URL to Postgres")

        if _is_production(app) and not _has_hostname(uri):
            raise RuntimeError("DATABASE_URL invalid: missing hostname")

        _ensure_db_registered(app)
        loaded = _load_models(force=force_reload_models)

        required: Set[str] = {"User", "Category", "Product", "Order", "OrderItem"}
        missing = sorted(required.difference(set(loaded)))
        if missing:
            raise RuntimeError(f"Missing core models: {', '.join(missing)}")

        # ✅ tests default: ping_db False recommended (caller should pass ping_db=False)
        if ping_db:
            _ping_db(app)

        # ✅ create schema only if explicitly enabled
        if create_schema_if_missing:
            ensure_schema_created(app)

        if log_loaded_models:
            log.info("Models loaded: %s", ", ".join(sorted(loaded)))

        # ✅ tests: expose real models in globals to avoid proxy surprises
        if _is_testing(app):
            for name, model in loaded.items():
                globals()[name] = model

        result: Dict[str, Any] = {
            "ok": True,
            "env": _app_env(app),
            "db_uri": _mask_db_uri(_db_uri(app)),  # ✅ masked
            "models": sorted(loaded),
        }

        seed = _env_flag("SEED", False)
        skip_admin = _env_flag("SKIP_ADMIN_BOOTSTRAP", False)

        # ✅ bootstrap once per process, only when SEED=1, never in tests
        if create_admin and seed and (not skip_admin) and (not _is_testing(app)) and (not _BOOTSTRAP_DONE):
            result["admin"] = create_admin_owner_guard(app)
            _BOOTSTRAP_DONE = True
        else:
            result["admin"] = {"skipped": True}

        return result


def create_admin_if_missing(app: Flask) -> Dict[str, Any]:
    return create_admin_owner_guard(app)


__all__ = (
    "db",
    "text",
    "init_models",
    "ensure_schema_created",
    "create_admin_owner_guard",
    "create_admin_if_missing",
    "User",
    "UserAddress",
    "Category",
    "Product",
    "ProductMedia",
    "Tag",
    "Order",
    "OrderItem",
    "Offer",
    "Media",
    "Event",
    "Campaign",
    "CampaignSend",
    "CommissionLedgerEntry",
    "CommissionPayout",
)
