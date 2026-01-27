from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, Optional, Set

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import OperationalError, ProgrammingError

log = logging.getLogger("models")

db = SQLAlchemy()

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off"}

_INIT_LOCK = threading.RLock()
_LOADED_MODELS: Optional[Dict[str, Any]] = None
_MODELS_INIT_ONCE_OK = False


try:
    from sqlalchemy import text as _sa_text

    def text(sql: str):
        return _sa_text(sql)

except Exception:
    def text(sql: str):
        raise RuntimeError("sqlalchemy.text no disponible")


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


def _env_str(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


def _app_env(app: Flask) -> str:
    env = (
        (app.config.get("ENV") or "")
        or (app.config.get("ENVIRONMENT") or "")
        or (os.getenv("ENV") or "")
        or (os.getenv("FLASK_ENV") or "")
    ).lower().strip()

    if env in {"prod", "production"}:
        return "production"
    if env in {"dev", "development"}:
        return "development"
    if bool(app.config.get("DEBUG")):
        return "development"
    return "production"


def _is_production(app: Flask) -> bool:
    return _app_env(app) == "production"


def _normalize_db_url(raw: str) -> str:
    u = (raw or "").strip()
    if u.startswith("postgres://"):
        u = u.replace("postgres://", "postgresql://", 1)
    return u


def _ensure_db_uri(app: Flask) -> str:
    uri = _normalize_db_url(str(app.config.get("SQLALCHEMY_DATABASE_URI") or ""))
    if uri:
        app.config["SQLALCHEMY_DATABASE_URI"] = uri
        return uri

    env_uri = _normalize_db_url(os.getenv("SQLALCHEMY_DATABASE_URI") or "")
    if env_uri:
        app.config["SQLALCHEMY_DATABASE_URI"] = env_uri
        return env_uri

    db_url = _normalize_db_url(os.getenv("DATABASE_URL") or "")
    if db_url:
        app.config["SQLALCHEMY_DATABASE_URI"] = db_url
        return db_url

    if not _is_production(app):
        fallback = "sqlite:///skyline_local.db"
        app.config["SQLALCHEMY_DATABASE_URI"] = fallback
        return fallback

    return ""


def _db_uri(app: Flask) -> str:
    return (app.config.get("SQLALCHEMY_DATABASE_URI") or "").strip()


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
    app.config.setdefault("SQLALCHEMY_TRACK_MODIFICATIONS", False)

    if app.config.get("TESTING"):
        app.config.setdefault("SQLALCHEMY_SESSION_OPTIONS", {"expire_on_commit": False})
        app.config.setdefault("SQLALCHEMY_ENGINE_OPTIONS", {"pool_pre_ping": True})

    ext = app.extensions.get("sqlalchemy")
    if ext is db:
        return

    db.init_app(app)

    if app.extensions.get("sqlalchemy") is not db:
        raise RuntimeError("Multiple SQLAlchemy instances detected")


def _import_required(module: str, name: str) -> Any:
    mod = __import__(module, fromlist=[name])
    return getattr(mod, name)


def _import_optional(module: str, name: str) -> Optional[Any]:
    try:
        mod = __import__(module, fromlist=[name])
        return getattr(mod, name)
    except Exception:
        return None


def _load_models(*, force: bool = False) -> Dict[str, Any]:
    global _LOADED_MODELS
    with _INIT_LOCK:
        if _LOADED_MODELS is not None and not force:
            return _LOADED_MODELS

        models = {
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
    __slots__ = ("_name",)

    def __init__(self, name: str):
        self._name = name

    def _resolve(self):
        if not _LOADED_MODELS or self._name not in _LOADED_MODELS:
            raise RuntimeError(f"Model '{self._name}' not loaded")
        return _LOADED_MODELS[self._name]

    def __clause_element__(self):
        return self._resolve().__table__

    def __sa_inspect__(self):
        from sqlalchemy.inspection import inspect
        return inspect(self._resolve())

    @property
    def __mapper__(self):
        return self.__sa_inspect__().mapper

    def __getattr__(self, item):
        return getattr(self._resolve(), item)

    def __call__(self, *a, **kw):
        return self._resolve()(*a, **kw)

    def __repr__(self):
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
    with app.app_context():
        _ensure_db_registered(app)
        db.session.execute(text("SELECT 1"))
        db.session.rollback()


def _looks_like_email(email: str) -> bool:
    e = (email or "").strip().lower()
    if not e or "@" not in e:
        return False
    local, _, domain = e.partition("@")
    return bool(local and domain and "." in domain and " " not in e and ".." not in e)


def create_admin_owner_guard(app: Flask) -> Dict[str, Any]:
    loaded = _LOADED_MODELS or {}
    UserModel = loaded.get("User")
    if not UserModel:
        return {"ok": False}

    if _env_flag("SKIP_ADMIN_BOOTSTRAP", False) or app.config.get("TESTING"):
        return {"skipped": True}

    email = _env_str("ADMIN_EMAIL").lower()
    password = _env_str("ADMIN_PASSWORD")
    name = _env_str("ADMIN_NAME", "Admin")

    if not _looks_like_email(email):
        return {"ok": False}

    if _is_production(app) and len(password) < 12:
        return {"ok": False}

    with app.app_context():
        try:
            _ensure_db_registered(app)
            existing = db.session.query(UserModel).filter_by(email=email).first()
        except (OperationalError, ProgrammingError) as e:
            if _db_tables_not_ready_error(e):
                return {"skipped": True}
            return {"ok": False}

        if existing:
            for f in ("is_admin", "is_active", "email_verified"):
                if hasattr(existing, f):
                    setattr(existing, f, True)
            db.session.commit()
            return {"ok": True, "created": False}

        if len(password) < 8:
            return {"ok": False}

        u = UserModel(name=name, email=email)
        if hasattr(u, "set_password"):
            u.set_password(password)
        u.is_admin = True
        u.is_active = True
        u.email_verified = True
        db.session.add(u)
        db.session.commit()
        return {"ok": True, "created": True}


def init_models(
    app: Flask,
    *,
    create_admin: bool = True,
    force_reload_models: bool = False,
    log_loaded_models: bool = False,
    ping_db: bool = True,
) -> Dict[str, Any]:
    global _MODELS_INIT_ONCE_OK

    with _INIT_LOCK:
        uri = _ensure_db_uri(app)
        if not uri:
            raise RuntimeError("SQLALCHEMY_DATABASE_URI missing")

        _ensure_db_registered(app)
        loaded = _load_models(force=force_reload_models)

        required: Set[str] = {"User", "Category", "Product", "Order", "OrderItem"}
        if not required.issubset(set(loaded)):
            raise RuntimeError("Missing core models")

        if ping_db:
            _ping_db(app)

        if log_loaded_models:
            log.info("Models: %s", ", ".join(sorted(loaded)))

        if app.config.get("TESTING"):
            for name, model in loaded.items():
                globals()[name] = model

        result: Dict[str, Any] = {
            "ok": True,
            "env": _app_env(app),
            "db_uri": _db_uri(app),
            "models": sorted(loaded),
        }

        seed = _env_flag("SEED", False)
        skip_admin = _env_flag("SKIP_ADMIN_BOOTSTRAP", False)

        if create_admin and seed and not skip_admin and not _MODELS_INIT_ONCE_OK:
            result["admin"] = create_admin_owner_guard(app)
            _MODELS_INIT_ONCE_OK = True
        else:
            result["admin"] = {"skipped": True}

        return result


def create_admin_if_missing(app: Flask) -> Dict[str, Any]:
    return create_admin_owner_guard(app)


__all__ = [
    "db",
    "text",
    "init_models",
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
]
