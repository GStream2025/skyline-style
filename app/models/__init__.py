# app/models/__init__.py
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
log = logging.getLogger("models")

_TRUE = {"1", "true", "yes", "y", "on"}
_FALSE = {"0", "false", "no", "n", "off"}

# cache por proceso
_LOADED_CACHE: Optional[Dict[str, Any]] = None


# ==========================================================
# Helpers ENV
# ==========================================================
def _env_flag(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    s = v.strip().lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return default


def _app_env(app: Flask) -> str:
    env = (app.config.get("ENV") or os.getenv("ENV") or os.getenv("FLASK_ENV") or "").strip().lower()
    if env in {"prod", "production"}:
        return "production"
    if env in {"dev", "development"}:
        return "development"
    if app.debug:
        return "development"
    return env or "production"


def _is_production(app: Flask) -> bool:
    return _app_env(app) == "production"


def _db_is_initialized(app: Flask) -> bool:
    return "sqlalchemy" in getattr(app, "extensions", {})


def _db_uri(app: Flask) -> str:
    return (app.config.get("SQLALCHEMY_DATABASE_URI") or "").strip()


# ==========================================================
# Import helpers
# ==========================================================
def _import_required(module: str, name: str, *, debug: bool) -> Any:
    """
    Import obligatorio:
    - Si falla, levanta error (en prod y dev)
    - En debug loguea stacktrace, en prod log corto
    """
    try:
        mod = __import__(module, fromlist=[name])
        obj = getattr(mod, name)
        return obj
    except Exception as e:
        if debug:
            log.exception("❌ Required model import failed: %s.%s", module, name)
        else:
            log.error("❌ Required model import failed: %s.%s (%s)", module, name, e)
        raise


def _try_import_optional(module: str, name: str, *, debug: bool) -> Any:
    """
    Import opcional:
    - Si falla NO rompe el proceso
    - En debug muestra exception, en prod solo debug
    """
    try:
        mod = __import__(module, fromlist=[name])
        return getattr(mod, name)
    except Exception as e:
        if debug:
            log.debug("Optional model import failed: %s.%s (%s)", module, name, e, exc_info=True)
        else:
            log.debug("Optional model import failed: %s.%s (%s)", module, name, e)
        return None


# ==========================================================
# Loader con ORDEN GARANTIZADO y CORES OBLIGATORIOS
# ==========================================================
def _load_models(app: Flask, *, force: bool = False) -> Dict[str, Any]:
    """
    Carga modelos SOLO cuando init_models(app) lo pide.
    Cache por proceso para performance.

    ✔️ Orden fijo
    ✔️ Core models obligatorios (si faltan → mejor fallar claro)
    ✔️ Opcionales no rompen
    """
    global _LOADED_CACHE
    if _LOADED_CACHE is not None and not force:
        return _LOADED_CACHE

    debug = bool(app.debug) or _app_env(app) == "development"

    models: Dict[str, Any] = {}

    # -------------------------
    # CORE (OBLIGATORIOS)
    # -------------------------
    # 1) User siempre primero (evita: relationship("User") not found)
    models["User"] = _import_required("app.models.user", "User", debug=debug)
    models["UserAddress"] = _import_required("app.models.user", "UserAddress", debug=debug)

    # 2) Catálogo
    models["Category"] = _import_required("app.models.category", "Category", debug=debug)

    models["Product"] = _import_required("app.models.product", "Product", debug=debug)
    models["ProductMedia"] = _try_import_optional("app.models.product", "ProductMedia", debug=debug)
    models["Tag"] = _try_import_optional("app.models.product", "Tag", debug=debug)

    # 3) Orders al final (dependen de User/Product)
    models["Order"] = _import_required("app.models.order", "Order", debug=debug)
    models["OrderItem"] = _import_required("app.models.order", "OrderItem", debug=debug)

    # -------------------------
    # OPCIONALES
    # -------------------------
    models["Offer"] = _try_import_optional("app.models.offer", "Offer", debug=debug)
    models["Media"] = _try_import_optional("app.models.media", "Media", debug=debug)
    models["Event"] = _try_import_optional("app.models.event", "Event", debug=debug)
    models["Campaign"] = _try_import_optional("app.models.campaign", "Campaign", debug=debug)
    models["CampaignSend"] = _try_import_optional("app.models.campaign", "CampaignSend", debug=debug)

    # Filtrar None
    _LOADED_CACHE = {k: v for k, v in models.items() if v is not None}
    return _LOADED_CACHE


# ==========================================================
# Proxies (EXPORTS sin romper import-time)
# ==========================================================
class _ModelProxy:
    """
    Proxy que permite: from app.models import User
    sin forzar imports antes de init_models(app).
    """
    __slots__ = ("_name",)

    def __init__(self, name: str):
        self._name = name

    def _resolve(self):
        loaded = _LOADED_CACHE or {}
        m = loaded.get(self._name)
        if m is None:
            raise RuntimeError(
                f"Model '{self._name}' no está cargado. "
                "Llamá init_models(app) dentro de create_app() antes de usar modelos."
            )
        return m

    def __getattr__(self, item: str):
        return getattr(self._resolve(), item)

    def __call__(self, *args, **kwargs):
        return self._resolve()(*args, **kwargs)

    def __repr__(self) -> str:
        return f"<ModelProxy {self._name} loaded={self._name in (_LOADED_CACHE or {})}>"


# Exports seguros
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


# ==========================================================
# Init principal
# ==========================================================
def init_models(
    app: Flask,
    *,
    create_admin: bool = True,
    auto_create_tables: Optional[bool] = None,
    force_reload_models: bool = False,
    log_loaded_models: bool = False,
) -> Dict[str, Any]:
    warnings: list[str] = []

    # init db una sola vez
    if not _db_is_initialized(app):
        db.init_app(app)

    env = _app_env(app)
    uri = _db_uri(app)
    debug = bool(app.debug) or env == "development"

    # cargar modelos (ordena User antes que Order)
    loaded = _load_models(app, force=force_reload_models)

    # sanity check (core)
    required = ["User", "Category", "Product", "Order", "OrderItem"]
    missing = [m for m in required if m not in loaded]
    if missing:
        msg = f"Faltan modelos core: {', '.join(missing)}"
        # en prod no seguimos: mejor fallar rápido que romper routes
        if _is_production(app):
            raise RuntimeError(msg)
        warnings.append(msg)

    if not uri:
        warnings.append("SQLALCHEMY_DATABASE_URI vacío. Revisá DATABASE_URL/SQLite config.")

    # create_all solo en dev/local por defecto
    if auto_create_tables is None:
        auto_create_tables = (not _is_production(app)) and _env_flag("AUTO_CREATE_TABLES", True)

    if auto_create_tables and uri:
        with app.app_context():
            db.create_all()
            log.info("✅ db.create_all() OK (%s)", env)

    if log_loaded_models:
        log.info("📦 Modelos cargados: %s", ", ".join(sorted(list(loaded.keys()))))

    out: Dict[str, Any] = {
        "ok": True,
        "env": env,
        "db_uri": uri,
        "models": sorted(list(loaded.keys())),
        "auto_create_tables": bool(auto_create_tables),
        "warnings": warnings,
        "debug": debug,
    }

    if create_admin:
        out["admin"] = create_admin_if_missing(app)

    return out


# ==========================================================
# Admin bootstrap (blindado)
# ==========================================================
def create_admin_if_missing(app: Flask) -> Dict[str, Any]:
    if not _db_is_initialized(app):
        return {"ok": False, "msg": "db no inicializado. Llamá init_models(app) antes."}

    if not _db_uri(app):
        return {"ok": False, "msg": "No hay SQLALCHEMY_DATABASE_URI configurado."}

    loaded = _LOADED_CACHE or {}
    UserModel = loaded.get("User")
    if UserModel is None:
        return {"ok": False, "msg": "User model no encontrado (app/models/user.py)"}

    admin_email = (os.getenv("ADMIN_EMAIL") or "admin@skyline.store").strip().lower()
    admin_password = (os.getenv("ADMIN_PASSWORD") or "ChangeMe_123!").strip()
    admin_name = (os.getenv("ADMIN_NAME") or "Skyline Admin").strip()

    if not admin_email or "@" not in admin_email:
        return {"ok": False, "msg": "ADMIN_EMAIL inválido"}
    if not admin_password or len(admin_password) < 8:
        return {"ok": False, "msg": "ADMIN_PASSWORD mínimo 8 caracteres"}

    # En prod: jamás crear admin con pass default
    if _is_production(app) and admin_password == "ChangeMe_123!":
        return {"ok": False, "msg": "Seteá ADMIN_PASSWORD seguro en producción (no default)."}

    with app.app_context():
        existing = db.session.query(UserModel).filter_by(email=admin_email).first()
        if existing:
            if hasattr(existing, "is_admin"):
                existing.is_admin = True
            if hasattr(existing, "is_active"):
                existing.is_active = True
            if hasattr(existing, "email_verified"):
                existing.email_verified = True
            db.session.commit()
            return {"ok": True, "created": False, "email": admin_email}

        u = UserModel(name=admin_name, email=admin_email)

        if hasattr(u, "set_password"):
            u.set_password(admin_password)
        elif hasattr(u, "password_hash"):
            from werkzeug.security import generate_password_hash
            u.password_hash = generate_password_hash(admin_password)
        else:
            return {"ok": False, "msg": "User no tiene set_password() ni password_hash"}

        if hasattr(u, "is_admin"):
            u.is_admin = True
        if hasattr(u, "is_active"):
            u.is_active = True
        if hasattr(u, "email_verified"):
            u.email_verified = True

        db.session.add(u)
        db.session.commit()
        return {"ok": True, "created": True, "email": admin_email}


__all__ = [
    "db",
    "init_models",
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
    "Campaign",
    "CampaignSend",
]
