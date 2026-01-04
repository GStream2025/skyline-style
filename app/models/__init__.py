# app/models/__init__.py
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import OperationalError

db = SQLAlchemy()
log = logging.getLogger("models")

# ==========================================================
# ENV helpers
# ==========================================================
_TRUE = {"1", "true", "yes", "y", "on"}
_FALSE = {"0", "false", "no", "n", "off"}


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
    env = (app.config.get("ENV") or os.getenv("ENV") or "").lower().strip()
    if env in {"prod", "production"}:
        return "production"
    if env in {"dev", "development"}:
        return "development"
    return "production"


def _is_production(app: Flask) -> bool:
    return _app_env(app) == "production"


def _db_uri(app: Flask) -> str:
    return (app.config.get("SQLALCHEMY_DATABASE_URI") or "").strip()


# ==========================================================
# Model cache (por proceso)
# ==========================================================
_LOADED_MODELS: Optional[Dict[str, Any]] = None


# ==========================================================
# Import helpers
# ==========================================================
def _import_required(module: str, name: str) -> Any:
    try:
        mod = __import__(module, fromlist=[name])
        return getattr(mod, name)
    except Exception:
        log.exception("❌ Required model import failed: %s.%s", module, name)
        raise


def _import_optional(module: str, name: str) -> Optional[Any]:
    try:
        mod = __import__(module, fromlist=[name])
        return getattr(mod, name)
    except Exception as e:
        log.debug("Optional model skipped: %s.%s (%s)", module, name, e)
        return None


# ==========================================================
# Load models (orden garantizado)
# ==========================================================
def _load_models(app: Flask, *, force: bool = False) -> Dict[str, Any]:
    global _LOADED_MODELS

    if _LOADED_MODELS is not None and not force:
        return _LOADED_MODELS

    models: Dict[str, Any] = {}

    # CORE (orden crítico)
    models["User"] = _import_required("app.models.user", "User")
    models["UserAddress"] = _import_required("app.models.user", "UserAddress")

    models["Category"] = _import_required("app.models.category", "Category")

    models["Product"] = _import_required("app.models.product", "Product")
    models["ProductMedia"] = _import_optional("app.models.product", "ProductMedia")
    models["Tag"] = _import_optional("app.models.product", "Tag")

    models["Order"] = _import_required("app.models.order", "Order")
    models["OrderItem"] = _import_required("app.models.order", "OrderItem")

    # OPCIONALES
    models["Offer"] = _import_optional("app.models.offer", "Offer")
    models["Media"] = _import_optional("app.models.media", "Media")
    models["Event"] = _import_optional("app.models.event", "Event")
    models["Campaign"] = _import_optional("app.models.campaign", "Campaign")
    models["CampaignSend"] = _import_optional("app.models.campaign", "CampaignSend")

    _LOADED_MODELS = {k: v for k, v in models.items() if v is not None}
    return _LOADED_MODELS


# ==========================================================
# Model proxies (safe imports)
# ==========================================================
class _ModelProxy:
    __slots__ = ("_name",)

    def __init__(self, name: str):
        self._name = name

    def _resolve(self):
        if not _LOADED_MODELS or self._name not in _LOADED_MODELS:
            raise RuntimeError(
                f"Model '{self._name}' no cargado. "
                "Llamá init_models(app) dentro de create_app()."
            )
        return _LOADED_MODELS[self._name]

    def __getattr__(self, item):
        return getattr(self._resolve(), item)

    def __call__(self, *a, **kw):
        return self._resolve()(*a, **kw)


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
# Init principal (NO crea tablas)
# ==========================================================
def init_models(
    app: Flask,
    *,
    create_admin: bool = True,
    force_reload_models: bool = False,
    log_loaded_models: bool = False,
) -> Dict[str, Any]:

    if "sqlalchemy" not in app.extensions:
        db.init_app(app)

    loaded = _load_models(app, force=force_reload_models)

    required = {"User", "Category", "Product", "Order", "OrderItem"}
    missing = required - set(loaded.keys())
    if missing:
        raise RuntimeError(f"❌ Faltan modelos core: {', '.join(sorted(missing))}")

    if not _db_uri(app):
        raise RuntimeError("❌ SQLALCHEMY_DATABASE_URI no configurado")

    if log_loaded_models:
        log.info("📦 Modelos cargados: %s", ", ".join(sorted(loaded.keys())))

    result = {
        "ok": True,
        "env": _app_env(app),
        "models": sorted(loaded.keys()),
    }

    # ✅ ADMIN: respetar SKIP_ADMIN_BOOTSTRAP SIEMPRE
    skip_admin = _env_flag("SKIP_ADMIN_BOOTSTRAP", False)
    if create_admin and not skip_admin:
        result["admin"] = create_admin_if_missing(app)
    else:
        result["admin"] = {"skipped": True, "reason": "admin bootstrap disabled"}

    return result


# ==========================================================
# Admin bootstrap (100% blindado)
# ==========================================================
def create_admin_if_missing(app: Flask) -> Dict[str, Any]:
    loaded = _LOADED_MODELS or {}
    UserModel = loaded.get("User")
    if not UserModel:
        return {"ok": False, "msg": "User model no cargado"}

    email = (os.getenv("ADMIN_EMAIL") or "").lower().strip()
    password = (os.getenv("ADMIN_PASSWORD") or "").strip()
    name = (os.getenv("ADMIN_NAME") or "Admin").strip()

    if not email or "@" not in email:
        return {"ok": False, "msg": "ADMIN_EMAIL inválido"}

    if _is_production(app) and len(password) < 10:
        return {"ok": False, "msg": "ADMIN_PASSWORD inseguro en producción"}

    # ✅ SKIP explícito
    if _env_flag("SKIP_ADMIN_BOOTSTRAP", False):
        return {"skipped": True, "reason": "SKIP_ADMIN_BOOTSTRAP=1"}

    with app.app_context():
        try:
            existing = db.session.query(UserModel).filter_by(email=email).first()
        except OperationalError as e:
            msg = str(e).lower()
            # ✅ tablas aún no creadas → NO romper nunca
            if "no such table" in msg or "does not exist" in msg:
                log.warning("⚠️ Admin bootstrap omitido: tablas aún no creadas")
                return {"skipped": True, "reason": "tables not ready"}
            raise

        if existing:
            existing.is_admin = True
            existing.is_active = True
            existing.email_verified = True
            db.session.commit()
            return {"ok": True, "created": False, "email": email}

        u = UserModel(name=name, email=email)
        u.set_password(password)
        u.is_admin = True
        u.is_active = True
        u.email_verified = True

        db.session.add(u)
        db.session.commit()
        return {"ok": True, "created": True, "email": email}


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
    "CampaignSend",
]
