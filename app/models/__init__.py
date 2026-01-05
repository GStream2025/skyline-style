# app/models/__init__.py — Skyline Store (PRO / FINAL / BLINDADO)
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional, Set

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import OperationalError, ProgrammingError

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
    s = str(v).strip().lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return default


def _env_str(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


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


def _db_tables_not_ready_error(e: Exception) -> bool:
    msg = str(e).lower()
    return (
        "no such table" in msg
        or "does not exist" in msg
        or "undefined table" in msg
        or "relation" in msg and "does not exist" in msg
    )


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
# Init principal (NO crea tablas por defecto)
# ==========================================================
def init_models(
    app: Flask,
    *,
    create_admin: bool = True,
    force_reload_models: bool = False,
    log_loaded_models: bool = False,
) -> Dict[str, Any]:
    """
    ✅ init_models(app) debe llamarse en create_app() SIEMPRE.

    - Inicializa SQLAlchemy si hace falta
    - Carga modelos (core y opcionales)
    - Valida DB URI
    - (Opcional) bootstrap admin SI SEED=1 y no SKIP_ADMIN_BOOTSTRAP=1
    """

    if "sqlalchemy" not in app.extensions:
        db.init_app(app)

    loaded = _load_models(app, force=force_reload_models)

    required: Set[str] = {"User", "Category", "Product", "Order", "OrderItem"}
    missing = required - set(loaded.keys())
    if missing:
        raise RuntimeError(f"❌ Faltan modelos core: {', '.join(sorted(missing))}")

    if not _db_uri(app):
        raise RuntimeError("❌ SQLALCHEMY_DATABASE_URI no configurado")

    if log_loaded_models:
        log.info("📦 Modelos cargados: %s", ", ".join(sorted(loaded.keys())))

    result: Dict[str, Any] = {
        "ok": True,
        "env": _app_env(app),
        "models": sorted(loaded.keys()),
    }

    # ✅ ADMIN bootstrap: SOLO si SEED=1 (por defecto local) y no SKIP_ADMIN_BOOTSTRAP
    # Esto NO “recrea” el admin si ya existe: solo lo asegura como dueño.
    seed = _env_flag("SEED", False)
    skip_admin = _env_flag("SKIP_ADMIN_BOOTSTRAP", False)

    if create_admin and seed and not skip_admin:
        result["admin"] = create_admin_owner_guard(app)
    else:
        result["admin"] = {"skipped": True, "reason": "SEED=0 o SKIP_ADMIN_BOOTSTRAP=1"}

    return result


# ==========================================================
# Admin owner guard (NO rompe nunca)
# - Si existe el email -> lo refuerza como admin activo y verificado
# - Si NO existe -> lo crea SOLO si el DB está listo
# ==========================================================
def create_admin_owner_guard(app: Flask) -> Dict[str, Any]:
    loaded = _LOADED_MODELS or {}
    UserModel = loaded.get("User")
    if not UserModel:
        return {"ok": False, "msg": "User model no cargado"}

    # Datos del dueño (TU acceso permanente)
    email = _env_str("ADMIN_EMAIL", "").lower()
    password = _env_str("ADMIN_PASSWORD", "")
    name = _env_str("ADMIN_NAME", "Admin") or "Admin"

    if not email or "@" not in email:
        return {"ok": False, "msg": "ADMIN_EMAIL inválido"}

    # Seguridad básica en PROD (no bloquea en local)
    if _is_production(app) and len(password) < 12:
        return {"ok": False, "msg": "ADMIN_PASSWORD inseguro en producción (mín 12)"}

    if _env_flag("SKIP_ADMIN_BOOTSTRAP", False):
        return {"skipped": True, "reason": "SKIP_ADMIN_BOOTSTRAP=1"}

    with app.app_context():
        try:
            existing = db.session.query(UserModel).filter_by(email=email).first()
        except (OperationalError, ProgrammingError) as e:
            if _db_tables_not_ready_error(e):
                log.warning("⚠️ Admin bootstrap omitido: tablas aún no creadas/migradas")
                return {"skipped": True, "reason": "tables not ready"}
            log.exception("❌ Error DB consultando admin")
            return {"ok": False, "msg": "db error querying admin"}

        # ✅ Si ya existe: NO lo recrea. Solo lo asegura como dueño.
        if existing:
            changed = False

            for attr, value in [
                ("is_admin", True),
                ("is_active", True),
                ("email_verified", True),
            ]:
                if hasattr(existing, attr):
                    try:
                        if bool(getattr(existing, attr)) != bool(value):
                            setattr(existing, attr, value)
                            changed = True
                    except Exception:
                        pass

            if changed:
                try:
                    db.session.commit()
                except Exception:
                    db.session.rollback()
                    return {"ok": False, "msg": "db commit failed (existing admin)"}

            return {"ok": True, "created": False, "email": email}

        # ✅ Si NO existe: lo crea (solo si password válido)
        if not password or len(password) < 8:
            return {"ok": False, "msg": "ADMIN_PASSWORD inválido (mín 8) para crear admin"}

        try:
            u = UserModel(name=name, email=email)
            u.set_password(password)

            if hasattr(u, "is_admin"):
                u.is_admin = True
            if hasattr(u, "is_active"):
                u.is_active = True
            if hasattr(u, "email_verified"):
                u.email_verified = True

            db.session.add(u)
            db.session.commit()
            return {"ok": True, "created": True, "email": email}
        except Exception:
            db.session.rollback()
            log.exception("❌ Error creando admin owner")
            return {"ok": False, "msg": "failed to create admin"}


__all__ = [
    "db",
    "init_models",
    "create_admin_owner_guard",
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
