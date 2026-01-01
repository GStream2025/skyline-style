# app/models/__init__.py
from __future__ import annotations

import os
import logging
from typing import Any, Dict, Optional

from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
log = logging.getLogger("models")

# ==========================================================
# Skyline Store — Models HUB ULTRA PRO (FINAL)
# - 1 solo db global (este)
# - imports seguros (no rompe si falta un modelo)
# - init_models(app): init db + carga modelos + create_all SOLO en dev/local si se habilita
# - create_admin_if_missing(app): crea admin desde ENV (blindado)
# - exports: from app.models import Product, Category, User...
# ==========================================================

_TRUE = {"1", "true", "yes", "y", "on"}
_FALSE = {"0", "false", "no", "n", "off"}

# ---------- cache de modelos ----------
_LOADED_CACHE: Optional[Dict[str, Any]] = None


# ---------- import seguro ----------
def _try_import(module: str, name: str):
    try:
        mod = __import__(module, fromlist=[name])
        return getattr(mod, name)
    except Exception as e:
        # debug-only (no spamea prod)
        log.debug("Model import failed: %s.%s (%s)", module, name, e)
        return None


def _load_models(*, force: bool = False) -> Dict[str, Any]:
    """
    Carga modelos con import seguro.
    Usa cache por proceso para performance.
    """
    global _LOADED_CACHE
    if _LOADED_CACHE is not None and not force:
        return _LOADED_CACHE

    models: Dict[str, Any] = {}

    # Core
    models["User"] = _try_import("app.models.user", "User")
    models["UserAddress"] = _try_import("app.models.user", "UserAddress")

    models["Category"] = _try_import("app.models.category", "Category")

    models["Product"] = _try_import("app.models.product", "Product")
    models["ProductMedia"] = _try_import("app.models.product", "ProductMedia")
    models["Tag"] = _try_import("app.models.product", "Tag")

    models["Order"] = _try_import("app.models.order", "Order")
    models["OrderItem"] = _try_import("app.models.order", "OrderItem")

    # Opcionales
    models["Offer"] = _try_import("app.models.offer", "Offer")
    models["Media"] = _try_import("app.models.media", "Media")
    models["Event"] = _try_import("app.models.event", "Event")
    models["Campaign"] = _try_import("app.models.campaign", "Campaign")
    models["CampaignSend"] = _try_import("app.models.campaign", "CampaignSend")

    _LOADED_CACHE = {k: v for k, v in models.items() if v is not None}
    return _LOADED_CACHE


# ---------- helpers ENV ----------
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
    # fallback: Flask 2+ puede usar app.debug
    if app.debug:
        return "development"
    return env or "production"


def _is_production(app: Flask) -> bool:
    return _app_env(app) == "production"


def _db_is_initialized(app: Flask) -> bool:
    # Si db.init_app(app) no corrió, app.extensions no tendrá sqlalchemy
    return "sqlalchemy" in getattr(app, "extensions", {})


def _db_uri(app: Flask) -> str:
    return (app.config.get("SQLALCHEMY_DATABASE_URI") or "").strip()


# ---------- init principal ----------
def init_models(
    app: Flask,
    *,
    create_admin: bool = True,
    auto_create_tables: Optional[bool] = None,
    force_reload_models: bool = False,
    log_loaded_models: bool = False,
) -> Dict[str, Any]:
    """
    Inicializa db + registra modelos + crea tablas (solo dev/local) + crea admin si falta.

    auto_create_tables:
      - None  -> decide por ENV:
                dev/local: True (default, si AUTO_CREATE_TABLES no lo desactiva)
                prod: False (default)
      - True  -> fuerza create_all()
      - False -> nunca create_all()
    """
    warnings: list[str] = []

    # Evita doble init (idempotente)
    if not _db_is_initialized(app):
        db.init_app(app)

    # 🔥 Importante: cargar modelos DESPUÉS de init_app para evitar casos raros
    loaded = _load_models(force=force_reload_models)

    env = _app_env(app)
    uri = _db_uri(app)

    if not uri:
        warnings.append("SQLALCHEMY_DATABASE_URI vacío. Revisá DATABASE_URL/SQLite config.")

    # Decide create_all (SUPER seguro)
    if auto_create_tables is None:
        auto_create_tables = (not _is_production(app)) and _env_flag("AUTO_CREATE_TABLES", True)

    if auto_create_tables:
        if uri:
            with app.app_context():
                db.create_all()
                log.info("✅ db.create_all() OK (%s)", env)
        else:
            warnings.append("create_all() omitido porque no hay DB URI.")
            log.warning("⚠️ create_all() omitido: no hay SQLALCHEMY_DATABASE_URI.")
    else:
        log.debug("db.create_all() skipped (auto_create_tables=%s env=%s)", auto_create_tables, env)

    if log_loaded_models:
        log.info("📦 Modelos cargados: %s", ", ".join(sorted(list(loaded.keys()))))

    out: Dict[str, Any] = {
        "ok": True,
        "env": env,
        "db_uri": uri,
        "models": sorted(list(loaded.keys())),
        "auto_create_tables": bool(auto_create_tables),
        "warnings": warnings,
    }

    if create_admin:
        out["admin"] = create_admin_if_missing(app)

    return out


# ---------- admin bootstrap ----------
def create_admin_if_missing(app: Flask) -> Dict[str, Any]:
    """
    Crea admin REAL si no existe.
    Usa User.set_password() (tu sistema) y fallback seguro si no existe.

    Blindaje PRO:
    - En producción, si ADMIN_PASSWORD es el default => NO crea admin.
    """
    if not _db_is_initialized(app):
        return {"ok": False, "msg": "db no inicializado. Llamá init_models(app) antes."}

    if not _db_uri(app):
        return {"ok": False, "msg": "No hay SQLALCHEMY_DATABASE_URI configurado."}

    loaded = _load_models()
    User = loaded.get("User")

    if User is None:
        return {"ok": False, "msg": "User model no encontrado (app/models/user.py)"}

    admin_email = (os.getenv("ADMIN_EMAIL") or "admin@skyline.store").strip().lower()
    admin_password = (os.getenv("ADMIN_PASSWORD") or "ChangeMe_123!").strip()
    admin_name = (os.getenv("ADMIN_NAME") or "Skyline Admin").strip()

    if not admin_email or "@" not in admin_email:
        return {"ok": False, "msg": "ADMIN_EMAIL inválido"}
    if not admin_password or len(admin_password) < 8:
        return {"ok": False, "msg": "ADMIN_PASSWORD mínimo 8 caracteres"}

    # Blindaje real: jamás crear admin con password default en producción
    if _is_production(app) and admin_password == "ChangeMe_123!":
        return {
            "ok": False,
            "msg": "En producción no se crea admin con password por defecto. Seteá ADMIN_PASSWORD seguro en el deploy.",
        }

    with app.app_context():
        existing = db.session.query(User).filter_by(email=admin_email).first()
        if existing:
            if hasattr(existing, "is_admin"):
                existing.is_admin = True
            if hasattr(existing, "is_active"):
                existing.is_active = True
            # opcional: marcar verificado si existe el campo
            if hasattr(existing, "email_verified"):
                existing.email_verified = True
            db.session.commit()
            return {"ok": True, "created": False, "email": admin_email}

        u = User(name=admin_name, email=admin_email)

        # Preferencia: set_password (tu hashing real)
        if hasattr(u, "set_password"):
            u.set_password(admin_password)  # type: ignore[attr-defined]
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


# ==========================================================
# EXPORTS (no rompen aunque el modelo falte)
# ==========================================================
# Nota: NO hacemos _load_models() acá arriba para no disparar imports antes de init_models(app).
# Igual, para compat: si alguien importa "User" antes, lo intentamos cargar “suave”.
_loaded = _load_models()

User = _loaded.get("User")
UserAddress = _loaded.get("UserAddress")
Category = _loaded.get("Category")
Product = _loaded.get("Product")
ProductMedia = _loaded.get("ProductMedia")
Tag = _loaded.get("Tag")
Order = _loaded.get("Order")
OrderItem = _loaded.get("OrderItem")
Offer = _loaded.get("Offer")
Media = _loaded.get("Media")
Event = _loaded.get("Event")
Campaign = _loaded.get("Campaign")
CampaignSend = _loaded.get("CampaignSend")

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
