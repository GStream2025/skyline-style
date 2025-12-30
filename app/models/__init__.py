# app/models/__init__.py
from __future__ import annotations

import os
from typing import Any, Optional, Dict

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

# ==========================================================
# Skyline Store — Models HUB
# - 1 solo db global
# - imports seguros (NO rompe si falta un modelo)
# - init_models(app) + create_admin_if_missing(app)
# - exports reales para: from app.models import Product, Category, User, ...
# ==========================================================

db = SQLAlchemy()


# ---------- import seguro ----------
def _try_import(module: str, name: str):
    try:
        mod = __import__(module, fromlist=[name])
        return getattr(mod, name)
    except Exception:
        return None


# ---------- carga de modelos ----------
def _load_models() -> Dict[str, Any]:
    models: Dict[str, Any] = {}

    models["User"] = _try_import("app.models.user", "User")
    models["Category"] = _try_import("app.models.category", "Category")
    models["Product"] = _try_import("app.models.product", "Product")
    models["Order"] = _try_import("app.models.order", "Order")
    models["Offer"] = _try_import("app.models.offer", "Offer")
    models["Media"] = _try_import("app.models.media", "Media")
    models["Event"] = _try_import("app.models.event", "Event")
    models["Campaign"] = _try_import("app.models.campaign", "Campaign")

    # elimina None
    return {k: v for k, v in models.items() if v is not None}


# ---------- init de DB + tablas ----------
def init_models(app: Flask, create_admin: bool = True, auto_create_tables: bool = True) -> Dict[str, Any]:
    """
    Inicializa db + registra modelos + crea tablas (solo local/dev) + crea admin si falta.
    """
    db.init_app(app)

    loaded = _load_models()

    out: Dict[str, Any] = {"ok": True, "models": sorted(list(loaded.keys()))}

    if auto_create_tables:
        with app.app_context():
            db.create_all()

    if create_admin:
        out["admin"] = create_admin_if_missing(app)

    return out


def create_admin_if_missing(app: Flask) -> Dict[str, Any]:
    """
    Crea admin REAL si no existe.
    Requiere que User tenga: email, name, password_hash (o set_password()).
    """
    loaded = _load_models()
    User = loaded.get("User")

    if User is None:
        return {"ok": False, "msg": "User model no encontrado (app/models/user.py)"}

    admin_email = (os.getenv("ADMIN_EMAIL") or "admin@skyline.store").strip().lower()
    admin_password = (os.getenv("ADMIN_PASSWORD") or "ChangeMe_123!").strip()
    admin_name = (os.getenv("ADMIN_NAME") or "Skyline Admin").strip()
    admin_role = (os.getenv("ADMIN_ROLE") or "admin").strip().lower()

    if not admin_email or "@" not in admin_email:
        return {"ok": False, "msg": "ADMIN_EMAIL inválido"}
    if not admin_password or len(admin_password) < 8:
        return {"ok": False, "msg": "ADMIN_PASSWORD mínimo 8 caracteres"}

    with app.app_context():
        # OJO: si la tabla users no existe todavía, create_all() arriba ya la crea.
        existing = db.session.query(User).filter_by(email=admin_email).first()
        if existing:
            # asegura flags/rol si existen
            for attr, val in (("role", admin_role), ("is_admin", True), ("is_active", True)):
                if hasattr(existing, attr):
                    try:
                        setattr(existing, attr, val)
                    except Exception:
                        pass
            db.session.commit()
            return {"ok": True, "created": False, "email": admin_email}

        u = User(name=admin_name, email=admin_email)

        if hasattr(u, "password_hash"):
            u.password_hash = generate_password_hash(admin_password)
        elif hasattr(u, "set_password"):
            u.set_password(admin_password)  # type: ignore[attr-defined]
        else:
            return {"ok": False, "msg": "User no tiene password_hash ni set_password()"}

        if hasattr(u, "role"):
            try:
                u.role = admin_role
            except Exception:
                pass
        if hasattr(u, "is_admin"):
            try:
                u.is_admin = True
            except Exception:
                pass
        if hasattr(u, "is_active"):
            try:
                u.is_active = True
            except Exception:
                pass

        db.session.add(u)
        db.session.commit()
        return {"ok": True, "created": True, "email": admin_email}


# ==========================================================
# EXPORTS reales (solo si existen)
# ==========================================================

_loaded = _load_models()

User = _loaded.get("User")
Category = _loaded.get("Category")
Product = _loaded.get("Product")
Order = _loaded.get("Order")
Offer = _loaded.get("Offer")
Media = _loaded.get("Media")
Event = _loaded.get("Event")
Campaign = _loaded.get("Campaign")

__all__ = [
    "db",
    "init_models",
    "create_admin_if_missing",
    "User",
    "Category",
    "Product",
    "Order",
    "Offer",
    "Media",
    "Event",
    "Campaign",
]
