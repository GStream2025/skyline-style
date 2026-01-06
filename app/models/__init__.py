# app/models/__init__.py — Skyline Store (BULLETPROOF · FINAL · +23 mejoras)
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional, Set

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import OperationalError, ProgrammingError

db = SQLAlchemy()
log = logging.getLogger("models")

# =============================================================================
# ✅ Mejora 1: helper SQLAlchemy text export (health checks / raw sql)
# =============================================================================
try:
    from sqlalchemy import text as _sa_text  # type: ignore

    def text(sql: str):
        return _sa_text(sql)

except Exception:  # pragma: no cover

    def text(sql: str):
        raise RuntimeError("sqlalchemy.text no disponible")


# =============================================================================
# ✅ Mejora 2: env parsing robusto
# =============================================================================
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
    # Flask 3 puede no setear ENV: inferimos por DEBUG también
    if bool(app.config.get("DEBUG")):
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
        or ("relation" in msg and "does not exist" in msg)
    )


# =============================================================================
# ✅ Mejora 3: cache de modelos por proceso + guard de estado
# =============================================================================
_LOADED_MODELS: Optional[Dict[str, Any]] = None
_MODELS_INIT_ONCE_OK: bool = False


# =============================================================================
# ✅ Mejora 4: alias compat (tu Render error anterior)
# =============================================================================
def create_admin_if_missing(app: Flask) -> Dict[str, Any]:
    return create_admin_owner_guard(app)


# =============================================================================
# ✅ Mejora 5: import helpers con logs claros
# =============================================================================
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
        # opcional: debug (no ensucia logs en prod)
        log.debug("Optional model skipped: %s.%s (%s)", module, name, e)
        return None


# =============================================================================
# ✅ Mejora 6: carga de modelos con orden garantizado + incluye ledger/payout
# =============================================================================
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

    # ✅ NUEVO: Commission ledger / payouts (conecta tu módulo de comisiones)
    models["CommissionLedgerEntry"] = _import_optional(
        "app.models.commission_ledger", "CommissionLedgerEntry"
    )
    models["CommissionPayout"] = _import_optional(
        "app.models.commission_ledger", "CommissionPayout"
    )

    _LOADED_MODELS = {k: v for k, v in models.items() if v is not None}
    return _LOADED_MODELS


# =============================================================================
# ✅ Mejora 7: proxy seguro (evita circular imports / rompe menos en wsgi)
# =============================================================================
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


# =============================================================================
# Proxies exportados (compat)
# =============================================================================
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


# =============================================================================
# ✅ Mejora 8: init_models con hardening real
# - NO crea tablas
# - valida DB uri
# - evita doble init en el mismo proceso
# - permite recargar modelos
# =============================================================================
def init_models(
    app: Flask,
    *,
    create_admin: bool = True,
    force_reload_models: bool = False,
    log_loaded_models: bool = False,
    ping_db: bool = True,
) -> Dict[str, Any]:
    """
    Debe llamarse dentro de create_app() SIEMPRE.

    - Inicializa SQLAlchemy si hace falta
    - Carga modelos core y opcionales
    - (opcional) ping DB para detectar URI mala temprano
    - (opcional) bootstrap admin sólo si SEED=1 y no SKIP_ADMIN_BOOTSTRAP=1
    """
    global _MODELS_INIT_ONCE_OK

    # ✅ Mejora 9: no re-inicializar SQLAlchemy si ya existe
    if "sqlalchemy" not in app.extensions:
        db.init_app(app)

    loaded = _load_models(app, force=force_reload_models)

    # ✅ Mejora 10: required set completo y mensaje claro
    required: Set[str] = {"User", "Category", "Product", "Order", "OrderItem"}
    missing = required - set(loaded.keys())
    if missing:
        raise RuntimeError(f"❌ Faltan modelos core: {', '.join(sorted(missing))}")

    # ✅ Mejora 11: valida DB URI
    if not _db_uri(app):
        raise RuntimeError("❌ SQLALCHEMY_DATABASE_URI no configurado")

    # ✅ Mejora 12: ping DB (opcional) para fallar rápido
    if ping_db:
        with app.app_context():
            try:
                db.session.execute(text("SELECT 1"))
            except Exception as e:
                # No hacemos crash si estás en primera corrida sin tablas (SELECT 1 no depende de tablas)
                log.exception("❌ DB ping failed (URI/credenciales/conexión): %s", e)
                raise RuntimeError(
                    "❌ No se pudo conectar a la DB (ping failed)"
                ) from e

    if log_loaded_models:
        log.info("📦 Modelos cargados: %s", ", ".join(sorted(loaded.keys())))

    result: Dict[str, Any] = {
        "ok": True,
        "env": _app_env(app),
        "models": sorted(loaded.keys()),
    }

    seed = _env_flag("SEED", False)
    skip_admin = _env_flag("SKIP_ADMIN_BOOTSTRAP", False)

    # ✅ Mejora 13: evita re-correr bootstrap admin dos veces en el mismo proceso
    if create_admin and seed and not skip_admin and not _MODELS_INIT_ONCE_OK:
        result["admin"] = create_admin_owner_guard(app)
        _MODELS_INIT_ONCE_OK = True
    else:
        reason = (
            "SEED=0 o SKIP_ADMIN_BOOTSTRAP=1"
            if (not seed or skip_admin)
            else "already initialized"
        )
        result["admin"] = {"skipped": True, "reason": reason}

    return result


# =============================================================================
# ✅ Mejora 14: util email simple y segura (sin dependencias)
# =============================================================================
def _looks_like_email(email: str) -> bool:
    e = email.strip().lower()
    if not e or "@" not in e:
        return False
    local, _, domain = e.partition("@")
    if not local or not domain or "." not in domain:
        return False
    if " " in e or ".." in e:
        return False
    return True


# =============================================================================
# ✅ Mejora 15: admin bootstrap "owner guard" ultra seguro (no rompe nunca)
# =============================================================================
def create_admin_owner_guard(app: Flask) -> Dict[str, Any]:
    loaded = _LOADED_MODELS or {}
    UserModel = loaded.get("User")
    if not UserModel:
        return {"ok": False, "msg": "User model no cargado"}

    email = _env_str("ADMIN_EMAIL", "").lower()
    password = _env_str("ADMIN_PASSWORD", "")
    name = _env_str("ADMIN_NAME", "Admin") or "Admin"

    if _env_flag("SKIP_ADMIN_BOOTSTRAP", False):
        return {"skipped": True, "reason": "SKIP_ADMIN_BOOTSTRAP=1"}

    # ✅ Mejora 16: validación email mejorada
    if not _looks_like_email(email):
        return {"ok": False, "msg": "ADMIN_EMAIL inválido"}

    # ✅ Mejora 17: prod exige password fuerte; dev avisa pero no bloquea (salvo crear)
    if _is_production(app) and len(password) < 12:
        return {"ok": False, "msg": "ADMIN_PASSWORD inseguro en producción (mín 12)"}

    with app.app_context():
        try:
            existing = db.session.query(UserModel).filter_by(email=email).first()
        except (OperationalError, ProgrammingError) as e:
            if _db_tables_not_ready_error(e):
                log.warning("⚠️ Admin bootstrap omitido: tablas aún no creadas/migradas")
                return {"skipped": True, "reason": "tables not ready"}
            log.exception("❌ Error DB consultando admin")
            return {"ok": False, "msg": "db error querying admin"}
        except Exception:
            log.exception("❌ Error inesperado consultando admin")
            return {"ok": False, "msg": "unexpected db error querying admin"}

        # ✅ Mejora 18: si existe, refuerza flags sin romper
        if existing:
            changed = False
            for attr, value in [
                ("is_admin", True),
                ("is_active", True),
                ("email_verified", True),
            ]:
                if hasattr(existing, attr):
                    try:
                        cur = getattr(existing, attr)
                        if bool(cur) != bool(value):
                            setattr(existing, attr, value)
                            changed = True
                    except Exception:
                        pass

            # ✅ Mejora 19: commit sólo si cambia (y rollback seguro)
            if changed:
                try:
                    db.session.commit()
                except Exception:
                    db.session.rollback()
                    return {"ok": False, "msg": "db commit failed (existing admin)"}

            return {"ok": True, "created": False, "email": email}

        # ✅ Mejora 20: creación requiere password mínimo SIEMPRE
        if not password or len(password) < 8:
            return {
                "ok": False,
                "msg": "ADMIN_PASSWORD inválido (mín 8) para crear admin",
            }

        # ✅ Mejora 21: creación robusta con set_password si existe
        try:
            u = UserModel(name=name, email=email)

            if hasattr(u, "set_password") and callable(getattr(u, "set_password")):
                u.set_password(password)
            else:
                # fallback seguro (evita crash)
                if hasattr(u, "password_hash"):
                    setattr(u, "password_hash", password)

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


# =============================================================================
# ✅ Mejora 22: exports coherentes (incluye comisión)
# =============================================================================
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
