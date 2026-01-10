# app/models/__init__.py — Skyline Store (BULLETPROOF · FINAL · NO BREAK)
from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, Optional, Set, Callable

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import OperationalError, ProgrammingError

db = SQLAlchemy()
log = logging.getLogger("models")

# =============================================================================
# ✅ Mejora 1: helper sqlalchemy.text export (health checks / raw sql)
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
    env = (app.config.get("ENV") or os.getenv("ENV") or os.getenv("FLASK_ENV") or "").lower().strip()
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


# =============================================================================
# ✅ Mejora 3 EXTRA: normalización DB (postgres:// → postgresql://)
# y fallback fuerte desde ENV (Render-proof)
# =============================================================================
def _normalize_db_url(raw: str) -> str:
    u = (raw or "").strip()
    if u.startswith("postgres://"):
        u = u.replace("postgres://", "postgresql://", 1)
    return u


def _ensure_db_uri(app: Flask) -> str:
    """
    Garantiza que app.config tenga SQLALCHEMY_DATABASE_URI.
    Prioridad:
      1) app.config['SQLALCHEMY_DATABASE_URI']
      2) ENV SQLALCHEMY_DATABASE_URI
      3) ENV DATABASE_URL
      4) fallback sqlite SOLO en development
    """
    uri = (app.config.get("SQLALCHEMY_DATABASE_URI") or "").strip()
    if uri:
        uri = _normalize_db_url(uri)
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

    # Fallback local (solo dev)
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


# =============================================================================
# ✅ Mejora 4 EXTRA: locks para evitar condiciones de carrera (gunicorn threads)
# =============================================================================
_INIT_LOCK = threading.RLock()


# =============================================================================
# ✅ Mejora 5: cache de modelos por proceso + guard de estado
# =============================================================================
_LOADED_MODELS: Optional[Dict[str, Any]] = None
_MODELS_INIT_ONCE_OK: bool = False


# =============================================================================
# ✅ Mejora 6: alias compat
# =============================================================================
def create_admin_if_missing(app: Flask) -> Dict[str, Any]:
    return create_admin_owner_guard(app)


# =============================================================================
# ✅ Mejora 7: import helpers con logs claros
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
        log.debug("Optional model skipped: %s.%s (%s)", module, name, e)
        return None


# =============================================================================
# ✅ Mejora 8: carga de modelos con orden garantizado
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

    # Opcionales
    models["Offer"] = _import_optional("app.models.offer", "Offer")
    models["Media"] = _import_optional("app.models.media", "Media")
    models["Event"] = _import_optional("app.models.event", "Event")
    models["Campaign"] = _import_optional("app.models.campaign", "Campaign")
    models["CampaignSend"] = _import_optional("app.models.campaign", "CampaignSend")

    # Comisión / ledger (opc)
    models["CommissionLedgerEntry"] = _import_optional("app.models.commission_ledger", "CommissionLedgerEntry")
    models["CommissionPayout"] = _import_optional("app.models.commission_ledger", "CommissionPayout")

    _LOADED_MODELS = {k: v for k, v in models.items() if v is not None}
    return _LOADED_MODELS


# =============================================================================
# ✅ Mejora 9: proxy seguro (evita circular imports)
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
# ✅ Mejora 10 EXTRA: ping DB más robusto + logs claros
# =============================================================================
def _ping_db(app: Flask) -> None:
    with app.app_context():
        # IMPORTANTE: SELECT 1 no depende de tablas/migrations
        db.session.execute(text("SELECT 1"))


# =============================================================================
# ✅ Mejora 11: init_models con hardening real (NO BREAK)
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
    - Garantiza SQLALCHEMY_DATABASE_URI (Render-proof)
    - Carga modelos core y opcionales
    - (opcional) ping DB para detectar credenciales/URI malas temprano
    - (opcional) bootstrap admin si SEED=1 y no SKIP_ADMIN_BOOTSTRAP=1
    """
    global _MODELS_INIT_ONCE_OK

    with _INIT_LOCK:
        # ✅ Asegurar DB URI ANTES de tocar db.init_app()
        uri = _ensure_db_uri(app)

        if not uri:
            raise RuntimeError(
                "❌ SQLALCHEMY_DATABASE_URI no configurado. "
                "Seteá SQLALCHEMY_DATABASE_URI o DATABASE_URL en Render."
            )

        # ✅ no re-inicializar SQLAlchemy si ya existe
        if "sqlalchemy" not in app.extensions:
            db.init_app(app)

        loaded = _load_models(app, force=force_reload_models)

        # Required core set
        required: Set[str] = {"User", "Category", "Product", "Order", "OrderItem"}
        missing = required - set(loaded.keys())
        if missing:
            raise RuntimeError(f"❌ Faltan modelos core: {', '.join(sorted(missing))}")

        # Ping DB (opcional)
        if ping_db:
            try:
                _ping_db(app)
            except Exception as e:
                log.exception("❌ DB ping failed (URI/credenciales/conexión): %s", e)
                raise RuntimeError("❌ No se pudo conectar a la DB (ping failed)") from e

        if log_loaded_models:
            log.info("📦 Modelos cargados: %s", ", ".join(sorted(loaded.keys())))

        result: Dict[str, Any] = {
            "ok": True,
            "env": _app_env(app),
            "db": "configured",
            "models": sorted(loaded.keys()),
        }

        seed = _env_flag("SEED", False)
        skip_admin = _env_flag("SKIP_ADMIN_BOOTSTRAP", False)

        # Evita re-correr bootstrap admin dos veces
        if create_admin and seed and not skip_admin and not _MODELS_INIT_ONCE_OK:
            result["admin"] = create_admin_owner_guard(app)
            _MODELS_INIT_ONCE_OK = True
        else:
            reason = "SEED=0 o SKIP_ADMIN_BOOTSTRAP=1" if (not seed or skip_admin) else "already initialized"
            result["admin"] = {"skipped": True, "reason": reason}

        return result


# =============================================================================
# ✅ Mejora 12: util email simple y segura
# =============================================================================
def _looks_like_email(email: str) -> bool:
    e = (email or "").strip().lower()
    if not e or "@" not in e:
        return False
    local, _, domain = e.partition("@")
    if not local or not domain or "." not in domain:
        return False
    if " " in e or ".." in e:
        return False
    return True


# =============================================================================
# ✅ Mejora 13: admin bootstrap ultra seguro (no rompe nunca)
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

    if not _looks_like_email(email):
        return {"ok": False, "msg": "ADMIN_EMAIL inválido"}

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

        if existing:
            changed = False
            for attr, value in (("is_admin", True), ("is_active", True), ("email_verified", True)):
                if hasattr(existing, attr):
                    try:
                        cur = getattr(existing, attr)
                        if bool(cur) != bool(value):
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

        # creación requiere password mínimo siempre
        if not password or len(password) < 8:
            return {"ok": False, "msg": "ADMIN_PASSWORD inválido (mín 8) para crear admin"}

        try:
            u = UserModel(name=name, email=email)

            if hasattr(u, "set_password") and callable(getattr(u, "set_password")):
                u.set_password(password)
            else:
                # fallback (evitar crash si no existe hashing)
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
# ✅ Mejora 14: exports coherentes
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
