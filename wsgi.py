# wsgi.py — Skyline Store (ULTRA PRO / FINAL · Bulletproof v3.1)
from __future__ import annotations

import logging
import os
import sys
import time
from typing import Any, Dict, Optional, Tuple

# =============================================================================
# Early env helpers (sin side-effects peligrosos)
# =============================================================================
_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off"}

_ALLOWED_LOG_LEVELS = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}


def _bool_env(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    s = str(v).strip().lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return default


def _normalize_env_value(raw: str) -> str:
    e = (raw or "").strip().lower()
    if e == "dev":
        e = "development"
    if e in {"development", "production", "testing"}:
        return e
    return "production"


def _normalize_env() -> str:
    """
    Compat:
    - si ENV no existe pero FLASK_ENV sí, copiamos una vez.
    """
    if not os.getenv("ENV") and os.getenv("FLASK_ENV"):
        os.environ["ENV"] = os.getenv("FLASK_ENV", "production")
    return _normalize_env_value(os.getenv("ENV") or "production")


def _is_cloud() -> bool:
    """
    Detectores típicos (Render/Railway/Fly/Heroku/Docker/K8s)
    """
    return bool(
        os.getenv("RENDER")
        or os.getenv("RENDER_EXTERNAL_HOSTNAME")
        or os.getenv("RAILWAY_ENVIRONMENT")
        or os.getenv("RAILWAY_PROJECT_ID")
        or os.getenv("FLY_APP_NAME")
        or os.getenv("DYNO")
        or os.getenv("HEROKU_APP_NAME")
        or os.getenv("K_SERVICE")  # Cloud Run
        or os.getenv("KUBERNETES_SERVICE_HOST")
        or os.getenv("PORT")
        or os.path.exists("/.dockerenv")
    )


ENV = _normalize_env()
CLOUD = _is_cloud()

# DEBUG determinista (prioridad: DEBUG > FLASK_DEBUG > env)
if os.getenv("DEBUG") is not None:
    DEBUG = _bool_env("DEBUG", ENV == "development")
elif os.getenv("FLASK_DEBUG") is not None:
    DEBUG = _bool_env("FLASK_DEBUG", ENV == "development")
else:
    DEBUG = ENV == "development"

LOG_LEVEL_RAW = (os.getenv("LOG_LEVEL") or ("DEBUG" if DEBUG else "INFO")).upper().strip()
LOG_LEVEL = LOG_LEVEL_RAW if LOG_LEVEL_RAW in _ALLOWED_LOG_LEVELS else ("DEBUG" if DEBUG else "INFO")  # ✅ mejora #2


# =============================================================================
# Logging (no duplica handlers si gunicorn ya configuró)
# =============================================================================
root = logging.getLogger()

# ✅ mejora #1: si Gunicorn ya tiene logging, no lo pises
if not root.handlers:
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format="%(asctime)s | %(levelname)-8s | %(name)s - %(message)s",
    )
else:
    # Si ya hay handlers, solo aseguramos nivel razonable sin reconfigurar handlers
    root.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

log = logging.getLogger("wsgi")

# Snapshot (sin secrets)
log.info("🚀 Skyline WSGI boot | ENV=%s DEBUG=%s CLOUD=%s", ENV, DEBUG, CLOUD)
log.info("Python=%s | Platform=%s", sys.version.split()[0], sys.platform)
log.info(
    "ENV flags: PORT=%s DATABASE_URL=%s SQLALCHEMY_DATABASE_URI=%s",
    "yes" if os.getenv("PORT") else "no",
    "yes" if os.getenv("DATABASE_URL") else "no",
    "yes" if os.getenv("SQLALCHEMY_DATABASE_URI") else "no",
)


# =============================================================================
# Import App Factory
# =============================================================================
try:
    # app/__init__.py debe exponer create_app
    from app import create_app
except Exception as e:
    log.exception("❌ No se pudo importar create_app desde app: %s", e)
    raise


# =============================================================================
# Create App (con timing)
# =============================================================================
try:
    t0 = time.time()
    app = create_app()
    log.info("✅ create_app() OK en %.3fs", time.time() - t0)
except Exception as e:
    log.exception("❌ create_app() falló: %s", e)
    log.error("Contexto: ENV=%s DEBUG=%s CLOUD=%s", ENV, DEBUG, CLOUD)
    raise


# =============================================================================
# ProxyFix (solo si corresponde y si NO está aplicado)
# =============================================================================
def _is_proxyfix_applied(wsgi_app: Any) -> bool:
    try:
        return (getattr(wsgi_app, "__class__", None).__name__ == "ProxyFix")
    except Exception:
        return False


try:
    from werkzeug.middleware.proxy_fix import ProxyFix

    trust_proxy_cfg = bool(app.config.get("TRUST_PROXY_HEADERS", False))
    trust_proxy_env = _bool_env("TRUST_PROXY_HEADERS", False)
    should_apply = bool(CLOUD or trust_proxy_cfg or trust_proxy_env)

    already = _is_proxyfix_applied(getattr(app, "wsgi_app", None))
    if should_apply and not already:
        # Render típico: 1 hop
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=1,
            x_proto=1,
            x_host=1,
            x_prefix=1,
            x_port=1,  # ✅ mejora #3
        )  # type: ignore[attr-defined]
        log.info("✅ ProxyFix habilitado (x_for=1 x_proto=1 x_host=1 x_prefix=1 x_port=1)")
    elif should_apply and already:
        log.info("ℹ️ ProxyFix ya estaba aplicado (omitido)")
    else:
        log.info("ℹ️ ProxyFix omitido (no cloud y TRUST_PROXY_HEADERS=0)")
except Exception as e:
    log.info("ℹ️ ProxyFix no aplicado (no crítico): %s", e)


# =============================================================================
# Health / Ready endpoints (solo si no existen)
# =============================================================================
def _has_rule(rule_path: str) -> bool:
    try:
        return any(r.rule == rule_path for r in app.url_map.iter_rules())
    except Exception:
        return False


def _db_ping() -> Tuple[bool, Optional[str], Optional[float]]:
    """
    Ready check real:
    - si NO hay SQLALCHEMY_DATABASE_URI pero sí DATABASE_URL, lo consideramos "set" (Render)
    - ejecuta SELECT 1 con SQLAlchemy
    - rollback seguro si falla
    """
    t0 = time.time()
    try:
        uri_cfg = (app.config.get("SQLALCHEMY_DATABASE_URI") or "").strip()
        uri_env = (os.getenv("SQLALCHEMY_DATABASE_URI") or "").strip()
        db_url = (os.getenv("DATABASE_URL") or "").strip()

        # ✅ mejora #4: no marcar missing si está DATABASE_URL
        if not (uri_cfg or uri_env or db_url):
            return False, "DB url missing (SQLALCHEMY_DATABASE_URI/DATABASE_URL)", (time.time() - t0)

        from app.models import db  # type: ignore
        from sqlalchemy import text

        db.session.execute(text("SELECT 1"))
        return True, None, (time.time() - t0)
    except Exception as e:
        try:
            from app.models import db  # type: ignore
            db.session.rollback()
        except Exception:
            pass
        msg = f"{type(e).__name__}: {e}".strip()
        return False, (msg[:240] if msg else "db_error"), (time.time() - t0)


# /health: liveness (liviano)
try:
    if not _has_rule("/health"):

        @app.get("/health")
        def health() -> Tuple[Dict[str, Any], int]:  # pragma: no cover
            return {"ok": True, "service": "skyline-store", "env": ENV}, 200

        log.info("✅ /health agregado desde wsgi")
except Exception:
    pass


# /ready: readiness (con ping DB)
try:
    if not _has_rule("/ready"):

        @app.get("/ready")
        def ready() -> Tuple[Dict[str, Any], int]:  # pragma: no cover
            ok, err, dt = _db_ping()
            payload: Dict[str, Any] = {
                "ok": bool(ok),
                "service": "skyline-store",
                "env": (app.config.get("ENV") or ENV),
                "db": "ok" if ok else "degraded",
                "latency_s": dt,
            }
            if not ok:
                payload["error"] = (err or "db_error")[:220]
                return payload, 503
            return payload, 200

        log.info("✅ /ready agregado desde wsgi (con ping DB)")
except Exception:
    pass
