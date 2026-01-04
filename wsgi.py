# wsgi.py — Skyline Store (ULTRA PRO / FINAL)
from __future__ import annotations

import logging
import os
import sys
import time
from typing import Any, Optional


# ==========================================================
# Logs tempranos (antes de importar app)
# ==========================================================
def _is_cloud() -> bool:
    return bool(
        os.getenv("RENDER")
        or os.getenv("RENDER_EXTERNAL_HOSTNAME")
        or os.getenv("RAILWAY_ENVIRONMENT")
        or os.getenv("RAILWAY_PROJECT_ID")
        or os.getenv("FLY_APP_NAME")
        or os.getenv("DYNO")
        or os.getenv("HEROKU_APP_NAME")
        or os.getenv("PORT")
        or os.path.exists("/.dockerenv")
    )


def _normalize_env() -> str:
    # compat: FLASK_ENV -> ENV
    if not os.getenv("ENV") and os.getenv("FLASK_ENV"):
        os.environ["ENV"] = os.getenv("FLASK_ENV", "production")

    env = (os.getenv("ENV") or "production").strip().lower()
    if env == "dev":
        env = "development"
    if env not in {"development", "production", "testing"}:
        env = "production"
    return env


def _bool_env(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    s = str(v).strip().lower()
    return s in {"1", "true", "yes", "y", "on"} if s in {"1", "true", "yes", "y", "on", "0", "false", "no", "n", "off"} else default


ENV = _normalize_env()
CLOUD = _is_cloud()

# DEBUG: respeta DEBUG/FLASK_DEBUG si vienen, sino por ENV
if os.getenv("DEBUG") is not None:
    DEBUG = _bool_env("DEBUG", ENV == "development")
elif os.getenv("FLASK_DEBUG") is not None:
    DEBUG = _bool_env("FLASK_DEBUG", ENV == "development")
else:
    DEBUG = ENV == "development"

LOG_LEVEL = (os.getenv("LOG_LEVEL") or ("DEBUG" if DEBUG else "INFO")).upper().strip()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)-8s | %(name)s - %(message)s",
)
log = logging.getLogger("wsgi")

log.info("🚀 Skyline WSGI boot | ENV=%s DEBUG=%s CLOUD=%s", ENV, DEBUG, CLOUD)
log.info("Python=%s | Platform=%s", sys.version.split()[0], sys.platform)


# ==========================================================
# Import App Factory
# ==========================================================
try:
    from app import create_app  # app/__init__.py debe exponer create_app
except Exception as e:
    log.exception("❌ No se pudo importar create_app desde app. Error: %s", e)
    raise


# ==========================================================
# Create App
# ==========================================================
try:
    app = create_app()
except Exception as e:
    log.exception("❌ create_app() falló. Error: %s", e)
    raise


# ==========================================================
# ProxyFix (solo si corresponde)
# ==========================================================
try:
    from werkzeug.middleware.proxy_fix import ProxyFix

    # Solo tiene sentido detrás de proxy (Render/Heroku/etc.) o si el user lo pide
    if CLOUD or _bool_env("TRUST_PROXY_HEADERS", False):
        # x_for/x_proto/x_host/x_prefix: 1 hop típico en Render
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)  # type: ignore[attr-defined]
        log.info("✅ ProxyFix habilitado (x_for=1 x_proto=1 x_host=1 x_prefix=1)")
    else:
        log.info("ℹ️ ProxyFix omitido (no cloud y TRUST_PROXY_HEADERS=0)")
except Exception as e:
    log.info("ℹ️ ProxyFix no aplicado (no crítico): %s", e)


# ==========================================================
# Health / Ready endpoints (no rompen si ya existen)
# ==========================================================
def _has_rule(rule_path: str) -> bool:
    try:
        return any(r.rule == rule_path for r in app.url_map.iter_rules())
    except Exception:
        return False


def _db_ping() -> tuple[bool, Optional[str], Optional[float]]:
    """
    Ready check real:
    - intenta ejecutar SELECT 1 con SQLAlchemy si existe
    - no rompe si no hay db o no hay modelos cargados
    """
    t0 = time.time()
    try:
        # Intento 1: models hub (tu proyecto lo usa)
        from app.models import db  # type: ignore

        # SQLAlchemy 2: db.session.execute(text("SELECT 1"))
        from sqlalchemy import text  # type: ignore

        db.session.execute(text("SELECT 1"))  # type: ignore[attr-defined]
        return True, None, (time.time() - t0)
    except Exception as e:
        # No rompemos: devolvemos degradado
        return False, str(e), (time.time() - t0)


# /health: liviano (para balanceadores)
try:
    if not _has_rule("/health"):

        @app.get("/health")
        def health() -> tuple[dict[str, Any], int]:  # pragma: no cover
            return {"ok": True, "service": "skyline-store"}, 200

        log.info("✅ /health agregado desde wsgi")
except Exception:
    pass


# /ready: chequea DB (para deploys/rollouts)
try:
    if not _has_rule("/ready"):

        @app.get("/ready")
        def ready() -> tuple[dict[str, Any], int]:  # pragma: no cover
            ok, err, ms = _db_ping()
            payload: dict[str, Any] = {
                "ok": bool(ok),
                "service": "skyline-store",
                "db": "ok" if ok else "degraded",
                "latency_s": ms,
            }
            if not ok:
                # no filtramos secretos; solo error simple
                payload["error"] = (err or "db_error")[:220]
                return payload, 503
            return payload, 200

        log.info("✅ /ready agregado desde wsgi (con ping DB)")
except Exception:
    pass
