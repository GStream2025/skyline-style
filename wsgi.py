# wsgi.py — Skyline Store (ULTRA PRO / FINAL · Bulletproof)
from __future__ import annotations

import logging
import os
import sys
import time
from typing import Any, Optional, Tuple


# =============================================================================
# Early env helpers (no side effects peligrosos)
# =============================================================================
_TRUE = {"1", "true", "yes", "y", "on"}
_FALSE = {"0", "false", "no", "n", "off"}


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


def _normalize_env_value(raw: str) -> str:
    e = (raw or "").strip().lower()
    if e == "dev":
        e = "development"
    if e in {"development", "production", "testing"}:
        return e
    return "production"


def _normalize_env() -> str:
    """
    Mejora #1: compat limpia:
    - si ENV no existe pero FLASK_ENV sí, copiamos una vez.
    - nunca inventamos valores raros
    """
    if not os.getenv("ENV") and os.getenv("FLASK_ENV"):
        os.environ["ENV"] = os.getenv("FLASK_ENV", "production")
    return _normalize_env_value(os.getenv("ENV") or "production")


ENV = _normalize_env()
CLOUD = _is_cloud()

# Mejora #2: DEBUG determinista
# - respeta DEBUG/FLASK_DEBUG si vienen
# - sino DEBUG = (ENV == development)
if os.getenv("DEBUG") is not None:
    DEBUG = _bool_env("DEBUG", ENV == "development")
elif os.getenv("FLASK_DEBUG") is not None:
    DEBUG = _bool_env("FLASK_DEBUG", ENV == "development")
else:
    DEBUG = ENV == "development"

LOG_LEVEL = (os.getenv("LOG_LEVEL") or ("DEBUG" if DEBUG else "INFO")).upper().strip()


# =============================================================================
# Logging (no duplica handlers si gunicorn ya configuró)
# =============================================================================
root = logging.getLogger()
if not root.handlers:
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format="%(asctime)s | %(levelname)-8s | %(name)s - %(message)s",
    )
root.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

log = logging.getLogger("wsgi")

# Mejora #3: startup snapshot (sin secrets)
log.info("🚀 Skyline WSGI boot | ENV=%s DEBUG=%s CLOUD=%s", ENV, DEBUG, CLOUD)
log.info("Python=%s | Platform=%s", sys.version.split()[0], sys.platform)
log.info(
    "ENV vars present: PORT=%s DATABASE_URL=%s SQLALCHEMY_DATABASE_URI=%s",
    "yes" if os.getenv("PORT") else "no",
    "yes" if os.getenv("DATABASE_URL") else "no",
    "yes" if os.getenv("SQLALCHEMY_DATABASE_URI") else "no",
)


# =============================================================================
# Import App Factory
# =============================================================================
try:
    from app import create_app  # app/__init__.py debe exponer create_app
except Exception as e:
    log.exception("❌ No se pudo importar create_app desde app. Error: %s", e)
    raise


# =============================================================================
# Create App (con timing)
# =============================================================================
try:
    t0 = time.time()
    app = create_app()
    log.info("✅ create_app() OK en %.3fs", time.time() - t0)
except Exception as e:
    log.exception("❌ create_app() falló. Error: %s", e)
    raise


# =============================================================================
# ProxyFix (solo si corresponde)
# =============================================================================
try:
    from werkzeug.middleware.proxy_fix import ProxyFix

    # Mejora #4: prioridad al config del app
    trust_proxy_cfg = bool(app.config.get("TRUST_PROXY_HEADERS", False))
    trust_proxy_env = _bool_env("TRUST_PROXY_HEADERS", False)

    if CLOUD or trust_proxy_cfg or trust_proxy_env:
        # Render típico: 1 hop
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)  # type: ignore[attr-defined]
        log.info("✅ ProxyFix habilitado (x_for=1 x_proto=1 x_host=1 x_prefix=1)")
    else:
        log.info("ℹ️ ProxyFix omitido (no cloud y TRUST_PROXY_HEADERS=0)")
except Exception as e:
    log.info("ℹ️ ProxyFix no aplicado (no crítico): %s", e)


# =============================================================================
# Health / Ready endpoints (no rompen si ya existen)
# =============================================================================
def _has_rule(rule_path: str) -> bool:
    try:
        return any(r.rule == rule_path for r in app.url_map.iter_rules())
    except Exception:
        return False


def _db_ping() -> Tuple[bool, Optional[str], Optional[float]]:
    """
    Ready check real:
    - si NO hay SQLALCHEMY_DATABASE_URI, no intentamos ping (evita crash y logs feos)
    - intenta ejecutar SELECT 1 con SQLAlchemy
    """
    t0 = time.time()
    try:
        uri = (app.config.get("SQLALCHEMY_DATABASE_URI") or "").strip()
        if not uri:
            return False, "SQLALCHEMY_DATABASE_URI missing", (time.time() - t0)

        # Intento 1: usar app.models.text (si existe)
        try:
            from app.models import db as _db  # type: ignore
            from app.models import text as _text  # type: ignore
            _db.session.execute(_text("SELECT 1"))  # type: ignore[attr-defined]
            return True, None, (time.time() - t0)
        except Exception:
            # Intento 2: fallback directo sqlalchemy.text
            from app.models import db as _db  # type: ignore
            from sqlalchemy import text as sa_text  # type: ignore
            _db.session.execute(sa_text("SELECT 1"))  # type: ignore[attr-defined]
            return True, None, (time.time() - t0)

    except Exception as e:
        return False, str(e), (time.time() - t0)


# /health: liviano (para balanceadores)
try:
    if not _has_rule("/health"):

        @app.get("/health")
        def health() -> Tuple[dict[str, Any], int]:  # pragma: no cover
            return {"ok": True, "service": "skyline-store"}, 200

        log.info("✅ /health agregado desde wsgi")
except Exception:
    pass


# /ready: chequea DB (para deploys/rollouts)
try:
    if not _has_rule("/ready"):

        @app.get("/ready")
        def ready() -> Tuple[dict[str, Any], int]:  # pragma: no cover
            ok, err, dt = _db_ping()
            payload: dict[str, Any] = {
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
