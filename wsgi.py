from __future__ import annotations

import logging
import os
import sys
import time
from typing import Any, Dict, Optional, Tuple

_TRUE = {"1", "true", "yes", "y", "on", "checked", "enable", "enabled"}
_FALSE = {"0", "false", "no", "n", "off", "disable", "disabled"}
_ALLOWED_LOG_LEVELS = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}
_SERVICE_NAME = os.getenv("APP_NAME", "skyline-store").strip() or "skyline-store"


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
    env = os.getenv("ENV")
    flask_env = os.getenv("FLASK_ENV")
    if (not env) and flask_env:
        os.environ["ENV"] = flask_env
        env = flask_env
    return _normalize_env_value(env or "production")


def _is_cloud() -> bool:
    return bool(
        os.getenv("RENDER")
        or os.getenv("RENDER_EXTERNAL_HOSTNAME")
        or os.getenv("RENDER_EXTERNAL_URL")
        or os.getenv("RAILWAY_ENVIRONMENT")
        or os.getenv("RAILWAY_PROJECT_ID")
        or os.getenv("FLY_APP_NAME")
        or os.getenv("DYNO")
        or os.getenv("HEROKU_APP_NAME")
        or os.getenv("K_SERVICE")
        or os.getenv("KUBERNETES_SERVICE_HOST")
        or os.getenv("PORT")
        or os.path.exists("/.dockerenv")
    )


def _get_debug(env_name: str) -> bool:
    if os.getenv("DEBUG") is not None:
        return _bool_env("DEBUG", env_name == "development")
    if os.getenv("FLASK_DEBUG") is not None:
        return _bool_env("FLASK_DEBUG", env_name == "development")
    return env_name == "development"


def _get_log_level(debug: bool) -> str:
    raw = (os.getenv("LOG_LEVEL") or ("DEBUG" if debug else "INFO")).upper().strip()
    return raw if raw in _ALLOWED_LOG_LEVELS else ("DEBUG" if debug else "INFO")


def _setup_logging(level: str) -> None:
    root = logging.getLogger()
    lvl = getattr(logging, level, logging.INFO)
    if not root.handlers:
        logging.basicConfig(
            level=lvl,
            format="%(asctime)s | %(levelname)-8s | %(name)s - %(message)s",
        )
    else:
        root.setLevel(lvl)


def _is_proxyfix_applied(wsgi_app: Any) -> bool:
    try:
        return getattr(getattr(wsgi_app, "__class__", None), "__name__", "") == "ProxyFix"
    except Exception:
        return False


def _has_rule(app_obj: Any, rule_path: str) -> bool:
    try:
        return any(r.rule == rule_path for r in app_obj.url_map.iter_rules())
    except Exception:
        return False


def _db_ping(app_obj: Any) -> Tuple[bool, Optional[str], Optional[float]]:
    t0 = time.time()
    try:
        uri_cfg = str(app_obj.config.get("SQLALCHEMY_DATABASE_URI") or "").strip()
        uri_env = (os.getenv("SQLALCHEMY_DATABASE_URI") or "").strip()
        db_url = (os.getenv("DATABASE_URL") or "").strip()
        if not (uri_cfg or uri_env or db_url):
            return False, "DB url missing (SQLALCHEMY_DATABASE_URI/DATABASE_URL)", (time.time() - t0)

        from sqlalchemy import text

        try:
            from app.models import db  # type: ignore
        except Exception:
            return False, "db not initialized (app.models.db import failed)", (time.time() - t0)

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


ENV = _normalize_env()
CLOUD = _is_cloud()
DEBUG = _get_debug(ENV)
LOG_LEVEL = _get_log_level(DEBUG)

_setup_logging(LOG_LEVEL)
log = logging.getLogger("wsgi")

log.info("WSGI boot | service=%s env=%s debug=%s cloud=%s", _SERVICE_NAME, ENV, DEBUG, CLOUD)
log.info("Python=%s | Platform=%s", sys.version.split()[0], sys.platform)
log.info(
    "Flags: PORT=%s DATABASE_URL=%s SQLALCHEMY_DATABASE_URI=%s",
    "yes" if os.getenv("PORT") else "no",
    "yes" if os.getenv("DATABASE_URL") else "no",
    "yes" if os.getenv("SQLALCHEMY_DATABASE_URI") else "no",
)

try:
    from app import create_app
except Exception as e:
    log.exception("Import create_app failed: %s", e)
    raise

try:
    t0 = time.time()
    app = create_app()
    log.info("create_app() OK in %.3fs", time.time() - t0)
except Exception as e:
    log.exception("create_app() failed: %s", e)
    log.error("Context: env=%s debug=%s cloud=%s", ENV, DEBUG, CLOUD)
    raise

try:
    from werkzeug.middleware.proxy_fix import ProxyFix

    trust_proxy_cfg = bool(app.config.get("TRUST_PROXY_HEADERS", False))
    trust_proxy_env = _bool_env("TRUST_PROXY_HEADERS", False)
    should_apply = bool(CLOUD or trust_proxy_cfg or trust_proxy_env)

    already = _is_proxyfix_applied(getattr(app, "wsgi_app", None))
    if should_apply and not already:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1, x_port=1)  # type: ignore[attr-defined]
        log.info("ProxyFix enabled")
    elif should_apply and already:
        log.info("ProxyFix already applied")
    else:
        log.info("ProxyFix skipped")
except Exception as e:
    log.info("ProxyFix not applied (non-fatal): %s", e)

try:
    if not _has_rule(app, "/health"):

        @app.get("/health")
        def health() -> Tuple[Dict[str, Any], int]:  # pragma: no cover
            return {"ok": True, "service": _SERVICE_NAME, "env": ENV}, 200

        log.info("/health added")
except Exception:
    pass

try:
    if not _has_rule(app, "/ready"):

        @app.get("/ready")
        def ready() -> Tuple[Dict[str, Any], int]:  # pragma: no cover
            ok, err, dt = _db_ping(app)
            payload: Dict[str, Any] = {
                "ok": bool(ok),
                "service": _SERVICE_NAME,
                "env": (app.config.get("ENV") or ENV),
                "db": "ok" if ok else "degraded",
                "latency_s": dt,
            }
            if not ok:
                payload["error"] = (err or "db_error")[:220]
                return payload, 503
            return payload, 200

        log.info("/ready added")
except Exception:
    pass
