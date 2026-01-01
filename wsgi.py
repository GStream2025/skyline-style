# wsgi.py — Skyline Store (PRO / FINAL)
from __future__ import annotations

import os
import logging

# Logs tempranos (antes de importar app)
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
log = logging.getLogger("wsgi")

try:
    from app import create_app  # app/__init__.py debe exponer create_app
except Exception as e:
    log.exception("❌ No se pudo importar create_app desde app. Error: %s", e)
    raise

try:
    app = create_app()
except Exception as e:
    log.exception("❌ create_app() falló. Error: %s", e)
    raise

# Render/Proxy headers (si tu app usa FORCE_HTTPS / redirect)
# Esto ayuda a que url_for(_external=True) y request.is_secure funcionen bien detrás de proxy.
try:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)  # type: ignore[attr-defined]
    log.info("✅ ProxyFix habilitado")
except Exception:
    log.info("ℹ️ ProxyFix no aplicado (no es crítico)")

# Healthcheck fallback (por si no lo registraste en rutas)
# Render pega /health. Si ya lo tenés, no molesta.
try:
    if not any(r.rule == "/health" for r in app.url_map.iter_rules()):
        @app.get("/health")
        def _health():  # pragma: no cover
            return {"ok": True}, 200
        log.info("✅ /health agregado desde wsgi")
except Exception:
    pass
