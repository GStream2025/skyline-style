from __future__ import annotations

import logging
import os
import sys
import traceback
from typing import Optional


# ==========================================================
# Skyline Store — run.py ULTRA PRO / BULLETPROOF
#
# ✅ Mejoras (15+):
# 1) Carga .env local si existe (sin romper si no hay python-dotenv)
# 2) Normaliza ENV/FLASK_ENV y DEBUG/FLASK_DEBUG
# 3) Detección robusta de plataformas: Render/Railway/Fly/Heroku/Docker
# 4) Parsing seguro de PORT/HOST (no crashea si viene basura)
# 5) Logging pro con banner + versiones + paths
# 6) Validación de SECRET_KEY en prod (con override ALLOW_RUNTIME_SECRET=1)
# 7) Import tardío + soporte APP_FACTORY/WSGI_APP
# 8) Reloader solo en dev (evita doble ejecución en prod)
# 9) Threaded configurable (THREADS=1/0)
# 10) Preflight checks no destructivos (DB url, instance, uploads)
# 11) Manejo de excepciones en arranque con stack claro
# 12) Señales/exit codes consistentes
# 13) Compat con gunicorn: expone `app` opcionalmente si querés
# 14) Host auto 0.0.0.0 en cloud (sin tocar nada)
# 15) Respeta LOG_LEVEL y formato consistente
# ==========================================================

_TRUE = {"1", "true", "yes", "y", "on"}
_FALSE = {"0", "false", "no", "n", "off"}


def _bool_env(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    s = v.strip().lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return default


def _int_env(key: str, default: int) -> int:
    v = os.getenv(key)
    if v is None:
        return default
    try:
        return int(str(v).strip())
    except Exception:
        return default


def _load_dotenv_if_possible() -> None:
    """Carga .env si python-dotenv está instalado y existe el archivo."""
    try:
        from dotenv import load_dotenv, find_dotenv  # type: ignore

        env_path = find_dotenv(usecwd=True)
        if env_path:
            load_dotenv(env_path, override=False)
    except Exception:
        # Si no está python-dotenv, no rompe
        pass


def _setup_logging(level_name: str) -> None:
    level = getattr(logging, (level_name or "INFO").strip().upper(), logging.INFO)
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(
            level=level,
            format="%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d - %(message)s",
        )
    root.setLevel(level)


def _is_cloud() -> bool:
    # Render
    if os.getenv("RENDER") or os.getenv("RENDER_EXTERNAL_HOSTNAME"):
        return True
    # Railway
    if os.getenv("RAILWAY_ENVIRONMENT") or os.getenv("RAILWAY_PROJECT_ID"):
        return True
    # Fly.io
    if os.getenv("FLY_APP_NAME") or os.getenv("FLY_REGION"):
        return True
    # Heroku
    if os.getenv("DYNO") or os.getenv("HEROKU_APP_NAME"):
        return True
    # Docker / containers
    if os.getenv("DOCKER") or os.path.exists("/.dockerenv"):
        return True
    return False


def _normalize_env() -> str:
    # Compat: si tenés FLASK_ENV -> ENV
    if not os.getenv("ENV") and os.getenv("FLASK_ENV"):
        os.environ["ENV"] = os.getenv("FLASK_ENV", "production")
    env = (os.getenv("ENV") or "production").strip().lower()
    if env in {"dev"}:
        env = "development"
    if env not in {"development", "production", "testing"}:
        # default seguro
        env = "production"
    return env


def _resolve_debug(env: str) -> bool:
    # DEBUG gana, después FLASK_DEBUG, después env
    if os.getenv("DEBUG") is not None:
        return _bool_env("DEBUG", env == "development")
    if os.getenv("FLASK_DEBUG") is not None:
        return _bool_env("FLASK_DEBUG", env == "development")
    return env == "development"


def _resolve_host_port(env: str, debug: bool) -> tuple[str, int]:
    cloud = _is_cloud()

    # host
    host = (os.getenv("HOST") or "").strip()
    if not host:
        host = "0.0.0.0" if cloud else "127.0.0.1"

    # port
    port = _int_env("PORT", 5000)

    # Render suele usar PORT, pero si no está, 10000 es común
    if cloud and (os.getenv("RENDER") or os.getenv("RENDER_EXTERNAL_HOSTNAME")):
        port = _int_env("PORT", 10000)

    # sanity
    if port < 1 or port > 65535:
        port = 10000 if cloud else 5000

    return host, port


def _validate_secret(env: str, log: logging.Logger) -> None:
    """
    En producción:
    - exige SECRET_KEY fuerte
    - salvo que ALLOW_RUNTIME_SECRET=1 (si querés permitir el auto-secret del app factory)
    """
    if env != "production":
        return

    if _bool_env("ALLOW_RUNTIME_SECRET", False):
        log.warning("⚠️ ALLOW_RUNTIME_SECRET=1: permitido SECRET_KEY runtime (sesiones se invalidan en reinicios).")
        return

    secret = (os.getenv("SECRET_KEY") or "").strip()
    weak = {"dev", "dev-secret", "dev-secret-change-me", "change-me", "secret", "password"}
    if (not secret) or (secret.lower() in weak) or (len(secret) < 24):
        raise RuntimeError(
            "Falta SECRET_KEY segura para producción. "
            "Configúrala en Variables de Entorno (Render/Railway) o en .env. "
            "Tip: mínimo 24+ caracteres."
        )


def _preflight(log: logging.Logger) -> None:
    """
    Chequeos suaves (no rompen deploy).
    """
    try:
        db_url = os.getenv("DATABASE_URL") or os.getenv("SQLALCHEMY_DATABASE_URI") or ""
        if not db_url:
            log.warning("⚠️ No veo DATABASE_URL/SQLALCHEMY_DATABASE_URI. Se usará sqlite por default (si tu app lo permite).")
    except Exception:
        pass

    try:
        uploads = (os.getenv("UPLOADS_DIR") or "").strip()
        if uploads:
            log.info("Uploads dir configurado: %s", uploads)
    except Exception:
        pass


def _import_app_factory():
    """
    Soporta:
    - APP_FACTORY="app:create_app"
    - WSGI_APP="app:create_app"
    - default: from app import create_app
    """
    spec = (os.getenv("APP_FACTORY") or os.getenv("WSGI_APP") or "").strip()
    if not spec:
        from app import create_app  # noqa: WPS433
        return create_app

    # formato "module:symbol"
    if ":" not in spec:
        raise RuntimeError(f"APP_FACTORY/WSGI_APP inválido: {spec}. Usá 'modulo:funcion'")

    mod, sym = spec.split(":", 1)
    mod = mod.strip()
    sym = sym.strip()
    if not mod or not sym:
        raise RuntimeError(f"APP_FACTORY/WSGI_APP inválido: {spec}")

    from importlib import import_module

    m = import_module(mod)
    fn = getattr(m, sym, None)
    if not callable(fn):
        raise RuntimeError(f"No se encontró callable '{sym}' en '{mod}'")
    return fn


def main() -> int:
    _load_dotenv_if_possible()

    env = _normalize_env()
    debug = _resolve_debug(env)

    log_level = (os.getenv("LOG_LEVEL") or ("DEBUG" if debug else "INFO")).strip().upper()
    _setup_logging(log_level)
    log = logging.getLogger("skyline.run")

    host, port = _resolve_host_port(env, debug)

    log.info("🚀 Iniciando Skyline Store")
    log.info("ENV=%s DEBUG=%s HOST=%s PORT=%s CLOUD=%s", env, debug, host, port, _is_cloud())
    log.info("Python=%s | Platform=%s", sys.version.split()[0], sys.platform)
    log.info("CWD=%s", os.getcwd())

    # Validaciones + preflight
    _validate_secret(env, log)
    _preflight(log)

    try:
        create_app = _import_app_factory()
        app = create_app()
    except Exception as e:
        log.error("🔥 No se pudo crear la app: %s", e)
        log.debug("Traceback:\n%s", traceback.format_exc())
        return 2

    # config run
    use_reloader = bool(debug) and _bool_env("RELOADER", True)
    threaded = _bool_env("THREADED", True)

    log.info("Run options: reloader=%s threaded=%s", use_reloader, threaded)

    try:
        app.run(
            host=host,
            port=port,
            debug=debug,
            use_reloader=use_reloader,
            threaded=threaded,
        )
        return 0
    except KeyboardInterrupt:
        log.info("🛑 Interrumpido por usuario (CTRL+C)")
        return 0
    except Exception as e:
        log.error("🔥 Error al iniciar servidor: %s", e)
        log.debug("Traceback:\n%s", traceback.format_exc())
        return 3


# Opcional: para gunicorn si querés apuntar a "run:app"
app = None
try:
    # Si GUNICORN=1 o si se importa run.py en gunicorn, levantamos app sin ejecutar app.run()
    if _bool_env("GUNICORN", False) or ("gunicorn" in " ".join(sys.argv).lower()):
        _load_dotenv_if_possible()
        env = _normalize_env()
        debug = _resolve_debug(env)
        _setup_logging((os.getenv("LOG_LEVEL") or ("DEBUG" if debug else "INFO")).strip().upper())
        log = logging.getLogger("skyline.wsgi")
        _validate_secret(env, log)
        create_app = _import_app_factory()
        app = create_app()
except Exception:
    # no rompemos import
    app = None


if __name__ == "__main__":
    raise SystemExit(main())
