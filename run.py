from __future__ import annotations

import logging
import os
import sys
import traceback
from pathlib import Path
from typing import Callable, Tuple


# ==========================================================
# Skyline Store — run.py ULTRA PRO / BULLETPROOF (FINAL)
#
# ✅ Compatible:
# - Local (Windows / Linux / Mac)
# - Render / Railway / Fly / Heroku / Docker
# - Gunicorn (wsgi import)
#
# ✅ 5 mejoras NUEVAS (reales):
# 1) Auto-fix de ENV local para evitar "production accidental"
# 2) Preflight DB local (sqlite) y folders
# 3) Diagnóstico claro (sin filtrar secretos)
# 4) Strict prod real (SECRET_KEY + optional REQUIRE_POSTGRES)
# 5) WSGI limpio (app export) + APP_FACTORY robusto
# ==========================================================

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


def _int_env(key: str, default: int) -> int:
    v = os.getenv(key)
    if v is None:
        return default
    try:
        return int(str(v).strip())
    except Exception:
        return default


def _str_env(key: str, default: str = "") -> str:
    v = os.getenv(key)
    return default if v is None else str(v)


def _load_dotenv_if_possible() -> None:
    """
    Carga .env local si python-dotenv está instalado.
    No rompe si no existe / no está instalado.
    """
    try:
        from dotenv import find_dotenv, load_dotenv  # type: ignore

        env_path = find_dotenv(usecwd=True)
        if env_path:
            load_dotenv(env_path, override=False)
    except Exception:
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
    # Docker/container
    if os.getenv("DOCKER") or os.path.exists("/.dockerenv"):
        return True
    # Si hay PORT seteado por plataforma, casi seguro es cloud
    if os.getenv("PORT"):
        return True
    return False


def _normalize_env() -> str:
    """
    Normaliza ENV/FLASK_ENV.
    """
    if not os.getenv("ENV") and os.getenv("FLASK_ENV"):
        os.environ["ENV"] = os.getenv("FLASK_ENV", "production")

    env = (os.getenv("ENV") or "production").strip().lower()
    if env == "dev":
        env = "development"
    if env not in {"development", "production", "testing"}:
        env = "production"
    return env


def _auto_fix_local_env(env: str) -> str:
    """
    ✅ Mejora nueva #1
    Si estás LOCAL (no cloud) y ENV quedó production por accidente, lo corrige
    SOLO si el usuario no definió explícitamente ENV.
    """
    explicit_env = os.getenv("ENV") is not None or os.getenv("FLASK_ENV") is not None
    if explicit_env:
        return env

    if not _is_cloud():
        # Local sin ENV explícito => development por defecto
        return "development"
    return env


def _resolve_debug(env: str) -> bool:
    """
    DEBUG > FLASK_DEBUG > env
    """
    if os.getenv("DEBUG") is not None:
        return _bool_env("DEBUG", env == "development")
    if os.getenv("FLASK_DEBUG") is not None:
        return _bool_env("FLASK_DEBUG", env == "development")
    return env == "development"


def _resolve_host_port(env: str, debug: bool) -> Tuple[str, int]:
    cloud = _is_cloud()

    host = (os.getenv("HOST") or "").strip()
    if not host:
        host = "0.0.0.0" if cloud else "127.0.0.1"

    port = _int_env("PORT", 5000)

    # Render suele servir en 10000 si PORT no llega por alguna razón rara
    if cloud and (os.getenv("RENDER") or os.getenv("RENDER_EXTERNAL_HOSTNAME")):
        port = _int_env("PORT", 10000)

    if port < 1 or port > 65535:
        port = 10000 if cloud else 5000

    return host, port


def _validate_secret(env: str, log: logging.Logger) -> None:
    """
    Producción: exige SECRET_KEY fuerte (a menos ALLOW_RUNTIME_SECRET=1)
    """
    if env != "production":
        return

    if _bool_env("ALLOW_RUNTIME_SECRET", False):
        log.warning(
            "⚠️ ALLOW_RUNTIME_SECRET=1: permitido SECRET_KEY runtime (no recomendado)."
        )
        return

    secret = (_str_env("SECRET_KEY", "")).strip()
    weak = {
        "dev",
        "dev-secret",
        "dev-secret-change-me",
        "change-me",
        "secret",
        "password",
    }
    if (not secret) or (secret.lower() in weak) or (len(secret) < 24):
        raise RuntimeError(
            "Falta SECRET_KEY segura para producción. "
            "Configurala en Render → Environment. "
            "Tip: 24+ caracteres, única."
        )


def _validate_prod_db_policy(env: str, log: logging.Logger) -> None:
    """
    ✅ Mejora nueva #4
    Si REQUIRE_POSTGRES=1 en prod, exige DATABASE_URL real (no sqlite).
    """
    if env != "production":
        return

    if not _bool_env("REQUIRE_POSTGRES", False):
        return

    db_url = (
        _str_env("DATABASE_URL", "") or _str_env("SQLALCHEMY_DATABASE_URI", "")
    ).strip()
    if not db_url:
        raise RuntimeError(
            "REQUIRE_POSTGRES=1 pero falta DATABASE_URL en producción (Render)."
        )
    if db_url.startswith("sqlite"):
        raise RuntimeError(
            "REQUIRE_POSTGRES=1 pero estás usando sqlite en producción. Configurá Postgres en Render."
        )


def _preflight_db_local(log: logging.Logger) -> None:
    """
    ✅ Mejora nueva #2
    Si estás en sqlite local, intenta preparar el path (sin romper).
    """
    db_url = (
        _str_env("DATABASE_URL", "") or _str_env("SQLALCHEMY_DATABASE_URI", "")
    ).strip()
    if not db_url:
        return

    if not db_url.startswith("sqlite:///"):
        return

    # sqlite:///file.db -> file.db en cwd
    rel = db_url.replace("sqlite:///", "", 1).strip()
    if not rel:
        return

    try:
        p = Path(rel)
        # Si viene con carpetas, crearlas
        if p.parent and str(p.parent) not in {".", ""}:
            p.parent.mkdir(parents=True, exist_ok=True)
        # No creamos el archivo manualmente (sqlite lo crea), solo avisamos
        log.info("🗄️ SQLite local: %s", str(p))
    except Exception as e:
        log.warning("⚠️ No pude preparar path de SQLite (%s): %s", rel, e)


def _diagnostics(
    log: logging.Logger, env: str, debug: bool, host: str, port: int
) -> None:
    """
    ✅ Mejora nueva #3
    Diagnóstico sin filtrar secretos.
    """
    db_url = (
        _str_env("DATABASE_URL", "") or _str_env("SQLALCHEMY_DATABASE_URI", "")
    ).strip()
    secret = (_str_env("SECRET_KEY", "")).strip()

    log.info("🚀 Skyline Store boot")
    log.info("ENV=%s DEBUG=%s CLOUD=%s", env, debug, _is_cloud())
    log.info("HOST=%s PORT=%s", host, port)
    log.info("Python=%s | Platform=%s", sys.version.split()[0], sys.platform)
    log.info("CWD=%s", os.getcwd())

    log.info("DATABASE_URL=%s", "SET" if bool(db_url) else "MISSING")
    log.info("SECRET_KEY=%s", "SET" if bool(secret) else "MISSING")


def _import_app_factory() -> Callable[[], object]:
    """
    Soporta:
    - APP_FACTORY="app:create_app"
    - WSGI_APP="app:create_app"
    - default: from app import create_app
    """
    spec = (_str_env("APP_FACTORY", "") or _str_env("WSGI_APP", "")).strip()
    if not spec:
        from app import create_app  # noqa: WPS433

        return create_app

    if ":" not in spec:
        raise RuntimeError(
            f"APP_FACTORY/WSGI_APP inválido: {spec}. Usá 'modulo:funcion'"
        )

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
    env = _auto_fix_local_env(env)  # ✅ nueva mejora #1
    debug = _resolve_debug(env)

    log_level = (
        (_str_env("LOG_LEVEL", "") or ("DEBUG" if debug else "INFO")).strip().upper()
    )
    _setup_logging(log_level)
    log = logging.getLogger("skyline.run")

    host, port = _resolve_host_port(env, debug)

    _diagnostics(log, env, debug, host, port)

    # strict prod
    _validate_secret(env, log)
    _validate_prod_db_policy(env, log)

    # local preflight
    if env != "production":
        _preflight_db_local(log)

    try:
        create_app = _import_app_factory()
        app_obj = create_app()
    except Exception as e:
        log.error("🔥 No se pudo crear la app: %s", e)
        log.debug("Traceback:\n%s", traceback.format_exc())
        return 2

    # Opciones run
    use_reloader = bool(debug) and _bool_env("RELOADER", True)
    threaded = _bool_env("THREADED", True)

    log.info("Run options: reloader=%s threaded=%s", use_reloader, threaded)

    try:
        # type: ignore[attr-defined]
        app_obj.run(
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


# ==========================================================
# ✅ WSGI export limpio (gunicorn: run:app)
# ==========================================================
app = None
try:
    # Si se importa desde gunicorn o si forzás GUNICORN=1
    if _bool_env("GUNICORN", False) or ("gunicorn" in " ".join(sys.argv).lower()):
        _load_dotenv_if_possible()
        env = _normalize_env()
        env = _auto_fix_local_env(env)
        debug = _resolve_debug(env)

        _setup_logging(
            (_str_env("LOG_LEVEL", "") or ("DEBUG" if debug else "INFO"))
            .strip()
            .upper()
        )
        log = logging.getLogger("skyline.wsgi")

        _validate_secret(env, log)
        _validate_prod_db_policy(env, log)

        create_app = _import_app_factory()
        app = create_app()
except Exception:
    # No rompemos el import
    app = None


if __name__ == "__main__":
    raise SystemExit(main())
