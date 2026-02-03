from __future__ import annotations

import logging
import os
import sys
import traceback
from importlib import import_module
from pathlib import Path
from typing import Any, Callable, Tuple

# ==========================================================
# Skyline Store — run.py (ULTRA PRO / BULLETPROOF · FINAL v3.0)
# ==========================================================

_TRUE = {"1", "true", "yes", "y", "on", "checked", "enable", "enabled"}
_FALSE = {"0", "false", "no", "n", "off", "disable", "disabled"}

_ENV_ALLOWED = {"development", "production", "testing"}
_WEAK_SECRETS = {"dev", "dev-secret", "dev-secret-change-me", "change-me", "secret", "password"}


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


def _int_env(key: str, default: int, *, lo: int = 1, hi: int = 65535) -> int:
    v = os.getenv(key)
    if v is None:
        return default
    try:
        n = int(str(v).strip())
    except Exception:
        return default
    return max(lo, min(hi, n))


def _str_env(key: str, default: str = "") -> str:
    v = os.getenv(key)
    return default if v is None else str(v).strip()


def _load_dotenv_if_possible() -> None:
    """
    Carga .env solo en entornos locales (no pisa Render/Cloud).
    """
    try:
        from dotenv import find_dotenv, load_dotenv  # type: ignore
    except Exception:
        return

    env = _str_env("ENV", _str_env("FLASK_ENV", "")).lower()
    if env == "production":
        return
    if _bool_env("DISABLE_DOTENV", False):
        return

    try:
        env_path = find_dotenv(usecwd=True)
        if env_path:
            load_dotenv(env_path, override=False)
    except Exception:
        pass


def _setup_logging(level_name: str) -> None:
    name = (level_name or "INFO").strip().upper()
    level = getattr(logging, name, logging.INFO)

    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(
            level=level,
            format="%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d - %(message)s",
        )
    root.setLevel(level)

    # Silencia logs ruidosos en prod (si querés)
    if name != "DEBUG":
        logging.getLogger("werkzeug").setLevel(logging.WARNING)


def _is_cloud() -> bool:
    # Señales típicas de cloud/provider
    if os.getenv("RENDER") or os.getenv("RENDER_EXTERNAL_HOSTNAME"):
        return True
    if os.getenv("RAILWAY_ENVIRONMENT") or os.getenv("RAILWAY_PROJECT_ID"):
        return True
    if os.getenv("FLY_APP_NAME") or os.getenv("FLY_REGION"):
        return True
    if os.getenv("DYNO") or os.getenv("HEROKU_APP_NAME"):
        return True
    if os.getenv("DOCKER") or os.path.exists("/.dockerenv"):
        return True
    # PORT suele existir en cloud
    if os.getenv("PORT"):
        return True
    return False


def _normalize_env() -> str:
    # Compat: si tenés FLASK_ENV pero no ENV, lo copia
    if not os.getenv("ENV") and os.getenv("FLASK_ENV"):
        os.environ["ENV"] = os.getenv("FLASK_ENV", "production")

    env = _str_env("ENV", "production").lower()
    if env == "dev":
        env = "development"
    if env not in _ENV_ALLOWED:
        env = "production"
    return env


def _auto_fix_local_env(env: str) -> str:
    # Solo auto-dev si el usuario NO definió ENV/FLASK_ENV explícitamente
    explicit = (os.getenv("ENV") is not None) or (os.getenv("FLASK_ENV") is not None)
    if explicit:
        return env
    return "development" if not _is_cloud() else env


def _resolve_debug(env: str) -> bool:
    if os.getenv("DEBUG") is not None:
        return _bool_env("DEBUG", env == "development")
    if os.getenv("FLASK_DEBUG") is not None:
        return _bool_env("FLASK_DEBUG", env == "development")
    return env == "development"


def _normalize_db_url(db_url: str) -> str:
    """
    Fixes:
    - postgres:// (Render legacy) -> postgresql://
    - postgresql+psycopg2:// -> postgresql+psycopg:// (evita psycopg2 missing)
    """
    u = (db_url or "").strip()
    if u.startswith("postgres://"):
        u = "postgresql://" + u[len("postgres://") :]
    if u.startswith("postgresql+psycopg2://"):
        u = u.replace("postgresql+psycopg2://", "postgresql+psycopg://", 1)
    return u


def _resolve_db_url() -> str:
    # Orden: SQLALCHEMY_DATABASE_URI > DATABASE_URL
    raw = _str_env("SQLALCHEMY_DATABASE_URI", "") or _str_env("DATABASE_URL", "")
    return _normalize_db_url(raw)


def _resolve_host_port() -> Tuple[str, int]:
    cloud = _is_cloud()
    host = _str_env("HOST", "")
    if not host:
        host = "0.0.0.0" if cloud else "127.0.0.1"

    # Render suele setear PORT, no hace falta forzar 10000 (pero mantenemos fallback)
    port = _int_env("PORT", 10000 if cloud else 5000, lo=1, hi=65535)
    return host, port


def _validate_secret(env: str, log: logging.Logger) -> None:
    if env != "production":
        return

    if _bool_env("ALLOW_RUNTIME_SECRET", False):
        log.warning("⚠️ ALLOW_RUNTIME_SECRET=1: permitido SECRET_KEY runtime (no recomendado).")
        return

    secret = _str_env("SECRET_KEY", "")
    if (not secret) or (secret.lower() in _WEAK_SECRETS) or (len(secret) < 24):
        raise RuntimeError(
            "Falta SECRET_KEY segura para producción. "
            "Configurala en Render → Environment. "
            "Tip: 24+ caracteres, única."
        )


def _validate_prod_db_policy(env: str) -> None:
    if env != "production":
        return
    if not _bool_env("REQUIRE_POSTGRES", False):
        return

    db_url = _resolve_db_url()
    if not db_url:
        raise RuntimeError("REQUIRE_POSTGRES=1 pero falta DATABASE_URL/SQLALCHEMY_DATABASE_URI en producción.")
    if db_url.startswith("sqlite"):
        raise RuntimeError("REQUIRE_POSTGRES=1 pero estás usando sqlite en producción. Configurá Postgres en Render.")


def _preflight_sqlite_path(db_url: str, log: logging.Logger) -> None:
    """
    Prepara el directorio del archivo sqlite si aplica.
    Soporta:
      - sqlite:///relative/or/abs
      - sqlite:////abs/path
    """
    u = (db_url or "").strip()
    if not u.startswith("sqlite:"):
        return

    try:
        path_str = ""
        if u.startswith("sqlite:////"):
            path_str = u.replace("sqlite:////", "/", 1).strip()
        elif u.startswith("sqlite:///"):
            path_str = u.replace("sqlite:///", "", 1).strip()

        if not path_str:
            return

        p = Path(path_str)
        if p.parent and str(p.parent) not in {".", ""}:
            p.parent.mkdir(parents=True, exist_ok=True)
        log.info("🗄️ SQLite path listo: %s", str(p))
    except Exception as e:
        log.warning("⚠️ No pude preparar SQLite path: %s", e)


def _diagnostics(log: logging.Logger, env: str, debug: bool, host: str, port: int, db_url: str) -> None:
    # Evita filtrar URL completa (con password). Solo estado.
    log.info("🚀 Skyline Store boot")
    log.info("ENV=%s DEBUG=%s CLOUD=%s", env, debug, _is_cloud())
    log.info("HOST=%s PORT=%s", host, port)
    log.info("Python=%s | Platform=%s", sys.version.split()[0], sys.platform)
    log.info("CWD=%s", os.getcwd())
    log.info("DATABASE_URL=%s", "SET" if bool(db_url) else "MISSING")
    log.info("SECRET_KEY=%s", "SET" if bool(_str_env("SECRET_KEY", "")) else "MISSING")


def _import_app_factory() -> Callable[[], Any]:
    spec = (_str_env("APP_FACTORY", "") or _str_env("WSGI_APP", "")).strip()
    if not spec:
        from app import create_app  # local import (evita side-effects prematuros)

        return create_app

    if ":" not in spec:
        raise RuntimeError(f"APP_FACTORY/WSGI_APP inválido: {spec}. Usá 'modulo:funcion'")

    mod, sym = [x.strip() for x in spec.split(":", 1)]
    if not mod or not sym:
        raise RuntimeError(f"APP_FACTORY/WSGI_APP inválido: {spec}")

    # tolera "func()"
    if sym.endswith("()"):
        sym = sym[:-2].strip()

    m = import_module(mod)
    fn = getattr(m, sym, None)
    if not callable(fn):
        raise RuntimeError(f"No se encontró callable '{sym}' en '{mod}'")
    return fn


def _build_app(*, for_export: bool, log: logging.Logger, env: str, debug: bool) -> Any:
    """
    Crea la app asegurando:
    - DB url normalizada disponible como env var (para create_app que la lea)
    - No filtra secretos
    """
    db_url = _resolve_db_url()
    if db_url:
        # si tu create_app lee DATABASE_URL/SQLALCHEMY_DATABASE_URI, le dejamos ambos coherentes
        os.environ.setdefault("DATABASE_URL", db_url)
        os.environ.setdefault("SQLALCHEMY_DATABASE_URI", db_url)

    if not for_export and env != "production":
        _preflight_sqlite_path(db_url, log)

    create_app = _import_app_factory()
    app_obj = create_app()
    return app_obj


def main() -> int:
    _load_dotenv_if_possible()

    env = _auto_fix_local_env(_normalize_env())
    debug = _resolve_debug(env)

    log_level = (_str_env("LOG_LEVEL", "") or ("DEBUG" if debug else "INFO")).strip().upper()
    _setup_logging(log_level)
    log = logging.getLogger("skyline.run")

    host, port = _resolve_host_port()
    db_url = _resolve_db_url()
    _diagnostics(log, env, debug, host, port, db_url)

    _validate_secret(env, log)
    _validate_prod_db_policy(env)

    try:
        app_obj = _build_app(for_export=False, log=log, env=env, debug=debug)
    except Exception as e:
        log.error("🔥 No se pudo crear la app: %s", e)
        if debug or log_level == "DEBUG":
            log.debug("Traceback:\n%s", traceback.format_exc())
        return 2

    use_reloader = bool(debug) and _bool_env("RELOADER", True)
    threaded = _bool_env("THREADED", True)

    log.info("Run options: reloader=%s threaded=%s", use_reloader, threaded)

    try:
        # type: ignore[attr-defined]
        app_obj.run(host=host, port=port, debug=debug, use_reloader=use_reloader, threaded=threaded)
        return 0
    except KeyboardInterrupt:
        log.info("🛑 Interrumpido por usuario (CTRL+C)")
        return 0
    except Exception as e:
        log.error("🔥 Error al iniciar servidor: %s", e)
        if debug or log_level == "DEBUG":
            log.debug("Traceback:\n%s", traceback.format_exc())
        return 3


# ==========================================================
# ✅ WSGI export limpio (gunicorn: run:app)
# ==========================================================
_load_dotenv_if_possible()
_env = _auto_fix_local_env(_normalize_env())
_debug = _resolve_debug(_env)
_level = (_str_env("LOG_LEVEL", "") or ("DEBUG" if _debug else "INFO")).strip().upper()
_setup_logging(_level)
_log = logging.getLogger("skyline.wsgi")

_validate_secret(_env, _log)
_validate_prod_db_policy(_env)

# Si falla, que falle fuerte: Render/Gunicorn debe mostrar el error (no app=None)
app = _build_app(for_export=True, log=_log, env=_env, debug=_debug)


if __name__ == "__main__":
    raise SystemExit(main())
