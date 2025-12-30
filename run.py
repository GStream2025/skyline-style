from __future__ import annotations

import logging
import os
import sys

# ==========================================================
# Skyline Store — run.py BLINDADO
# - Carga .env en local (si existe)
# - Usa PORT de Render / HOST+PORT local
# - Logs prolijos
# - Valida SECRET_KEY en producción
# ==========================================================

def _bool_env(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}

def _load_dotenv_if_possible() -> None:
    """Carga .env si python-dotenv está instalado y existe el archivo."""
    try:
        from dotenv import load_dotenv, find_dotenv  # type: ignore
        env_path = find_dotenv(usecwd=True)
        if env_path:
            load_dotenv(env_path, override=False)
    except Exception:
        # Si no está python-dotenv, no rompe: solo no carga .env
        pass

def _setup_logging(level_name: str = "INFO") -> None:
    level = getattr(logging, level_name.upper(), logging.INFO)
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(
            level=level,
            format="%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d - %(message)s",
        )
    root.setLevel(level)

def main() -> None:
    _load_dotenv_if_possible()

    # Compat: si tenés FLASK_ENV, lo traducimos a ENV si ENV no existe
    if not os.getenv("ENV") and os.getenv("FLASK_ENV"):
        os.environ["ENV"] = os.getenv("FLASK_ENV", "production")

    env = (os.getenv("ENV") or "production").strip().lower()
    debug = _bool_env("DEBUG", env == "development")

    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "5000"))

    # Render suele setear PORT automáticamente
    if os.getenv("RENDER") or os.getenv("RENDER_EXTERNAL_HOSTNAME"):
        host = "0.0.0.0"
        port = int(os.getenv("PORT", "10000"))

    log_level = os.getenv("LOG_LEVEL", "DEBUG" if debug else "INFO")
    _setup_logging(log_level)
    log = logging.getLogger("skyline")

    log.info("🚀 Iniciando Skyline Store")
    log.info("ENV=%s DEBUG=%s HOST=%s PORT=%s", env, debug, host, port)
    log.info("Python=%s | Platform=%s", sys.version.split()[0], sys.platform)

    # En producción, exigimos SECRET_KEY fuerte
    secret = os.getenv("SECRET_KEY", "").strip()
    if env == "production" and (not secret or secret in {"dev", "dev-secret", "dev-secret-change-me"}):
        raise RuntimeError(
            "Falta SECRET_KEY segura para producción. Configúrala en Render (Environment) o .env."
        )

    # Import tardío para que ya estén cargadas las env vars
    from app import create_app  # noqa: WPS433

    app = create_app()

    # Run
    app.run(host=host, port=port, debug=debug)

if __name__ == "__main__":
    main()
