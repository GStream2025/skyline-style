# manage.py
from __future__ import annotations

import os
import sys
from typing import Optional

from flask import Flask
from flask_migrate import Migrate

from app import create_app
from app.models import db

def _env_str(key: str, default: str = "") -> str:
    v = os.getenv(key)
    return (default if v is None else str(v)).strip()

def _env_int(key: str, default: int, *, lo: int = 1, hi: int = 65535) -> int:
    raw = _env_str(key, "")
    if not raw:
        return default
    try:
        n = int(raw)
    except Exception:
        n = default
    return max(lo, min(hi, n))

def _is_sqlite(uri: str) -> bool:
    return (uri or "").strip().lower().startswith("sqlite:")

def _ensure_instance_dir(app: Flask) -> None:
    try:
        os.makedirs(app.instance_path, exist_ok=True)
    except Exception:
        pass

def _maybe_load_dotenv() -> None:
    for name in (".env", ".env.local", ".env.development", ".env.production"):
        try:
            if os.path.exists(name) and os.path.isfile(name):
                try:
                    from dotenv import load_dotenv  # type: ignore
                    load_dotenv(name, override=False)
                    return
                except Exception:
                    return
        except Exception:
            pass

def _show_banner(app: Flask) -> None:
    try:
        uri = str(app.config.get("SQLALCHEMY_DATABASE_URI") or "")
        env = str(app.config.get("ENV") or _env_str("ENV", "production"))
        debug = bool(app.debug)
        app.logger.info("manage.py ready | env=%s debug=%s db=%s", env, debug, "sqlite" if _is_sqlite(uri) else "sql")
    except Exception:
        pass

def create_cli_app() -> Flask:
    _maybe_load_dotenv()
    app = create_app()
    _ensure_instance_dir(app)

    uri = str(app.config.get("SQLALCHEMY_DATABASE_URI") or "")
    migrate_opts = {
        "compare_type": True,
        "compare_server_default": True,
        "render_as_batch": _is_sqlite(uri),
    }

    Migrate(app, db, **migrate_opts)
    _show_banner(app)
    return app

app: Flask = create_cli_app()

if __name__ == "__main__":
    host = _env_str("HOST", "127.0.0.1")
    port = _env_int("PORT", 5000)
    debug = _env_str("FLASK_DEBUG", "").lower() in {"1", "true", "yes", "y", "on"} or bool(app.debug)

    if "--check" in sys.argv:
        uri = str(app.config.get("SQLALCHEMY_DATABASE_URI") or "")
        print(f"OK env={app.config.get('ENV')} debug={debug} db={'sqlite' if _is_sqlite(uri) else 'sql'}")
        raise SystemExit(0)

    app.run(host=host, port=port, debug=debug)
