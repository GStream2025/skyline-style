from __future__ import annotations

import os
import sys
from typing import Optional

from flask import Flask

try:
    from flask_migrate import Migrate
except Exception:
    Migrate = None  # type: ignore

try:
    from dotenv import load_dotenv  # type: ignore
except Exception:
    load_dotenv = None  # type: ignore

from app import create_app
from app.models import db


_TRUE = {"1", "true", "yes", "y", "on", "checked", "enable", "enabled"}
_FALSE = {"0", "false", "no", "n", "off", "disable", "disabled"}


def _env_str(key: str, default: str = "") -> str:
    v = os.getenv(key)
    return (default if v is None else str(v)).strip()


def _env_bool(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    s = str(v).strip().lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return default


def _env_int(key: str, default: int, *, lo: int = 1, hi: int = 65535) -> int:
    raw = _env_str(key, "")
    try:
        n = int(raw) if raw else int(default)
    except Exception:
        n = int(default)
    return max(lo, min(hi, n))


def _is_sqlite(uri: str) -> bool:
    return (uri or "").strip().lower().startswith("sqlite:")


def _ensure_instance_dir(app: Flask) -> None:
    try:
        os.makedirs(app.instance_path, exist_ok=True)
    except Exception:
        pass


def _maybe_load_dotenv() -> None:
    if load_dotenv is None:
        return
    env_files = (".env", ".env.local", ".env.development", ".env.production")
    for name in env_files:
        try:
            if os.path.isfile(name):
                load_dotenv(name, override=False)
                return
        except Exception:
            continue


def _show_banner(app: Flask) -> None:
    try:
        uri = str(app.config.get("SQLALCHEMY_DATABASE_URI") or "")
        env = str(app.config.get("ENV") or _env_str("ENV", "production"))
        debug = bool(app.debug)
        app.logger.info(
            "manage.py ready | env=%s debug=%s db=%s",
            env,
            debug,
            "sqlite" if _is_sqlite(uri) else "sql",
        )
    except Exception:
        pass


def _init_migrate(app: Flask) -> None:
    if Migrate is None:
        app.logger.warning("flask_migrate not installed; migrations disabled")
        return
    uri = str(app.config.get("SQLALCHEMY_DATABASE_URI") or "")
    migrate_opts = {
        "compare_type": True,
        "compare_server_default": True,
        "render_as_batch": _is_sqlite(uri),
    }
    try:
        Migrate(app, db, **migrate_opts)  # type: ignore[misc]
    except TypeError:
        Migrate(app, db)  # type: ignore[misc]


def create_cli_app() -> Flask:
    _maybe_load_dotenv()
    app = create_app()
    _ensure_instance_dir(app)
    _init_migrate(app)
    _show_banner(app)
    return app


app: Flask = create_cli_app()


def _print_check(app: Flask, debug: bool) -> None:
    uri = str(app.config.get("SQLALCHEMY_DATABASE_URI") or "")
    env = str(app.config.get("ENV") or _env_str("ENV", "production"))
    db_kind = "sqlite" if _is_sqlite(uri) else "sql"
    print(f"OK env={env} debug={debug} db={db_kind}")


def _should_run_check(argv: list[str]) -> bool:
    return "--check" in argv or "check" in argv


def _parse_host_port() -> tuple[str, int]:
    host = _env_str("HOST", "127.0.0.1")
    port = _env_int("PORT", 5000)
    return host, port


if __name__ == "__main__":
    host, port = _parse_host_port()
    debug = _env_bool("DEBUG", _env_bool("FLASK_DEBUG", False)) or bool(app.debug)

    if _should_run_check(sys.argv):
        _print_check(app, debug)
        raise SystemExit(0)

    app.run(host=host, port=port, debug=debug)
