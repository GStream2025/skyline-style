from __future__ import annotations

"""
URL / Redirect Security — ULTRA PRO / BULLETPROOF (FINAL)

Mejoras clave (10+):
1) Bloquea esquemas peligrosos (javascript:, data:, file:, etc.)
2) Bloquea //evil.com (scheme-relative)
3) Bloquea backslashes (\) y control chars (CRLF)
4) Soporta paths relativos internos y URLs absolutas SOLO si son mismo host
5) Normaliza y “limpia” next antes de validar
6) Evita open-redirect incluso si target viene raro (espacios, tabs, %0a)
7) Permite whitelist opcional por prefix (SAFE_NEXT_PREFIXES)
8) Fallback seguro a endpoint interno
9) No rompe sin request context (dev/tests)
10) API estable: is_safe_url(), safe_next_url()
"""

import os
import re
from typing import Optional
from urllib.parse import urlparse, unquote

from flask import request, url_for

# Prefijos internos permitidos (opcional)
# Ej: SAFE_NEXT_PREFIXES="/,/shop,/account,/admin"
_DEFAULT_PREFIXES = "/"
_SAFE_PREFIXES_ENV = (os.getenv("SAFE_NEXT_PREFIXES") or "").strip()

# Control chars (CR/LF/TAB/etc.) -> potencial header injection / weird parsing
_CTRL_RE = re.compile(r"[\x00-\x1F\x7F]")

# Esquemas explícitamente prohibidos (aunque urlparse a veces es creativo)
_BAD_SCHEMES = {
    "javascript",
    "data",
    "file",
    "ftp",
    "blob",
    "chrome",
    "chrome-extension",
    "about",
    "mailto",
    "tel",
}


def _strip_and_decode(s: str) -> str:
    """
    Limpia:
    - strip espacios
    - decode %xx (1 vez) para detectar cosas como %0d%0a
    - corta si hay control chars
    """
    s = (s or "").strip()
    if not s:
        return ""
    try:
        s = unquote(s)
    except Exception:
        pass
    # elimina control chars
    s = _CTRL_RE.sub("", s)
    return s.strip()


def _allowed_prefixes() -> list[str]:
    """
    Lista de prefijos internos permitidos.
    Si no seteás env => permite todo lo interno.
    """
    raw = _SAFE_PREFIXES_ENV
    if not raw:
        return [_DEFAULT_PREFIXES]  # "/" permite todo interno
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    # asegura que empiezan con /
    out = []
    for p in parts:
        if not p.startswith("/"):
            p = "/" + p
        out.append(p)
    return out or [_DEFAULT_PREFIXES]


def _matches_prefix(path: str) -> bool:
    """
    Permite controlar por prefijo: /admin, /shop, etc.
    Por defecto "/" => todo ok.
    """
    prefixes = _allowed_prefixes()
    if prefixes == ["/"]:
        return True
    return any(path.startswith(p) for p in prefixes)


def is_safe_url(target: Optional[str]) -> bool:
    """
    Valida que target sea seguro para redirigir.

    Permite:
      - Rutas internas: "/shop", "/account/orders"
      - URL absoluta SOLO si es del mismo host: "https://tudominio.com/shop"

    Bloquea:
      - http(s) externos
      - esquemas peligrosos (javascript:, data:, etc.)
      - //evil.com
      - backslashes tipo "\\evil.com"
      - control chars / CRLF
    """
    if not target:
        return False

    t = _strip_and_decode(str(target))
    if not t:
        return False

    # bloquea backslash (Windows paths / evasiones)
    if "\\" in t:
        return False

    # bloquea scheme-relative: //evil.com
    if t.startswith("//"):
        return False

    # si es una ruta interna
    if t.startswith("/"):
        # evita "/\evil" etc.
        if t.startswith("/\\"):
            return False
        # whitelist de prefijos (opcional)
        return _matches_prefix(t)

    # si viene absoluto: solo permitimos si host coincide
    try:
        # Si no hay request context, no podemos validar host -> no seguro
        host_url = request.host_url  # puede lanzar si no hay contexto
    except Exception:
        return False

    try:
        ref = urlparse(host_url)
        test = urlparse(t)

        scheme = (test.scheme or "").lower()
        if scheme and scheme not in {"http", "https"}:
            return False
        if scheme in _BAD_SCHEMES:
            return False

        # netloc vacío no debería pasar acá (porque no empezaba con /),
        # pero por seguridad:
        if not test.netloc:
            return False

        # mismo host exacto
        if test.netloc != ref.netloc:
            return False

        # whitelist opcional por prefijos del path
        path = test.path or "/"
        if not path.startswith("/"):
            path = "/" + path
        return _matches_prefix(path)

    except Exception:
        return False


def safe_next_url(default_endpoint: str = "main.home", **endpoint_kwargs) -> str:
    """
    Devuelve next seguro o fallback a endpoint interno.

    Lee next de:
      - ?next=
      - form next
    """
    try:
        nxt = (request.args.get("next") or request.form.get("next") or "")
    except Exception:
        nxt = ""

    nxt = _strip_and_decode(nxt)

    if nxt and is_safe_url(nxt):
        # Si viene absoluto del mismo host, devolvemos solo path+query para consistencia
        try:
            u = urlparse(nxt)
            if u.scheme and u.netloc:
                path = u.path or "/"
                if u.query:
                    path = f"{path}?{u.query}"
                return path
        except Exception:
            pass
        return nxt

    # fallback endpoint interno
    try:
        return url_for(default_endpoint, **endpoint_kwargs)
    except Exception:
        return "/"


__all__ = ["is_safe_url", "safe_next_url"]
