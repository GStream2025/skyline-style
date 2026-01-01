from __future__ import annotations

from urllib.parse import urlparse
from typing import Optional

from flask import request, url_for


# ============================================================
# URL / Redirect Security — FINAL
# ============================================================

def is_safe_url(target: Optional[str]) -> bool:
    """
    Valida que la URL sea interna.
    Bloquea:
      - http(s) externos
      - javascript:
      - //evil.com
    """
    if not target:
        return False

    try:
        ref_url = urlparse(request.host_url)
        test_url = urlparse(target)

        if test_url.scheme and test_url.scheme not in {"http", "https"}:
            return False

        return (
            not test_url.netloc
            or test_url.netloc == ref_url.netloc
        )
    except Exception:
        return False


def safe_next_url(
    default_endpoint: str = "main.index",
    **endpoint_kwargs,
) -> str:
    """
    Retorna next seguro o fallback a endpoint interno.
    """
    nxt = (
        request.args.get("next")
        or request.form.get("next")
        or ""
    ).strip()

    if nxt and is_safe_url(nxt):
        return nxt

    try:
        return url_for(default_endpoint, **endpoint_kwargs)
    except Exception:
        return "/"


__all__ = [
    "is_safe_url",
    "safe_next_url",
]
