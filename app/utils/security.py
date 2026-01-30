from __future__ import annotations

import os
import re
from typing import Optional
from urllib.parse import urlparse, unquote

from flask import redirect, request, url_for

_CTRL_RE = re.compile(r"[\x00-\x1F\x7F]")
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

_DEFAULT_PREFIXES = "/"
_SAFE_PREFIXES_ENV = (os.getenv("SAFE_NEXT_PREFIXES") or "").strip()


def _safe_strip(s: Optional[str], *, max_len: int = 2048) -> str:
    if s is None:
        return ""
    out = str(s).replace("\x00", "").replace("\u200b", "").strip()
    if max_len > 0 and len(out) > max_len:
        out = out[:max_len]
    return out


def _decode_once(s: str) -> str:
    try:
        return unquote(s)
    except Exception:
        return s


def _normalize_target(raw: Optional[str]) -> str:
    s = _safe_strip(raw)
    if not s:
        return ""
    s = _decode_once(s)
    s = _CTRL_RE.sub("", s).strip()
    if not s:
        return ""
    s2 = _decode_once(s)
    if s2 != s:
        s = _CTRL_RE.sub("", s2).strip()
    return s


def _allowed_prefixes() -> list[str]:
    raw = _SAFE_PREFIXES_ENV
    if not raw:
        return [_DEFAULT_PREFIXES]
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    out: list[str] = []
    for p in parts:
        if not p.startswith("/"):
            p = "/" + p
        out.append(p)
    return out or [_DEFAULT_PREFIXES]


def _matches_prefix(path: str) -> bool:
    prefixes = _allowed_prefixes()
    if prefixes == ["/"]:
        return True
    return any(path.startswith(p) for p in prefixes)


def _same_host(url: str) -> bool:
    try:
        test = urlparse(url)
        if not test.netloc:
            return False

        try:
            req_host = urlparse(request.host_url).netloc
        except Exception:
            req_host = ""

        cfg_hosts = set()
        for k in ("SITE_URL", "APP_URL", "RENDER_EXTERNAL_URL"):
            v = (os.getenv(k) or "").strip()
            if v:
                try:
                    cfg_hosts.add(urlparse(v if "://" in v else f"https://{v}").netloc)
                except Exception:
                    pass

        server_name = (os.getenv("SERVER_NAME") or "").strip()
        if server_name:
            cfg_hosts.add(server_name)

        allowed = {h for h in {req_host, *cfg_hosts} if h}
        return bool(allowed) and (test.netloc in allowed)
    except Exception:
        return False


def is_safe_url(target: Optional[str]) -> bool:
    t = _normalize_target(target)
    if not t:
        return False

    if "\\" in t:
        return False
    if t.startswith("//"):
        return False

    if t.startswith("/"):
        if t.startswith("/\\"):
            return False
        parsed = urlparse(t)
        path = parsed.path or "/"
        if not path.startswith("/"):
            path = "/" + path
        return _matches_prefix(path)

    parsed = urlparse(t)
    scheme = (parsed.scheme or "").lower()
    if not scheme or scheme not in {"http", "https"}:
        return False
    if scheme in _BAD_SCHEMES:
        return False
    if not parsed.netloc:
        return False
    if not _same_host(t):
        return False

    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return _matches_prefix(path)


def safe_next_url(default_endpoint: str = "main.home", **endpoint_kwargs) -> str:
    try:
        raw = request.args.get("next") or request.form.get("next") or ""
    except Exception:
        raw = ""

    nxt = _normalize_target(raw)
    if nxt and is_safe_url(nxt):
        try:
            u = urlparse(nxt)
            if u.scheme and u.netloc:
                out = u.path or "/"
                if u.query:
                    out = f"{out}?{u.query}"
                if u.fragment:
                    out = f"{out}#{u.fragment}"
                return out
        except Exception:
            pass
        return nxt

    try:
        return url_for(default_endpoint, **endpoint_kwargs)
    except Exception:
        return "/"


def safe_redirect(default_endpoint: str = "main.home", **endpoint_kwargs):
    return redirect(safe_next_url(default_endpoint, **endpoint_kwargs), code=302)


def with_next(url: str, next_value: str) -> str:
    base = _safe_strip(url, max_len=2048)
    nxt = _normalize_target(next_value)
    if not base:
        base = "/"
    if not nxt or not is_safe_url(nxt):
        return base
    sep = "&" if "?" in base else "?"
    return f"{base}{sep}next={nxt}"
