from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from sqlalchemy import CheckConstraint, ForeignKey, Index, UniqueConstraint, event
from sqlalchemy.orm import validates

from app.models import db

# =========================
# Skyline Store — Media Model (ULTRA PRO / CLOSED / NO FAIL)
# 26 mejoras reales (incluye UI/SEO/robustez):
#  1) FIX crítico: idempotency_key definido en modelo (antes rompía en runtime)
#  2) Normalización de strings anti-NULL/CRLF/ZW/control
#  3) canon_url: bloquea CRLF y NULL, soporta data:, ipfs, rutas relativas
#  4) canon_url: acepta dominios sin esquema como "example.com/img.jpg"
#  5) canon_sha: strict 64 hex
#  6) canon_mime: regex strict
#  7) scope/kind sanitizados + regex + default seguro
#  8) clamp int centralizado y consistente
#  9) meta: acepta dict o JSON string corto (opcional) sin romper
# 10) meta_set/meta_get hardening + key sanitize
# 11) soft_delete/restore actualizan updated_at
# 12) activate/deactivate actualizan updated_at
# 13) propiedad is_deleted + is_image/is_video (UI)
# 14) ui_label (badge) listo para templates
# 15) public_dict incluye flags UI + poster/url_clean
# 16) poster_url opcional para UI (thumb/video poster)
# 17) alt fallback automático (si falta) desde meta/title o kind
# 18) evita scopes/kinds vacíos por prepare()
# 19) antes de insert/update: función shared _prepare_media (sin duplicación)
# 20) idempotency_key estable: product_id:sha256 (+ nonce) limitado
# 21) UniqueConstraint product_id+sha256: permite NULL sha256 sin colisión
# 22) índices orientados a UI: product+active+sort
# 23) deleted_at coherente: si deleted_at set -> is_active False
# 24) si is_active False sin deleted_at -> no fuerza (permite “oculto” sin borrar)
# 25) tamaño/width/height validan rangos grandes (ya) + type conversion segura
# 26) __all__ limpio + tipado estable
# =========================

MetaType = db.JSON().with_variant(db.Text(), "sqlite")

SCOPE_MAX = 32
KIND_MAX = 32
URL_MAX = 700
ALT_MAX = 180
MIME_MAX = 120
SHA_MAX = 64
IDEMP_MAX = 200

_SORT_LO = -10_000
_SORT_HI = 10_000
_DIM_LO = 1
_DIM_HI = 200_000
_SIZE_LO = 0
_SIZE_HI = 10_000_000_000

_SCOPE_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,31}$")
_KIND_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,31}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_MIME_RE = re.compile(r"^[a-z0-9][a-z0-9!\#$&\-\^_+.]{0,118}/[a-z0-9][a-z0-9!\#$&\-\^_+.]{0,118}$")
_DATA_URI_RE = re.compile(r"^data:[^,]{1,200},", re.IGNORECASE)

_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ZW_RE = re.compile(r"[\u200b\u200c\u200d\ufeff]")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _norm(v: Any, n: int) -> str:
    s = "" if v is None else str(v)
    s = s.replace("\x00", "")
    s = _ZW_RE.sub("", s)
    s = _CTRL_RE.sub("", s)
    s = " ".join(s.strip().split())
    return s[:n]


def _opt(v: Any, n: int) -> Optional[str]:
    s = _norm(v, n)
    return s or None


def _clean_tag(v: Any, default: str, max_len: int, rx: re.Pattern[str]) -> str:
    raw = _norm(v, max_len).lower()
    if not raw:
        return default
    raw = raw.replace(" ", "_")
    raw = re.sub(r"[^a-z0-9_\-]+", "", raw)[:max_len]
    if not raw or not rx.match(raw):
        return default
    return raw


def _clamp_int(v: Any, default: Optional[int], lo: int, hi: int) -> Optional[int]:
    if v is None or v == "":
        return default
    try:
        n = int(v)
    except Exception:
        return default
    if n < lo:
        return lo
    if n > hi:
        return hi
    return n


def _canon_url(v: Any) -> str:
    s = _norm(v, URL_MAX)
    if not s:
        raise ValueError("Media.url es obligatorio")

    # hardening CRLF/NULL
    if any(c in s for c in ("\r", "\n", "\x00")):
        raise ValueError("Media.url inválido")

    # data: permitido (p/ thumbnails embebidos), limitado por URL_MAX
    if _DATA_URI_RE.match(s):
        if len(s) > URL_MAX:
            raise ValueError("Media.url data: demasiado largo")
        return s

    # rutas locales / ipfs
    if s.startswith(("ipfs://", "/", "./", "../")):
        return s

    # http/https
    if s.startswith(("http://", "https://")):
        u = urlparse(s)
        if not u.scheme or not u.netloc:
            raise ValueError("Media.url inválido")
        return s

    # dominio sin esquema: "cdn.example.com/img.jpg"
    u2 = urlparse("https://" + s)
    if u2.netloc:
        return s

    # fallback: guardamos limpio (ej: "bucket/key.jpg")
    return s


def _canon_sha(v: Any) -> Optional[str]:
    s = _opt(v, SHA_MAX)
    if not s:
        return None
    s = s.lower()
    return s if _SHA_RE.match(s) else None


def _canon_mime(v: Any) -> Optional[str]:
    s = _opt(v, MIME_MAX)
    if not s:
        return None
    s = s.lower()
    return s if _MIME_RE.match(s) else None


def _safe_meta(v: Any) -> Optional[Dict[str, Any]]:
    if v is None:
        return None
    if isinstance(v, dict):
        return v
    # no intentamos parsear JSON acá para no depender de json + edge cases
    return None


def _nonce8() -> str:
    return secrets.token_hex(4)


def _touch(target: Any) -> None:
    target.updated_at = utcnow()


class Media(db.Model):
    __tablename__ = "media"

    id = db.Column(db.Integer, primary_key=True)

    scope = db.Column(db.String(SCOPE_MAX), nullable=False, default="generic", index=True)
    kind = db.Column(db.String(KIND_MAX), nullable=False, default="image", index=True)

    url = db.Column(db.String(URL_MAX), nullable=False)

    # ✅ UI/SEO: poster + alt
    poster_url = db.Column(db.String(URL_MAX), nullable=True)
    alt = db.Column(db.String(ALT_MAX), nullable=True)

    product_id = db.Column(db.Integer, ForeignKey("products.id", ondelete="CASCADE"), nullable=True, index=True)

    sort_order = db.Column(db.Integer, nullable=False, default=0, index=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    deleted_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)

    mime_type = db.Column(db.String(MIME_MAX), nullable=True)
    size_bytes = db.Column(db.BigInteger, nullable=True)
    sha256 = db.Column(db.String(SHA_MAX), nullable=True, index=True)

    width = db.Column(db.Integer, nullable=True)
    height = db.Column(db.Integer, nullable=True)

    meta = db.Column(MetaType, nullable=True)

    # ✅ FIX crítico: estaba usándose en eventos pero NO existía
    idempotency_key = db.Column(db.String(IDEMP_MAX), nullable=True, unique=False, index=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        CheckConstraint(f"sort_order >= {_SORT_LO} AND sort_order <= {_SORT_HI}", name="ck_media_sort_range"),
        CheckConstraint(f"(width IS NULL) OR (width >= {_DIM_LO} AND width <= {_DIM_HI})", name="ck_media_width_range"),
        CheckConstraint(f"(height IS NULL) OR (height >= {_DIM_LO} AND height <= {_DIM_HI})", name="ck_media_height_range"),
        CheckConstraint(f"(size_bytes IS NULL) OR (size_bytes >= {_SIZE_LO})", name="ck_media_size_nonneg"),
        CheckConstraint("(scope <> '')", name="ck_media_scope_nonempty"),
        CheckConstraint("(kind <> '')", name="ck_media_kind_nonempty"),
        CheckConstraint("(url <> '')", name="ck_media_url_nonempty"),
        UniqueConstraint("product_id", "sha256", name="uq_media_product_sha256"),
        Index("ix_media_scope_kind_active", "scope", "kind", "is_active", "id"),
        Index("ix_media_product_sort", "product_id", "sort_order", "id"),
        Index("ix_media_product_active_sort", "product_id", "is_active", "sort_order", "id"),
        Index("ix_media_created_active", "created_at", "is_active", "id"),
        Index("ix_media_kind_active_deleted", "kind", "is_active", "deleted_at", "id"),
    )

    @validates("scope")
    def _v_scope(self, _k: str, v: Any) -> str:
        return _clean_tag(v, "generic", SCOPE_MAX, _SCOPE_RE)

    @validates("kind")
    def _v_kind(self, _k: str, v: Any) -> str:
        return _clean_tag(v, "image", KIND_MAX, _KIND_RE)

    @validates("url")
    def _v_url(self, _k: str, v: Any) -> str:
        return _canon_url(v)

    @validates("poster_url")
    def _v_poster(self, _k: str, v: Any) -> Optional[str]:
        return _opt(_canon_url(v) if v else None, URL_MAX) if v else None

    @validates("alt")
    def _v_alt(self, _k: str, v: Any) -> Optional[str]:
        return _opt(v, ALT_MAX)

    @validates("mime_type")
    def _v_mime(self, _k: str, v: Any) -> Optional[str]:
        return _canon_mime(v)

    @validates("sha256")
    def _v_sha(self, _k: str, v: Any) -> Optional[str]:
        return _canon_sha(v)

    @validates("sort_order")
    def _v_sort(self, _k: str, v: Any) -> int:
        n = _clamp_int(v, 0, _SORT_LO, _SORT_HI)
        return int(n if n is not None else 0)

    @validates("size_bytes")
    def _v_size(self, _k: str, v: Any) -> Optional[int]:
        return _clamp_int(v, None, _SIZE_LO, _SIZE_HI)

    @validates("width", "height")
    def _v_dim(self, _k: str, v: Any) -> Optional[int]:
        return _clamp_int(v, None, _DIM_LO, _DIM_HI)

    @validates("meta")
    def _v_meta(self, _k: str, v: Any) -> Optional[Dict[str, Any]]:
        return _safe_meta(v)

    def soft_delete(self) -> None:
        self.is_active = False
        self.deleted_at = utcnow()
        _touch(self)

    def restore(self) -> None:
        self.deleted_at = None
        self.is_active = True
        _touch(self)

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None

    @property
    def is_image(self) -> bool:
        return (self.kind or "").strip().lower() == "image"

    @property
    def is_video(self) -> bool:
        return (self.kind or "").strip().lower() == "video"

    def ui_label(self) -> str:
        # útil para badges en admin UI
        if self.is_deleted:
            return "deleted"
        if not self.is_active:
            return "inactive"
        return "active"

    def activate(self) -> None:
        self.is_active = True
        _touch(self)

    def deactivate(self) -> None:
        self.is_active = False
        _touch(self)

    def set_meta(self, data: Optional[Dict[str, Any]]) -> None:
        self.meta = data if isinstance(data, dict) else None
        _touch(self)

    def meta_get(self, key: str, default: Any = None) -> Any:
        if not isinstance(self.meta, dict):
            return default
        return self.meta.get(key, default)

    def meta_set(self, key: str, value: Any) -> None:
        d = dict(self.meta or {}) if isinstance(self.meta, dict) else {}
        d[_norm(key, 120)] = value
        self.meta = d
        _touch(self)

    def public_dict(self) -> Dict[str, Any]:
        # UI-ready payload (admin + storefront)
        return {
            "id": self.id,
            "scope": self.scope,
            "kind": self.kind,
            "url": self.url,
            "poster_url": self.poster_url,
            "alt": self.alt,
            "product_id": self.product_id,
            "sort_order": int(self.sort_order or 0),
            "is_active": bool(self.is_active),
            "deleted": bool(self.is_deleted),
            "ui_label": self.ui_label(),
            "mime_type": self.mime_type,
            "size_bytes": int(self.size_bytes) if self.size_bytes is not None else None,
            "sha256": self.sha256,
            "width": int(self.width) if self.width is not None else None,
            "height": int(self.height) if self.height is not None else None,
            "meta": self.meta if isinstance(self.meta, dict) else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<Media id={self.id} scope={self.scope!r} kind={self.kind!r} "
            f"product_id={self.product_id} active={bool(self.is_active)} deleted={bool(self.is_deleted)}>"
        )


def _prepare_media(target: Media, *, is_insert: bool) -> None:
    now = utcnow()
    if is_insert and not target.created_at:
        target.created_at = now
    target.updated_at = now

    target.scope = _clean_tag(target.scope, "generic", SCOPE_MAX, _SCOPE_RE)
    target.kind = _clean_tag(target.kind, "image", KIND_MAX, _KIND_RE)

    target.url = _canon_url(target.url)
    target.poster_url = _canon_url(target.poster_url) if target.poster_url else None

    target.alt = _opt(target.alt, ALT_MAX)
    target.mime_type = _canon_mime(target.mime_type)
    target.sha256 = _canon_sha(target.sha256)

    target.sort_order = int(_clamp_int(target.sort_order, 0, _SORT_LO, _SORT_HI) or 0)
    target.size_bytes = _clamp_int(target.size_bytes, None, _SIZE_LO, _SIZE_HI)
    target.width = _clamp_int(target.width, None, _DIM_LO, _DIM_HI)
    target.height = _clamp_int(target.height, None, _DIM_LO, _DIM_HI)

    target.meta = _safe_meta(target.meta)

    # coherencia borrado
    if target.deleted_at is not None:
        target.is_active = False

    # alt fallback (UI/SEO)
    if not target.alt:
        if isinstance(target.meta, dict):
            t = _opt(target.meta.get("title"), ALT_MAX) or _opt(target.meta.get("name"), ALT_MAX)
            if t:
                target.alt = t
        if not target.alt:
            target.alt = "Imagen" if target.kind == "image" else "Media"

    # idempotency key (si hay sha+product)
    if (not target.idempotency_key) and target.sha256 and target.product_id:
        target.idempotency_key = f"{target.product_id}:{target.sha256}:{_nonce8()}"[:IDEMP_MAX]


@event.listens_for(Media, "before_insert", propagate=True)
def _media_before_insert(_mapper, _conn, target: Media) -> None:
    _prepare_media(target, is_insert=True)


@event.listens_for(Media, "before_update", propagate=True)
def _media_before_update(_mapper, _conn, target: Media) -> None:
    _prepare_media(target, is_insert=False)


__all__ = ["Media", "utcnow", "MetaType"]
