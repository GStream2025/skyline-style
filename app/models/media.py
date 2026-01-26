from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from sqlalchemy import CheckConstraint, ForeignKey, Index, UniqueConstraint, event
from sqlalchemy.orm import validates

from app.models import db

MetaType = db.JSON().with_variant(db.Text(), "sqlite")

SCOPE_MAX = 32
KIND_MAX = 32
URL_MAX = 700
ALT_MAX = 180
MIME_MAX = 120
SHA_MAX = 64

_SCOPE_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,31}$")
_KIND_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,31}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_MIME_RE = re.compile(r"^[a-z0-9][a-z0-9!\#$&\-\^_+.]{0,118}/[a-z0-9][a-z0-9!\#$&\-\^_+.]{0,118}$")
_DATA_URI_RE = re.compile(r"^data:[^,]{1,200},", re.IGNORECASE)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _clip_str(v: Any, n: int) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip().replace("\x00", "")
    if not s:
        return None
    return s[:n]


def _clean_tag(v: Any, default: str, max_len: int) -> str:
    raw = (str(v) if v is not None else "").strip().lower()
    if not raw:
        return default
    raw = raw.replace(" ", "_")
    raw = re.sub(r"[^a-z0-9_\-]+", "", raw)[:max_len]
    if not raw:
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
    s = (str(v) if v is not None else "").strip().replace("\x00", "")
    if not s:
        raise ValueError("Media.url es obligatorio")
    if len(s) > URL_MAX:
        s = s[:URL_MAX]
    if _DATA_URI_RE.match(s):
        if len(s) > URL_MAX:
            raise ValueError("Media.url data: demasiado largo")
        return s

    if s.startswith(("/", "./", "../")):
        return s

    if s.startswith("ipfs://"):
        return s

    if s.startswith(("http://", "https://")):
        try:
            u = urlparse(s)
            if not u.scheme or not u.netloc:
                raise ValueError("Media.url inválido")
            return s
        except Exception as e:
            raise ValueError("Media.url inválido") from e

    try:
        u2 = urlparse("https://" + s)
        if u2.netloc:
            return s
    except Exception:
        pass

    return s


def _canon_sha(v: Any) -> Optional[str]:
    s = _clip_str(v, SHA_MAX)
    if not s:
        return None
    s = s.lower()
    return s if _SHA_RE.match(s) else None


def _canon_mime(v: Any) -> Optional[str]:
    s = _clip_str(v, MIME_MAX)
    if not s:
        return None
    s = s.lower()
    return s if _MIME_RE.match(s) else None


def _safe_meta(v: Any) -> Optional[Dict[str, Any]]:
    if v is None:
        return None
    if isinstance(v, dict):
        return v
    return None


def _nonce8() -> str:
    return secrets.token_hex(4)


class Media(db.Model):
    __tablename__ = "media"

    id = db.Column(db.Integer, primary_key=True)

    scope = db.Column(db.String(SCOPE_MAX), nullable=False, default="generic", index=True)
    kind = db.Column(db.String(KIND_MAX), nullable=False, default="image", index=True)

    url = db.Column(db.String(URL_MAX), nullable=False)
    alt = db.Column(db.String(ALT_MAX), nullable=True)

    product_id = db.Column(
        db.Integer,
        ForeignKey("products.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    sort_order = db.Column(db.Integer, nullable=False, default=0, index=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    deleted_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)

    mime_type = db.Column(db.String(MIME_MAX), nullable=True)
    size_bytes = db.Column(db.BigInteger, nullable=True)
    sha256 = db.Column(db.String(SHA_MAX), nullable=True, index=True)

    width = db.Column(db.Integer, nullable=True)
    height = db.Column(db.Integer, nullable=True)

    meta = db.Column(MetaType, nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        CheckConstraint("sort_order >= -10000 AND sort_order <= 10000", name="ck_media_sort_range"),
        CheckConstraint("(width IS NULL) OR (width >= 1 AND width <= 200000)", name="ck_media_width_range"),
        CheckConstraint("(height IS NULL) OR (height >= 1 AND height <= 200000)", name="ck_media_height_range"),
        CheckConstraint("(size_bytes IS NULL) OR (size_bytes >= 0)", name="ck_media_size_nonneg"),
        CheckConstraint("(scope <> '')", name="ck_media_scope_nonempty"),
        CheckConstraint("(kind <> '')", name="ck_media_kind_nonempty"),
        CheckConstraint("(url <> '')", name="ck_media_url_nonempty"),
        UniqueConstraint("product_id", "sha256", name="uq_media_product_sha256"),
        Index("ix_media_scope_kind_active", "scope", "kind", "is_active", "id"),
        Index("ix_media_product_sort", "product_id", "sort_order", "id"),
        Index("ix_media_created_active", "created_at", "is_active", "id"),
        Index("ix_media_kind_active_deleted", "kind", "is_active", "deleted_at", "id"),
    )

    @validates("scope")
    def _v_scope(self, _k: str, v: Any) -> str:
        out = _clean_tag(v, "generic", SCOPE_MAX)
        return out if _SCOPE_RE.match(out) else "generic"

    @validates("kind")
    def _v_kind(self, _k: str, v: Any) -> str:
        out = _clean_tag(v, "image", KIND_MAX)
        return out if _KIND_RE.match(out) else "image"

    @validates("url")
    def _v_url(self, _k: str, v: Any) -> str:
        return _canon_url(v)

    @validates("alt")
    def _v_alt(self, _k: str, v: Any) -> Optional[str]:
        return _clip_str(v, ALT_MAX)

    @validates("mime_type")
    def _v_mime(self, _k: str, v: Any) -> Optional[str]:
        return _canon_mime(v)

    @validates("sha256")
    def _v_sha(self, _k: str, v: Any) -> Optional[str]:
        return _canon_sha(v)

    @validates("sort_order")
    def _v_sort(self, _k: str, v: Any) -> int:
        n = _clamp_int(v, 0, -10_000, 10_000)
        return int(n if n is not None else 0)

    @validates("size_bytes")
    def _v_size(self, _k: str, v: Any) -> Optional[int]:
        return _clamp_int(v, None, 0, 10_000_000_000)

    @validates("width", "height")
    def _v_dim(self, _k: str, v: Any) -> Optional[int]:
        return _clamp_int(v, None, 1, 200_000)

    @validates("meta")
    def _v_meta(self, _k: str, v: Any) -> Optional[Dict[str, Any]]:
        return _safe_meta(v)

    def soft_delete(self) -> None:
        self.is_active = False
        self.deleted_at = utcnow()

    def restore(self) -> None:
        self.deleted_at = None
        self.is_active = True

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None

    def activate(self) -> None:
        self.is_active = True

    def deactivate(self) -> None:
        self.is_active = False

    def set_meta(self, data: Optional[Dict[str, Any]]) -> None:
        self.meta = data if isinstance(data, dict) else None

    def meta_get(self, key: str, default: Any = None) -> Any:
        if not isinstance(self.meta, dict):
            return default
        return self.meta.get(key, default)

    def meta_set(self, key: str, value: Any) -> None:
        d = dict(self.meta or {}) if isinstance(self.meta, dict) else {}
        d[str(key)] = value
        self.meta = d

    def public_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scope": self.scope,
            "kind": self.kind,
            "url": self.url,
            "alt": self.alt,
            "product_id": self.product_id,
            "sort_order": int(self.sort_order or 0),
            "is_active": bool(self.is_active),
            "deleted": bool(self.deleted_at is not None),
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
            f"product_id={self.product_id} active={bool(self.is_active)} deleted={bool(self.deleted_at is not None)}>"
        )


@event.listens_for(Media, "before_insert", propagate=True)
def _media_before_insert(_mapper, _conn, target: Media) -> None:
    now = utcnow()
    if not target.created_at:
        target.created_at = now
    target.updated_at = now
    if not (target.scope or "").strip():
        target.scope = "generic"
    if not (target.kind or "").strip():
        target.kind = "image"
    target.scope = _clean_tag(target.scope, "generic", SCOPE_MAX)
    target.kind = _clean_tag(target.kind, "image", KIND_MAX)
    if not _SCOPE_RE.match(target.scope):
        target.scope = "generic"
    if not _KIND_RE.match(target.kind):
        target.kind = "image"
    target.url = _canon_url(target.url)
    target.alt = _clip_str(target.alt, ALT_MAX)
    target.mime_type = _canon_mime(target.mime_type)
    target.sha256 = _canon_sha(target.sha256)
    target.sort_order = int(_clamp_int(target.sort_order, 0, -10_000, 10_000) or 0)
    target.size_bytes = _clamp_int(target.size_bytes, None, 0, 10_000_000_000)
    target.width = _clamp_int(target.width, None, 1, 200_000)
    target.height = _clamp_int(target.height, None, 1, 200_000)
    target.meta = _safe_meta(target.meta)


@event.listens_for(Media, "before_update", propagate=True)
def _media_before_update(_mapper, _conn, target: Media) -> None:
    target.updated_at = utcnow()
    if target.scope:
        target.scope = _clean_tag(target.scope, "generic", SCOPE_MAX)
        if not _SCOPE_RE.match(target.scope):
            target.scope = "generic"
    if target.kind:
        target.kind = _clean_tag(target.kind, "image", KIND_MAX)
        if not _KIND_RE.match(target.kind):
            target.kind = "image"
    if target.url:
        target.url = _canon_url(target.url)
    target.alt = _clip_str(target.alt, ALT_MAX)
    target.mime_type = _canon_mime(target.mime_type)
    target.sha256 = _canon_sha(target.sha256)
    target.sort_order = int(_clamp_int(target.sort_order, 0, -10_000, 10_000) or 0)
    target.size_bytes = _clamp_int(target.size_bytes, None, 0, 10_000_000_000)
    target.width = _clamp_int(target.width, None, 1, 200_000)
    target.height = _clamp_int(target.height, None, 1, 200_000)
    target.meta = _safe_meta(target.meta)


__all__ = ["Media", "utcnow", "MetaType"]
