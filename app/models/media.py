from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import ForeignKey, Index
from sqlalchemy.orm import validates

from app.models import db

MetaType = db.JSON().with_variant(db.Text(), "sqlite")

_SCOPE_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,31}$")
_KIND_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,31}$")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _s(v: Optional[str], max_len: int) -> Optional[str]:
    if v is None:
        return None
    out = str(v).strip()
    if not out:
        return None
    return out[:max_len]


def _clamp_int(v: Any, lo: int, hi: int) -> Optional[int]:
    if v is None:
        return None
    try:
        n = int(v)
    except Exception:
        return None
    if n < lo:
        return lo
    if n > hi:
        return hi
    return n


def _norm_tag(v: Optional[str], default: str) -> str:
    raw = (v or "").strip().lower()
    if not raw:
        return default
    raw = raw.replace(" ", "_")
    raw = re.sub(r"[^a-z0-9_\-]+", "", raw)[:32]
    if not raw:
        return default
    return raw


def _url_is_plausible(url: str) -> bool:
    u = (url or "").strip()
    if not u:
        return False
    if u.startswith(("http://", "https://", "ipfs://", "data:", "/")):
        return True
    if u.startswith("./") or u.startswith("../"):
        return True
    if "://" in u:
        return True
    return True


class Media(db.Model):
    __tablename__ = "media"

    id = db.Column(db.Integer, primary_key=True)

    scope = db.Column(db.String(32), nullable=False, default="generic", index=True)
    kind = db.Column(db.String(32), nullable=False, default="image", index=True)

    url = db.Column(db.String(700), nullable=False)
    alt = db.Column(db.String(180), nullable=True)

    product_id = db.Column(
        db.Integer,
        ForeignKey("products.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    sort_order = db.Column(db.Integer, nullable=False, default=0)
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    deleted_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)

    mime_type = db.Column(db.String(120), nullable=True)
    size_bytes = db.Column(db.Integer, nullable=True)
    sha256 = db.Column(db.String(64), nullable=True, index=True)

    width = db.Column(db.Integer, nullable=True)
    height = db.Column(db.Integer, nullable=True)

    meta = db.Column(MetaType, nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)

    @validates("scope")
    def _v_scope(self, _k: str, v: str) -> str:
        out = _norm_tag(v, "generic")
        return out if _SCOPE_RE.match(out) else "generic"

    @validates("kind")
    def _v_kind(self, _k: str, v: str) -> str:
        out = _norm_tag(v, "image")
        return out if _KIND_RE.match(out) else "image"

    @validates("url")
    def _v_url(self, _k: str, v: str) -> str:
        out = (v or "").strip()
        if not out:
            raise ValueError("Media.url es obligatorio")
        if len(out) > 700:
            out = out[:700]
        if not _url_is_plausible(out):
            raise ValueError("Media.url inválido")
        return out

    @validates("alt")
    def _v_alt(self, _k: str, v: Optional[str]) -> Optional[str]:
        out = _s(v, 180)
        return out

    @validates("mime_type")
    def _v_mime(self, _k: str, v: Optional[str]) -> Optional[str]:
        out = _s(v, 120)
        return out.lower() if out else None

    @validates("sha256")
    def _v_sha(self, _k: str, v: Optional[str]) -> Optional[str]:
        out = _s(v, 64)
        if not out:
            return None
        out2 = out.lower()
        if len(out2) != 64 or not re.fullmatch(r"[0-9a-f]{64}", out2):
            return None
        return out2

    @validates("sort_order")
    def _v_sort(self, _k: str, v: Any) -> int:
        n = _clamp_int(v, -10_000, 10_000)
        return int(n if n is not None else 0)

    @validates("size_bytes")
    def _v_size(self, _k: str, v: Any) -> Optional[int]:
        return _clamp_int(v, 0, 10_000_000_000)

    @validates("width", "height")
    def _v_dim(self, _k: str, v: Any) -> Optional[int]:
        return _clamp_int(v, 1, 200_000)

    @validates("meta")
    def _v_meta(self, _k: str, v: Any) -> Optional[Dict[str, Any]]:
        if v is None:
            return None
        if isinstance(v, dict):
            return v
        return None

    def soft_delete(self) -> None:
        self.is_active = False
        self.deleted_at = utcnow()

    def restore(self) -> None:
        self.deleted_at = None
        self.is_active = True

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None

    def set_meta(self, data: Optional[Dict[str, Any]]) -> None:
        self.meta = data if isinstance(data, dict) else None

    def meta_get(self, key: str, default: Any = None) -> Any:
        if not isinstance(self.meta, dict):
            return default
        return self.meta.get(key, default)

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
        return f"<Media id={self.id} scope={self.scope!r} kind={self.kind!r} product_id={self.product_id} active={bool(self.is_active)} deleted={bool(self.deleted_at is not None)}>"


Index("ix_media_scope_kind_active", Media.scope, Media.kind, Media.is_active)
Index("ix_media_product_sort", Media.product_id, Media.sort_order)
Index("ix_media_created_active", Media.created_at, Media.is_active)
Index("ix_media_kind_active_deleted", Media.kind, Media.is_active, Media.deleted_at)
