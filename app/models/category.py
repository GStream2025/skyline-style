from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import CheckConstraint, Index, UniqueConstraint, event
from sqlalchemy.orm import validates

from app.models import db

# ----------------------------
# Constants / Limits
# ----------------------------
_SLUG_MAX = 160
_NAME_MAX = 120
_TITLE_MAX = 180
_DESC_MAX = 260
_PATH_MAX = 700

# Slug & path helpers
_slug_re = re.compile(r"[^a-z0-9\-]+")
_space_re = re.compile(r"\s+")
_dash_re = re.compile(r"-{2,}")


def utcnow() -> datetime:
    """UTC aware now (stable for DB defaults)."""
    return datetime.now(timezone.utc)


def _clip_str(v: Any, n: int) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    return s[:n] if s else None


def _clean_text(v: Any, n: int) -> str:
    # ✅ removes null-bytes, collapses whitespace, clamps
    s = _clip_str(v, n) or ""
    if "\x00" in s:
        s = s.replace("\x00", "")
    s = " ".join(s.split())
    return s[:n]


def _clamp_int(v: Any, default: int = 0, min_v: int = -1_000_000, max_v: int = 1_000_000) -> int:
    try:
        n = int(v)
    except Exception:
        return default
    if n < min_v:
        return min_v
    if n > max_v:
        return max_v
    return n


def _ascii_fold(s: str) -> str:
    # ✅ stable ASCII folding (keeps letters/numbers)
    s2 = unicodedata.normalize("NFKD", s)
    return "".join(ch for ch in s2 if not unicodedata.combining(ch))


def slugify(text: Optional[str], max_len: int = _SLUG_MAX) -> str:
    """
    ✅ deterministic slug:
    - lowercase
    - ascii fold
    - spaces -> dash
    - removes non [a-z0-9-]
    - collapses dashes
    """
    s = (text or "").strip().lower()
    if not s:
        return "categoria"
    s = _ascii_fold(s)
    s = _space_re.sub("-", s)
    s = _slug_re.sub("", s)
    s = _dash_re.sub("-", s).strip("-")
    return (s or "categoria")[:max_len]


def _canon_slug(v: Any) -> str:
    return slugify(str(v) if v is not None else "", _SLUG_MAX)


def _safe_parent_id(v: Any) -> Optional[int]:
    try:
        if v is None or v == "":
            return None
        n = int(v)
        return n if n > 0 else None
    except Exception:
        return None


def _clean_slug_path(v: Any) -> Optional[str]:
    """
    ✅ canonical path like "parent/child":
    - strips leading/trailing slashes
    - collapses spaces
    - removes null bytes
    - clamps length
    """
    s = _clip_str(v, _PATH_MAX)
    if not s:
        return None
    s = s.replace("\x00", "").strip().strip("/")
    if not s:
        return None
    s = _space_re.sub("-", s)
    return s[:_PATH_MAX] if s else None


class Category(db.Model):
    __tablename__ = "categories"

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(_NAME_MAX), nullable=False)

    # ✅ keep unique + index; (unique already implies index in most DBs,
    # but explicit index helps sqlite and query planners; OK)
    slug = db.Column(db.String(_SLUG_MAX), nullable=False, unique=True, index=True)

    parent_id = db.Column(
        db.Integer,
        db.ForeignKey("categories.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    sort_order = db.Column(db.Integer, nullable=False, default=0, index=True)

    seo_title = db.Column(db.String(_TITLE_MAX), nullable=True)
    seo_description = db.Column(db.String(_DESC_MAX), nullable=True)

    # ✅ IMPORTANT FIX:
    # keep index=True OR Index(...) in __table_args__, NOT BOTH.
    # We'll keep index=True and REMOVE the explicit Index for slug_path below.
    slug_path = db.Column(db.String(_PATH_MAX), nullable=True, index=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow, index=True)

    parent = db.relationship(
        "Category",
        remote_side=[id],
        backref=db.backref("children", lazy="select", order_by="Category.sort_order.asc()"),
        lazy="select",
    )

    __table_args__ = (
        # ✅ data integrity
        CheckConstraint("sort_order >= -1000000 AND sort_order <= 1000000", name="ck_categories_sort_range"),
        CheckConstraint("slug <> ''", name="ck_categories_slug_nonempty"),
        CheckConstraint("name <> ''", name="ck_categories_name_nonempty"),

        # ✅ keep explicit unique constraint name (helps migrations / clarity)
        UniqueConstraint("slug", name="uq_categories_slug"),

        # ✅ composite indexes for common filters/sorts
        Index("ix_categories_active_sort", "active", "sort_order", "id"),
        Index("ix_categories_parent_sort", "parent_id", "sort_order", "id"),

        # ❌ REMOVED to avoid duplicate with slug_path index=True:
        # Index("ix_categories_slug_path", "slug_path"),
    )

    # ----------------------------
    # Convenience
    # ----------------------------
    @property
    def is_active(self) -> bool:
        return bool(self.active)

    @property
    def status(self) -> str:
        return "active" if self.active else "hidden"

    def is_root(self) -> bool:
        return self.parent_id is None

    # ----------------------------
    # Validators
    # ----------------------------
    @validates("name")
    def _v_name(self, _k: str, v: Any) -> str:
        s = _clean_text(v, _NAME_MAX)
        return s or "Categoría"

    @validates("slug")
    def _v_slug(self, _k: str, v: Any) -> str:
        return _canon_slug(v)

    @validates("parent_id")
    def _v_parent(self, _k: str, v: Any) -> Optional[int]:
        return _safe_parent_id(v)

    @validates("sort_order")
    def _v_sort(self, _k: str, v: Any) -> int:
        return _clamp_int(v, default=0)

    @validates("seo_title")
    def _v_seo_title(self, _k: str, v: Any) -> Optional[str]:
        s = _clean_text(v, _TITLE_MAX)
        return s or None

    @validates("seo_description")
    def _v_seo_description(self, _k: str, v: Any) -> Optional[str]:
        s = _clean_text(v, _DESC_MAX)
        return s or None

    @validates("slug_path")
    def _v_slug_path(self, _k: str, v: Any) -> Optional[str]:
        return _clean_slug_path(v)

    # ----------------------------
    # Path building
    # ----------------------------
    def ancestors(self) -> List["Category"]:
        """
        ✅ in-memory ancestor chain (uses relationship).
        Safe against loops.
        """
        out: List["Category"] = []
        cur = self.parent
        seen: set[int] = set()
        while cur is not None:
            cid = getattr(cur, "id", None)
            if isinstance(cid, int):
                if cid in seen:
                    break
                seen.add(cid)
            out.append(cur)
            cur = cur.parent
        out.reverse()
        return out

    def full_path_slugs(self) -> List[str]:
        parts = [c.slug for c in self.ancestors()] + [self.slug]
        return [p for p in parts if p]

    def compute_slug_path(self) -> str:
        parts = self.full_path_slugs()
        s = "/".join(parts) if parts else (self.slug or "categoria")
        return s[:_PATH_MAX]

    def compute_slug_path_db_safe(self) -> str:
        """
        ✅ DB-walk path, safe if relationship not loaded.
        Uses session.get; avoids recursion/loops.
        """
        parts: List[str] = []
        cur_id = self.parent_id
        seen: set[int] = set()
        while cur_id:
            cid = int(cur_id)
            if cid in seen:
                break
            seen.add(cid)

            parent = db.session.get(Category, cid)
            if not parent:
                break
            if parent.slug:
                parts.append(parent.slug)
            cur_id = parent.parent_id

        parts.reverse()
        if self.slug:
            parts.append(self.slug)
        s = "/".join(parts) if parts else (self.slug or "categoria")
        return s[:_PATH_MAX]

    def ensure_slug_path(self) -> None:
        self.slug_path = self.compute_slug_path()

    # ----------------------------
    # Serialization
    # ----------------------------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "slug": self.slug,
            "parent_id": self.parent_id,
            "active": bool(self.active),
            "sort_order": int(self.sort_order or 0),
            "seo_title": self.seo_title,
            "seo_description": self.seo_description,
            "slug_path": self.slug_path,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return f"<Category id={self.id} name={self.name!r} slug={self.slug!r} parent_id={self.parent_id}>"


def _touch_and_paths(target: Category) -> None:
    """
    ✅ central pre-save normalization:
    - ensures name/slug
    - updates timestamps
    - ensures slug_path (DB-safe)
    """
    # name fallback
    if not (target.name or "").strip():
        target.name = "Categoría"

    # slug from name if missing/empty
    if not (target.slug or "").strip():
        target.slug = target.name
    target.slug = _canon_slug(target.slug or target.name)

    # timestamps
    now = utcnow()
    if not target.created_at:
        target.created_at = now
    target.updated_at = now

    # slug_path
    try:
        target.slug_path = target.compute_slug_path_db_safe()
    except Exception:
        target.slug_path = (target.slug or "categoria")[:_PATH_MAX]


@event.listens_for(Category, "before_insert", propagate=True)
def _cat_before_insert(_mapper, _conn, target: Category) -> None:
    _touch_and_paths(target)


@event.listens_for(Category, "before_update", propagate=True)
def _cat_before_update(_mapper, _conn, target: Category) -> None:
    _touch_and_paths(target)


__all__ = ["Category", "slugify", "utcnow"]
