from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional, List

from sqlalchemy import event
from sqlalchemy.orm import validates

from app.models import db  # ✅ db ÚNICO


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


_slug_re = re.compile(r"[^a-z0-9\-]+")


def slugify(text: str, max_len: int = 160) -> str:
    """Slug simple sin deps. Mantiene compat y evita basura."""
    s = (text or "").strip().lower()
    s = s.replace("á", "a").replace("é", "e").replace("í", "i").replace("ó", "o").replace("ú", "u").replace("ñ", "n")
    s = re.sub(r"\s+", "-", s)
    s = _slug_re.sub("", s)
    s = re.sub(r"-{2,}", "-", s).strip("-")
    if not s:
        s = "categoria"
    return s[:max_len]


class Category(db.Model):
    """
    Skyline Store — Category ULTRA PRO (FINAL)

    ✅ Marketplace real:
    - Árbol infinito (parent/children)
    - active (soft hide)
    - sort_order
    - SEO
    - slug_path jerárquico cacheado
    - compat: status/is_active sin tocar DB
    """

    __tablename__ = "categories"

    id = db.Column(db.Integer, primary_key=True)

    # Base
    name = db.Column(db.String(120), nullable=False)
    slug = db.Column(db.String(160), nullable=False, unique=True, index=True)

    # Jerarquía
    parent_id = db.Column(
        db.Integer,
        db.ForeignKey("categories.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Control marketplace
    active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    sort_order = db.Column(db.Integer, nullable=False, default=0, index=True)

    # SEO opcional
    seo_title = db.Column(db.String(180), nullable=True)
    seo_description = db.Column(db.String(260), nullable=True)

    # Path cacheado (opcional)
    slug_path = db.Column(db.String(700), nullable=True, index=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow, index=True)

    # Relación: parent -> children
    parent = db.relationship(
        "Category",
        remote_side=[id],
        backref=db.backref(
            "children",
            lazy="select",
            order_by="Category.sort_order.asc()",
        ),
        lazy="select",
    )

    # -------------------------
    # Compat extra (sin tocar DB)
    # -------------------------
    @property
    def is_active(self) -> bool:
        return bool(self.active)

    @property
    def status(self) -> str:
        # útil si alguna parte del código pide status
        return "active" if self.active else "hidden"

    # -------------------------
    # Validaciones suaves
    # -------------------------
    @validates("name")
    def _v_name(self, _k, v: str) -> str:
        v = (v or "").strip()
        return (v[:120] if v else "Categoría")

    @validates("slug")
    def _v_slug(self, _k, v: str) -> str:
        v = slugify(v or "")
        return v[:160] if v else "categoria"

    @validates("sort_order")
    def _v_sort(self, _k, v: int) -> int:
        try:
            return int(v)
        except Exception:
            return 0

    # -------------------------
    # Helpers PRO
    # -------------------------
    def is_root(self) -> bool:
        return self.parent_id is None

    def ancestors(self) -> List["Category"]:
        """
        root -> parent (sin incluir self)
        """
        out: List["Category"] = []
        cur = self.parent
        # loop guard por si hay ciclos por error humano
        seen: set[int] = set()
        while cur is not None and (cur.id not in seen):
            if cur.id is not None:
                seen.add(cur.id)
            out.append(cur)
            cur = cur.parent
        out.reverse()
        return out

    def full_path_slugs(self) -> List[str]:
        """root -> ... -> self"""
        slugs = [c.slug for c in self.ancestors()] + [self.slug]
        return [s for s in slugs if s]

    def compute_slug_path(self) -> str:
        return "/".join(self.full_path_slugs())

    def ensure_slug_path(self) -> None:
        """Recalcula slug_path (usalo si cambias parent/slug)."""
        self.slug_path = self.compute_slug_path()

    # ---- versión blindada para hooks (cuando parent no está cargado)
    def compute_slug_path_db_safe(self) -> str:
        """
        Calcula slug_path incluso si self.parent no está cargado,
        usando parent_id con queries.
        """
        parts: List[str] = []
        cur_id = self.parent_id
        seen: set[int] = set()
        while cur_id:
            if cur_id in seen:
                break
            seen.add(cur_id)
            parent = db.session.get(Category, int(cur_id))
            if not parent:
                break
            parts.append(parent.slug)
            cur_id = parent.parent_id
        parts.reverse()
        parts.append(self.slug)
        parts = [p for p in parts if p]
        return "/".join(parts) if parts else (self.slug or "categoria")

    def __repr__(self) -> str:
        return f"<Category id={self.id} name={self.name!r} slug={self.slug!r} parent_id={self.parent_id}>"


# ============================================================
# Índices PRO
# ============================================================

db.Index("ix_categories_active_sort", Category.active, Category.sort_order)
db.Index("ix_categories_parent_sort", Category.parent_id, Category.sort_order)


# ============================================================
# Hooks: mantener slug_path + updated_at
# ============================================================

@event.listens_for(Category, "before_insert", propagate=True)
def _cat_before_insert(_mapper, _conn, target: Category):
    # slug auto si faltó (mejora #1)
    if not (target.slug or "").strip():
        target.slug = slugify(target.name or "categoria")

    # created/updated consistentes (mejora #2)
    if not target.created_at:
        target.created_at = utcnow()
    target.updated_at = utcnow()

    # slug_path robusto (mejora #3)
    try:
        target.slug_path = target.compute_slug_path_db_safe()
    except Exception:
        target.slug_path = target.slug


@event.listens_for(Category, "before_update", propagate=True)
def _cat_before_update(_mapper, _conn, target: Category):
    target.updated_at = utcnow()

    # si cambia parent/slug, actualizamos path robusto
    try:
        target.slug_path = target.compute_slug_path_db_safe()
    except Exception:
        target.slug_path = target.slug
