from __future__ import annotations

from datetime import datetime, timezone
from app import db


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Category(db.Model):
    __tablename__ = "categories"

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(120), nullable=False)
    slug = db.Column(db.String(160), nullable=False, unique=True, index=True)

    # árbol tipo Temu: parent -> children
    parent_id = db.Column(db.Integer, db.ForeignKey("categories.id", ondelete="SET NULL"), nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    parent = db.relationship("Category", remote_side=[id], backref="children", lazy="select")

    def __repr__(self) -> str:
        return f"<Category id={self.id} name={self.name}>"
