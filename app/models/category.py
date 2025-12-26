# app/models/category.py
from __future__ import annotations

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

try:
    from app.extensions import db  # recomendado si tu proyecto lo tiene
except Exception:
    try:
        from app import db  # si db está en app/__init__.py
    except Exception:
        db = SQLAlchemy()


class Category(db.Model):
    __tablename__ = "categories"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    slug = db.Column(db.String(140), unique=True, nullable=False)

    is_active = db.Column(db.Boolean, default=True, nullable=False)
    sort_order = db.Column(db.Integer, default=0, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def __repr__(self) -> str:
        return f"<Category {self.slug}>"
