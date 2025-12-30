# app/models/event.py
from __future__ import annotations

from datetime import datetime
from sqlalchemy import Index
from app.models import db


class Event(db.Model):
    """
    Eventos reales para tracking/marketing/admin:
    - page_view, add_to_cart, checkout, purchase, login, signup, etc.
    """

    __tablename__ = "events"

    id = db.Column(db.Integer, primary_key=True)

    # Quien lo generó (si existe)
    user_id = db.Column(db.Integer, nullable=True, index=True)

    # Session / visitante
    session_id = db.Column(db.String(128), nullable=True, index=True)
    ip = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)

    # Tipo de evento (clave)
    name = db.Column(db.String(80), nullable=False, index=True)

    # Ruta / referencia
    path = db.Column(db.String(255), nullable=True, index=True)
    ref = db.Column(db.String(255), nullable=True)

    # Datos flexibles (JSON en Postgres; Text en SQLite)
    # Para no romper en SQLite:
    payload = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    def __repr__(self) -> str:
        return f"<Event {self.name} #{self.id}>"

    @staticmethod
    def now() -> datetime:
        return datetime.utcnow()


# Índices útiles para performance
Index("ix_events_name_created", Event.name, Event.created_at)
Index("ix_events_user_created", Event.user_id, Event.created_at)
