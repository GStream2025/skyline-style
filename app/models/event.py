# app/models/event.py
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional, Dict

from sqlalchemy import Index, ForeignKey
from sqlalchemy.orm import validates

from app.models import db  # ✅ db ÚNICO


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# JSON "portable": en Postgres queda JSONB; en SQLite cae a TEXT
PayloadType = db.JSON().with_variant(db.Text(), "sqlite")


class Event(db.Model):
    """
    Skyline Store — Event ULTRA PRO (FINAL)

    Eventos reales para tracking/marketing/admin:
    - page_view, view_product, search, add_to_cart, begin_checkout, add_payment_info, purchase
    - login, signup, logout
    - admin_login, admin_action, etc.

    PRO:
    - UTC timezone-aware
    - payload JSON en Postgres (y Text en SQLite)
    - FK opcional a users (sin romper si users no existe todavía)
    - idempotency_key: evita duplicados (ej: purchase por refresh)
    - utm/source/referrer para marketing
    """

    __tablename__ = "events"

    id = db.Column(db.Integer, primary_key=True)

    # Usuario (opcional) — si hay tabla users, mejor con FK; si no, igual funciona con nullable.
    user_id = db.Column(db.Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)

    # Session / visitante
    session_id = db.Column(db.String(128), nullable=True, index=True)
    ip = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)

    # Tipo de evento
    name = db.Column(db.String(80), nullable=False, index=True)

    # Ruta / referencia
    path = db.Column(db.String(255), nullable=True, index=True)
    ref = db.Column(db.String(255), nullable=True)

    # Marketing (opcional)
    source = db.Column(db.String(80), nullable=True, index=True)  # ej: "google", "instagram", "email"
    utm_source = db.Column(db.String(80), nullable=True, index=True)
    utm_medium = db.Column(db.String(80), nullable=True, index=True)
    utm_campaign = db.Column(db.String(120), nullable=True, index=True)

    # Anti-duplicados (opcional)
    # Ej: "purchase:ORDER123" o "checkout:SESSIONID"
    idempotency_key = db.Column(db.String(200), nullable=True, unique=True, index=True)

    # Datos flexibles
    payload = db.Column(PayloadType, nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)

    # -------------------------
    # Validaciones suaves
    # -------------------------
    @validates("name")
    def _v_name(self, _k, v: str) -> str:
        v = (v or "").strip()
        return (v[:80] if v else "event")

    @validates("path", "ref")
    def _v_paths(self, _k, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        v = v.strip()
        return v[:255]

    @staticmethod
    def now() -> datetime:
        return utcnow()

    def __repr__(self) -> str:
        return f"<Event id={self.id} name={self.name!r} user_id={self.user_id} at={self.created_at.isoformat()}>"

    # -------------------------
    # Helper PRO: log rápido
    # -------------------------
    @classmethod
    def log(
        cls,
        name: str,
        *,
        user_id: Optional[int] = None,
        session_id: Optional[str] = None,
        ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        path: Optional[str] = None,
        ref: Optional[str] = None,
        source: Optional[str] = None,
        utm: Optional[Dict[str, str]] = None,
        payload: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
        commit: bool = True,
    ) -> "Event":
        """
        Crea evento de forma segura.
        Si idempotency_key ya existe, devuelve el existente (no duplica).
        """
        if idempotency_key:
            existing = db.session.query(cls).filter_by(idempotency_key=idempotency_key).first()
            if existing:
                return existing

        utm = utm or {}
        ev = cls(
            name=name,
            user_id=user_id,
            session_id=session_id,
            ip=ip,
            user_agent=user_agent,
            path=path,
            ref=ref,
            source=source,
            utm_source=utm.get("utm_source"),
            utm_medium=utm.get("utm_medium"),
            utm_campaign=utm.get("utm_campaign"),
            payload=payload,
            idempotency_key=idempotency_key,
        )
        db.session.add(ev)
        if commit:
            db.session.commit()
        return ev


# Índices útiles para performance
Index("ix_events_name_created", Event.name, Event.created_at)
Index("ix_events_user_created", Event.user_id, Event.created_at)
Index("ix_events_session_created", Event.session_id, Event.created_at)
Index("ix_events_path_created", Event.path, Event.created_at)
Index("ix_events_utm_created", Event.utm_source, Event.utm_medium, Event.created_at)
