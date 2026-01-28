from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional

from sqlalchemy import ForeignKey, Index
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import validates

from app.models import db

log = db.get_engine  # type: ignore[attr-defined]  # avoid unused-lint in some setups (safe no-op)
_log = __import__("logging").getLogger("event")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


PayloadType = db.JSON().with_variant(db.Text(), "sqlite")

_NAME_RE = re.compile(r"^[a-z0-9_:\-\.]{1,80}$", re.IGNORECASE)


def _s(v: Any, n: int) -> str:
    s = "" if v is None else str(v)
    s = s.strip()
    return s[:n]


def _opt(v: Any, n: int) -> Optional[str]:
    s = _s(v, n)
    return s or None


def _clean_event_name(v: Any) -> str:
    s = _s(v, 80).lower()
    if not s:
        return "event"
    if _NAME_RE.match(s):
        return s
    s2 = re.sub(r"[^a-z0-9_:\-\.]+", "_", s).strip("_")
    return (s2[:80] or "event")


def _clean_ip(v: Any) -> Optional[str]:
    s = _opt(v, 64)
    if not s:
        return None
    return s


class Event(db.Model):
    __tablename__ = "events"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    session_id = db.Column(db.String(128), nullable=True, index=True)
    ip = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)

    name = db.Column(db.String(80), nullable=False, index=True)

    path = db.Column(db.String(255), nullable=True, index=True)
    ref = db.Column(db.String(255), nullable=True)

    source = db.Column(db.String(80), nullable=True, index=True)
    utm_source = db.Column(db.String(80), nullable=True, index=True)
    utm_medium = db.Column(db.String(80), nullable=True, index=True)
    utm_campaign = db.Column(db.String(120), nullable=True, index=True)

    idempotency_key = db.Column(db.String(200), nullable=True, unique=True, index=True)

    payload = db.Column(PayloadType, nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)

    __table_args__ = (
        Index("ix_events_name_created", "name", "created_at"),
        Index("ix_events_user_created", "user_id", "created_at"),
        Index("ix_events_session_created", "session_id", "created_at"),
        Index("ix_events_path_created", "path", "created_at"),
        Index("ix_events_utm_created", "utm_source", "utm_medium", "created_at"),
    )

    @validates("name")
    def _v_name(self, _k: str, v: Any) -> str:
        return _clean_event_name(v)

    @validates("path", "ref")
    def _v_paths(self, _k: str, v: Any) -> Optional[str]:
        return _opt(v, 255)

    @validates("source", "utm_source", "utm_medium")
    def _v_small_marketing(self, _k: str, v: Any) -> Optional[str]:
        return _opt(v, 80)

    @validates("utm_campaign")
    def _v_campaign(self, _k: str, v: Any) -> Optional[str]:
        return _opt(v, 120)

    @validates("session_id")
    def _v_session(self, _k: str, v: Any) -> Optional[str]:
        return _opt(v, 128)

    @validates("user_agent")
    def _v_ua(self, _k: str, v: Any) -> Optional[str]:
        return _opt(v, 255)

    @validates("ip")
    def _v_ip(self, _k: str, v: Any) -> Optional[str]:
        return _clean_ip(v)

    @validates("idempotency_key")
    def _v_ikey(self, _k: str, v: Any) -> Optional[str]:
        return _opt(v, 200)

    @staticmethod
    def now() -> datetime:
        return utcnow()

    def __repr__(self) -> str:
        ca = self.created_at.isoformat() if self.created_at else "?"
        return f"<Event id={self.id} name={self.name!r} user_id={self.user_id} at={ca}>"

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
        utm: Optional[Mapping[str, Any]] = None,
        payload: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
        commit: bool = True,
    ) -> "Event":
        ikey = _opt(idempotency_key, 200)

        if ikey:
            existing = db.session.query(cls).filter_by(idempotency_key=ikey).first()
            if existing:
                return existing

        u = utm or {}
        ev = cls(
            name=name,
            user_id=int(user_id) if user_id is not None else None,
            session_id=session_id,
            ip=ip,
            user_agent=user_agent,
            path=path,
            ref=ref,
            source=source,
            utm_source=_opt(u.get("utm_source"), 80),
            utm_medium=_opt(u.get("utm_medium"), 80),
            utm_campaign=_opt(u.get("utm_campaign"), 120),
            payload=payload,
            idempotency_key=ikey,
        )

        db.session.add(ev)

        if not commit:
            return ev

        try:
            db.session.commit()
            return ev
        except IntegrityError:
            db.session.rollback()
            if ikey:
                again = db.session.query(cls).filter_by(idempotency_key=ikey).first()
                if again:
                    return again
            raise
        except Exception:
            db.session.rollback()
            raise


__all__ = ["Event", "utcnow", "PayloadType"]
