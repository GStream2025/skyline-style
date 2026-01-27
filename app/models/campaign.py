from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import CheckConstraint, Index, event, func
from sqlalchemy.orm import validates

from app.models import db


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


_CAMPAIGN_STATUSES = {"draft", "scheduled", "sending", "sent", "paused"}
_SEND_STATUSES = {"pending", "sent", "failed", "skipped"}

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

_NAME_MAX = 160
_SUBJECT_MAX = 200
_FROM_NAME_MAX = 120
_EMAIL_MAX = 255
_ERROR_MAX = 500


def _s(v: Optional[str], max_len: int) -> Optional[str]:
    if v is None:
        return None
    out = str(v).replace("\x00", "").strip()
    if not out:
        return None
    out = " ".join(out.split())
    return out[:max_len]


def _s_req(v: Optional[str], max_len: int, default: str) -> str:
    out = _s(v, max_len)
    return out if out else default


def _normalize_email(v: Optional[str]) -> Optional[str]:
    out = _s(v, _EMAIL_MAX)
    if not out:
        return None
    out = out.lower()
    out = out.replace("\u200b", "")
    out = " ".join(out.split())
    return out[:_EMAIL_MAX] if out else None


def _looks_like_email(v: str) -> bool:
    if not v or len(v) > _EMAIL_MAX:
        return False
    if " " in v or ".." in v:
        return False
    return bool(_EMAIL_RE.match(v))


def _email(v: Optional[str]) -> Optional[str]:
    out = _normalize_email(v)
    if not out:
        return None
    return out if _looks_like_email(out) else out


def _clamp_int(v: Any, lo: int = 0, hi: int = 2_000_000_000) -> int:
    try:
        n = int(v)
    except Exception:
        n = 0
    if n < lo:
        return lo
    if n > hi:
        return hi
    return n


def _status(v: Optional[str], allowed: set[str], default: str) -> str:
    out = (v or default).strip().lower()
    return out if out in allowed else default


def _json_dict(raw: Optional[str]) -> Dict[str, Any]:
    s = (raw or "").strip()
    if not s:
        return {}
    try:
        obj = json.loads(s)
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def _json_dump(obj: Optional[Dict[str, Any]]) -> str:
    try:
        payload = obj if isinstance(obj, dict) else {}
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        return "{}"


class Campaign(db.Model):
    __tablename__ = "campaigns"

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(_NAME_MAX), nullable=False)
    subject = db.Column(db.String(_SUBJECT_MAX), nullable=False)

    from_name = db.Column(db.String(_FROM_NAME_MAX), nullable=True)
    from_email = db.Column(db.String(_EMAIL_MAX), nullable=True)

    content_html = db.Column(db.Text, nullable=False)
    content_text = db.Column(db.Text, nullable=True)

    audience_rule_json = db.Column(db.Text, nullable=True)

    status = db.Column(db.String(30), nullable=False, default="draft", index=True)
    scheduled_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)

    sent_count = db.Column(db.Integer, nullable=False, default=0)
    delivered_count = db.Column(db.Integer, nullable=False, default=0)
    failed_count = db.Column(db.Integer, nullable=False, default=0)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow, index=True)

    sends = db.relationship(
        "CampaignSend",
        back_populates="campaign",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    __table_args__ = (
        CheckConstraint("sent_count >= 0", name="ck_campaigns_sent_nonneg"),
        CheckConstraint("delivered_count >= 0", name="ck_campaigns_delivered_nonneg"),
        CheckConstraint("failed_count >= 0", name="ck_campaigns_failed_nonneg"),
        CheckConstraint(
            "status IN ('draft','scheduled','sending','sent','paused')",
            name="ck_campaigns_status_allowed",
        ),
        Index("ix_campaigns_status_scheduled", "status", "scheduled_at"),
        Index("ix_campaigns_created", "created_at"),
        Index("ix_campaigns_updated", "updated_at"),
    )

    @validates("name")
    def _v_name(self, _k, v: str) -> str:
        return _s_req(v, _NAME_MAX, "Campaña")

    @validates("subject")
    def _v_subject(self, _k, v: str) -> str:
        return _s_req(v, _SUBJECT_MAX, "Skyline Store")

    @validates("from_name")
    def _v_from_name(self, _k, v: Optional[str]) -> Optional[str]:
        return _s(v, _FROM_NAME_MAX)

    @validates("from_email")
    def _v_from_email(self, _k, v: Optional[str]) -> Optional[str]:
        return _email(v)

    @validates("status")
    def _v_status(self, _k, v: str) -> str:
        return _status(v, _CAMPAIGN_STATUSES, "draft")

    def audience_rules(self) -> Dict[str, Any]:
        return _json_dict(self.audience_rule_json)

    def set_audience_rules(self, rules: Optional[Dict[str, Any]]) -> None:
        self.audience_rule_json = _json_dump(rules)

    def is_scheduled(self) -> bool:
        return self.status == "scheduled" and self.scheduled_at is not None

    def is_ready_to_send(self, now: Optional[datetime] = None) -> bool:
        if self.status != "scheduled" or not self.scheduled_at:
            return False
        now = now or utcnow()
        return now >= self.scheduled_at

    def mark_scheduled(self, when: datetime) -> None:
        self.status = "scheduled"
        self.scheduled_at = when

    def mark_sending(self) -> None:
        self.status = "sending"

    def mark_sent(self) -> None:
        self.status = "sent"

    def pause(self) -> None:
        if self.status in {"scheduled", "sending"}:
            self.status = "paused"

    def resume(self) -> None:
        if self.status == "paused":
            self.status = "draft" if not self.scheduled_at else "scheduled"

    def bump_counters(self, *, sent: int = 0, delivered: int = 0, failed: int = 0) -> None:
        self.sent_count = _clamp_int(self.sent_count) + _clamp_int(sent)
        self.delivered_count = _clamp_int(self.delivered_count) + _clamp_int(delivered)
        self.failed_count = _clamp_int(self.failed_count) + _clamp_int(failed)

    def __repr__(self) -> str:
        return f"<Campaign id={self.id} name={self.name!r} status={self.status!r}>"


class CampaignSend(db.Model):
    __tablename__ = "campaign_sends"

    id = db.Column(db.Integer, primary_key=True)

    campaign_id = db.Column(
        db.Integer,
        db.ForeignKey("campaigns.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    to_email = db.Column(db.String(_EMAIL_MAX), nullable=False, index=True)
    status = db.Column(db.String(30), nullable=False, default="pending", index=True)

    sent_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)
    delivered_at = db.Column(db.DateTime(timezone=True), nullable=True)
    failed_at = db.Column(db.DateTime(timezone=True), nullable=True)

    opened_at = db.Column(db.DateTime(timezone=True), nullable=True)
    clicked_at = db.Column(db.DateTime(timezone=True), nullable=True)

    error_message = db.Column(db.String(_ERROR_MAX), nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)

    campaign = db.relationship("Campaign", back_populates="sends", lazy="selectin")

    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','sent','failed','skipped')",
            name="ck_campaign_sends_status_allowed",
        ),
        CheckConstraint("length(to_email) <= 255", name="ck_campaign_sends_email_len"),
        Index("ix_campaign_sends_campaign_status", "campaign_id", "status", "id"),
        Index("ix_campaign_sends_email_status", "to_email", "status", "id"),
        Index("ix_campaign_sends_sent_at", "sent_at", "id"),
    )

    @validates("to_email")
    def _v_to_email(self, _k, v: str) -> str:
        out = _normalize_email(v) or "unknown@example.com"
        return out

    @validates("status")
    def _v_status(self, _k, v: str) -> str:
        return _status(v, _SEND_STATUSES, "pending")

    @validates("error_message")
    def _v_error_message(self, _k, v: Optional[str]) -> Optional[str]:
        return _s(v, _ERROR_MAX)

    def mark_sent(self) -> None:
        self.status = "sent"
        self.sent_at = utcnow()
        self.failed_at = None
        self.error_message = None

    def mark_delivered(self) -> None:
        if not self.delivered_at:
            self.delivered_at = utcnow()

    def mark_failed(self, msg: str = "") -> None:
        self.status = "failed"
        self.failed_at = utcnow()
        self.error_message = _s(msg, _ERROR_MAX)

    def mark_skipped(self, msg: str = "") -> None:
        self.status = "skipped"
        self.error_message = _s(msg, _ERROR_MAX)

    def mark_opened(self) -> None:
        if not self.opened_at:
            self.opened_at = utcnow()

    def mark_clicked(self) -> None:
        if not self.clicked_at:
            self.clicked_at = utcnow()

    def __repr__(self) -> str:
        return f"<CampaignSend id={self.id} campaign_id={self.campaign_id} status={self.status!r}>"


@event.listens_for(Campaign, "before_insert", propagate=True)
def _campaign_before_insert(_mapper, _conn, target: Campaign):
    now = utcnow()
    target.updated_at = now
    if not target.created_at:
        target.created_at = now
    if target.status == "scheduled" and target.scheduled_at is None:
        target.status = "draft"
    if target.scheduled_at is not None and target.status == "draft":
        target.status = "scheduled"
    target.sent_count = _clamp_int(target.sent_count)
    target.delivered_count = _clamp_int(target.delivered_count)
    target.failed_count = _clamp_int(target.failed_count)


@event.listens_for(Campaign, "before_update", propagate=True)
def _campaign_before_update(_mapper, _conn, target: Campaign):
    target.updated_at = utcnow()
    if target.status == "scheduled" and target.scheduled_at is None:
        target.status = "draft"
    if target.scheduled_at is not None and target.status == "draft":
        target.status = "scheduled"
    target.sent_count = _clamp_int(target.sent_count)
    target.delivered_count = _clamp_int(target.delivered_count)
    target.failed_count = _clamp_int(target.failed_count)


@event.listens_for(CampaignSend, "before_insert", propagate=True)
def _send_before_insert(_mapper, _conn, target: CampaignSend):
    target.to_email = _normalize_email(target.to_email) or "unknown@example.com"
    target.status = _status(target.status, _SEND_STATUSES, "pending")


@event.listens_for(CampaignSend, "before_update", propagate=True)
def _send_before_update(_mapper, _conn, target: CampaignSend):
    target.to_email = _normalize_email(target.to_email) or "unknown@example.com"
    target.status = _status(target.status, _SEND_STATUSES, "pending")


__all__ = ["Campaign", "CampaignSend", "utcnow"]
