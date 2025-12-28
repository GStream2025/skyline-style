from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from app import db


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Campaign(db.Model):
    """
    Campañas de email (marketing):
    - audience_rule_json: reglas para segmentar (country, opt-in, etc.)
    - status: draft | scheduled | sending | sent | paused
    """
    __tablename__ = "campaigns"

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(160), nullable=False)
    subject = db.Column(db.String(200), nullable=False)

    from_name = db.Column(db.String(120), nullable=True)
    from_email = db.Column(db.String(255), nullable=True)

    content_html = db.Column(db.Text, nullable=False)
    content_text = db.Column(db.Text, nullable=True)

    audience_rule_json = db.Column(db.Text, nullable=True)  # guardás reglas JSON como string

    status = db.Column(db.String(30), nullable=False, default="draft")
    scheduled_at = db.Column(db.DateTime(timezone=True), nullable=True)

    sent_count = db.Column(db.Integer, nullable=False, default=0)
    delivered_count = db.Column(db.Integer, nullable=False, default=0)
    failed_count = db.Column(db.Integer, nullable=False, default=0)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)

    sends = db.relationship("CampaignSend", back_populates="campaign", cascade="all, delete-orphan", lazy="select")

    def __repr__(self) -> str:
        return f"<Campaign id={self.id} name={self.name} status={self.status}>"


class CampaignSend(db.Model):
    """
    Registro por usuario: enviado / falló / open / click (más adelante)
    """
    __tablename__ = "campaign_sends"

    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    to_email = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(30), nullable=False, default="pending")  # pending/sent/failed

    sent_at = db.Column(db.DateTime(timezone=True), nullable=True)
    error_message = db.Column(db.String(500), nullable=True)

    campaign = db.relationship("Campaign", back_populates="sends", lazy="select")

    def __repr__(self) -> str:
        return f"<CampaignSend id={self.id} campaign_id={self.campaign_id} status={self.status}>"
