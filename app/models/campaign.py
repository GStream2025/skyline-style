from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Any, Dict

import json

from sqlalchemy import event
from sqlalchemy.orm import validates

from app.models import db  # ✅ db ÚNICO (no usar: from app import db)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ==========================
# Constantes / enums suaves
# ==========================

CAMPAIGN_STATUSES = {"draft", "scheduled", "sending", "sent", "paused"}
SEND_STATUSES = {"pending", "sent", "failed", "skipped"}

# (opcional pro para tracking más adelante)
EVENT_TYPES = {"open", "click", "unsubscribe"}


class Campaign(db.Model):
    """
    Skyline Store — Campaign ULTRA PRO (FINAL)
    Campañas de email (marketing) listas para crecer:

    - status: draft | scheduled | sending | sent | paused
    - audience_rule_json: reglas JSON como string (segmentación)
    - counters: sent/delivered/failed
    - programable con scheduled_at
    """

    __tablename__ = "campaigns"

    id = db.Column(db.Integer, primary_key=True)

    # Metadata
    name = db.Column(db.String(160), nullable=False)
    subject = db.Column(db.String(200), nullable=False)

    from_name = db.Column(db.String(120), nullable=True)
    from_email = db.Column(db.String(255), nullable=True)

    # Contenido
    content_html = db.Column(db.Text, nullable=False)
    content_text = db.Column(db.Text, nullable=True)

    # Segmentación
    audience_rule_json = db.Column(db.Text, nullable=True)  # JSON string

    # Estado / programación
    status = db.Column(db.String(30), nullable=False, default="draft", index=True)
    scheduled_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)

    # Métricas (contadores rápidos)
    sent_count = db.Column(db.Integer, nullable=False, default=0)
    delivered_count = db.Column(db.Integer, nullable=False, default=0)
    failed_count = db.Column(db.Integer, nullable=False, default=0)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow, index=True)

    # Relación
    sends = db.relationship(
        "CampaignSend",
        back_populates="campaign",
        cascade="all, delete-orphan",
        lazy="select",
    )

    # ==========================
    # Validaciones suaves
    # ==========================
    @validates("name")
    def _v_name(self, _k, v: str) -> str:
        v = (v or "").strip()
        return (v[:160] if v else "Campaña")

    @validates("subject")
    def _v_subject(self, _k, v: str) -> str:
        v = (v or "").strip()
        return (v[:200] if v else "Skyline Store")

    @validates("from_email")
    def _v_from_email(self, _k, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        v = v.strip().lower()
        return v[:255]

    @validates("status")
    def _v_status(self, _k, v: str) -> str:
        v = (v or "draft").strip().lower()
        return v if v in CAMPAIGN_STATUSES else "draft"

    # ==========================
    # Helpers PRO
    # ==========================
    def audience_rules(self) -> Dict[str, Any]:
        """
        Devuelve dict a partir de audience_rule_json.
        Si está vacío o inválido, devuelve {} (no rompe).
        """
        raw = (self.audience_rule_json or "").strip()
        if not raw:
            return {}
        try:
            out = json.loads(raw)
            return out if isinstance(out, dict) else {}
        except Exception:
            return {}

    def set_audience_rules(self, rules: Dict[str, Any]) -> None:
        """
        Guarda dict como JSON string (compacto).
        """
        try:
            self.audience_rule_json = json.dumps(rules or {}, ensure_ascii=False, separators=(",", ":"))
        except Exception:
            self.audience_rule_json = "{}"

    def is_scheduled(self) -> bool:
        return self.status == "scheduled" and self.scheduled_at is not None

    def is_ready_to_send(self, now: Optional[datetime] = None) -> bool:
        now = now or utcnow()
        if self.status != "scheduled":
            return False
        if not self.scheduled_at:
            return False
        return now >= self.scheduled_at

    def mark_sending(self) -> None:
        self.status = "sending"

    def mark_sent(self) -> None:
        self.status = "sent"

    def __repr__(self) -> str:
        return f"<Campaign id={self.id} name={self.name!r} status={self.status!r}>"


class CampaignSend(db.Model):
    """
    Skyline Store — CampaignSend ULTRA PRO (FINAL)
    Registro por destinatario:
    - status: pending | sent | failed | skipped
    - sent_at + error_message
    - preparado para tracking (opens/clicks)
    """

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

    to_email = db.Column(db.String(255), nullable=False, index=True)

    status = db.Column(db.String(30), nullable=False, default="pending", index=True)

    sent_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)
    delivered_at = db.Column(db.DateTime(timezone=True), nullable=True)
    failed_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Tracking básico listo
    opened_at = db.Column(db.DateTime(timezone=True), nullable=True)
    clicked_at = db.Column(db.DateTime(timezone=True), nullable=True)

    error_message = db.Column(db.String(500), nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)

    campaign = db.relationship("Campaign", back_populates="sends", lazy="select")

    # ==========================
    # Validaciones suaves
    # ==========================
    @validates("to_email")
    def _v_to_email(self, _k, v: str) -> str:
        v = (v or "").strip().lower()
        return v[:255]

    @validates("status")
    def _v_status(self, _k, v: str) -> str:
        v = (v or "pending").strip().lower()
        return v if v in SEND_STATUSES else "pending"

    # ==========================
    # Helpers PRO
    # ==========================
    def mark_sent(self) -> None:
        self.status = "sent"
        self.sent_at = utcnow()

    def mark_failed(self, msg: str = "") -> None:
        self.status = "failed"
        self.failed_at = utcnow()
        self.error_message = (msg or "")[:500] or None

    def mark_opened(self) -> None:
        if not self.opened_at:
            self.opened_at = utcnow()

    def mark_clicked(self) -> None:
        if not self.clicked_at:
            self.clicked_at = utcnow()

    def __repr__(self) -> str:
        return f"<CampaignSend id={self.id} campaign_id={self.campaign_id} status={self.status!r}>"


# ============================================================
# Índices PRO (performance real)
# ============================================================

db.Index("ix_campaigns_status_scheduled", Campaign.status, Campaign.scheduled_at)
db.Index("ix_campaigns_created", Campaign.created_at)

db.Index("ix_campaign_sends_campaign_status", CampaignSend.campaign_id, CampaignSend.status)
db.Index("ix_campaign_sends_email_status", CampaignSend.to_email, CampaignSend.status)
db.Index("ix_campaign_sends_sent_at", CampaignSend.sent_at)


# ============================================================
# Hooks: updated_at fuerte
# ============================================================

@event.listens_for(Campaign, "before_update", propagate=True)
def _campaign_before_update(_mapper, _conn, target: Campaign):
    target.updated_at = utcnow()
