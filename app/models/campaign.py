from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import CheckConstraint, Index, UniqueConstraint, event
from sqlalchemy.orm import validates

from app.models import db

# =========================
# Skyline Store — Email Campaigns (ULTRA PRO / CLOSED / NO FAIL)
# 26 mejoras reales (robustez + "UI/admin" readiness):
#  1) Normalización fuerte (quita NULL/ZW/control + colapsa espacios)
#  2) Email normalize + validate estricta (casefold, evita whitespace, "..", etc.)
#  3) status sanitize centralizado con defaults seguros
#  4) JSON audience: parse/compact con límite bytes y fallback seguro
#  5) CheckConstraint length(audience_rule_json) con bytes-lógico (aprox) ya presente + hardening
#  6) content_html/text: sanitize leve anti-null/ZW/control (sin “romper” HTML)
#  7) subject/name defaults consistentes (brand-safe)
#  8) from_email validado (o None) — evita “unknown@” en Campaign
#  9) CampaignSend: NO guarda unknown@example.com silencioso (marca skipped + error)
# 10) CampaignSend: Unique(campaign_id,to_email) para evitar duplicados en cola
# 11) Counters: clamp + saturación
# 12) Sync schedule: status<->scheduled_at coherente y auto-correct
# 13) Timestamps coherentes: sent/delivered/failed/opened/clicked
# 14) delivered_at no permitido antes de sent_at (normaliza)
# 15) failed_at solo si status failed; si no, se limpia
# 16) opened/clicked: solo si sent/delivered (coherencia mínima)
# 17) Helper methods admin/UI: progress_rate(), status_badge(), summary()
# 18) audience_rules() cacheable (sin side effects)
# 19) set_audience_rules() siempre compacta
# 20) Índices mejorados para UI: status+scheduled, status+updated, send status+times
# 21) error_message sanitizado + truncado
# 22) Evita payload JSON gigante por seguridad (32KB)
# 23) “paused” resume: vuelve a scheduled si corresponde
# 24) bump_counters no deja delivered > sent (corrige suave)
# 25) __repr__ más informativo
# 26) __all__ limpio
# =========================

_CAMPAIGN_STATUSES = {"draft", "scheduled", "sending", "sent", "paused"}
_SEND_STATUSES = {"pending", "sent", "failed", "skipped"}

_NAME_MAX = 160
_SUBJECT_MAX = 200
_FROM_NAME_MAX = 120
_EMAIL_MAX = 255
_ERROR_MAX = 500
_JSON_MAX_BYTES = 32_000

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_ZW_RE = re.compile(r"[\u200b\u200c\u200d\ufeff]")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _norm(v: Any, max_len: int) -> Optional[str]:
    if v is None or max_len <= 0:
        return None
    s = str(v).replace("\x00", "")
    s = _ZW_RE.sub("", s)
    s = _CTRL_RE.sub("", s)
    s = " ".join(s.strip().split())
    if not s:
        return None
    return s[:max_len]


def _req(v: Any, max_len: int, default: str) -> str:
    return _norm(v, max_len) or default


def _normalize_email(v: Any) -> Optional[str]:
    s = _norm(v, _EMAIL_MAX)
    if not s:
        return None
    s = s.casefold()
    s = s.replace("..", ".").strip(".")
    return s[:_EMAIL_MAX] if s else None


def _looks_like_email(v: str) -> bool:
    if not v or len(v) > _EMAIL_MAX:
        return False
    if any(ch.isspace() for ch in v):
        return False
    if ".." in v:
        return False
    if v.count("@") != 1:
        return False
    return bool(_EMAIL_RE.match(v))


def _email(v: Any) -> Optional[str]:
    out = _normalize_email(v)
    if not out:
        return None
    return out if _looks_like_email(out) else None


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


def _status(v: Any, allowed: set[str], default: str) -> str:
    s = str(v or default).strip().lower()
    return s if s in allowed else default


def _json_dict(raw: Any) -> Dict[str, Any]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    s = str(raw).strip()
    if not s:
        return {}
    if len(s.encode("utf-8", "ignore")) > _JSON_MAX_BYTES:
        return {}
    try:
        obj = json.loads(s)
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def _json_dump(obj: Any) -> str:
    try:
        payload = obj if isinstance(obj, dict) else {}
        s = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        if len(s.encode("utf-8", "ignore")) > _JSON_MAX_BYTES:
            return "{}"
        return s
    except Exception:
        return "{}"


def _sync_campaign_schedule(target: "Campaign") -> None:
    # si dice scheduled pero no hay fecha -> draft
    if target.status == "scheduled" and target.scheduled_at is None:
        target.status = "draft"
    # si hay fecha y está draft -> scheduled
    if target.scheduled_at is not None and target.status == "draft":
        target.status = "scheduled"


def _safe_html(v: Any, *, default: str = "<p></p>") -> str:
    # no parseamos HTML; solo limpiamos caracteres peligrosos
    s = _norm(v, 10_000_000)
    return s or default


def _safe_text(v: Any) -> Optional[str]:
    return _norm(v, 10_000_000)


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
        CheckConstraint(
            f"(audience_rule_json IS NULL) OR (length(audience_rule_json) <= {_JSON_MAX_BYTES})",
            name="ck_campaigns_audience_json_len",
        ),
        Index("ix_campaigns_status_scheduled", "status", "scheduled_at", "id"),
        Index("ix_campaigns_status_updated", "status", "updated_at", "id"),
        Index("ix_campaigns_created", "created_at", "id"),
        Index("ix_campaigns_updated", "updated_at", "id"),
    )

    @validates("name")
    def _v_name(self, _k: str, v: Any) -> str:
        return _req(v, _NAME_MAX, "Campaña")

    @validates("subject")
    def _v_subject(self, _k: str, v: Any) -> str:
        return _req(v, _SUBJECT_MAX, "Skyline Store")

    @validates("from_name")
    def _v_from_name(self, _k: str, v: Any) -> Optional[str]:
        return _norm(v, _FROM_NAME_MAX)

    @validates("from_email")
    def _v_from_email(self, _k: str, v: Any) -> Optional[str]:
        return _email(v)

    @validates("content_html")
    def _v_html(self, _k: str, v: Any) -> str:
        return _safe_html(v)

    @validates("content_text")
    def _v_text(self, _k: str, v: Any) -> Optional[str]:
        return _safe_text(v)

    @validates("audience_rule_json")
    def _v_audience(self, _k: str, v: Any) -> Optional[str]:
        if v is None:
            return None
        s = str(v).strip()
        if not s:
            return None
        if len(s.encode("utf-8", "ignore")) > _JSON_MAX_BYTES:
            return "{}"
        obj = _json_dict(s)
        return _json_dump(obj) if obj else "{}"

    @validates("status")
    def _v_status(self, _k: str, v: Any) -> str:
        return _status(v, _CAMPAIGN_STATUSES, "draft")

    @validates("sent_count", "delivered_count", "failed_count")
    def _v_counts(self, _k: str, v: Any) -> int:
        return _clamp_int(v, 0, 2_000_000_000)

    def audience_rules(self) -> Dict[str, Any]:
        return _json_dict(self.audience_rule_json)

    def set_audience_rules(self, rules: Optional[Dict[str, Any]]) -> None:
        self.audience_rule_json = _json_dump(rules)

    def is_scheduled(self) -> bool:
        return (self.status == "scheduled") and (self.scheduled_at is not None)

    def is_ready_to_send(self, now: Optional[datetime] = None) -> bool:
        if self.status != "scheduled" or not self.scheduled_at:
            return False
        return (now or utcnow()) >= self.scheduled_at

    def mark_scheduled(self, when: Optional[datetime]) -> None:
        self.scheduled_at = when
        self.status = "scheduled" if when else "draft"

    def mark_sending(self) -> None:
        self.status = "sending"

    def mark_sent(self) -> None:
        self.status = "sent"

    def pause(self) -> None:
        if self.status in {"scheduled", "sending"}:
            self.status = "paused"

    def resume(self) -> None:
        if self.status == "paused":
            self.status = "scheduled" if self.scheduled_at else "draft"

    def bump_counters(self, *, sent: int = 0, delivered: int = 0, failed: int = 0) -> None:
        s0 = _clamp_int(self.sent_count)
        d0 = _clamp_int(self.delivered_count)
        f0 = _clamp_int(self.failed_count)
        self.sent_count = _clamp_int(s0 + _clamp_int(sent), 0, 2_000_000_000)
        self.delivered_count = _clamp_int(d0 + _clamp_int(delivered), 0, 2_000_000_000)
        self.failed_count = _clamp_int(f0 + _clamp_int(failed), 0, 2_000_000_000)
        # delivered no debería exceder sent (corrige suave)
        if self.delivered_count > self.sent_count:
            self.delivered_count = self.sent_count
        if self.failed_count > self.sent_count:
            self.failed_count = self.sent_count

    def progress_rate(self) -> Dict[str, Any]:
        sent = _clamp_int(self.sent_count)
        delivered = _clamp_int(self.delivered_count)
        failed = _clamp_int(self.failed_count)
        total = max(1, sent)
        return {
            "sent": sent,
            "delivered": delivered,
            "failed": failed,
            "delivered_pct": int((delivered / total) * 100),
            "failed_pct": int((failed / total) * 100),
        }

    def status_badge(self) -> str:
        # útil para UI admin
        if self.status == "scheduled" and self.scheduled_at:
            return "scheduled"
        return self.status

    def summary(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "subject": self.subject,
            "status": self.status,
            "scheduled_at": self.scheduled_at.isoformat() if self.scheduled_at else None,
            "progress": self.progress_rate(),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return f"<Campaign id={self.id} name={self.name!r} status={self.status!r} scheduled_at={self.scheduled_at!r}>"


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

    sent_at = db.Column(db.DateTime(timezone=True), nullable=True)
    delivered_at = db.Column(db.DateTime(timezone=True), nullable=True)
    failed_at = db.Column(db.DateTime(timezone=True), nullable=True)

    opened_at = db.Column(db.DateTime(timezone=True), nullable=True)
    clicked_at = db.Column(db.DateTime(timezone=True), nullable=True)

    error_message = db.Column(db.String(_ERROR_MAX), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)

    campaign = db.relationship("Campaign", back_populates="sends", lazy="selectin")

    __table_args__ = (
        CheckConstraint("status IN ('pending','sent','failed','skipped')", name="ck_campaign_sends_status_allowed"),
        CheckConstraint("length(to_email) <= 255", name="ck_campaign_sends_email_len"),
        # evita duplicar al mismo destinatario dentro de la campaña
        UniqueConstraint("campaign_id", "to_email", name="uq_campaign_sends_campaign_email"),
        Index("ix_campaign_sends_campaign_status", "campaign_id", "status", "id"),
        Index("ix_campaign_sends_email_status", "to_email", "status", "id"),
        Index("ix_campaign_sends_sent_at", "sent_at", "id"),
        Index("ix_campaign_sends_created", "created_at", "id"),
    )

    @validates("to_email")
    def _v_to_email(self, _k: str, v: Any) -> str:
        out = _email(v)
        # no metemos "unknown@" silencioso: guardamos placeholder consistente
        return (out or "invalid@example.com")[:_EMAIL_MAX]

    @validates("status")
    def _v_status(self, _k: str, v: Any) -> str:
        return _status(v, _SEND_STATUSES, "pending")

    @validates("error_message")
    def _v_error_message(self, _k: str, v: Any) -> Optional[str]:
        return _norm(v, _ERROR_MAX)

    def mark_sent(self, when: Optional[datetime] = None) -> None:
        self.status = "sent"
        self.sent_at = when or utcnow()
        self.failed_at = None
        self.error_message = None

    def mark_delivered(self, when: Optional[datetime] = None) -> None:
        if not self.sent_at:
            self.sent_at = utcnow()
        if not self.delivered_at:
            self.delivered_at = when or utcnow()
        if self.delivered_at and self.sent_at and self.delivered_at < self.sent_at:
            self.delivered_at = self.sent_at

    def mark_failed(self, msg: str = "", when: Optional[datetime] = None) -> None:
        self.status = "failed"
        self.failed_at = when or utcnow()
        self.error_message = _norm(msg, _ERROR_MAX)

    def mark_skipped(self, msg: str = "") -> None:
        self.status = "skipped"
        self.error_message = _norm(msg, _ERROR_MAX)

    def mark_opened(self, when: Optional[datetime] = None) -> None:
        # coherencia mínima
        if self.status not in {"sent", "failed"} and not self.sent_at:
            return
        if not self.opened_at:
            self.opened_at = when or utcnow()

    def mark_clicked(self, when: Optional[datetime] = None) -> None:
        if self.status not in {"sent", "failed"} and not self.sent_at:
            return
        if not self.clicked_at:
            self.clicked_at = when or utcnow()

    def __repr__(self) -> str:
        return f"<CampaignSend id={self.id} campaign_id={self.campaign_id} to={self.to_email!r} status={self.status!r}>"


@event.listens_for(Campaign, "before_insert", propagate=True)
def _campaign_before_insert(_mapper, _conn, target: Campaign) -> None:
    now = utcnow()
    target.updated_at = now
    if not target.created_at:
        target.created_at = now

    _sync_campaign_schedule(target)

    target.status = _status(target.status, _CAMPAIGN_STATUSES, "draft")
    target.sent_count = _clamp_int(target.sent_count)
    target.delivered_count = _clamp_int(target.delivered_count)
    target.failed_count = _clamp_int(target.failed_count)

    if target.audience_rule_json:
        target.audience_rule_json = _json_dump(_json_dict(target.audience_rule_json))


@event.listens_for(Campaign, "before_update", propagate=True)
def _campaign_before_update(_mapper, _conn, target: Campaign) -> None:
    target.updated_at = utcnow()

    _sync_campaign_schedule(target)

    target.status = _status(target.status, _CAMPAIGN_STATUSES, "draft")
    target.sent_count = _clamp_int(target.sent_count)
    target.delivered_count = _clamp_int(target.delivered_count)
    target.failed_count = _clamp_int(target.failed_count)

    if target.audience_rule_json:
        target.audience_rule_json = _json_dump(_json_dict(target.audience_rule_json))


@event.listens_for(CampaignSend, "before_insert", propagate=True)
@event.listens_for(CampaignSend, "before_update", propagate=True)
def _send_before_save(_mapper, _conn, target: CampaignSend) -> None:
    # email + status
    em = _email(target.to_email)
    if not em:
        target.to_email = "invalid@example.com"
        target.status = "skipped"
        target.error_message = target.error_message or "Invalid recipient email"
    else:
        target.to_email = em[:_EMAIL_MAX]
        target.status = _status(target.status, _SEND_STATUSES, "pending")

    target.error_message = _norm(target.error_message, _ERROR_MAX) if target.error_message else None

    # coherencia timestamps
    if target.status == "sent" and target.sent_at is None:
        target.sent_at = utcnow()
    if target.status == "failed" and target.failed_at is None:
        target.failed_at = utcnow()
    if target.status != "failed":
        target.failed_at = None
    if target.delivered_at and target.sent_at and target.delivered_at < target.sent_at:
        target.delivered_at = target.sent_at
    if target.opened_at and target.sent_at and target.opened_at < target.sent_at:
        target.opened_at = target.sent_at
    if target.clicked_at and target.sent_at and target.clicked_at < target.sent_at:
        target.clicked_at = target.sent_at


__all__ = ["Campaign", "CampaignSend", "utcnow"]
