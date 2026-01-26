from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import CheckConstraint, Index, event
from sqlalchemy.orm import validates

from app.models import db


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


HANDLE_RE = re.compile(r"^[a-zA-Z0-9._]{2,64}$")
ALLOWED_STATUS = {"pending", "approved", "rejected"}


def _safe_strip(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None


def _clamp(s: Optional[str], max_len: int) -> Optional[str]:
    if not s:
        return None
    return s[:max_len]


def _normalize_status(v: Any) -> str:
    s = (_safe_strip(v) or "pending").lower()
    return s if s in ALLOWED_STATUS else "pending"


def _clean_phone(v: Any) -> Optional[str]:
    s = _safe_strip(v)
    if not s:
        return None
    keep = []
    for ch in s:
        if ch.isdigit() or ch in {"+", " ", "(", ")", "-"}:
            keep.append(ch)
    out = "".join(keep).strip()
    return out[:40] if out else None


def _normalize_handle_or_url(v: Any, max_len: int) -> Optional[str]:
    s = _safe_strip(v)
    if not s:
        return None
    s = s.replace(" ", "")
    if s.startswith("@"):
        s = s[1:]
    if HANDLE_RE.match(s):
        return s[:max_len]
    return s[:max_len]


def _normalize_url(v: Any, max_len: int = 200) -> Optional[str]:
    s = _safe_strip(v)
    return s[:max_len] if s else None


def _token_ref_code() -> str:
    raw = secrets.token_urlsafe(10)
    return raw.replace("-", "").replace("_", "")[:16]


class AffiliateProfile(db.Model):
    __tablename__ = "affiliate_profiles"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )

    status = db.Column(db.String(20), nullable=False, default="pending", index=True)
    ref_code = db.Column(db.String(32), nullable=False, unique=True, index=True)

    display_name = db.Column(db.String(120), nullable=True)
    phone = db.Column(db.String(40), nullable=True)

    instagram = db.Column(db.String(120), nullable=True)
    tiktok = db.Column(db.String(120), nullable=True)
    website = db.Column(db.String(200), nullable=True)

    payout_method = db.Column(db.String(40), nullable=True)
    payout_details = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    approved_at = db.Column(db.DateTime(timezone=True), nullable=True)

    user = db.relationship("User", lazy="select")

    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','approved','rejected')",
            name="ck_affiliate_status_allowed",
        ),
    )

    STATUS_PENDING = "pending"
    STATUS_APPROVED = "approved"
    STATUS_REJECTED = "rejected"

    @property
    def is_pending(self) -> bool:
        return (self.status or "").lower() == self.STATUS_PENDING

    @property
    def is_approved(self) -> bool:
        return (self.status or "").lower() == self.STATUS_APPROVED

    @property
    def is_rejected(self) -> bool:
        return (self.status or "").lower() == self.STATUS_REJECTED

    @property
    def display_label(self) -> str:
        dn = _safe_strip(self.display_name)
        if dn:
            return dn
        u = getattr(self, "user", None)
        if u is not None:
            nm = _safe_strip(getattr(u, "name", None))
            if nm:
                return nm
            em = _safe_strip(getattr(u, "email", None))
            if em and "@" in em:
                return em.split("@", 1)[0]
        return "Afiliado"

    @staticmethod
    def generate_ref_code() -> str:
        return _token_ref_code()

    @classmethod
    def ensure_unique_ref_code(cls, max_tries: int = 20) -> str:
        for _ in range(max_tries):
            code = cls.generate_ref_code()
            exists = db.session.query(cls.id).filter_by(ref_code=code).first()
            if not exists:
                return code
        return secrets.token_hex(10)[:20]

    def ensure_ref_code(self) -> str:
        if not _safe_strip(self.ref_code):
            self.ref_code = self.ensure_unique_ref_code()
        else:
            self.ref_code = _clamp(_safe_strip(self.ref_code), 32) or self.ensure_unique_ref_code()
        return self.ref_code

    @classmethod
    def create_for_user(
        cls,
        user_id: int,
        *,
        display_name: Optional[str] = None,
        phone: Optional[str] = None,
        instagram: Optional[str] = None,
        tiktok: Optional[str] = None,
        website: Optional[str] = None,
        payout_method: Optional[str] = None,
        payout_details: Optional[str] = None,
        keep_existing: bool = True,
    ) -> "AffiliateProfile":
        uid = int(user_id)
        existing = cls.query.filter_by(user_id=uid).first()
        if existing:
            if keep_existing:
                existing.display_name = display_name or existing.display_name
                existing.phone = phone or existing.phone
                existing.instagram = instagram or existing.instagram
                existing.tiktok = tiktok or existing.tiktok
                existing.website = website or existing.website
                existing.payout_method = payout_method or existing.payout_method
                existing.payout_details = payout_details or existing.payout_details
            else:
                existing.display_name = display_name
                existing.phone = phone
                existing.instagram = instagram
                existing.tiktok = tiktok
                existing.website = website
                existing.payout_method = payout_method
                existing.payout_details = payout_details
            existing.status = _normalize_status(existing.status)
            existing.ensure_ref_code()
            return existing

        p = cls(
            user_id=uid,
            status=cls.STATUS_PENDING,
            ref_code=cls.ensure_unique_ref_code(),
            display_name=display_name,
            phone=phone,
            instagram=instagram,
            tiktok=tiktok,
            website=website,
            payout_method=payout_method,
            payout_details=payout_details,
        )
        p.prepare_for_save()
        return p

    def approve(self) -> None:
        if self.is_approved:
            return
        self.status = self.STATUS_APPROVED
        if not self.approved_at:
            self.approved_at = utcnow()

    def reject(self) -> None:
        if self.is_rejected:
            return
        self.status = self.STATUS_REJECTED

    def set_pending(self) -> None:
        self.status = self.STATUS_PENDING

    def payout_details_masked(self) -> Optional[str]:
        txt = _safe_strip(self.payout_details)
        if not txt:
            return None
        if len(txt) <= 8:
            return "*" * len(txt)
        core = "*" * min(12, max(0, len(txt) - 6))
        return txt[:3] + core + txt[-3:]

    def is_ready_for_payout(self) -> bool:
        if not self.is_approved:
            return False
        return bool(_safe_strip(self.payout_method)) and bool(_safe_strip(self.payout_details))

    def prepare_for_save(self) -> None:
        self.status = _normalize_status(self.status)
        self.ensure_ref_code()

        self.display_name = _clamp(_safe_strip(self.display_name), 120)
        self.phone = _clean_phone(self.phone)

        self.instagram = _normalize_handle_or_url(self.instagram, 120)
        self.tiktok = _normalize_handle_or_url(self.tiktok, 120)
        self.website = _normalize_url(self.website, 200)

        pm = _safe_strip(self.payout_method)
        self.payout_method = pm.lower()[:40] if pm else None

        pd = _safe_strip(self.payout_details)
        self.payout_details = pd[:4000] if pd else None

        if self.status != self.STATUS_APPROVED:
            if self.approved_at is not None:
                self.approved_at = self.approved_at

    @validates("status")
    def _v_status(self, _k: str, v: Any) -> str:
        return _normalize_status(v)

    @validates("display_name")
    def _v_display_name(self, _k: str, v: Any) -> Optional[str]:
        return _clamp(_safe_strip(v), 120)

    @validates("phone")
    def _v_phone(self, _k: str, v: Any) -> Optional[str]:
        return _clean_phone(v)

    @validates("instagram")
    def _v_instagram(self, _k: str, v: Any) -> Optional[str]:
        return _normalize_handle_or_url(v, 120)

    @validates("tiktok")
    def _v_tiktok(self, _k: str, v: Any) -> Optional[str]:
        return _normalize_handle_or_url(v, 120)

    @validates("website")
    def _v_website(self, _k: str, v: Any) -> Optional[str]:
        return _normalize_url(v, 200)

    @validates("payout_method")
    def _v_payout_method(self, _k: str, v: Any) -> Optional[str]:
        s = _safe_strip(v)
        return s.lower()[:40] if s else None

    @validates("payout_details")
    def _v_payout_details(self, _k: str, v: Any) -> Optional[str]:
        s = _safe_strip(v)
        return s[:4000] if s else None

    @validates("ref_code")
    def _v_ref_code(self, _k: str, v: Any) -> str:
        s = (_safe_strip(v) or "").strip()
        return s[:32]

    def as_admin_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "status": self.status,
            "ref_code": self.ref_code,
            "display_name": self.display_name,
            "display_label": self.display_label,
            "phone": self.phone,
            "instagram": self.instagram,
            "tiktok": self.tiktok,
            "website": self.website,
            "payout_method": self.payout_method,
            "payout_details_masked": self.payout_details_masked(),
            "is_ready_for_payout": self.is_ready_for_payout(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
        }

    def as_public_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "ref_code": self.ref_code,
            "referral_path": self.referral_path(),
            "display_name": self.display_name,
            "instagram": self.instagram,
            "tiktok": self.tiktok,
            "website": self.website,
            "payout_method": self.payout_method,
            "is_ready_for_payout": self.is_ready_for_payout(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
        }

    def referral_path(self) -> str:
        return f"/r/{self.ref_code}"

    def referral_url(self, base_url: str) -> str:
        b = (base_url or "").rstrip("/")
        return f"{b}{self.referral_path()}" if b else self.referral_path()

    def __repr__(self) -> str:
        return (
            f"<AffiliateProfile id={self.id} user_id={self.user_id} "
            f"status={self.status!r} ref={self.ref_code!r}>"
        )


Index("ix_affiliate_profiles_status_created", AffiliateProfile.status, AffiliateProfile.created_at)
Index("ix_affiliate_profiles_user_status", AffiliateProfile.user_id, AffiliateProfile.status)


@event.listens_for(AffiliateProfile, "before_insert", propagate=True)
def _aff_before_insert(_mapper, _conn, target: AffiliateProfile):
    target.prepare_for_save()


@event.listens_for(AffiliateProfile, "before_update", propagate=True)
def _aff_before_update(_mapper, _conn, target: AffiliateProfile):
    target.prepare_for_save()
