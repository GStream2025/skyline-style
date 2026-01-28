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


_HANDLE_RE = re.compile(r"^[a-zA-Z0-9._]{2,64}$")
_ALLOWED_STATUS = {"pending", "approved", "rejected"}

_DISPLAY_NAME_MAX = 120
_PHONE_MAX = 40
_HANDLE_MAX = 120
_URL_MAX = 200
_PAYOUT_METHOD_MAX = 40
_PAYOUT_DETAILS_MAX = 4000
_REF_CODE_MAX = 32
_REF_CODE_TRIES = 30


def _strip(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = str(v).replace("\x00", "").replace("\u200b", "").strip()
    if not s:
        return None
    s = " ".join(s.split())
    return s


def _clip(s: Optional[str], n: int) -> Optional[str]:
    if not s:
        return None
    if n <= 0:
        return None
    return s[:n]


def _status(v: Any) -> str:
    s = (_strip(v) or "pending").lower()
    return s if s in _ALLOWED_STATUS else "pending"


def _clean_phone(v: Any) -> Optional[str]:
    s = _strip(v)
    if not s:
        return None
    keep = []
    for ch in s:
        if ch.isdigit() or ch in {"+", " ", "(", ")", "-"}:
            keep.append(ch)
    out = "".join(keep).strip()
    if not out:
        return None
    out = " ".join(out.split())
    return out[:_PHONE_MAX]


def _clean_handle(v: Any, *, max_len: int = _HANDLE_MAX) -> Optional[str]:
    s = _strip(v)
    if not s:
        return None
    s = s.replace(" ", "")
    if s.startswith("@"):
        s = s[1:]
    s = _clip(s, max_len)
    return s if (s and _HANDLE_RE.match(s)) else s


def _clean_url(v: Any, *, max_len: int = _URL_MAX) -> Optional[str]:
    s = _strip(v)
    if not s:
        return None
    return _clip(s, max_len)


def _token_ref_code() -> str:
    raw = secrets.token_urlsafe(12)
    raw = raw.replace("-", "").replace("_", "")
    return (raw[:16] if len(raw) >= 16 else (raw + secrets.token_hex(8))[:16])


def _normalize_ref_code(v: Any) -> Optional[str]:
    s = _strip(v)
    if not s:
        return None
    s = s.replace(" ", "").strip()
    s = s.replace("-", "").replace("_", "")
    s = "".join(ch for ch in s if ch.isalnum())
    if not s:
        return None
    return s[:_REF_CODE_MAX]


class AffiliateProfile(db.Model):
    __tablename__ = "affiliate_profiles"

    STATUS_PENDING = "pending"
    STATUS_APPROVED = "approved"
    STATUS_REJECTED = "rejected"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )

    status = db.Column(db.String(20), nullable=False, default=STATUS_PENDING, index=True)
    ref_code = db.Column(db.String(_REF_CODE_MAX), nullable=False, unique=True, index=True)

    display_name = db.Column(db.String(_DISPLAY_NAME_MAX), nullable=True)
    phone = db.Column(db.String(_PHONE_MAX), nullable=True)

    instagram = db.Column(db.String(_HANDLE_MAX), nullable=True)
    tiktok = db.Column(db.String(_HANDLE_MAX), nullable=True)
    website = db.Column(db.String(_URL_MAX), nullable=True)

    payout_method = db.Column(db.String(_PAYOUT_METHOD_MAX), nullable=True)
    payout_details = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    approved_at = db.Column(db.DateTime(timezone=True), nullable=True)

    user = db.relationship("User", lazy="select")

    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','approved','rejected')",
            name="ck_affiliate_status_allowed",
        ),
        CheckConstraint("length(ref_code) <= 32", name="ck_affiliate_ref_len"),
        Index("ix_affiliate_profiles_status_created", "status", "created_at"),
        Index("ix_affiliate_profiles_user_status", "user_id", "status"),
    )

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
        dn = _strip(self.display_name)
        if dn:
            return dn
        u = getattr(self, "user", None)
        if u is not None:
            nm = _strip(getattr(u, "name", None))
            if nm:
                return nm
            em = _strip(getattr(u, "email", None))
            if em and "@" in em:
                return em.split("@", 1)[0]
        return "Afiliado"

    @staticmethod
    def generate_ref_code() -> str:
        return _token_ref_code()

    @classmethod
    def ensure_unique_ref_code(cls, max_tries: int = _REF_CODE_TRIES) -> str:
        tries = _clamp(max_tries, 3)
        n = int(tries or _REF_CODE_TRIES)
        for _ in range(max(3, n)):
            code = cls.generate_ref_code()
            exists = db.session.query(cls.id).filter_by(ref_code=code).first()
            if not exists:
                return code
        return secrets.token_hex(12)[:_REF_CODE_MAX]

    def ensure_ref_code(self) -> str:
        current = _normalize_ref_code(self.ref_code)
        if not current:
            self.ref_code = self.ensure_unique_ref_code()
            return self.ref_code

        if current != self.ref_code:
            self.ref_code = current

        exists = (
            db.session.query(AffiliateProfile.id)
            .filter(AffiliateProfile.ref_code == self.ref_code, AffiliateProfile.id != (self.id or 0))
            .first()
        )
        if exists:
            self.ref_code = self.ensure_unique_ref_code()
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
                if display_name is not None:
                    existing.display_name = display_name
                if phone is not None:
                    existing.phone = phone
                if instagram is not None:
                    existing.instagram = instagram
                if tiktok is not None:
                    existing.tiktok = tiktok
                if website is not None:
                    existing.website = website
                if payout_method is not None:
                    existing.payout_method = payout_method
                if payout_details is not None:
                    existing.payout_details = payout_details
            else:
                existing.display_name = display_name
                existing.phone = phone
                existing.instagram = instagram
                existing.tiktok = tiktok
                existing.website = website
                existing.payout_method = payout_method
                existing.payout_details = payout_details

            existing.status = _status(existing.status)
            existing.prepare_for_save()
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
        txt = _strip(self.payout_details)
        if not txt:
            return None
        t = txt.strip()
        if len(t) <= 8:
            return "*" * len(t)
        core_len = max(0, len(t) - 6)
        core = "*" * min(24, core_len)
        return t[:3] + core + t[-3:]

    def is_ready_for_payout(self) -> bool:
        if not self.is_approved:
            return False
        return bool(_strip(self.payout_method)) and bool(_strip(self.payout_details))

    def prepare_for_save(self) -> None:
        self.status = _status(self.status)
        self.display_name = _clip(_strip(self.display_name), _DISPLAY_NAME_MAX)
        self.phone = _clean_phone(self.phone)

        self.instagram = _clean_handle(self.instagram, max_len=_HANDLE_MAX)
        self.tiktok = _clean_handle(self.tiktok, max_len=_HANDLE_MAX)
        self.website = _clean_url(self.website, max_len=_URL_MAX)

        pm = _strip(self.payout_method)
        self.payout_method = (pm.lower()[:_PAYOUT_METHOD_MAX] if pm else None)

        pd = _strip(self.payout_details)
        self.payout_details = (pd[:_PAYOUT_DETAILS_MAX] if pd else None)

        if self.status == self.STATUS_APPROVED:
            if not self.approved_at:
                self.approved_at = utcnow()
        else:
            self.approved_at = None

        self.ensure_ref_code()

    @validates("status")
    def _v_status(self, _k: str, v: Any) -> str:
        return _status(v)

    @validates("display_name")
    def _v_display_name(self, _k: str, v: Any) -> Optional[str]:
        return _clip(_strip(v), _DISPLAY_NAME_MAX)

    @validates("phone")
    def _v_phone(self, _k: str, v: Any) -> Optional[str]:
        return _clean_phone(v)

    @validates("instagram")
    def _v_instagram(self, _k: str, v: Any) -> Optional[str]:
        return _clean_handle(v, max_len=_HANDLE_MAX)

    @validates("tiktok")
    def _v_tiktok(self, _k: str, v: Any) -> Optional[str]:
        return _clean_handle(v, max_len=_HANDLE_MAX)

    @validates("website")
    def _v_website(self, _k: str, v: Any) -> Optional[str]:
        return _clean_url(v, max_len=_URL_MAX)

    @validates("payout_method")
    def _v_payout_method(self, _k: str, v: Any) -> Optional[str]:
        s = _strip(v)
        return s.lower()[:_PAYOUT_METHOD_MAX] if s else None

    @validates("payout_details")
    def _v_payout_details(self, _k: str, v: Any) -> Optional[str]:
        s = _strip(v)
        return s[:_PAYOUT_DETAILS_MAX] if s else None

    @validates("ref_code")
    def _v_ref_code(self, _k: str, v: Any) -> str:
        return _normalize_ref_code(v) or self.ensure_unique_ref_code()

    def referral_path(self) -> str:
        rc = _strip(self.ref_code) or ""
        return f"/r/{rc}"

    def referral_url(self, base_url: str) -> str:
        b = (base_url or "").strip().rstrip("/")
        return f"{b}{self.referral_path()}" if b else self.referral_path()

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

    def __repr__(self) -> str:
        return (
            f"<AffiliateProfile id={self.id} user_id={self.user_id} "
            f"status={self.status!r} ref={self.ref_code!r}>"
        )


@event.listens_for(AffiliateProfile, "before_insert", propagate=True)
@event.listens_for(AffiliateProfile, "before_update", propagate=True)
def _aff_before_save(_mapper, _conn, target: AffiliateProfile) -> None:
    target.prepare_for_save()


__all__ = ["AffiliateProfile", "utcnow"]
