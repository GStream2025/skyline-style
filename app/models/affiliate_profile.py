from __future__ import annotations

import secrets
import re
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from sqlalchemy import Index, CheckConstraint, event
from sqlalchemy.orm import validates

from app.models import db

# ============================================================
# Helpers
# ============================================================


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


HANDLE_RE = re.compile(r"^[a-zA-Z0-9._]{2,64}$")


def _safe_strip(v: Optional[str]) -> Optional[str]:
    if v is None:
        return None
    vv = str(v).strip()
    return vv if vv else None


def _clamp_str(v: Optional[str], max_len: int) -> Optional[str]:
    vv = _safe_strip(v)
    if not vv:
        return None
    return vv[:max_len]


def _normalize_status(v: Optional[str]) -> str:
    vv = (_safe_strip(v) or "pending").lower()
    return vv if vv in {"pending", "approved", "rejected"} else "pending"


def _clean_phone(v: Optional[str]) -> Optional[str]:
    vv = _safe_strip(v)
    if not vv:
        return None
    cleaned = "".join(
        ch for ch in vv if ch.isdigit() or ch in {"+", " ", "(", ")", "-"}
    ).strip()
    return cleaned[:40] if cleaned else None


def _normalize_handle_or_url(v: Optional[str], max_len: int) -> Optional[str]:
    """
    Acepta:
    - '@usuario'
    - 'usuario'
    - 'https://instagram.com/usuario'
    - 'instagram.com/usuario'
    Guarda el string normalizado sin inventar esquemas.
    """
    vv = _safe_strip(v)
    if not vv:
        return None
    vv = vv.replace(" ", "")
    if vv.startswith("@"):
        vv = vv[1:]
    # si es handle puro, ok
    if HANDLE_RE.match(vv):
        return vv[:max_len]
    # si parece url/dominio, lo guardamos
    return vv[:max_len]


def _normalize_url(v: Optional[str], max_len: int = 200) -> Optional[str]:
    vv = _safe_strip(v)
    if not vv:
        return None
    return vv[:max_len]


# ============================================================
# AffiliateProfile
# ============================================================


class AffiliateProfile(db.Model):
    """
    Skyline Store — AffiliateProfile (PRO / FINAL / NO BREAK)

    - Cualquiera puede registrarse como afiliado/socio (se crea en register)
    - Admin ve solicitudes (pending) y aprueba/rechaza
    - ref_code único para link /r/<ref_code>

    Filosofía:
    - NO BREAK: no agregamos columnas nuevas
    - Validaciones suaves y helpers “enterprise”
    """

    __tablename__ = "affiliate_profiles"

    # PK
    id = db.Column(db.Integer, primary_key=True)

    # FK (1 a 1 con user)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )

    # Estado + referral code
    status = db.Column(db.String(20), nullable=False, default="pending", index=True)
    ref_code = db.Column(db.String(32), nullable=False, unique=True, index=True)

    # Datos del socio
    display_name = db.Column(db.String(120), nullable=True)
    phone = db.Column(db.String(40), nullable=True)

    instagram = db.Column(
        db.String(120), nullable=True
    )  # guardamos handle normalizado (sin @)
    tiktok = db.Column(db.String(120), nullable=True)
    website = db.Column(db.String(200), nullable=True)

    payout_method = db.Column(db.String(40), nullable=True)
    payout_details = db.Column(db.Text, nullable=True)

    created_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    approved_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Relación al usuario
    user = db.relationship("User", lazy="select")

    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','approved','rejected')",
            name="ck_affiliate_status_allowed",
        ),
    )

    # Constantes
    STATUS_PENDING = "pending"
    STATUS_APPROVED = "approved"
    STATUS_REJECTED = "rejected"

    # ============================================================
    # Estado / UX
    # ============================================================

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
        """
        Etiqueta bonita para UI/admin:
        display_name > user.name > user.email_username
        """
        dn = (self.display_name or "").strip()
        if dn:
            return dn
        try:
            if self.user and getattr(self.user, "name", None):
                nm = (self.user.name or "").strip()
                if nm:
                    return nm
            if self.user and getattr(self.user, "email", None):
                em = (self.user.email or "").strip()
                if em and "@" in em:
                    return em.split("@", 1)[0]
        except Exception:
            pass
        return "Afiliado"

    # ============================================================
    # Referral code — ultra robusto
    # ============================================================

    @staticmethod
    def generate_ref_code() -> str:
        """
        Genera un code corto, consistente, amigable:
        - lo limpiamos
        - lo recortamos a 16 para que sea estable
        """
        raw = secrets.token_urlsafe(10)
        cleaned = raw.replace("-", "").replace("_", "")
        return cleaned[:16]

    @classmethod
    def ensure_unique_ref_code(cls, max_tries: int = 15) -> str:
        """
        Anti-colisiones real (y sin depender del caller).
        """
        for _ in range(max_tries):
            code = cls.generate_ref_code()
            exists = db.session.query(cls.id).filter_by(ref_code=code).first()
            if not exists:
                return code
        # fallback ultra fuerte
        return secrets.token_hex(8)

    def ensure_ref_code(self) -> str:
        if not (self.ref_code or "").strip():
            self.ref_code = self.ensure_unique_ref_code()
        return self.ref_code

    # ============================================================
    # Creación segura (para register)
    # ============================================================

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
    ) -> "AffiliateProfile":
        """
        Crea o devuelve el perfil del user (evita duplicados).
        Ideal para usar en /register.
        """
        existing = cls.query.filter_by(user_id=int(user_id)).first()
        if existing:
            # actualiza datos (soft)
            existing.display_name = display_name or existing.display_name
            existing.phone = phone or existing.phone
            existing.instagram = instagram or existing.instagram
            existing.tiktok = tiktok or existing.tiktok
            existing.website = website or existing.website
            existing.payout_method = payout_method or existing.payout_method
            existing.payout_details = payout_details or existing.payout_details
            existing.status = existing.status or cls.STATUS_PENDING
            existing.ensure_ref_code()
            return existing

        p = cls(
            user_id=int(user_id),
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
        return p

    # ============================================================
    # Transiciones de estado (dominio)
    # ============================================================

    def approve(self) -> None:
        """
        Pasa a approved y setea approved_at (solo si no estaba).
        """
        if self.is_approved:
            return
        self.status = self.STATUS_APPROVED
        if not self.approved_at:
            self.approved_at = utcnow()

    def reject(self) -> None:
        """
        Pasa a rejected.
        """
        if self.is_rejected:
            return
        self.status = self.STATUS_REJECTED

    def set_pending(self) -> None:
        """
        Vuelve a pending.
        """
        self.status = self.STATUS_PENDING

    # ============================================================
    # Payout (experiencia pro)
    # ============================================================

    def payout_details_masked(self) -> Optional[str]:
        """
        Devuelve payout_details “enmascarado” para mostrar sin filtrar todo.
        """
        txt = _safe_strip(self.payout_details)
        if not txt:
            return None
        if len(txt) <= 8:
            return "*" * len(txt)
        return txt[:3] + ("*" * min(12, len(txt) - 6)) + txt[-3:]

    def is_ready_for_payout(self) -> bool:
        """
        PRO: El afiliado está listo para cobrar si:
        - status approved
        - payout_method y payout_details presentes
        """
        if not self.is_approved:
            return False
        return bool(_safe_strip(self.payout_method)) and bool(
            _safe_strip(self.payout_details)
        )

    # ============================================================
    # Validaciones suaves (NO BREAK)
    # ============================================================

    def prepare_for_save(self) -> None:
        """
        Centraliza normalización, reduce bugs y repetición.
        """
        try:
            self.status = _normalize_status(self.status)
        except Exception:
            pass
        try:
            self.ensure_ref_code()
        except Exception:
            pass
        try:
            self.display_name = _clamp_str(self.display_name, 120)
        except Exception:
            pass
        try:
            self.phone = _clean_phone(self.phone)
        except Exception:
            pass
        try:
            self.instagram = _normalize_handle_or_url(self.instagram, 120)
        except Exception:
            pass
        try:
            self.tiktok = _normalize_handle_or_url(self.tiktok, 120)
        except Exception:
            pass
        try:
            self.website = _normalize_url(self.website, 200)
        except Exception:
            pass
        try:
            pm = _safe_strip(self.payout_method)
            self.payout_method = pm.lower()[:40] if pm else None
        except Exception:
            pass
        try:
            pd = _safe_strip(self.payout_details)
            self.payout_details = pd[:4000] if pd else None
        except Exception:
            pass

    @validates("status")
    def _v_status(self, _k, v: Optional[str]) -> str:
        return _normalize_status(v)

    @validates("display_name")
    def _v_display_name(self, _k, v: Optional[str]) -> Optional[str]:
        return _clamp_str(v, 120)

    @validates("phone")
    def _v_phone(self, _k, v: Optional[str]) -> Optional[str]:
        return _clean_phone(v)

    @validates("instagram")
    def _v_instagram(self, _k, v: Optional[str]) -> Optional[str]:
        return _normalize_handle_or_url(v, 120)

    @validates("tiktok")
    def _v_tiktok(self, _k, v: Optional[str]) -> Optional[str]:
        return _normalize_handle_or_url(v, 120)

    @validates("website")
    def _v_website(self, _k, v: Optional[str]) -> Optional[str]:
        return _normalize_url(v, 200)

    @validates("payout_method")
    def _v_payout_method(self, _k, v: Optional[str]) -> Optional[str]:
        vv = _safe_strip(v)
        return vv.lower()[:40] if vv else None

    @validates("payout_details")
    def _v_payout_details(self, _k, v: Optional[str]) -> Optional[str]:
        vv = _safe_strip(v)
        return vv[:4000] if vv else None

    @validates("ref_code")
    def _v_ref_code(self, _k, v: str) -> str:
        return (v or "").strip()[:32]

    # ============================================================
    # Serialización segura
    # ============================================================

    def as_admin_dict(self) -> Dict[str, Any]:
        """
        Para panel admin: incluye masked payout para listar.
        """
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
        """
        Para dashboard del afiliado.
        """
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

    # ============================================================
    # Links
    # ============================================================

    def referral_path(self) -> str:
        return f"/r/{self.ref_code}"

    def referral_url(self, base_url: str) -> str:
        """
        Arma URL absoluta:
        base_url ejemplo: https://skyline-store.com
        """
        b = (base_url or "").rstrip("/")
        return f"{b}{self.referral_path()}" if b else self.referral_path()

    # ============================================================
    # Debug
    # ============================================================

    def __repr__(self) -> str:
        return f"<AffiliateProfile id={self.id} user_id={self.user_id} status={self.status!r} ref={self.ref_code!r}>"


# ============================================================
# Índices recomendados
# ============================================================

Index(
    "ix_affiliate_profiles_status_created",
    AffiliateProfile.status,
    AffiliateProfile.created_at,
)
Index(
    "ix_affiliate_profiles_user_status",
    AffiliateProfile.user_id,
    AffiliateProfile.status,
)


# ============================================================
# Hooks ultra safe (NO BREAK)
# ============================================================


@event.listens_for(AffiliateProfile, "before_insert", propagate=True)
def _aff_before_insert(_mapper, _conn, target: AffiliateProfile):
    try:
        target.prepare_for_save()
    except Exception:
        pass


@event.listens_for(AffiliateProfile, "before_update", propagate=True)
def _aff_before_update(_mapper, _conn, target: AffiliateProfile):
    try:
        target.prepare_for_save()
    except Exception:
        pass
