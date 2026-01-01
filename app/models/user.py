# app/models/user.py
from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional

from flask_login import UserMixin
from sqlalchemy import Index
from sqlalchemy.orm import validates

from app.models import db
from app.utils.security import hash_password, verify_password

# ============================================================
# Helpers
# ============================================================

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def _token64() -> str:
    """Token EXACTO 64 chars (hex)."""
    return secrets.token_hex(32)


def _safe_strip(v: Optional[str]) -> Optional[str]:
    if v is None:
        return None
    vv = v.strip()
    return vv if vv else None


# ============================================================
# User
# ============================================================

class User(UserMixin, db.Model):
    """
    Skyline Store — User ULTRA PRO (FINAL)
    ✅ Flask-Login compatible
    ✅ Cliente + Admin + Checkout + Marketing
    ✅ Hash seguro + lockouts
    ✅ Tokens 64 fixed (DB safe)
    """

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    # -------------------------
    # Auth
    # -------------------------
    email = db.Column(db.String(255), unique=True, index=True, nullable=False)

    # nullable=True para NO romper DB vieja.
    password_hash = db.Column(db.String(255), nullable=True)

    name = db.Column(db.String(120), nullable=True)
    phone = db.Column(db.String(40), nullable=True)

    # -------------------------
    # Segmentación
    # -------------------------
    country = db.Column(db.String(2), nullable=True, index=True)  # ISO2
    city = db.Column(db.String(80), nullable=True)

    # -------------------------
    # Estado / roles
    # -------------------------
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)

    # Legacy/admin boolean (tu app ya lo usa)
    is_admin = db.Column(db.Boolean, nullable=False, default=False, index=True)

    # Role string (opcional, PRO). No rompe: puede ser NULL.
    # Si lo usás: "admin" / "staff" / "customer"
    role = db.Column(db.String(20), nullable=True, index=True)

    # -------------------------
    # Email verification
    # -------------------------
    email_verified = db.Column(db.Boolean, nullable=False, default=False, index=True)
    email_verified_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # -------------------------
    # Auditoría / seguridad
    # -------------------------
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    last_login_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)
    password_changed_at = db.Column(db.DateTime(timezone=True), nullable=True)

    failed_login_count = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime(timezone=True), nullable=True, index=True)

    # -------------------------
    # Tokens (64 fixed)
    # -------------------------
    email_verify_token = db.Column(db.String(64), nullable=True, unique=True, index=True)
    reset_password_token = db.Column(db.String(64), nullable=True, unique=True, index=True)
    reset_password_expires_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # -------------------------
    # Marketing
    # -------------------------
    email_opt_in = db.Column(db.Boolean, nullable=False, default=True, index=True)
    email_opt_in_at = db.Column(db.DateTime(timezone=True), nullable=True)

    unsubscribe_token = db.Column(
        db.String(64),
        nullable=False,
        unique=True,
        index=True,
        default=_token64,
    )

    # -------------------------
    # Relaciones (BLINDADAS)
    # -------------------------
    addresses = db.relationship(
        "UserAddress",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="select",
        passive_deletes=True,
    )

    orders = db.relationship(
        "Order",
        back_populates="user",
        lazy="select",
        passive_deletes=True,
    )

    # ============================================================
    # Flask-Login compatibility
    # ============================================================

    def get_id(self) -> str:
        # Flask-Login usa string
        return str(self.id)

    @property
    def is_staff(self) -> bool:
        # staff = admin o role staff
        r = (self.role or "").lower().strip()
        return bool(self.is_admin) or r in {"admin", "staff"}

    @property
    def role_effective(self) -> str:
        # para UI / permisos: no rompe si role NULL
        if self.is_admin:
            return "admin"
        r = (self.role or "").lower().strip()
        return r if r else "customer"

    # ============================================================
    # Password
    # ============================================================

    def set_password(self, raw_password: str) -> None:
        raw_password = (raw_password or "").strip()
        if not raw_password:
            raise ValueError("Password vacío")
        self.password_hash = hash_password(raw_password)
        self.password_changed_at = utcnow()

    def check_password(self, raw_password: str) -> bool:
        if not self.password_hash:
            return False
        return verify_password(raw_password or "", self.password_hash)

    # ============================================================
    # Login / Lockouts
    # ============================================================

    def can_login(self) -> bool:
        if not self.is_active:
            return False
        if self.locked_until and utcnow() < self.locked_until:
            return False
        return True

    def mark_login(self) -> None:
        self.last_login_at = utcnow()
        self.failed_login_count = 0
        self.locked_until = None

    def mark_failed_login(self, lock_after: int = 8, lock_minutes: int = 15) -> None:
        self.failed_login_count = int(self.failed_login_count or 0) + 1
        if self.failed_login_count >= int(lock_after):
            self.locked_until = utcnow() + timedelta(minutes=int(lock_minutes))

    # ============================================================
    # Email verify / reset tokens
    # ============================================================

    def ensure_email_verify_token(self) -> str:
        if not self.email_verify_token:
            self.email_verify_token = _token64()
        return self.email_verify_token

    def verify_email(self) -> None:
        self.email_verified = True
        self.email_verified_at = utcnow()
        self.email_verify_token = None

    def create_reset_token(self, minutes: int = 30) -> str:
        self.reset_password_token = _token64()
        self.reset_password_expires_at = utcnow() + timedelta(minutes=int(minutes))
        return self.reset_password_token

    def reset_token_is_valid(self, token: str) -> bool:
        if not token or not self.reset_password_token:
            return False
        if token.strip() != self.reset_password_token:
            return False
        if not self.reset_password_expires_at:
            return False
        return utcnow() <= self.reset_password_expires_at

    def clear_reset_token(self) -> None:
        self.reset_password_token = None
        self.reset_password_expires_at = None

    # ============================================================
    # Marketing helpers
    # ============================================================

    def subscribe_email(self) -> None:
        self.email_opt_in = True
        self.email_opt_in_at = utcnow()

    def unsubscribe_email(self) -> None:
        self.email_opt_in = False

    # ============================================================
    # Checkout helpers
    # ============================================================

    @property
    def display_name(self) -> str:
        nm = (self.name or "").strip()
        if nm:
            return nm
        if self.email:
            return self.email.split("@")[0]
        return "Usuario"

    def default_address(self) -> Optional["UserAddress"]:
        addrs = self.addresses or []
        for a in addrs:
            if a.is_default:
                return a
        return addrs[0] if addrs else None

    # ============================================================
    # Normalización / validaciones suaves
    # ============================================================

    @staticmethod
    def normalize_email(email: str) -> str:
        return (email or "").strip().lower()

    @validates("email")
    def _v_email(self, _k, v: str) -> str:
        vv = self.normalize_email(v)
        # No rompe: solo limpia
        return vv[:255] if vv else ""

    @validates("country")
    def _v_country(self, _k, v: Optional[str]) -> Optional[str]:
        vv = _safe_strip(v)
        return vv.upper()[:2] if vv else None

    @validates("name")
    def _v_name(self, _k, v: Optional[str]) -> Optional[str]:
        vv = _safe_strip(v)
        return vv[:120] if vv else None

    @validates("phone")
    def _v_phone(self, _k, v: Optional[str]) -> Optional[str]:
        vv = _safe_strip(v)
        if not vv:
            return None
        cleaned = "".join(ch for ch in vv if ch.isdigit() or ch in {"+", " ", "(", ")", "-"}).strip()
        return cleaned[:40] if cleaned else None

    @validates("role")
    def _v_role(self, _k, v: Optional[str]) -> Optional[str]:
        vv = _safe_strip(v)
        return vv.lower()[:20] if vv else None

    # ============================================================
    # Safety: ensure tokens
    # ============================================================

    def ensure_tokens(self) -> None:
        if not self.unsubscribe_token:
            self.unsubscribe_token = _token64()

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email!r} role={self.role_effective!r} active={bool(self.is_active)}>"

Index("ix_users_active_admin", User.is_active, User.is_admin)
Index("ix_users_country_city", User.country, User.city)
Index("ix_users_email_verified", User.email_verified)


# ============================================================
# UserAddress
# ============================================================

class UserAddress(db.Model):
    """
    Direcciones:
    - múltiples
    - 1 sola default real
    """

    __tablename__ = "user_addresses"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    label = db.Column(db.String(50), nullable=True)
    full_name = db.Column(db.String(120), nullable=True)
    phone = db.Column(db.String(40), nullable=True)

    line1 = db.Column(db.String(200), nullable=False)
    line2 = db.Column(db.String(200), nullable=True)

    city = db.Column(db.String(120), nullable=True)
    state = db.Column(db.String(120), nullable=True)
    postal_code = db.Column(db.String(40), nullable=True)
    country = db.Column(db.String(2), nullable=True)

    is_default = db.Column(db.Boolean, nullable=False, default=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)

    user = db.relationship("User", back_populates="addresses", lazy="select")

    @validates("label")
    def _v_label(self, _k, v: Optional[str]) -> Optional[str]:
        vv = _safe_strip(v)
        return vv[:50] if vv else None

    @validates("country")
    def _v_country(self, _k, v: Optional[str]) -> Optional[str]:
        vv = _safe_strip(v)
        return vv.upper()[:2] if vv else None

    @validates("full_name")
    def _v_full_name(self, _k, v: Optional[str]) -> Optional[str]:
        vv = _safe_strip(v)
        return vv[:120] if vv else None

    @validates("phone")
    def _v_phone(self, _k, v: Optional[str]) -> Optional[str]:
        vv = _safe_strip(v)
        if not vv:
            return None
        cleaned = "".join(ch for ch in vv if ch.isdigit() or ch in {"+", " ", "(", ")", "-"}).strip()
        return cleaned[:40] if cleaned else None

    def set_as_default(self) -> None:
        """
        Marca esta dirección como default y desmarca las demás.
        ✅ Seguro: update masivo sin necesitar cargar todo.
        """
        if not self.user_id:
            self.is_default = True
            return

        db.session.query(UserAddress).filter(
            UserAddress.user_id == self.user_id,
            UserAddress.id != self.id,
        ).update({"is_default": False}, synchronize_session=False)

        self.is_default = True

    def __repr__(self) -> str:
        return f"<UserAddress id={self.id} user_id={self.user_id} default={bool(self.is_default)}>"

Index("ix_user_addresses_user_default", UserAddress.user_id, UserAddress.is_default)
