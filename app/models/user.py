from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import Index
from sqlalchemy.orm import validates

from app.models import db
from app.utils.security import hash_password, verify_password


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# email soft validation (no rompe, pero limpia)
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def _token64() -> str:
    """
    ✅ Mejora #1: token EXACTO 64 chars (hex) -> nunca rompe columnas String(64).
    """
    return secrets.token_hex(32)  # 64 chars


class User(db.Model):
    """
    Skyline Store — User ULTRA PRO (FINAL)

    ✅ Cliente + Admin + Checkout + Marketing.
    ✅ Compatible con tu hash_password/verify_password.
    """

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    # Auth
    email = db.Column(db.String(255), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    name = db.Column(db.String(120), nullable=True)
    phone = db.Column(db.String(40), nullable=True)

    # Segmentación
    country = db.Column(db.String(2), nullable=True, index=True)  # ISO2
    city = db.Column(db.String(80), nullable=True)

    # Estado / roles
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    is_admin = db.Column(db.Boolean, nullable=False, default=False, index=True)

    # Email verification
    email_verified = db.Column(db.Boolean, nullable=False, default=False, index=True)
    email_verified_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Seguridad / auditoría
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    last_login_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)
    password_changed_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Anti abuso (lockouts listos)
    failed_login_count = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime(timezone=True), nullable=True, index=True)

    # Tokens (64 fixed)
    email_verify_token = db.Column(db.String(64), nullable=True, unique=True, index=True)
    reset_password_token = db.Column(db.String(64), nullable=True, unique=True, index=True)
    reset_password_expires_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Marketing / consentimiento
    email_opt_in = db.Column(db.Boolean, nullable=False, default=True, index=True)
    email_opt_in_at = db.Column(db.DateTime(timezone=True), nullable=True)

    unsubscribe_token = db.Column(
        db.String(64),
        nullable=False,
        unique=True,
        index=True,
        default=_token64,  # ✅ Mejora #2: 64 exacto
    )

    # Relaciones
    addresses = db.relationship(
        "UserAddress",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="select",
    )

    orders = db.relationship(
        "Order",
        back_populates="user",
        lazy="select",
    )

    # ============================================================
    # Password
    # ============================================================

    def set_password(self, raw_password: str) -> None:
        self.password_hash = hash_password(raw_password)
        self.password_changed_at = utcnow()

    def check_password(self, raw_password: str) -> bool:
        return verify_password(raw_password, self.password_hash)

    # ============================================================
    # Login / Lockouts
    # ============================================================

    def can_login(self) -> bool:
        """
        ✅ Mejora #3: guard real
        """
        if not self.is_active:
            return False
        if self.locked_until and utcnow() < self.locked_until:
            return False
        return True

    def mark_login(self) -> None:
        """
        ✅ Mejora #4: auditoría + limpia lockouts
        """
        self.last_login_at = utcnow()
        self.failed_login_count = 0
        self.locked_until = None

    def mark_failed_login(self, lock_after: int = 8, lock_minutes: int = 15) -> None:
        """
        ✅ Mejora #5: anti-bruteforce sin tocar routes.
        """
        self.failed_login_count = int(self.failed_login_count or 0) + 1
        if self.failed_login_count >= int(lock_after):
            self.locked_until = utcnow() + timedelta(minutes=int(lock_minutes))

    # ============================================================
    # Email verify / reset tokens
    # ============================================================

    def ensure_email_verify_token(self) -> str:
        """
        ✅ Mejora #6: token 64 fijo (no rompe DB)
        """
        if not self.email_verify_token:
            self.email_verify_token = _token64()
        return self.email_verify_token

    def verify_email(self) -> None:
        self.email_verified = True
        self.email_verified_at = utcnow()
        self.email_verify_token = None

    def create_reset_token(self, minutes: int = 30) -> str:
        """
        ✅ Mejora #7: reset token + expiry robusto
        """
        self.reset_password_token = _token64()
        self.reset_password_expires_at = utcnow() + timedelta(minutes=int(minutes))
        return self.reset_password_token

    def reset_token_is_valid(self, token: str) -> bool:
        """
        ✅ Mejora #8: verificación segura
        """
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
        return (self.name or "").strip() or (self.email.split("@")[0] if self.email else "Usuario")

    def default_address(self) -> Optional["UserAddress"]:
        for a in (self.addresses or []):
            if a.is_default:
                return a
        return (self.addresses[0] if self.addresses else None)

    # ============================================================
    # Normalización / validaciones suaves
    # ============================================================

    @staticmethod
    def normalize_email(email: str) -> str:
        return (email or "").strip().lower()

    @validates("email")
    def _v_email(self, _k, v: str) -> str:
        v = self.normalize_email(v)
        # ✅ Mejora #9: no rompe, pero evita basura extrema
        if v and not EMAIL_RE.match(v):
            # lo guardamos igual “limpio” para no romper forms legacy,
            # pero queda normalizado y recortado.
            return v[:255]
        return v[:255] if v else ""

    @validates("country")
    def _v_country(self, _k, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        v = v.strip().upper()
        return v[:2] if v else None

    @validates("name")
    def _v_name(self, _k, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        v = v.strip()
        return v[:120] if v else None

    @validates("phone")
    def _v_phone(self, _k, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        v = v.strip()
        if not v:
            return None
        # ✅ Mejora #10: limpia pero permite + y números (no rompe)
        cleaned = "".join(ch for ch in v if ch.isdigit() or ch in {"+", " ", "(", ")", "-"})
        cleaned = cleaned.strip()
        return cleaned[:40] if cleaned else None

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email!r} admin={self.is_admin} active={self.is_active}>"


Index("ix_users_active_admin", User.is_active, User.is_admin)
Index("ix_users_country_city", User.country, User.city)
Index("ix_users_email_verified", User.email_verified)


class UserAddress(db.Model):
    """
    Direcciones:
    - múltiples
    - 1 sola default real (helper)
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

    user = db.relationship("User", back_populates="addresses")

    @validates("label")
    def _v_label(self, _k, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        v = v.strip()
        return v[:50] if v else None

    @validates("country")
    def _v_country(self, _k, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        v = v.strip().upper()
        return v[:2] if v else None

    def set_as_default(self) -> None:
        """
        Marca esta dirección como default y desmarca las demás.
        """
        if self.user_id:
            db.session.query(UserAddress).filter(
                UserAddress.user_id == self.user_id,
                UserAddress.id != self.id
            ).update({"is_default": False})
        self.is_default = True

    def __repr__(self) -> str:
        return f"<UserAddress id={self.id} user_id={self.user_id} default={self.is_default}>"


Index("ix_user_addresses_user_default", UserAddress.user_id, UserAddress.is_default)
