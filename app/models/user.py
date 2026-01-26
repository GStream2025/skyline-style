from __future__ import annotations

import hmac
import os
import re
import secrets
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Dict, Optional

from flask_login import UserMixin
from sqlalchemy import CheckConstraint, Index, event
from sqlalchemy import text as sa_text
from sqlalchemy.orm import validates

from app.models import db
from app.utils.password_engine import hash_password, verify_and_maybe_rehash


_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_ALLOWED_ROLES = {"admin", "staff", "customer", "affiliate"}
_MIN_PASSWORD_LEN = 8
_MAX_PASSWORD_LEN = 256


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _token64() -> str:
    return secrets.token_hex(32)


def _s(v: Optional[str], max_len: int) -> Optional[str]:
    if not v:
        return None
    out = str(v).strip()
    return out[:max_len] if out else None


def _normalize_email(email: str) -> str:
    return " ".join((email or "").lower().replace("\u200b", "").split())


def _email_ok(email: str) -> bool:
    e = _normalize_email(email)
    return bool(e and len(e) <= 254 and _EMAIL_RE.match(e))


def _safe_eq(a: Optional[str], b: Optional[str]) -> bool:
    try:
        return bool(a and b and hmac.compare_digest(a, b))
    except Exception:
        return False


def _owner_email() -> str:
    return _normalize_email(os.getenv("ADMIN_EMAIL") or "")


def _clean_phone(v: Optional[str]) -> Optional[str]:
    if not v:
        return None
    out = "".join(c for c in v if c.isdigit() or c in "+()- ").strip()
    return out[:40] if out else None


def _ensure_unique(field: str, make: Callable[[], str], model) -> str:
    for _ in range(10):
        tok = make()
        if not db.session.query(model.id).filter(getattr(model, field) == tok).first():
            return tok
    return make()


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    email = db.Column(db.String(255), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(255))

    name = db.Column(db.String(120))
    phone = db.Column(db.String(40))

    country = db.Column(db.String(2), index=True)
    city = db.Column(db.String(80))

    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    is_admin = db.Column(db.Boolean, default=False, nullable=False, index=True)
    role = db.Column(db.String(20), index=True)

    email_verified = db.Column(db.Boolean, default=False, nullable=False, index=True)
    email_verified_at = db.Column(db.DateTime(timezone=True))

    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    last_login_at = db.Column(db.DateTime(timezone=True))
    password_changed_at = db.Column(db.DateTime(timezone=True))

    failed_login_count = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime(timezone=True))
    last_login_ip = db.Column(db.String(64))

    email_verify_token = db.Column(db.String(64), unique=True, index=True)
    reset_password_token = db.Column(db.String(64), unique=True, index=True)
    reset_password_expires_at = db.Column(db.DateTime(timezone=True))

    email_opt_in = db.Column(db.Boolean, default=True, nullable=False, index=True)
    email_opt_in_at = db.Column(db.DateTime(timezone=True))
    unsubscribe_token = db.Column(db.String(64), unique=True, nullable=False, default=_token64)

    addresses = db.relationship(
        "UserAddress",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (
        CheckConstraint("failed_login_count >= 0"),
        CheckConstraint("role IS NULL OR role IN ('admin','staff','customer','affiliate')"),
        Index("ix_users_active_role", "is_active", "role"),
    )

    def get_id(self) -> str:
        return str(self.id)

    @property
    def is_owner(self) -> bool:
        return _safe_eq(_normalize_email(self.email), _owner_email())

    @property
    def role_effective(self) -> str:
        if self.is_owner or self.is_admin:
            return "admin"
        return self.role if self.role in _ALLOWED_ROLES else "customer"

    def set_password(self, raw: str) -> None:
        if not raw or len(raw) < _MIN_PASSWORD_LEN or len(raw) > _MAX_PASSWORD_LEN:
            raise ValueError("Contraseña inválida")
        self.password_hash = hash_password(raw)
        self.password_changed_at = utcnow()
        if self.is_owner:
            self.is_admin = True
            self.role = "admin"

    def check_password(self, raw: str) -> bool:
        if not self.password_hash:
            return False
        ok, new_hash = verify_and_maybe_rehash(raw, self.password_hash)
        if ok and new_hash:
            self.password_hash = new_hash
            self.password_changed_at = utcnow()
        return bool(ok)

    def can_login(self) -> bool:
        if not self.is_active:
            return False
        if self.locked_until and utcnow() < self.locked_until:
            return False
        return True

    def touch_login(self, ip: Optional[str] = None) -> None:
        self.last_login_at = utcnow()
        self.failed_login_count = 0
        self.locked_until = None
        self.last_login_ip = ip[:64] if ip else None

    def mark_failed_login(self) -> None:
        self.failed_login_count += 1
        if self.failed_login_count >= 8:
            self.locked_until = utcnow() + timedelta(minutes=15)

    def ensure_tokens(self) -> None:
        if not self.unsubscribe_token:
            self.unsubscribe_token = _ensure_unique("unsubscribe_token", _token64, User)

    def prepare(self) -> None:
        self.email = _normalize_email(self.email)[:255]
        self.phone = _clean_phone(self.phone)
        self.country = _s(self.country, 2)
        self.city = _s(self.city, 80)
        self.role = self.role_effective
        self.ensure_tokens()
        if self.email_verified and not self.email_verified_at:
            self.email_verified_at = utcnow()

    def as_public(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "role": self.role_effective,
            "is_active": self.is_active,
            "email_verified": self.email_verified,
        }

    def __repr__(self) -> str:
        return f"<User {self.id} {self.email} role={self.role_effective}>"


class UserAddress(db.Model):
    __tablename__ = "user_addresses"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    label = db.Column(db.String(50))
    full_name = db.Column(db.String(120))
    phone = db.Column(db.String(40))

    line1 = db.Column(db.String(200), nullable=False)
    line2 = db.Column(db.String(200))

    city = db.Column(db.String(120))
    state = db.Column(db.String(120))
    postal_code = db.Column(db.String(40))
    country = db.Column(db.String(2))

    is_default = db.Column(db.Boolean, default=False, nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

    user = db.relationship("User", back_populates="addresses")

    __table_args__ = (
        Index("ix_user_addresses_default", "user_id", "is_default"),
    )

    def set_as_default(self) -> None:
        if self.user_id:
            db.session.query(UserAddress).filter(
                UserAddress.user_id == self.user_id,
                UserAddress.id != self.id,
            ).update({"is_default": False})
        self.is_default = True

    def __repr__(self) -> str:
        return f"<UserAddress {self.id} user={self.user_id} default={self.is_default}>"
