from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from app import db
from app.utils.security import hash_password, verify_password


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    email = db.Column(db.String(255), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    name = db.Column(db.String(120), nullable=True)
    phone = db.Column(db.String(40), nullable=True)

    # Para segmentación: UY vs resto
    country = db.Column(db.String(2), nullable=True)  # ISO-2: "UY", "AR", "US"
    city = db.Column(db.String(80), nullable=True)

    is_active = db.Column(db.Boolean, nullable=False, default=True)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    last_login_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Marketing / consentimiento
    email_opt_in = db.Column(db.Boolean, nullable=False, default=True)
    email_opt_in_at = db.Column(db.DateTime(timezone=True), nullable=True)
    unsubscribe_token = db.Column(db.String(64), nullable=True, index=True)

    # Relaciones
    addresses = db.relationship("UserAddress", back_populates="user", cascade="all, delete-orphan", lazy="select")
    orders = db.relationship("Order", back_populates="user", lazy="select")

    def set_password(self, raw_password: str) -> None:
        self.password_hash = hash_password(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return verify_password(raw_password, self.password_hash)

    def mark_login(self) -> None:
        self.last_login_at = utcnow()

    def subscribe_email(self) -> None:
        self.email_opt_in = True
        self.email_opt_in_at = utcnow()

    def unsubscribe_email(self) -> None:
        self.email_opt_in = False

    @staticmethod
    def normalize_email(email: str) -> str:
        return (email or "").strip().lower()

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email}>"



class UserAddress(db.Model):
    __tablename__ = "user_addresses"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    label = db.Column(db.String(50), nullable=True)  # "Casa", "Trabajo"
    full_name = db.Column(db.String(120), nullable=True)
    phone = db.Column(db.String(40), nullable=True)

    line1 = db.Column(db.String(200), nullable=False)
    line2 = db.Column(db.String(200), nullable=True)
    city = db.Column(db.String(120), nullable=True)
    state = db.Column(db.String(120), nullable=True)
    postal_code = db.Column(db.String(40), nullable=True)
    country = db.Column(db.String(2), nullable=True)

    is_default = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    user = db.relationship("User", back_populates="addresses")

    def __repr__(self) -> str:
        return f"<UserAddress id={self.id} user_id={self.user_id}>"
