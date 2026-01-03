# app/models/user.py
from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional

from flask_login import UserMixin
from sqlalchemy import Index, event, CheckConstraint
from sqlalchemy.orm import validates

from app.models import db
from app.utils.password_engine import hash_password, verify_and_maybe_rehash

# ============================================================
# Helpers
# ============================================================

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def _token64() -> str:
    """Token EXACTO 64 chars hex (32 bytes)."""
    return secrets.token_hex(32)


def _safe_strip(v: Optional[str]) -> Optional[str]:
    if v is None:
        return None
    vv = str(v).strip()
    return vv if vv else None


def _clean_phone(v: Optional[str]) -> Optional[str]:
    vv = _safe_strip(v)
    if not vv:
        return None
    cleaned = "".join(ch for ch in vv if ch.isdigit() or ch in {"+", " ", "(", ")", "-"}).strip()
    return cleaned[:40] if cleaned else None


def _clamp_int(v: Optional[int], lo: int = 0, hi: int = 10_000) -> int:
    try:
        n = int(v or 0)
    except Exception:
        n = 0
    if n < lo:
        return lo
    if n > hi:
        return hi
    return n


# ============================================================
# User
# ============================================================

class User(UserMixin, db.Model):
    """
    Skyline Store — User ULTRA PRO (FINAL / NO BREAK)

    ✅ Flask-Login compatible
    ✅ Password hashing + auto rehash
    ✅ Lockouts robustos
    ✅ Email verify + reset tokens (64 fixed)
    ✅ Marketing opt-in + unsubscribe token
    ✅ Relaciones rápidas (selectin) y sin loops
    ✅ Validaciones suaves (no rompen DB vieja)
    ✅ Hooks ultra safe
    ✅ Direcciones: 1 sola default real (sin migración)
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
    is_admin = db.Column(db.Boolean, nullable=False, default=False, index=True)
    role = db.Column(db.String(20), nullable=True, index=True)  # "admin"/"staff"/"customer"

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
    # Relaciones (RÁPIDAS + BLINDADAS)
    # -------------------------
    addresses = db.relationship(
        "UserAddress",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin",
        passive_deletes=True,
    )

    # ✅ CLAVE ANTI-CRASH:
    # - Order NO define relationship a User (para no romper mapper).
    # - Desde User creamos:
    #   - User.orders
    #   - y automáticamente Order.user via backref.
    orders = db.relationship(
        "Order",
        lazy="selectin",
        passive_deletes=True,
        backref=db.backref("user", lazy="select"),
    )

    __table_args__ = (
        CheckConstraint("failed_login_count >= 0", name="ck_users_failed_login_nonneg"),
    )

    # ============================================================
    # Flask-Login
    # ============================================================

    def get_id(self) -> str:
        return str(self.id)

    @property
    def is_staff(self) -> bool:
        r = (self.role or "").lower().strip()
        return bool(self.is_admin) or r in {"admin", "staff"}

    @property
    def role_effective(self) -> str:
        if self.is_admin:
            return "admin"
        r = (self.role or "").lower().strip()
        return r if r else "customer"

    # ============================================================
    # Password
    # ============================================================

    def set_password(self, raw_password: str) -> None:
        pwd = (raw_password or "").strip()
        if not pwd:
            raise ValueError("Password vacío")
        self.password_hash = hash_password(pwd)
        self.password_changed_at = utcnow()

    def check_password(self, raw_password: str) -> bool:
        if not self.password_hash:
            return False
        ok, new_hash = verify_and_maybe_rehash(raw_password or "", self.password_hash)
        if ok and new_hash:
            self.password_hash = new_hash
            self.password_changed_at = utcnow()
        return ok

    # ============================================================
    # Login / Lockouts
    # ============================================================

    def can_login(self) -> bool:
        if not bool(self.is_active):
            return False
        if self.locked_until and utcnow() < self.locked_until:
            return False
        return True

    def mark_login(self) -> None:
        self.last_login_at = utcnow()
        self.failed_login_count = 0
        self.locked_until = None

    def mark_failed_login(self, lock_after: int = 8, lock_minutes: int = 15) -> None:
        cnt = _clamp_int(self.failed_login_count, 0, 9999) + 1
        self.failed_login_count = cnt
        if cnt >= int(lock_after):
            self.locked_until = utcnow() + timedelta(minutes=int(lock_minutes))

    def lock_for(self, minutes: int = 15) -> None:
        self.locked_until = utcnow() + timedelta(minutes=int(minutes))

    def unlock(self) -> None:
        self.locked_until = None
        self.failed_login_count = 0

    def lock_seconds_left(self) -> int:
        if not self.locked_until:
            return 0
        delta = self.locked_until - utcnow()
        return max(0, int(delta.total_seconds()))

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
    # Marketing
    # ============================================================

    def subscribe_email(self) -> None:
        self.email_opt_in = True
        if not self.email_opt_in_at:
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
        addrs = list(self.addresses or [])
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
        # validación suave: no rompe DB vieja, pero evita basura obvia
        vv = vv[:255] if vv else ""
        return vv

    @validates("country")
    def _v_country(self, _k, v: Optional[str]) -> Optional[str]:
        vv = _safe_strip(v)
        return vv.upper()[:2] if vv else None

    @validates("city")
    def _v_city(self, _k, v: Optional[str]) -> Optional[str]:
        vv = _safe_strip(v)
        return vv[:80] if vv else None

    @validates("name")
    def _v_name(self, _k, v: Optional[str]) -> Optional[str]:
        vv = _safe_strip(v)
        return vv[:120] if vv else None

    @validates("phone")
    def _v_phone(self, _k, v: Optional[str]) -> Optional[str]:
        return _clean_phone(v)

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
        return (
            f"<User id={self.id} email={self.email!r} role={self.role_effective!r} "
            f"active={bool(self.is_active)}>"
        )


# Índices extra (no rompen DB vieja)
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
        return _clean_phone(v)

    def set_as_default(self) -> None:
        """
        Marca esta dirección como default y desmarca las demás.
        ✅ update masivo, no necesita cargar todo
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


# ============================================================
# Hooks (ultra safe)
# ============================================================

@event.listens_for(User, "before_insert", propagate=True)
def _user_before_insert(_mapper, _conn, target: User):
    try:
        target.email = User.normalize_email(target.email)
    except Exception:
        pass

    try:
        target.ensure_tokens()
    except Exception:
        pass

    try:
        target.phone = _clean_phone(target.phone)
    except Exception:
        pass

    try:
        # opt-in timestamp coherente
        if target.email_opt_in and not target.email_opt_in_at:
            target.email_opt_in_at = utcnow()
    except Exception:
        pass


@event.listens_for(User, "before_update", propagate=True)
def _user_before_update(_mapper, _conn, target: User):
    try:
        target.email = User.normalize_email(target.email)
    except Exception:
        pass

    try:
        target.ensure_tokens()
    except Exception:
        pass

    try:
        target.phone = _clean_phone(target.phone)
    except Exception:
        pass

    try:
        if target.email_opt_in and not target.email_opt_in_at:
            target.email_opt_in_at = utcnow()
    except Exception:
        pass


# ------------------------------------------------------------
# Garantiza 1 default address por usuario (sin migraciones)
# ------------------------------------------------------------
@event.listens_for(UserAddress, "before_insert", propagate=True)
@event.listens_for(UserAddress, "before_update", propagate=True)
def _addr_ensure_single_default(_mapper, _conn, target: UserAddress):
    try:
        if target.is_default and target.user_id:
            db.session.query(UserAddress).filter(
                UserAddress.user_id == target.user_id,
                UserAddress.id != (target.id or 0),
            ).update({"is_default": False}, synchronize_session=False)
    except Exception:
        pass
