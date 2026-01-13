# app/models/user.py — Skyline Store (ULTRA PRO+++ / UNION-SAFE / NO BREAK / FAIL-SAFE · vNEXT)
from __future__ import annotations

import hmac
import os
import re
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, Callable

from flask_login import UserMixin
from sqlalchemy import Index, event, CheckConstraint
from sqlalchemy import text as sa_text
from sqlalchemy.orm import validates

from app.models import db
from app.utils.password_engine import hash_password, verify_and_maybe_rehash

# ============================================================
# Time
# ============================================================

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

# ============================================================
# Constants / Regex
# ============================================================

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

ALLOWED_ROLES = {"admin", "staff", "customer", "affiliate"}
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 256

COMMON_PASSWORDS = {
    "12345678",
    "password",
    "qwerty123",
    "admin12345",
    "123456789",
    "iloveyou",
    "11111111",
    "00000000",
    "skyline123",
    "gabriel123",
}

# ============================================================
# Helpers (safe)
# ============================================================

def _token64() -> str:
    """Token EXACTO 64 chars hex (32 bytes)."""
    return secrets.token_hex(32)

def _safe_strip(v: Optional[str]) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None

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

def _normalize_email(email: str) -> str:
    # limpia NBSP / zero-width / espacios raros
    e = (email or "").replace("\u00A0", " ").replace("\u200B", "").strip().lower()
    return e

def _is_email_valid(email: str) -> bool:
    e = _normalize_email(email)
    if not e or len(e) > 254:
        return False
    return bool(EMAIL_RE.match(e))

def _normalize_role(v: Optional[str]) -> str:
    vv = _safe_strip(v)
    if not vv:
        return "customer"
    rv = vv.lower()[:20]
    return rv if rv in ALLOWED_ROLES else "customer"

def _safe_digest_eq(a: Optional[str], b: Optional[str]) -> bool:
    """Comparación constante (anti timing)."""
    if not a or not b:
        return False
    try:
        return hmac.compare_digest(str(a).strip(), str(b).strip())
    except Exception:
        return False

def _env_owner_email() -> str:
    # Owner definido por ADMIN_EMAIL (env)
    return _normalize_email(os.getenv("ADMIN_EMAIL") or "")

def _safe_ip(ip: Optional[str]) -> Optional[str]:
    if not ip:
        return None
    s = str(ip).strip()
    return s[:64] if s else None

def _safe_provider_max_tries() -> int:
    try:
        return max(3, min(20, int(os.getenv("TOKEN_RETRY_MAX") or "8")))
    except Exception:
        return 8

def _ensure_unique_token(
    field_name: str,
    make_token: Callable[[], str],
    model_cls,
    max_tries: Optional[int] = None,
) -> str:
    """
    Token uniqueness guard (DB-safe / fail-safe):
    - Genera token
    - Chequea colisión en DB
    - Reintenta si colisiona
    - Si DB falla, devuelve token igual (no rompe)
    """
    tries = max_tries if isinstance(max_tries, int) else _safe_provider_max_tries()

    last = make_token()
    for _ in range(tries):
        tok = make_token()
        last = tok
        try:
            q = db.session.query(model_cls.id).filter(getattr(model_cls, field_name) == tok).limit(1)
            if q.first() is None:
                return tok
        except Exception:
            return tok
    return last

def _password_is_bad(pwd: str, email: Optional[str]) -> bool:
    p = (pwd or "").strip()
    if not p:
        return True
    if len(p) < MIN_PASSWORD_LEN or len(p) > MAX_PASSWORD_LEN:
        return True

    low = p.lower()
    if low in COMMON_PASSWORDS:
        return True

    em = _normalize_email(email or "")
    if em:
        user_part = em.split("@", 1)[0] if "@" in em else em
        if em in low:
            return True
        if user_part and user_part in low:
            return True

    if len(low) >= 10 and len(set(low)) <= 2:
        return True

    return False

# ============================================================
# User
# ============================================================

class User(UserMixin, db.Model):
    """
    Skyline Store — User (ULTRA PRO++ / UNION-SAFE / FAIL-SAFE)

    ✅ No agrega columnas nuevas
    ✅ Normalización fuerte de email
    ✅ Owner hard lock por ADMIN_EMAIL
    ✅ Lockouts seguros (owner no se bloquea)
    ✅ Tokens únicos (DB-safe)
    ✅ Hooks idempotentes
    ✅ Evita choques con Order (sin backref)
    """

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    # Auth
    email = db.Column(db.String(255), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)

    name = db.Column(db.String(120), nullable=True)
    phone = db.Column(db.String(40), nullable=True)

    # Segmentación
    country = db.Column(db.String(2), nullable=True, index=True)
    city = db.Column(db.String(80), nullable=True)

    # Estado / roles
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    is_admin = db.Column(db.Boolean, nullable=False, default=False, index=True)
    role = db.Column(db.String(20), nullable=True, index=True)

    # Email verification
    email_verified = db.Column(db.Boolean, nullable=False, default=False, index=True)
    email_verified_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Auditoría / seguridad
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    last_login_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)
    password_changed_at = db.Column(db.DateTime(timezone=True), nullable=True)

    failed_login_count = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime(timezone=True), nullable=True, index=True)
    last_login_ip = db.Column(db.String(64), nullable=True)

    # Tokens (64 fixed)
    email_verify_token = db.Column(db.String(64), nullable=True, unique=True, index=True)
    reset_password_token = db.Column(db.String(64), nullable=True, unique=True, index=True)
    reset_password_expires_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Marketing
    email_opt_in = db.Column(db.Boolean, nullable=False, default=True, index=True)
    email_opt_in_at = db.Column(db.DateTime(timezone=True), nullable=True)
    unsubscribe_token = db.Column(db.String(64), nullable=False, unique=True, index=True, default=_token64)

    # Relaciones
    addresses = db.relationship(
        "UserAddress",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin",
        passive_deletes=True,
    )

    # ⚠️ NO backref (evita choque si Order ya define relación)
    orders = db.relationship(
        "Order",
        lazy="selectin",
        passive_deletes=True,
    )

    __table_args__ = (
        CheckConstraint("failed_login_count >= 0", name="ck_users_failed_login_nonneg"),
        CheckConstraint("length(email) > 3", name="ck_users_email_len_min"),
        CheckConstraint("role IS NULL OR role IN ('admin','staff','customer','affiliate')", name="ck_users_role_allowed"),
    )

    # --------------------------------------------------------
    # Flask-Login
    # --------------------------------------------------------
    def get_id(self) -> str:
        return str(self.id)

    # --------------------------------------------------------
    # Owner HARD LOCK
    # --------------------------------------------------------
    @property
    def is_owner(self) -> bool:
        owner = _env_owner_email()
        if not owner:
            return False
        return _safe_digest_eq(_normalize_email(self.email), owner)

    def reinforce_owner_flags(self) -> None:
        """Owner no se puede desactivar / bloquear / des-verificar."""
        if not self.is_owner:
            return
        try:
            self.is_admin = True
            self.role = "admin"
        except Exception:
            pass
        try:
            self.is_active = True
        except Exception:
            pass
        try:
            self.failed_login_count = 0
            self.locked_until = None
        except Exception:
            pass
        try:
            self.email_verified = True
            if not self.email_verified_at:
                self.email_verified_at = utcnow()
        except Exception:
            pass

    # --------------------------------------------------------
    # Display helpers
    # --------------------------------------------------------
    @property
    def email_username(self) -> str:
        if not self.email:
            return "usuario"
        return (self.email.split("@", 1)[0] or "usuario")[:64]

    @property
    def masked_email(self) -> str:
        if not self.email or "@" not in self.email:
            return "***"
        local, domain = self.email.split("@", 1)
        if len(local) <= 2:
            local_mask = local[:1] + "*"
        else:
            local_mask = local[:2] + "*" * max(1, min(8, len(local) - 2))
        return f"{local_mask}@{domain}"

    @property
    def display_name(self) -> str:
        nm = (self.name or "").strip()
        return nm if nm else self.email_username

    # --------------------------------------------------------
    # Roles / ACL
    # --------------------------------------------------------
    @property
    def role_effective(self) -> str:
        if self.is_owner:
            return "admin"
        if bool(self.is_admin):
            return "admin"
        r = (self.role or "").lower().strip()
        return r if r in ALLOWED_ROLES else "customer"

    def has_role(self, *roles: str) -> bool:
        rr = {r.strip().lower() for r in roles if r}
        return self.role_effective in rr

    def can_access_admin(self) -> bool:
        return self.has_role("admin", "staff")

    def set_role_safe(self, role: Optional[str]) -> None:
        nr = _normalize_role(role)
        if nr == "admin" and not (self.is_admin or self.is_owner):
            self.role = "customer"
            return
        self.role = nr

    def set_admin_safe(self, enabled: bool) -> None:
        if self.is_owner:
            self.is_admin = True
            self.role = "admin"
            return
        self.is_admin = bool(enabled)
        if self.is_admin:
            self.role = "admin"
        else:
            if (self.role or "").lower() == "admin":
                self.role = "customer"
            else:
                self.role = self.role or "customer"

    # --------------------------------------------------------
    # Password policy
    # --------------------------------------------------------
    def set_password(self, raw_password: str) -> None:
        pwd = (raw_password or "").strip()
        if _password_is_bad(pwd, self.email):
            raise ValueError("Contraseña insegura. Usá 8+ caracteres y evitá claves comunes o relacionadas a tu email.")
        self.password_hash = hash_password(pwd)
        self.password_changed_at = utcnow()
        self.reinforce_owner_flags()

    def check_password(self, raw_password: str) -> bool:
        if not self.password_hash:
            return False
        ok, new_hash = verify_and_maybe_rehash(raw_password or "", self.password_hash)
        if ok and new_hash:
            self.password_hash = new_hash
            self.password_changed_at = utcnow()
        return bool(ok)

    # --------------------------------------------------------
    # Login / Lockouts
    # --------------------------------------------------------
    def can_login(self) -> bool:
        if self.is_owner:
            return True
        if not bool(self.is_active):
            return False
        if self.locked_until and utcnow() < self.locked_until:
            return False
        return True

    def touch_login(self, ip: Optional[str] = None) -> None:
        self.last_login_at = utcnow()
        self.failed_login_count = 0
        self.locked_until = None
        ip2 = _safe_ip(ip)
        if ip2:
            self.last_login_ip = ip2
        self.reinforce_owner_flags()

    def mark_failed_login(self, lock_after: int = 8, lock_minutes: int = 15) -> None:
        if self.is_owner:
            self.failed_login_count = 0
            self.locked_until = None
            return
        cnt = _clamp_int(self.failed_login_count, 0, 9999) + 1
        self.failed_login_count = cnt
        if cnt >= int(lock_after):
            self.locked_until = utcnow() + timedelta(minutes=int(lock_minutes))

    def lock_seconds_left(self) -> int:
        if self.is_owner or not self.locked_until:
            return 0
        delta = self.locked_until - utcnow()
        return max(0, int(delta.total_seconds()))

    # --------------------------------------------------------
    # Email verify / reset tokens
    # --------------------------------------------------------
    @staticmethod
    def is_email_valid(email: str) -> bool:
        return _is_email_valid(email)

    @staticmethod
    def normalize_email(email: str) -> str:
        return _normalize_email(email)

    def ensure_email_verify_token(self) -> str:
        if not self.email_verify_token:
            self.email_verify_token = _ensure_unique_token("email_verify_token", _token64, User)
        return self.email_verify_token

    def verify_email(self) -> None:
        self.email_verified = True
        self.email_verified_at = utcnow()
        self.email_verify_token = None
        self.reinforce_owner_flags()

    def create_reset_token(self, minutes: int = 30) -> str:
        self.reset_password_token = _ensure_unique_token("reset_password_token", _token64, User)
        self.reset_password_expires_at = utcnow() + timedelta(minutes=int(minutes))
        return self.reset_password_token

    def reset_token_is_valid(self, token: str) -> bool:
        if not token or not self.reset_password_token:
            return False
        if not _safe_digest_eq(token, self.reset_password_token):
            return False
        if not self.reset_password_expires_at:
            return False
        return utcnow() <= self.reset_password_expires_at

    def clear_reset_token(self) -> None:
        self.reset_password_token = None
        self.reset_password_expires_at = None

    def token_matches_unsubscribe(self, token: str) -> bool:
        return _safe_digest_eq(token, self.unsubscribe_token)

    # --------------------------------------------------------
    # Marketing
    # --------------------------------------------------------
    def subscribe_email(self) -> None:
        self.email_opt_in = True
        if not self.email_opt_in_at:
            self.email_opt_in_at = utcnow()

    def unsubscribe_email(self) -> None:
        self.email_opt_in = False

    def set_email_opt_in(self, enabled: bool) -> None:
        enabled = bool(enabled)
        self.email_opt_in = enabled
        if enabled and not self.email_opt_in_at:
            self.email_opt_in_at = utcnow()

    # --------------------------------------------------------
    # Checkout helpers
    # --------------------------------------------------------
    def default_address(self) -> Optional["UserAddress"]:
        for a in self.addresses or []:
            if a.is_default:
                return a
        addrs = list(self.addresses or [])
        return addrs[0] if addrs else None

    # --------------------------------------------------------
    # Normalización / consistencia (UNION SAFE)
    # --------------------------------------------------------
    def ensure_tokens(self) -> None:
        if not self.unsubscribe_token:
            self.unsubscribe_token = _ensure_unique_token("unsubscribe_token", _token64, User)

    def prepare_for_save(self) -> None:
        """
        ✅ Punto de unión:
        - Asegura email/role/tokens SIEMPRE
        - Evita valores inválidos que rompen templates/routes
        - Idempotente (safe en insert/update)
        """
        try:
            if self.email is not None:
                self.email = self.normalize_email(self.email)[:255]
        except Exception:
            pass

        try:
            self.phone = _clean_phone(self.phone)
        except Exception:
            pass

        try:
            self.country = (self.country or "").strip().upper()[:2] or None
            self.city = (self.city or "").strip()[:80] or None
        except Exception:
            pass

        try:
            self.set_role_safe(self.role)
        except Exception:
            pass

        try:
            self.ensure_tokens()
        except Exception:
            pass

        try:
            if self.email_opt_in and not self.email_opt_in_at:
                self.email_opt_in_at = utcnow()
        except Exception:
            pass

        try:
            if self.email_verified and not self.email_verified_at:
                self.email_verified_at = utcnow()
        except Exception:
            pass

        try:
            self.reinforce_owner_flags()
        except Exception:
            pass

    # --------------------------------------------------------
    # Serialización segura
    # --------------------------------------------------------
    def as_public_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "phone": self.phone,
            "country": self.country,
            "city": self.city,
            "role": self.role_effective,
            "is_active": bool(self.is_active),
            "email_verified": bool(self.email_verified),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
        }

    def public_admin_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "email": self.email,
            "masked_email": self.masked_email,
            "name": self.name,
            "role": self.role_effective,
            "is_owner": bool(self.is_owner),
            "is_active": bool(self.is_active),
            "email_verified": bool(self.email_verified),
            "failed_login_count": int(self.failed_login_count or 0),
            "locked": bool(self.locked_until and utcnow() < self.locked_until),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
            "last_login_ip": self.last_login_ip,
        }

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.masked_email!r} role={self.role_effective!r} active={bool(self.is_active)}>"

    # --------------------------------------------------------
    # Validations (suaves)
    # --------------------------------------------------------
    @validates("email")
    def _v_email(self, _k, v: str) -> str:
        vv = self.normalize_email(v)
        return (vv[:255] if vv else "")

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
        return _normalize_role(v)

# ============================================================
# Indexes
# ============================================================
Index("ix_users_active_admin", User.is_active, User.is_admin)
Index("ix_users_country_city", User.country, User.city)
Index("ix_users_role_active", User.role, User.is_active)

# ============================================================
# UserAddress
# ============================================================

class UserAddress(db.Model):
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
# Hooks (ultra safe / idempotentes)
# ============================================================

@event.listens_for(User, "before_insert", propagate=True)
def _user_before_insert(_mapper, _conn, target: User):
    try:
        target.prepare_for_save()
    except Exception:
        pass

@event.listens_for(User, "before_update", propagate=True)
def _user_before_update(_mapper, _conn, target: User):
    try:
        target.prepare_for_save()
    except Exception:
        pass

@event.listens_for(UserAddress, "before_insert", propagate=True)
@event.listens_for(UserAddress, "before_update", propagate=True)
def _addr_ensure_single_default(_mapper, conn, target: UserAddress):
    try:
        if target.is_default and target.user_id:
            conn.execute(
                sa_text(
                    "UPDATE user_addresses "
                    "SET is_default = 0 "
                    "WHERE user_id = :uid AND id != :id"
                ),
                {"uid": int(target.user_id), "id": int(target.id or 0)},
            )
    except Exception:
        pass
