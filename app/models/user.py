from __future__ import annotations

import hmac
import os
import re
import secrets
import unicodedata
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from typing import Any, Callable, Dict, Optional, Tuple

from flask_login import UserMixin
from sqlalchemy import CheckConstraint, Index, event, inspect, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session as SASession
from sqlalchemy.orm import validates

from app.models import db
from app.utils.password_engine import hash_password, verify_and_maybe_rehash

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

_ALLOWED_ROLES = {"admin", "staff", "customer", "affiliate"}

_MIN_PASSWORD_LEN = 8
_MAX_PASSWORD_LEN = 256

_MAX_EMAIL_LEN = 254
_DB_EMAIL_LEN = 255
_MAX_NAME_LEN = 120
_MAX_CITY_LEN = 80
_MAX_PHONE_LEN = 40
_MAX_IP_LEN = 64

_LOCK_THRESHOLD = 8
_LOCK_MINUTES = 15

_TOKEN_HEX_LEN = 64
_UNSUB_TOKEN_LEN = 64

_TRUTHY = {"1", "true", "yes", "y", "on", "enabled", "enable", "checked"}
_FALSY = {"0", "false", "no", "n", "off", "disabled", "disable", "unchecked"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _token64() -> str:
    return secrets.token_hex(32)


def _normalize_text(s: str) -> str:
    s = (s or "").replace("\u200b", "").replace("\ufeff", "")
    return unicodedata.normalize("NFKC", s)


def _strip_or_none(v: Any, max_len: int) -> Optional[str]:
    if v is None:
        return None
    out = _normalize_text(str(v)).strip()
    if not out:
        return None
    if max_len > 0 and len(out) > max_len:
        out = out[:max_len]
    return out


def _normalize_email(email: Any) -> str:
    e = _normalize_text(str(email or "")).strip().lower()
    e = " ".join(e.split())
    return e


def _email_ok(email: Any) -> bool:
    e = _normalize_email(email)
    return bool(e and len(e) <= _MAX_EMAIL_LEN and _EMAIL_RE.match(e))


def _safe_eq(a: Optional[str], b: Optional[str]) -> bool:
    try:
        return bool(a and b and hmac.compare_digest(str(a), str(b)))
    except Exception:
        return False


def _owner_email() -> str:
    return _normalize_email(os.getenv("ADMIN_EMAIL") or "")


def _clean_phone(v: Any) -> Optional[str]:
    raw = _strip_or_none(v, _MAX_PHONE_LEN)
    if not raw:
        return None
    cleaned = "".join(c for c in raw if c.isdigit() or c in "+()- ")
    cleaned = " ".join(cleaned.split())
    return cleaned[:_MAX_PHONE_LEN] if cleaned else None


def _safe_ip(v: Any) -> Optional[str]:
    raw = _strip_or_none(v, _MAX_IP_LEN)
    if not raw:
        return None
    raw = raw.strip()[:_MAX_IP_LEN]
    try:
        return str(ip_address(raw))
    except Exception:
        # si viene "unknown" u otra cosa, lo guardamos sanitizado igual
        return raw


def _clamp_int(v: Any, default: int, min_v: int, max_v: int) -> int:
    try:
        n = int(v)
    except Exception:
        n = int(default)
    if n < min_v:
        return min_v
    if n > max_v:
        return max_v
    return n


def _role_normalize(role: Any) -> Optional[str]:
    r = _strip_or_none(role, 20)
    if not r:
        return None
    r = r.lower()
    return r if r in _ALLOWED_ROLES else None


def _boolish(v: Any, default: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    s = _strip_or_none(v, 12)
    if not s:
        return default
    s = s.lower()
    if s in _TRUTHY:
        return True
    if s in _FALSY:
        return False
    return default


def _ensure_unique_token(field: str, make: Callable[[], str], model) -> str:
    # IMPORTANTE: esto NO debe ejecutarse dentro de un flush “activo”.
    # Usalo para generación explícita (ej: reset token) fuera de eventos.
    for _ in range(12):
        tok = make()
        stmt = select(model.id).where(getattr(model, field) == tok).limit(1)
        if db.session.execute(stmt).first() is None:
            return tok
    return make()


def _maybe_unique_violation(e: Exception) -> bool:
    msg = str(e).lower()
    return "unique" in msg or "duplicate" in msg


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    email = db.Column(db.String(_DB_EMAIL_LEN), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(255))

    name = db.Column(db.String(_MAX_NAME_LEN))
    phone = db.Column(db.String(_MAX_PHONE_LEN))

    country = db.Column(db.String(2), index=True)
    city = db.Column(db.String(_MAX_CITY_LEN))

    is_active = db.Column(db.Boolean, default=True, server_default="1", nullable=False, index=True)
    is_admin = db.Column(db.Boolean, default=False, server_default="0", nullable=False, index=True)
    role = db.Column(db.String(20), index=True)

    email_verified = db.Column(db.Boolean, default=False, server_default="0", nullable=False, index=True)
    email_verified_at = db.Column(db.DateTime(timezone=True))

    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    last_login_at = db.Column(db.DateTime(timezone=True))
    password_changed_at = db.Column(db.DateTime(timezone=True))

    failed_login_count = db.Column(db.Integer, default=0, server_default="0", nullable=False)
    locked_until = db.Column(db.DateTime(timezone=True))
    last_login_ip = db.Column(db.String(_MAX_IP_LEN))

    email_verify_token = db.Column(db.String(_TOKEN_HEX_LEN), unique=True, index=True)
    reset_password_token = db.Column(db.String(_TOKEN_HEX_LEN), unique=True, index=True)
    reset_password_expires_at = db.Column(db.DateTime(timezone=True))

    email_opt_in = db.Column(db.Boolean, default=True, server_default="1", nullable=False, index=True)
    email_opt_in_at = db.Column(db.DateTime(timezone=True))

    unsubscribe_token = db.Column(
        db.String(_UNSUB_TOKEN_LEN),
        unique=True,
        nullable=False,
        default=_token64,
    )

    addresses = db.relationship(
        "UserAddress",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin",
        passive_deletes=True,
    )

    __table_args__ = (
        CheckConstraint("failed_login_count >= 0", name="ck_users_failed_login_nonneg"),
        CheckConstraint(
            "role IS NULL OR role IN ('admin','staff','customer','affiliate')",
            name="ck_users_role_allowed",
        ),
        CheckConstraint("unsubscribe_token IS NOT NULL", name="ck_users_unsub_token_not_null"),
        Index("ix_users_active_role", "is_active", "role"),
        Index("ix_users_verified_active", "email_verified", "is_active"),
    )

    def get_id(self) -> str:
        return str(self.id)

    @validates("email")
    def _v_email(self, key: str, value: Any) -> str:
        e = _normalize_email(value)
        if not _email_ok(e):
            raise ValueError("Email inválido")
        if len(e) > _DB_EMAIL_LEN:
            e = e[:_DB_EMAIL_LEN]
        return e

    @validates("phone")
    def _v_phone(self, key: str, value: Any) -> Optional[str]:
        return _clean_phone(value)

    @validates("name")
    def _v_name(self, key: str, value: Any) -> Optional[str]:
        return _strip_or_none(value, _MAX_NAME_LEN)

    @validates("city")
    def _v_city(self, key: str, value: Any) -> Optional[str]:
        return _strip_or_none(value, _MAX_CITY_LEN)

    @validates("country")
    def _v_country(self, key: str, value: Any) -> Optional[str]:
        v = _strip_or_none(value, 2)
        return v.upper() if v else None

    @validates("role")
    def _v_role(self, key: str, value: Any) -> Optional[str]:
        return _role_normalize(value)

    @property
    def is_owner(self) -> bool:
        return _safe_eq(_normalize_email(self.email), _owner_email())

    @property
    def role_effective(self) -> str:
        if self.is_owner or bool(self.is_admin):
            return "admin"
        r = _role_normalize(self.role)
        return r or "customer"

    @property
    def is_locked(self) -> bool:
        return bool(self.locked_until and utcnow() < self.locked_until)

    def can_login(self) -> bool:
        return bool(self.is_active and not self.is_locked)

    def set_password(self, raw: Any) -> None:
        raw_s = _normalize_text(str(raw or ""))
        if len(raw_s) < _MIN_PASSWORD_LEN or len(raw_s) > _MAX_PASSWORD_LEN:
            raise ValueError("Contraseña inválida")
        self.password_hash = hash_password(raw_s)
        self.password_changed_at = utcnow()
        if self.is_owner:
            self.is_admin = True
            self.role = "admin"

    def check_password(self, raw: Any) -> bool:
        if not self.password_hash:
            return False
        ok, new_hash = verify_and_maybe_rehash(_normalize_text(str(raw or "")), self.password_hash)
        if ok and new_hash:
            self.password_hash = new_hash
            self.password_changed_at = utcnow()
        return bool(ok)

    def touch_login(self, ip: Any = None) -> None:
        self.last_login_at = utcnow()
        self.failed_login_count = 0
        self.locked_until = None
        self.last_login_ip = _safe_ip(ip)

    def mark_failed_login(self) -> None:
        self.failed_login_count = _clamp_int(self.failed_login_count, 0, 0, 10_000) + 1
        if self.failed_login_count >= _LOCK_THRESHOLD:
            self.locked_until = utcnow() + timedelta(minutes=_LOCK_MINUTES)

    def unlock(self) -> None:
        self.failed_login_count = 0
        self.locked_until = None

    def _clear_expired_reset(self) -> None:
        if self.reset_password_token and self.reset_password_expires_at and utcnow() >= self.reset_password_expires_at:
            self.reset_password_token = None
            self.reset_password_expires_at = None

    def ensure_tokens(self) -> None:
        # No consultamos DB en flush: generamos y dejamos al unique constraint hacer su trabajo.
        if not self.unsubscribe_token:
            self.unsubscribe_token = _token64()

    def ensure_auth_tokens(self) -> None:
        if self.email_verified:
            self.email_verify_token = None
        elif not self.email_verify_token:
            self.email_verify_token = _token64()

        self._clear_expired_reset()

    def create_reset_token(self, minutes: int = 30) -> str:
        minutes = _clamp_int(minutes, 30, 5, 24 * 60)
        tok = _ensure_unique_token("reset_password_token", _token64, User)
        self.reset_password_token = tok
        self.reset_password_expires_at = utcnow() + timedelta(minutes=minutes)
        return tok

    def clear_reset_token(self) -> None:
        self.reset_password_token = None
        self.reset_password_expires_at = None

    def mark_email_verified(self) -> None:
        self.email_verified = True
        self.email_verified_at = utcnow()
        self.email_verify_token = None

    def set_email_opt_in(self, enabled: Any) -> None:
        self.email_opt_in = _boolish(enabled, True)
        if self.email_opt_in:
            self.email_opt_in_at = self.email_opt_in_at or utcnow()
        else:
            self.email_opt_in_at = None

    def rotate_unsubscribe_token(self) -> str:
        tok = _ensure_unique_token("unsubscribe_token", _token64, User)
        self.unsubscribe_token = tok
        return tok

    def is_staff(self) -> bool:
        return self.role_effective in {"admin", "staff"}

    def promote_to_staff(self) -> None:
        if self.is_owner:
            self.is_admin = True
            self.role = "admin"
        else:
            self.role = "staff"

    def deactivate(self) -> None:
        self.is_active = False
        self.unlock()

    def activate(self) -> None:
        self.is_active = True

    def safe_email(self) -> str:
        e = str(self.email or "")
        if "@" not in e:
            return e
        name, domain = e.split("@", 1)
        if len(name) <= 2:
            return f"{name[:1]}*@{domain}"
        return f"{name[:2]}***@{domain}"

    def prepare(self) -> None:
        # normalizaciones base
        self.email = _normalize_email(self.email)[:_DB_EMAIL_LEN]
        self.phone = _clean_phone(self.phone)
        self.name = _strip_or_none(self.name, _MAX_NAME_LEN)
        self.city = _strip_or_none(self.city, _MAX_CITY_LEN)

        c = _strip_or_none(self.country, 2)
        self.country = c.upper() if c else None

        # booleans robustos
        self.is_active = bool(self.is_active)
        self.is_admin = bool(self.is_admin)
        self.email_verified = bool(self.email_verified)
        self.email_opt_in = bool(self.email_opt_in)

        # rol final consistente
        if self.is_owner:
            self.is_admin = True
            self.role = "admin"
        else:
            self.role = _role_normalize(self.role) or ("admin" if self.is_admin else "customer")

        # tokens + auth tokens (sin consultas DB en flush)
        self.ensure_tokens()

        st = inspect(self)
        try:
            if st.attrs.email.history.has_changes():
                self.email_verified = False
                self.email_verified_at = None
                self.email_verify_token = None
        except Exception:
            pass

        self.ensure_auth_tokens()

        # timestamps coherentes
        if self.email_verified and not self.email_verified_at:
            self.email_verified_at = utcnow()

        if self.email_opt_in and not self.email_opt_in_at:
            self.email_opt_in_at = utcnow()
        if not self.email_opt_in:
            self.email_opt_in_at = None

        # seguridad de contadores e IPs
        self.failed_login_count = _clamp_int(self.failed_login_count, 0, 0, 10_000)
        self.last_login_ip = _safe_ip(self.last_login_ip)

        # locked_until debe ser datetime o None
        if self.locked_until and not isinstance(self.locked_until, datetime):
            self.locked_until = None

    def as_public(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "role": self.role_effective,
            "is_active": bool(self.is_active),
            "email_verified": bool(self.email_verified),
        }

    def __repr__(self) -> str:
        return f"<User {self.id} {self.email} role={self.role_effective}>"


class UserAddress(db.Model):
    __tablename__ = "user_addresses"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    label = db.Column(db.String(50))
    full_name = db.Column(db.String(120))
    phone = db.Column(db.String(_MAX_PHONE_LEN))

    line1 = db.Column(db.String(200), nullable=False)
    line2 = db.Column(db.String(200))

    city = db.Column(db.String(120))
    state = db.Column(db.String(120))
    postal_code = db.Column(db.String(40))
    country = db.Column(db.String(2))

    is_default = db.Column(db.Boolean, default=False, server_default="0", nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

    user = db.relationship("User", back_populates="addresses")

    __table_args__ = (
        Index("ix_user_addresses_default", "user_id", "is_default"),
        Index("ix_user_addresses_user_created", "user_id", "created_at"),
        CheckConstraint("is_default IN (0,1)", name="ck_user_addresses_default_bool"),
    )

    @validates("phone")
    def _v_phone(self, key: str, value: Any) -> Optional[str]:
        return _clean_phone(value)

    @validates("country")
    def _v_country(self, key: str, value: Any) -> Optional[str]:
        v = _strip_or_none(value, 2)
        return v.upper() if v else None

    def set_as_default(self) -> None:
        self.is_default = True
        if not self.user_id:
            return
        try:
            db.session.query(UserAddress).filter(
                UserAddress.user_id == self.user_id,
                UserAddress.id != self.id,
                UserAddress.is_default.is_(True),
            ).update({"is_default": False}, synchronize_session=False)
        except SQLAlchemyError:
            db.session.rollback()
            raise

    def __repr__(self) -> str:
        return f"<UserAddress {self.id} user={self.user_id} default={bool(self.is_default)}>"


@event.listens_for(User, "before_insert")
def _user_before_insert(mapper, connection, target: User) -> None:
    # NO hacemos queries acá: solo preparación determinística
    target.prepare()


@event.listens_for(User, "before_update")
def _user_before_update(mapper, connection, target: User) -> None:
    target.prepare()


@event.listens_for(SASession, "before_flush")
def _users_before_flush(session: SASession, flush_context, instances) -> None:
    # ✅ FIX CRÍTICO: before_flush es evento de Session, no de User.
    # Además: nada de queries acá (evita errores/recursión durante flush).
    for obj in list(session.new) + list(session.dirty):
        if isinstance(obj, User):
            try:
                obj.ensure_tokens()
                obj.ensure_auth_tokens()
            except Exception:
                pass


@event.listens_for(User, "after_insert")
def _user_after_insert(mapper, connection, target: User) -> None:
    # hardening para filas que por cualquier razón queden sin unsubscribe_token
    if target.unsubscribe_token:
        return
    for _ in range(3):
        try:
            tok = _token64()
            connection.execute(
                User.__table__.update()
                .where(User.__table__.c.id == target.id)
                .where(User.__table__.c.unsubscribe_token.is_(None))
                .values(unsubscribe_token=tok)
            )
            break
        except Exception:
            continue


def create_user_safely(**kwargs) -> Tuple[User, bool]:
    # Crea usuario y maneja duplicados de email/tokens con rollback limpio.
    u = User(**kwargs)
    u.prepare()
    db.session.add(u)

    try:
        db.session.commit()
        return u, True

    except IntegrityError as e:
        db.session.rollback()

        # Retry “token collisions” (rarísimo) sin reventar deploy
        if _maybe_unique_violation(e):
            # si el duplicado fue token (email_verify/reset/unsub), rotamos y reintentamos una vez
            try:
                if u.unsubscribe_token:
                    u.unsubscribe_token = _token64()
                if u.email_verify_token:
                    u.email_verify_token = _token64()
                if u.reset_password_token:
                    u.reset_password_token = _token64()
                db.session.add(u)
                db.session.commit()
                return u, True
            except IntegrityError as e2:
                db.session.rollback()
                raise ValueError("Email o token ya existe (duplicado).") from e2

        raise

    except SQLAlchemyError:
        db.session.rollback()
        raise
