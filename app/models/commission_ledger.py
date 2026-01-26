from __future__ import annotations

import enum
import json
import logging
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    and_,
    func,
    select,
    text,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.models import db

log = logging.getLogger("commission_ledger")

TWOPLACES = Decimal("0.01")
USER_TABLE_NAME = "users"
USER_PK_COL = "id"
META_JSON_MAX_BYTES = 32_000
MAX_ABS_AMOUNT = Decimal("999999999999.99")

_SQLITE_DIALECTS = {"sqlite"}
_LOCK_TTL_SEC = 8
_ENV_REFRESH_SEC = 30
_env_last_applied = 0

DEFAULT_BALANCE_EXCLUDES_VOIDED = True


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _now_ts() -> int:
    return int(time.time())


def _safe_str(v: Any, max_len: int) -> str:
    s = "" if v is None else str(v)
    s = s.strip()
    if len(s) > max_len:
        s = s[:max_len]
    return s


def _currency(code: Any) -> str:
    c = _safe_str(code, 8).upper()
    if not c:
        return "USD"
    if len(c) < 3:
        raise ValueError("currency code too short")
    return c


def _to_decimal(v: Any, *, places: Decimal = TWOPLACES, allow_negative: bool = True) -> Decimal:
    if v is None:
        raise ValueError("amount is required")
    try:
        d = v if isinstance(v, Decimal) else Decimal(str(v))
    except (InvalidOperation, ValueError) as e:
        raise ValueError(f"Invalid decimal value: {v!r}") from e

    if d.is_nan() or d.is_infinite():
        raise ValueError("amount cannot be NaN/Infinity")

    d = d.quantize(places, rounding=ROUND_HALF_UP)

    if not allow_negative and d < 0:
        raise ValueError("amount cannot be negative")

    if abs(d) > MAX_ABS_AMOUNT:
        raise ValueError("amount out of allowed range")

    return d


def _gen_public_id(prefix: str = "cl") -> str:
    return f"{prefix}_{secrets.token_urlsafe(12)}"


def _json_dumps_compact(obj: Any) -> str:
    if obj is None:
        return ""

    if isinstance(obj, str):
        s = obj.strip()
        if not s:
            return ""
        if s[:1] in ("{", "["):
            try:
                json.loads(s)
            except Exception as e:
                raise ValueError("meta_json string is not valid JSON") from e
        if len(s.encode("utf-8")) > META_JSON_MAX_BYTES:
            raise ValueError("meta_json too large")
        return s

    try:
        s2 = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True, default=str)
    except Exception as e:
        raise ValueError("meta_json is not JSON-serializable") from e

    if len(s2.encode("utf-8")) > META_JSON_MAX_BYTES:
        raise ValueError("meta_json too large")
    return s2


def _apply_env_overrides(force: bool = False) -> None:
    global USER_TABLE_NAME, USER_PK_COL, META_JSON_MAX_BYTES, _env_last_applied

    now = _now_ts()
    if not force and _env_last_applied and (now - _env_last_applied) < _ENV_REFRESH_SEC:
        return
    _env_last_applied = now

    try:
        cfg = getattr(db, "get_app", None)
        app = cfg() if callable(cfg) else None
        conf = getattr(app, "config", None) if app else None
    except Exception:
        conf = None

    def _cfg(key: str, default: Any) -> Any:
        try:
            if conf and key in conf:
                return conf.get(key, default)
        except Exception:
            pass
        return default

    USER_TABLE_NAME = _safe_str(_cfg("USER_TABLE_NAME", USER_TABLE_NAME), 64) or USER_TABLE_NAME
    USER_PK_COL = _safe_str(_cfg("USER_PK_COL", USER_PK_COL), 64) or USER_PK_COL

    try:
        mj = _cfg("META_JSON_MAX_BYTES", META_JSON_MAX_BYTES)
        META_JSON_MAX_BYTES = int(mj) if mj is not None else META_JSON_MAX_BYTES
        META_JSON_MAX_BYTES = max(2_000, min(META_JSON_MAX_BYTES, 256_000))
    except Exception:
        META_JSON_MAX_BYTES = META_JSON_MAX_BYTES


class LedgerEntryType(str, enum.Enum):
    COMMISSION_EARNED = "commission_earned"
    COMMISSION_ADJUST = "commission_adjust"
    COMMISSION_REVERSE = "commission_reverse"
    PAYOUT_PENDING = "payout_pending"
    PAYOUT_SENT = "payout_sent"
    PAYOUT_FAILED = "payout_failed"
    PAYOUT_REFUND = "payout_refund"
    DISPUTE_HOLD = "dispute_hold"
    DISPUTE_RELEASE = "dispute_release"
    NOTE = "note"


class LedgerStatus(str, enum.Enum):
    POSTED = "posted"
    VOIDED = "voided"
    RECONCILED = "reconciled"


class PayoutStatus(str, enum.Enum):
    CREATED = "created"
    PROCESSING = "processing"
    SENT = "sent"
    FAILED = "failed"
    CANCELED = "canceled"
    RECONCILED = "reconciled"


class CommissionLedgerError(RuntimeError):
    pass


class InsufficientAvailableBalance(CommissionLedgerError):
    pass


class DuplicateIdempotencyKey(CommissionLedgerError):
    pass


class InvalidLedgerOperation(CommissionLedgerError):
    pass


class ConcurrencyError(CommissionLedgerError):
    pass


@dataclass(frozen=True)
class EntryRule:
    amount_sign: str
    avail_sign: str
    requires_related: bool = False


_RULES: Dict[LedgerEntryType, EntryRule] = {
    LedgerEntryType.COMMISSION_EARNED: EntryRule("pos", "pos"),
    LedgerEntryType.COMMISSION_ADJUST: EntryRule("any", "any"),
    LedgerEntryType.COMMISSION_REVERSE: EntryRule("any", "any", requires_related=True),
    LedgerEntryType.PAYOUT_PENDING: EntryRule("zero", "neg"),
    LedgerEntryType.PAYOUT_SENT: EntryRule("neg", "zero"),
    LedgerEntryType.PAYOUT_FAILED: EntryRule("zero", "pos"),
    LedgerEntryType.PAYOUT_REFUND: EntryRule("pos", "pos"),
    LedgerEntryType.DISPUTE_HOLD: EntryRule("zero", "neg"),
    LedgerEntryType.DISPUTE_RELEASE: EntryRule("zero", "pos"),
    LedgerEntryType.NOTE: EntryRule("zero", "zero"),
}


def _enforce_sign(rule: EntryRule, amount: Decimal, avail: Decimal) -> None:
    z = Decimal("0.00")

    def ok(sign: str, v: Decimal) -> bool:
        if sign == "any":
            return True
        if sign == "zero":
            return v == z
        if sign == "pos":
            return v > z
        if sign == "neg":
            return v < z
        return False

    if not ok(rule.amount_sign, amount):
        raise InvalidLedgerOperation(f"amount violates rule: expected {rule.amount_sign}, got {amount}")
    if not ok(rule.avail_sign, avail):
        raise InvalidLedgerOperation(f"available_delta violates rule: expected {rule.avail_sign}, got {avail}")


class CommissionLedgerEntry(db.Model):
    __tablename__ = "commission_ledger_entries"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    public_id: Mapped[str] = mapped_column(String(40), nullable=False, unique=True, index=True, default=_gen_public_id)

    entry_type: Mapped[LedgerEntryType] = mapped_column(
        Enum(LedgerEntryType, name="commission_ledger_entry_type"), nullable=False, index=True
    )

    status: Mapped[LedgerStatus] = mapped_column(
        Enum(LedgerStatus, name="commission_ledger_status"), nullable=False, index=True, default=LedgerStatus.POSTED
    )

    currency: Mapped[str] = mapped_column(String(8), nullable=False, index=True, default="USD")

    amount: Mapped[Decimal] = mapped_column(Numeric(18, 2), nullable=False, default=Decimal("0.00"))
    available_delta: Mapped[Decimal] = mapped_column(Numeric(18, 2), nullable=False, default=Decimal("0.00"))

    actor_user_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey(f"{USER_TABLE_NAME}.{USER_PK_COL}", ondelete="CASCADE"), nullable=False, index=True
    )
    actor = relationship("User", foreign_keys=[actor_user_id], lazy="joined")

    created_by_user_id: Mapped[Optional[int]] = mapped_column(
        BigInteger, ForeignKey(f"{USER_TABLE_NAME}.{USER_PK_COL}", ondelete="SET NULL"), nullable=True, index=True
    )
    created_by = relationship("User", foreign_keys=[created_by_user_id], lazy="select")

    order_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True, index=True)
    order_item_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True, index=True)
    payment_provider: Mapped[Optional[str]] = mapped_column(String(40), nullable=True, index=True)
    payment_ref: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)

    idempotency_key: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, unique=True, index=True)

    related_entry_id: Mapped[Optional[int]] = mapped_column(
        BigInteger, ForeignKey("commission_ledger_entries.id", ondelete="SET NULL"), nullable=True, index=True
    )
    related_entry = relationship("CommissionLedgerEntry", remote_side=[id], lazy="select")

    note: Mapped[Optional[str]] = mapped_column(String(300), nullable=True)
    meta_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    posted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)

    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    is_voided: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    __table_args__ = (
        CheckConstraint("currency <> ''", name="ck_comm_ledger_currency_nonempty"),
        CheckConstraint("version >= 1", name="ck_comm_ledger_version_gte_1"),
        CheckConstraint(
            "amount <= 999999999999.99 AND amount >= -999999999999.99",
            name="ck_comm_ledger_amount_range",
        ),
        CheckConstraint(
            "available_delta <= 999999999999.99 AND available_delta >= -999999999999.99",
            name="ck_comm_ledger_avail_range",
        ),
        CheckConstraint(
            "(is_voided = 0 AND status <> 'voided') OR (is_voided = 1 AND status = 'voided')",
            name="ck_comm_ledger_void_consistency",
        ),
        Index("ix_comm_ledger_actor_created", "actor_user_id", "created_at"),
        Index("ix_comm_ledger_actor_currency_created", "actor_user_id", "currency", "created_at"),
        Index("ix_comm_ledger_order_actor", "order_id", "actor_user_id"),
        Index("ix_comm_ledger_payref_actor", "payment_ref", "actor_user_id"),
        Index("ix_comm_ledger_type_actor_created", "entry_type", "actor_user_id", "created_at"),
        Index("ix_comm_ledger_actor_entry_created", "actor_user_id", "entry_type", "created_at", "id"),
    )

    @validates("currency")
    def _v_currency(self, _key: str, v: Any) -> str:
        return _currency(v)

    @validates("note")
    def _v_note(self, _key: str, v: Any) -> Optional[str]:
        s = _safe_str(v, 300)
        return s or None

    @validates("payment_provider")
    def _v_provider(self, _key: str, v: Any) -> Optional[str]:
        s = _safe_str(v, 40)
        return s or None

    @validates("payment_ref")
    def _v_payref(self, _key: str, v: Any) -> Optional[str]:
        s = _safe_str(v, 120)
        return s or None

    @validates("idempotency_key")
    def _v_ikey(self, _key: str, v: Any) -> Optional[str]:
        s = _safe_str(v, 120)
        return s or None

    @validates("meta_json")
    def _v_meta(self, _key: str, v: Any) -> Optional[str]:
        s = _json_dumps_compact(v)
        return s or None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "public_id": self.public_id,
            "entry_type": self.entry_type.value,
            "status": self.status.value,
            "currency": self.currency,
            "amount": str(self.amount),
            "available_delta": str(self.available_delta),
            "actor_user_id": self.actor_user_id,
            "created_by_user_id": self.created_by_user_id,
            "order_id": self.order_id,
            "order_item_id": self.order_item_id,
            "payment_provider": self.payment_provider,
            "payment_ref": self.payment_ref,
            "idempotency_key": self.idempotency_key,
            "related_entry_id": self.related_entry_id,
            "note": self.note,
            "meta_json": self.meta_json,
            "created_at": self.created_at.isoformat(),
            "posted_at": self.posted_at.isoformat() if self.posted_at else None,
            "version": self.version,
            "is_voided": self.is_voided,
        }


class CommissionPayout(db.Model):
    __tablename__ = "commission_payouts"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    public_id: Mapped[str] = mapped_column(
        String(40), nullable=False, unique=True, index=True, default=lambda: _gen_public_id("po")
    )

    status: Mapped[PayoutStatus] = mapped_column(
        Enum(PayoutStatus, name="commission_payout_status"), nullable=False, index=True, default=PayoutStatus.CREATED
    )

    provider: Mapped[Optional[str]] = mapped_column(String(40), nullable=True, index=True)
    provider_ref: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)

    currency: Mapped[str] = mapped_column(String(8), nullable=False, index=True, default="USD")
    gross_amount: Mapped[Decimal] = mapped_column(Numeric(18, 2), nullable=False, default=Decimal("0.00"))
    fee_amount: Mapped[Decimal] = mapped_column(Numeric(18, 2), nullable=False, default=Decimal("0.00"))
    net_amount: Mapped[Decimal] = mapped_column(Numeric(18, 2), nullable=False, default=Decimal("0.00"))

    created_by_user_id: Mapped[Optional[int]] = mapped_column(
        BigInteger, ForeignKey(f"{USER_TABLE_NAME}.{USER_PK_COL}", ondelete="SET NULL"), nullable=True, index=True
    )
    created_by = relationship("User", foreign_keys=[created_by_user_id], lazy="select")

    note: Mapped[Optional[str]] = mapped_column(String(300), nullable=True)
    meta_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow, index=True)

    __table_args__ = (
        CheckConstraint("currency <> ''", name="ck_comm_payout_currency_nonempty"),
        CheckConstraint("gross_amount >= 0", name="ck_comm_payout_gross_nonneg"),
        CheckConstraint("fee_amount >= 0", name="ck_comm_payout_fee_nonneg"),
        CheckConstraint("net_amount >= 0", name="ck_comm_payout_net_nonneg"),
        Index("ix_comm_payout_provider_ref", "provider", "provider_ref"),
        Index("ix_comm_payout_status_created", "status", "created_at"),
    )

    @validates("currency")
    def _v_currency(self, _key: str, v: Any) -> str:
        return _currency(v)

    @validates("provider")
    def _v_provider(self, _key: str, v: Any) -> Optional[str]:
        s = _safe_str(v, 40)
        return s or None

    @validates("provider_ref")
    def _v_ref(self, _key: str, v: Any) -> Optional[str]:
        s = _safe_str(v, 120)
        return s or None

    @validates("note")
    def _v_note(self, _key: str, v: Any) -> Optional[str]:
        s = _safe_str(v, 300)
        return s or None

    @validates("meta_json")
    def _v_meta(self, _key: str, v: Any) -> Optional[str]:
        s = _json_dumps_compact(v)
        return s or None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "public_id": self.public_id,
            "status": self.status.value,
            "provider": self.provider,
            "provider_ref": self.provider_ref,
            "currency": self.currency,
            "gross_amount": str(self.gross_amount),
            "fee_amount": str(self.fee_amount),
            "net_amount": str(self.net_amount),
            "created_by_user_id": self.created_by_user_id,
            "note": self.note,
            "meta_json": self.meta_json,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass(frozen=True)
class CommissionBalance:
    actor_user_id: int
    currency: str
    total: Decimal
    available: Decimal
    reserved: Decimal

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actor_user_id": self.actor_user_id,
            "currency": self.currency,
            "total": str(self.total),
            "available": str(self.available),
            "reserved": str(self.reserved),
        }


def _dialect_name() -> str:
    try:
        return str(db.session.bind.dialect.name)  # type: ignore[union-attr]
    except Exception:
        return ""


def _try_advisory_lock(key: str, ttl_sec: int = _LOCK_TTL_SEC) -> bool:
    try:
        cache = current_app.extensions.get("cache")  # type: ignore[union-attr]
    except Exception:
        cache = None
    if not cache:
        return False
    try:
        return bool(cache.add(f"comm_ledger_lock:{key}", "1", timeout=max(1, int(ttl_sec))))
    except Exception:
        return False


def _release_advisory_lock(key: str) -> None:
    try:
        cache = current_app.extensions.get("cache")  # type: ignore[union-attr]
    except Exception:
        cache = None
    if not cache:
        return
    try:
        cache.delete(f"comm_ledger_lock:{key}")
    except Exception:
        pass


def _lock_actor_rows(actor_user_id: int, currency: Optional[str] = None) -> None:
    if actor_user_id <= 0:
        raise InvalidLedgerOperation("actor_user_id must be > 0")

    if _dialect_name().lower() in _SQLITE_DIALECTS:
        return

    _apply_env_overrides()
    cur = _currency(currency) if currency else None
    lock_key = f"{actor_user_id}:{cur or '*'}"

    locked_by_cache = _try_advisory_lock(lock_key, ttl_sec=_LOCK_TTL_SEC)
    try:
        tbl = USER_TABLE_NAME
        pk = USER_PK_COL
        db.session.execute(
            select(func.cast(1, Integer))
            .select_from(text(tbl))
            .where(text(f"{pk} = :uid"))
            .params(uid=actor_user_id)
            .with_for_update()
        )
    finally:
        if locked_by_cache:
            _release_advisory_lock(lock_key)


def get_balance(actor_user_id: int, currency: str = "USD", *, include_voided: bool = False) -> CommissionBalance:
    cur = _currency(currency)

    q = select(
        func.coalesce(func.sum(CommissionLedgerEntry.amount), 0),
        func.coalesce(func.sum(CommissionLedgerEntry.available_delta), 0),
    ).where(
        CommissionLedgerEntry.actor_user_id == actor_user_id,
        CommissionLedgerEntry.currency == cur,
        CommissionLedgerEntry.status.in_([LedgerStatus.POSTED, LedgerStatus.RECONCILED]),
        *( [] if include_voided else [CommissionLedgerEntry.is_voided.is_(False)] ),
    )

    total, available = db.session.execute(q).one()
    total_d = _to_decimal(total, allow_negative=True)
    available_d = _to_decimal(available, allow_negative=True)
    reserved_d = (total_d - available_d).quantize(TWOPLACES, rounding=ROUND_HALF_UP)
    return CommissionBalance(actor_user_id=actor_user_id, currency=cur, total=total_d, available=available_d, reserved=reserved_d)


def get_balances_bulk(
    actor_user_ids: Sequence[int], currency: str = "USD", *, include_voided: bool = False
) -> Dict[int, CommissionBalance]:
    cur = _currency(currency)
    ids = [int(x) for x in actor_user_ids if int(x) > 0]
    if not ids:
        return {}

    q = (
        select(
            CommissionLedgerEntry.actor_user_id,
            func.coalesce(func.sum(CommissionLedgerEntry.amount), 0),
            func.coalesce(func.sum(CommissionLedgerEntry.available_delta), 0),
        )
        .where(
            CommissionLedgerEntry.actor_user_id.in_(ids),
            CommissionLedgerEntry.currency == cur,
            CommissionLedgerEntry.status.in_([LedgerStatus.POSTED, LedgerStatus.RECONCILED]),
            *( [] if include_voided else [CommissionLedgerEntry.is_voided.is_(False)] ),
        )
        .group_by(CommissionLedgerEntry.actor_user_id)
    )

    out: Dict[int, CommissionBalance] = {}
    for uid, total, avail in db.session.execute(q).all():
        total_d = _to_decimal(total, allow_negative=True)
        avail_d = _to_decimal(avail, allow_negative=True)
        out[int(uid)] = CommissionBalance(
            actor_user_id=int(uid),
            currency=cur,
            total=total_d,
            available=avail_d,
            reserved=(total_d - avail_d).quantize(TWOPLACES, rounding=ROUND_HALF_UP),
        )

    for uid in ids:
        if uid not in out:
            out[uid] = CommissionBalance(uid, cur, Decimal("0.00"), Decimal("0.00"), Decimal("0.00"))

    return out


def list_entries(
    actor_user_id: int,
    *,
    currency: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    include_voided: bool = False,
    entry_types: Optional[Sequence[LedgerEntryType]] = None,
) -> List[CommissionLedgerEntry]:
    limit_i = max(1, min(int(limit or 100), 500))
    offset_i = max(0, int(offset or 0))

    conds = [CommissionLedgerEntry.actor_user_id == int(actor_user_id)]
    if currency:
        conds.append(CommissionLedgerEntry.currency == _currency(currency))
    if not include_voided:
        conds.append(CommissionLedgerEntry.is_voided.is_(False))
    if entry_types:
        conds.append(CommissionLedgerEntry.entry_type.in_(list(entry_types)))

    q = (
        select(CommissionLedgerEntry)
        .where(and_(*conds))
        .order_by(CommissionLedgerEntry.created_at.desc(), CommissionLedgerEntry.id.desc())
        .limit(limit_i)
        .offset(offset_i)
    )
    return list(db.session.execute(q).scalars().all())


def get_entry_by_public_id(public_id: str) -> Optional[CommissionLedgerEntry]:
    pid = _safe_str(public_id, 60)
    if not pid:
        return None
    return db.session.execute(select(CommissionLedgerEntry).where(CommissionLedgerEntry.public_id == pid)).scalar_one_or_none()


def _get_entry_by_idempotency_key(ikey: str) -> Optional[CommissionLedgerEntry]:
    s = _safe_str(ikey, 120)
    if not s:
        return None
    return db.session.execute(
        select(CommissionLedgerEntry).where(CommissionLedgerEntry.idempotency_key == s)
    ).scalar_one_or_none()


def _insert_entry(
    *,
    actor_user_id: int,
    entry_type: LedgerEntryType,
    currency: str,
    amount: Union[Decimal, Any],
    available_delta: Union[Decimal, Any],
    created_by_user_id: Optional[int] = None,
    order_id: Optional[int] = None,
    order_item_id: Optional[int] = None,
    payment_provider: Optional[str] = None,
    payment_ref: Optional[str] = None,
    idempotency_key: Optional[str] = None,
    related_entry_id: Optional[int] = None,
    note: Optional[str] = None,
    meta_json: Optional[Any] = None,
    posted: bool = True,
) -> CommissionLedgerEntry:
    cur = _currency(currency)
    amount_q = _to_decimal(amount, allow_negative=True)
    avail_q = _to_decimal(available_delta, allow_negative=True)

    rule = _RULES.get(entry_type)
    if not rule:
        raise InvalidLedgerOperation("unknown entry_type rule")
    _enforce_sign(rule, amount_q, avail_q)
    if rule.requires_related and not related_entry_id:
        raise InvalidLedgerOperation("related_entry_id is required for this entry_type")

    ikey = _safe_str(idempotency_key, 120) or None
    if ikey:
        existing = _get_entry_by_idempotency_key(ikey)
        if existing:
            return existing

    e = CommissionLedgerEntry(
        entry_type=entry_type,
        status=LedgerStatus.POSTED,
        currency=cur,
        amount=amount_q,
        available_delta=avail_q,
        actor_user_id=int(actor_user_id),
        created_by_user_id=created_by_user_id,
        order_id=order_id,
        order_item_id=order_item_id,
        payment_provider=_safe_str(payment_provider, 40) or None,
        payment_ref=_safe_str(payment_ref, 120) or None,
        idempotency_key=ikey,
        related_entry_id=related_entry_id,
        note=_safe_str(note, 300) or None,
        meta_json=_json_dumps_compact(meta_json) or None,
        posted_at=utcnow() if posted else None,
    )
    db.session.add(e)

    try:
        with db.session.begin_nested():
            db.session.flush()
        return e
    except IntegrityError as ie:
        db.session.rollback()
        if ikey:
            existing2 = _get_entry_by_idempotency_key(ikey)
            if existing2:
                return existing2
        raise DuplicateIdempotencyKey("Unique constraint hit (idempotency_key/public_id).") from ie


def post_commission_earned(
    *,
    actor_user_id: int,
    amount: Any,
    currency: str = "USD",
    order_id: Optional[int] = None,
    order_item_id: Optional[int] = None,
    created_by_user_id: Optional[int] = None,
    idempotency_key: Optional[str] = None,
    note: Optional[str] = None,
    meta_json: Optional[Any] = None,
) -> CommissionLedgerEntry:
    amt = _to_decimal(amount, allow_negative=False)
    if amt <= Decimal("0.00"):
        raise InvalidLedgerOperation("commission_earned amount must be > 0")

    _lock_actor_rows(actor_user_id, currency)

    return _insert_entry(
        actor_user_id=actor_user_id,
        entry_type=LedgerEntryType.COMMISSION_EARNED,
        currency=currency,
        amount=amt,
        available_delta=amt,
        created_by_user_id=created_by_user_id,
        order_id=order_id,
        order_item_id=order_item_id,
        idempotency_key=idempotency_key,
        note=note,
        meta_json=meta_json,
        posted=True,
    )


def post_adjustment(
    *,
    actor_user_id: int,
    amount: Any,
    currency: str = "USD",
    created_by_user_id: Optional[int] = None,
    idempotency_key: Optional[str] = None,
    note: Optional[str] = None,
    meta_json: Optional[Any] = None,
) -> CommissionLedgerEntry:
    amt = _to_decimal(amount, allow_negative=True)
    if amt == Decimal("0.00"):
        raise InvalidLedgerOperation("adjustment amount must be non-zero")

    _lock_actor_rows(actor_user_id, currency)

    return _insert_entry(
        actor_user_id=actor_user_id,
        entry_type=LedgerEntryType.COMMISSION_ADJUST,
        currency=currency,
        amount=amt,
        available_delta=amt,
        created_by_user_id=created_by_user_id,
        idempotency_key=idempotency_key,
        note=note or "Manual adjustment",
        meta_json=meta_json,
        posted=True,
    )


def reverse_entry(
    *,
    actor_user_id: int,
    entry_id: int,
    created_by_user_id: Optional[int] = None,
    idempotency_key: Optional[str] = None,
    note: Optional[str] = None,
    meta_json: Optional[Any] = None,
) -> CommissionLedgerEntry:
    _lock_actor_rows(actor_user_id)

    original = db.session.get(CommissionLedgerEntry, int(entry_id))
    if not original or original.actor_user_id != int(actor_user_id):
        raise InvalidLedgerOperation("entry not found")
    if original.is_voided:
        raise InvalidLedgerOperation("cannot reverse a voided entry")

    rev_amount = (-original.amount).quantize(TWOPLACES, rounding=ROUND_HALF_UP)
    rev_avail = (-original.available_delta).quantize(TWOPLACES, rounding=ROUND_HALF_UP)

    return _insert_entry(
        actor_user_id=actor_user_id,
        entry_type=LedgerEntryType.COMMISSION_REVERSE,
        currency=original.currency,
        amount=rev_amount,
        available_delta=rev_avail,
        created_by_user_id=created_by_user_id,
        order_id=original.order_id,
        order_item_id=original.order_item_id,
        payment_provider=original.payment_provider,
        payment_ref=original.payment_ref,
        idempotency_key=idempotency_key,
        related_entry_id=original.id,
        note=note or f"Reverse of entry {original.public_id}",
        meta_json=meta_json,
        posted=True,
    )


def create_payout(
    *,
    actor_user_id: int,
    amount: Any,
    currency: str = "USD",
    fee_amount: Any = "0",
    provider: Optional[str] = None,
    provider_ref: Optional[str] = None,
    created_by_user_id: Optional[int] = None,
    idempotency_key: Optional[str] = None,
    note: Optional[str] = None,
    meta_json: Optional[Any] = None,
) -> Tuple[CommissionPayout, CommissionLedgerEntry]:
    cur = _currency(currency)
    amt = _to_decimal(amount, allow_negative=False)
    fee = _to_decimal(fee_amount, allow_negative=False)

    if amt <= Decimal("0.00"):
        raise InvalidLedgerOperation("payout amount must be > 0")
    if fee > amt:
        raise InvalidLedgerOperation("fee cannot exceed amount")

    _lock_actor_rows(actor_user_id, cur)

    bal = get_balance(actor_user_id, cur)
    if bal.available < amt:
        raise InsufficientAvailableBalance(f"available {bal.available} < requested {amt}")

    payout = CommissionPayout(
        status=PayoutStatus.CREATED,
        provider=_safe_str(provider, 40) or None,
        provider_ref=_safe_str(provider_ref, 120) or None,
        currency=cur,
        gross_amount=amt,
        fee_amount=fee,
        net_amount=(amt - fee).quantize(TWOPLACES, rounding=ROUND_HALF_UP),
        created_by_user_id=created_by_user_id,
        note=_safe_str(note, 300) or None,
        meta_json=_json_dumps_compact(meta_json) or None,
    )
    db.session.add(payout)
    db.session.flush()

    hold_entry = _insert_entry(
        actor_user_id=actor_user_id,
        entry_type=LedgerEntryType.PAYOUT_PENDING,
        currency=cur,
        amount=Decimal("0.00"),
        available_delta=(-amt).quantize(TWOPLACES, rounding=ROUND_HALF_UP),
        created_by_user_id=created_by_user_id,
        payment_provider=payout.provider,
        payment_ref=payout.public_id,
        idempotency_key=idempotency_key,
        note=f"Reserve for payout {payout.public_id}",
        meta_json={
            "payout_id": payout.id,
            "payout_public_id": payout.public_id,
            **(meta_json or {}),
        },
        posted=True,
    )

    return payout, hold_entry


def mark_payout_sent(
    *,
    actor_user_id: int,
    payout_id: int,
    provider: Optional[str] = None,
    provider_ref: Optional[str] = None,
    created_by_user_id: Optional[int] = None,
    idempotency_key: Optional[str] = None,
    note: Optional[str] = None,
    meta_json: Optional[Any] = None,
) -> Tuple[CommissionPayout, CommissionLedgerEntry]:
    _lock_actor_rows(actor_user_id)

    payout = db.session.get(CommissionPayout, int(payout_id))
    if not payout:
        raise InvalidLedgerOperation("payout not found")

    if payout.status in (PayoutStatus.SENT, PayoutStatus.RECONCILED):
        if idempotency_key:
            existing = _get_entry_by_idempotency_key(_safe_str(idempotency_key, 120))
            if existing:
                return payout, existing
        raise DuplicateIdempotencyKey("payout already marked as sent/reconciled")

    payout.provider = _safe_str(provider, 40) or payout.provider
    payout.provider_ref = _safe_str(provider_ref, 120) or payout.provider_ref
    payout.status = PayoutStatus.SENT
    payout.updated_at = utcnow()

    amt = _to_decimal(payout.gross_amount, allow_negative=False)

    sent_entry = _insert_entry(
        actor_user_id=actor_user_id,
        entry_type=LedgerEntryType.PAYOUT_SENT,
        currency=payout.currency,
        amount=(-amt).quantize(TWOPLACES, rounding=ROUND_HALF_UP),
        available_delta=Decimal("0.00"),
        created_by_user_id=created_by_user_id,
        payment_provider=payout.provider,
        payment_ref=payout.provider_ref or payout.public_id,
        idempotency_key=idempotency_key,
        note=_safe_str(note, 300) or f"Payout sent {payout.public_id}",
        meta_json={
            "payout_id": payout.id,
            "payout_public_id": payout.public_id,
            **(meta_json or {}),
        },
        posted=True,
    )
    return payout, sent_entry


def mark_payout_failed(
    *,
    actor_user_id: int,
    payout_id: int,
    reason: Optional[str] = None,
    created_by_user_id: Optional[int] = None,
    idempotency_key: Optional[str] = None,
    meta_json: Optional[Any] = None,
) -> Tuple[CommissionPayout, CommissionLedgerEntry]:
    _lock_actor_rows(actor_user_id)

    payout = db.session.get(CommissionPayout, int(payout_id))
    if not payout:
        raise InvalidLedgerOperation("payout not found")

    if payout.status in (PayoutStatus.FAILED, PayoutStatus.CANCELED):
        if idempotency_key:
            existing = _get_entry_by_idempotency_key(_safe_str(idempotency_key, 120))
            if existing:
                return payout, existing
        raise DuplicateIdempotencyKey("payout already failed/canceled")

    payout.status = PayoutStatus.FAILED
    payout.updated_at = utcnow()

    amt = _to_decimal(payout.gross_amount, allow_negative=False)

    entry = _insert_entry(
        actor_user_id=actor_user_id,
        entry_type=LedgerEntryType.PAYOUT_FAILED,
        currency=payout.currency,
        amount=Decimal("0.00"),
        available_delta=amt,
        created_by_user_id=created_by_user_id,
        payment_provider=payout.provider,
        payment_ref=payout.public_id,
        idempotency_key=idempotency_key,
        note=f"Payout failed {payout.public_id}: {_safe_str(reason, 200)}".strip(),
        meta_json={
            "payout_id": payout.id,
            "payout_public_id": payout.public_id,
            "reason": reason,
            **(meta_json or {}),
        },
        posted=True,
    )
    return payout, entry


def reconcile_entries(
    *,
    actor_user_id: int,
    entry_ids: Sequence[int],
    created_by_user_id: Optional[int] = None,
    note: Optional[str] = None,
) -> int:
    ids = [int(i) for i in entry_ids if int(i) > 0]
    if not ids:
        return 0

    _lock_actor_rows(actor_user_id)

    q = db.session.query(CommissionLedgerEntry).filter(
        CommissionLedgerEntry.actor_user_id == int(actor_user_id),
        CommissionLedgerEntry.id.in_(ids),
        CommissionLedgerEntry.is_voided.is_(False),
    )

    count = 0
    now = utcnow()
    note_s = _safe_str(note, 300) if note else ""

    for e in q.all():
        if e.status != LedgerStatus.RECONCILED:
            e.status = LedgerStatus.RECONCILED
            e.version = int(e.version or 1) + 1
            e.posted_at = e.posted_at or now
            if note_s:
                e.note = note_s or e.note
            if created_by_user_id is not None and e.created_by_user_id is None:
                e.created_by_user_id = int(created_by_user_id)
            count += 1

    return count


def void_entry(
    *,
    actor_user_id: int,
    entry_id: int,
    created_by_user_id: Optional[int] = None,
    reason: Optional[str] = None,
) -> CommissionLedgerEntry:
    _lock_actor_rows(actor_user_id)

    e = db.session.get(CommissionLedgerEntry, int(entry_id))
    if not e or e.actor_user_id != int(actor_user_id):
        raise InvalidLedgerOperation("entry not found")

    if e.is_voided:
        return e

    e.is_voided = True
    e.status = LedgerStatus.VOIDED
    e.version = int(e.version or 1) + 1
    e.note = (f"VOIDED: {_safe_str(reason, 240)}" if reason else "VOIDED").strip()
    if created_by_user_id is not None:
        e.created_by_user_id = int(created_by_user_id)
    return e


@db.event.listens_for(CommissionLedgerEntry, "before_insert")
def _before_insert_entry(_mapper, _conn, target: CommissionLedgerEntry) -> None:
    target.currency = _currency(target.currency)
    target.amount = _to_decimal(target.amount, allow_negative=True)
    target.available_delta = _to_decimal(target.available_delta, allow_negative=True)
    target.created_at = target.created_at or utcnow()

    if not target.public_id:
        target.public_id = _gen_public_id("cl")

    if target.posted_at is None and target.status in (LedgerStatus.POSTED, LedgerStatus.RECONCILED):
        target.posted_at = utcnow()

    if target.entry_type == LedgerEntryType.NOTE:
        target.amount = Decimal("0.00")
        target.available_delta = Decimal("0.00")

    if target.is_voided:
        target.status = LedgerStatus.VOIDED

    rule = _RULES.get(target.entry_type)
    if rule:
        _enforce_sign(rule, target.amount, target.available_delta)
        if rule.requires_related and not target.related_entry_id:
            raise InvalidLedgerOperation("related_entry_id is required for this entry_type")


@db.event.listens_for(CommissionPayout, "before_insert")
def _before_insert_payout(_mapper, _conn, target: CommissionPayout) -> None:
    target.currency = _currency(target.currency)
    target.gross_amount = _to_decimal(target.gross_amount, allow_negative=False)
    target.fee_amount = _to_decimal(target.fee_amount, allow_negative=False)

    net = _to_decimal(target.net_amount, allow_negative=False)
    expected = (target.gross_amount - target.fee_amount).quantize(TWOPLACES, rounding=ROUND_HALF_UP)
    if net != expected:
        target.net_amount = expected

    if target.fee_amount > target.gross_amount:
        raise InvalidLedgerOperation("fee cannot exceed gross amount")

    if not target.public_id:
        target.public_id = _gen_public_id("po")

    target.created_at = target.created_at or utcnow()
    target.updated_at = target.updated_at or utcnow()


@db.event.listens_for(CommissionPayout, "before_update")
def _before_update_payout(_mapper, _conn, target: CommissionPayout) -> None:
    target.updated_at = utcnow()


__all__ = [
    "LedgerEntryType",
    "LedgerStatus",
    "PayoutStatus",
    "CommissionLedgerEntry",
    "CommissionPayout",
    "CommissionBalance",
    "CommissionLedgerError",
    "InsufficientAvailableBalance",
    "DuplicateIdempotencyKey",
    "InvalidLedgerOperation",
    "ConcurrencyError",
    "get_balance",
    "get_balances_bulk",
    "list_entries",
    "get_entry_by_public_id",
    "post_commission_earned",
    "post_adjustment",
    "reverse_entry",
    "create_payout",
    "mark_payout_sent",
    "mark_payout_failed",
    "reconcile_entries",
    "void_entry",
]
