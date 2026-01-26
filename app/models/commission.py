from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Optional, Tuple, List, Dict

from sqlalchemy import (
    Index,
    CheckConstraint,
    UniqueConstraint,
    event,
    select,
    func,
    and_,
    or_,
)
from sqlalchemy.orm import validates

from app.models import db


RATE_MIN = Decimal("0.0000")
RATE_MAX = Decimal("0.8000")
RATE_Q = Decimal("0.0001")
DEFAULT_RATE = Decimal("0.1000")
DEFAULT_SORT = 100

SALES_MIN = 1
SALES_MAX = 1_000_000_000
_INF = 10**18


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _s(v: Any) -> str:
    return "" if v is None else str(v).strip()


def _to_int(
    v: Any,
    default: int,
    *,
    min_value: Optional[int] = None,
    max_value: Optional[int] = None,
) -> int:
    try:
        n = int(_s(v))
    except Exception:
        n = default

    if min_value is not None and n < min_value:
        n = min_value
    if max_value is not None and n > max_value:
        n = max_value
    return n


def _normalize_label(label: Any) -> Optional[str]:
    s = _s(label)
    return (s[:120] if s else None)


def _parse_decimal(v: Any) -> Optional[Decimal]:
    if v is None or v == "":
        return None
    if isinstance(v, Decimal):
        return v
    if isinstance(v, int):
        return Decimal(v)
    if isinstance(v, float):
        try:
            return Decimal(str(v))
        except Exception:
            return None
    s = _s(v)
    if not s:
        return None
    s = s.replace(" ", "").replace(",", ".")
    try:
        return Decimal(s)
    except (InvalidOperation, ValueError, TypeError):
        return None


def _to_rate(v: Any, default: Decimal) -> Decimal:
    raw = _s(v)
    if v is None or raw == "":
        r = default
    else:
        s = raw.replace(" ", "").replace(",", ".")
        try:
            if s.endswith("%"):
                d = Decimal(s[:-1])
                r = d / Decimal("100")
            else:
                d = _parse_decimal(s)
                if d is None:
                    r = default
                else:
                    if d >= Decimal("1"):
                        r = d / Decimal("100")
                    else:
                        r = d
        except Exception:
            r = default

    if r < RATE_MIN:
        r = RATE_MIN
    if r > RATE_MAX:
        r = RATE_MAX
    return r.quantize(RATE_Q, rounding=ROUND_HALF_UP)


def _normalize_target(t: "CommissionTier") -> None:
    t.min_sales = _to_int(getattr(t, "min_sales", SALES_MIN) or SALES_MIN, SALES_MIN, min_value=SALES_MIN, max_value=SALES_MAX)

    mx = getattr(t, "max_sales", None)
    if mx is None or mx == "":
        t.max_sales = None
    else:
        n = _to_int(mx, default=-1, min_value=SALES_MIN, max_value=SALES_MAX)
        t.max_sales = None if n <= 0 else n

    if t.max_sales is not None and int(t.max_sales) < int(t.min_sales):
        t.max_sales = int(t.min_sales)

    t.rate = _to_rate(getattr(t, "rate", DEFAULT_RATE), DEFAULT_RATE)
    t.label = _normalize_label(getattr(t, "label", None))
    t.sort_order = _to_int(getattr(t, "sort_order", DEFAULT_SORT), DEFAULT_SORT, min_value=0, max_value=10_000)

    now = utcnow()
    if not getattr(t, "created_at", None):
        t.created_at = now
    t.updated_at = now


@dataclass(frozen=True)
class TierMatch:
    tier_id: int
    min_sales: int
    max_sales: Optional[int]
    rate: Decimal
    label: Optional[str]


class CommissionTier(db.Model):
    __tablename__ = "commission_tiers"

    id = db.Column(db.Integer, primary_key=True)

    active = db.Column(db.Boolean, nullable=False, default=True, index=True)

    min_sales = db.Column(db.Integer, nullable=False, default=SALES_MIN)
    max_sales = db.Column(db.Integer, nullable=True)

    rate = db.Column(db.Numeric(6, 4), nullable=False, default=DEFAULT_RATE)

    label = db.Column(db.String(120), nullable=True)

    sort_order = db.Column(db.Integer, nullable=False, default=DEFAULT_SORT, index=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
        index=True,
    )

    __table_args__ = (
        CheckConstraint("min_sales >= 1", name="ck_commission_tiers_min_sales_ge_1"),
        CheckConstraint("(max_sales IS NULL) OR (max_sales >= 1)", name="ck_commission_tiers_max_sales_ge_1_or_null"),
        CheckConstraint("(max_sales IS NULL) OR (max_sales >= min_sales)", name="ck_commission_tiers_max_ge_min_or_null"),
        CheckConstraint(f"rate >= {str(RATE_MIN)} AND rate <= {str(RATE_MAX)}", name="ck_commission_tiers_rate_range"),
        UniqueConstraint("min_sales", "max_sales", name="uq_commission_tiers_min_max"),
    )

    @validates("min_sales")
    def _v_min(self, _k: str, v: Any) -> int:
        return _to_int(v, default=SALES_MIN, min_value=SALES_MIN, max_value=SALES_MAX)

    @validates("max_sales")
    def _v_max(self, _k: str, v: Any) -> Optional[int]:
        if v is None or v == "":
            return None
        n = _to_int(v, default=-1, min_value=SALES_MIN, max_value=SALES_MAX)
        return None if n <= 0 else n

    @validates("rate")
    def _v_rate(self, _k: str, v: Any) -> Decimal:
        return _to_rate(v, DEFAULT_RATE)

    @validates("label")
    def _v_label(self, _k: str, v: Any) -> Optional[str]:
        return _normalize_label(v)

    @validates("sort_order")
    def _v_sort(self, _k: str, v: Any) -> int:
        return _to_int(v, default=DEFAULT_SORT, min_value=0, max_value=10_000)

    @property
    def range_label(self) -> str:
        mn = int(self.min_sales or SALES_MIN)
        mx = self.max_sales
        return f"{mn}-{int(mx) if mx is not None else '∞'}"

    @property
    def rate_percent(self) -> Decimal:
        r = self.rate if isinstance(self.rate, Decimal) else _to_rate(self.rate, DEFAULT_RATE)
        r = _to_rate(r, DEFAULT_RATE)
        return (r * Decimal("100")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    def matches(self, sales_count: Any) -> bool:
        if not bool(self.active):
            return False
        sc = _to_int(sales_count, default=0, min_value=0, max_value=SALES_MAX)
        mn = _to_int(self.min_sales, default=SALES_MIN, min_value=SALES_MIN, max_value=SALES_MAX)
        if sc < mn:
            return False
        return True if self.max_sales is None else sc <= int(self.max_sales)

    def to_match(self) -> TierMatch:
        r = self.rate if isinstance(self.rate, Decimal) else _to_rate(self.rate, DEFAULT_RATE)
        r = _to_rate(r, DEFAULT_RATE)
        return TierMatch(
            tier_id=int(self.id),
            min_sales=_to_int(self.min_sales, default=SALES_MIN, min_value=SALES_MIN, max_value=SALES_MAX),
            max_sales=int(self.max_sales) if self.max_sales is not None else None,
            rate=r,
            label=self.label,
        )

    def apply_to_amount(self, amount: Any) -> Decimal:
        s = _s(amount).replace(",", ".")
        try:
            a = Decimal(s) if s else Decimal("0.00")
        except Exception:
            a = Decimal("0.00")
        if a < Decimal("0.00"):
            a = Decimal("0.00")

        r = self.rate if isinstance(self.rate, Decimal) else _to_rate(self.rate, DEFAULT_RATE)
        r = _to_rate(r, DEFAULT_RATE)
        return (a * r).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    def to_dict(self) -> Dict[str, Any]:
        r = self.rate if isinstance(self.rate, Decimal) else _to_rate(self.rate, DEFAULT_RATE)
        r = _to_rate(r, DEFAULT_RATE)
        return {
            "id": int(self.id) if self.id is not None else None,
            "active": bool(self.active),
            "min_sales": int(self.min_sales or SALES_MIN),
            "max_sales": int(self.max_sales) if self.max_sales is not None else None,
            "rate": str(r),
            "rate_percent": str(self.rate_percent),
            "label": self.label,
            "sort_order": int(self.sort_order or DEFAULT_SORT),
            "range_label": self.range_label,
            "created_at": self.created_at.isoformat() if getattr(self, "created_at", None) else None,
            "updated_at": self.updated_at.isoformat() if getattr(self, "updated_at", None) else None,
        }

    def __repr__(self) -> str:
        return f"<CommissionTier id={self.id} active={self.active} range={self.range_label} rate={self.rate} sort={self.sort_order}>"

    @classmethod
    def resolve_for_sales(cls, sales_count: Any, *, session=None) -> Optional["CommissionTier"]:
        sess = session or db.session
        sc = _to_int(sales_count, default=0, min_value=0, max_value=SALES_MAX)

        stmt = (
            select(cls)
            .where(
                cls.active.is_(True),
                cls.min_sales <= sc,
                or_(cls.max_sales.is_(None), cls.max_sales >= sc),
            )
            .order_by(cls.min_sales.desc(), cls.sort_order.asc(), cls.id.asc())
            .limit(1)
        )
        return sess.execute(stmt).scalars().first()

    @classmethod
    def list_active_ordered(cls, *, session=None) -> List["CommissionTier"]:
        sess = session or db.session
        stmt = (
            select(cls)
            .where(cls.active.is_(True))
            .order_by(cls.sort_order.asc(), cls.min_sales.asc(), cls.id.asc())
        )
        return list(sess.execute(stmt).scalars().all())

    @classmethod
    def sanity_check_overlaps(cls, *, session=None) -> Tuple[bool, List[str]]:
        sess = session or db.session
        tiers = cls.list_active_ordered(session=sess)
        issues: List[str] = []

        def end_or_inf(t: "CommissionTier") -> int:
            return int(t.max_sales) if t.max_sales is not None else _INF

        tiers_sorted = sorted(
            tiers,
            key=lambda t: (
                int(t.min_sales or SALES_MIN),
                end_or_inf(t),
                int(t.id or 0),
            ),
        )

        prev: Optional["CommissionTier"] = None
        prev_end: Optional[int] = None

        for t in tiers_sorted:
            start = int(t.min_sales or SALES_MIN)
            end = int(t.max_sales) if t.max_sales is not None else None

            if prev is not None:
                if prev_end is None:
                    issues.append(
                        f"Overlap: tier {prev.id} ({prev.range_label}) es infinito y solapa con {t.id} ({t.range_label})."
                    )
                else:
                    if start <= prev_end:
                        issues.append(
                            f"Overlap: tier {prev.id} ({prev.range_label}) solapa con {t.id} ({t.range_label})."
                        )

            prev = t
            prev_end = end

        return (len(issues) == 0, issues)

    @classmethod
    def validate_integrity(cls, *, session=None) -> None:
        ok, issues = cls.sanity_check_overlaps(session=session)
        if not ok:
            raise ValueError("Commission tiers invalid:\n- " + "\n- ".join(issues))

    @classmethod
    def ensure_default_seed(cls, *, session=None) -> None:
        sess = session or db.session
        try:
            cnt = sess.execute(select(func.count(cls.id))).scalar_one()
            if int(cnt or 0) > 0:
                return

            defaults = [
                cls(active=True, min_sales=1, max_sales=10, rate="10%", label="Bronce", sort_order=10),
                cls(active=True, min_sales=11, max_sales=30, rate="15%", label="Plata", sort_order=20),
                cls(active=True, min_sales=31, max_sales=60, rate="20%", label="Oro", sort_order=30),
                cls(active=True, min_sales=61, max_sales=100, rate="25%", label="Platino", sort_order=40),
                cls(active=True, min_sales=101, max_sales=None, rate="30%", label="Diamante", sort_order=50),
            ]
            sess.add_all(defaults)
            sess.flush()
            sess.commit()
        except Exception:
            sess.rollback()
            raise


Index("ix_commission_tiers_active_sort", CommissionTier.active, CommissionTier.sort_order)
Index("ix_commission_tiers_min_max", CommissionTier.min_sales, CommissionTier.max_sales)
Index("ix_commission_tiers_active_min", CommissionTier.active, CommissionTier.min_sales)
Index("ix_commission_tiers_active_min_max", CommissionTier.active, CommissionTier.min_sales, CommissionTier.max_sales)
Index("ix_commission_tiers_active_min_sort", CommissionTier.active, CommissionTier.min_sales, CommissionTier.sort_order)


def _validate_no_overlap(mapper, connection, target: CommissionTier) -> None:
    if not bool(getattr(target, "active", True)):
        return

    _normalize_target(target)

    a1 = int(target.min_sales)
    a2 = int(target.max_sales) if target.max_sales is not None else None

    ct = CommissionTier.__table__

    cond = and_(
        ct.c.active.is_(True),
        ct.c.id != (int(target.id) if getattr(target, "id", None) is not None else -1),
        or_(a2 is None, ct.c.min_sales <= a2),
        or_(ct.c.max_sales.is_(None), a1 <= ct.c.max_sales),
    )

    row = connection.execute(
        select(ct.c.id, ct.c.min_sales, ct.c.max_sales)
        .where(cond)
        .order_by(ct.c.min_sales.asc(), ct.c.id.asc())
        .limit(1)
    ).first()

    if row:
        b_id, b1, b2 = row
        b_label = f"{b1}-{b2 if b2 is not None else '∞'}"
        a_label = f"{a1}-{a2 if a2 is not None else '∞'}"
        raise ValueError(
            f"CommissionTier overlap: rango nuevo {a_label} solapa con tier existente {b_id} ({b_label}). "
            f"Solución: ajustá min/max o desactivá uno de los tiers."
        )


def _before_save(mapper, connection, target: CommissionTier) -> None:
    _normalize_target(target)
    if bool(getattr(target, "active", True)):
        _validate_no_overlap(mapper, connection, target)


event.listen(CommissionTier, "before_insert", _before_save)
event.listen(CommissionTier, "before_update", _before_save)
