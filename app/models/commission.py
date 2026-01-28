from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Dict, List, Optional, Sequence, Tuple

from sqlalchemy import CheckConstraint, Index, UniqueConstraint, and_, event, func, or_, select
from sqlalchemy.orm import validates

from app.models import db


RATE_MIN = Decimal("0.0000")
RATE_MAX = Decimal("0.8000")
RATE_Q = Decimal("0.0001")
DEFAULT_RATE = Decimal("0.1000")

DEFAULT_SORT = 100
SORT_MIN = 0
SORT_MAX = 10_000

SALES_MIN = 1
SALES_MAX = 1_000_000_000
_AMT_Q = Decimal("0.01")
_INF = 10**18


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _to_str(v: Any) -> str:
    if v is None:
        return ""
    s = str(v).replace("\x00", "").replace("\u200b", "").strip()
    return " ".join(s.split())


def _to_int(
    v: Any,
    default: int,
    *,
    min_value: Optional[int] = None,
    max_value: Optional[int] = None,
) -> int:
    s = _to_str(v)
    try:
        n = int(s) if s else int(default)
    except Exception:
        n = int(default)

    if min_value is not None and n < min_value:
        n = min_value
    if max_value is not None and n > max_value:
        n = max_value
    return n


def _to_decimal(v: Any) -> Optional[Decimal]:
    if v is None or v == "":
        return None
    if isinstance(v, Decimal):
        return v
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return Decimal(v)
    if isinstance(v, float):
        try:
            return Decimal(str(v))
        except Exception:
            return None

    s = _to_str(v)
    if not s:
        return None
    s = s.replace(" ", "").replace(",", ".")
    try:
        return Decimal(s)
    except (InvalidOperation, ValueError, TypeError):
        return None


def _q_rate(d: Decimal) -> Decimal:
    if d.is_nan() or d.is_infinite():
        d = DEFAULT_RATE
    if d < RATE_MIN:
        d = RATE_MIN
    if d > RATE_MAX:
        d = RATE_MAX
    return d.quantize(RATE_Q, rounding=ROUND_HALF_UP)


def _to_rate(v: Any, default: Decimal = DEFAULT_RATE) -> Decimal:
    if v is None or v == "":
        return _q_rate(default)

    if isinstance(v, Decimal):
        return _q_rate(v)

    s = _to_str(v).replace(" ", "")
    if not s:
        return _q_rate(default)

    s2 = s.replace(",", ".")
    try:
        if s2.endswith("%"):
            d = _to_decimal(s2[:-1])
            if d is None:
                return _q_rate(default)
            return _q_rate(d / Decimal("100"))

        d = _to_decimal(s2)
        if d is None:
            return _q_rate(default)

        if d >= Decimal("1"):
            return _q_rate(d / Decimal("100"))
        return _q_rate(d)
    except Exception:
        return _q_rate(default)


def _normalize_label(v: Any, *, max_len: int = 120) -> Optional[str]:
    s = _to_str(v)
    if not s:
        return None
    return s[:max_len]


def _q_money(d: Decimal) -> Decimal:
    if d.is_nan() or d.is_infinite() or d < Decimal("0.00"):
        d = Decimal("0.00")
    return d.quantize(_AMT_Q, rounding=ROUND_HALF_UP)


def _money(v: Any) -> Decimal:
    d = _to_decimal(v)
    return _q_money(d if d is not None else Decimal("0.00"))


def _end_or_inf(mx: Optional[int]) -> int:
    return int(mx) if mx is not None else _INF


def _normalize_target(t: "CommissionTier") -> None:
    t.min_sales = _to_int(getattr(t, "min_sales", SALES_MIN), SALES_MIN, min_value=SALES_MIN, max_value=SALES_MAX)

    mx_raw = getattr(t, "max_sales", None)
    if mx_raw is None or mx_raw == "":
        t.max_sales = None
    else:
        mx = _to_int(mx_raw, default=-1, min_value=SALES_MIN, max_value=SALES_MAX)
        t.max_sales = None if mx <= 0 else mx

    if t.max_sales is not None and int(t.max_sales) < int(t.min_sales):
        t.max_sales = int(t.min_sales)

    t.rate = _to_rate(getattr(t, "rate", DEFAULT_RATE), DEFAULT_RATE)
    t.label = _normalize_label(getattr(t, "label", None))
    t.sort_order = _to_int(
        getattr(t, "sort_order", DEFAULT_SORT),
        DEFAULT_SORT,
        min_value=SORT_MIN,
        max_value=SORT_MAX,
    )

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
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow, index=True)

    __table_args__ = (
        CheckConstraint("min_sales >= 1", name="ck_commission_tiers_min_sales_ge_1"),
        CheckConstraint("(max_sales IS NULL) OR (max_sales >= 1)", name="ck_commission_tiers_max_sales_ge_1_or_null"),
        CheckConstraint("(max_sales IS NULL) OR (max_sales >= min_sales)", name="ck_commission_tiers_max_ge_min_or_null"),
        CheckConstraint(f"rate >= {str(RATE_MIN)} AND rate <= {str(RATE_MAX)}", name="ck_commission_tiers_rate_range"),
        UniqueConstraint("min_sales", "max_sales", name="uq_commission_tiers_min_max"),
        Index("ix_commission_tiers_active_sort", "active", "sort_order"),
        Index("ix_commission_tiers_min_max", "min_sales", "max_sales"),
        Index("ix_commission_tiers_active_min", "active", "min_sales"),
        Index("ix_commission_tiers_active_min_max", "active", "min_sales", "max_sales"),
        Index("ix_commission_tiers_active_min_sort", "active", "min_sales", "sort_order"),
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
        return _to_int(v, default=DEFAULT_SORT, min_value=SORT_MIN, max_value=SORT_MAX)

    @property
    def range_label(self) -> str:
        mn = int(self.min_sales or SALES_MIN)
        mx = self.max_sales
        return f"{mn}-{int(mx) if mx is not None else '∞'}"

    @property
    def rate_percent(self) -> Decimal:
        r = _to_rate(self.rate, DEFAULT_RATE)
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
        r = _to_rate(self.rate, DEFAULT_RATE)
        return TierMatch(
            tier_id=int(self.id or 0),
            min_sales=_to_int(self.min_sales, default=SALES_MIN, min_value=SALES_MIN, max_value=SALES_MAX),
            max_sales=int(self.max_sales) if self.max_sales is not None else None,
            rate=r,
            label=self.label,
        )

    def apply_to_amount(self, amount: Any) -> Decimal:
        a = _money(amount)
        r = _to_rate(self.rate, DEFAULT_RATE)
        return _q_money(a * r)

    def to_dict(self) -> Dict[str, Any]:
        r = _to_rate(self.rate, DEFAULT_RATE)
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
        return (
            f"<CommissionTier id={self.id} active={self.active} "
            f"range={self.range_label} rate={self.rate} sort={self.sort_order}>"
        )

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
        stmt = select(cls).where(cls.active.is_(True)).order_by(cls.sort_order.asc(), cls.min_sales.asc(), cls.id.asc())
        return list(sess.execute(stmt).scalars().all())

    @classmethod
    def sanity_check_overlaps(cls, *, session=None) -> Tuple[bool, List[str]]:
        sess = session or db.session
        tiers = cls.list_active_ordered(session=sess)
        issues: List[str] = []

        tiers_sorted = sorted(
            tiers,
            key=lambda t: (int(t.min_sales or SALES_MIN), _end_or_inf(t.max_sales), int(t.id or 0)),
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

            defaults: Sequence["CommissionTier"] = [
                cls(active=True, min_sales=1, max_sales=10, rate="10%", label="Bronce", sort_order=10),
                cls(active=True, min_sales=11, max_sales=30, rate="15%", label="Plata", sort_order=20),
                cls(active=True, min_sales=31, max_sales=60, rate="20%", label="Oro", sort_order=30),
                cls(active=True, min_sales=61, max_sales=100, rate="25%", label="Platino", sort_order=40),
                cls(active=True, min_sales=101, max_sales=None, rate="30%", label="Diamante", sort_order=50),
            ]
            sess.add_all(list(defaults))
            sess.flush()
            sess.commit()
        except Exception:
            sess.rollback()
            raise


def _validate_no_overlap(_mapper, connection, target: CommissionTier) -> None:
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

    row = (
        connection.execute(
            select(ct.c.id, ct.c.min_sales, ct.c.max_sales)
            .where(cond)
            .order_by(ct.c.min_sales.asc(), ct.c.id.asc())
            .limit(1)
        )
        .first()
    )

    if row:
        b_id, b1, b2 = row
        b_label = f"{int(b1)}-{int(b2) if b2 is not None else '∞'}"
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

__all__ = ["CommissionTier", "TierMatch", "utcnow"]
