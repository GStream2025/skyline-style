# app/models/commission.py
from __future__ import annotations

"""
Skyline Store — Commission Tiers (ULTRA PRO MAX / FINAL)

✅ 20+ mejoras reales vs tu versión:
1) Tipos y constantes centralizadas + límites configurables
2) Parseo de rate MUY robusto: "10", "10%", "0.10", "0,10", " 15 % ", "10,5%"
3) Soporta admin ingresando 1.5 => 1.5% (heurística segura) y 0.015 => 1.5% (decimal real)
4) Clamp + quantize consistente (4 decimales) con ROUND_HALF_UP
5) Normalización DRY en una sola función (reutilizada por validators + events)
6) Validación de rangos: min>=1, max None o >=min
7) Prevención de solapes SOLO para tiers activos (regla negocio)
8) Mensajes de error claros y accionables
9) Query helpers con select() y session opcional (test friendly)
10) Resolver por ventas con orden estable + deterministic tie-break
11) list_active_ordered estable por sort/min/id
12) sanity_check_overlaps considera “∞” como infinito y detecta cadenas de solapes
13) validate_integrity lanza error con lista formateada
14) ensure_default_seed idempotente, transaccional y con flush previo
15) Método apply_to_amount() para calcular comisión segura en dinero
16) to_dict() listo para JSON/UI/admin sin dependencias
17) Propiedades rate_percent y range_label robustas y consistentes
18) Indexes pro (ya tenías) + uno extra útil (active+min+sort)
19) __repr__ más informativo
20) No rompe en SQLite/Postgres (Numeric(6,4) y DateTime tz)
"""

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


# =============================================================================
# Constants / helpers
# =============================================================================

RATE_MIN = Decimal("0.0000")
RATE_MAX = Decimal("0.8000")  # hard cap: 80%
RATE_Q = Decimal("0.0001")  # 4 decimales
DEFAULT_RATE = Decimal("0.1000")  # 10%
DEFAULT_SORT = 100

# límites de ventas (anti datos locos)
SALES_MIN = 1
SALES_MAX = 1_000_000_000

_INF = 10**18  # para ordenar NULL como infinito en sanity checks


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _to_int(
    v: Any,
    default: int,
    *,
    min_value: Optional[int] = None,
    max_value: Optional[int] = None,
) -> int:
    try:
        # soporta strings con espacios
        n = int(str(v).strip())
    except Exception:
        n = default

    if min_value is not None and n < min_value:
        n = min_value
    if max_value is not None and n > max_value:
        n = max_value
    return n


def _normalize_label(label: Any) -> Optional[str]:
    if label is None:
        return None
    s = str(label).strip()
    return s[:120] if s else None


def _to_decimal(v: Any, default: Decimal) -> Decimal:
    """
    Parse robusto de comisión:
      - Decimal / int / float / str
      - "0.10", "10", "10%", " 15 % ", "0,10", "10,5%"
    Reglas seguras:
      - "10"  => 10%   => 0.10
      - "10%" => 10%   => 0.10
      - "0.10" => 0.10 (10%)
      - "0,10" => 0.10
      - "1.5" => 1.5%  => 0.015   (heurística: 0 < x < 1 => decimal real, 1..80 => porcentaje)
    """
    if v is None or v == "":
        return default

    if isinstance(v, Decimal):
        return v

    if isinstance(v, (int, float)):
        try:
            return Decimal(str(v))
        except Exception:
            return default

    s = str(v).strip()
    if not s:
        return default

    # normaliza espacios y coma decimal
    s = s.replace(" ", "")
    s = s.replace(",", ".")

    try:
        if s.endswith("%"):
            raw = s[:-1]
            d = Decimal(raw)
            return d / Decimal("100")

        d = Decimal(s)

        # Heurística:
        # - si d >= 1 => interpretamos porcentaje entero/real (10 => 10%, 1.5 => 1.5%)
        # - si 0 < d < 1 => ya es decimal (0.15 => 15%)
        if d >= Decimal("1.0"):
            return d / Decimal("100")
        return d
    except (InvalidOperation, ValueError, TypeError):
        return default


def _clamp_rate(r: Decimal) -> Decimal:
    if r < RATE_MIN:
        r = RATE_MIN
    if r > RATE_MAX:
        r = RATE_MAX
    return r.quantize(RATE_Q, rounding=ROUND_HALF_UP)


def _normalize_target(target: "CommissionTier") -> None:
    """
    Normaliza campos del target (sin depender de session).
    Usado por validators y events para evitar duplicación.
    """
    target.min_sales = _to_int(
        getattr(target, "min_sales", SALES_MIN) or SALES_MIN,
        SALES_MIN,
        min_value=SALES_MIN,
        max_value=SALES_MAX,
    )

    mx = getattr(target, "max_sales", None)
    if mx is None or mx == "":
        mx = None
    else:
        try:
            mx = _to_int(mx, default=-1, min_value=SALES_MIN, max_value=SALES_MAX)
        except Exception:
            mx = None
        if mx is not None and mx <= 0:
            mx = None

    # si max existe y quedó por debajo, lo alineamos a min (evita inserts inválidos)
    if mx is not None and int(mx) < int(target.min_sales):
        mx = int(target.min_sales)

    target.max_sales = int(mx) if mx is not None else None
    target.rate = _clamp_rate(
        _to_decimal(getattr(target, "rate", DEFAULT_RATE), DEFAULT_RATE)
    )
    target.label = _normalize_label(getattr(target, "label", None))
    target.sort_order = _to_int(
        getattr(target, "sort_order", DEFAULT_SORT),
        DEFAULT_SORT,
        min_value=0,
        max_value=10_000,
    )


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
    max_sales = db.Column(db.Integer, nullable=True)  # None = infinito

    rate = db.Column(db.Numeric(6, 4), nullable=False, default=DEFAULT_RATE)

    label = db.Column(db.String(120), nullable=True)

    sort_order = db.Column(db.Integer, nullable=False, default=DEFAULT_SORT, index=True)

    created_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
        index=True,
    )

    __table_args__ = (
        CheckConstraint("min_sales >= 1", name="ck_commission_tiers_min_sales_ge_1"),
        CheckConstraint(
            "(max_sales IS NULL) OR (max_sales >= 1)",
            name="ck_commission_tiers_max_sales_ge_1_or_null",
        ),
        CheckConstraint(
            "(max_sales IS NULL) OR (max_sales >= min_sales)",
            name="ck_commission_tiers_max_ge_min_or_null",
        ),
        CheckConstraint(
            f"rate >= {str(RATE_MIN)} AND rate <= {str(RATE_MAX)}",
            name="ck_commission_tiers_rate_range",
        ),
        UniqueConstraint("min_sales", "max_sales", name="uq_commission_tiers_min_max"),
    )

    # -------------------------------------------------------------------------
    # Validations (ORM) — delegan en normalizadores pro
    # -------------------------------------------------------------------------

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
        return _clamp_rate(_to_decimal(v, DEFAULT_RATE))

    @validates("label")
    def _v_label(self, _k: str, v: Any) -> Optional[str]:
        return _normalize_label(v)

    @validates("sort_order")
    def _v_sort(self, _k: str, v: Any) -> int:
        return _to_int(v, default=DEFAULT_SORT, min_value=0, max_value=10_000)

    # -------------------------------------------------------------------------
    # Business logic
    # -------------------------------------------------------------------------

    @property
    def range_label(self) -> str:
        mn = int(self.min_sales or SALES_MIN)
        mx = self.max_sales
        return f"{mn}-{int(mx) if mx is not None else '∞'}"

    @property
    def rate_percent(self) -> Decimal:
        """
        Ej: rate=0.1500 => 15.00
        Útil para UI/Admin.
        """
        r = (
            self.rate
            if isinstance(self.rate, Decimal)
            else _to_decimal(self.rate, DEFAULT_RATE)
        )
        r = _clamp_rate(r)
        return (r * Decimal("100")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    def matches(self, sales_count: Any) -> bool:
        if not bool(self.active):
            return False

        sc = _to_int(sales_count, default=0, min_value=0, max_value=SALES_MAX)
        mn = _to_int(
            self.min_sales, default=SALES_MIN, min_value=SALES_MIN, max_value=SALES_MAX
        )
        if sc < mn:
            return False

        mx = self.max_sales
        return True if mx is None else sc <= int(mx)

    def to_match(self) -> TierMatch:
        r = (
            self.rate
            if isinstance(self.rate, Decimal)
            else _to_decimal(self.rate, DEFAULT_RATE)
        )
        r = _clamp_rate(r)
        return TierMatch(
            tier_id=int(self.id),
            min_sales=_to_int(
                self.min_sales,
                default=SALES_MIN,
                min_value=SALES_MIN,
                max_value=SALES_MAX,
            ),
            max_sales=int(self.max_sales) if self.max_sales is not None else None,
            rate=r,
            label=self.label,
        )

    def apply_to_amount(self, amount: Any) -> Decimal:
        """
        Calcula comisión en dinero:
          comisión = amount * rate
        - normaliza amount a Decimal no-negativo
        - redondea a 2 decimales (money) HALF_UP
        """
        try:
            a = Decimal(str(amount).replace(",", ".").strip())
        except Exception:
            a = Decimal("0.00")
        if a < Decimal("0.00"):
            a = Decimal("0.00")

        r = (
            self.rate
            if isinstance(self.rate, Decimal)
            else _to_decimal(self.rate, DEFAULT_RATE)
        )
        r = _clamp_rate(r)

        return (a * r).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": int(self.id) if self.id is not None else None,
            "active": bool(self.active),
            "min_sales": int(self.min_sales or SALES_MIN),
            "max_sales": int(self.max_sales) if self.max_sales is not None else None,
            "rate": str(_clamp_rate(_to_decimal(self.rate, DEFAULT_RATE))),
            "rate_percent": str(self.rate_percent),
            "label": self.label,
            "sort_order": int(self.sort_order or DEFAULT_SORT),
            "range_label": self.range_label,
            "created_at": (
                self.created_at.isoformat()
                if getattr(self, "created_at", None)
                else None
            ),
            "updated_at": (
                self.updated_at.isoformat()
                if getattr(self, "updated_at", None)
                else None
            ),
        }

    def __repr__(self) -> str:
        return (
            f"<CommissionTier id={self.id} active={self.active} range={self.range_label} "
            f"rate={self.rate} sort={self.sort_order}>"
        )

    # -------------------------------------------------------------------------
    # Query helpers
    # -------------------------------------------------------------------------

    @classmethod
    def resolve_for_sales(
        cls, sales_count: Any, *, session=None
    ) -> Optional["CommissionTier"]:
        """
        Devuelve el tier activo que matchea sales_count.
        Orden determinista:
          - min_sales desc (el más específico)
          - sort_order asc
          - id asc
        """
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
        """
        Detecta solapes entre tiers activos (para UI de admin).
        """
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
        """
        Valida que los tiers activos no estén solapados.
        Lanza ValueError si hay problemas.
        """
        ok, issues = cls.sanity_check_overlaps(session=session)
        if not ok:
            raise ValueError("Commission tiers invalid:\n- " + "\n- ".join(issues))

    @classmethod
    def ensure_default_seed(cls, *, session=None) -> None:
        """
        Crea tiers default si la tabla está vacía.
        Idempotente y con rollback seguro.
        """
        sess = session or db.session
        try:
            cnt = sess.execute(select(func.count(cls.id))).scalar_one()
            if int(cnt or 0) > 0:
                return

            defaults = [
                cls(
                    active=True,
                    min_sales=1,
                    max_sales=10,
                    rate="10%",
                    label="Bronce",
                    sort_order=10,
                ),
                cls(
                    active=True,
                    min_sales=11,
                    max_sales=30,
                    rate="15%",
                    label="Plata",
                    sort_order=20,
                ),
                cls(
                    active=True,
                    min_sales=31,
                    max_sales=60,
                    rate="20%",
                    label="Oro",
                    sort_order=30,
                ),
                cls(
                    active=True,
                    min_sales=61,
                    max_sales=100,
                    rate="25%",
                    label="Platino",
                    sort_order=40,
                ),
                cls(
                    active=True,
                    min_sales=101,
                    max_sales=None,
                    rate="30%",
                    label="Diamante",
                    sort_order=50,
                ),
            ]
            sess.add_all(defaults)
            # flush antes de commit = detecta constraints y overlap event
            sess.flush()
            sess.commit()
        except Exception:
            sess.rollback()
            raise


# =============================================================================
# Indexes
# =============================================================================

Index(
    "ix_commission_tiers_active_sort", CommissionTier.active, CommissionTier.sort_order
)
Index("ix_commission_tiers_min_max", CommissionTier.min_sales, CommissionTier.max_sales)
Index("ix_commission_tiers_active_min", CommissionTier.active, CommissionTier.min_sales)
Index(
    "ix_commission_tiers_active_min_max",
    CommissionTier.active,
    CommissionTier.min_sales,
    CommissionTier.max_sales,
)
Index(
    "ix_commission_tiers_active_min_sort",
    CommissionTier.active,
    CommissionTier.min_sales,
    CommissionTier.sort_order,
)


# =============================================================================
# Events: prevent overlaps for ACTIVE tiers
# =============================================================================


def _validate_no_overlap(mapper, connection, target: CommissionTier) -> None:
    """
    Previene tiers ACTIVOS solapados (regla negocio).
    """
    if not bool(getattr(target, "active", True)):
        return

    _normalize_target(target)

    a1 = int(target.min_sales)
    a2 = int(target.max_sales) if target.max_sales is not None else None

    ct = CommissionTier.__table__

    # solape si:
    #  existing.min_sales <= new.max_sales (o new infinito)
    #  y existing.max_sales >= new.min_sales (o existing infinito)
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


event.listen(CommissionTier, "before_insert", _validate_no_overlap)
event.listen(CommissionTier, "before_update", _validate_no_overlap)
