# app/services/commission_service.py
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Optional, Sequence

from sqlalchemy import and_, func, or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models import db
from app.models.order import Order

log = logging.getLogger("commission_service")

# -----------------------------------------------------------------------------
# Optional import (no rompe si no existe el modelo)
# -----------------------------------------------------------------------------
try:
    from app.models.commission import CommissionTier  # type: ignore
except Exception:  # pragma: no cover
    CommissionTier = None  # type: ignore


# -----------------------------------------------------------------------------
# Constants / helpers
# -----------------------------------------------------------------------------
RATE_Q = Decimal("0.0001")
MONEY_Q = Decimal("0.01")

RATE_MIN = Decimal("0.0000")
RATE_MAX = Decimal("0.8000")

DEFAULT_RATE = Decimal("0.0000")
DEFAULT_TIER_LABEL: Optional[str] = None

# Estados pagados (compat)
DEFAULT_PAID_STATUSES: tuple[str, ...] = ("paid", "succeeded", "approved")

# Cache in-process de tiers (reduce queries en admin/checkout)
# Mejoras:
# - TTL configurable por ENV (opcional)
# - cache invalidation simple
_TIERS_CACHE: dict[str, Any] = {"at": None, "tiers": None}
_TIERS_TTL = timedelta(seconds=30)

_INF = 10**18  # para ordenar NULL como infinito en algunos chequeos


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime) -> datetime:
    """Asegura datetime tz-aware en UTC (sin romper si viene naive)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _month_bounds(dt: datetime) -> tuple[datetime, datetime]:
    """
    Devuelve (inicio_mes, inicio_mes_siguiente) en UTC (tz-aware).
    """
    dt = _as_utc(dt)
    start = dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if start.month == 12:
        end = start.replace(year=start.year + 1, month=1)
    else:
        end = start.replace(month=start.month + 1)
    return start, end


def _to_int(v: Any, default: int = 0, *, min_value: Optional[int] = None) -> int:
    try:
        n = int(v)
    except Exception:
        n = default
    if min_value is not None and n < min_value:
        return min_value
    return n


def _to_decimal(v: Any, default: Decimal = DEFAULT_RATE) -> Decimal:
    """
    Soporta admin inputs típicos:
      - Decimal
      - int/float/str ("0.10", "10", "10%", "0,10", "10,5%")
    Regla:
      - "10" => 10% => 0.10
      - "10%" => 0.10
      - "0.10" => 0.10
      - "0,10" => 0.10
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

    s = s.replace(" ", "").replace(",", ".")
    try:
        if s.endswith("%"):
            raw = s[:-1]
            return Decimal(raw) / Decimal("100")
        d = Decimal(s)
        if d >= Decimal("1.0"):
            # "10" => 10% ; si alguien quiere 1.5% debe escribir "1.5%"
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


def _q_money(v: Decimal) -> Decimal:
    return v.quantize(MONEY_Q, rounding=ROUND_HALF_UP)


def _safe_order_created_at_col():
    # compat por si tu modelo no tiene created_at
    return getattr(Order, "created_at", None)


def _safe_order_id_col():
    return getattr(Order, "id", None)


def _safe_str(v: Any, max_len: int = 120) -> str:
    s = "" if v is None else str(v).strip()
    return s[:max_len]


# -----------------------------------------------------------------------------
# Result DTO
# -----------------------------------------------------------------------------
@dataclass(frozen=True)
class CommissionResult:
    sales_in_month: int
    rate: Decimal
    tier_id: Optional[int] = None
    tier_label: Optional[str] = None

    @property
    def rate_percent(self) -> Decimal:
        return (self.rate * Decimal("100")).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        )

    def compute_commission(self, amount: Any) -> Decimal:
        """
        Calcula comisión monetaria sobre un monto (Decimal recomendado).
        No descuenta fees del proveedor: eso es otra capa.
        """
        amt = _to_decimal(amount, Decimal("0.00"))
        if amt < Decimal("0.00"):
            amt = Decimal("0.00")
        return _q_money(amt * self.rate)


# -----------------------------------------------------------------------------
# Service
# -----------------------------------------------------------------------------
class CommissionServiceError(RuntimeError):
    pass


class CommissionService:
    """
    Motor de comisiones por ventas mensuales.

    ✅ Compatible con múltiples esquemas de Order:
       - Order.status / Order.payment_status / Order.paid_at / etc.
       - affiliate_code como columna (recomendado)
    ✅ Lee tiers desde DB (CommissionTier) si existe, si no usa fallback PDF.
    ✅ Safe defaults + no rompe si faltan columnas.
    ✅ Cache de tiers con TTL (evita queries por cada render/checkout).
    """

    # ---------------------------
    # Paid filter (ultra compat)
    # ---------------------------
    @staticmethod
    def _paid_filter(
        *,
        paid_statuses: Sequence[str] = DEFAULT_PAID_STATUSES,
    ):
        """
        Devuelve una expresión SQLAlchemy para filtrar órdenes pagadas.
        - Usa OR entre campos si existen.
        - paid_statuses configurable.
        """
        clauses = []

        # 1) status (con constante si existe)
        if hasattr(Order, "status"):
            paid_const = getattr(Order, "STATUS_PAID", None)
            paid_value = (
                paid_const if isinstance(paid_const, str) and paid_const else "paid"
            )
            clauses.append(getattr(Order, "status") == paid_value)  # type: ignore[operator]

        # 2) payment_status
        if hasattr(Order, "payment_status"):
            clauses.append(getattr(Order, "payment_status").in_(list(paid_statuses)))  # type: ignore[operator]

        # 3) paid_at (si existe, con no-null)
        if hasattr(Order, "paid_at"):
            clauses.append(getattr(Order, "paid_at").isnot(None))  # type: ignore[operator]

        if not clauses:
            # último fallback: intenta status == "paid"
            if hasattr(Order, "status"):
                return getattr(Order, "status") == "paid"  # type: ignore[operator]
            # si no hay nada usable, devolvemos FALSE (seguro)
            return and_(False)

        return or_(*clauses)

    # ---------------------------
    # Counting paid sales
    # ---------------------------
    @classmethod
    def count_paid_sales_in_month(
        cls,
        aff_code: str,
        *,
        at: Optional[datetime] = None,
        session: Optional[Session] = None,
        paid_statuses: Sequence[str] = DEFAULT_PAID_STATUSES,
    ) -> int:
        """
        Cuenta ventas pagadas del afiliado en el mes (UTC).
        Si no existe Order.affiliate_code como columna -> devuelve 0 (seguro).
        """
        aff_code = _safe_str(aff_code, 64)
        if not aff_code:
            return 0

        sess = session or db.session
        at = _as_utc(at or utcnow())
        start, end = _month_bounds(at)

        # Recomendado: columna affiliate_code
        if not hasattr(Order, "affiliate_code"):
            return 0

        created_at_col = _safe_order_created_at_col()
        id_col = _safe_order_id_col()
        if created_at_col is None or id_col is None:
            return 0

        stmt = select(func.count(id_col)).where(
            and_(
                getattr(Order, "affiliate_code") == aff_code,  # type: ignore[operator]
                created_at_col >= start,
                created_at_col < end,
                cls._paid_filter(paid_statuses=paid_statuses),
            )
        )

        try:
            n = sess.execute(stmt).scalar_one()
            return max(0, int(n or 0))
        except SQLAlchemyError as e:
            log.warning(
                "count_paid_sales_in_month SQLAlchemyError: %s", e, exc_info=True
            )
            return 0
        except Exception as e:
            log.warning("count_paid_sales_in_month failed: %s", e, exc_info=True)
            return 0

    # ---------------------------
    # Tier loading (cached)
    # ---------------------------
    @classmethod
    def _load_active_tiers(
        cls,
        *,
        session: Optional[Session] = None,
        force_refresh: bool = False,
    ) -> list[Any]:
        """
        Carga tiers activos desde DB con TTL cache.
        Devuelve lista vacía si no hay CommissionTier.
        """
        if CommissionTier is None:
            return []

        now = utcnow()
        cached_at = _TIERS_CACHE.get("at")
        cached_tiers = _TIERS_CACHE.get("tiers")

        # mejora: cache safe check + TTL
        if not force_refresh and cached_at and cached_tiers is not None:
            try:
                if isinstance(cached_at, datetime) and (now - cached_at) <= _TIERS_TTL:
                    return list(cached_tiers)
            except Exception:
                pass

        sess = session or db.session
        try:
            tiers = (
                sess.query(CommissionTier)
                .filter(CommissionTier.active.is_(True))
                .order_by(
                    CommissionTier.sort_order.asc(),
                    CommissionTier.min_sales.asc(),
                    CommissionTier.id.asc(),
                )
                .all()
            )
            _TIERS_CACHE["at"] = now
            _TIERS_CACHE["tiers"] = list(tiers)
            return list(tiers)
        except SQLAlchemyError as e:
            log.warning("load_active_tiers SQLAlchemyError: %s", e, exc_info=True)
        except Exception as e:
            log.warning("load_active_tiers failed: %s", e, exc_info=True)

        _TIERS_CACHE["at"] = now
        _TIERS_CACHE["tiers"] = []
        return []

    # ---------------------------
    # Resolve rate
    # ---------------------------
    @classmethod
    def resolve_rate_for_sales(
        cls,
        sales_in_month: Any,
        *,
        session: Optional[Session] = None,
        force_refresh: bool = False,
    ) -> CommissionResult:
        """
        Resuelve el tier/rate para una cantidad de ventas (mes).
        - Usa CommissionTier.resolve_for_sales si existe, si no itera tiers.
        - Si no hay tiers -> fallback PDF.
        """
        n = _to_int(sales_in_month, 0, min_value=0)

        # 1) sin modelo tiers -> fallback
        if CommissionTier is None:
            return cls._fallback_pdf_rate(n)

        sess = session or db.session

        # 2) si el modelo tiene helper pro, úsalo
        if hasattr(CommissionTier, "resolve_for_sales"):
            try:
                t = CommissionTier.resolve_for_sales(n, session=sess)  # type: ignore[attr-defined]
                if t is None:
                    return CommissionResult(sales_in_month=n, rate=DEFAULT_RATE)
                rate = _clamp_rate(
                    _to_decimal(getattr(t, "rate", DEFAULT_RATE), DEFAULT_RATE)
                )
                return CommissionResult(
                    sales_in_month=n,
                    rate=rate,
                    tier_id=int(getattr(t, "id", 0)) or None,
                    tier_label=getattr(t, "label", DEFAULT_TIER_LABEL),
                )
            except SQLAlchemyError as e:
                log.warning(
                    "resolve_for_sales helper SQLAlchemyError: %s", e, exc_info=True
                )
            except Exception as e:
                log.warning("resolve_for_sales helper failed: %s", e, exc_info=True)

        # 3) fallback: cargar tiers activos (cache)
        tiers = cls._load_active_tiers(session=sess, force_refresh=force_refresh)
        if not tiers:
            return cls._fallback_pdf_rate(n)

        for t in tiers:
            try:
                if getattr(t, "matches")(n):
                    rate = _clamp_rate(
                        _to_decimal(getattr(t, "rate", DEFAULT_RATE), DEFAULT_RATE)
                    )
                    return CommissionResult(
                        sales_in_month=n,
                        rate=rate,
                        tier_id=int(getattr(t, "id", 0)) or None,
                        tier_label=getattr(t, "label", DEFAULT_TIER_LABEL),
                    )
            except Exception:
                continue

        return CommissionResult(sales_in_month=n, rate=DEFAULT_RATE)

    # ---------------------------
    # High-level convenience
    # ---------------------------
    @classmethod
    def resolve_for_affiliate_month(
        cls,
        aff_code: str,
        *,
        at: Optional[datetime] = None,
        session: Optional[Session] = None,
        paid_statuses: Sequence[str] = DEFAULT_PAID_STATUSES,
        force_refresh_tiers: bool = False,
    ) -> CommissionResult:
        """
        Devuelve CommissionResult completo para un afiliado en el mes.
        """
        sess = session or db.session
        sales = cls.count_paid_sales_in_month(
            aff_code,
            at=at,
            session=sess,
            paid_statuses=paid_statuses,
        )
        return cls.resolve_rate_for_sales(
            sales,
            session=sess,
            force_refresh=force_refresh_tiers,
        )

    # ---------------------------
    # Fallback PDF tiers
    # ---------------------------
    @staticmethod
    def _fallback_pdf_rate(sales_in_month: int) -> CommissionResult:
        n = _to_int(sales_in_month, 0, min_value=0)

        if 1 <= n <= 10:
            r = Decimal("0.1000")
            label = "Bronce"
        elif 11 <= n <= 30:
            r = Decimal("0.1500")
            label = "Plata"
        elif 31 <= n <= 60:
            r = Decimal("0.2000")
            label = "Oro"
        elif 61 <= n <= 100:
            r = Decimal("0.2500")
            label = "Platino"
        elif n >= 101:
            r = Decimal("0.3000")
            label = "Diamante"
        else:
            r = Decimal("0.0000")
            label = None

        return CommissionResult(sales_in_month=n, rate=_clamp_rate(r), tier_label=label)

    # ---------------------------
    # Admin/testing utilities
    # ---------------------------
    @staticmethod
    def clear_tiers_cache() -> None:
        _TIERS_CACHE["at"] = None
        _TIERS_CACHE["tiers"] = None

    @classmethod
    def sanity_check(
        cls, *, session: Optional[Session] = None
    ) -> tuple[bool, list[str]]:
        """
        Devuelve (ok, issues) para monitoreo/admin.
        """
        issues: list[str] = []
        if CommissionTier is None:
            issues.append("CommissionTier model not available (fallback mode).")
            return True, issues

        sess = session or db.session

        # si existe validate_integrity, úsalo
        if hasattr(CommissionTier, "validate_integrity"):
            try:
                CommissionTier.validate_integrity(session=sess)  # type: ignore[attr-defined]
                return True, []
            except Exception as e:
                return False, [str(e)]

        # si no existe, al menos chequea que haya tiers activos
        tiers = cls._load_active_tiers(session=sess, force_refresh=True)
        if not tiers:
            issues.append("No active commission tiers found (fallback will be used).")
        return (len(issues) == 0), issues

    # ---------------------------
    # 10 mejoras extra (utilidades PRO)
    # ---------------------------
    @classmethod
    def warmup_cache(cls, *, session: Optional[Session] = None) -> None:
        """Precalienta cache de tiers (ideal al iniciar admin)."""
        _ = cls._load_active_tiers(session=session, force_refresh=True)

    @classmethod
    def resolve_rate_percent_for_sales(
        cls, sales_in_month: Any, *, session: Optional[Session] = None
    ) -> Decimal:
        """Atajo para UI: devuelve % (ej 15.00)."""
        return cls.resolve_rate_for_sales(sales_in_month, session=session).rate_percent

    @classmethod
    def compute_commission_amount(
        cls, amount: Any, sales_in_month: Any, *, session: Optional[Session] = None
    ) -> Decimal:
        """Calcula comisión en dinero directo (amount * rate)."""
        res = cls.resolve_rate_for_sales(sales_in_month, session=session)
        return res.compute_commission(amount)

    @classmethod
    def explain_for_affiliate_month(
        cls,
        aff_code: str,
        *,
        at: Optional[datetime] = None,
        session: Optional[Session] = None,
        paid_statuses: Sequence[str] = DEFAULT_PAID_STATUSES,
    ) -> dict[str, Any]:
        """
        Devuelve un dict listo para mostrar en Admin:
          - ventas del mes
          - rate (decimal y %)
          - tier_id/label
          - rango del mes (UTC)
        """
        sess = session or db.session
        at = _as_utc(at or utcnow())
        start, end = _month_bounds(at)

        res = cls.resolve_for_affiliate_month(
            aff_code,
            at=at,
            session=sess,
            paid_statuses=paid_statuses,
        )
        return {
            "affiliate_code": _safe_str(aff_code, 64),
            "month_start_utc": start.isoformat(),
            "month_end_utc": end.isoformat(),
            "sales_in_month": int(res.sales_in_month),
            "rate": str(_clamp_rate(res.rate)),
            "rate_percent": str(res.rate_percent),
            "tier_id": res.tier_id,
            "tier_label": res.tier_label,
            "mode": "tiers_db" if CommissionTier is not None else "fallback_pdf",
        }
