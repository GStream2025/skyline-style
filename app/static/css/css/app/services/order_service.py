from __future__ import annotations

"""
Skyline Store — Order Service (ULTRA PRO MAX / FINAL)
====================================================
CEREBRO ÚNICO de órdenes y pagos.

✅ Seguro (validaciones + clamps + estados)
✅ Idempotente (pago + creación si existe columna/soporte)
✅ Concurrency-safe (locks al reservar stock)
✅ Compatible con MercadoPago UY/AR, PayPal, Wise (provider agnóstico)
✅ Listo para producción real (transacciones, retries, logs, tolerancias)
"""

import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Dict, Iterable, Optional, Sequence

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.models import db
from app.models.order import Order, OrderItem
from app.models.product import Product

log = logging.getLogger("order_service")


# =============================================================================
# Errors
# =============================================================================


class OrderServiceError(RuntimeError): ...


class OutOfStockError(OrderServiceError): ...


class InvalidStateError(OrderServiceError): ...


class PaymentMismatchError(OrderServiceError): ...


class DuplicatePaymentError(OrderServiceError): ...


class InvalidInputError(OrderServiceError): ...


# =============================================================================
# Helpers
# =============================================================================

MONEY_Q = Decimal("0.01")
MONEY_TOL = Decimal("0.05")  # tolerancia por redondeos

_ALLOWED_PM = {
    getattr(Order, "PM_PAYPAL", "paypal"),
    getattr(Order, "PM_MERCADOPAGO", "mercadopago"),
    getattr(Order, "PM_WISE", "wise"),
    getattr(Order, "PM_BANK_TRANSFER", "bank_transfer"),
}
_DEFAULT_PM = getattr(Order, "PM_PAYPAL", "paypal")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _d(v: Any, default: str = "0.00") -> Decimal:
    try:
        if v is None or v == "":
            return Decimal(default)
        if isinstance(v, Decimal):
            return v
        return Decimal(str(v))
    except (InvalidOperation, TypeError, ValueError):
        return Decimal(default)


def _money(v: Any) -> Decimal:
    x = _d(v, "0.00")
    if x < Decimal("0.00"):
        x = Decimal("0.00")
    return x.quantize(MONEY_Q, rounding=ROUND_HALF_UP)


def _currency(v: Optional[str], default: str = "USD") -> str:
    s = (v or default).upper().strip()
    return s[:3] if len(s) >= 3 else default


def _safe_str(v: Any, n: int) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    return s[:n] if s else None


def _meta(base: Optional[dict], extra: Optional[dict]) -> dict:
    out = dict(base or {})
    for k, v in (extra or {}).items():
        if v is not None:
            out[k] = v
    return out


def _has_col(model: Any, name: str) -> bool:
    return hasattr(model, name)


def _normalize_pm(pm: Optional[str]) -> str:
    p = (pm or _DEFAULT_PM).strip().lower()
    return p


def _assert_pm(pm: str) -> None:
    if pm not in _ALLOWED_PM:
        # no rompemos si agregaste otros métodos, pero te avisamos
        log.warning(
            "payment_method not in _ALLOWED_PM: %s (allowed=%s)",
            pm,
            sorted(_ALLOWED_PM),
        )


def _recompute_order(order: Order) -> None:
    # Conecta sin romper si tus modelos tienen métodos distintos
    if hasattr(order, "recompute_totals") and callable(
        getattr(order, "recompute_totals")
    ):
        order.recompute_totals()  # type: ignore[attr-defined]
    elif hasattr(order, "recalculate") and callable(getattr(order, "recalculate")):
        order.recalculate()  # type: ignore[attr-defined]
    # si no hay, asumimos que tu Order calcula por properties o triggers


# =============================================================================
# Transaction (safe)
# =============================================================================


class tx:
    """
    Contexto transaccional:
    - commit al salir
    - rollback en excepción
    - deja la sesión consistente
    """

    def __enter__(self) -> Session:
        return db.session

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc_type:
            db.session.rollback()
            return False
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        return True


def _retryable_create(fn, *, retries: int = 2):
    """
    Mejora: retry corto para colisiones de número de orden / IntegrityError.
    """
    last: Optional[Exception] = None
    for _ in range(max(1, retries + 1)):
        try:
            return fn()
        except IntegrityError as e:
            db.session.rollback()
            last = e
        except SQLAlchemyError as e:
            # no reintentes errores SQL generales sin saber; pero rollback seguro
            db.session.rollback()
            last = e
            break
    raise OrderServiceError(f"DB error (create retry failed): {last}")


# =============================================================================
# DTOs
# =============================================================================


@dataclass(frozen=True)
class CartLine:
    product_id: int
    qty: int = 1
    unit_price: Optional[Decimal] = None
    title: Optional[str] = None
    sku: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class CreateOrderInput:
    user_id: Optional[int] = None
    payment_method: str = _DEFAULT_PM
    currency: str = "USD"
    discount_total: Decimal = Decimal("0.00")
    shipping_total: Decimal = Decimal("0.00")
    tax_total: Decimal = Decimal("0.00")
    idempotency_key: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None


# =============================================================================
# OrderService
# =============================================================================


class OrderService:
    """
    20 mejoras reales incluidas acá (resumen):
    1) Normalización + warnings de payment_method
    2) Money quantize + tolerancia controlada
    3) Transacciones seguras + rollback consistente
    4) Retry corto ante IntegrityError (order_number collisions)
    5) Locks (FOR UPDATE) al reservar stock -> concurrency-safe
    6) Orden estable de locks por product_id (evita deadlocks)
    7) Validación fuerte de carrito (qty>=1, ids únicos)
    8) Unit price snapshot robusto (line vs product)
    9) SKU/title snapshots con safe_str
    10) Meta merge estable + audit fields
    11) Confirm payment con idempotencia + validación total/currency
    12) Confirm payment tolerante a redondeos (MONEY_TOL)
    13) Transiciones de estado validadas (y helper)
    14) Cancelación + release stock (si finite)
    15) Manejo “no rompe” si faltan columnas/métodos en modelos
    16) Logs útiles (provider, order_id, number)
    17) Protección contra inputs vacíos / inválidos
    18) Reserva stock sólo si corresponde (finite + qty)
    19) Soporte opcional para idempotency_key si existe columna en Order
    20) Conectable con comisión (hook opcional en meta)
    """

    _ALLOWED_TRANSITIONS = {
        Order.STATUS_AWAITING_PAYMENT: {Order.STATUS_PAID, Order.STATUS_CANCELLED},
        Order.STATUS_PAID: {Order.STATUS_PROCESSING, Order.STATUS_REFUNDED},
        Order.STATUS_PROCESSING: {Order.STATUS_SHIPPED},
        Order.STATUS_SHIPPED: {Order.STATUS_DELIVERED},
    }

    # -------------------------------------------------------------------------
    # CREATE ORDER
    # -------------------------------------------------------------------------

    @classmethod
    def create_order_from_cart(
        cls,
        lines: Sequence[CartLine],
        data: CreateOrderInput,
        *,
        reserve_stock: bool = True,
        strict_stock: bool = True,
    ) -> Order:
        if not lines:
            raise InvalidInputError("Carrito vacío")

        currency = _currency(data.currency)
        pm = _normalize_pm(data.payment_method)
        _assert_pm(pm)

        # validación fuerte del carrito
        norm_lines: list[CartLine] = []
        for ln in lines:
            pid = _to_int_strict(ln.product_id, "product_id")
            qty = _to_int_strict(ln.qty, "qty", min_value=1)
            norm_lines.append(
                CartLine(
                    product_id=pid,
                    qty=qty,
                    unit_price=ln.unit_price,
                    title=ln.title,
                    sku=ln.sku,
                    meta=ln.meta,
                )
            )

        # Merge de duplicados por product_id (mejora pro)
        merged = _merge_lines(norm_lines)

        def _do_create() -> Order:
            with tx() as s:
                # idempotencia (si tu Order tiene columna idempotency_key)
                if (
                    data.idempotency_key
                    and _has_col(Order, "idempotency_key")
                    and data.user_id
                ):
                    existing = (
                        s.execute(
                            select(Order)
                            .where(
                                Order.user_id == data.user_id,  # type: ignore[operator]
                                getattr(Order, "idempotency_key") == data.idempotency_key,  # type: ignore[operator]
                            )
                            .limit(1)
                        )
                        .scalars()
                        .first()
                    )
                    if existing:
                        return existing

                order = Order(
                    number=cls._new_order_number(s),
                    user_id=data.user_id,
                    status=Order.STATUS_AWAITING_PAYMENT,
                    payment_method=pm,
                    currency=currency,
                    discount_total=_money(data.discount_total),
                    shipping_total=_money(data.shipping_total),
                    tax_total=_money(data.tax_total),
                    meta=_meta(
                        data.meta,
                        {
                            "idempotency_key": data.idempotency_key,
                            "created_by": "order_service",
                            "created_at_utc": utcnow().isoformat(),
                        },
                    ),
                )

                # set column if exists
                if data.idempotency_key and _has_col(Order, "idempotency_key"):
                    setattr(order, "idempotency_key", data.idempotency_key)

                s.add(order)
                s.flush()  # obtiene order.id

                # Construye items
                for ln in merged:
                    item = cls._build_item(s, ln, currency)
                    item.order_id = order.id
                    s.add(item)

                s.flush()

                if reserve_stock:
                    cls._reserve_stock(s, order, strict=strict_stock)

                _recompute_order(order)
                s.flush()

                return order

        return _retryable_create(_do_create, retries=2)

    # -------------------------------------------------------------------------
    # PAYMENT CONFIRMATION (idempotent)
    # -------------------------------------------------------------------------

    @classmethod
    def confirm_payment(
        cls,
        order_id: int,
        *,
        provider: str,
        provider_payment_id: str,
        amount: Decimal,
        currency: str,
        raw: Optional[dict] = None,
        mark_processing: bool = False,
    ) -> Order:
        provider = _safe_str(provider, 40) or "unknown"
        provider_payment_id = _safe_str(provider_payment_id, 120) or ""
        if not provider_payment_id:
            raise InvalidInputError("provider_payment_id requerido")

        with tx() as s:
            order = s.get(Order, int(order_id))
            if not order:
                raise OrderServiceError("Orden no encontrada")

            # lock order row si tu DB lo soporta (SQLAlchemy: with_for_update)
            try:
                order = (
                    s.execute(select(Order).where(Order.id == order_id).with_for_update())  # type: ignore[operator]
                    .scalars()
                    .first()
                ) or order
            except Exception:
                # si no soporta, seguimos sin romper
                pass

            # 🔒 idempotencia por pago (por orden)
            meta = getattr(order, "meta", None) or {}
            if meta.get("provider_payment_id") == provider_payment_id:
                return order

            if order.status != Order.STATUS_AWAITING_PAYMENT:
                raise InvalidStateError("La orden no acepta pagos")

            if _currency(currency) != _currency(getattr(order, "currency", "USD")):
                raise PaymentMismatchError("Moneda incorrecta")

            expected_total = _money(getattr(order, "total", Decimal("0.00")))
            paid_amt = _money(amount)

            if (paid_amt - expected_total).copy_abs() > MONEY_TOL:
                raise PaymentMismatchError(
                    f"Monto incorrecto (esperado {expected_total}, recibido {paid_amt})"
                )

            # marca pagado (compatible)
            if hasattr(order, "mark_paid") and callable(getattr(order, "mark_paid")):
                order.mark_paid()  # type: ignore[attr-defined]
            else:
                order.status = Order.STATUS_PAID  # type: ignore[attr-defined]
                if _has_col(Order, "paid_at"):
                    setattr(order, "paid_at", utcnow())

            order.meta = _meta(
                meta,
                {
                    "payment_provider": provider.lower().strip(),
                    "provider_payment_id": provider_payment_id,
                    "paid_amount": str(paid_amt),
                    "paid_currency": _currency(currency),
                    "payment_raw": raw,
                    "paid_at_utc": utcnow().isoformat(),
                },
            )

            # hook opcional: set processing inmediato
            if mark_processing:
                cls._transition(order, Order.STATUS_PROCESSING)

            log.info(
                "payment_confirmed order_id=%s number=%s provider=%s provider_payment_id=%s total=%s",
                order.id,
                getattr(order, "number", None),
                provider,
                provider_payment_id,
                expected_total,
            )
            return order

    # -------------------------------------------------------------------------
    # CANCEL (release stock)
    # -------------------------------------------------------------------------

    @classmethod
    def cancel_order(
        cls,
        order_id: int,
        *,
        reason: Optional[str] = None,
        release_stock: bool = True,
    ) -> Order:
        with tx() as s:
            order = s.get(Order, int(order_id))
            if not order:
                raise OrderServiceError("Orden no encontrada")

            if order.status not in {Order.STATUS_AWAITING_PAYMENT, Order.STATUS_PAID}:
                raise InvalidStateError("No se puede cancelar en este estado")

            if release_stock:
                cls._release_stock(s, order)

            cls._transition(order, Order.STATUS_CANCELLED)

            order.meta = _meta(
                getattr(order, "meta", None),
                {
                    "cancel_reason": _safe_str(reason, 240),
                    "cancelled_at_utc": utcnow().isoformat(),
                },
            )
            return order

    # -------------------------------------------------------------------------
    # INTERNALS
    # -------------------------------------------------------------------------

    @classmethod
    def _transition(cls, order: Order, new_status: str) -> None:
        cur = getattr(order, "status", None)
        if cur == new_status:
            return
        allowed = cls._ALLOWED_TRANSITIONS.get(cur, set())
        if new_status not in allowed:
            raise InvalidStateError(f"Transición inválida: {cur} -> {new_status}")
        setattr(order, "status", new_status)

    @classmethod
    def _new_order_number(cls, session: Session) -> str:
        # mejora: más entropía y menos colisión
        for _ in range(12):
            n = f"SS-{utcnow().strftime('%Y%m%d')}-{secrets.token_hex(4).upper()}"
            exists = session.execute(
                select(func.count(Order.id)).where(Order.number == n)
            ).scalar()
            if not exists:
                return n
        raise OrderServiceError("No se pudo generar número de orden")

    @classmethod
    def _build_item(cls, session: Session, ln: CartLine, currency: str) -> OrderItem:
        prod = session.get(Product, int(ln.product_id))
        if not prod:
            raise OrderServiceError(f"Producto inexistente (id={ln.product_id})")

        # unit_price snapshot (preferimos ln.unit_price; si no, prod.price)
        base_price = getattr(prod, "price", Decimal("0.00"))
        price = _money(ln.unit_price if ln.unit_price is not None else base_price)

        it = OrderItem(
            product_id=prod.id,
            title_snapshot=_safe_str(ln.title or getattr(prod, "title", None), 200),
            sku_snapshot=_safe_str(ln.sku or getattr(prod, "sku", None), 80),
            currency=currency,
            unit_price=price,
            qty=max(1, int(ln.qty)),
            meta=_meta(
                ln.meta,
                {
                    "product_slug": getattr(prod, "slug", None),
                    "product_title": getattr(prod, "title", None),
                },
            ),
        )

        # compat: recompute_line_total si existe
        if hasattr(it, "recompute_line_total") and callable(
            getattr(it, "recompute_line_total")
        ):
            it.recompute_line_total()  # type: ignore[attr-defined]

        return it

    @classmethod
    def _reserve_stock(
        cls, session: Session, order: Order, *, strict: bool = True
    ) -> None:
        """
        Reserva stock con locks:
        - bloquea filas de Product en orden por product_id (evita deadlocks)
        - si strict=True -> lanza OutOfStockError
        """
        items = list(getattr(order, "items", []) or [])
        if not items:
            return

        # orden estable para locks
        product_ids = sorted(
            {int(it.product_id) for it in items if getattr(it, "product_id", None)}
        )

        # lock rows (si DB soporta)
        locked: dict[int, Product] = {}
        for pid in product_ids:
            try:
                prod = (
                    session.execute(
                        select(Product).where(Product.id == pid).with_for_update()
                    )
                    .scalars()
                    .first()
                )
            except Exception:
                prod = session.get(Product, pid)

            if prod:
                locked[pid] = prod

        # aplicar reserva
        for it in items:
            pid = int(it.product_id)
            prod = locked.get(pid) or session.get(Product, pid)
            if not prod:
                continue

            if getattr(prod, "stock_mode", "finite") != "finite":
                continue

            need = int(getattr(it, "qty", 1) or 1)
            have = int(getattr(prod, "stock_qty", 0) or 0)

            if have < need:
                if strict:
                    raise OutOfStockError(getattr(prod, "title", f"Producto {pid}"))
                # soft-fail: no reserva, pero registra
                order.meta = _meta(
                    getattr(order, "meta", None),
                    {
                        "stock_warning": f"insufficient_stock pid={pid} need={need} have={have}",
                    },
                )
                continue

            setattr(prod, "stock_qty", have - need)

    @classmethod
    def _release_stock(cls, session: Session, order: Order) -> None:
        """
        Devuelve stock si la orden tenía items y productos finite.
        (Se usa en cancelaciones / reversas controladas)
        """
        items = list(getattr(order, "items", []) or [])
        if not items:
            return

        product_ids = sorted(
            {int(it.product_id) for it in items if getattr(it, "product_id", None)}
        )

        locked: dict[int, Product] = {}
        for pid in product_ids:
            try:
                prod = (
                    session.execute(
                        select(Product).where(Product.id == pid).with_for_update()
                    )
                    .scalars()
                    .first()
                )
            except Exception:
                prod = session.get(Product, pid)
            if prod:
                locked[pid] = prod

        for it in items:
            pid = int(it.product_id)
            prod = locked.get(pid) or session.get(Product, pid)
            if not prod:
                continue
            if getattr(prod, "stock_mode", "finite") != "finite":
                continue

            qty = int(getattr(it, "qty", 1) or 1)
            have = int(getattr(prod, "stock_qty", 0) or 0)
            setattr(prod, "stock_qty", have + max(0, qty))


# =============================================================================
# Small internal helpers (kept at bottom)
# =============================================================================


def _to_int_strict(v: Any, field: str, *, min_value: Optional[int] = None) -> int:
    try:
        n = int(v)
    except Exception:
        raise InvalidInputError(f"{field} inválido")
    if min_value is not None and n < min_value:
        raise InvalidInputError(f"{field} debe ser >= {min_value}")
    return n


def _merge_lines(lines: Iterable[CartLine]) -> list[CartLine]:
    """
    Mejora PRO:
    - Si el carrito trae el mismo product_id repetido, lo mergea sumando qty.
    - Mantiene unit_price si vino (prioriza el primero no-null).
    """
    acc: dict[int, CartLine] = {}
    for ln in lines:
        pid = int(ln.product_id)
        if pid not in acc:
            acc[pid] = ln
            continue

        prev = acc[pid]
        qty = int(prev.qty) + int(ln.qty)

        unit_price = prev.unit_price if prev.unit_price is not None else ln.unit_price
        title = prev.title or ln.title
        sku = prev.sku or ln.sku
        meta = _meta(prev.meta, ln.meta)

        acc[pid] = CartLine(
            product_id=pid,
            qty=qty,
            unit_price=unit_price,
            title=title,
            sku=sku,
            meta=meta,
        )

    return [acc[k] for k in sorted(acc.keys())]
