from __future__ import annotations

import re
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Optional

from sqlalchemy import CheckConstraint, Index
from sqlalchemy.orm import relationship, validates

from app.models import db

TWOPLACES = Decimal("0.01")
_MAX_ABS_DISCOUNT = Decimal("99999999.99")

_TITLE_MAX = 80
_SUBTITLE_MAX = 120
_BADGE_MAX = 24
_MEDIA_URL_MAX = 255
_CTA_TEXT_MAX = 30
_CTA_URL_MAX = 240

_THEME_SET = {"auto", "amber", "emerald", "sky", "rose", "slate"}
_DTYPE_SET = {"none", "percent", "amount"}

_URL_OK_SCHEMES = {"http", "https"}
_PATH_PREFIXES = ("/", "./", "../")
_SAFE_TEXT_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _s(v: Any, n: int) -> str:
    s = "" if v is None else str(v)
    s = s.strip()
    s = _SAFE_TEXT_RE.sub("", s)
    return s[:n]


def _opt(v: Any, n: int) -> Optional[str]:
    s = _s(v, n)
    return s or None


def _to_decimal(v: Any, *, places: Decimal = TWOPLACES, allow_negative: bool = False) -> Decimal:
    if v is None or v == "":
        return Decimal("0.00")
    try:
        d = v if isinstance(v, Decimal) else Decimal(str(v).strip())
    except (InvalidOperation, ValueError) as e:
        raise ValueError(f"invalid decimal: {v!r}") from e
    if d.is_nan() or d.is_infinite():
        raise ValueError("decimal cannot be NaN/Infinity")
    d = d.quantize(places, rounding=ROUND_HALF_UP)
    if not allow_negative and d < 0:
        raise ValueError("decimal cannot be negative")
    if abs(d) > _MAX_ABS_DISCOUNT:
        raise ValueError("discount_value out of range")
    return d


def _canon_url(v: Any, *, max_len: int, allow_empty: bool = True) -> Optional[str]:
    s = _opt(v, max_len)
    if not s:
        return None if allow_empty else ""
    if s.startswith(_PATH_PREFIXES):
        return s
    try:
        from urllib.parse import urlparse

        u = urlparse(s)
        if u.scheme and u.netloc:
            if u.scheme.lower() in _URL_OK_SCHEMES:
                return s
            return None
    except Exception:
        return None
    return s


def _in_set(v: Any, allowed: set[str], default: str) -> str:
    s = _s(v, 32).lower()
    return s if s in allowed else default


class Offer(db.Model):
    __tablename__ = "offers"

    id = db.Column(db.Integer, primary_key=True)

    active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    sort_order = db.Column(db.Integer, nullable=False, default=0, index=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow, index=True)

    title = db.Column(db.String(_TITLE_MAX), nullable=False)
    subtitle = db.Column(db.String(_SUBTITLE_MAX), nullable=True)
    badge = db.Column(db.String(_BADGE_MAX), nullable=True)

    media_url = db.Column(db.String(_MEDIA_URL_MAX), nullable=True)

    cta_text = db.Column(db.String(_CTA_TEXT_MAX), nullable=True)
    cta_url = db.Column(db.String(_CTA_URL_MAX), nullable=True)

    theme = db.Column(db.String(20), nullable=False, default="auto", index=True)

    discount_type = db.Column(db.String(16), nullable=False, default="none", index=True)
    discount_value = db.Column(db.Numeric(10, 2), nullable=False, default=Decimal("0.00"))

    starts_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)
    ends_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)

    product_id = db.Column(
        db.Integer,
        db.ForeignKey("products.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    product = relationship("Product", lazy="joined")

    __table_args__ = (
        CheckConstraint("sort_order >= -10000 AND sort_order <= 10000", name="ck_offer_sort_range"),
        CheckConstraint("discount_value >= 0", name="ck_offer_discount_nonneg"),
        CheckConstraint("(ends_at IS NULL) OR (starts_at IS NULL) OR (ends_at >= starts_at)", name="ck_offer_dates_order"),
        CheckConstraint("title <> ''", name="ck_offer_title_nonempty"),
        Index("ix_offers_active_sort", "active", "sort_order", "id"),
        Index("ix_offers_live_window", "starts_at", "ends_at", "active", "id"),
        Index("ix_offers_product_active", "product_id", "active", "sort_order", "id"),
        Index("ix_offers_discount", "discount_type", "discount_value"),
    )

    @validates("active")
    def _v_active(self, _k: str, v: Any) -> bool:
        return bool(v)

    @validates("sort_order")
    def _v_sort(self, _k: str, v: Any) -> int:
        try:
            n = int(v)
        except Exception:
            n = 0
        if n < -10000:
            return -10000
        if n > 10000:
            return 10000
        return n

    @validates("discount_type")
    def _v_discount_type(self, _k: str, v: Any) -> str:
        return _in_set(v, _DTYPE_SET, "none")

    @validates("theme")
    def _v_theme(self, _k: str, v: Any) -> str:
        return _in_set(v, _THEME_SET, "auto")

    @validates("title")
    def _v_title(self, _k: str, v: Any) -> str:
        s = _s(v, _TITLE_MAX)
        return s or "Oferta"

    @validates("subtitle")
    def _v_subtitle(self, _k: str, v: Any) -> Optional[str]:
        return _opt(v, _SUBTITLE_MAX)

    @validates("badge")
    def _v_badge(self, _k: str, v: Any) -> Optional[str]:
        return _opt(v, _BADGE_MAX)

    @validates("media_url")
    def _v_media_url(self, _k: str, v: Any) -> Optional[str]:
        return _canon_url(v, max_len=_MEDIA_URL_MAX, allow_empty=True)

    @validates("cta_text")
    def _v_cta_text(self, _k: str, v: Any) -> Optional[str]:
        return _opt(v, _CTA_TEXT_MAX)

    @validates("cta_url")
    def _v_cta_url(self, _k: str, v: Any) -> Optional[str]:
        return _canon_url(v, max_len=_CTA_URL_MAX, allow_empty=True)

    @validates("discount_value")
    def _v_discount_value(self, _k: str, v: Any) -> Decimal:
        d = _to_decimal(v, allow_negative=False)
        if getattr(self, "discount_type", "none") == "percent":
            if d > Decimal("100.00"):
                return Decimal("100.00")
        return d

    @validates("starts_at", "ends_at")
    def _v_dates(self, _k: str, v: Any) -> Optional[datetime]:
        if v is None or v == "":
            return None
        if isinstance(v, datetime):
            return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        s = str(v).strip()
        if not s:
            return None
        try:
            dt = datetime.fromisoformat(s)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None

    def is_live(self, now: Optional[datetime] = None) -> bool:
        if not bool(self.active):
            return False
        now = now or utcnow()
        if self.starts_at and now < self.starts_at:
            return False
        if self.ends_at and now > self.ends_at:
            return False
        return True

    def has_discount(self) -> bool:
        return self.discount_type != "none" and _to_decimal(self.discount_value) > Decimal("0.00")

    def discount_label(self, currency: str = "$") -> Optional[str]:
        if not self.has_discount():
            return None
        v = _to_decimal(self.discount_value)
        if self.discount_type == "percent":
            q = v.quantize(TWOPLACES, rounding=ROUND_HALF_UP)
            if q == q.to_integral():
                return f"-{int(q)}%"
            return f"-{q.normalize()}%"
        if self.discount_type == "amount":
            q = v.quantize(TWOPLACES, rounding=ROUND_HALF_UP)
            if q == q.to_integral():
                return f"-{currency}{int(q)}"
            return f"-{currency}{q.normalize()}"
        return None

    def applies_to_product(self, product_id: int) -> bool:
        pid = int(product_id)
        return self.product_id is None or int(self.product_id) == pid

    def normalized(self) -> None:
        self.title = self._v_title("title", self.title)
        self.subtitle = self._v_subtitle("subtitle", self.subtitle)
        self.badge = self._v_badge("badge", self.badge)
        self.theme = self._v_theme("theme", self.theme)
        self.discount_type = self._v_discount_type("discount_type", self.discount_type)
        self.discount_value = self._v_discount_value("discount_value", self.discount_value)
        self.media_url = self._v_media_url("media_url", self.media_url)
        self.cta_text = self._v_cta_text("cta_text", self.cta_text)
        self.cta_url = self._v_cta_url("cta_url", self.cta_url)

    def __repr__(self) -> str:
        return f"<Offer id={self.id} active={bool(self.active)} title={self.title!r} discount={self.discount_type}:{self.discount_value}>"


__all__ = ["Offer", "utcnow"]
