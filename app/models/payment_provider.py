from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import (
    CheckConstraint,
    Index,
    UniqueConstraint,
    event,
    func,
    select,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import validates

from app.models import db

_CODE_RE = re.compile(r"^[a-z0-9_]{2,40}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_ALLOWED_CODES = {
    "mercadopago_uy",
    "mercadopago_ar",
    "paypal",
    "transferencia",
    "wise",
    "payoneer",
    "paxum",
}
_ALLOWED_KINDS = {"wallet", "card", "bank_transfer", "cash", "other"}

_SECRET_KEY_HINTS = {
    "access_token",
    "client_secret",
    "webhook_secret",
    "api_key",
    "private_key",
    "secret",
    "password",
    "signature",
    "bearer",
    "token",
}

_STR_MAX_CODE = 40
_STR_MAX_NAME = 80
_STR_MAX_NOTES = 500
_STR_MAX_AUDIT = 120
_STR_MAX_IP = 64
_STR_MAX_LABEL = 80
_STR_MAX_BRAND = 40
_STR_MAX_LAST4 = 8
_STR_MAX_URL = 500
_STR_MAX_EMAIL = 160

_INT_MAX_SORT = 9999
_INT_MAX_ETA = 100000
_INT_MAX_MONEY = 1_000_000_000


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _clean_str(v: Any, max_len: int) -> str:
    s = "" if v is None else str(v)
    s = s.replace("\x00", "").strip()
    if not s:
        return ""
    return s[:max_len]


def _clean_code(v: Any) -> str:
    s = _clean_str(v, _STR_MAX_CODE).lower().replace("-", "_").replace(" ", "_")
    s = re.sub(r"__+", "_", s).strip("_")
    if not _CODE_RE.match(s):
        raise ValueError("code inválido")
    if s not in _ALLOWED_CODES:
        raise ValueError("Proveedor no permitido")
    return s


def _clean_kind(v: Any) -> str:
    s = _clean_str(v, 20).lower()
    return s if s in _ALLOWED_KINDS else "other"


def _clean_country(v: Any) -> str:
    s = _clean_str(v, 2).upper()
    return s if len(s) == 2 else "UY"


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(str(v).strip())
    except Exception:
        return default


def _clamp_int(v: Any, *, lo: int, hi: int, default: int = 0) -> int:
    n = _as_int(v, default)
    if n < lo:
        return lo
    if n > hi:
        return hi
    return n


def _as_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    s = _clean_str(v, 10).lower()
    return s in {"1", "true", "yes", "y", "on"}


def _safe_dict(v: Any) -> Dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _deep_merge(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(a or {})
    for k, v in (b or {}).items():
        if isinstance(out.get(k), dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _is_secret_key(k: str) -> bool:
    k2 = (k or "").lower()
    if k2 in _SECRET_KEY_HINTS:
        return True
    return any(x in k2 for x in ("token", "secret", "key", "password", "bearer"))


def _mask(v: Any, keep: int = 4) -> str:
    s = _clean_str(v, 600)
    if not s:
        return ""
    if len(s) <= keep:
        return "•" * len(s)
    return ("•" * (len(s) - keep)) + s[-keep:]


def _clean_url(v: Any) -> str:
    s = _clean_str(v, _STR_MAX_URL)
    if not s:
        return ""
    if s.startswith("/"):
        return s
    if not (s.lower().startswith("http://") or s.lower().startswith("https://")):
        raise ValueError("URL inválida")
    return s


def _clean_email(v: Any) -> str:
    s = _clean_str(v, _STR_MAX_EMAIL).lower()
    if not s:
        return ""
    if not _EMAIL_RE.match(s):
        raise ValueError("Email inválido")
    return s


def _clean_last4(v: Any) -> str:
    s = _clean_str(v, _STR_MAX_LAST4)
    if not s:
        return ""
    return s if re.fullmatch(r"\d{4,8}", s) else ""


class PaymentProvider(db.Model):
    __tablename__ = "payment_providers"

    id = db.Column(db.Integer, primary_key=True)

    code = db.Column(db.String(_STR_MAX_CODE), unique=True, nullable=False, index=True)
    name = db.Column(db.String(_STR_MAX_NAME), nullable=False)

    enabled = db.Column(db.Boolean, default=False, nullable=False, index=True)
    recommended = db.Column(db.Boolean, default=False, nullable=False, index=True)
    sort_order = db.Column(db.Integer, default=100, nullable=False, index=True)

    kind = db.Column(db.String(20), nullable=False, default="other", index=True)
    country = db.Column(db.String(2), nullable=False, default="UY", index=True)

    fee_percent = db.Column(db.Integer, nullable=False, default=0)
    eta_minutes = db.Column(db.Integer, nullable=False, default=0)
    min_amount = db.Column(db.Integer, nullable=False, default=0)
    max_amount = db.Column(db.Integer, nullable=False, default=0)

    notes = db.Column(db.String(_STR_MAX_NOTES), nullable=False, default="")
    config = db.Column(db.JSON, nullable=False, default=dict)

    updated_by = db.Column(db.String(_STR_MAX_AUDIT), nullable=False, default="")
    updated_ip = db.Column(db.String(_STR_MAX_IP), nullable=False, default="")

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        CheckConstraint("length(code) >= 2", name="ck_pp_code_len"),
        CheckConstraint("length(name) >= 2", name="ck_pp_name_len"),
        CheckConstraint(f"sort_order BETWEEN 0 AND {_INT_MAX_SORT}", name="ck_pp_sort"),
        CheckConstraint("fee_percent BETWEEN 0 AND 100", name="ck_pp_fee"),
        CheckConstraint(f"eta_minutes BETWEEN 0 AND {_INT_MAX_ETA}", name="ck_pp_eta"),
        CheckConstraint(f"min_amount BETWEEN 0 AND {_INT_MAX_MONEY}", name="ck_pp_min"),
        CheckConstraint(f"max_amount BETWEEN 0 AND {_INT_MAX_MONEY}", name="ck_pp_max"),
        Index("ix_pp_enabled_sort", "enabled", "sort_order", "name"),
        Index("ix_pp_country_enabled", "country", "enabled", "sort_order"),
        Index("ix_pp_kind_enabled", "kind", "enabled", "sort_order"),
    )

    @validates("code")
    def _v_code(self, _k: str, v: Any) -> str:
        return _clean_code(v)

    @validates("name")
    def _v_name(self, _k: str, v: Any) -> str:
        s = _clean_str(v, _STR_MAX_NAME)
        if len(s) < 2:
            raise ValueError("Nombre inválido")
        return s

    @validates("config")
    def _v_config(self, _k: str, v: Any) -> Dict[str, Any]:
        return _safe_dict(v)

    @validates("kind")
    def _v_kind(self, _k: str, v: Any) -> str:
        return _clean_kind(v)

    @validates("country")
    def _v_country(self, _k: str, v: Any) -> str:
        return _clean_country(v)

    @validates("notes", "updated_by", "updated_ip")
    def _v_txt(self, _k: str, v: Any) -> str:
        max_len = _STR_MAX_NOTES if _k == "notes" else (_STR_MAX_AUDIT if _k == "updated_by" else _STR_MAX_IP)
        return _clean_str(v, max_len)

    @validates("fee_percent", "eta_minutes", "min_amount", "max_amount", "sort_order")
    def _v_ints(self, _k: str, v: Any) -> int:
        if _k == "fee_percent":
            return _clamp_int(v, lo=0, hi=100, default=0)
        if _k == "sort_order":
            return _clamp_int(v, lo=0, hi=_INT_MAX_SORT, default=100)
        if _k == "eta_minutes":
            return _clamp_int(v, lo=0, hi=_INT_MAX_ETA, default=0)
        if _k in {"min_amount", "max_amount"}:
            return _clamp_int(v, lo=0, hi=_INT_MAX_MONEY, default=0)
        return max(0, _as_int(v, 0))

    def ensure_config(self) -> Dict[str, Any]:
        if not isinstance(self.config, dict):
            self.config = {}
        return self.config

    def get(self, key: str, default: Any = None) -> Any:
        return self.ensure_config().get(key, default)

    def set(self, key: str, value: Any) -> None:
        cfg = self.ensure_config()
        cfg[str(key)] = value
        self.config = cfg

    def update_config(self, data: Dict[str, Any], *, deep: bool = False) -> None:
        cur = self.ensure_config()
        self.config = _deep_merge(cur, data) if deep else {**cur, **(data or {})}

    def validate_config(self) -> Tuple[bool, List[str]]:
        errors: List[str] = []
        cfg = self.ensure_config()
        schema = self.config_schema_for(self.code)

        for f in schema:
            k = str(f.get("key") or "").strip()
            if not k:
                continue
            typ = str(f.get("type") or "text").strip().lower()
            required = bool(f.get("required"))

            if required and not cfg.get(k):
                errors.append(f"Falta: {k}")
                continue

            if not cfg.get(k):
                continue

            try:
                if typ == "url":
                    cfg[k] = _clean_url(cfg[k])
                elif typ == "email":
                    cfg[k] = _clean_email(cfg[k])
                elif typ == "bool":
                    cfg[k] = _as_bool(cfg[k])
                elif typ == "int":
                    cfg[k] = _clamp_int(cfg[k], lo=0, hi=_INT_MAX_MONEY, default=0)
                else:
                    cfg[k] = _clean_str(cfg[k], _STR_MAX_URL)
            except Exception as e:
                errors.append(f"{k}: {e}")

        self.config = cfg
        return (len(errors) == 0), errors

    def is_ready_for_checkout(self) -> bool:
        ok, _ = self.validate_config()
        if not self.enabled or not ok:
            return False
        if self.max_amount and self.min_amount and self.max_amount < self.min_amount:
            return False
        if self.kind not in _ALLOWED_KINDS:
            return False
        if self.code not in _ALLOWED_CODES:
            return False
        return True

    def checkout_link(self) -> str:
        return str(self.get("checkout_url") or self.get("paypal_me") or "")

    def get_label_for_checkout(self) -> str:
        v = self.get("label_checkout") or ""
        return _clean_str(v, _STR_MAX_LABEL) or self.name

    def icon_hint(self) -> str:
        v = self.get("icon") or ""
        return _clean_str(v, 60) or self.code

    def masked_config(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for k, v in self.ensure_config().items():
            ks = str(k)
            out[ks] = _mask(v) if _is_secret_key(ks) else v
        return out

    def admin_preview(self) -> Dict[str, Any]:
        ok, errs = self.validate_config()
        d = self.as_dict(masked=True)
        d["ready"] = bool(self.enabled and ok)
        d["errors"] = errs
        return d

    def as_dict(self, *, masked: bool = False) -> Dict[str, Any]:
        return {
            "id": self.id,
            "code": self.code,
            "name": self.name,
            "enabled": bool(self.enabled),
            "recommended": bool(self.recommended),
            "sort_order": int(self.sort_order or 0),
            "kind": self.kind,
            "country": self.country,
            "fee_percent": int(self.fee_percent or 0),
            "eta_minutes": int(self.eta_minutes or 0),
            "min_amount": int(self.min_amount or 0),
            "max_amount": int(self.max_amount or 0),
            "notes": self.notes,
            "config": self.masked_config() if masked else self.ensure_config(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    @staticmethod
    def config_schema_for(code: str) -> List[Dict[str, Any]]:
        if code == "mercadopago_uy":
            return [
                {"key": "mode", "type": "text", "required": False},
                {"key": "checkout_url", "type": "url", "required": False},
                {"key": "public_key", "type": "text", "required": False},
                {"key": "access_token", "type": "text", "required": False},
                {"key": "currency", "type": "text", "required": True},
                {"key": "label_checkout", "type": "text", "required": False},
                {"key": "icon", "type": "text", "required": False},
            ]
        if code == "mercadopago_ar":
            return [
                {"key": "mode", "type": "text", "required": False},
                {"key": "checkout_url", "type": "url", "required": False},
                {"key": "public_key", "type": "text", "required": False},
                {"key": "access_token", "type": "text", "required": False},
                {"key": "currency", "type": "text", "required": True},
                {"key": "label_checkout", "type": "text", "required": False},
                {"key": "icon", "type": "text", "required": False},
            ]
        if code == "paypal":
            return [
                {"key": "paypal_me", "type": "url", "required": False},
                {"key": "business_email", "type": "email", "required": False},
                {"key": "mode", "type": "text", "required": False},
                {"key": "label_checkout", "type": "text", "required": False},
                {"key": "icon", "type": "text", "required": False},
            ]
        if code == "transferencia":
            return [
                {"key": "title", "type": "text", "required": True},
                {"key": "instructions", "type": "text", "required": True},
                {"key": "bank_name", "type": "text", "required": False},
                {"key": "account_name", "type": "text", "required": False},
                {"key": "account_number", "type": "text", "required": False},
                {"key": "label_checkout", "type": "text", "required": False},
                {"key": "icon", "type": "text", "required": False},
            ]
        if code in {"wise", "payoneer", "paxum"}:
            return [
                {"key": "title", "type": "text", "required": True},
                {"key": "instructions", "type": "text", "required": True},
                {"key": "checkout_url", "type": "url", "required": False},
                {"key": "label_checkout", "type": "text", "required": False},
                {"key": "icon", "type": "text", "required": False},
            ]
        return [
            {"key": "title", "type": "text", "required": True},
            {"key": "instructions", "type": "text", "required": True},
        ]

    @staticmethod
    def boot_defaults() -> List["PaymentProvider"]:
        defaults = [
            ("mercadopago_uy", "Mercado Pago Uruguay", "wallet", "UY", 10),
            ("mercadopago_ar", "Mercado Pago Argentina", "wallet", "AR", 20),
            ("paypal", "PayPal", "wallet", "WW", 30),
            ("transferencia", "Transferencia bancaria", "bank_transfer", "UY", 40),
            ("wise", "Wise", "bank_transfer", "WW", 50),
            ("payoneer", "Payoneer", "wallet", "WW", 60),
            ("paxum", "Paxum", "wallet", "WW", 70),
        ]
        items: List[PaymentProvider] = []
        for code, name, kind, country, order in defaults:
            exists = PaymentProvider.query.filter_by(code=code).first()
            if not exists:
                items.append(
                    PaymentProvider(
                        code=code,
                        name=name,
                        kind=kind,
                        country=("UY" if country == "WW" else country),
                        sort_order=order,
                        enabled=False,
                        recommended=False,
                        config={},
                    )
                )
        return items


class UserPreferredPayment(db.Model):
    __tablename__ = "user_preferred_payments"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    provider_code = db.Column(db.String(_STR_MAX_CODE), nullable=False, index=True)

    label = db.Column(db.String(_STR_MAX_LABEL), nullable=False, default="")
    brand = db.Column(db.String(_STR_MAX_BRAND), nullable=False, default="")
    last4 = db.Column(db.String(_STR_MAX_LAST4), nullable=False, default="")

    meta = db.Column(db.JSON, nullable=False, default=dict)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        UniqueConstraint("user_id", name="uq_user_preferred_payment_user"),
        CheckConstraint("length(provider_code) >= 2", name="ck_upp_code_len"),
        Index("ix_upp_user_code", "user_id", "provider_code"),
    )

    @validates("provider_code")
    def _v_provider_code(self, _k: str, v: Any) -> str:
        s = _clean_str(v, _STR_MAX_CODE).lower().replace("-", "_").replace(" ", "_")
        s = re.sub(r"__+", "_", s).strip("_")
        if not _CODE_RE.match(s):
            raise ValueError("provider_code inválido")
        if s not in _ALLOWED_CODES:
            raise ValueError("provider_code no permitido")
        return s

    @validates("label")
    def _v_label(self, _k: str, v: Any) -> str:
        return _clean_str(v, _STR_MAX_LABEL)

    @validates("brand")
    def _v_brand(self, _k: str, v: Any) -> str:
        return _clean_str(v, _STR_MAX_BRAND)

    @validates("last4")
    def _v_last4(self, _k: str, v: Any) -> str:
        return _clean_last4(v)

    @validates("meta")
    def _v_meta(self, _k: str, v: Any) -> Dict[str, Any]:
        return _safe_dict(v)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "provider_code": self.provider_code,
            "label": self.label,
            "brand": self.brand,
            "last4": self.last4,
            "meta": _safe_dict(self.meta),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return f"<UserPreferredPayment user_id={self.user_id} provider={self.provider_code}>"


class PaymentProviderService:
    @staticmethod
    def get_enabled_for_checkout(country: Optional[str] = None) -> List[PaymentProvider]:
        try:
            q = PaymentProvider.query.filter(PaymentProvider.enabled.is_(True))

            if country:
                cc = _clean_str(country, 2).upper()
                if len(cc) == 2:
                    q = q.filter(PaymentProvider.country.in_([cc, "UY", "AR"]))

            providers = (
                q.order_by(
                    PaymentProvider.recommended.desc(),
                    PaymentProvider.sort_order.asc(),
                    PaymentProvider.name.asc(),
                )
                .all()
            )
            return [p for p in providers if p.is_ready_for_checkout()]
        except Exception:
            return []

    @staticmethod
    def get_by_code(code: str) -> Optional[PaymentProvider]:
        try:
            c = _clean_str(code, _STR_MAX_CODE).lower().replace("-", "_").replace(" ", "_")
            c = re.sub(r"__+", "_", c).strip("_")
            return PaymentProvider.query.filter_by(code=c).first()
        except Exception:
            return None

    @staticmethod
    def get_user_preferred(user_id: int) -> Optional[UserPreferredPayment]:
        try:
            return UserPreferredPayment.query.filter_by(user_id=int(user_id)).first()
        except Exception:
            return None

    @staticmethod
    def set_user_preferred(
        user_id: int,
        provider_code: str,
        *,
        label: str = "",
        brand: str = "",
        last4: str = "",
        meta: Optional[Dict[str, Any]] = None,
        require_ready: bool = True,
    ) -> Tuple[bool, str]:
        provider = PaymentProviderService.get_by_code(provider_code)
        if not provider:
            return False, "Método no existe"

        if require_ready and not provider.is_ready_for_checkout():
            return False, "Método no está listo para checkout"

        pref = PaymentProviderService.get_user_preferred(user_id)
        if not pref:
            pref = UserPreferredPayment(user_id=int(user_id), provider_code=provider.code)

        pref.provider_code = provider.code
        pref.label = _clean_str(label, _STR_MAX_LABEL) or provider.get_label_for_checkout()
        pref.brand = _clean_str(brand, _STR_MAX_BRAND)
        pref.last4 = _clean_last4(last4)
        pref.meta = _safe_dict(meta)

        try:
            db.session.add(pref)
            db.session.commit()
            return True, "Preferencia guardada"
        except IntegrityError:
            db.session.rollback()
            try:
                pref2 = UserPreferredPayment.query.filter_by(user_id=int(user_id)).first()
                if pref2:
                    pref2.provider_code = provider.code
                    pref2.label = pref.label
                    pref2.brand = pref.brand
                    pref2.last4 = pref.last4
                    pref2.meta = pref.meta
                    db.session.add(pref2)
                    db.session.commit()
                    return True, "Preferencia guardada"
            except Exception:
                db.session.rollback()
            return False, "No se pudo guardar la preferencia"
        except Exception:
            db.session.rollback()
            return False, "No se pudo guardar la preferencia"

    @staticmethod
    def bootstrap_defaults() -> Tuple[int, int]:
        created = 0
        try:
            items = PaymentProvider.boot_defaults()
            for it in items:
                db.session.add(it)
                created += 1
            if created:
                db.session.commit()
        except Exception:
            db.session.rollback()
            created = 0

        try:
            total = int(db.session.execute(select(func.count(PaymentProvider.id))).scalar() or 0)
        except Exception:
            try:
                total = int(PaymentProvider.query.count())
            except Exception:
                total = 0
        return created, total


@event.listens_for(PaymentProvider, "before_insert", propagate=True)
def _pp_before_insert(_mapper, _conn, target: PaymentProvider) -> None:
    target.code = _clean_code(target.code)
    target.name = _clean_str(target.name, _STR_MAX_NAME) or target.code
    target.kind = _clean_kind(target.kind)
    target.country = _clean_country(target.country)
    target.notes = _clean_str(target.notes, _STR_MAX_NOTES)
    target.updated_by = _clean_str(target.updated_by, _STR_MAX_AUDIT)
    target.updated_ip = _clean_str(target.updated_ip, _STR_MAX_IP)
    target.sort_order = _clamp_int(target.sort_order, lo=0, hi=_INT_MAX_SORT, default=100)
    target.fee_percent = _clamp_int(target.fee_percent, lo=0, hi=100, default=0)
    target.eta_minutes = _clamp_int(target.eta_minutes, lo=0, hi=_INT_MAX_ETA, default=0)
    target.min_amount = _clamp_int(target.min_amount, lo=0, hi=_INT_MAX_MONEY, default=0)
    target.max_amount = _clamp_int(target.max_amount, lo=0, hi=_INT_MAX_MONEY, default=0)
    target.enabled = bool(target.enabled)
    target.recommended = bool(target.recommended)
    target.config = _safe_dict(target.config)
    now = utcnow()
    if not target.created_at:
        target.created_at = now
    target.updated_at = now


@event.listens_for(PaymentProvider, "before_update", propagate=True)
def _pp_before_update(_mapper, _conn, target: PaymentProvider) -> None:
    target.kind = _clean_kind(target.kind)
    target.country = _clean_country(target.country)
    target.notes = _clean_str(target.notes, _STR_MAX_NOTES)
    target.updated_by = _clean_str(target.updated_by, _STR_MAX_AUDIT)
    target.updated_ip = _clean_str(target.updated_ip, _STR_MAX_IP)
    target.sort_order = _clamp_int(target.sort_order, lo=0, hi=_INT_MAX_SORT, default=100)
    target.fee_percent = _clamp_int(target.fee_percent, lo=0, hi=100, default=0)
    target.eta_minutes = _clamp_int(target.eta_minutes, lo=0, hi=_INT_MAX_ETA, default=0)
    target.min_amount = _clamp_int(target.min_amount, lo=0, hi=_INT_MAX_MONEY, default=0)
    target.max_amount = _clamp_int(target.max_amount, lo=0, hi=_INT_MAX_MONEY, default=0)
    target.enabled = bool(target.enabled)
    target.recommended = bool(target.recommended)
    target.config = _safe_dict(target.config)
    target.updated_at = utcnow()


@event.listens_for(UserPreferredPayment, "before_insert", propagate=True)
def _upp_before_insert(_mapper, _conn, target: UserPreferredPayment) -> None:
    target.provider_code = _clean_code(target.provider_code)
    target.label = _clean_str(target.label, _STR_MAX_LABEL)
    target.brand = _clean_str(target.brand, _STR_MAX_BRAND)
    target.last4 = _clean_last4(target.last4)
    target.meta = _safe_dict(target.meta)
    now = utcnow()
    if not target.created_at:
        target.created_at = now
    target.updated_at = now


@event.listens_for(UserPreferredPayment, "before_update", propagate=True)
def _upp_before_update(_mapper, _conn, target: UserPreferredPayment) -> None:
    target.provider_code = _clean_code(target.provider_code)
    target.label = _clean_str(target.label, _STR_MAX_LABEL)
    target.brand = _clean_str(target.brand, _STR_MAX_BRAND)
    target.last4 = _clean_last4(target.last4)
    target.meta = _safe_dict(target.meta)
    target.updated_at = utcnow()


__all__ = [
    "PaymentProvider",
    "UserPreferredPayment",
    "PaymentProviderService",
    "utcnow",
]
