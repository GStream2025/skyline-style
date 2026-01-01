from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, List, Tuple

from sqlalchemy import Index, CheckConstraint
from sqlalchemy.orm import validates

from app.models import db

# -------------------------------------------------
# Regex / Constantes
# -------------------------------------------------
_CODE_RE = re.compile(r"^[a-z0-9_]{2,40}$")
_URL_RE = re.compile(r"^https?://", re.I)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

_SECRET_KEYS_HINT = {
    "access_token", "client_secret", "webhook_secret", "api_key",
    "private_key", "secret", "password", "signature", "bearer", "token"
}

_ALLOWED_CODES = {
    "mercadopago_uy",
    "mercadopago_ar",
    "paypal",
    "transferencia",
    "wise",
    "payoneer",
    "paxum",
}


# -------------------------------------------------
# Utils internos (no tocar)
# -------------------------------------------------
def _utcnow() -> datetime:
    return datetime.utcnow()


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
    return k2 in _SECRET_KEYS_HINT or any(x in k2 for x in ("token", "secret", "key", "password"))


def _mask(v: Any, keep: int = 4) -> str:
    s = ("" if v is None else str(v)).strip()
    if not s:
        return ""
    if len(s) <= keep:
        return "•" * len(s)
    return ("•" * (len(s) - keep)) + s[-keep:]


def _clean_str(v: Any, max_len: int) -> str:
    return ("" if v is None else str(v)).strip()[:max_len]


def _clean_url(v: Any) -> str:
    s = _clean_str(v, 500)
    if not s:
        return ""
    if s.startswith("/"):
        return s
    if not _URL_RE.match(s):
        raise ValueError("URL inválida.")
    return s


def _clean_email(v: Any) -> str:
    s = _clean_str(v, 160)
    if not s:
        return ""
    if not _EMAIL_RE.match(s):
        raise ValueError("Email inválido.")
    return s


# =================================================
# MODEL
# =================================================
class PaymentProvider(db.Model):
    """
    PaymentProvider — ULTRA PRO FINAL (NO TOCAR MÁS)

    - Admin 100% visual
    - Checkout seguro
    - Multi país
    - Multi billetera
    """

    __tablename__ = "payment_providers"

    id = db.Column(db.Integer, primary_key=True)

    code = db.Column(db.String(40), unique=True, nullable=False, index=True)
    name = db.Column(db.String(80), nullable=False)

    enabled = db.Column(db.Boolean, default=False, nullable=False, index=True)
    sort_order = db.Column(db.Integer, default=100, nullable=False, index=True)
    recommended = db.Column(db.Boolean, default=False, nullable=False, index=True)

    notes = db.Column(db.String(500), nullable=False, default="")
    config = db.Column(db.JSON, nullable=False, default=dict)

    updated_by = db.Column(db.String(120), nullable=False, default="")
    updated_ip = db.Column(db.String(64), nullable=False, default="")

    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow, nullable=False)

    __table_args__ = (
        CheckConstraint("length(code) >= 2", name="ck_pp_code_len"),
        CheckConstraint("length(name) >= 2", name="ck_pp_name_len"),
        CheckConstraint("sort_order BETWEEN 0 AND 9999", name="ck_pp_sort"),
        Index("ix_pp_enabled_sort", "enabled", "sort_order"),
    )

    # -------------------------
    # Validación
    # -------------------------
    @validates("code")
    def _validate_code(self, _, value: str) -> str:
        v = _clean_str(value, 40).lower().replace("-", "_").replace(" ", "_")
        v = re.sub(r"__+", "_", v)
        if not _CODE_RE.match(v):
            raise ValueError("code inválido.")
        if v not in _ALLOWED_CODES:
            raise ValueError(f"Proveedor no permitido: {v}")
        return v

    @validates("name")
    def _validate_name(self, _, value: str) -> str:
        v = _clean_str(value, 80)
        if len(v) < 2:
            raise ValueError("Nombre inválido.")
        return v

    @validates("config")
    def _validate_config(self, _, value: Any) -> Dict[str, Any]:
        return _safe_dict(value)

    # -------------------------
    # Config helpers
    # -------------------------
    def ensure_config(self) -> Dict[str, Any]:
        if not isinstance(self.config, dict):
            self.config = {}
        return self.config

    def get(self, key: str, default: Any = None) -> Any:
        return self.ensure_config().get(key, default)

    def set(self, key: str, value: Any) -> None:
        cfg = self.ensure_config()
        cfg[key] = value
        self.config = cfg

    def update_config(self, data: Dict[str, Any], *, deep: bool = False) -> None:
        cur = self.ensure_config()
        self.config = _deep_merge(cur, data) if deep else {**cur, **data}

    # -------------------------
    # VALIDACIÓN REAL
    # -------------------------
    def validate_config(self) -> Tuple[bool, List[str]]:
        errors: List[str] = []
        cfg = self.ensure_config()

        for f in self.config_schema_for(self.code):
            k = f["key"]
            if f.get("required") and not cfg.get(k):
                errors.append(f"Falta: {k}")
                continue

            if not cfg.get(k):
                continue

            try:
                if f["type"] == "url":
                    cfg[k] = _clean_url(cfg[k])
                elif f["type"] == "email":
                    cfg[k] = _clean_email(cfg[k])
            except Exception as e:
                errors.append(f"{k}: {e}")

        self.config = cfg
        return (len(errors) == 0), errors

    # -------------------------
    # CHECKOUT SAFE
    # -------------------------
    def is_ready_for_checkout(self) -> bool:
        ok, _ = self.validate_config()
        return bool(self.enabled and ok)

    def checkout_link(self) -> str:
        return self.get("checkout_url") or self.get("paypal_me") or ""

    def get_label_for_checkout(self) -> str:
        return self.get("label_checkout") or self.name

    # -------------------------
    # ADMIN
    # -------------------------
    def masked_config(self) -> Dict[str, Any]:
        return {
            k: (_mask(v) if _is_secret_key(k) else v)
            for k, v in self.ensure_config().items()
        }

    def admin_preview(self) -> Dict[str, Any]:
        return {
            **self.as_dict(masked=True),
            "ready": self.is_ready_for_checkout(),
        }

    # -------------------------
    # SERIALIZE
    # -------------------------
    def as_dict(self, *, masked: bool = False) -> Dict[str, Any]:
        return {
            "id": self.id,
            "code": self.code,
            "name": self.name,
            "enabled": self.enabled,
            "recommended": self.recommended,
            "sort_order": self.sort_order,
            "notes": self.notes,
            "config": self.masked_config() if masked else self.ensure_config(),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    def __repr__(self) -> str:
        return f"<PaymentProvider {self.code} enabled={self.enabled}>"

    # -------------------------
    # SCHEMA ADMIN
    # -------------------------
    @staticmethod
    def config_schema_for(code: str) -> List[Dict[str, Any]]:
        if code == "mercadopago_uy":
            return [
                {"key": "checkout_url", "type": "url", "required": True},
                {"key": "currency", "type": "text", "required": True},
            ]
        if code == "mercadopago_ar":
            return [
                {"key": "checkout_url", "type": "url", "required": True},
                {"key": "currency", "type": "text", "required": True},
            ]
        if code == "paypal":
            return [
                {"key": "paypal_me", "type": "url", "required": False},
                {"key": "business_email", "type": "email", "required": False},
            ]
        return [
            {"key": "title", "type": "text", "required": True},
            {"key": "instructions", "type": "text", "required": True},
        ]

    # -------------------------
    # BOOTSTRAP
    # -------------------------
    @staticmethod
    def boot_defaults() -> List["PaymentProvider"]:
        defaults = [
            ("mercadopago_uy", "Mercado Pago Uruguay", 10),
            ("mercadopago_ar", "Mercado Pago Argentina", 20),
            ("paypal", "PayPal", 30),
            ("transferencia", "Transferencia", 40),
        ]
        items = []
        for code, name, order in defaults:
            if not PaymentProvider.query.filter_by(code=code).first():
                items.append(PaymentProvider(code=code, name=name, sort_order=order))
        return items


# =================================================
# SERVICE
# =================================================
class PaymentProviderService:
    @staticmethod
    def get_enabled_for_checkout() -> List[PaymentProvider]:
        try:
            providers = (
                PaymentProvider.query
                .filter(PaymentProvider.enabled.is_(True))
                .order_by(
                    PaymentProvider.recommended.desc(),
                    PaymentProvider.sort_order.asc()
                )
                .all()
            )
            return [p for p in providers if p.is_ready_for_checkout()]
        except Exception:
            return []
