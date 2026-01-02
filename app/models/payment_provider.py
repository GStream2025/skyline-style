from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import Index, CheckConstraint, UniqueConstraint
from sqlalchemy.orm import validates

from app.models import db

# ============================================================
# Payment Providers (GLOBAL) + User Preferred Payment (PER USER)
# - Estilo MercadoLibre/Temu: el usuario elige "método preferido"
# - NO se guardan tarjetas (PCI). Solo preferencia + metadatos no sensibles.
# ============================================================


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

# Tipos UI (para que el front los dibuje lindo)
_ALLOWED_KINDS = {"wallet", "card", "bank_transfer", "cash", "other"}


# -------------------------------------------------
# Utils internos
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
    return (
        k2 in _SECRET_KEYS_HINT
        or any(x in k2 for x in ("token", "secret", "key", "password", "bearer"))
    )


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


def _clean_kind(v: Any) -> str:
    s = _clean_str(v, 30).lower()
    return s if s in _ALLOWED_KINDS else "other"


def _as_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    s = str(v or "").strip().lower()
    return s in {"1", "true", "yes", "y", "on"}


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(str(v).strip())
    except Exception:
        return default


# =================================================
# MODEL: PaymentProvider (GLOBAL)
# =================================================
class PaymentProvider(db.Model):
    """
    PaymentProvider — ULTRA PRO FINAL

    Objetivo:
    - Admin configura métodos (habilitar, ordenar, recomendar)
    - Checkout lista solo "enabled + config válida"
    - Multi-país / multi-wallet / transferencias
    - Config JSON con schema validable

    Importante:
    - Este modelo NO guarda datos sensibles del cliente (tarjetas).
    - Eso va en pasarela (MercadoPago/Stripe/PayPal).
    """

    __tablename__ = "payment_providers"

    id = db.Column(db.Integer, primary_key=True)

    # Identidad
    code = db.Column(db.String(40), unique=True, nullable=False, index=True)
    name = db.Column(db.String(80), nullable=False)

    # UI / Checkout
    enabled = db.Column(db.Boolean, default=False, nullable=False, index=True)
    recommended = db.Column(db.Boolean, default=False, nullable=False, index=True)
    sort_order = db.Column(db.Integer, default=100, nullable=False, index=True)

    # Tipo visual y país (para filtros)
    kind = db.Column(db.String(20), nullable=False, default="other", index=True)  # wallet/card/bank_transfer/...
    country = db.Column(db.String(2), nullable=False, default="UY", index=True)  # ISO2, ej "UY", "AR"

    # UX pro
    fee_percent = db.Column(db.Integer, nullable=False, default=0)     # % comisión estimada (solo info UI)
    eta_minutes = db.Column(db.Integer, nullable=False, default=0)     # tiempo estimado confirmación
    min_amount = db.Column(db.Integer, nullable=False, default=0)      # mínimo (en moneda base UI)
    max_amount = db.Column(db.Integer, nullable=False, default=0)      # 0 = sin máximo

    # Extras
    notes = db.Column(db.String(500), nullable=False, default="")
    config = db.Column(db.JSON, nullable=False, default=dict)

    # Auditoría (admin)
    updated_by = db.Column(db.String(120), nullable=False, default="")
    updated_ip = db.Column(db.String(64), nullable=False, default="")

    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow, nullable=False)

    __table_args__ = (
        CheckConstraint("length(code) >= 2", name="ck_pp_code_len"),
        CheckConstraint("length(name) >= 2", name="ck_pp_name_len"),
        CheckConstraint("sort_order BETWEEN 0 AND 9999", name="ck_pp_sort"),
        CheckConstraint("fee_percent BETWEEN 0 AND 100", name="ck_pp_fee"),
        CheckConstraint("eta_minutes BETWEEN 0 AND 100000", name="ck_pp_eta"),
        CheckConstraint("min_amount BETWEEN 0 AND 1000000000", name="ck_pp_min"),
        CheckConstraint("max_amount BETWEEN 0 AND 1000000000", name="ck_pp_max"),
        Index("ix_pp_enabled_sort", "enabled", "sort_order"),
        Index("ix_pp_country_enabled", "country", "enabled"),
        Index("ix_pp_kind_enabled", "kind", "enabled"),
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

    @validates("kind")
    def _validate_kind(self, _, value: Any) -> str:
        return _clean_kind(value)

    @validates("country")
    def _validate_country(self, _, value: Any) -> str:
        v = _clean_str(value, 2).upper()
        return v if len(v) == 2 else "UY"

    @validates("fee_percent", "eta_minutes", "min_amount", "max_amount", "sort_order")
    def _validate_ints(self, _k, value: Any) -> int:
        return max(0, _as_int(value, 0))

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
    # VALIDACIÓN REAL por schema
    # -------------------------
    def validate_config(self) -> Tuple[bool, List[str]]:
        errors: List[str] = []
        cfg = self.ensure_config()

        schema = self.config_schema_for(self.code)
        for f in schema:
            k = f["key"]
            typ = f.get("type", "text")
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
                    cfg[k] = max(0, _as_int(cfg[k], 0))
                else:
                    cfg[k] = _clean_str(cfg[k], 500)
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
        """
        Para flujos tipo "link de pago".
        Si integrás API (MP/Stripe), esto puede estar vacío y usar tu service.
        """
        return self.get("checkout_url") or self.get("paypal_me") or ""

    def get_label_for_checkout(self) -> str:
        return self.get("label_checkout") or self.name

    def icon_hint(self) -> str:
        """
        Hint para UI (no obligatorio):
        - mp / paypal / bank / card
        """
        return self.get("icon") or self.code

    # -------------------------
    # ADMIN
    # -------------------------
    def masked_config(self) -> Dict[str, Any]:
        return {
            k: (_mask(v) if _is_secret_key(k) else v)
            for k, v in self.ensure_config().items()
        }

    def admin_preview(self) -> Dict[str, Any]:
        ok, errs = self.validate_config()
        return {
            **self.as_dict(masked=True),
            "ready": bool(self.enabled and ok),
            "errors": errs,
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
            "kind": self.kind,
            "country": self.country,
            "fee_percent": self.fee_percent,
            "eta_minutes": self.eta_minutes,
            "min_amount": self.min_amount,
            "max_amount": self.max_amount,
            "notes": self.notes,
            "config": self.masked_config() if masked else self.ensure_config(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return f"<PaymentProvider {self.code} enabled={self.enabled}>"

    # -------------------------
    # SCHEMA ADMIN (editable + validable)
    # -------------------------
    @staticmethod
    def config_schema_for(code: str) -> List[Dict[str, Any]]:
        """
        Schema mínimo para validar config y ayudar al admin.
        Tipos soportados: text | url | email | bool | int
        """
        if code == "mercadopago_uy":
            return [
                {"key": "mode", "type": "text", "required": False},  # live/test
                {"key": "checkout_url", "type": "url", "required": False},  # si usás link directo
                {"key": "public_key", "type": "text", "required": False},
                {"key": "access_token", "type": "text", "required": False},
                {"key": "currency", "type": "text", "required": True},  # UYU
                {"key": "label_checkout", "type": "text", "required": False},
                {"key": "icon", "type": "text", "required": False},
            ]
        if code == "mercadopago_ar":
            return [
                {"key": "mode", "type": "text", "required": False},
                {"key": "checkout_url", "type": "url", "required": False},
                {"key": "public_key", "type": "text", "required": False},
                {"key": "access_token", "type": "text", "required": False},
                {"key": "currency", "type": "text", "required": True},  # ARS
                {"key": "label_checkout", "type": "text", "required": False},
                {"key": "icon", "type": "text", "required": False},
            ]
        if code == "paypal":
            return [
                {"key": "paypal_me", "type": "url", "required": False},
                {"key": "business_email", "type": "email", "required": False},
                {"key": "mode", "type": "text", "required": False},  # live/sandbox
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

    # -------------------------
    # BOOTSTRAP DEFAULTS (GLOBAL)
    # -------------------------
    @staticmethod
    def boot_defaults() -> List["PaymentProvider"]:
        """
        Crea providers base si no existen.
        No los habilita automáticamente (seguridad).
        """
        defaults = [
            # code, name, kind, country, sort
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
                        country=country if country != "WW" else "UY",
                        sort_order=order,
                        enabled=False,
                        recommended=False,
                        config={},
                    )
                )
        return items


# =================================================
# MODEL: UserPreferredPayment (PER USER)
# Guarda SOLO preferencia + metadatos NO sensibles
# =================================================
class UserPreferredPayment(db.Model):
    """
    Preferencia de pago del usuario (tipo MercadoLibre/Temu).

    - Un usuario tiene 1 preferido (simple, rápido, sin vueltas).
    - NO guardar tarjetas, NO guardar tokens sensibles.
    - Si algún día integrás vault (MP/Stripe), guardás solo alias/last4/brand.
    """

    __tablename__ = "user_preferred_payments"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    # code debe ser uno de PaymentProvider.code (ej: mercadopago_uy)
    provider_code = db.Column(db.String(40), nullable=False, index=True)

    # UI info (no sensible)
    label = db.Column(db.String(80), nullable=False, default="")
    brand = db.Column(db.String(40), nullable=False, default="")   # Visa/Mastercard/etc (si aplica)
    last4 = db.Column(db.String(8), nullable=False, default="")    # últimos 4 (si aplica)

    # Extra data NO sensible (ej: "debit"/"credit", cuotas preferidas, etc.)
    meta = db.Column(db.JSON, nullable=False, default=dict)

    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("user_id", name="uq_user_preferred_payment_user"),
        CheckConstraint("length(provider_code) >= 2", name="ck_upp_code_len"),
        Index("ix_upp_user_code", "user_id", "provider_code"),
    )

    @validates("provider_code")
    def _v_provider_code(self, _k, v: str) -> str:
        vv = _clean_str(v, 40).lower().replace("-", "_").replace(" ", "_")
        vv = re.sub(r"__+", "_", vv)
        if not _CODE_RE.match(vv):
            raise ValueError("provider_code inválido.")
        return vv

    @validates("label")
    def _v_label(self, _k, v: Any) -> str:
        return _clean_str(v, 80)

    @validates("brand")
    def _v_brand(self, _k, v: Any) -> str:
        return _clean_str(v, 40)

    @validates("last4")
    def _v_last4(self, _k, v: Any) -> str:
        s = _clean_str(v, 8)
        # permitir vacío o 4 dígitos
        if s and not re.fullmatch(r"\d{4,8}", s):
            return ""
        return s

    @validates("meta")
    def _v_meta(self, _k, v: Any) -> Dict[str, Any]:
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


# =================================================
# SERVICE
# =================================================
class PaymentProviderService:
    """
    Service pro:
    - lista providers habilitados y listos
    - obtiene provider preferido del usuario
    - setea preferido del usuario (validando que exista y esté listo)
    """

    @staticmethod
    def get_enabled_for_checkout(country: Optional[str] = None) -> List[PaymentProvider]:
        try:
            q = PaymentProvider.query.filter(PaymentProvider.enabled.is_(True))

            # filtro país (si lo usás en UI)
            if country:
                cc = _clean_str(country, 2).upper()
                if len(cc) == 2:
                    # deja WW: hoy simplificado (si querés WW real, lo expandimos)
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
            c = _clean_str(code, 40).lower().replace("-", "_").replace(" ", "_")
            c = re.sub(r"__+", "_", c)
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
        """
        Guarda preferido del usuario.
        - require_ready=True: solo permite providers habilitados y listos (recomendado)
        """
        provider = PaymentProviderService.get_by_code(provider_code)
        if not provider:
            return False, "Método no existe."

        if require_ready and not provider.is_ready_for_checkout():
            return False, "Método no está listo para checkout."

        pref = PaymentProviderService.get_user_preferred(user_id)
        if not pref:
            pref = UserPreferredPayment(user_id=int(user_id), provider_code=provider.code)

        pref.provider_code = provider.code
        pref.label = _clean_str(label, 80) or provider.get_label_for_checkout()
        pref.brand = _clean_str(brand, 40)
        pref.last4 = _clean_str(last4, 8)
        pref.meta = _safe_dict(meta)

        db.session.add(pref)
        db.session.commit()
        return True, "Preferencia guardada."

    @staticmethod
    def bootstrap_defaults() -> Tuple[int, int]:
        """
        Crea providers base si faltan.
        Retorna: (creados, total)
        """
        created = 0
        items = PaymentProvider.boot_defaults()
        for it in items:
            db.session.add(it)
            created += 1
        if created:
            db.session.commit()
        total = PaymentProvider.query.count()
        return created, total
