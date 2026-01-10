# app/routes/address_routes.py — Skyline Store (ULTRA PRO / FINAL / NO BREAK)
from __future__ import annotations

import re
import secrets
import time
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
    current_app,
    jsonify,
)

from app.models import db, User, UserAddress

# ============================================================
# Blueprint
# ============================================================

address_bp = Blueprint(
    "address",
    __name__,
    url_prefix="/account",
    template_folder="../templates",
)

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
PHONE_RE = re.compile(r"^[0-9+() \-]{6,40}$")


# ============================================================
# Time / Negotiation
# ============================================================


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _wants_json() -> bool:
    """
    ✅ Mejora extra #1: negotiation PRO
    - Accept application/json
    - XHR
    - ?format=json
    """
    if (request.args.get("format") or "").lower() == "json":
        return True
    accept = (request.headers.get("Accept") or "").lower()
    if "application/json" in accept:
        return True
    if (request.headers.get("X-Requested-With") or "").lower() == "xmlhttprequest":
        return True
    return False


def _json(payload: Dict[str, Any], status: int = 200):
    return jsonify(payload), status


def _json_or_redirect(payload: Dict[str, Any], endpoint: str, **kwargs):
    if _wants_json():
        status = int(payload.get("status", 200))
        payload.pop("status", None)
        return _json(payload, status)
    return redirect(url_for(endpoint, **kwargs))


# ============================================================
# Auth helpers
# ============================================================


def _login_required() -> Optional[Any]:
    if session.get("user_id"):
        return None
    if _wants_json():
        return _json({"ok": False, "error": "auth_required"}, 401)
    flash("Iniciá sesión para gestionar tus direcciones.", "warning")
    return redirect(url_for("auth.login", next=request.path))


def _current_user() -> Optional[User]:
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        return db.session.get(User, int(uid))
    except Exception:
        return None


# ============================================================
# CSRF (sin Flask-WTF)
# ============================================================


def _ensure_csrf() -> str:
    tok = session.get("csrf_token")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf_token"] = tok
    return tok


def _get_csrf_from_request() -> str:
    """
    ✅ Mejora extra #2: CSRF header aliases + JSON body
    """
    # Headers (dos variantes comunes)
    h = (
        request.headers.get("X-CSRF-Token") or request.headers.get("X-CSRFToken") or ""
    ).strip()
    if h:
        return h
    # Form
    f = (request.form.get("csrf_token") or "").strip()
    if f:
        return f
    # JSON
    j = request.get_json(silent=True) or {}
    try:
        v = (j.get("csrf_token") or "").strip()
        return v
    except Exception:
        return ""


def _check_csrf() -> bool:
    tok = (session.get("csrf_token") or "").strip()
    got = _get_csrf_from_request()
    return bool(tok) and bool(got) and secrets.compare_digest(tok, got)


def _csrf_required() -> Optional[Any]:
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if not _check_csrf():
            if _wants_json():
                return _json({"ok": False, "error": "csrf_invalid"}, 400)
            flash("Token inválido. Recargá la página.", "warning")
            return redirect(url_for("address.addresses_page"))
    return None


# ============================================================
# Rate-limit + Soft Idempotency
# ============================================================


def _rate_limit(key: str, seconds: int = 2) -> bool:
    """
    Rate limit mínimo por sesión.
    Devuelve True si está permitido, False si bloquea.
    """
    now = time.time()
    last = session.get(key)
    if isinstance(last, (int, float)) and (now - float(last)) < seconds:
        return False
    session[key] = now
    return True


def _dedupe_guard(user_id: int, signature: str, ttl: int = 10) -> bool:
    """
    ✅ Mejora extra #5: evita duplicados obvios (misma dirección enviada 2 veces)
    Guarda firma en session por 10s.
    """
    k = f"addr:dedupe:{user_id}"
    now = int(time.time())
    raw = session.get(k) or {}
    if not isinstance(raw, dict):
        raw = {}
    # purge
    for s, ts in list(raw.items()):
        try:
            if now - int(ts) > ttl:
                raw.pop(s, None)
        except Exception:
            raw.pop(s, None)
    # check
    if signature in raw:
        return False
    raw[signature] = now
    session[k] = raw
    return True


# ============================================================
# Sanitizers / Validation (checkout-ready)
# ============================================================


def _clean_str(v: Optional[str], max_len: int) -> Optional[str]:
    if v is None:
        return None
    v = str(v).strip()
    if not v:
        return None
    return v[:max_len]


def _clean_country(v: Optional[str]) -> Optional[str]:
    if not v:
        return None
    v = str(v).strip().upper()
    return v[:2] if len(v) >= 2 else None


def _validate_phone(v: Optional[str]) -> Optional[str]:
    if not v:
        return None
    v = str(v).strip()
    if not v:
        return None
    # no bloquea: solo limpia
    if not PHONE_RE.match(v):
        return v[:40]
    return v[:40]


def _payload_from_request() -> Dict[str, Any]:
    """
    Soporta FORM o JSON para create/update.
    """
    payload = request.get_json(silent=True) or {}
    form = request.form

    def g(name: str) -> Optional[str]:
        if payload:
            v = payload.get(name)
            return None if v is None else str(v)
        return form.get(name)

    is_default_raw = (g("is_default") or "").strip().lower()

    return {
        "label": _clean_str(g("label"), 50),
        "full_name": _clean_str(g("full_name"), 120),
        "phone": _validate_phone(g("phone")),
        "line1": (g("line1") or "").strip()[:200],
        "line2": _clean_str(g("line2"), 200),
        "city": _clean_str(g("city"), 120),
        "state": _clean_str(g("state"), 120),
        "postal_code": _clean_str(g("postal_code"), 40),
        "country": _clean_country(g("country")),
        "is_default": is_default_raw in _TRUE,
    }


def _validate_payload(data: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    ✅ Mejora extra #3: lista de errores por campo (API/UI friendly)
    """
    errors: List[Dict[str, str]] = []
    if not (data.get("line1") or "").strip():
        errors.append({"field": "line1", "error": "required"})
    # Si hay phone, validar mínimo real
    ph = (data.get("phone") or "").strip() if data.get("phone") else ""
    if ph and (len(ph) < 6 or len(ph) > 40):
        errors.append({"field": "phone", "error": "invalid"})
    # country si viene debe ser 2 chars
    cc = data.get("country")
    if cc and len(cc) != 2:
        errors.append({"field": "country", "error": "invalid"})
    return errors


def _address_to_dict(a: UserAddress) -> Dict[str, Any]:
    return {
        "id": a.id,
        "label": getattr(a, "label", None),
        "full_name": getattr(a, "full_name", None),
        "phone": getattr(a, "phone", None),
        "line1": getattr(a, "line1", None),
        "line2": getattr(a, "line2", None),
        "city": getattr(a, "city", None),
        "state": getattr(a, "state", None),
        "postal_code": getattr(a, "postal_code", None),
        "country": getattr(a, "country", None),
        "is_default": bool(getattr(a, "is_default", False)),
        "created_at": (
            getattr(a, "created_at", None).isoformat()
            if getattr(a, "created_at", None)
            else None
        ),
    }


# ============================================================
# Default logic (1 sola default) — centralizado
# ============================================================


def _set_default_address(user_id: int, addr_id: int) -> None:
    db.session.query(UserAddress).filter_by(user_id=user_id).update(
        {"is_default": False}
    )
    a = db.session.get(UserAddress, addr_id)
    if a and a.user_id == user_id:
        a.is_default = True


def _ensure_default_exists(user_id: int) -> None:
    has_def = (
        db.session.query(UserAddress)
        .filter_by(user_id=user_id, is_default=True)
        .first()
    )
    if has_def:
        return
    last = (
        db.session.query(UserAddress)
        .filter_by(user_id=user_id)
        .order_by(UserAddress.id.desc())
        .first()
    )
    if last:
        last.is_default = True


def _normalize_default(user_id: int, preferred_id: Optional[int] = None) -> None:
    """
    ✅ Mejora extra #7: una sola función para mantener default consistente
    - si preferred_id existe => set default
    - si no => ensure default
    """
    if preferred_id:
        _set_default_address(user_id, int(preferred_id))
    _ensure_default_exists(user_id)


def _get_user_address_or_none(user_id: int, addr_id: int) -> Optional[UserAddress]:
    addr = db.session.get(UserAddress, addr_id)
    if not addr or addr.user_id != user_id:
        return None
    return addr


# ============================================================
# Routes
# ============================================================


@address_bp.get("/addresses")
def addresses_page():
    guard = _login_required()
    if guard:
        return guard

    user = _current_user()
    if not user:
        session.clear()
        return redirect(url_for("auth.login", next=request.path))

    csrf = _ensure_csrf()

    items = (
        db.session.query(UserAddress)
        .filter_by(user_id=user.id)
        .order_by(UserAddress.is_default.desc(), UserAddress.id.desc())
        .all()
    )

    return render_template(
        "account/addresses.html",
        user=user,
        addresses=items,
        csrf_token=csrf,
    )


@address_bp.get("/addresses.json")
def addresses_json():
    guard = _login_required()
    if guard:
        return guard

    user = _current_user()
    if not user:
        return _json({"ok": False, "error": "session_invalid"}, 401)

    items = (
        db.session.query(UserAddress)
        .filter_by(user_id=user.id)
        .order_by(UserAddress.is_default.desc(), UserAddress.id.desc())
        .all()
    )
    return _json({"ok": True, "addresses": [_address_to_dict(a) for a in items]}, 200)


@address_bp.post("/addresses/new")
def address_create():
    guard = _login_required()
    if guard:
        return guard

    gate = _csrf_required()
    if gate:
        return gate

    if not _rate_limit("rl:addr_new", 2):
        return _json_or_redirect(
            {"ok": False, "error": "rate_limited", "status": 429},
            "address.addresses_page",
        )

    user = _current_user()
    if not user:
        return _json_or_redirect(
            {"ok": False, "error": "session_invalid", "status": 401}, "auth.login"
        )

    data = _payload_from_request()
    errors = _validate_payload(data)
    if errors:
        if _wants_json():
            return _json(
                {"ok": False, "error": "validation_failed", "fields": errors}, 400
            )
        flash("Revisá los datos de la dirección (faltan campos).", "warning")
        return redirect(url_for("address.addresses_page"))

    # ✅ Mejora extra #5: dedupe (firma simple)
    sig = f"{(data.get('line1') or '').lower()}|{(data.get('city') or '').lower()}|{(data.get('postal_code') or '').lower()}"
    if not _dedupe_guard(int(user.id), sig, ttl=10):
        return _json_or_redirect(
            {"ok": False, "error": "duplicate_request", "status": 409},
            "address.addresses_page",
        )

    try:
        # ✅ Mejora extra #4: transacción segura
        with db.session.begin():
            addr = UserAddress(user_id=user.id, **data)
            db.session.add(addr)
            db.session.flush()

            _normalize_default(
                user.id, preferred_id=addr.id if data.get("is_default") else None
            )

        # audit session (✅ mejora extra #6)
        session["addr_last_action"] = "create"
        session["addr_last_id"] = int(addr.id)

    except Exception as exc:
        current_app.logger.exception("Address create error: %s", exc)
        return _json_or_redirect(
            {"ok": False, "error": "save_failed", "status": 500},
            "address.addresses_page",
        )

    if _wants_json():
        return _json(
            {"ok": True, "created": True, "address": _address_to_dict(addr)}, 201
        )

    flash("Dirección guardada ✅", "success")
    return redirect(url_for("address.addresses_page"))


@address_bp.post("/addresses/<int:addr_id>/update")
def address_update(addr_id: int):
    guard = _login_required()
    if guard:
        return guard

    gate = _csrf_required()
    if gate:
        return gate

    if not _rate_limit("rl:addr_upd", 1):
        return _json_or_redirect(
            {"ok": False, "error": "rate_limited", "status": 429},
            "address.addresses_page",
        )

    user = _current_user()
    if not user:
        return _json_or_redirect(
            {"ok": False, "error": "session_invalid", "status": 401}, "auth.login"
        )

    addr = _get_user_address_or_none(user.id, addr_id)
    if not addr:
        return _json_or_redirect(
            {"ok": False, "error": "not_found", "status": 404}, "address.addresses_page"
        )

    data = _payload_from_request()
    errors = _validate_payload(data)
    if errors:
        if _wants_json():
            return _json(
                {"ok": False, "error": "validation_failed", "fields": errors}, 400
            )
        flash("Revisá los datos de la dirección (faltan campos).", "warning")
        return redirect(url_for("address.addresses_page"))

    try:
        with db.session.begin():
            for k, v in data.items():
                setattr(addr, k, v)

            _normalize_default(
                user.id, preferred_id=addr.id if data.get("is_default") else None
            )

        session["addr_last_action"] = "update"
        session["addr_last_id"] = int(addr.id)

    except Exception as exc:
        current_app.logger.exception("Address update error: %s", exc)
        return _json_or_redirect(
            {"ok": False, "error": "save_failed", "status": 500},
            "address.addresses_page",
        )

    if _wants_json():
        return _json(
            {"ok": True, "updated": True, "address": _address_to_dict(addr)}, 200
        )

    flash("Dirección actualizada ✅", "success")
    return redirect(url_for("address.addresses_page"))


@address_bp.post("/addresses/<int:addr_id>/delete")
def address_delete(addr_id: int):
    guard = _login_required()
    if guard:
        return guard

    gate = _csrf_required()
    if gate:
        return gate

    if not _rate_limit("rl:addr_del", 1):
        return _json_or_redirect(
            {"ok": False, "error": "rate_limited", "status": 429},
            "address.addresses_page",
        )

    user = _current_user()
    if not user:
        return _json_or_redirect(
            {"ok": False, "error": "session_invalid", "status": 401}, "auth.login"
        )

    addr = _get_user_address_or_none(user.id, addr_id)
    if not addr:
        return _json_or_redirect(
            {"ok": False, "error": "not_found", "status": 404}, "address.addresses_page"
        )

    was_default = bool(getattr(addr, "is_default", False))

    try:
        with db.session.begin():
            db.session.delete(addr)
            db.session.flush()

            # si borró default, reasignar
            if was_default:
                _normalize_default(user.id)

        session["addr_last_action"] = "delete"
        session["addr_last_id"] = int(addr_id)

    except Exception as exc:
        current_app.logger.exception("Address delete error: %s", exc)
        return _json_or_redirect(
            {"ok": False, "error": "delete_failed", "status": 500},
            "address.addresses_page",
        )

    if _wants_json():
        return _json({"ok": True, "deleted": True, "id": addr_id}, 200)

    flash("Dirección eliminada 🗑️", "success")
    return redirect(url_for("address.addresses_page"))


@address_bp.post("/addresses/<int:addr_id>/default")
def address_set_default(addr_id: int):
    guard = _login_required()
    if guard:
        return guard

    gate = _csrf_required()
    if gate:
        return gate

    if not _rate_limit("rl:addr_def", 1):
        return _json_or_redirect(
            {"ok": False, "error": "rate_limited", "status": 429},
            "address.addresses_page",
        )

    user = _current_user()
    if not user:
        return _json_or_redirect(
            {"ok": False, "error": "session_invalid", "status": 401}, "auth.login"
        )

    addr = _get_user_address_or_none(user.id, addr_id)
    if not addr:
        return _json_or_redirect(
            {"ok": False, "error": "not_found", "status": 404}, "address.addresses_page"
        )

    try:
        with db.session.begin():
            _normalize_default(user.id, preferred_id=addr.id)

        session["addr_last_action"] = "default"
        session["addr_last_id"] = int(addr.id)

    except Exception as exc:
        current_app.logger.exception("Set default error: %s", exc)
        return _json_or_redirect(
            {"ok": False, "error": "save_failed", "status": 500},
            "address.addresses_page",
        )

    if _wants_json():
        return _json({"ok": True, "default_set": True, "id": addr_id}, 200)

    flash("Dirección predeterminada ✅", "success")
    return redirect(url_for("address.addresses_page"))


@address_bp.get("/addresses/csrf")
def addresses_csrf_token():
    guard = _login_required()
    if guard:
        return guard
    return _json({"ok": True, "csrf_token": _ensure_csrf()}, 200)


__all__ = ["address_bp"]
