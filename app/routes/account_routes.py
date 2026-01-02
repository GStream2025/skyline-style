# app/routes/account_routes.py
from __future__ import annotations

import os
import re
import secrets
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from app.models import db, User, UserAddress, Order

# ============================================================
# Blueprints
# ============================================================

account_bp = Blueprint(
    "account",
    __name__,
    url_prefix="/account",
    template_folder="../templates",
)

# Alias /cuenta (sin url_prefix)
cuenta_bp = Blueprint("cuenta", __name__)


# ============================================================
# Flags / Config
# ============================================================

_TRUE = {"1", "true", "yes", "y", "on"}
_FALSE = {"0", "false", "no", "n", "off"}

REQUIRE_CSRF = (os.getenv("REQUIRE_CSRF", "1").strip().lower() in _TRUE)  # ✅ default ON
ACCOUNT_ALLOW_JSON = (os.getenv("ACCOUNT_ALLOW_JSON", "1").strip().lower() in _TRUE)

# Edad mínima para comprar (default 18)
MIN_AGE = int(os.getenv("MIN_AGE", "18") or "18")

# Limita updates de perfil (simple anti spam)
PROFILE_MAX_LEN = 120

# ============================================================
# Helpers — JSON / Templates / Seguridad
# ============================================================

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_\.]{3,24}$")
_PHONE_CLEAN_RE = re.compile(r"[^0-9\+\-\(\)\s]")


def _wants_json() -> bool:
    if not ACCOUNT_ALLOW_JSON:
        return False
    accept = (request.headers.get("Accept") or "").lower()
    ctype = (request.headers.get("Content-Type") or "").lower()
    return ("application/json" in accept) or ("application/json" in ctype) or (request.args.get("format") == "json")


def _json_or_html(payload: Dict[str, Any], html_fn):
    if _wants_json():
        return jsonify(payload)
    return html_fn()


def _template_exists(name: str) -> bool:
    try:
        current_app.jinja_env.get_template(name)
        return True
    except Exception:
        return False


def _is_safe_next(target: Optional[str]) -> bool:
    """Evita open-redirect: solo rutas internas."""
    if not target:
        return False
    target = target.strip()
    if not target.startswith("/"):
        return False
    ref = urlparse(request.host_url)
    test = urlparse(urljoin(request.host_url, target))
    return (test.scheme == ref.scheme) and (test.netloc == ref.netloc)


def _next_url(default: str = "/account") -> str:
    nxt = (request.args.get("next") or request.form.get("next") or "").strip()
    return nxt if _is_safe_next(nxt) else default


def _clear_session() -> None:
    try:
        session.clear()
    except Exception:
        for k in list(session.keys()):
            session.pop(k, None)


def _commit_or_rollback() -> bool:
    try:
        db.session.commit()
        return True
    except Exception:
        db.session.rollback()
        return False


def _csrf_token() -> str:
    tok = session.get("csrf_token")
    if not tok or not isinstance(tok, str) or len(tok) < 16:
        tok = secrets.token_urlsafe(32)
        session["csrf_token"] = tok
    return tok


def _csrf_ok() -> bool:
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return True
    if not REQUIRE_CSRF:
        return True
    sent = (request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or "").strip()
    stored = (session.get("csrf_token") or "").strip()
    return bool(sent) and bool(stored) and secrets.compare_digest(sent, stored)


@account_bp.before_request
def _before_account_request():
    # ✅ token siempre disponible para templates
    if request.method == "GET":
        _csrf_token()
        return None

    # ✅ valida CSRF en writes
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not _csrf_ok():
        if _wants_json():
            return jsonify(ok=False, error="csrf_failed"), 400
        flash("Sesión expirada o formulario inválido. Reintentá.", "error")
        return redirect(request.referrer or url_for("account.account_home"))


@account_bp.context_processor
def _inject_csrf():
    return {"csrf_token": session.get("csrf_token", "")}


def _get_current_user() -> Optional[User]:
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        uid_int = int(uid)
    except Exception:
        _clear_session()
        return None

    try:
        u = db.session.get(User, uid_int)
    except Exception:
        u = None

    if not u:
        _clear_session()
        return None

    # lock / inactive
    if hasattr(u, "is_active") and not bool(getattr(u, "is_active")):
        _clear_session()
        return None

    return u


def _is_admin_session(u: Optional[User]) -> bool:
    if u and bool(getattr(u, "is_admin", False)):
        return True
    v = session.get("is_admin", False)
    if isinstance(v, str):
        return v.strip().lower() in _TRUE
    return bool(v)


def _require_user() -> Tuple[Optional[User], Optional[Any]]:
    u = _get_current_user()
    if u:
        return u, None

    nxt = _next_url("/account")
    if _wants_json():
        return None, (jsonify(ok=False, error="login_required", next=nxt), 401)

    flash("Iniciá sesión para acceder a tu cuenta.", "info")
    return None, redirect(url_for("auth.login", next=nxt))


# ============================================================
# Validación / Normalización (perfil tipo MercadoLibre/Temu)
# ============================================================

def _clean_str(v: Any, max_len: int = 120) -> str:
    return ("" if v is None else str(v)).strip()[:max_len]


def _clean_phone(v: Any) -> str:
    s = _clean_str(v, 40)
    s = _PHONE_CLEAN_RE.sub("", s).strip()
    return s[:40]


def _clean_email(v: Any) -> str:
    s = _clean_str(v, 255).lower()
    if not s or not _EMAIL_RE.match(s):
        raise ValueError("Email inválido.")
    return s


def _clean_username(v: Any) -> str:
    s = _clean_str(v, 24)
    if not s:
        return ""
    if not _USERNAME_RE.match(s):
        raise ValueError("Usuario inválido (3–24, letras/números/._)")
    return s


def _parse_dob(v: Any) -> Optional[date]:
    s = _clean_str(v, 32)
    if not s:
        return None
    # acepta YYYY-MM-DD
    try:
        d = datetime.strptime(s, "%Y-%m-%d").date()
        return d
    except Exception:
        return None


def _age_years(dob: date) -> int:
    today = date.today()
    years = today.year - dob.year
    if (today.month, today.day) < (dob.month, dob.day):
        years -= 1
    return years


def _safe_setattr(model: Any, attr: str, value: Any) -> bool:
    """Setea solo si el modelo realmente tiene el atributo."""
    if hasattr(model, attr):
        try:
            setattr(model, attr, value)
            return True
        except Exception:
            return False
    return False


# ============================================================
# Account Home
# ============================================================

@account_bp.get("")
@account_bp.get("/")
def account_home():
    u = _get_current_user()
    nxt = _next_url("/account")

    if not u:
        def _html():
            if _template_exists("account/account_home.html"):
                return render_template("account/account_home.html", next=nxt)
            if _template_exists("account.html"):
                return render_template("account.html", next=nxt)
            return ("Login required", 401)

        return _json_or_html({"ok": False, "login_required": True, "next": nxt}, _html)

    # Admin: acceso rápido al panel
    if _is_admin_session(u):
        try:
            return redirect(url_for("admin.dashboard"))
        except Exception:
            return redirect("/admin")

    orders_count = 0
    try:
        orders_count = db.session.query(Order).filter(Order.user_id == u.id).count()
    except Exception:
        orders_count = 0

    def _html():
        if _template_exists("account/dashboard.html"):
            return render_template("account/dashboard.html", user=u, orders_count=orders_count)
        if _template_exists("account/home.html"):
            return render_template("account/home.html", user=u, orders_count=orders_count)
        if _template_exists("account.html"):
            return render_template("account.html", user=u, orders_count=orders_count)
        return ("OK", 200)

    return _json_or_html(
        {
            "ok": True,
            "user": {"id": u.id, "email": u.email, "name": getattr(u, "name", None)},
            "orders_count": orders_count,
        },
        _html,
    )


# ============================================================
# Profile — full (datos + edad + preferencias)
# ============================================================

@account_bp.get("/profile")
def profile_get():
    u, resp = _require_user()
    if resp:
        return resp

    def _html():
        if _template_exists("account/profile.html"):
            return render_template("account/profile.html", user=u)
        return redirect(url_for("account.account_home"))

    # Si existen columnas extra en User, las exponemos; si no, no rompe
    payload = {
        "ok": True,
        "user": {
            "email": getattr(u, "email", None),
            "name": getattr(u, "name", None),
            "username": getattr(u, "username", None),
            "phone": getattr(u, "phone", None),
            "country": getattr(u, "country", None),
            "city": getattr(u, "city", None),
            "email_verified": bool(getattr(u, "email_verified", False)),
            "dob": (getattr(u, "dob", None).isoformat() if getattr(u, "dob", None) else None),
            "age_verified": bool(getattr(u, "age_verified", False)),
            "marketing_opt_in": bool(getattr(u, "email_opt_in", True)),
            # preferido de pago (si existe)
            "preferred_payment": getattr(u, "preferred_payment", None),
            "preferred_payment_type": getattr(u, "preferred_payment_type", None),
        },
    }
    return _json_or_html(payload, _html)


@account_bp.post("/profile")
def profile_post():
    u, resp = _require_user()
    if resp:
        return resp

    # Campos base
    name = _clean_str(request.form.get("name"), 120) or None
    phone = _clean_phone(request.form.get("phone")) or None
    country = _clean_str(request.form.get("country"), 2).upper() or None
    city = _clean_str(request.form.get("city"), 80) or None

    # Extra (tipo marketplace)
    username_raw = request.form.get("username")
    dob_raw = request.form.get("dob")  # YYYY-MM-DD
    marketing_opt_in = (request.form.get("marketing_opt_in") or "").strip().lower() in _TRUE

    # Validaciones suaves
    try:
        username = _clean_username(username_raw) if username_raw is not None else ""
    except Exception as e:
        if _wants_json():
            return jsonify(ok=False, error="invalid_username", detail=str(e)), 400
        flash(str(e), "error")
        return redirect(url_for("account.profile_get"))

    dob = _parse_dob(dob_raw)
    if dob:
        age = _age_years(dob)
        if age < MIN_AGE:
            msg = f"Debés tener {MIN_AGE}+ para comprar. (Edad detectada: {age})"
            if _wants_json():
                return jsonify(ok=False, error="age_required", detail=msg), 400
            flash(msg, "error")
            return redirect(url_for("account.profile_get"))

    # Persistimos solo lo que exista en el modelo (NO rompe DB vieja)
    _safe_setattr(u, "name", name)
    _safe_setattr(u, "phone", phone)
    _safe_setattr(u, "country", country)
    _safe_setattr(u, "city", city)

    if username_raw is not None:
        _safe_setattr(u, "username", username or None)

    if dob_raw is not None:
        _safe_setattr(u, "dob", dob)
        _safe_setattr(u, "age_verified", True if dob else False)

    _safe_setattr(u, "email_opt_in", bool(marketing_opt_in))
    if bool(marketing_opt_in):
        # si existe
        _safe_setattr(u, "email_opt_in_at", datetime.utcnow())

    ok = _commit_or_rollback()

    if _wants_json():
        return jsonify(ok=ok)

    flash("Perfil actualizado ✅" if ok else "No se pudo actualizar el perfil.", "success" if ok else "error")
    return redirect(url_for("account.profile_get"))


# ============================================================
# Payments — /account/payments (método preferido + lista)
# - MercadoLibre/Temu style: guardar preferencia para checkout rápido
# ============================================================

def _get_available_payment_methods() -> List[Dict[str, Any]]:
    """
    Devuelve métodos disponibles para checkout.
    - Si existe PaymentProviderService: lo usa.
    - Si existe PaymentProvider: lo usa.
    - Si no: fallback seguro.
    """
    # 1) Service
    try:
        from app.models.payment_provider import PaymentProviderService  # type: ignore
        providers = PaymentProviderService.get_enabled_for_checkout()
        out = []
        for p in providers:
            out.append({
                "code": p.code,
                "name": p.get_label_for_checkout() if hasattr(p, "get_label_for_checkout") else p.name,
                "recommended": bool(getattr(p, "recommended", False)),
            })
        return out
    except Exception:
        pass

    # 2) Model directo
    try:
        from app.models.payment_provider import PaymentProvider  # type: ignore
        providers = (
            PaymentProvider.query
            .filter(PaymentProvider.enabled.is_(True))
            .order_by(PaymentProvider.recommended.desc(), PaymentProvider.sort_order.asc())
            .all()
        )
        out = []
        for p in providers:
            # si tiene validación real, filtramos
            ready = True
            try:
                ready = p.is_ready_for_checkout() if hasattr(p, "is_ready_for_checkout") else True
            except Exception:
                ready = True
            if not ready:
                continue
            out.append({
                "code": p.code,
                "name": p.get_label_for_checkout() if hasattr(p, "get_label_for_checkout") else p.name,
                "recommended": bool(getattr(p, "recommended", False)),
            })
        return out
    except Exception:
        pass

    # 3) Fallback
    return [
        {"code": "mercadopago_uy", "name": "Mercado Pago (UY)", "recommended": True},
        {"code": "paypal", "name": "PayPal", "recommended": False},
        {"code": "transferencia", "name": "Transferencia bancaria", "recommended": False},
    ]


@account_bp.get("/payments")
def payments_get():
    u, resp = _require_user()
    if resp:
        return resp

    methods = _get_available_payment_methods()

    preferred = getattr(u, "preferred_payment", None) or session.get("preferred_payment")
    preferred_type = getattr(u, "preferred_payment_type", None) or session.get("preferred_payment_type")

    def _html():
        # template recomendado
        if _template_exists("account/payments.html"):
            return render_template(
                "account/payments.html",
                user=u,
                methods=methods,
                preferred=preferred,
                preferred_type=preferred_type,
            )
        return redirect(url_for("account.account_home"))

    return _json_or_html(
        {
            "ok": True,
            "methods": methods,
            "preferred": preferred,
            "preferred_type": preferred_type,
        },
        _html,
    )


@account_bp.post("/payments")
def payments_post():
    u, resp = _require_user()
    if resp:
        return resp

    code = (_clean_str(request.form.get("preferred_payment"), 40) or "").lower()
    ptype = (_clean_str(request.form.get("preferred_payment_type"), 20) or "").lower()
    # ptype: debito/credito/mp/transfer/paypal/...
    if ptype and ptype not in {"debito", "credito", "mp", "transfer", "paypal", "otro"}:
        ptype = "otro"

    allowed_codes = {m["code"] for m in _get_available_payment_methods()}
    if code and code not in allowed_codes:
        if _wants_json():
            return jsonify(ok=False, error="invalid_payment_method"), 400
        flash("Método de pago inválido.", "error")
        return redirect(url_for("account.payments_get"))

    # Guardamos (DB si existe, si no -> session)
    saved_db = False
    if code:
        saved_db = _safe_setattr(u, "preferred_payment", code) or saved_db
    if ptype:
        saved_db = _safe_setattr(u, "preferred_payment_type", ptype) or saved_db

    if saved_db:
        ok = _commit_or_rollback()
    else:
        ok = True
        if code:
            session["preferred_payment"] = code
        if ptype:
            session["preferred_payment_type"] = ptype

    if _wants_json():
        return jsonify(ok=ok, preferred=code, preferred_type=ptype)

    flash("Preferencia de pago guardada ✅" if ok else "No se pudo guardar tu preferencia.", "success" if ok else "error")
    return redirect(url_for("account.payments_get"))


# ============================================================
# Addresses — CRUD + default PRO
# ============================================================

def _addr_to_dict(a: UserAddress) -> Dict[str, Any]:
    return {
        "id": a.id,
        "label": a.label,
        "full_name": a.full_name,
        "phone": a.phone,
        "line1": a.line1,
        "line2": a.line2,
        "city": a.city,
        "state": a.state,
        "postal_code": a.postal_code,
        "country": a.country,
        "is_default": bool(getattr(a, "is_default", False)),
    }


@account_bp.get("/addresses")
def addresses_get():
    u, resp = _require_user()
    if resp:
        return resp

    addrs: List[UserAddress] = []
    try:
        addrs = (
            db.session.query(UserAddress)
            .filter(UserAddress.user_id == u.id)
            .order_by(UserAddress.is_default.desc(), UserAddress.id.desc())
            .all()
        )
    except Exception:
        addrs = []

    def _html():
        if _template_exists("account/addresses.html"):
            return render_template("account/addresses.html", user=u, addresses=addrs)
        return redirect(url_for("account.account_home"))

    return _json_or_html({"ok": True, "addresses": [_addr_to_dict(a) for a in addrs]}, _html)


@account_bp.post("/addresses/new")
def addresses_new():
    u, resp = _require_user()
    if resp:
        return resp

    line1 = _clean_str(request.form.get("line1"), 200)
    if not line1:
        if _wants_json():
            return jsonify(ok=False, error="line1_required"), 400
        flash("Dirección (línea 1) es obligatoria.", "warning")
        return redirect(url_for("account.addresses_get"))

    is_default = (request.form.get("is_default") or "").strip().lower() in _TRUE

    a = UserAddress(
        user_id=u.id,
        label=_clean_str(request.form.get("label"), 50) or None,
        full_name=_clean_str(request.form.get("full_name"), 120) or None,
        phone=_clean_phone(request.form.get("phone")) or None,
        line1=line1,
        line2=_clean_str(request.form.get("line2"), 200) or None,
        city=_clean_str(request.form.get("city"), 120) or None,
        state=_clean_str(request.form.get("state"), 120) or None,
        postal_code=_clean_str(request.form.get("postal_code"), 40) or None,
        country=_clean_str(request.form.get("country"), 2).upper() or None,
        is_default=is_default,
    )

    try:
        db.session.add(a)
        db.session.flush()

        # primera dirección -> default
        any_other = (
            db.session.query(UserAddress.id)
            .filter(UserAddress.user_id == u.id, UserAddress.id != a.id)
            .first()
        )
        if not any_other:
            a.is_default = True

        if a.is_default:
            db.session.query(UserAddress).filter(
                UserAddress.user_id == u.id,
                UserAddress.id != a.id,
            ).update({"is_default": False}, synchronize_session=False)

        db.session.commit()

        if _wants_json():
            return jsonify(ok=True, address=_addr_to_dict(a))

        flash("Dirección guardada ✅", "success")
        return redirect(url_for("account.addresses_get"))
    except Exception:
        db.session.rollback()
        if _wants_json():
            return jsonify(ok=False, error="save_failed"), 500
        flash("No se pudo guardar la dirección.", "error")
        return redirect(url_for("account.addresses_get"))


@account_bp.post("/addresses/<int:addr_id>/default")
def addresses_set_default(addr_id: int):
    u, resp = _require_user()
    if resp:
        return resp

    try:
        a = db.session.get(UserAddress, addr_id)
    except Exception:
        a = None

    if not a or a.user_id != u.id:
        if _wants_json():
            return jsonify(ok=False, error="not_found"), 404
        flash("Dirección no encontrada.", "error")
        return redirect(url_for("account.addresses_get"))

    try:
        db.session.query(UserAddress).filter(UserAddress.user_id == u.id).update({"is_default": False}, synchronize_session=False)
        a.is_default = True
        db.session.commit()
        if _wants_json():
            return jsonify(ok=True)
        flash("Dirección por defecto ✅", "success")
    except Exception:
        db.session.rollback()
        if _wants_json():
            return jsonify(ok=False, error="update_failed"), 500
        flash("No se pudo actualizar la dirección.", "error")

    return redirect(url_for("account.addresses_get"))


@account_bp.post("/addresses/<int:addr_id>/delete")
def addresses_delete(addr_id: int):
    u, resp = _require_user()
    if resp:
        return resp

    try:
        a = db.session.get(UserAddress, addr_id)
    except Exception:
        a = None

    if not a or a.user_id != u.id:
        if _wants_json():
            return jsonify(ok=False, error="not_found"), 404
        flash("Dirección no encontrada.", "error")
        return redirect(url_for("account.addresses_get"))

    was_default = bool(getattr(a, "is_default", False))

    try:
        db.session.delete(a)
        db.session.flush()

        # si borró default, setea otra
        if was_default:
            next_addr = (
                db.session.query(UserAddress)
                .filter(UserAddress.user_id == u.id)
                .order_by(UserAddress.id.desc())
                .first()
            )
            if next_addr:
                next_addr.is_default = True

        db.session.commit()

        if _wants_json():
            return jsonify(ok=True)

        flash("Dirección eliminada 🗑️", "success")
    except Exception:
        db.session.rollback()
        if _wants_json():
            return jsonify(ok=False, error="delete_failed"), 500
        flash("No se pudo eliminar la dirección.", "error")

    return redirect(url_for("account.addresses_get"))


# ============================================================
# Orders — historial
# ============================================================

@account_bp.get("/orders")
def orders_get():
    u, resp = _require_user()
    if resp:
        return resp

    items: List[Order] = []
    try:
        items = (
            db.session.query(Order)
            .filter(Order.user_id == u.id)
            .order_by(Order.id.desc())
            .limit(200)
            .all()
        )
    except Exception:
        items = []

    def _html():
        if _template_exists("account/orders.html"):
            return render_template("account/orders.html", user=u, orders=items)
        return redirect(url_for("account.account_home"))

    return _json_or_html(
        {
            "ok": True,
            "orders": [
                {
                    "id": o.id,
                    "number": getattr(o, "number", None),
                    "status": getattr(o, "status", None),
                    "payment_status": getattr(o, "payment_status", None),
                    "total": str(getattr(o, "total", "0.00")),
                    "currency": getattr(o, "currency", None),
                    "created_at": (o.created_at.isoformat() if getattr(o, "created_at", None) else None),
                }
                for o in items
            ],
        },
        _html,
    )


# ============================================================
# Alias /cuenta (ES)
# ============================================================

@cuenta_bp.get("/cuenta")
def cuenta_alias():
    nxt = _next_url("/account")
    try:
        return redirect(url_for("account.account_home", next=nxt))
    except Exception:
        return redirect("/account")


__all__ = ["account_bp", "cuenta_bp"]
