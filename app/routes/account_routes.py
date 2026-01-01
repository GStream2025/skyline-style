# app/routes/account_routes.py
from __future__ import annotations

import os
import secrets
from urllib.parse import urlparse, urljoin
from typing import Optional, List, Dict, Any, Tuple, Union

from flask import (
    Blueprint,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
    current_app,
)

# ✅ SIEMPRE usar el db único del HUB
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
# Config / flags
# ============================================================

_TRUE = {"1", "true", "yes", "y", "on"}

# CSRF simple (sin dependencia extra). Recomendado: activarlo en prod.
# REQUIRE_CSRF=1 -> exige token en POST
REQUIRE_CSRF = (os.getenv("REQUIRE_CSRF", "0").strip().lower() in _TRUE)

# Si querés bloquear JSON en estas rutas (por seguridad), podés:
# ACCOUNT_ALLOW_JSON=0
ACCOUNT_ALLOW_JSON = (os.getenv("ACCOUNT_ALLOW_JSON", "1").strip().lower() in _TRUE)


# ============================================================
# Helpers — UX / JSON / Seguridad
# ============================================================

def _wants_json() -> bool:
    if not ACCOUNT_ALLOW_JSON:
        return False
    accept = (request.headers.get("Accept") or "").lower()
    ctype = (request.headers.get("Content-Type") or "").lower()
    return ("application/json" in accept) or ("application/json" in ctype) or (request.args.get("format") == "json")


def _json_or_html(json_payload: Dict[str, Any], html_fn):
    """Devuelve JSON si corresponde, sino HTML."""
    if _wants_json():
        return jsonify(json_payload)
    return html_fn()


def _template_exists(name: str) -> bool:
    try:
        current_app.jinja_env.get_template(name)
        return True
    except Exception:
        return False


def _is_safe_next(target: Optional[str]) -> bool:
    """Evita open-redirect: solo rutas internas del mismo host."""
    if not target:
        return False
    target = target.strip()
    if not target.startswith("/"):
        return False

    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return (test_url.scheme == ref_url.scheme and test_url.netloc == ref_url.netloc)


def _next_url(default: str = "/account") -> str:
    nxt = (request.args.get("next") or request.form.get("next") or "").strip()
    return nxt if _is_safe_next(nxt) else default


def _clear_session() -> None:
    try:
        session.clear()
    except Exception:
        # fallback ultra-safe
        for k in list(session.keys()):
            session.pop(k, None)


def _commit_or_rollback() -> bool:
    try:
        db.session.commit()
        return True
    except Exception:
        db.session.rollback()
        return False


def _get_current_user() -> Optional[User]:
    """User desde session; si está corrupta, limpia."""
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

    # account lock (si existe)
    if hasattr(u, "is_active") and not bool(getattr(u, "is_active")):
        _clear_session()
        return None

    return u


def _is_admin_session() -> bool:
    v = session.get("is_admin", False)
    if isinstance(v, str):
        return v.strip().lower() in _TRUE
    return bool(v)


def _require_user() -> Tuple[Optional[User], Optional[Any]]:
    """
    Devuelve (user, response).
    Si response != None, ya es redirect/json.
    """
    u = _get_current_user()
    if u:
        return u, None

    nxt = _next_url("/account")
    if _wants_json():
        return None, (jsonify(ok=False, error="login_required", next=nxt), 401)

    flash("Iniciá sesión para acceder a tu cuenta.", "info")
    return None, redirect(url_for("auth.login", next=request.path or nxt))


# ============================================================
# CSRF (simple, sin libs)
# ============================================================

def _csrf_token() -> str:
    tok = session.get("csrf_token")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf_token"] = tok
    return tok


def _csrf_check() -> bool:
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return True
    if not REQUIRE_CSRF:
        return True
    sent = (request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or "").strip()
    return bool(sent) and secrets.compare_digest(sent, session.get("csrf_token", "") or "")


@account_bp.before_app_request
def _csrf_guard():
    # genera token para templates
    if request.method == "GET":
        _csrf_token()
        return None

    # valida token en writes
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not _csrf_check():
        if _wants_json():
            return jsonify(ok=False, error="csrf_failed"), 400
        flash("Sesión expirada o formulario inválido (CSRF). Reintentá.", "error")
        return redirect(request.referrer or url_for("account.account_home"))
    return None


@account_bp.context_processor
def _inject_csrf():
    # disponible en templates como {{ csrf_token }}
    return {"csrf_token": session.get("csrf_token")}


# ============================================================
# Routes — Account Home
# ============================================================

@account_bp.get("")
@account_bp.get("/")
def account_home():
    """
    /account
    - No logueado: página de acceso
    - Logueado: dashboard cuenta (resumen)
    """
    u = _get_current_user()
    nxt = _next_url("/account")

    if not u:
        def _html():
            # soporta ambos nombres por compatibilidad
            if _template_exists("account/account_home.html"):
                return render_template("account/account_home.html", next=nxt)
            if _template_exists("account.html"):
                return render_template("account.html", next=nxt)
            # fallback mínimo
            return render_template("base.html", next=nxt) if _template_exists("base.html") else ("Login required", 401)

        return _json_or_html({"ok": False, "login_required": True, "next": nxt}, _html)

    # Admin: acceso rápido al panel
    if _is_admin_session() or bool(getattr(u, "is_admin", False)):
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
        return render_template("account.html", user=u, orders_count=orders_count) if _template_exists("account.html") else ("OK", 200)

    return _json_or_html(
        {
            "ok": True,
            "user": {"id": u.id, "email": u.email, "name": getattr(u, "name", None)},
            "orders_count": orders_count,
        },
        _html,
    )


# ============================================================
# Profile — editar datos
# ============================================================

@account_bp.get("/profile")
def profile_get():
    u, resp = _require_user()
    if resp:
        return resp

    def _html():
        if _template_exists("account/profile.html"):
            return render_template("account/profile.html", user=u)
        return render_template("account/dashboard.html", user=u) if _template_exists("account/dashboard.html") else ("OK", 200)

    return _json_or_html(
        {
            "ok": True,
            "user": {
                "email": u.email,
                "name": getattr(u, "name", None),
                "phone": getattr(u, "phone", None),
                "country": getattr(u, "country", None),
                "city": getattr(u, "city", None),
            },
        },
        _html,
    )


@account_bp.post("/profile")
def profile_post():
    u, resp = _require_user()
    if resp:
        return resp

    name = (request.form.get("name") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    country = (request.form.get("country") or "").strip()
    city = (request.form.get("city") or "").strip()

    # saneo + límites seguros
    u.name = name[:120] if name else None
    u.phone = phone[:40] if phone else None
    u.country = country[:2].upper() if country else None
    u.city = city[:80] if city else None

    ok = _commit_or_rollback()

    if _wants_json():
        return jsonify(ok=ok)

    flash("Perfil actualizado ✅" if ok else "No se pudo actualizar el perfil.", "success" if ok else "error")
    return redirect(url_for("account.profile_get"))


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
        return ("OK", 200)

    return _json_or_html({"ok": True, "addresses": [_addr_to_dict(a) for a in addrs]}, _html)


@account_bp.post("/addresses/new")
def addresses_new():
    u, resp = _require_user()
    if resp:
        return resp

    line1 = (request.form.get("line1") or "").strip()
    if not line1:
        if _wants_json():
            return jsonify(ok=False, error="line1_required"), 400
        flash("Dirección (línea 1) es obligatoria.", "warning")
        return redirect(url_for("account.addresses_get"))

    is_default = (request.form.get("is_default") or "").strip().lower() in _TRUE

    a = UserAddress(
        user_id=u.id,
        label=(request.form.get("label") or "").strip()[:50] or None,
        full_name=(request.form.get("full_name") or "").strip()[:120] or None,
        phone=(request.form.get("phone") or "").strip()[:40] or None,
        line1=line1[:200],
        line2=(request.form.get("line2") or "").strip()[:200] or None,
        city=(request.form.get("city") or "").strip()[:120] or None,
        state=(request.form.get("state") or "").strip()[:120] or None,
        postal_code=(request.form.get("postal_code") or "").strip()[:40] or None,
        country=((request.form.get("country") or "").strip()[:2].upper() or None),
        is_default=is_default,
    )

    try:
        db.session.add(a)
        db.session.flush()  # ✅ asegura a.id

        # Si es la primera dirección del usuario, la hacemos default automáticamente
        try:
            any_other = (
                db.session.query(UserAddress.id)
                .filter(UserAddress.user_id == u.id, UserAddress.id != a.id)
                .first()
            )
            if not any_other:
                a.is_default = True
        except Exception:
            pass

        # Si va a quedar default, desmarcamos las otras
        if a.is_default:
            db.session.query(UserAddress).filter(
                UserAddress.user_id == u.id,
                UserAddress.id != a.id,
            ).update({"is_default": False})

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

    a = None
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
        db.session.query(UserAddress).filter(UserAddress.user_id == u.id).update({"is_default": False})
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

    a = None
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

        # Si borró la default, seteamos otra como default automáticamente (la más nueva)
        if was_default:
            try:
                next_addr = (
                    db.session.query(UserAddress)
                    .filter(UserAddress.user_id == u.id)
                    .order_by(UserAddress.id.desc())
                    .first()
                )
                if next_addr:
                    next_addr.is_default = True
            except Exception:
                pass

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
# Orders — historial (mínimo viable PRO)
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
        return ("OK", 200)

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
    # conserva next pero blindado
    try:
        return redirect(url_for("account.account_home", next=nxt))
    except Exception:
        return redirect("/account")


__all__ = ["account_bp", "cuenta_bp"]
