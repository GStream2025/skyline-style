# app/routes/admin_payments_routes.py — Skyline Admin Payments (ULTRA PRO / FINAL / NO BREAK)
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
    jsonify,
    current_app,
)

from app.models import db

# Modelos pagos (si existen)
try:
    from app.models.payment_provider import PaymentProvider, PaymentProviderService  # type: ignore
except Exception:
    PaymentProvider = None  # type: ignore
    PaymentProviderService = None  # type: ignore


admin_payments_bp = Blueprint("admin_payments", __name__, url_prefix="/admin")

_TRUE = {"1", "true", "yes", "y", "on", "checked"}


# ============================================================
# Helpers base (PRO)
# ============================================================

def _wants_json() -> bool:
    p = (request.path or "").lower()
    if p.startswith("/api/"):
        return True
    accept = (request.headers.get("Accept") or "").lower()
    if "application/json" in accept:
        return True
    if (request.headers.get("X-Requested-With") or "").lower() == "xmlhttprequest":
        return True
    return False


def _json(payload: Dict[str, Any], status: int = 200):
    return jsonify(payload), status


def _client_ip() -> str:
    xf = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    if xf:
        return xf[:64]
    return (request.remote_addr or "")[:64]


def _commit_safe() -> bool:
    try:
        db.session.commit()
        return True
    except Exception:
        db.session.rollback()
        return False


def _read_bool(name: str) -> bool:
    return (request.form.get(name) or "").strip().lower() in _TRUE


def _read_int(name: str, default: int = 0) -> int:
    try:
        return int((request.form.get(name) or "").strip())
    except Exception:
        return default


def _read_str(name: str, max_len: int = 500) -> str:
    return (request.form.get(name) or "").strip()[:max_len]


def _clamp_int(v: int, lo: int, hi: int) -> int:
    if v < lo:
        return lo
    if v > hi:
        return hi
    return v


def _normalize_code(code: str) -> str:
    return (code or "").strip().lower().replace(" ", "_").replace("-", "_")


def _safe_redirect(endpoint: str, **values):
    """
    ✅ Mejora: nunca rompe si falta el endpoint
    """
    try:
        return redirect(url_for(endpoint, **values))
    except Exception:
        return redirect("/")


def _audit_user_email() -> str:
    """
    ✅ Mejora: unifica de dónde sale el email del admin
    """
    try:
        uid = int(session.get("user_id") or 0)
        if uid:
            from app.models import User  # import local
            u = db.session.get(User, uid)
            if u:
                return (getattr(u, "email", "") or "").lower()[:120]
    except Exception:
        pass
    return (session.get("user_email") or "")[:120]


# ============================================================
# Security gates (ULTRA)
# ============================================================

def _csrf_ok() -> bool:
    """
    CSRF PRO:
    - create_app asegura session['csrf_token']
    - Validamos header configurable + hidden input
    """
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return True

    header_name = (current_app.config.get("CSRF_HEADER") or "X-CSRF-Token").strip()
    sent = (request.headers.get(header_name) or request.form.get("csrf_token") or "").strip()
    tok = (session.get("csrf_token") or "").strip()

    try:
        import secrets
        return bool(tok) and bool(sent) and secrets.compare_digest(tok, sent)
    except Exception:
        return False


def _admin_required():
    """
    Gate PRO:
    - requiere login
    - requiere is_admin en session
    - fallback: verifica en DB por si session quedó vieja
    """
    uid = session.get("user_id")
    if not uid:
        if _wants_json():
            return _json({"ok": False, "error": "auth_required"}, 401)
        flash("Iniciá sesión para entrar al admin.", "warning")
        return _safe_redirect("auth.login", next=request.path)

    if bool(session.get("is_admin")):
        return None

    # fallback: validar contra DB (owner/admin)
    try:
        from app.models import User  # import local para no romper imports
        u = db.session.get(User, int(uid))
        if u and (bool(getattr(u, "is_admin", False)) or bool(getattr(u, "is_owner", False))):
            session["is_admin"] = True
            session["user_email"] = (getattr(u, "email", "") or "").lower()
            return None
    except Exception:
        pass

    if _wants_json():
        return _json({"ok": False, "error": "forbidden"}, 403)

    flash("No tenés permisos para acceder al admin.", "error")
    return _safe_redirect("main.home")


def _rate_limit(key: str, seconds: float = 0.6) -> bool:
    """
    ✅ Mejora: rate-limit por acción, evita doble submit / spam
    """
    now = time.time()
    last = session.get(key, 0)
    try:
        last = float(last)
    except Exception:
        last = 0.0
    if (now - last) < seconds:
        return False
    session[key] = now
    return True


# ============================================================
# Provider helpers (PRO)
# ============================================================

def _payments_available() -> bool:
    return PaymentProvider is not None and PaymentProviderService is not None


def _bootstrap_defaults_if_needed() -> None:
    """
    Crea providers base si faltan (NO habilita nada).
    Se puede llamar sin miedo.
    """
    if not _payments_available():
        return
    try:
        PaymentProviderService.bootstrap_defaults()  # type: ignore[attr-defined]
    except Exception:
        pass


def _get_provider_by_code(code: str):
    if PaymentProvider is None:
        return None
    c = _normalize_code(code)
    return PaymentProvider.query.filter_by(code=c).first()  # type: ignore[attr-defined]


def _safe_checkout_url() -> str:
    """
    No rompe si no existe shop.checkout.
    """
    try:
        return url_for("shop.checkout")
    except Exception:
        try:
            return url_for("main.home")
        except Exception:
            return "/"


def _provider_to_ui_dict(p) -> Dict[str, Any]:
    """
    ✅ Mejora: UI dict uniforme + schema siempre presente
    """
    try:
        prev = p.admin_preview()
    except Exception:
        try:
            prev = p.as_dict(masked=True)
        except Exception:
            prev = {"code": getattr(p, "code", ""), "name": getattr(p, "name", "Provider")}

    try:
        prev.setdefault("schema", p.config_schema_for(getattr(p, "code", "")))
    except Exception:
        prev.setdefault("schema", [])

    # ✅ Mejora: defaults seguros para template (evita KeyError por campos faltantes)
    prev.setdefault("enabled", bool(getattr(p, "enabled", False)))
    prev.setdefault("recommended", bool(getattr(p, "recommended", False)))
    prev.setdefault("sort_order", int(getattr(p, "sort_order", 100) or 100))
    prev.setdefault("kind", getattr(p, "kind", "other") or "other")
    prev.setdefault("country", getattr(p, "country", "UY") or "UY")
    prev.setdefault("notes", getattr(p, "notes", "") or "")
    prev.setdefault("config", prev.get("config") or {})
    prev.setdefault("ready", bool(prev.get("ready", False)))
    prev.setdefault("errors", prev.get("errors") or [])
    return prev


def _sanitize_cfg(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    ✅ Mejora: limpia JSON para no guardar basura
    - borra keys vacías
    - recorta strings largas
    """
    out: Dict[str, Any] = {}
    for k, v in (cfg or {}).items():
        if v is None:
            continue
        if isinstance(v, str):
            vv = v.strip()
            if not vv:
                continue
            out[k] = vv[:500]
            continue
        out[k] = v
    return out


# ============================================================
# Routes (ULTRA)
# ============================================================

@admin_payments_bp.get("/payments")
def admin_payments_page():
    guard = _admin_required()
    if guard:
        return guard

    if not _payments_available():
        flash("Módulo de pagos no disponible: falta PaymentProvider/Service.", "error")
        return _safe_redirect("admin.dashboard")

    _bootstrap_defaults_if_needed()

    providers = (
        PaymentProvider.query  # type: ignore[attr-defined]
        .order_by(
            PaymentProvider.enabled.desc(),       # type: ignore[attr-defined]
            PaymentProvider.recommended.desc(),   # type: ignore[attr-defined]
            PaymentProvider.sort_order.asc(),     # type: ignore[attr-defined]
            PaymentProvider.name.asc(),           # type: ignore[attr-defined]
        )
        .all()
    )

    items: List[Dict[str, Any]] = [_provider_to_ui_dict(p) for p in providers]

    # ✅ Mejora: stats arriba para UI (sirve para badges/resumen)
    stats = {
        "total": len(items),
        "enabled": sum(1 for x in items if x.get("enabled")),
        "ready": sum(1 for x in items if x.get("ready")),
        "recommended": sum(1 for x in items if x.get("recommended")),
    }

    return render_template(
        "admin/payments.html",
        providers=items,
        checkout_url=_safe_checkout_url(),
        csrf_token=(session.get("csrf_token") or ""),
        stats=stats,
    )


@admin_payments_bp.post("/payments/<code>/save")
def admin_payments_save(code: str):
    guard = _admin_required()
    if guard:
        return guard

    if not _csrf_ok():
        if _wants_json():
            return _json({"ok": False, "error": "csrf_invalid"}, 400)
        flash("CSRF inválido. Recargá la página e intentá de nuevo.", "warning")
        return _safe_redirect("admin_payments.admin_payments_page")

    # ✅ Mejora: rate-limit por proveedor (anti doble submit por método)
    norm_code = _normalize_code(code)
    rl_key = f"rl:admin_payments_save:{norm_code}"
    if not _rate_limit(rl_key, seconds=0.6):
        if _wants_json():
            return _json({"ok": False, "error": "rate_limited"}, 429)
        flash("Muy rápido 😅 Esperá un segundo y reintentá.", "warning")
        return _safe_redirect("admin_payments.admin_payments_page")

    if not _payments_available():
        if _wants_json():
            return _json({"ok": False, "error": "payments_not_ready"}, 500)
        flash("Payments no disponibles.", "error")
        return _safe_redirect("admin_payments.admin_payments_page")

    p = _get_provider_by_code(norm_code)
    if not p:
        if _wants_json():
            return _json({"ok": False, "error": "not_found"}, 404)
        flash("Método no encontrado.", "error")
        return _safe_redirect("admin_payments.admin_payments_page")

    # ---------- básicos ----------
    enabled = _read_bool("enabled")
    recommended = _read_bool("recommended")

    # ✅ Mejora: no permitir recommended si está disabled (evita estado UI raro)
    if not enabled and recommended:
        recommended = False

    p.enabled = enabled
    p.recommended = recommended

    p.sort_order = _clamp_int(_read_int("sort_order", 100), 0, 9999)

    kind = (_read_str("kind", 20) or getattr(p, "kind", "other")).lower().strip()
    p.kind = (kind[:20] if kind else (getattr(p, "kind", "other") or "other"))

    country = (_read_str("country", 2) or getattr(p, "country", "UY")).upper().strip()
    p.country = (country[:2] if len(country) == 2 else "UY")

    p.fee_percent = _clamp_int(_read_int("fee_percent", 0), 0, 100)
    p.eta_minutes = _clamp_int(_read_int("eta_minutes", 0), 0, 100000)

    min_amount = _clamp_int(_read_int("min_amount", 0), 0, 1_000_000_000)
    max_amount = _clamp_int(_read_int("max_amount", 0), 0, 1_000_000_000)

    # ✅ Mejora: si max < min y max != 0, lo corregimos
    if max_amount != 0 and max_amount < min_amount:
        max_amount = min_amount

    p.min_amount = min_amount
    p.max_amount = max_amount

    p.notes = _read_str("notes", 500)

    # ---------- config schema-driven ----------
    try:
        cfg = dict(p.ensure_config())
    except Exception:
        cfg = {}

    try:
        schema = p.config_schema_for(p.code)
    except Exception:
        schema = []

    for f in schema:
        k = (f.get("key") or "").strip()
        typ = (f.get("type") or "text").strip().lower()
        if not k:
            continue

        field_name = f"cfg__{k}"

        if typ == "bool":
            cfg[k] = _read_bool(field_name)
        else:
            val = _read_str(field_name, 500)

            # ✅ Mejora: si vacío, lo borramos (no ensucia JSON)
            if val == "":
                cfg.pop(k, None)
            else:
                cfg[k] = val

    # ✅ Mejora: limpieza final (anti basura / strings vacías)
    cfg = _sanitize_cfg(cfg)

    # Guardar + validar (pero NO perder datos aunque falte algo)
    try:
        p.config = cfg
        ok, errs = p.validate_config()
    except Exception as e:
        db.session.rollback()
        if _wants_json():
            return _json({"ok": False, "error": "config_invalid", "message": str(e)}, 400)
        flash(f"Config inválida: {e}", "error")
        return _safe_redirect("admin_payments.admin_payments_page")

    # ✅ Mejora: si activó enabled pero no está listo, no lo apagamos,
    # lo dejamos enabled pero queda "ready=false" y avisamos (UX pro).
    # (Si querés modo estricto: apagarlo acá cuando ok==False)

    # Auditoría
    p.updated_by = _audit_user_email()
    try:
        p.updated_ip = _client_ip()
    except Exception:
        pass

    if not _commit_safe():
        if _wants_json():
            return _json({"ok": False, "error": "save_failed"}, 500)
        flash("No se pudo guardar. Reintentá.", "error")
        return _safe_redirect("admin_payments.admin_payments_page")

    # Respuesta PRO
    if _wants_json():
        prev = _provider_to_ui_dict(p)
        return _json(
            {
                "ok": True,
                "saved": True,
                "ready": bool(getattr(p, "enabled", False) and ok),
                "errors": errs if not ok else [],
                "provider": prev,
            },
            200,
        )

    if ok:
        flash("Método actualizado ✅ (listo para checkout)", "success")
    else:
        flash("Guardado ✅ pero falta completar: " + " | ".join(errs), "warning")

    return _safe_redirect("admin_payments.admin_payments_page")


__all__ = ["admin_payments_bp"]
