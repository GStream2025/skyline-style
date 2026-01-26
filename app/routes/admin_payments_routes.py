from __future__ import annotations

import time
from typing import Any, Dict, List, Mapping, Optional, Tuple
from urllib.parse import urlencode

from flask import (
    Blueprint,
    Response,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from app.models import db

try:
    from app.models.payment_provider import PaymentProvider, PaymentProviderService  # type: ignore
except Exception:
    PaymentProvider = None  # type: ignore
    PaymentProviderService = None  # type: ignore


admin_payments_bp = Blueprint("admin_payments", __name__, url_prefix="/admin")

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_MAX_CODE = 64
_MAX_EMAIL = 160
_MAX_IP = 64
_MAX_STR = 500
_MAX_CFG_STR = 800
_RL_DEFAULT_SEC = 0.6


def _wants_json() -> bool:
    try:
        if request.is_json:
            return True
        if (request.args.get("format") or "").strip().lower() == "json":
            return True
        p = (request.path or "").lower()
        if p.startswith("/api/"):
            return True
        accept = (request.headers.get("Accept") or "").lower()
        if "application/json" in accept:
            return True
        if (request.headers.get("X-Requested-With") or "").lower() == "xmlhttprequest":
            return True
        best = request.accept_mimetypes.best_match(["application/json", "text/html"])
        if best == "application/json" and request.accept_mimetypes[best] > request.accept_mimetypes["text/html"]:
            return True
    except Exception:
        return False
    return False


def _json(payload: Dict[str, Any], status: int = 200) -> Tuple[Response, int]:
    return jsonify(payload), int(status)


def _client_ip() -> str:
    try:
        xf = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        if xf:
            return xf[:_MAX_IP]
    except Exception:
        pass
    return (request.remote_addr or "")[:_MAX_IP]


def _commit_safe() -> bool:
    try:
        db.session.commit()
        return True
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        return False


def _read_form(name: str) -> str:
    try:
        return (request.form.get(name) or "").strip()
    except Exception:
        return ""


def _read_bool(name: str) -> bool:
    return _read_form(name).lower() in _TRUE


def _read_int(name: str, default: int = 0) -> int:
    v = _read_form(name)
    if not v:
        return default
    try:
        return int(v)
    except Exception:
        return default


def _read_str(name: str, max_len: int = _MAX_STR) -> str:
    s = _read_form(name)
    if not s:
        return ""
    return s[: max(0, int(max_len))]


def _clamp_int(v: int, lo: int, hi: int) -> int:
    if v < lo:
        return lo
    if v > hi:
        return hi
    return v


def _normalize_code(code: str) -> str:
    c = (code or "").strip().lower().replace(" ", "_").replace("-", "_")
    c = "".join(ch for ch in c if ch.isalnum() or ch == "_")
    return c[:_MAX_CODE]


def _safe_redirect(endpoint: str, **values):
    try:
        return redirect(url_for(endpoint, **values))
    except Exception:
        try:
            return redirect(url_for("main.home"))
        except Exception:
            return redirect("/")


def _safe_redirect_path(path: str):
    p = (path or "").strip()
    if not p.startswith("/") or p.startswith("//") or any(c in p for c in ("\x00", "\r", "\n", "\\")):
        p = "/"
    return redirect(p)


def _audit_user_email() -> str:
    try:
        uid = int(session.get("user_id") or 0)
        if uid:
            from app.models import User  # local import

            u = db.session.get(User, uid)
            if u:
                em = (getattr(u, "email", "") or "").strip().lower()
                return em[:_MAX_EMAIL]
    except Exception:
        pass
    em2 = (session.get("user_email") or "").strip().lower()
    return em2[:_MAX_EMAIL]


def _csrf_ok() -> bool:
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return True

    try:
        header_name = (current_app.config.get("CSRF_HEADER") or "X-CSRF-Token").strip()
    except Exception:
        header_name = "X-CSRF-Token"

    sent = ""
    try:
        sent = (request.headers.get(header_name) or request.form.get("csrf_token") or "").strip()
    except Exception:
        sent = ""

    tok = (session.get("csrf_token") or "").strip()
    if not tok or not sent:
        return False

    try:
        import secrets as _secrets

        return _secrets.compare_digest(tok, sent)
    except Exception:
        return False


def _admin_required():
    uid = session.get("user_id")
    if not uid:
        if _wants_json():
            return _json({"ok": False, "error": "auth_required"}, 401)
        flash("Iniciá sesión para entrar al admin.", "warning")
        try:
            return _safe_redirect("auth.login", next=request.path)
        except Exception:
            return _safe_redirect_path("/auth/login?" + urlencode({"next": request.path}))

    if bool(session.get("is_admin")):
        return None

    try:
        from app.models import User  # local import

        u = db.session.get(User, int(uid))
        if u and (bool(getattr(u, "is_admin", False)) or bool(getattr(u, "is_owner", False))):
            session["is_admin"] = True
            session["user_email"] = (getattr(u, "email", "") or "").lower()[:_MAX_EMAIL]
            return None
    except Exception:
        pass

    if _wants_json():
        return _json({"ok": False, "error": "forbidden"}, 403)

    flash("No tenés permisos para acceder al admin.", "error")
    return _safe_redirect("main.home")


def _rate_limit(key: str, seconds: float = _RL_DEFAULT_SEC) -> bool:
    now = time.time()
    try:
        last = float(session.get(key, 0) or 0)
    except Exception:
        last = 0.0
    if (now - last) < float(seconds):
        return False
    session[key] = now
    return True


def _payments_available() -> bool:
    return PaymentProvider is not None and PaymentProviderService is not None


def _bootstrap_defaults_if_needed() -> None:
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
    try:
        return PaymentProvider.query.filter_by(code=c).first()  # type: ignore[attr-defined]
    except Exception:
        return None


def _safe_checkout_url() -> str:
    for ep in ("shop.checkout", "checkout.checkout", "main.home"):
        try:
            return url_for(ep)
        except Exception:
            continue
    return "/"


def _as_mapping(v: Any) -> Dict[str, Any]:
    if isinstance(v, dict):
        return dict(v)
    if isinstance(v, Mapping):
        return dict(v)
    return {}


def _provider_to_ui_dict(p) -> Dict[str, Any]:
    prev: Dict[str, Any] = {}
    try:
        prev = _as_mapping(p.admin_preview())
    except Exception:
        try:
            prev = _as_mapping(p.as_dict(masked=True))
        except Exception:
            prev = {
                "code": getattr(p, "code", "") or "",
                "name": getattr(p, "name", "Provider") or "Provider",
            }

    try:
        prev.setdefault("schema", p.config_schema_for(getattr(p, "code", "")))
    except Exception:
        prev.setdefault("schema", [])

    prev.setdefault("code", getattr(p, "code", "") or "")
    prev.setdefault("name", getattr(p, "name", "") or prev.get("code") or "Provider")
    prev.setdefault("enabled", bool(getattr(p, "enabled", False)))
    prev.setdefault("recommended", bool(getattr(p, "recommended", False)))
    prev.setdefault("sort_order", int(getattr(p, "sort_order", 100) or 100))
    prev.setdefault("kind", getattr(p, "kind", "other") or "other")
    prev.setdefault("country", getattr(p, "country", "UY") or "UY")
    prev.setdefault("notes", getattr(p, "notes", "") or "")
    prev.setdefault("config", _as_mapping(prev.get("config") or getattr(p, "config", {}) or {}))
    prev.setdefault("ready", bool(prev.get("ready", False)))
    prev.setdefault("errors", list(prev.get("errors") or []))
    return prev


def _sanitize_cfg(cfg: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in (cfg or {}).items():
        kk = (str(k) if k is not None else "").strip()
        if not kk:
            continue
        if v is None:
            continue
        if isinstance(v, str):
            vv = v.strip()
            if not vv:
                continue
            out[kk] = vv[:_MAX_CFG_STR]
        else:
            out[kk] = v
    return out


def _set_if_exists(obj: Any, field: str, value: Any) -> None:
    try:
        if hasattr(obj, field):
            setattr(obj, field, value)
    except Exception:
        pass


def _get_schema(p) -> List[Dict[str, Any]]:
    try:
        sch = p.config_schema_for(p.code)
    except Exception:
        return []
    if isinstance(sch, list):
        out: List[Dict[str, Any]] = []
        for item in sch:
            if isinstance(item, dict):
                out.append(item)
        return out
    return []


@admin_payments_bp.get("/payments")
def admin_payments_page():
    guard = _admin_required()
    if guard:
        return guard

    if not _payments_available():
        flash("Módulo de pagos no disponible (faltan modelos PaymentProvider/Service).", "error")
        return _safe_redirect("admin.dashboard")

    _bootstrap_defaults_if_needed()

    try:
        providers = PaymentProvider.query.order_by(  # type: ignore[attr-defined]
            PaymentProvider.enabled.desc(),  # type: ignore[attr-defined]
            PaymentProvider.recommended.desc(),  # type: ignore[attr-defined]
            PaymentProvider.sort_order.asc(),  # type: ignore[attr-defined]
            PaymentProvider.name.asc(),  # type: ignore[attr-defined]
        ).all()
    except Exception as e:
        current_app.logger.exception("Error listando providers: %s", e)
        flash("No se pudieron cargar los métodos de pago.", "error")
        return _safe_redirect("admin.dashboard")

    items: List[Dict[str, Any]] = [_provider_to_ui_dict(p) for p in (providers or [])]

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

    norm_code = _normalize_code(code)

    if not _csrf_ok():
        if _wants_json():
            return _json({"ok": False, "error": "csrf_invalid"}, 400)
        flash("CSRF inválido. Recargá la página e intentá de nuevo.", "warning")
        return _safe_redirect("admin_payments.admin_payments_page")

    if not _rate_limit(f"rl:admin_payments_save:{norm_code}", seconds=_RL_DEFAULT_SEC):
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

    enabled = _read_bool("enabled")
    recommended = _read_bool("recommended")
    if not enabled and recommended:
        recommended = False

    sort_order = _clamp_int(_read_int("sort_order", int(getattr(p, "sort_order", 100) or 100)), 0, 9999)
    kind_in = (_read_str("kind", 20) or (getattr(p, "kind", "other") or "other")).lower().strip()
    kind = (kind_in[:20] if kind_in else "other") or "other"

    country_in = (_read_str("country", 2) or (getattr(p, "country", "UY") or "UY")).upper().strip()
    country = country_in if len(country_in) == 2 and country_in.isalpha() else "UY"

    fee_percent = _clamp_int(_read_int("fee_percent", int(getattr(p, "fee_percent", 0) or 0)), 0, 100)
    eta_minutes = _clamp_int(_read_int("eta_minutes", int(getattr(p, "eta_minutes", 0) or 0)), 0, 100000)

    min_amount = _clamp_int(_read_int("min_amount", int(getattr(p, "min_amount", 0) or 0)), 0, 1_000_000_000)
    max_amount = _clamp_int(_read_int("max_amount", int(getattr(p, "max_amount", 0) or 0)), 0, 1_000_000_000)
    if max_amount != 0 and max_amount < min_amount:
        max_amount = min_amount

    notes = _read_str("notes", _MAX_STR)

    _set_if_exists(p, "enabled", bool(enabled))
    _set_if_exists(p, "recommended", bool(recommended))
    _set_if_exists(p, "sort_order", int(sort_order))
    _set_if_exists(p, "kind", kind)
    _set_if_exists(p, "country", country)
    _set_if_exists(p, "fee_percent", int(fee_percent))
    _set_if_exists(p, "eta_minutes", int(eta_minutes))
    _set_if_exists(p, "min_amount", int(min_amount))
    _set_if_exists(p, "max_amount", int(max_amount))
    _set_if_exists(p, "notes", notes)

    cfg: Dict[str, Any] = {}
    try:
        cfg = dict(p.ensure_config())
    except Exception:
        try:
            cfg = dict(getattr(p, "config", {}) or {})
        except Exception:
            cfg = {}

    schema = _get_schema(p)
    for f in schema:
        k = (f.get("key") or "").strip()
        typ = (f.get("type") or "text").strip().lower()
        if not k:
            continue

        field_name = f"cfg__{k}"
        if typ == "bool":
            cfg[k] = _read_bool(field_name)
            continue

        val = _read_str(field_name, _MAX_CFG_STR)
        if val == "":
            cfg.pop(k, None)
        else:
            cfg[k] = val

    cfg = _sanitize_cfg(cfg)

    ok = True
    errs: List[str] = []
    try:
        _set_if_exists(p, "config", cfg)
        vres = p.validate_config()
        if isinstance(vres, tuple) and len(vres) == 2:
            ok = bool(vres[0])
            errs = list(vres[1] or [])
        elif isinstance(vres, bool):
            ok = bool(vres)
            errs = []
        else:
            ok = True
            errs = []
    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        if _wants_json():
            return _json({"ok": False, "error": "config_invalid", "message": str(e)}, 400)
        flash(f"Config inválida: {e}", "error")
        return _safe_redirect("admin_payments.admin_payments_page")

    _set_if_exists(p, "updated_by", _audit_user_email())
    _set_if_exists(p, "updated_ip", _client_ip())

    try:
        db.session.flush()
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        if _wants_json():
            return _json({"ok": False, "error": "save_failed"}, 500)
        flash("No se pudo guardar. Reintentá.", "error")
        return _safe_redirect("admin_payments.admin_payments_page")

    if not _commit_safe():
        if _wants_json():
            return _json({"ok": False, "error": "save_failed"}, 500)
        flash("No se pudo guardar. Reintentá.", "error")
        return _safe_redirect("admin_payments.admin_payments_page")

    if _wants_json():
        prev = _provider_to_ui_dict(p)
        ready = bool(getattr(p, "enabled", False)) and bool(ok)
        return _json(
            {
                "ok": True,
                "saved": True,
                "code": norm_code,
                "ready": ready,
                "errors": errs if not ok else [],
                "provider": prev,
            },
            200,
        )

    if ok and bool(getattr(p, "enabled", False)):
        flash("Método actualizado ✅ (listo para checkout)", "success")
    elif ok:
        flash("Guardado ✅", "success")
    else:
        msg = "Guardado ✅ pero falta completar: " + " | ".join(str(x) for x in (errs or ["config incompleta"]))
        flash(msg[:240], "warning")

    return _safe_redirect("admin_payments.admin_payments_page")


__all__ = ["admin_payments_bp"]
