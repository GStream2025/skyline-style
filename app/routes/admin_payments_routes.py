from __future__ import annotations

import secrets
import time
from typing import Any, Dict, List, Mapping, Optional, Tuple
from urllib.parse import urlencode, urlparse

from flask import (
    Blueprint,
    Response,
    abort,
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
admin_payments_bp.strict_slashes = False

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off", "unchecked"}

_MAX_CODE = 64
_MAX_EMAIL = 160
_MAX_IP = 64
_MAX_STR = 500
_MAX_CFG_STR = 800
_MAX_FLASH = 240

_RL_DEFAULT_SEC = 0.75
_RL_BUCKET = "_rl_admin_payments_v1"
_RL_CAP = 220
_RL_TTL_SEC = 60 * 45

_SESSION_CSRF_KEY = "csrf_token"

_NO_STORE_HEADERS = {
    "Cache-Control": "no-store, max-age=0, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-Frame-Options": "SAMEORIGIN",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def _now() -> int:
    return int(time.time())


def _clean_str(v: Any, max_len: int, *, default: str = "") -> str:
    if max_len <= 0:
        return default
    if v is None:
        return default
    s = str(v).replace("\x00", "").replace("\u200b", "").strip()
    if not s:
        return default
    s = " ".join(s.split())
    return s[:max_len] if len(s) > max_len else s


def _bool(v: Any) -> bool:
    if v is None:
        return False
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if not s or s in _FALSE:
        return False
    return s in _TRUE or s == "1"


def _wants_json() -> bool:
    try:
        if request.is_json:
            return True
        if _clean_str(request.args.get("format"), 12).lower() == "json":
            return True
        accept = (request.headers.get("Accept") or "").lower()
        if "application/json" in accept or "text/json" in accept:
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


def _no_store(resp: Response) -> Response:
    try:
        for k, v in _NO_STORE_HEADERS.items():
            resp.headers.setdefault(k, v)
        vary = resp.headers.get("Vary", "")
        parts = [p.strip() for p in vary.split(",") if p.strip()]
        if "Accept" not in parts:
            parts.append("Accept")
        if "Cookie" not in parts:
            parts.append("Cookie")
        resp.headers["Vary"] = ", ".join(parts)
    except Exception:
        pass
    return resp


def _template_exists(name: str) -> bool:
    try:
        current_app.jinja_env.get_template(name)
        return True
    except Exception:
        return False


def _render_safe(template: str, **ctx: Any):
    if _template_exists(template):
        try:
            return render_template(template, **ctx)
        except Exception:
            try:
                current_app.logger.exception("Template render failed: %s", template)
            except Exception:
                pass
    title = _clean_str(ctx.get("title") or "Admin Payments", 100, default="Admin Payments")
    body = (
        "<!doctype html><html lang='es'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{title}</title></head>"
        "<body style='font-family:system-ui;padding:24px;max-width:980px;margin:0 auto'>"
        f"<h1 style='margin:0 0 10px'>{title}</h1>"
        "<p style='opacity:.75;margin:0'>Falta template o hubo un error al renderizar.</p>"
        "</body></html>"
    )
    return body, 200, {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store"}


def _client_ip() -> str:
    try:
        xf = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        if xf:
            return xf[:_MAX_IP]
    except Exception:
        pass
    return _clean_str(request.remote_addr, _MAX_IP, default="")[:_MAX_IP]


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


def _ensure_csrf() -> str:
    tok = session.get(_SESSION_CSRF_KEY)
    if not isinstance(tok, str) or len(tok) < 24:
        tok = secrets.token_urlsafe(32)
        session[_SESSION_CSRF_KEY] = tok
    session.permanent = True
    session.modified = True
    return str(session[_SESSION_CSRF_KEY])


def _csrf_ok() -> bool:
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return True
    sess = _clean_str(session.get(_SESSION_CSRF_KEY), 256, default="")
    if not sess:
        return False

    header_name = _clean_str(current_app.config.get("CSRF_HEADER"), 64, default="X-CSRF-Token")
    sent = _clean_str(request.headers.get(header_name), 256, default="")
    if not sent:
        sent = _clean_str(request.form.get("csrf_token"), 256, default="")
    if not sent and request.is_json:
        try:
            data = request.get_json(silent=True) or {}
            if isinstance(data, dict):
                sent = _clean_str(data.get("csrf_token"), 256, default="")
        except Exception:
            sent = ""

    if not sent:
        return False
    try:
        return secrets.compare_digest(sess, sent)
    except Exception:
        return False


def _sanitize_next(path: str, *, fallback: str = "/admin") -> str:
    p = _clean_str(path, 700, default="")
    if not p:
        return fallback
    if not p.startswith("/") or p.startswith("//") or "://" in p:
        return fallback
    if any(c in p for c in ("\x00", "\r", "\n", "\t", "\\", " ")):
        return fallback
    if ".." in p:
        return fallback
    try:
        u = urlparse(p)
        if u.scheme or u.netloc:
            return fallback
    except Exception:
        return fallback
    if "?" in p:
        p = p.split("?", 1)[0]
    if "#" in p:
        p = p.split("#", 1)[0]
    return p or fallback


def _safe_redirect(endpoint: str, **values):
    try:
        return redirect(url_for(endpoint, **values), code=302)
    except Exception:
        try:
            return redirect(url_for("main.home"), code=302)
        except Exception:
            return redirect("/", code=302)


def _safe_redirect_path(path: str):
    p = _sanitize_next(path, fallback="/")
    return redirect(p, code=302)


def _audit_user_email() -> str:
    try:
        uid = int(session.get("user_id") or 0)
        if uid:
            from app.models import User  # type: ignore

            u = db.session.get(User, uid)
            if u:
                em = _clean_str(getattr(u, "email", ""), _MAX_EMAIL, default="").lower()
                return em[:_MAX_EMAIL]
    except Exception:
        pass
    return _clean_str(session.get("user_email"), _MAX_EMAIL, default="").lower()[:_MAX_EMAIL]


def _admin_required():
    uid = session.get("user_id")
    if not uid:
        if _wants_json():
            return _json({"ok": False, "error": "auth_required"}, 401)
        flash("Iniciá sesión para entrar al admin.", "warning")
        nxt = _sanitize_next(request.path, fallback="/admin")
        try:
            return _safe_redirect("auth.login", next=nxt)
        except Exception:
            return _safe_redirect_path("/auth/login?" + urlencode({"next": nxt}))

    if _bool(session.get("is_admin")):
        return None

    try:
        from app.models import User  # type: ignore

        u = db.session.get(User, int(uid))
        if u and (_bool(getattr(u, "is_admin", False)) or _bool(getattr(u, "is_owner", False))):
            session["is_admin"] = True
            session["user_email"] = _clean_str(getattr(u, "email", ""), _MAX_EMAIL, default="").lower()
            session.modified = True
            return None
    except Exception:
        pass

    if _wants_json():
        return _json({"ok": False, "error": "forbidden"}, 403)

    flash("No tenés permisos para acceder al admin.", "error")
    return _safe_redirect("main.home")


def _rl_get_store() -> Dict[str, Dict[str, Any]]:
    store = session.get(_RL_BUCKET)
    if isinstance(store, dict):
        out: Dict[str, Dict[str, Any]] = {}
        for k, v in store.items():
            if isinstance(k, str) and isinstance(v, dict):
                out[k] = dict(v)
        return out
    return {}


def _rl_put_store(store: Dict[str, Dict[str, Any]]) -> None:
    session[_RL_BUCKET] = store
    session.modified = True


def _rate_limit(key: str, seconds: float = _RL_DEFAULT_SEC) -> bool:
    now = _now()
    store = _rl_get_store()

    cutoff = now - _RL_TTL_SEC
    if store:
        for k in list(store.keys()):
            try:
                t0 = int(store.get(k, {}).get("t", 0) or 0)
            except Exception:
                t0 = 0
            if t0 and t0 < cutoff:
                store.pop(k, None)

    if len(store) > _RL_CAP:
        items: List[Tuple[int, str]] = []
        for k, v in store.items():
            try:
                items.append((int(v.get("t", 0) or 0), k))
            except Exception:
                items.append((0, k))
        items.sort()
        for _, k in items[: max(0, len(store) - _RL_CAP)]:
            store.pop(k, None)

    b = store.get(key)
    if not isinstance(b, dict):
        store[key] = {"t": now}
        _rl_put_store(store)
        return True

    try:
        last = int(b.get("t", 0) or 0)
    except Exception:
        last = 0

    if (now - last) < int(max(1, seconds * 1000)) // 1000 and (time.time() - float(last)) < float(seconds):
        return False

    store[key] = {"t": now}
    _rl_put_store(store)
    return True


def _payments_available() -> bool:
    return PaymentProvider is not None and PaymentProviderService is not None


def _bootstrap_defaults_if_needed() -> None:
    if not _payments_available():
        return
    try:
        PaymentProviderService.bootstrap_defaults()  # type: ignore[attr-defined]
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass


def _normalize_code(code: str) -> str:
    c = _clean_str(code, _MAX_CODE, default="").lower().replace(" ", "_").replace("-", "_")
    c = "".join(ch for ch in c if ch.isalnum() or ch == "_")
    return c[:_MAX_CODE]


def _get_provider_by_code(code: str):
    if PaymentProvider is None:
        return None
    c = _normalize_code(code)
    if not c:
        return None
    try:
        return PaymentProvider.query.filter_by(code=c).first()  # type: ignore[attr-defined]
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
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
            prev = {"code": getattr(p, "code", "") or "", "name": getattr(p, "name", "Provider") or "Provider"}

    try:
        prev.setdefault("schema", p.config_schema_for(getattr(p, "code", "")))
    except Exception:
        prev.setdefault("schema", [])

    prev.setdefault("code", getattr(p, "code", "") or "")
    prev.setdefault("name", getattr(p, "name", "") or prev.get("code") or "Provider")
    prev.setdefault("enabled", _bool(getattr(p, "enabled", False)))
    prev.setdefault("recommended", _bool(getattr(p, "recommended", False)))
    prev.setdefault("sort_order", int(getattr(p, "sort_order", 100) or 100))
    prev.setdefault("kind", getattr(p, "kind", "other") or "other")
    prev.setdefault("country", getattr(p, "country", "UY") or "UY")
    prev.setdefault("notes", getattr(p, "notes", "") or "")
    prev.setdefault("config", _as_mapping(prev.get("config") or getattr(p, "config", {}) or {}))
    prev.setdefault("ready", _bool(prev.get("ready", False)))
    prev.setdefault("errors", list(prev.get("errors") or []))
    return prev


def _sanitize_cfg(cfg: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in (cfg or {}).items():
        kk = _clean_str(k, 80, default="")
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


@admin_payments_bp.before_request
def _before():
    _ensure_csrf()


@admin_payments_bp.after_request
def _after(resp: Response):
    return _no_store(resp)


@admin_payments_bp.context_processor
def _inject():
    return {
        "csrf_token_value": session.get(_SESSION_CSRF_KEY, ""),
        "checkout_url_value": _safe_checkout_url(),
    }


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
    except Exception:
        try:
            current_app.logger.exception("Error listando providers")
        except Exception:
            pass
        flash("No se pudieron cargar los métodos de pago.", "error")
        return _safe_redirect("admin.dashboard")

    items: List[Dict[str, Any]] = [_provider_to_ui_dict(p) for p in (providers or [])]
    stats = {
        "total": len(items),
        "enabled": sum(1 for x in items if _bool(x.get("enabled"))),
        "ready": sum(1 for x in items if _bool(x.get("ready"))),
        "recommended": sum(1 for x in items if _bool(x.get("recommended"))),
    }

    return _render_safe(
        "admin/payments.html",
        providers=items,
        checkout_url=_safe_checkout_url(),
        csrf_token_value=session.get(_SESSION_CSRF_KEY, ""),
        stats=stats,
        title="Métodos de pago",
    )


@admin_payments_bp.post("/payments/<code>/save")
def admin_payments_save(code: str):
    guard = _admin_required()
    if guard:
        return guard

    norm_code = _normalize_code(code)
    if not norm_code:
        if _wants_json():
            return _json({"ok": False, "error": "bad_code"}, 400)
        flash("Código inválido.", "error")
        return _safe_redirect("admin_payments.admin_payments_page")

    if not _csrf_ok():
        if _wants_json():
            return _json({"ok": False, "error": "csrf_invalid"}, 400)
        flash("CSRF inválido. Recargá la página e intentá de nuevo.", "warning")
        return _safe_redirect("admin_payments.admin_payments_page")

    if not _rate_limit(f"save:{norm_code}", seconds=_RL_DEFAULT_SEC):
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

    enabled = _bool(request.form.get("enabled"))
    recommended = _bool(request.form.get("recommended"))
    if not enabled and recommended:
        recommended = False

    def _read_int(name: str, default: int = 0) -> int:
        v = _clean_str(request.form.get(name), 32, default="")
        if not v:
            return default
        try:
            return int(v)
        except Exception:
            return default

    def _clamp_int(v: int, lo: int, hi: int) -> int:
        return lo if v < lo else (hi if v > hi else v)

    sort_order = _clamp_int(_read_int("sort_order", int(getattr(p, "sort_order", 100) or 100)), 0, 9999)
    kind_in = _clean_str(request.form.get("kind"), 20, default=str(getattr(p, "kind", "other") or "other")).lower()
    kind = kind_in[:20] or "other"

    country_in = _clean_str(request.form.get("country"), 2, default=str(getattr(p, "country", "UY") or "UY")).upper()
    country = country_in if len(country_in) == 2 and country_in.isalpha() else "UY"

    fee_percent = _clamp_int(_read_int("fee_percent", int(getattr(p, "fee_percent", 0) or 0)), 0, 100)
    eta_minutes = _clamp_int(_read_int("eta_minutes", int(getattr(p, "eta_minutes", 0) or 0)), 0, 100000)

    min_amount = _clamp_int(_read_int("min_amount", int(getattr(p, "min_amount", 0) or 0)), 0, 1_000_000_000)
    max_amount = _clamp_int(_read_int("max_amount", int(getattr(p, "max_amount", 0) or 0)), 0, 1_000_000_000)
    if max_amount != 0 and max_amount < min_amount:
        max_amount = min_amount

    notes = _clean_str(request.form.get("notes"), _MAX_STR, default="")

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
        k = _clean_str(f.get("key"), 80, default="")
        typ = _clean_str(f.get("type"), 20, default="text").lower()
        if not k:
            continue
        field_name = f"cfg__{k}"
        if typ == "bool":
            cfg[k] = _bool(request.form.get(field_name))
            continue
        val = _clean_str(request.form.get(field_name), _MAX_CFG_STR, default="")
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
            errs = [str(x) for x in (vres[1] or [])]
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
            return _json({"ok": False, "error": "config_invalid", "message": _clean_str(e, 500, default="invalid")}, 400)
        flash(_clean_str(f"Config inválida: {e}", _MAX_FLASH, default="Config inválida"), "error")
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
        msg = "Guardado ✅ pero falta completar: " + " | ".join(_clean_str(x, 120, default="") for x in (errs or ["config incompleta"]))
        flash(_clean_str(msg, _MAX_FLASH, default="Guardado"), "warning")

    return _safe_redirect("admin_payments.admin_payments_page")


__all__ = ["admin_payments_bp"]
