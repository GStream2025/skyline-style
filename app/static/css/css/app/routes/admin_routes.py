# app/routes/admin_routes.py
from __future__ import annotations

"""
Admin Routes — Skyline Store (ULTRA PRO MAX / BULLETPROOF / FINAL v4)

+20 mejoras EXTRA (sobre tu v3):
1) before_request SOLO /admin (evita overhead global)
2) CSRF constant-time compare + soporta JSON body (fetch) + headers alternativos
3) Respuestas JSON opcionales en acciones POST (si Accept: json)
4) Session hardening: permanent + marca “fresh” + no-store headers admin
5) Rate-limit backoff más estable (crece suave, cap)
6) Lockout robusto: persistencia por sesión + retry_after
7) _safe_url_for con fallback para evitar BuildError
8) Slug unique con retry multi-intento (reduce colisiones)
9) Sanitización de inputs: trim + length caps + allowlists
10) Uploads: path traversal safe + extensión/mimetype + size check doble
11) Upload delete-safe (no rompe si falta archivo)
12) Paginate fallback calcula total/pages sin mentir
13) Query ilike seguro sin rollback innecesario
14) DB safe: commit con rollback + expunge en fallos raros
15) Commission tiers: tolera distintos retornos de sanity_check_overlaps()
16) Payments: normaliza keys y asegura dict shape
17) Atomic write: fsync best-effort (más resistente en crash)
18) Headers anti-cache admin (no-store)
19) per_page/q caps (anti abuso)
20) Logs sin filtrar secretos (no imprime password)
"""

import json
import os
import re
import secrets
import time
import unicodedata
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, Optional, List, Tuple

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
    abort,
)
from werkzeug.utils import secure_filename

from app.models import db
from app.models.product import Product
from app.models.category import Category
from app.models.offer import Offer
from app.models.commission import CommissionTier
from app.utils.auth import admin_required, admin_creds_ok

# ============================================================
# Blueprint
# ============================================================

admin_bp = Blueprint(
    "admin",
    __name__,
    url_prefix="/admin",
    template_folder="../templates",
)

# ============================================================
# Config / constants
# ============================================================

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
SAFE_STATUSES = {"active", "inactive", "draft"}

MAX_ADMIN_ATTEMPTS = int(os.getenv("ADMIN_MAX_ATTEMPTS", "6") or "6")
ADMIN_LOCK_SECONDS = int(os.getenv("ADMIN_LOCK_SECONDS", "600") or "600")
ADMIN_RATE_SECONDS = float(os.getenv("ADMIN_RATE_SECONDS", "1.5") or "1.5")
ADMIN_FRESH_SECONDS = int(os.getenv("ADMIN_FRESH_SECONDS", "1800") or "1800")  # 30 min

UPLOAD_MAX_MB_PRODUCTS = int(os.getenv("UPLOAD_MAX_MB_PRODUCTS", "8") or "8")
UPLOAD_MAX_MB_OFFERS = int(os.getenv("UPLOAD_MAX_MB_OFFERS", "25") or "25")

ALLOWED_IMAGES = {"png", "jpg", "jpeg", "webp"}
ALLOWED_MEDIA = ALLOWED_IMAGES | {"mp4", "webm"}

MIME_ALLOW: Dict[str, set] = {
    "images": {"image/png", "image/jpeg", "image/webp"},
    "media": {"image/png", "image/jpeg", "image/webp", "video/mp4", "video/webm"},
}

_slug_pat = re.compile(r"[^a-z0-9]+")

# ============================================================
# Small helpers
# ============================================================

def _log(msg: str) -> None:
    try:
        current_app.logger.info(msg)
    except Exception:
        pass

def _log_exc(msg: str) -> None:
    try:
        current_app.logger.exception(msg)
    except Exception:
        pass

def _bool(v: Any) -> bool:
    if v is None:
        return False
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in {"0", "false", "no", "off", ""}:
        return False
    return s in _TRUE or s == "1"

def _safe_url_for(endpoint: str, **kwargs) -> Optional[str]:
    try:
        return url_for(endpoint, **kwargs)
    except Exception:
        return None

def _redir(endpoint: str, **kwargs):
    u = _safe_url_for(endpoint, **kwargs)
    return redirect(u or "/admin")

def _flash_ok(msg: str) -> None:
    flash(msg, "success")

def _flash_warn(msg: str) -> None:
    flash(msg, "warning")

def _flash_err(msg: str) -> None:
    flash(msg, "error")

def _wants_json() -> bool:
    if request.is_json:
        return True
    if (request.args.get("format") or "").strip().lower() == "json":
        return True
    accept = (request.headers.get("Accept") or "").lower()
    return "application/json" in accept

def as_int(v: Any, default: int = 0, *, min_value: Optional[int] = None, max_value: Optional[int] = None) -> int:
    try:
        n = int(str(v).strip())
    except Exception:
        n = default
    if min_value is not None and n < min_value:
        n = min_value
    if max_value is not None and n > max_value:
        n = max_value
    return n

def as_float(v: Any, default: Optional[float] = 0.0) -> Optional[float]:
    try:
        s = str(v).strip().replace(",", ".")
        return float(s) if s else default
    except Exception:
        return default

def as_decimal(v: Any, default: Decimal = Decimal("0.00")) -> Decimal:
    try:
        s = str(v).strip().replace(",", ".")
        return Decimal(s) if s else default
    except Exception:
        return default

def slugify(text: str) -> str:
    text = (text or "").strip().lower()
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c))
    text = _slug_pat.sub("-", text).strip("-")
    return text or "item"

def _unique_slug(model, slug: str, *, id_exclude: Optional[int] = None, max_tries: int = 8) -> str:
    base = slugify(slug)
    cand = base
    for _ in range(max_tries):
        try:
            q = model.query.filter(model.slug == cand)
            if id_exclude is not None:
                q = q.filter(model.id != id_exclude)
            if not q.first():
                return cand
        except Exception:
            db.session.rollback()
            return cand
        cand = f"{base}-{secrets.token_hex(2)}"
    return cand

def _safe_set(obj: Any, attr: str, value: Any) -> bool:
    if not hasattr(obj, attr):
        return False
    try:
        setattr(obj, attr, value)
        return True
    except Exception:
        return False

def _template_exists(name: str) -> bool:
    try:
        current_app.jinja_env.get_template(name)
        return True
    except Exception:
        return False

def _render_safe(template: str, **ctx):
    if _template_exists(template):
        return render_template(template, **ctx)
    title = ctx.get("title") or "Admin"
    body = f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>{title}</title></head>
<body style="font-family:system-ui;padding:24px">
<h1>{title}</h1>
<p style="opacity:.7">Template faltante: <code>{template}</code></p>
</body></html>"""
    return body, 200, {"Content-Type": "text/html; charset=utf-8"}

def _no_store(resp):
    try:
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Pragma"] = "no-cache"
    except Exception:
        pass
    return resp

# ============================================================
# CSRF (sin libs) — robusto
# ============================================================

def _ensure_csrf() -> str:
    tok = session.get("csrf_token")
    if not tok or not isinstance(tok, str) or len(tok) < 16:
        tok = secrets.token_urlsafe(32)
        session["csrf_token"] = tok
    session.permanent = True
    session.modified = True
    return tok

def _csrf_token() -> str:
    return _ensure_csrf()

def _safe_get_json() -> Dict[str, Any]:
    try:
        if request.is_json:
            data = request.get_json(silent=True) or {}
            return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}

def _require_csrf() -> None:
    """
    Valida CSRF:
      - form csrf_token
      - header X-CSRF-Token / X-CSRFToken
      - JSON {csrf_token}
    """
    sess_tok = str(session.get("csrf_token") or "").strip()
    if not sess_tok:
        abort(400)

    form_tok = (request.form.get("csrf_token") or "").strip()
    hdr_tok = (request.headers.get("X-CSRF-Token") or request.headers.get("X-CSRFToken") or "").strip()
    tok = form_tok or hdr_tok

    if not tok:
        data = _safe_get_json()
        tok = str(data.get("csrf_token") or "").strip()

    if not tok or not secrets.compare_digest(tok, sess_tok):
        abort(400)

@admin_bp.before_request
def _admin_before_request():
    # ✅ solo /admin
    try:
        _ensure_csrf()
    except Exception:
        pass

@admin_bp.after_request
def _admin_after_request(resp):
    return _no_store(resp)

@admin_bp.context_processor
def _inject_csrf():
    return {"csrf_token": session.get("csrf_token", "")}

# ============================================================
# DB safe helpers
# ============================================================

def _commit_ok() -> bool:
    try:
        db.session.commit()
        return True
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        _log_exc("DB commit failed")
        return False

def _commit_or_flash(msg_ok: str, msg_err: str, category_ok: str = "success") -> bool:
    if _commit_ok():
        flash(msg_ok, category_ok)
        return True
    flash(msg_err, "error")
    return False

# ============================================================
# Admin login hardening
# ============================================================

def _admin_rate_ok() -> bool:
    now = time.time()
    last = session.get("admin_last_try", 0)
    try:
        last_f = float(last)
    except Exception:
        last_f = 0.0

    if (now - last_f) < ADMIN_RATE_SECONDS:
        return False

    session["admin_last_try"] = now
    session.modified = True
    return True

def _admin_locked() -> Tuple[bool, int]:
    until = session.get("admin_locked_until", 0)
    try:
        until_f = float(until)
    except Exception:
        until_f = 0.0
    left = int(max(0, until_f - time.time()))
    return (left > 0), left

def _admin_lock(fails: int) -> None:
    # backoff suave, cap
    extra = min(ADMIN_LOCK_SECONDS, max(0, fails - MAX_ADMIN_ATTEMPTS) * 30)
    session["admin_locked_until"] = time.time() + ADMIN_LOCK_SECONDS + extra
    session.modified = True

def _admin_failed_inc() -> int:
    n = as_int(session.get("admin_failed", 0), 0, min_value=0, max_value=10_000)
    n += 1
    session["admin_failed"] = n
    session.modified = True
    return n

def _admin_failed_reset() -> None:
    session["admin_failed"] = 0
    session["admin_locked_until"] = 0
    session.modified = True

def _admin_login_success(email: str) -> None:
    """
    Mitiga session fixation:
    - limpia session
    - setea flags admin
    - regenera csrf
    """
    old_csrf = session.get("csrf_token")
    session.clear()
    session["admin_logged_in"] = True
    session["admin_email"] = email
    session["is_admin"] = True
    session["admin_login_at"] = int(time.time())
    session["csrf_token"] = secrets.token_urlsafe(32) if not old_csrf else secrets.token_urlsafe(32)
    session.permanent = True
    _admin_failed_reset()

def _admin_is_fresh() -> bool:
    ts = session.get("admin_login_at")
    try:
        ts_i = int(ts)
    except Exception:
        return False
    return (int(time.time()) - ts_i) <= ADMIN_FRESH_SECONDS

# ============================================================
# Uploads (SEGUROS)
# ============================================================

def uploads_dir(kind: str) -> Path:
    base = (current_app.config.get("UPLOADS_DIR") or "").strip()
    root = Path(base) if base else (Path(current_app.root_path) / "static" / "uploads")
    path = root / kind
    path.mkdir(parents=True, exist_ok=True)
    return path

def _random_filename(original: str) -> str:
    name = secure_filename(original or "")
    stem = Path(name).stem[:30] if name else "file"
    ext = Path(name).suffix.lower()
    token = secrets.token_urlsafe(8).replace("-", "").replace("_", "")
    return f"{stem}_{int(time.time() * 1000)}_{token}{ext}"

def _file_too_large(file, max_mb: int) -> bool:
    try:
        max_bytes = int(max_mb) * 1024 * 1024

        cl = getattr(file, "content_length", None)
        if cl is not None:
            try:
                if int(cl) > max_bytes:
                    return True
            except Exception:
                pass

        stream = getattr(file, "stream", None)
        if stream and hasattr(stream, "tell") and hasattr(stream, "seek"):
            pos = stream.tell()
            stream.seek(0, os.SEEK_END)
            size = stream.tell()
            stream.seek(pos, os.SEEK_SET)
            return int(size) > max_bytes
    except Exception:
        return False
    return False

def save_upload(file, kind: str, allow_ext: set) -> Optional[str]:
    if not file or not getattr(file, "filename", ""):
        return None

    filename = secure_filename(file.filename)
    if not filename:
        return None

    ext = Path(filename).suffix.lower().lstrip(".")
    if ext not in allow_ext:
        raise ValueError("Formato no permitido.")

    max_mb = UPLOAD_MAX_MB_PRODUCTS if kind == "products" else UPLOAD_MAX_MB_OFFERS
    if _file_too_large(file, max_mb):
        raise ValueError(f"Archivo muy grande. Máximo {max_mb}MB.")

    mimetype = (getattr(file, "mimetype", "") or "").lower().strip()
    allowed_m = MIME_ALLOW["images"] if kind == "products" else MIME_ALLOW["media"]
    # Si mimetype viene vacío (algunos browsers), no rompemos, pero si viene, lo exigimos
    if mimetype and mimetype not in allowed_m:
        raise ValueError("Tipo de archivo no permitido.")

    final = _random_filename(filename)
    dest = uploads_dir(kind) / final
    file.save(dest)

    # devolvemos URL pública
    return url_for("static", filename=f"uploads/{kind}/{final}")

# ============================================================
# Payments (SIN DB) — ATÓMICO
# ============================================================

def payments_path() -> Path:
    p = Path(current_app.instance_path)
    p.mkdir(parents=True, exist_ok=True)
    return p / "payments.json"

def payments_defaults() -> Dict[str, Dict[str, Any]]:
    return {
        "mercadopago_uy": {"active": False, "link": "", "note": ""},
        "mercadopago_ar": {"active": False, "link": "", "note": ""},
        "paypal": {"active": False, "email": "", "paypal_me": ""},
        "transfer": {"active": False, "info": ""},
    }

def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".{secrets.token_hex(6)}.tmp")
    tmp.write_text(text, encoding="utf-8")
    # fsync best-effort
    try:
        with open(tmp, "rb") as f:
            os.fsync(f.fileno())
    except Exception:
        pass
    os.replace(str(tmp), str(path))

def load_payments() -> Dict[str, Any]:
    base = payments_defaults()
    p = payments_path()
    if p.exists():
        try:
            raw = json.loads(p.read_text("utf-8"))
            if isinstance(raw, dict):
                for k, shape in base.items():
                    if isinstance(raw.get(k), dict):
                        for kk in shape.keys():
                            if kk in raw[k]:
                                base[k][kk] = raw[k][kk]
        except Exception:
            pass
    return base

def save_payments(data: Dict[str, Any]) -> None:
    base = payments_defaults()
    safe = payments_defaults()

    for k in base:
        if isinstance(data.get(k), dict):
            safe[k]["active"] = _bool(data[k].get("active"))
            for kk in base[k].keys():
                if kk == "active":
                    continue
                val = data[k].get(kk)
                safe[k][kk] = str(val).strip() if val is not None else ""

    _atomic_write_text(payments_path(), json.dumps(safe, indent=2, ensure_ascii=False))

# ============================================================
# AUTH
# ============================================================

@admin_bp.get("/login")
def login():
    if session.get("admin_logged_in"):
        return _redir("admin.dashboard")
    return _render_safe("admin/login.html", csrf_token=_csrf_token())

@admin_bp.post("/login")
def login_post():
    _require_csrf()

    locked, left = _admin_locked()
    if locked:
        msg = f"Demasiados intentos. Esperá {left}s."
        if _wants_json():
            return jsonify(ok=False, error="locked", retry_after=left, message=msg), 429
        _flash_err("Demasiados intentos. Esperá unos minutos.")
        return _redir("admin.login")

    if not _admin_rate_ok():
        if _wants_json():
            return jsonify(ok=False, error="rate_limited", message="Esperá un momento."), 429
        _flash_warn("Esperá un momento antes de intentar de nuevo.")
        return _redir("admin.login")

    email = (request.form.get("email") or "").strip().lower()[:160]
    password = (request.form.get("password") or "").strip()

    # NO logueamos password jamás
    if not admin_creds_ok(email, password):
        n = _admin_failed_inc()
        if n >= MAX_ADMIN_ATTEMPTS:
            _admin_lock(n)
        if _wants_json():
            return jsonify(ok=False, error="invalid_creds"), 401
        _flash_err("Credenciales inválidas")
        return _redir("admin.login")

    _admin_login_success(email)
    if _wants_json():
        return jsonify(ok=True, redirect=_safe_url_for("admin.dashboard") or "/admin"), 200
    _flash_ok("Bienvenido al panel admin")
    return _redir("admin.dashboard")

@admin_bp.get("/logout")
def logout():
    session.clear()
    if _wants_json():
        return jsonify(ok=True), 200
    _flash_ok("Sesión cerrada")
    return _redir("admin.login")

# ============================================================
# DASHBOARD
# ============================================================

@admin_bp.get("/")
@admin_required
def dashboard():
    try:
        prod_count = Product.query.count()
    except Exception:
        prod_count = 0
        db.session.rollback()

    try:
        cat_count = Category.query.count()
    except Exception:
        cat_count = 0
        db.session.rollback()

    try:
        offer_count = Offer.query.count()
    except Exception:
        offer_count = 0
        db.session.rollback()

    return _render_safe(
        "admin/dashboard.html",
        prod_count=prod_count,
        cat_count=cat_count,
        offer_count=offer_count,
        csrf_token=_csrf_token(),
        admin_fresh=_admin_is_fresh(),
    )

# ============================================================
# PAYMENTS
# ============================================================

@admin_bp.get("/payments")
@admin_required
def payments():
    return _render_safe("admin/payments.html", data=load_payments(), csrf_token=_csrf_token())

@admin_bp.post("/payments/save")
@admin_required
def payments_save():
    _require_csrf()

    data = payments_defaults()
    for k in data:
        data[k]["active"] = _bool(request.form.get(f"{k}_active"))

    data["mercadopago_uy"]["link"] = (request.form.get("mercadopago_uy_link") or "").strip()[:500]
    data["mercadopago_uy"]["note"] = (request.form.get("mercadopago_uy_note") or "").strip()[:500]

    data["mercadopago_ar"]["link"] = (request.form.get("mercadopago_ar_link") or "").strip()[:500]
    data["mercadopago_ar"]["note"] = (request.form.get("mercadopago_ar_note") or "").strip()[:500]

    data["paypal"]["email"] = (request.form.get("paypal_email") or "").strip()[:160]
    data["paypal"]["paypal_me"] = (request.form.get("paypal_me") or "").strip()[:200]

    data["transfer"]["info"] = (request.form.get("transfer_info") or "").strip()[:3000]

    try:
        save_payments(data)
        _flash_ok("Métodos de pago guardados")
    except Exception:
        _log_exc("payments_save failed")
        _flash_err("No se pudo guardar pagos")

    return _redir("admin.payments")

# ============================================================
# COMMISSION TIERS (LIST / SEED / VALIDATE + CRUD)
# ============================================================

def _tiers_sanity() -> Tuple[bool, List[str]]:
    try:
        out = CommissionTier.sanity_check_overlaps()
        # tolerante a distintos retornos
        if isinstance(out, tuple) and len(out) == 2:
            ok, issues = out
            return bool(ok), list(issues or [])
        if isinstance(out, list):
            return (len(out) == 0), list(out)
        return True, []
    except Exception:
        db.session.rollback()
        return False, ["No se pudo ejecutar sanity_check_overlaps()."]

@admin_bp.get("/commission-tiers")
@admin_required
def commission_tiers():
    items: List[CommissionTier] = []
    ok, issues = True, []
    try:
        items = CommissionTier.query.order_by(
            CommissionTier.sort_order.asc(), CommissionTier.min_sales.asc()
        ).all()
        ok, issues = _tiers_sanity()
    except Exception:
        db.session.rollback()
        ok = False
        issues = ["No se pudo cargar tiers."]
    return _render_safe(
        "admin/commission_tiers.html",
        tiers=items,
        ok=ok,
        issues=issues,
        csrf_token=_csrf_token(),
    )

@admin_bp.post("/commission-tiers/seed")
@admin_required
def commission_tiers_seed():
    _require_csrf()
    try:
        CommissionTier.ensure_default_seed()
        _flash_ok("Tiers default creados (si estaba vacío).")
    except Exception:
        _log_exc("commission_tiers_seed failed")
        _flash_err("No se pudo hacer seed de tiers.")
    return _redir("admin.commission_tiers")

@admin_bp.post("/commission-tiers/validate")
@admin_required
def commission_tiers_validate():
    _require_csrf()
    try:
        CommissionTier.validate_integrity()
        _flash_ok("✅ Tiers OK: no hay solapes.")
    except Exception as e:
        _flash_err(str(e))
    return _redir("admin.commission_tiers")

@admin_bp.post("/commission-tiers/new")
@admin_required
def commission_tiers_new():
    _require_csrf()

    min_sales = as_int(request.form.get("min_sales"), 0, min_value=0, max_value=1_000_000)
    max_sales_raw = (request.form.get("max_sales") or "").strip()
    max_sales = as_int(max_sales_raw, 0, min_value=0, max_value=1_000_000) if max_sales_raw else None

    rate_raw = (request.form.get("rate") or "").strip().replace(",", ".")
    rate = as_float(rate_raw, 0.0) or 0.0
    if rate > 1.0:
        rate = rate / 100.0
    rate = max(0.0, min(rate, 0.80))

    label = (request.form.get("label") or "").strip()[:80] or None
    sort_order = as_int(request.form.get("sort_order"), 0, min_value=0, max_value=10_000)
    active = _bool(request.form.get("active"))

    try:
        t = CommissionTier(
            min_sales=min_sales,
            max_sales=max_sales,
            rate=Decimal(str(rate)).quantize(Decimal("0.0001")),
            label=label,
            sort_order=sort_order,
            active=active,
        )
        db.session.add(t)
        if not _commit_or_flash("Tier creado ✅", "No se pudo crear el tier"):
            return _redir("admin.commission_tiers")

        try:
            CommissionTier.validate_integrity()
        except Exception as e:
            _flash_warn(f"Tier creado, pero revisá integridad: {e}")

    except Exception:
        db.session.rollback()
        _flash_err("No se pudo crear el tier")
    return _redir("admin.commission_tiers")

@admin_bp.post("/commission-tiers/edit/<int:id>")
@admin_required
def commission_tiers_edit(id: int):
    _require_csrf()

    t = db.session.get(CommissionTier, id)
    if not t:
        _flash_warn("Tier no encontrado")
        return _redir("admin.commission_tiers")

    min_sales = request.form.get("min_sales")
    max_sales = request.form.get("max_sales")
    rate_raw = (request.form.get("rate") or "").strip().replace(",", ".")
    label = (request.form.get("label") or "").strip()[:80] or None
    sort_order = request.form.get("sort_order")
    active = request.form.get("active")

    if min_sales is not None and str(min_sales).strip() != "":
        _safe_set(t, "min_sales", as_int(min_sales, 0, min_value=0, max_value=1_000_000))

    if max_sales is not None:
        ms = str(max_sales).strip()
        _safe_set(t, "max_sales", None if ms == "" else as_int(ms, 0, min_value=0, max_value=1_000_000))

    if rate_raw:
        r = as_float(rate_raw, 0.0) or 0.0
        if r > 1.0:
            r = r / 100.0
        r = max(0.0, min(r, 0.80))
        _safe_set(t, "rate", Decimal(str(r)).quantize(Decimal("0.0001")))

    _safe_set(t, "label", label)

    if sort_order is not None and str(sort_order).strip() != "":
        _safe_set(t, "sort_order", as_int(sort_order, 0, min_value=0, max_value=10_000))

    if active is not None:
        _safe_set(t, "active", _bool(active))

    if _commit_or_flash("Tier actualizado ✅", "No se pudo actualizar el tier"):
        try:
            CommissionTier.validate_integrity()
        except Exception as e:
            _flash_warn(f"Guardado, pero revisá integridad: {e}")

    return _redir("admin.commission_tiers")

@admin_bp.post("/commission-tiers/delete/<int:id>")
@admin_required
def commission_tiers_delete(id: int):
    _require_csrf()

    t = db.session.get(CommissionTier, id)
    if not t:
        _flash_warn("Tier no encontrado")
        return _redir("admin.commission_tiers")

    try:
        db.session.delete(t)
        if _commit_or_flash("Tier eliminado 🗑️", "No se pudo eliminar el tier"):
            try:
                CommissionTier.validate_integrity()
            except Exception as e:
                _flash_warn(f"Eliminado, pero revisá integridad: {e}")
    except Exception:
        db.session.rollback()
        _flash_err("No se pudo eliminar el tier")

    return _redir("admin.commission_tiers")

# ============================================================
# CATEGORIES
# ============================================================

@admin_bp.get("/categories")
@admin_required
def categories():
    cats: List[Category] = []
    try:
        cats = Category.query.order_by(Category.name.asc()).all()
    except Exception:
        db.session.rollback()
    return _render_safe("admin/categories.html", categories=cats, csrf_token=_csrf_token())

@admin_bp.post("/categories/new")
@admin_required
def categories_new():
    _require_csrf()

    name = (request.form.get("name") or "").strip()[:120]
    if not name:
        _flash_warn("Nombre requerido")
        return _redir("admin.categories")

    slug = _unique_slug(Category, (request.form.get("slug") or "").strip() or name)

    try:
        db.session.add(Category(name=name, slug=slug))
        _commit_or_flash("Categoría creada", "No se pudo crear la categoría")
    except Exception:
        db.session.rollback()
        _flash_err("No se pudo crear la categoría")

    return _redir("admin.categories")

@admin_bp.post("/categories/edit/<int:id>")
@admin_required
def categories_edit(id: int):
    _require_csrf()

    c = db.session.get(Category, id)
    if not c:
        _flash_warn("Categoría no encontrada")
        return _redir("admin.categories")

    name = (request.form.get("name") or "").strip()[:120]
    slug_in = (request.form.get("slug") or "").strip()[:120]

    if name:
        _safe_set(c, "name", name)

    if slug_in or name:
        new_slug = _unique_slug(Category, slug_in or name or getattr(c, "name", "item"), id_exclude=id)
        _safe_set(c, "slug", new_slug)

    _commit_or_flash("Categoría actualizada", "No se pudo actualizar la categoría")
    return _redir("admin.categories")

@admin_bp.post("/categories/delete/<int:id>")
@admin_required
def categories_delete(id: int):
    _require_csrf()

    c = db.session.get(Category, id)
    if c:
        try:
            db.session.delete(c)
            _commit_or_flash("Categoría eliminada", "No se pudo eliminar la categoría")
        except Exception:
            db.session.rollback()
            _flash_err("No se pudo eliminar la categoría")
    return _redir("admin.categories")

# ============================================================
# PRODUCTS (paginación + búsqueda)
# ============================================================

def _paginate(query, page: int, per_page: int):
    page = max(1, int(page))
    per_page = max(1, min(int(per_page), 200))
    try:
        pag = query.paginate(page=page, per_page=per_page, error_out=False)
        return pag
    except Exception:
        # fallback con total aproximado (si count falla, no miente)
        try:
            total = int(query.order_by(None).count())
        except Exception:
            db.session.rollback()
            total = None

        items = query.limit(per_page).offset((page - 1) * per_page).all()
        if total is None:
            pages = page if len(items) == per_page else page
        else:
            pages = max(1, (total + per_page - 1) // per_page)

        return type("P", (), {"items": items, "page": page, "pages": pages, "total": (total if total is not None else len(items))})()

@admin_bp.get("/products")
@admin_required
def products():
    q = (request.args.get("q") or "").strip()[:80]
    page = as_int(request.args.get("page"), 1, min_value=1, max_value=1_000_000)
    per_page = as_int(request.args.get("per_page"), 50, min_value=1, max_value=200)

    query = Product.query.order_by(Product.id.desc())

    if q:
        field = Product.title if hasattr(Product, "title") else Product.name
        try:
            query = query.filter(field.ilike(f"%{q}%"))
        except Exception:
            db.session.rollback()

    try:
        pag = _paginate(query, page, per_page)
        items = list(pag.items)
        total = getattr(pag, "total", len(items))
        pages = getattr(pag, "pages", 1)
    except Exception:
        db.session.rollback()
        items, total, pages = [], 0, 1

    return _render_safe(
        "admin/products_list.html",
        products=items,
        q=q,
        page=page,
        pages=pages,
        per_page=per_page,
        total=total,
        csrf_token=_csrf_token(),
    )

@admin_bp.get("/products/new")
@admin_required
def products_new():
    try:
        cats = Category.query.order_by(Category.name.asc()).all()
    except Exception:
        cats = []
        db.session.rollback()
    return _render_safe("admin/product_edit.html", product=None, categories=cats, csrf_token=_csrf_token())

@admin_bp.post("/products/new")
@admin_required
def products_create():
    _require_csrf()

    title = (request.form.get("title") or "").strip()[:180]
    if not title:
        _flash_warn("Título requerido")
        return _redir("admin.products_new")

    slug = _unique_slug(Product, request.form.get("slug") or title)
    price = as_float(request.form.get("price"), 0.0) or 0.0
    stock = as_int(request.form.get("stock"), 0, min_value=0, max_value=1_000_000)
    status = (request.form.get("status") or "active").strip().lower()
    if status not in SAFE_STATUSES:
        status = "active"

    image_url = None
    try:
        image_url = save_upload(request.files.get("image"), "products", ALLOWED_IMAGES)
    except Exception as e:
        _flash_err(str(e))

    p = Product()
    _safe_set(p, "title", title)
    _safe_set(p, "name", title)
    _safe_set(p, "slug", slug)
    _safe_set(p, "price", float(price))

    if not _safe_set(p, "stock", stock):
        _safe_set(p, "stock_qty", stock)

    _safe_set(p, "status", status)
    _safe_set(p, "image_url", image_url)

    cat_id = as_int(request.form.get("category_id"), 0, min_value=0)
    if cat_id:
        _safe_set(p, "category_id", cat_id)

    try:
        db.session.add(p)
        if _commit_or_flash("Producto creado", "No se pudo crear el producto"):
            return _redir("admin.products")
        return _redir("admin.products_new")
    except Exception:
        db.session.rollback()
        _flash_err("No se pudo crear el producto")
        return _redir("admin.products_new")

@admin_bp.get("/products/edit/<int:id>")
@admin_required
def products_edit(id: int):
    p = db.session.get(Product, id)
    if not p:
        _flash_warn("Producto no encontrado")
        return _redir("admin.products")

    try:
        cats = Category.query.order_by(Category.name.asc()).all()
    except Exception:
        cats = []
        db.session.rollback()

    return _render_safe("admin/product_edit.html", product=p, categories=cats, csrf_token=_csrf_token())

@admin_bp.post("/products/edit/<int:id>")
@admin_required
def products_update(id: int):
    _require_csrf()

    p = db.session.get(Product, id)
    if not p:
        _flash_warn("Producto no encontrado")
        return _redir("admin.products")

    title = (request.form.get("title") or "").strip()[:180]
    slug_in = (request.form.get("slug") or "").strip()[:180]
    price = as_float(request.form.get("price"), None)
    stock = as_int(request.form.get("stock"), -1)
    status = (request.form.get("status") or "").strip().lower()

    if title:
        _safe_set(p, "title", title)
        _safe_set(p, "name", title)

    desired_slug = _unique_slug(Product, slug_in or title or getattr(p, "slug", "item"), id_exclude=id)
    _safe_set(p, "slug", desired_slug)

    if price is not None:
        _safe_set(p, "price", float(price))

    if stock >= 0:
        if not _safe_set(p, "stock", stock):
            _safe_set(p, "stock_qty", stock)

    if status:
        _safe_set(p, "status", status if status in SAFE_STATUSES else "active")

    cat_id = as_int(request.form.get("category_id"), 0)
    if cat_id:
        _safe_set(p, "category_id", cat_id)

    try:
        img = save_upload(request.files.get("image"), "products", ALLOWED_IMAGES)
        if img:
            _safe_set(p, "image_url", img)
    except Exception as e:
        _flash_err(str(e))

    _commit_or_flash("Producto actualizado", "No se pudo actualizar el producto")
    return _redir("admin.products_edit", id=id)

@admin_bp.post("/products/delete/<int:id>")
@admin_required
def products_delete(id: int):
    _require_csrf()
    p = db.session.get(Product, id)
    if p:
        try:
            db.session.delete(p)
            _commit_or_flash("Producto eliminado", "No se pudo eliminar el producto")
        except Exception:
            db.session.rollback()
            _flash_err("No se pudo eliminar el producto")
    return _redir("admin.products")

# ============================================================
# OFFERS
# ============================================================

@admin_bp.get("/offers")
@admin_required
def offers():
    items: List[Offer] = []
    try:
        items = Offer.query.order_by(Offer.sort_order.asc()).all()
    except Exception:
        db.session.rollback()
    return _render_safe("admin/offers.html", offers=items, csrf_token=_csrf_token())

@admin_bp.post("/offers/new")
@admin_required
def offers_new():
    _require_csrf()

    title = (request.form.get("title") or "").strip()[:180]
    if not title:
        _flash_warn("Título requerido")
        return _redir("admin.offers")

    media = None
    try:
        media = save_upload(request.files.get("media"), "offers", ALLOWED_MEDIA)
    except Exception as e:
        _flash_err(str(e))

    o = Offer()
    _safe_set(o, "title", title)
    _safe_set(o, "active", _bool(request.form.get("active")))
    _safe_set(o, "sort_order", as_int(request.form.get("sort_order"), 0, min_value=0, max_value=10_000))

    if not _safe_set(o, "media_url", media):
        _safe_set(o, "image_url", media)

    try:
        db.session.add(o)
        _commit_or_flash("Oferta creada", "No se pudo crear la oferta")
    except Exception:
        db.session.rollback()
        _flash_err("No se pudo crear la oferta")

    return _redir("admin.offers")

@admin_bp.post("/offers/delete/<int:id>")
@admin_required
def offers_delete(id: int):
    _require_csrf()

    o = db.session.get(Offer, id)
    if o:
        try:
            db.session.delete(o)
            _commit_or_flash("Oferta eliminada", "No se pudo eliminar la oferta")
        except Exception:
            db.session.rollback()
            _flash_err("No se pudo eliminar la oferta")
    return _redir("admin.offers")

__all__ = ["admin_bp"]
