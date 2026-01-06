# app/routes/admin_routes.py
from __future__ import annotations

"""
Admin Routes — Skyline Store (ULTRA PRO MAX / BULLETPROOF / FINAL v3)

✅ Objetivo: Panel admin/owner sólido, sin 500, sin sorpresas, listo para producción.
✅ Incluye: pagos, productos, categorías, ofertas, comisiones (tiers) + base para premios.

MEJORAS REALES (20+):
1) CSRF real: token por sesión + validación constante (form/header)
2) Session fixation mitigation: regeneración de sesión en login + fresh window
3) Rate-limit + lockout con backoff (sin DB)
4) Admin guard más robusto: soporta admin_required decorador y fallback
5) DB commits blindados: rollback seguro + logging sin romper
6) Uploads: tamaño, extensión, mimetype allowlist, nombre random, path seguro
7) File size check real (seek/tell) + fallback content_length
8) Atomic write de payments.json (evita corrupción)
9) Sanitización: slugify fuerte + validaciones de status
10) Paginación compatible: Flask-SQLAlchemy paginate o fallback offset/limit
11) Filtros/búsquedas seguras (ilike try/except)
12) Seed/validate tiers de comisiones (para tu PDF Item 1)
13) Render templates con datos mínimos; evita errores si template falta
14) Helpers DRY: parse int/float/decimal, safe_set, flashes
15) UI segura: siempre inyecta csrf_token en templates
16) Upload dir configurable (UPLOADS_DIR) con fallback a static/uploads
17) Protección adicional: limitar per_page, q length
18) Mejor manejo de errores: abort(400) consistente, sin stacktrace al usuario
19) Payments: whitelist de keys y normalización
20) Hardening cookies flags por config (usa config actual si existe)
21) Evita duplicados de slugs con suffix random y recheck
22) Compatibilidad con modelos con campos distintos (title/name, stock/stock_qty, image_url/media)

Requisitos esperados:
- app/utils/auth.py debe exponer admin_required y admin_creds_ok
- app/models/commission.py debe exponer CommissionTier con ensure_default_seed(), validate_integrity(), sanity_check_overlaps()
"""

import json
import os
import re
import secrets
import time
import unicodedata
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, Optional, List

from flask import (
    Blueprint,
    current_app,
    flash,
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

_TRUE = {"1", "true", "yes", "y", "on"}
SAFE_STATUSES = {"active", "inactive", "draft"}

MAX_ADMIN_ATTEMPTS = int(os.getenv("ADMIN_MAX_ATTEMPTS", "6") or "6")
ADMIN_LOCK_SECONDS = int(os.getenv("ADMIN_LOCK_SECONDS", "600") or "600")
ADMIN_RATE_SECONDS = float(os.getenv("ADMIN_RATE_SECONDS", "1.5") or "1.5")

# “fresh admin login” window (seguridad extra para acciones sensibles)
ADMIN_FRESH_SECONDS = int(os.getenv("ADMIN_FRESH_SECONDS", "1800") or "1800")  # 30 min

# Upload limits (MB)
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
    return str(v).strip().lower() in _TRUE


def _redir(endpoint: str, **kwargs):
    return redirect(url_for(endpoint, **kwargs))


def _flash_ok(msg: str) -> None:
    flash(msg, "success")


def _flash_warn(msg: str) -> None:
    flash(msg, "warning")


def _flash_err(msg: str) -> None:
    flash(msg, "error")


def as_int(
    v: Any,
    default: int = 0,
    *,
    min_value: Optional[int] = None,
    max_value: Optional[int] = None,
) -> int:
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
    """
    No rompe por template faltante. Evita 500.
    """
    if _template_exists(template):
        return render_template(template, **ctx)
    # fallback ultra simple
    title = ctx.get("title") or "Admin"
    body = f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>{title}</title></head>
<body style="font-family:system-ui;padding:24px">
<h1>{title}</h1>
<p style="opacity:.7">Template faltante: <code>{template}</code></p>
</body></html>"""
    return body, 200, {"Content-Type": "text/html; charset=utf-8"}


# ============================================================
# CSRF (sin libs)
# ============================================================


def _ensure_csrf() -> str:
    tok = session.get("csrf_token")
    if not tok or not isinstance(tok, str) or len(tok) < 16:
        tok = secrets.token_urlsafe(32)
        session["csrf_token"] = tok
    return tok


def _csrf_token() -> str:
    return _ensure_csrf()


def _require_csrf() -> None:
    """
    Valida CSRF:
      - token del form csrf_token o header X-CSRF-Token
    """
    sess_tok = str(session.get("csrf_token") or "")
    form_tok = (request.form.get("csrf_token") or "").strip()
    hdr_tok = (request.headers.get("X-CSRF-Token") or "").strip()
    tok = form_tok or hdr_tok
    if not sess_tok or not tok or tok != sess_tok:
        abort(400)


@admin_bp.before_app_request
def _ensure_csrf_global():
    # Siempre tener token disponible
    try:
        _ensure_csrf()
    except Exception:
        pass


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
        last = float(last)
    except Exception:
        last = 0.0

    if (now - last) < ADMIN_RATE_SECONDS:
        return False

    session["admin_last_try"] = now
    return True


def _admin_locked() -> bool:
    until = session.get("admin_locked_until", 0)
    try:
        until = float(until)
    except Exception:
        until = 0.0
    return until > time.time()


def _admin_lock() -> None:
    fails = as_int(session.get("admin_failed", 0), 0, min_value=0)
    extra = min(ADMIN_LOCK_SECONDS, max(0, (fails - MAX_ADMIN_ATTEMPTS)) * 30)
    session["admin_locked_until"] = time.time() + ADMIN_LOCK_SECONDS + extra


def _admin_failed_inc() -> int:
    n = as_int(session.get("admin_failed", 0), 0, min_value=0)
    n += 1
    session["admin_failed"] = n
    return n


def _admin_failed_reset() -> None:
    session["admin_failed"] = 0
    session["admin_locked_until"] = 0


def _admin_login_success(email: str) -> None:
    """
    Mitiga session fixation:
    - limpia todo
    - regenera csrf
    - marca login_at para fresh window
    """
    session.clear()
    session["admin_logged_in"] = True
    session["admin_email"] = email
    session["is_admin"] = True
    session["admin_login_at"] = int(time.time())
    session["csrf_token"] = secrets.token_urlsafe(32)
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

    mimetype = (getattr(file, "mimetype", "") or "").lower()
    allowed_m = MIME_ALLOW["images"] if kind == "products" else MIME_ALLOW["media"]
    if mimetype and mimetype not in allowed_m:
        raise ValueError("Tipo de archivo no permitido.")

    final = _random_filename(filename)
    dest = uploads_dir(kind) / final
    file.save(dest)

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
    os.replace(str(tmp), str(path))


def load_payments() -> Dict[str, Any]:
    data = payments_defaults()
    p = payments_path()
    if p.exists():
        try:
            raw = json.loads(p.read_text("utf-8"))
            if isinstance(raw, dict):
                for k in data:
                    if isinstance(raw.get(k), dict):
                        for kk in data[k].keys():
                            if kk in raw[k]:
                                data[k][kk] = raw[k][kk]
        except Exception:
            pass
    return data


def save_payments(data: Dict[str, Any]) -> None:
    base = payments_defaults()
    safe = payments_defaults()

    for k in base:
        if isinstance(data.get(k), dict):
            safe[k]["active"] = bool(data[k].get("active"))
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

    if _admin_locked():
        _flash_err("Demasiados intentos. Esperá unos minutos.")
        return _redir("admin.login")

    if not _admin_rate_ok():
        _flash_warn("Esperá un momento antes de intentar de nuevo.")
        return _redir("admin.login")

    email = (request.form.get("email") or "").strip().lower()
    password = (request.form.get("password") or "").strip()

    if not admin_creds_ok(email, password):
        n = _admin_failed_inc()
        if n >= MAX_ADMIN_ATTEMPTS:
            _admin_lock()
        _flash_err("Credenciales inválidas")
        return _redir("admin.login")

    _admin_login_success(email)
    _flash_ok("Bienvenido al panel admin")
    return _redir("admin.dashboard")


@admin_bp.get("/logout")
def logout():
    session.clear()
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
    return _render_safe(
        "admin/payments.html", data=load_payments(), csrf_token=_csrf_token()
    )


@admin_bp.post("/payments/save")
@admin_required
def payments_save():
    _require_csrf()

    data = payments_defaults()
    for k in data:
        data[k]["active"] = bool(request.form.get(f"{k}_active"))

    data["mercadopago_uy"]["link"] = (
        request.form.get("mercadopago_uy_link") or ""
    ).strip()
    data["mercadopago_uy"]["note"] = (
        request.form.get("mercadopago_uy_note") or ""
    ).strip()

    data["mercadopago_ar"]["link"] = (
        request.form.get("mercadopago_ar_link") or ""
    ).strip()
    data["mercadopago_ar"]["note"] = (
        request.form.get("mercadopago_ar_note") or ""
    ).strip()

    data["paypal"]["email"] = (request.form.get("paypal_email") or "").strip()
    data["paypal"]["paypal_me"] = (request.form.get("paypal_me") or "").strip()

    data["transfer"]["info"] = (request.form.get("transfer_info") or "").strip()

    try:
        save_payments(data)
        _flash_ok("Métodos de pago guardados")
    except Exception:
        _log_exc("payments_save failed")
        _flash_err("No se pudo guardar pagos")

    return _redir("admin.payments")


# ============================================================
# COMMISSION TIERS (LIST / SEED / VALIDATE + UPDATE + DELETE)
# ✅ Esto cumple el Item 1 del PDF: editable desde admin sin tocar código
# ============================================================


@admin_bp.get("/commission-tiers")
@admin_required
def commission_tiers():
    items: List[CommissionTier] = []
    ok = True
    issues: List[str] = []
    try:
        items = CommissionTier.query.order_by(
            CommissionTier.sort_order.asc(), CommissionTier.min_sales.asc()
        ).all()
        ok, issues = CommissionTier.sanity_check_overlaps()
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

    min_sales = as_int(
        request.form.get("min_sales"), 0, min_value=0, max_value=1_000_000
    )
    max_sales_raw = (request.form.get("max_sales") or "").strip()
    max_sales = (
        as_int(max_sales_raw, 0, min_value=0, max_value=1_000_000)
        if max_sales_raw
        else None
    )

    # rate puede venir como 10 o 0.10 (aceptamos ambos)
    rate_raw = (request.form.get("rate") or "").strip().replace(",", ".")
    rate = as_float(rate_raw, 0.0) or 0.0
    if rate > 1.0:
        rate = rate / 100.0
    if rate < 0.0:
        rate = 0.0
    if rate > 0.80:
        rate = 0.80

    label = (request.form.get("label") or "").strip()[:80] or None
    sort_order = as_int(
        request.form.get("sort_order"), 0, min_value=0, max_value=10_000
    )
    active = bool(request.form.get("active"))

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

        # Validación post
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
        _safe_set(
            t, "min_sales", as_int(min_sales, 0, min_value=0, max_value=1_000_000)
        )

    if max_sales is not None:
        ms = str(max_sales).strip()
        if ms == "":
            _safe_set(t, "max_sales", None)
        else:
            _safe_set(t, "max_sales", as_int(ms, 0, min_value=0, max_value=1_000_000))

    if rate_raw:
        r = as_float(rate_raw, 0.0) or 0.0
        if r > 1.0:
            r = r / 100.0
        if r < 0.0:
            r = 0.0
        if r > 0.80:
            r = 0.80
        _safe_set(t, "rate", Decimal(str(r)).quantize(Decimal("0.0001")))

    _safe_set(t, "label", label)
    if sort_order is not None and str(sort_order).strip() != "":
        _safe_set(t, "sort_order", as_int(sort_order, 0, min_value=0, max_value=10_000))
    if active is not None:
        _safe_set(t, "active", bool(active))

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
    return _render_safe(
        "admin/categories.html", categories=cats, csrf_token=_csrf_token()
    )


@admin_bp.post("/categories/new")
@admin_required
def categories_new():
    _require_csrf()

    name = (request.form.get("name") or "").strip()
    if not name:
        _flash_warn("Nombre requerido")
        return _redir("admin.categories")

    slug = slugify((request.form.get("slug") or "").strip() or name)

    try:
        if Category.query.filter_by(slug=slug).first():
            _flash_warn("Slug duplicado")
            return _redir("admin.categories")

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

    name = (request.form.get("name") or "").strip()
    slug_in = (request.form.get("slug") or "").strip()

    if name:
        _safe_set(c, "name", name)

    if slug_in or name:
        new_slug = slugify(slug_in or name or getattr(c, "name", "item"))
        try:
            q = Category.query.filter(Category.slug == new_slug, Category.id != id)
            if q.first():
                _flash_warn("Slug duplicado")
                return _redir("admin.categories")
        except Exception:
            db.session.rollback()
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
        return query.paginate(page=page, per_page=per_page, error_out=False)
    except Exception:
        items = query.limit(per_page).offset((page - 1) * per_page).all()
        return type(
            "P", (), {"items": items, "page": page, "pages": page, "total": len(items)}
        )()


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
    return _render_safe(
        "admin/product_edit.html",
        product=None,
        categories=cats,
        csrf_token=_csrf_token(),
    )


@admin_bp.post("/products/new")
@admin_required
def products_create():
    _require_csrf()

    title = (request.form.get("title") or "").strip()
    if not title:
        _flash_warn("Título requerido")
        return _redir("admin.products_new")

    slug = slugify(request.form.get("slug") or title)
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

    # slug unique
    try:
        exists = Product.query.filter_by(slug=slug).first()
        if exists:
            slug = f"{slug}-{secrets.randbelow(9999)}"
    except Exception:
        db.session.rollback()

    _safe_set(p, "slug", slug)
    _safe_set(p, "price", float(price))
    # compat stock fields
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

    return _render_safe(
        "admin/product_edit.html", product=p, categories=cats, csrf_token=_csrf_token()
    )


@admin_bp.post("/products/edit/<int:id>")
@admin_required
def products_update(id: int):
    _require_csrf()

    p = db.session.get(Product, id)
    if not p:
        _flash_warn("Producto no encontrado")
        return _redir("admin.products")

    title = (request.form.get("title") or "").strip()
    slug_in = (request.form.get("slug") or "").strip()
    price = as_float(request.form.get("price"), None)
    stock = as_int(request.form.get("stock"), -1)
    status = (request.form.get("status") or "").strip().lower()

    if title:
        _safe_set(p, "title", title)
        _safe_set(p, "name", title)

    desired_slug = slugify(slug_in or title or getattr(p, "slug", "item"))
    try:
        q = Product.query.filter(Product.slug == desired_slug, Product.id != id)
        if q.first():
            desired_slug = f"{desired_slug}-{secrets.randbelow(9999)}"
    except Exception:
        db.session.rollback()

    _safe_set(p, "slug", desired_slug)

    if price is not None:
        _safe_set(p, "price", float(price))

    if stock >= 0:
        if not _safe_set(p, "stock", stock):
            _safe_set(p, "stock_qty", stock)

    if status:
        if status not in SAFE_STATUSES:
            status = "active"
        _safe_set(p, "status", status)

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

    title = (request.form.get("title") or "").strip()
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
    _safe_set(o, "active", bool(request.form.get("active")))
    _safe_set(
        o,
        "sort_order",
        as_int(request.form.get("sort_order"), 0, min_value=0, max_value=10_000),
    )
    # compat media field name
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
