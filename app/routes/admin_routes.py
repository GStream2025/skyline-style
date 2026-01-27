from __future__ import annotations

import json
import os
import re
import secrets
import time
import unicodedata
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, cast

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
from werkzeug.utils import secure_filename

from app.models import db
from app.models.category import Category
from app.models.commission import CommissionTier
from app.models.offer import Offer
from app.models.product import Product
from app.utils.auth import admin_creds_ok, admin_required

admin_bp = Blueprint("admin", __name__, url_prefix="/admin", template_folder="../templates")

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off", "unchecked"}

SAFE_STATUSES = {"active", "inactive", "draft"}

MAX_ADMIN_ATTEMPTS = int(os.getenv("ADMIN_MAX_ATTEMPTS", "6") or "6")
ADMIN_LOCK_SECONDS = int(os.getenv("ADMIN_LOCK_SECONDS", "600") or "600")
ADMIN_RATE_SECONDS = float(os.getenv("ADMIN_RATE_SECONDS", "1.5") or "1.5")
ADMIN_FRESH_SECONDS = int(os.getenv("ADMIN_FRESH_SECONDS", "1800") or "1800")

UPLOAD_MAX_MB_PRODUCTS = int(os.getenv("UPLOAD_MAX_MB_PRODUCTS", "8") or "8")
UPLOAD_MAX_MB_OFFERS = int(os.getenv("UPLOAD_MAX_MB_OFFERS", "25") or "25")

ALLOWED_IMAGES = {"png", "jpg", "jpeg", "webp"}
ALLOWED_MEDIA = ALLOWED_IMAGES | {"mp4", "webm"}

MIME_ALLOW: Dict[str, set[str]] = {
    "images": {"image/png", "image/jpeg", "image/webp"},
    "media": {"image/png", "image/jpeg", "image/webp", "video/mp4", "video/webm"},
}

_slug_pat = re.compile(r"[^a-z0-9]+")
_ext_pat = re.compile(r"^\.[a-z0-9]{1,8}$")

_MAX_Q = 80
_MAX_EMAIL = 160
_MAX_URL = 500
_MAX_NOTE = 500
_MAX_INFO = 3000

_DEC_RATE_Q = Decimal("0.0001")
_DEC_RATE_MAX = Decimal("0.8000")


def utcnow_ts() -> int:
    return int(time.time())


def _logger():
    try:
        return current_app.logger
    except Exception:
        return None


def _log(msg: str) -> None:
    lg = _logger()
    if not lg:
        return
    try:
        lg.info("%s", msg)
    except Exception:
        pass


def _log_exc(msg: str) -> None:
    lg = _logger()
    if not lg:
        return
    try:
        lg.exception("%s", msg)
    except Exception:
        pass


def _clean_str(v: Any, max_len: int, *, default: str = "") -> str:
    if v is None:
        return default
    s = str(v).replace("\x00", "").strip()
    if not s:
        return default
    s = " ".join(s.split())
    if max_len <= 0:
        return default
    return s[:max_len]


def _bool(v: Any) -> bool:
    if v is None:
        return False
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if not s or s in _FALSE:
        return False
    return s in _TRUE or s == "1"


def as_int(v: Any, default: int = 0, *, min_value: Optional[int] = None, max_value: Optional[int] = None) -> int:
    try:
        n = int(str(v).strip())
    except Exception:
        n = int(default)
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


def _dec_rate(v: Any, default: Decimal = Decimal("0.0000")) -> Decimal:
    try:
        s = str(v).strip().replace(",", ".")
        if not s:
            return default
        d = Decimal(s)
    except (InvalidOperation, ValueError, TypeError):
        return default
    if d.is_nan() or d.is_infinite():
        return default
    if d > Decimal("1.0"):
        d = d / Decimal("100.0")
    if d < Decimal("0.0"):
        d = Decimal("0.0")
    if d > _DEC_RATE_MAX:
        d = _DEC_RATE_MAX
    return d.quantize(_DEC_RATE_Q, rounding=ROUND_HALF_UP)


def slugify(text: str) -> str:
    t = (text or "").strip().lower()
    t = unicodedata.normalize("NFKD", t)
    t = "".join(c for c in t if not unicodedata.combining(c))
    t = _slug_pat.sub("-", t).strip("-")
    return t or "item"


def _wants_json() -> bool:
    try:
        if request.is_json:
            return True
        if _clean_str(request.args.get("format"), 12).lower() == "json":
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


def _safe_url_for(endpoint: str, **kwargs: Any) -> Optional[str]:
    try:
        return url_for(endpoint, **kwargs)
    except Exception:
        return None


def _redir(endpoint: str, **kwargs: Any) -> Response:
    u = _safe_url_for(endpoint, **kwargs)
    return redirect(u or "/admin")


def _json_ok(**payload: Any):
    out = {"ok": True}
    out.update(payload)
    return jsonify(out)


def _json_err(message: str, *, code: int = 400, **payload: Any):
    out = {"ok": False, "message": _clean_str(message, 400, default="Error")}
    out.update(payload)
    return jsonify(out), code


def _flash_ok(msg: str) -> None:
    flash(_clean_str(msg, 240, default="OK"), "success")


def _flash_warn(msg: str) -> None:
    flash(_clean_str(msg, 240, default="Atencion"), "warning")


def _flash_err(msg: str) -> None:
    flash(_clean_str(msg, 240, default="Error"), "error")


def _no_store(resp: Response) -> Response:
    try:
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Pragma"] = "no-cache"
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        vary = resp.headers.get("Vary", "")
        if "Accept" not in vary:
            resp.headers["Vary"] = (vary + ", Accept").strip(", ").strip()
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
        except Exception as e:
            _log_exc(f"render_template failed: {template} ({e})")
    title = _clean_str(ctx.get("title") or "Admin", 120, default="Admin")
    body = (
        "<!doctype html><html lang='es'><head><meta charset='utf-8'>"
        f"<title>{title}</title></head>"
        "<body style='font-family:system-ui;padding:24px'>"
        f"<h1>{title}</h1>"
        f"<p style='opacity:.75'>Template faltante o error: <code>{_clean_str(template, 180)}</code></p>"
        "</body></html>"
    )
    return body, 200, {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store"}


def _ensure_csrf() -> str:
    tok = session.get("csrf_token")
    if not isinstance(tok, str) or len(tok) < 24:
        tok = secrets.token_urlsafe(32)
        session["csrf_token"] = tok
    session.permanent = True
    session.modified = True
    return cast(str, session["csrf_token"])


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
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return
    sess_tok = _clean_str(session.get("csrf_token"), 256)
    if not sess_tok:
        abort(400)

    form_tok = _clean_str(request.form.get("csrf_token"), 256)
    hdr_tok = _clean_str(request.headers.get("X-CSRF-Token") or request.headers.get("X-CSRFToken"), 256)
    tok = form_tok or hdr_tok
    if not tok:
        tok = _clean_str(_safe_get_json().get("csrf_token"), 256)
    if not tok:
        abort(400)
    try:
        if not secrets.compare_digest(tok, sess_tok):
            abort(400)
    except Exception:
        abort(400)


@admin_bp.before_request
def _admin_before_request():
    try:
        _ensure_csrf()
    except Exception:
        pass


@admin_bp.after_request
def _admin_after_request(resp: Response):
    return _no_store(resp)


@admin_bp.context_processor
def _inject_csrf():
    return {"csrf_token": session.get("csrf_token", "")}


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
        flash(_clean_str(msg_ok, 240, default="OK"), category_ok)
        return True
    flash(_clean_str(msg_err, 240, default="Error"), "error")
    return False


def _admin_rate_ok() -> bool:
    now = time.time()
    last = session.get("admin_last_try", 0.0)
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
    until = session.get("admin_locked_until", 0.0)
    try:
        until_f = float(until)
    except Exception:
        until_f = 0.0
    left = int(max(0, until_f - time.time()))
    return (left > 0), left


def _admin_lock(fails: int) -> None:
    extra = min(ADMIN_LOCK_SECONDS, max(0, fails - MAX_ADMIN_ATTEMPTS) * 30)
    session["admin_locked_until"] = time.time() + ADMIN_LOCK_SECONDS + extra
    session.modified = True


def _admin_failed_inc() -> int:
    n = as_int(session.get("admin_failed", 0), 0, min_value=0, max_value=10000)
    n += 1
    session["admin_failed"] = n
    session.modified = True
    return n


def _admin_failed_reset() -> None:
    session["admin_failed"] = 0
    session["admin_locked_until"] = 0
    session.modified = True


def _admin_login_success(email: str) -> None:
    old_csrf = _clean_str(session.get("csrf_token"), 256, default="")
    session.clear()
    session["admin_logged_in"] = True
    session["admin_email"] = _clean_str(email, _MAX_EMAIL).lower()
    session["is_admin"] = True
    session["admin_login_at"] = utcnow_ts()
    session["csrf_token"] = secrets.token_urlsafe(32) if not old_csrf else secrets.token_urlsafe(32)
    session.permanent = True
    _admin_failed_reset()


def _admin_is_fresh() -> bool:
    ts = session.get("admin_login_at")
    try:
        ts_i = int(ts)
    except Exception:
        return False
    return (utcnow_ts() - ts_i) <= ADMIN_FRESH_SECONDS


def _unique_slug(model, slug: str, *, id_exclude: Optional[int] = None, max_tries: int = 12) -> str:
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
            try:
                db.session.rollback()
            except Exception:
                pass
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


def uploads_dir(kind: str) -> Path:
    base = _clean_str(current_app.config.get("UPLOADS_DIR"), 400, default="")
    root = Path(base) if base else (Path(current_app.root_path) / "static" / "uploads")
    kind2 = slugify(kind).replace("-", "")[:24] or "files"
    path = root / kind2
    path.mkdir(parents=True, exist_ok=True)
    return path


def _random_filename(original: str) -> str:
    name = secure_filename(original or "")
    stem = (Path(name).stem[:30] if name else "file") or "file"
    ext = Path(name).suffix.lower()
    if ext and not _ext_pat.fullmatch(ext):
        ext = ""
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


def save_upload(file, kind: str, allow_ext: set[str]) -> Optional[str]:
    if not file or not getattr(file, "filename", ""):
        return None

    filename = secure_filename(file.filename)
    if not filename:
        return None

    kind2 = kind if kind in {"products", "offers"} else "products"
    ext = Path(filename).suffix.lower().lstrip(".")
    if ext not in allow_ext:
        raise ValueError("Formato no permitido")

    max_mb = UPLOAD_MAX_MB_PRODUCTS if kind2 == "products" else UPLOAD_MAX_MB_OFFERS
    if _file_too_large(file, max_mb):
        raise ValueError(f"Archivo muy grande (max {max_mb}MB)")

    mimetype = (getattr(file, "mimetype", "") or "").lower().strip()
    allowed_m = MIME_ALLOW["images"] if kind2 == "products" else MIME_ALLOW["media"]
    if mimetype and mimetype not in allowed_m:
        raise ValueError("Tipo de archivo no permitido")

    final = _random_filename(filename)
    dest = uploads_dir(kind2) / final
    file.save(dest)

    return url_for("static", filename=f"uploads/{kind2}/{final}")


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
                safe[k][kk] = _clean_str(val, _MAX_INFO) if val is not None else ""

    _atomic_write_text(payments_path(), json.dumps(safe, indent=2, ensure_ascii=False))


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
        if _wants_json():
            return _json_err("Demasiados intentos", code=429, error="locked", retry_after=left)
        _flash_err("Demasiados intentos. Espera unos minutos.")
        return _redir("admin.login")

    if not _admin_rate_ok():
        if _wants_json():
            return _json_err("Espera un momento", code=429, error="rate_limited")
        _flash_warn("Espera un momento antes de intentar de nuevo.")
        return _redir("admin.login")

    email = _clean_str(request.form.get("email"), _MAX_EMAIL).lower()
    password = _clean_str(request.form.get("password"), 500)

    if not admin_creds_ok(email, password):
        n = _admin_failed_inc()
        if n >= MAX_ADMIN_ATTEMPTS:
            _admin_lock(n)
        if _wants_json():
            return _json_err("Credenciales invalidas", code=401, error="invalid_creds")
        _flash_err("Credenciales invalidas")
        return _redir("admin.login")

    _admin_login_success(email)
    if _wants_json():
        return _json_ok(redirect=_safe_url_for("admin.dashboard") or "/admin")
    _flash_ok("Bienvenido al panel admin")
    return _redir("admin.dashboard")


@admin_bp.get("/logout")
def logout():
    session.clear()
    if _wants_json():
        return _json_ok()
    _flash_ok("Sesion cerrada")
    return _redir("admin.login")


@admin_bp.get("/")
@admin_required
def dashboard():
    def _count(q) -> int:
        try:
            return int(q.count())
        except Exception:
            try:
                db.session.rollback()
            except Exception:
                pass
            return 0

    return _render_safe(
        "admin/dashboard.html",
        prod_count=_count(Product.query),
        cat_count=_count(Category.query),
        offer_count=_count(Offer.query),
        csrf_token=_csrf_token(),
        admin_fresh=_admin_is_fresh(),
    )


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

    data["mercadopago_uy"]["link"] = _clean_str(request.form.get("mercadopago_uy_link"), _MAX_URL)
    data["mercadopago_uy"]["note"] = _clean_str(request.form.get("mercadopago_uy_note"), _MAX_NOTE)
    data["mercadopago_ar"]["link"] = _clean_str(request.form.get("mercadopago_ar_link"), _MAX_URL)
    data["mercadopago_ar"]["note"] = _clean_str(request.form.get("mercadopago_ar_note"), _MAX_NOTE)
    data["paypal"]["email"] = _clean_str(request.form.get("paypal_email"), _MAX_EMAIL)
    data["paypal"]["paypal_me"] = _clean_str(request.form.get("paypal_me"), 200)
    data["transfer"]["info"] = _clean_str(request.form.get("transfer_info"), _MAX_INFO)

    try:
        save_payments(data)
        _flash_ok("Metodos de pago guardados")
        if _wants_json():
            return _json_ok()
    except Exception:
        _log_exc("payments_save failed")
        if _wants_json():
            return _json_err("No se pudo guardar pagos", code=500)
        _flash_err("No se pudo guardar pagos")

    return _redir("admin.payments")


def _tiers_sanity() -> Tuple[bool, List[str]]:
    try:
        out = CommissionTier.sanity_check_overlaps()
        if isinstance(out, tuple) and len(out) == 2:
            ok, issues = out
            return bool(ok), list(issues or [])
        if isinstance(out, list):
            return (len(out) == 0), list(out)
        return True, []
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        return False, ["No se pudo ejecutar sanity_check_overlaps()."]


@admin_bp.get("/commission-tiers")
@admin_required
def commission_tiers():
    items: List[CommissionTier] = []
    ok, issues = True, []
    try:
        items = CommissionTier.query.order_by(CommissionTier.sort_order.asc(), CommissionTier.min_sales.asc()).all()
        ok, issues = _tiers_sanity()
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        ok, issues = False, ["No se pudo cargar tiers."]
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
        _flash_ok("Tiers default creados")
    except Exception:
        _log_exc("commission_tiers_seed failed")
        _flash_err("No se pudo hacer seed de tiers")
    return _redir("admin.commission_tiers")


@admin_bp.post("/commission-tiers/validate")
@admin_required
def commission_tiers_validate():
    _require_csrf()
    try:
        CommissionTier.validate_integrity()
        _flash_ok("Tiers OK")
    except Exception as e:
        _flash_err(_clean_str(e, 220, default="Error validando tiers"))
    return _redir("admin.commission_tiers")


@admin_bp.post("/commission-tiers/new")
@admin_required
def commission_tiers_new():
    _require_csrf()

    min_sales = as_int(request.form.get("min_sales"), 0, min_value=0, max_value=1_000_000)
    max_sales_raw = _clean_str(request.form.get("max_sales"), 32, default="")
    max_sales = as_int(max_sales_raw, 0, min_value=0, max_value=1_000_000) if max_sales_raw else None

    rate = _dec_rate(request.form.get("rate"), Decimal("0.0000"))
    label = _clean_str(request.form.get("label"), 80, default="") or None
    sort_order = as_int(request.form.get("sort_order"), 0, min_value=0, max_value=10_000)
    active = _bool(request.form.get("active"))

    try:
        t = CommissionTier(
            min_sales=min_sales,
            max_sales=max_sales,
            rate=rate,
            label=label,
            sort_order=sort_order,
            active=active,
        )
        db.session.add(t)
        if not _commit_or_flash("Tier creado", "No se pudo crear el tier"):
            return _redir("admin.commission_tiers")
        try:
            CommissionTier.validate_integrity()
        except Exception as e:
            _flash_warn(f"Creado, pero revisa integridad: {_clean_str(e, 180)}")
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
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
    rate_raw = request.form.get("rate")
    label = _clean_str(request.form.get("label"), 80, default="") or None
    sort_order = request.form.get("sort_order")
    active = request.form.get("active")

    if min_sales is not None and str(min_sales).strip() != "":
        _safe_set(t, "min_sales", as_int(min_sales, 0, min_value=0, max_value=1_000_000))

    if max_sales is not None:
        ms = str(max_sales).strip()
        _safe_set(t, "max_sales", None if ms == "" else as_int(ms, 0, min_value=0, max_value=1_000_000))

    if rate_raw is not None and str(rate_raw).strip() != "":
        _safe_set(t, "rate", _dec_rate(rate_raw, Decimal("0.0000")))

    _safe_set(t, "label", label)

    if sort_order is not None and str(sort_order).strip() != "":
        _safe_set(t, "sort_order", as_int(sort_order, 0, min_value=0, max_value=10_000))

    if active is not None:
        _safe_set(t, "active", _bool(active))

    if _commit_or_flash("Tier actualizado", "No se pudo actualizar el tier"):
        try:
            CommissionTier.validate_integrity()
        except Exception as e:
            _flash_warn(f"Guardado, pero revisa integridad: {_clean_str(e, 180)}")

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
        if _commit_or_flash("Tier eliminado", "No se pudo eliminar el tier"):
            try:
                CommissionTier.validate_integrity()
            except Exception as e:
                _flash_warn(f"Eliminado, pero revisa integridad: {_clean_str(e, 180)}")
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        _flash_err("No se pudo eliminar el tier")

    return _redir("admin.commission_tiers")


@admin_bp.get("/categories")
@admin_required
def categories():
    try:
        cats = Category.query.order_by(Category.name.asc()).all()
    except Exception:
        cats = []
        try:
            db.session.rollback()
        except Exception:
            pass
    return _render_safe("admin/categories.html", categories=cats, csrf_token=_csrf_token())


@admin_bp.post("/categories/new")
@admin_required
def categories_new():
    _require_csrf()

    name = _clean_str(request.form.get("name"), 120, default="")
    if not name:
        _flash_warn("Nombre requerido")
        return _redir("admin.categories")

    slug = _unique_slug(Category, _clean_str(request.form.get("slug"), 120, default="") or name)

    try:
        db.session.add(Category(name=name, slug=slug))
        _commit_or_flash("Categoria creada", "No se pudo crear la categoria")
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        _flash_err("No se pudo crear la categoria")

    return _redir("admin.categories")


@admin_bp.post("/categories/edit/<int:id>")
@admin_required
def categories_edit(id: int):
    _require_csrf()

    c = db.session.get(Category, id)
    if not c:
        _flash_warn("Categoria no encontrada")
        return _redir("admin.categories")

    name = _clean_str(request.form.get("name"), 120, default="")
    slug_in = _clean_str(request.form.get("slug"), 120, default="")

    if name:
        _safe_set(c, "name", name)

    if slug_in or name:
        base = slug_in or name or getattr(c, "name", "item")
        new_slug = _unique_slug(Category, base, id_exclude=id)
        _safe_set(c, "slug", new_slug)

    _commit_or_flash("Categoria actualizada", "No se pudo actualizar la categoria")
    return _redir("admin.categories")


@admin_bp.post("/categories/delete/<int:id>")
@admin_required
def categories_delete(id: int):
    _require_csrf()

    c = db.session.get(Category, id)
    if c:
        try:
            db.session.delete(c)
            _commit_or_flash("Categoria eliminada", "No se pudo eliminar la categoria")
        except Exception:
            try:
                db.session.rollback()
            except Exception:
                pass
            _flash_err("No se pudo eliminar la categoria")
    return _redir("admin.categories")


def _paginate(query, page: int, per_page: int):
    page = max(1, int(page))
    per_page = max(1, min(int(per_page), 200))
    try:
        return query.paginate(page=page, per_page=per_page, error_out=False)
    except Exception:
        try:
            total = int(query.order_by(None).count())
        except Exception:
            try:
                db.session.rollback()
            except Exception:
                pass
            total = None

        try:
            items = query.limit(per_page).offset((page - 1) * per_page).all()
        except Exception:
            try:
                db.session.rollback()
            except Exception:
                pass
            items = []

        if total is None:
            pages = max(1, page)
            total_out = len(items)
        else:
            pages = max(1, (total + per_page - 1) // per_page)
            total_out = total

        return type("P", (), {"items": items, "page": page, "pages": pages, "total": total_out})()


@admin_bp.get("/products")
@admin_required
def products():
    q = _clean_str(request.args.get("q"), _MAX_Q, default="")
    page = as_int(request.args.get("page"), 1, min_value=1, max_value=1_000_000)
    per_page = as_int(request.args.get("per_page"), 50, min_value=1, max_value=200)

    query = Product.query.order_by(Product.id.desc())

    if q:
        field = Product.title if hasattr(Product, "title") else Product.name
        try:
            query = query.filter(field.ilike(f"%{q}%"))
        except Exception:
            try:
                db.session.rollback()
            except Exception:
                pass

    try:
        pag = _paginate(query, page, per_page)
        items = list(pag.items)
        total = int(getattr(pag, "total", len(items)) or 0)
        pages = int(getattr(pag, "pages", 1) or 1)
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
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
        try:
            db.session.rollback()
        except Exception:
            pass
    return _render_safe("admin/product_edit.html", product=None, categories=cats, csrf_token=_csrf_token())


@admin_bp.post("/products/new")
@admin_required
def products_create():
    _require_csrf()

    title = _clean_str(request.form.get("title"), 180, default="")
    if not title:
        _flash_warn("Titulo requerido")
        return _redir("admin.products_new")

    slug = _unique_slug(Product, _clean_str(request.form.get("slug"), 180, default="") or title)
    price = as_float(request.form.get("price"), 0.0) or 0.0
    price = max(0.0, min(float(price), 10_000_000.0))
    stock = as_int(request.form.get("stock"), 0, min_value=0, max_value=1_000_000)
    status = _clean_str(request.form.get("status"), 16, default="active").lower()
    if status not in SAFE_STATUSES:
        status = "active"

    image_url: Optional[str] = None
    try:
        image_url = save_upload(request.files.get("image"), "products", ALLOWED_IMAGES)
    except Exception as e:
        _flash_err(_clean_str(e, 220, default="Error subiendo imagen"))

    p = Product()
    _safe_set(p, "title", title)
    _safe_set(p, "name", title)
    _safe_set(p, "slug", slug)
    _safe_set(p, "price", float(price))

    if not _safe_set(p, "stock", stock):
        _safe_set(p, "stock_qty", stock)

    _safe_set(p, "status", status)
    if image_url:
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
        try:
            db.session.rollback()
        except Exception:
            pass
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
        try:
            db.session.rollback()
        except Exception:
            pass

    return _render_safe("admin/product_edit.html", product=p, categories=cats, csrf_token=_csrf_token())


@admin_bp.post("/products/edit/<int:id>")
@admin_required
def products_update(id: int):
    _require_csrf()

    p = db.session.get(Product, id)
    if not p:
        _flash_warn("Producto no encontrado")
        return _redir("admin.products")

    title = _clean_str(request.form.get("title"), 180, default="")
    slug_in = _clean_str(request.form.get("slug"), 180, default="")
    price = as_float(request.form.get("price"), None)
    stock = as_int(request.form.get("stock"), -1)
    status = _clean_str(request.form.get("status"), 16, default="").lower()

    if title:
        _safe_set(p, "title", title)
        _safe_set(p, "name", title)

    base_slug = slug_in or title or getattr(p, "slug", "item")
    _safe_set(p, "slug", _unique_slug(Product, base_slug, id_exclude=id))

    if price is not None:
        pr = max(0.0, min(float(price), 10_000_000.0))
        _safe_set(p, "price", float(pr))

    if stock >= 0:
        st = max(0, min(int(stock), 1_000_000))
        if not _safe_set(p, "stock", st):
            _safe_set(p, "stock_qty", st)

    if status:
        _safe_set(p, "status", status if status in SAFE_STATUSES else "active")

    cat_id = as_int(request.form.get("category_id"), 0, min_value=0)
    if cat_id:
        _safe_set(p, "category_id", cat_id)

    try:
        img = save_upload(request.files.get("image"), "products", ALLOWED_IMAGES)
        if img:
            _safe_set(p, "image_url", img)
    except Exception as e:
        _flash_err(_clean_str(e, 220, default="Error subiendo imagen"))

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
            try:
                db.session.rollback()
            except Exception:
                pass
            _flash_err("No se pudo eliminar el producto")
    return _redir("admin.products")


@admin_bp.get("/offers")
@admin_required
def offers():
    try:
        items = Offer.query.order_by(Offer.sort_order.asc()).all()
    except Exception:
        items = []
        try:
            db.session.rollback()
        except Exception:
            pass
    return _render_safe("admin/offers.html", offers=items, csrf_token=_csrf_token())


@admin_bp.post("/offers/new")
@admin_required
def offers_new():
    _require_csrf()

    title = _clean_str(request.form.get("title"), 180, default="")
    if not title:
        _flash_warn("Titulo requerido")
        return _redir("admin.offers")

    media: Optional[str] = None
    try:
        media = save_upload(request.files.get("media"), "offers", ALLOWED_MEDIA)
    except Exception as e:
        _flash_err(_clean_str(e, 220, default="Error subiendo media"))

    o = Offer()
    _safe_set(o, "title", title)
    _safe_set(o, "active", _bool(request.form.get("active")))
    _safe_set(o, "sort_order", as_int(request.form.get("sort_order"), 0, min_value=0, max_value=10_000))

    if media:
        if not _safe_set(o, "media_url", media):
            _safe_set(o, "image_url", media)

    try:
        db.session.add(o)
        _commit_or_flash("Oferta creada", "No se pudo crear la oferta")
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
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
            try:
                db.session.rollback()
            except Exception:
                pass
            _flash_err("No se pudo eliminar la oferta")
    return _redir("admin.offers")


__all__ = ["admin_bp"]
