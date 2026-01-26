# app/routes/affiliate_routes.py — Skyline Store (ULTRA PRO v3.0 / FINAL / BULLETPROOF)
from __future__ import annotations

import csv
import hmac
import hashlib
import io
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from flask import (
    Blueprint,
    current_app,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
    g,
)
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.wrappers import Response
from urllib.parse import urlparse

from app.models import db

try:
    from app.models.affiliate import AffiliatePartner, AffiliateClick  # type: ignore
except Exception:  # pragma: no cover
    AffiliatePartner = None  # type: ignore
    AffiliateClick = None  # type: ignore

try:
    from app.models import Product  # type: ignore
except Exception:  # pragma: no cover
    Product = None  # type: ignore


affiliate_bp = Blueprint("affiliate", __name__, url_prefix="/aff")

_TRUE = {"1", "true", "yes", "y", "on"}
_AFF_CODE_RE = re.compile(r"^[a-z0-9][a-z0-9\-_]{1,79}$")
_SUB_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-_\.]{0,119}$")

AFF_SESSION_KEY = "aff_ctx_v3"
AFF_COOKIE_NAME = (os.getenv("AFF_COOKIE_NAME") or "sky_aff").strip() or "sky_aff"
AFF_COOKIE_VERSION = "v1"

def _env_int(name: str, default: int, *, min_v: int, max_v: int) -> int:
    try:
        v = int((os.getenv(name) or str(default)).strip())
    except Exception:
        v = default
    return max(min_v, min(max_v, v))

def _env_float(name: str, default: float, *, min_v: float, max_v: float) -> float:
    try:
        v = float((os.getenv(name) or str(default)).strip())
    except Exception:
        v = default
    return max(min_v, min(max_v, v))

AFF_TTL_DAYS = _env_int("AFF_TTL_DAYS", 14, min_v=1, max_v=90)
AFF_USE_COOKIE = (os.getenv("AFF_USE_COOKIE") or "1").strip().lower() in _TRUE
AFF_ALLOW_JSON = (os.getenv("AFF_ALLOW_JSON") or "1").strip().lower() in _TRUE

RL_WINDOW_SEC = _env_float("AFF_RL_WINDOW", 2.0, min_v=0.25, max_v=60.0)
RL_MAX_ACTIONS = _env_int("AFF_RL_MAX", 18, min_v=3, max_v=300)
_RL_MEM: Dict[str, Dict[str, Any]] = {}

_TPL_CACHE: Dict[str, bool] = {}
_TPL_CACHE_MAX = 256

_MAX_QUERY_KEYS = 64
_MAX_KEY_LEN = 60
_MAX_VAL_LEN = 240


def _utc_ts() -> int:
    return int(time.time())

def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)

def _ttl_days() -> int:
    return AFF_TTL_DAYS

def _wants_json() -> bool:
    if not AFF_ALLOW_JSON:
        return False
    accept = (request.headers.get("Accept") or "").lower()
    ctype = (request.headers.get("Content-Type") or "").lower()
    return (
        ("application/json" in accept)
        or ("application/json" in ctype)
        or (request.args.get("format") == "json")
        or (request.args.get("json") == "1")
    )

def _template_exists(name: str) -> bool:
    cached = _TPL_CACHE.get(name)
    if cached is not None:
        return cached
    ok = False
    try:
        current_app.jinja_env.get_template(name)
        ok = True
    except Exception:
        ok = False
    if len(_TPL_CACHE) >= _TPL_CACHE_MAX:
        _TPL_CACHE.clear()
    _TPL_CACHE[name] = ok
    return ok

def _render_safe(template: str, *, status: int = 200, **ctx):
    if _template_exists(template):
        return render_template(template, **ctx), status
    if _wants_json():
        return jsonify(ok=True, template_missing=template, data=ctx), status
    title = str(ctx.get("title") or "Skyline Store")
    html = (
        "<!doctype html><html lang='es'>"
        "<head><meta charset='utf-8'>"
        f"<title>{title}</title></head>"
        "<body style='font-family:system-ui;padding:24px'>"
        f"<h1>{title}</h1>"
        f"<p style='opacity:.7'>Template faltante: <code>{template}</code></p>"
        "</body></html>"
    )
    return html, status, {"Content-Type": "text/html; charset=utf-8"}

def _safe_next(target: str) -> bool:
    if not target:
        return False
    t = target.strip()
    return t.startswith("/") and not t.startswith("//")

def _same_origin_referrer_path() -> Optional[str]:
    ref = (request.referrer or "").strip()
    if not ref:
        return None
    try:
        ref_u = urlparse(ref)
        host = request.host
        if not host:
            return None
        if ref_u.netloc != host:
            return None
        path = ref_u.path or "/"
        if not path.startswith("/"):
            return None
        q = f"?{ref_u.query}" if ref_u.query else ""
        return f"{path}{q}"
    except Exception:
        return None

def _redirect_target() -> str:
    nxt = (request.args.get("next") or "").strip()
    if nxt and _safe_next(nxt):
        return nxt

    ref_path = _same_origin_referrer_path()
    if ref_path and _safe_next(ref_path):
        return ref_path

    for ep in ("shop.shop", "main.home"):
        try:
            return url_for(ep)
        except Exception:
            continue
    return "/shop"

def _client_fingerprint() -> str:
    ip = (request.headers.get("X-Forwarded-For") or request.remote_addr or "0.0.0.0").split(",")[0].strip()
    ua = (request.headers.get("User-Agent") or "")[:120]
    return f"{ip}|{ua}"

def _rl_cleanup(now: float) -> None:
    if len(_RL_MEM) < 1200:
        return
    cutoff = now - max(RL_WINDOW_SEC * 4.0, 10.0)
    dead: List[str] = []
    for k, st in _RL_MEM.items():
        try:
            if float(st.get("start", 0.0)) < cutoff:
                dead.append(k)
        except Exception:
            dead.append(k)
    for k in dead[:4000]:
        _RL_MEM.pop(k, None)

def _rate_limit_ok(bucket: str) -> bool:
    key = f"{bucket}:{_client_fingerprint()}"
    now = time.time()
    _rl_cleanup(now)

    st = _RL_MEM.get(key) or {"start": now, "count": 0}
    start = float(st.get("start", now))
    cnt = int(st.get("count", 0))
    if now - start > RL_WINDOW_SEC:
        st = {"start": now, "count": 1}
    else:
        st["count"] = cnt + 1
    _RL_MEM[key] = st
    if int(st["count"]) > RL_MAX_ACTIONS:
        return False

    try:
        s_key = "_aff_rl_v3"
        s = session.get(s_key)
        if not isinstance(s, dict):
            s = {}
        b = s.get(bucket)
        if not isinstance(b, dict):
            b = {}
        win_start = float(b.get("start", now))
        count = int(b.get("count", 0))
        if now - win_start > RL_WINDOW_SEC:
            b = {"start": now, "count": 1}
        else:
            b["count"] = count + 1
        s[bucket] = b
        session[s_key] = s
        session.modified = True
        if int(b.get("count", 0)) > RL_MAX_ACTIONS:
            return False
    except Exception:
        pass

    return True

def _clean_aff(v: Any) -> str:
    s = ("" if v is None else str(v)).strip().lower()
    if not s:
        return ""
    s = s.replace(" ", "-")
    cleaned = "".join(ch for ch in s if ch.isalnum() or ch in {"-", "_"})
    cleaned = cleaned[:80]
    return cleaned if cleaned and _AFF_CODE_RE.match(cleaned) else ""

def _clean_sub(v: Any) -> Optional[str]:
    s = ("" if v is None else str(v)).strip()
    if not s:
        return None
    s = s[:120]
    return s if _SUB_RE.match(s) else None

def _clean_utm() -> Dict[str, str]:
    keys = ("utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content")
    out: Dict[str, str] = {}
    for k in keys:
        v = (request.args.get(k) or "").strip()
        if v:
            out[k] = v[:120]
    return out

def _get_product_id_from_request() -> Optional[int]:
    pid = request.args.get("product_id") or request.args.get("pid")
    if pid:
        try:
            return int(str(pid).strip())
        except Exception:
            return None
    slug = (request.args.get("slug") or "").strip()
    if slug and Product is not None:
        try:
            p = Product.query.filter_by(slug=slug).first()
            return int(p.id) if p else None
        except Exception:
            return None
    return None

def _partner_lookup(aff_code: str) -> Optional[Any]:
    if not aff_code or AffiliatePartner is None:
        return None
    try:
        p = AffiliatePartner.query.filter_by(code=aff_code).first()
        if not p:
            return None
        if hasattr(p, "active") and not bool(getattr(p, "active")):
            return None
        return p
    except Exception:
        return None

def _secret_bytes() -> bytes:
    secret = (current_app.config.get("SECRET_KEY") or os.getenv("SECRET_KEY") or "").strip()
    if not secret:
        secret = "dev-secret"
    return secret.encode("utf-8")

def _sign(payload: str) -> str:
    return hmac.new(_secret_bytes(), payload.encode("utf-8"), hashlib.sha256).hexdigest()

def _cookie_pack(aff: str, sub: Optional[str], exp: int) -> str:
    sub_s = sub or ""
    payload = f"{AFF_COOKIE_VERSION}|{aff}|{sub_s}|{exp}"
    return f"{payload}|{_sign(payload)}"

def _cookie_unpack(value: str) -> Optional[Dict[str, Any]]:
    try:
        parts = (value or "").split("|")
        if len(parts) != 5:
            return None
        ver, aff, sub, exp_s, sig = parts
        if ver != AFF_COOKIE_VERSION:
            return None
        payload = f"{ver}|{aff}|{sub}|{exp_s}"
        if not hmac.compare_digest(_sign(payload), sig):
            return None
        exp = int(exp_s)
        if exp and _utc_ts() > exp:
            return None
        aff_c = _clean_aff(aff)
        sub_c = _clean_sub(sub) if sub else None
        if not aff_c:
            return None
        return {"aff": aff_c, "sub": sub_c, "exp": exp}
    except Exception:
        return None

def _store_aff_context(aff_code: str, sub_code: Optional[str]) -> Dict[str, Any]:
    now = _utc_ts()
    ctx = {"aff": aff_code, "sub": sub_code, "ts": now, "exp": now + _ttl_days() * 86400}
    session[AFF_SESSION_KEY] = ctx
    session.modified = True
    return ctx

def _load_aff_context_from_session() -> Optional[Dict[str, Any]]:
    ctx = session.get(AFF_SESSION_KEY)
    if not isinstance(ctx, dict):
        return None
    exp = int(ctx.get("exp") or 0)
    if exp and _utc_ts() > exp:
        session.pop(AFF_SESSION_KEY, None)
        session.modified = True
        return None
    aff = _clean_aff(ctx.get("aff"))
    sub = _clean_sub(ctx.get("sub"))
    if not aff:
        return None
    return {"aff": aff, "sub": sub, "ts": int(ctx.get("ts") or 0), "exp": exp}

def _clear_aff_context() -> None:
    session.pop(AFF_SESSION_KEY, None)
    session.modified = True

def _cookie_defaults() -> Tuple[bool, str]:
    secure_cfg = current_app.config.get("SESSION_COOKIE_SECURE")
    samesite_cfg = current_app.config.get("SESSION_COOKIE_SAMESITE") or "Lax"
    secure = bool(secure_cfg) if secure_cfg is not None else (not current_app.debug)
    samesite = str(samesite_cfg)
    if samesite not in ("Lax", "Strict", "None"):
        samesite = "Lax"
    return secure, samesite

def _set_cookie(resp: Response, aff_code: str, sub_code: Optional[str], exp: int) -> None:
    if not AFF_USE_COOKIE:
        return
    secure, samesite = _cookie_defaults()
    now = _utc_ts()
    max_age = max(60, min(_ttl_days() * 86400, max(60, exp - now)))
    resp.set_cookie(
        AFF_COOKIE_NAME,
        value=_cookie_pack(aff_code, sub_code, exp),
        max_age=max_age,
        httponly=True,
        samesite=samesite,
        secure=secure,
        path="/",
    )

def _unset_cookie(resp: Response) -> None:
    if not AFF_USE_COOKIE:
        return
    resp.set_cookie(AFF_COOKIE_NAME, "", expires=0, path="/")

def _load_aff_context_from_cookie() -> Optional[Dict[str, Any]]:
    if not AFF_USE_COOKIE:
        return None
    v = request.cookies.get(AFF_COOKIE_NAME)
    if not v:
        return None
    return _cookie_unpack(v)

def _log_click(aff_code: str, sub_code: Optional[str]) -> bool:
    if AffiliateClick is None:
        return False
    try:
        ip = ((request.headers.get("X-Forwarded-For") or request.remote_addr or "").split(",")[0].strip()[:80]) or None
        ua = (request.headers.get("User-Agent") or "")[:300] or None
        ref = (request.referrer or "")[:500] or None
        pid = _get_product_id_from_request()

        safe_q: Dict[str, str] = {}
        for i, k in enumerate(request.args.keys()):
            if i >= _MAX_QUERY_KEYS:
                break
            if not k or len(k) > _MAX_KEY_LEN:
                continue
            v = (request.args.get(k) or "").strip()
            if v:
                safe_q[k] = v[:_MAX_VAL_LEN]

        meta: Dict[str, Any] = {"utm": _clean_utm(), "path": (request.path or "")[:200], "query": safe_q}

        click = AffiliateClick(
            aff_code=aff_code,
            sub_code=sub_code,
            product_id=pid,
            ip=ip,
            user_agent=ua,
            referrer=ref,
            meta=meta,
        )
        db.session.add(click)
        db.session.commit()
        return True
    except SQLAlchemyError as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        current_app.logger.info("AffiliateClick insert failed (ignored): %s", e)
        return False
    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        current_app.logger.info("AffiliateClick insert failed (ignored): %s", e)
        return False

def get_affiliate_context() -> Optional[Dict[str, Any]]:
    ctx = _load_aff_context_from_session()
    if ctx:
        return {"aff": ctx["aff"], "sub": ctx.get("sub")}
    c = _load_aff_context_from_cookie()
    if c:
        return {"aff": c["aff"], "sub": c.get("sub")}
    return None

def get_affiliate_code() -> Optional[str]:
    ctx = get_affiliate_context()
    return ctx.get("aff") if ctx else None

def apply_affiliate_to_order(order: Any) -> bool:
    ctx = get_affiliate_context()
    if not ctx:
        return False
    ok = False
    try:
        if hasattr(order, "aff_code"):
            setattr(order, "aff_code", ctx.get("aff"))
            ok = True
        if hasattr(order, "aff_sub"):
            setattr(order, "aff_sub", ctx.get("sub"))
            ok = True
        if hasattr(order, "affiliate_code"):
            setattr(order, "affiliate_code", ctx.get("aff"))
            ok = True
        if hasattr(order, "affiliate_sub"):
            setattr(order, "affiliate_sub", ctx.get("sub"))
            ok = True
    except Exception:
        return False
    return ok

@affiliate_bp.before_app_request
def _inject_aff_into_g() -> None:
    try:
        g.aff_ctx = get_affiliate_context()
    except Exception:
        g.aff_ctx = None

@affiliate_bp.app_context_processor
def _inject_aff_into_templates():
    return {"aff_ctx": getattr(g, "aff_ctx", None)}

def _is_admin_session() -> bool:
    v = session.get("is_admin", False)
    if isinstance(v, str):
        return v.strip().lower() in _TRUE
    return bool(v)

def _admin_required():
    if _is_admin_session():
        return None
    try:
        uid = session.get("user_id")
        if uid:
            from app.models import User  # type: ignore
            u = db.session.get(User, int(uid))
            if u and bool(getattr(u, "is_admin", False)):
                return None
    except Exception:
        pass

    if _wants_json():
        return jsonify(ok=False, error="admin_required"), 403
    try:
        return redirect(url_for("admin.login"))
    except Exception:
        return redirect("/admin/login")

@affiliate_bp.get("/health")
def aff_health():
    ok_models = bool(AffiliatePartner is not None and AffiliateClick is not None)
    return jsonify(
        ok=True,
        models=ok_models,
        ttl_days=_ttl_days(),
        cookie=bool(AFF_USE_COOKIE),
        rl={"window": RL_WINDOW_SEC, "max": RL_MAX_ACTIONS},
    )

@affiliate_bp.get("/go")
def aff_go():
    if not _rate_limit_ok("go"):
        if _wants_json():
            return jsonify(ok=False, error="rate_limited"), 429
        return redirect(_redirect_target())

    aff_code = _clean_aff(request.args.get("aff"))
    sub_code = _clean_sub(request.args.get("sub"))

    if not aff_code:
        if _wants_json():
            return jsonify(ok=False, error="aff_required"), 400
        return redirect(_redirect_target())

    if AffiliatePartner is not None:
        partner = _partner_lookup(aff_code)
        if not partner:
            if _wants_json():
                return jsonify(ok=False, error="affiliate_not_found_or_inactive"), 404
            return redirect(_redirect_target())

    ctx = _store_aff_context(aff_code, sub_code)
    _log_click(aff_code, sub_code)

    target = _redirect_target()

    if _wants_json():
        return jsonify(ok=True, aff=aff_code, sub=sub_code, next=target)

    resp = make_response(redirect(target))
    _set_cookie(resp, aff_code, sub_code, int(ctx["exp"]))
    return resp

@affiliate_bp.get("/attach")
def aff_attach():
    return aff_go()

@affiliate_bp.post("/clear")
def aff_clear():
    if not _rate_limit_ok("clear"):
        return jsonify(ok=False, error="rate_limited"), 429

    _clear_aff_context()

    if _wants_json():
        return jsonify(ok=True)

    resp = make_response(redirect(_redirect_target()))
    _unset_cookie(resp)
    return resp

@affiliate_bp.get("/me")
def aff_me():
    ctx = get_affiliate_context()
    if _wants_json():
        return jsonify(ok=True, affiliate=ctx)
    return _render_safe("affiliate/me.html", title="Afiliado", affiliate=ctx)

@affiliate_bp.get("/pixel.js")
def aff_pixel():
    ctx = get_affiliate_context() or {}
    js = "window.__AFF=" + json.dumps({"aff": ctx.get("aff"), "sub": ctx.get("sub")}, ensure_ascii=False) + ";"
    resp = make_response(js)
    resp.headers["Content-Type"] = "application/javascript; charset=utf-8"
    resp.headers["Cache-Control"] = "no-store, max-age=0"
    return resp

@affiliate_bp.get("/admin")
def admin_dashboard():
    guard = _admin_required()
    if guard:
        return guard

    if AffiliatePartner is None or AffiliateClick is None:
        if _wants_json():
            return jsonify(ok=False, error="affiliate_models_missing"), 501
        return _render_safe("affiliate/admin.html", title="Afiliados", partners=[], stats={}, clicks=[])

    aff = _clean_aff(request.args.get("aff"))
    days = request.args.get("days") or "30"
    try:
        days_i = max(1, min(365, int(str(days).strip())))
    except Exception:
        days_i = 30

    since_dt = _utcnow_naive()
    try:
        since_dt = datetime.fromtimestamp(_utc_ts() - days_i * 86400, tz=timezone.utc).replace(tzinfo=None)
    except Exception:
        pass

    partners: List[Any] = []
    clicks: List[Any] = []
    stats: Dict[str, Any] = {"days": days_i, "since": since_dt.isoformat()}

    try:
        partners_q = AffiliatePartner.query.order_by(
            AffiliatePartner.active.desc(),
            AffiliatePartner.created_at.desc(),
        )
        partners = partners_q.limit(800).all()

        clicks_q = AffiliateClick.query.filter(AffiliateClick.created_at >= since_dt)
        if aff:
            clicks_q = clicks_q.filter(AffiliateClick.aff_code == aff)
        clicks = clicks_q.order_by(AffiliateClick.created_at.desc()).limit(400).all()

        agg = (
            db.session.query(
                AffiliateClick.aff_code,
                func.count(AffiliateClick.id).label("clicks"),
            )
            .filter(AffiliateClick.created_at >= since_dt)
            .group_by(AffiliateClick.aff_code)
            .order_by(func.count(AffiliateClick.id).desc())
            .limit(50)
            .all()
        )
        stats["top"] = [{"aff": a, "clicks": int(c)} for a, c in agg]
    except Exception as e:
        current_app.logger.warning(
            "Affiliate admin dashboard failed: %s", e, exc_info=bool(current_app.debug)
        )

    if _wants_json():
        return jsonify(
            ok=True,
            partners=[
                {
                    "id": getattr(p, "id", None),
                    "code": getattr(p, "code", None),
                    "name": getattr(p, "name", None),
                    "active": bool(getattr(p, "active", False)),
                    "rate": str(getattr(p, "commission_rate", "0")),
                    "created_at": (p.created_at.isoformat() if getattr(p, "created_at", None) else None),
                }
                for p in partners
            ],
            clicks=[
                {
                    "id": getattr(c, "id", None),
                    "aff": getattr(c, "aff_code", None),
                    "sub": getattr(c, "sub_code", None),
                    "product_id": getattr(c, "product_id", None),
                    "ip": getattr(c, "ip", None),
                    "ref": getattr(c, "referrer", None),
                    "created_at": (c.created_at.isoformat() if getattr(c, "created_at", None) else None),
                }
                for c in clicks
            ],
            stats=stats,
        )

    return _render_safe(
        "affiliate/admin.html",
        title="Afiliados · Admin",
        partners=partners,
        clicks=clicks,
        stats=stats,
    )

@affiliate_bp.get("/admin/export.csv")
def admin_export_csv():
    guard = _admin_required()
    if guard:
        return guard

    if AffiliateClick is None:
        return jsonify(ok=False, error="affiliate_models_missing"), 501

    days = request.args.get("days") or "30"
    try:
        days_i = max(1, min(365, int(str(days).strip())))
    except Exception:
        days_i = 30

    try:
        since_dt = datetime.fromtimestamp(_utc_ts() - days_i * 86400, tz=timezone.utc).replace(tzinfo=None)
    except Exception:
        since_dt = _utcnow_naive()

    aff = _clean_aff(request.args.get("aff"))

    rows: List[Any] = []
    try:
        q = AffiliateClick.query.filter(AffiliateClick.created_at >= since_dt)
        if aff:
            q = q.filter(AffiliateClick.aff_code == aff)
        rows = q.order_by(AffiliateClick.created_at.desc()).limit(10000).all()
    except Exception as e:
        current_app.logger.warning("CSV export failed: %s", e)
        rows = []

    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(["id", "created_at", "aff_code", "sub_code", "product_id", "ip", "referrer", "user_agent"])
    for c in rows:
        created = getattr(c, "created_at", None)
        w.writerow(
            [
                getattr(c, "id", ""),
                (created.isoformat() if created else ""),
                getattr(c, "aff_code", ""),
                getattr(c, "sub_code", ""),
                getattr(c, "product_id", ""),
                getattr(c, "ip", ""),
                getattr(c, "referrer", ""),
                getattr(c, "user_agent", ""),
            ]
        )

    resp = make_response(output.getvalue())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename="affiliate_clicks_{days_i}d.csv"'
    resp.headers["Cache-Control"] = "no-store, max-age=0"
    return resp

@affiliate_bp.get("/")
def aff_home():
    return _render_safe("affiliate/index.html", title="Programa de Afiliados")

__all__ = ["affiliate_bp", "get_affiliate_context", "get_affiliate_code", "apply_affiliate_to_order"]
