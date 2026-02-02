from __future__ import annotations

import csv
import hmac
import io
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from flask import (
    Blueprint,
    Response,
    current_app,
    jsonify,
    render_template,
    request,
    session,
    url_for,
)
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app import db

# ============================================================
# Blueprint
# ============================================================

marketing_bp = Blueprint("marketing", __name__)

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
MAX_EMAIL_LEN = 254
MAX_SOURCE_LEN = 64

# Payload hardening
MAX_BODY_BYTES = 64_000  # 64KB: suficiente para form/json sin riesgo
DEFAULT_UNSUB_TTL = 60 * 60 * 24 * 365  # 1 año


# ============================================================
# Helpers base
# ============================================================


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _template_exists(name: str) -> bool:
    try:
        current_app.jinja_env.get_template(name)
        return True
    except Exception:
        return False


def _normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def _validate_email(email: str) -> Tuple[bool, str]:
    email = _normalize_email(email)
    if not email:
        return False, "Email requerido."
    if len(email) > MAX_EMAIL_LEN:
        return False, "Email demasiado largo."
    if not EMAIL_RE.match(email):
        return False, "Email inválido."
    return True, email


def _safe_int(v: Any, default: int, *, min_value: int = 0, max_value: int = 10_000) -> int:
    try:
        n = int(str(v).strip())
    except Exception:
        return default
    if n < min_value:
        return min_value
    if n > max_value:
        return max_value
    return n


def _client_ip() -> str:
    """
    Respeta proxy (Render/Cloudflare) si existe.
    Si tenés ProxyFix configurado, request.remote_addr suele ser correcto.
    """
    # Orden típico: CF-Connecting-IP, X-Real-IP, X-Forwarded-For
    cf = (request.headers.get("CF-Connecting-IP") or "").strip()
    if cf:
        return cf

    xri = (request.headers.get("X-Real-IP") or "").strip()
    if xri:
        return xri

    xff = (request.headers.get("X-Forwarded-For") or "").strip()
    if xff:
        # xff puede ser "client, proxy1, proxy2"
        return xff.split(",")[0].strip()

    return (request.remote_addr or "unknown").strip() or "unknown"


def _too_large_body() -> bool:
    try:
        cl = request.content_length
        if cl is None:
            return False
        return int(cl) > MAX_BODY_BYTES
    except Exception:
        return False


# ============================================================
# Rate limit simple (sin dependencias) + GC para evitar crecimiento
# ============================================================


def _rl_store() -> Dict[str, Tuple[float, int]]:
    """
    key -> (reset_ts, count)
    Se guarda en current_app.extensions para evitar globales por proceso.
    """
    ext = current_app.extensions.setdefault("marketing_rl", {})
    if not isinstance(ext, dict):
        current_app.extensions["marketing_rl"] = {}
    return current_app.extensions["marketing_rl"]  # type: ignore


def _rl_gc(store: Dict[str, Tuple[float, int]], *, max_keys: int = 5000) -> None:
    """
    Limpieza suave para evitar crecimiento infinito:
    - borra entries expiradas
    - si excede max_keys, borra las más viejas por reset_ts
    """
    try:
        now = time.time()
        expired = [k for k, (reset_ts, _) in store.items() if now > float(reset_ts)]
        for k in expired[:2000]:
            store.pop(k, None)

        if len(store) > max_keys:
            # ordena por reset_ts asc (más viejas primero)
            items = sorted(store.items(), key=lambda kv: float(kv[1][0]))
            for k, _ in items[: max(0, len(store) - max_keys)]:
                store.pop(k, None)
    except Exception:
        # nunca romper por GC
        return


def _rate_limit(key: str, limit: int, window_seconds: int) -> bool:
    """
    True = permitido
    False = bloqueado
    """
    store = _rl_store()
    now = time.time()

    reset_ts, count = store.get(key, (now + window_seconds, 0.0))
    try:
        reset_ts = float(reset_ts)
        count = int(count)
    except Exception:
        reset_ts, count = now + window_seconds, 0

    if now > reset_ts:
        reset_ts, count = now + window_seconds, 0

    count += 1
    store[key] = (reset_ts, count)

    # GC ocasional y barata
    if count == 1 and (len(store) % 257 == 0):
        _rl_gc(store)

    return count <= limit


def _rate_limit_or_429(bucket: str, limit: int, window_seconds: int):
    ip = _client_ip()
    key = f"{bucket}:{ip}"
    if _rate_limit(key, limit=limit, window_seconds=window_seconds):
        return None
    return jsonify(ok=False, error="too_many_requests"), 429


# ============================================================
# Email service (opcional, NO rompe)
# ============================================================


def _try_send_email(to_email: str, subject: str, html: str, text: str = "") -> bool:
    try:
        from app.services.email_service import send_email  # type: ignore

        send_email(to=to_email, subject=subject, html=html, text=text or "")
        return True
    except Exception as exc:
        current_app.logger.debug("Email service no disponible o falló: %s", exc)
        return False


# ============================================================
# Subscriber model (opcional, fallback total)
# ============================================================

_SUBSCRIBER_MODEL_CACHE: Optional[Any] = None


def _get_subscriber_model():
    """
    Se resuelve "lazy" en runtime para evitar import circular.
    Cachea el resultado para evitar penalidad por request.
    """
    global _SUBSCRIBER_MODEL_CACHE
    if _SUBSCRIBER_MODEL_CACHE is not None:
        return _SUBSCRIBER_MODEL_CACHE

    candidates = [
        ("app.models.subscriber", "Subscriber"),
        ("app.models.subscribers", "Subscriber"),
        ("app.models", "Subscriber"),
    ]
    for module_path, attr in candidates:
        try:
            mod = __import__(module_path, fromlist=[attr])
            model = getattr(mod, attr)
            _SUBSCRIBER_MODEL_CACHE = model
            return model
        except Exception:
            continue

    _SUBSCRIBER_MODEL_CACHE = None
    return None


@dataclass
class _SubscriberFallback:
    email: str
    status: str = "subscribed"
    source: str = "web"
    created_at: datetime = field(default_factory=utcnow)
    unsubscribed_at: Optional[datetime] = None


# In-memory fallback store (no persistente, pero NO rompe)
_FALLBACK_STORE: Dict[str, _SubscriberFallback] = {}


def _get_or_create_fallback(email: str, source: str) -> _SubscriberFallback:
    sub = _FALLBACK_STORE.get(email)
    if not sub:
        sub = _SubscriberFallback(email=email, source=source)
        _FALLBACK_STORE[email] = sub
    return sub


# ============================================================
# Security / Admin
# ============================================================


def _is_admin() -> bool:
    # Sesión
    if session.get("is_admin") is True:
        return True

    # Header / query key (opcional)
    admin_key = current_app.config.get("MARKETING_ADMIN_KEY")
    if admin_key:
        got = (request.headers.get("X-Admin-Key") or request.args.get("key") or "").strip()
        if got and hmac.compare_digest(str(got), str(admin_key)):
            return True

    return False


def _require_admin():
    if _is_admin():
        return None
    return jsonify(ok=False, error="forbidden"), 403


# ============================================================
# Tokens unsubscribe
# ============================================================


def _serializer() -> Optional[URLSafeTimedSerializer]:
    secret = current_app.config.get("SECRET_KEY")
    if not secret:
        return None
    salt = current_app.config.get("MARKETING_TOKEN_SALT", "skyline-marketing")
    return URLSafeTimedSerializer(secret_key=secret, salt=salt)


def _unsubscribe_token(email: str) -> Optional[str]:
    s = _serializer()
    if not s:
        return None
    payload = {
        "purpose": "unsubscribe",
        "email": _normalize_email(email),
        "iat": int(utcnow().timestamp()),
    }
    return s.dumps(payload)


def _decode_unsubscribe_token(token: str, max_age: int) -> str:
    s = _serializer()
    if not s:
        raise BadSignature("Serializer no disponible")

    data = s.loads(token, max_age=max_age)
    if not isinstance(data, dict):
        raise BadSignature("Token inválido")

    if data.get("purpose") != "unsubscribe":
        raise BadSignature("Token inválido (purpose)")

    email = _normalize_email(str(data.get("email", "")))
    if not email:
        raise BadSignature("Token inválido (email)")
    return email


# ============================================================
# Payload parsing + anti-bot
# ============================================================


def _read_payload() -> Dict[str, Any]:
    # Body hardening (evita payload gigantes)
    if _too_large_body():
        return {}

    if request.is_json:
        return request.get_json(silent=True) or {}

    # fallback form
    try:
        return dict(request.form or {})
    except Exception:
        return {}


def _honeypot_triggered(payload: Dict[str, Any]) -> bool:
    """
    Campo trampa: si viene lleno, casi seguro bot.
    Front: <input type="text" name="company" style="display:none">
    """
    hp = (payload.get("company") or "").strip()
    return bool(hp)


def _clean_source(v: Any) -> str:
    s = (str(v) if v is not None else "").strip()
    if not s:
        s = "web"
    # solo caracteres básicos para evitar basura
    s = re.sub(r"[^a-zA-Z0-9_\-\. ]+", "", s)
    return s[:MAX_SOURCE_LEN]


# ============================================================
# Fallback HTML “premium” (visual/diseño) si faltan templates
# ============================================================


def _fallback_unsubscribe_html(ok: bool, message: str, email: str = "") -> str:
    title = "Suscripción" if ok else "Ups"
    badge = "✅" if ok else "⚠️"
    email_line = f"<div class='muted'>Email: <b>{email}</b></div>" if email else ""
    return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · Skyline Store</title>
<style>
:root{{
  --bg:#0b1120; --card:rgba(255,255,255,.06); --stroke:rgba(148,163,184,.18);
  --txt:#e5e7eb; --muted:#9ca3af; --a:#38bdf8; --b:#2563eb; --r:18px;
  --shadow:0 22px 70px rgba(0,0,0,.55);
}}
*{{box-sizing:border-box}}
body{{
  margin:0; min-height:100vh; display:grid; place-items:center; padding:20px;
  font-family:system-ui,-apple-system,Segoe UI,Roboto,Inter,Arial;
  color:var(--txt);
  background:
    radial-gradient(900px 600px at 0% 0%, rgba(56,189,248,.18), transparent 60%),
    radial-gradient(900px 600px at 100% 0%, rgba(37,99,235,.18), transparent 60%),
    radial-gradient(900px 700px at 50% 120%, rgba(34,197,94,.10), transparent 60%),
    var(--bg);
}}
.card{{
  width:min(720px, 100%);
  border:1px solid var(--stroke);
  background:linear-gradient(180deg, rgba(255,255,255,.08), rgba(255,255,255,.05));
  border-radius:var(--r);
  box-shadow:var(--shadow);
  overflow:hidden;
}}
.head{{padding:22px 22px 12px; display:flex; align-items:center; gap:12px}}
.logo{{
  width:42px; height:42px; border-radius:14px;
  background:linear-gradient(135deg, var(--a), var(--b));
  box-shadow:0 12px 28px rgba(56,189,248,.18);
}}
.h1{{font-size:18px; font-weight:800; margin:0}}
.sub{{margin:2px 0 0; color:var(--muted); font-size:13px}}
.body{{padding:18px 22px 22px}}
.msg{{font-size:16px; line-height:1.45; margin:0 0 10px}}
.muted{{color:var(--muted); font-size:13px}}
.hr{{height:1px; background:rgba(148,163,184,.18); margin:16px 0}}
.btn{{
  display:inline-flex; align-items:center; justify-content:center; gap:8px;
  padding:10px 14px; border-radius:12px; text-decoration:none; color:#06121f;
  background:linear-gradient(135deg, var(--a), var(--b));
  font-weight:800;
}}
.footer{{padding:14px 22px; color:var(--muted); font-size:12px; border-top:1px solid rgba(148,163,184,.14)}}
</style>
</head>
<body>
  <div class="card">
    <div class="head">
      <div class="logo" aria-hidden="true"></div>
      <div>
        <p class="h1">{badge} {title}</p>
        <p class="sub">Skyline Store · Marketing</p>
      </div>
    </div>
    <div class="body">
      <p class="msg">{message}</p>
      {email_line}
      <div class="hr"></div>
      <a class="btn" href="/">Volver a la tienda</a>
      <div class="footer">Si no solicitaste esto, podés ignorar este mensaje.</div>
    </div>
  </div>
</body>
</html>"""


def _fallback_admin_html(subscribers: List[Dict[str, Any]], *, total: int, limit: int, offset: int) -> str:
    rows = []
    for s in subscribers:
        rows.append(
            "<tr>"
            f"<td>{s.get('email','')}</td>"
            f"<td>{s.get('status','')}</td>"
            f"<td>{s.get('source','')}</td>"
            f"<td>{s.get('created_at','')}</td>"
            f"<td>{s.get('unsubscribed_at','')}</td>"
            "</tr>"
        )
    rows_html = "\n".join(rows) if rows else "<tr><td colspan='5' class='muted'>Sin datos</td></tr>"

    return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Marketing · Admin</title>
<style>
:root{{
  --bg:#0b1120; --card:rgba(255,255,255,.06); --stroke:rgba(148,163,184,.18);
  --txt:#e5e7eb; --muted:#9ca3af; --a:#38bdf8; --b:#2563eb; --r:18px;
}}
*{{box-sizing:border-box}}
body{{
  margin:0; padding:22px;
  font-family:system-ui,-apple-system,Segoe UI,Roboto,Inter,Arial;
  color:var(--txt);
  background:
    radial-gradient(900px 600px at 0% 0%, rgba(56,189,248,.14), transparent 60%),
    radial-gradient(900px 600px at 100% 0%, rgba(37,99,235,.14), transparent 60%),
    var(--bg);
}}
.wrap{{max-width:1100px; margin:0 auto}}
.top{{display:flex; justify-content:space-between; align-items:flex-end; gap:12px; margin-bottom:14px}}
h1{{margin:0; font-size:18px; font-weight:900}}
.meta{{color:var(--muted); font-size:12px}}
.card{{border:1px solid var(--stroke); background:rgba(255,255,255,.05); border-radius:var(--r); overflow:hidden}}
table{{width:100%; border-collapse:collapse}}
th,td{{padding:12px; border-bottom:1px solid rgba(148,163,184,.14); font-size:13px}}
th{{text-align:left; color:#cbd5e1; background:rgba(255,255,255,.04)}}
td{{color:#e5e7eb}}
.muted{{color:var(--muted)}}
.actions{{display:flex; gap:10px}}
a.btn{{text-decoration:none; color:#06121f; font-weight:900; font-size:12px;
  padding:10px 12px; border-radius:12px;
  background:linear-gradient(135deg, var(--a), var(--b));
}}
</style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div>
        <h1>Marketing · Suscriptores</h1>
        <div class="meta">Total: {total} · Mostrando {limit} · Offset {offset}</div>
      </div>
      <div class="actions">
        <a class="btn" href="/marketing/export.csv">Exportar CSV</a>
      </div>
    </div>

    <div class="card">
      <table>
        <thead>
          <tr>
            <th>Email</th><th>Status</th><th>Source</th><th>Created</th><th>Unsubscribed</th>
          </tr>
        </thead>
        <tbody>
          {rows_html}
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>"""


# ============================================================
# Subscribe
# ============================================================


@marketing_bp.post("/marketing/subscribe")
def subscribe():
    # Rate-limit: 8 intentos / 2 minutos por IP
    rl = _rate_limit_or_429("subscribe", limit=8, window_seconds=120)
    if rl:
        return rl

    payload = _read_payload()

    # Body demasiado grande => respuesta genérica para no revelar info
    if payload == {} and _too_large_body():
        return jsonify(ok=False, error="invalid_payload"), 400

    if _honeypot_triggered(payload):
        # Respondemos ok igual para no dar pistas a bots
        return jsonify(ok=True, subscribed=True, bot_filtered=True)

    email = payload.get("email", "") or ""
    source = _clean_source(payload.get("source") or "web")

    ok, result = _validate_email(email)
    if not ok:
        return jsonify(ok=False, error=result), 400

    email_norm = result
    SubscriberModel = _get_subscriber_model()

    # Fallback total si no existe modelo
    if SubscriberModel is None:
        sub = _get_or_create_fallback(email_norm, source)
        sub.status = "subscribed"
        sub.unsubscribed_at = None
        return jsonify(ok=True, subscribed=True, email=email_norm, fallback=True)

    try:
        sub = SubscriberModel.query.filter_by(email=email_norm).first()

        if sub and getattr(sub, "status", "") == "subscribed":
            return jsonify(ok=True, subscribed=True, email=email_norm, already=True)

        if not sub:
            sub = SubscriberModel(email=email_norm)
            db.session.add(sub)

        if hasattr(sub, "status"):
            sub.status = "subscribed"
        if hasattr(sub, "source"):
            sub.source = source
        if hasattr(sub, "unsubscribed_at"):
            sub.unsubscribed_at = None
        if hasattr(sub, "created_at") and getattr(sub, "created_at", None) is None:
            sub.created_at = utcnow()

        db.session.commit()

        token = _unsubscribe_token(email_norm)
        unsub_url = url_for("marketing.unsubscribe", token=token, _external=True) if token else None

        # Email HTML
        if _template_exists("emails/subscribed.html"):
            html = render_template("emails/subscribed.html", email=email_norm, unsubscribe_url=unsub_url)
        else:
            link = f"<a href='{unsub_url}'>Darme de baja</a>" if unsub_url else ""
            html = f"<p>Gracias por suscribirte.</p><p>{link}</p>"

        _try_send_email(
            to_email=email_norm,
            subject="Suscripción confirmada — Skyline Store",
            html=html,
            text=(f"Para darte de baja: {unsub_url}" if unsub_url else "Suscripción confirmada."),
        )

        return jsonify(ok=True, subscribed=True, email=email_norm)

    except Exception as exc:
        db.session.rollback()
        current_app.logger.exception("Subscribe error: %s", exc)
        return jsonify(ok=False, error="No se pudo procesar la suscripción."), 500


# ============================================================
# Unsubscribe
# ============================================================


@marketing_bp.get("/unsubscribe/<token>")
def unsubscribe(token: str):
    ttl = _safe_int(current_app.config.get("MARKETING_UNSUB_TTL_SECONDS", DEFAULT_UNSUB_TTL), DEFAULT_UNSUB_TTL, min_value=60, max_value=60 * 60 * 24 * 365 * 5)

    try:
        email = _decode_unsubscribe_token(token, ttl)
    except (SignatureExpired, BadSignature):
        # Si existe template, lo usamos
        if _template_exists("unsubscribe.html"):
            return render_template("unsubscribe.html", ok=False, message="Link inválido o expirado.")
        # Fallback visual premium
        return Response(_fallback_unsubscribe_html(False, "Link inválido o expirado."), mimetype="text/html; charset=utf-8")

    SubscriberModel = _get_subscriber_model()

    if SubscriberModel is None:
        sub = _FALLBACK_STORE.get(email)
        if sub:
            sub.status = "unsubscribed"
            sub.unsubscribed_at = utcnow()

        if _template_exists("unsubscribe.html"):
            return render_template("unsubscribe.html", ok=True, message="Baja realizada.", email=email)
        return Response(_fallback_unsubscribe_html(True, "Baja realizada.", email=email), mimetype="text/html; charset=utf-8")

    try:
        sub = SubscriberModel.query.filter_by(email=email).first()
        if sub:
            if hasattr(sub, "status"):
                sub.status = "unsubscribed"
            if hasattr(sub, "unsubscribed_at"):
                sub.unsubscribed_at = utcnow()
            db.session.commit()

        if _template_exists("unsubscribe.html"):
            return render_template("unsubscribe.html", ok=True, message="Baja confirmada.", email=email)
        return Response(_fallback_unsubscribe_html(True, "Baja confirmada.", email=email), mimetype="text/html; charset=utf-8")

    except Exception as exc:
        db.session.rollback()
        current_app.logger.exception("Unsubscribe error: %s", exc)
        if _template_exists("unsubscribe.html"):
            return render_template("unsubscribe.html", ok=False, message="Error al procesar la baja."), 500
        return Response(_fallback_unsubscribe_html(False, "Error al procesar la baja."), mimetype="text/html; charset=utf-8"), 500


# ============================================================
# Admin / API (paginado)
# ============================================================


def _sub_to_dict(s: Any) -> Dict[str, Any]:
    return {
        "email": getattr(s, "email", ""),
        "status": getattr(s, "status", ""),
        "source": getattr(s, "source", ""),
        "created_at": getattr(s, "created_at", ""),
        "unsubscribed_at": getattr(s, "unsubscribed_at", ""),
    }


@marketing_bp.get("/marketing")
def marketing_admin():
    gate = _require_admin()
    if gate:
        return gate

    SubscriberModel = _get_subscriber_model()

    limit = _safe_int(request.args.get("limit", 200), 200, min_value=1, max_value=500)
    offset = _safe_int(request.args.get("offset", 0), 0, min_value=0, max_value=10_000_000)

    wants_json = "application/json" in (request.headers.get("Accept") or "")

    if SubscriberModel is None:
        subs = list(_FALLBACK_STORE.values())[offset : offset + limit]
        total = len(_FALLBACK_STORE)

        if wants_json or not _template_exists("marketing_admin.html"):
            return jsonify(
                ok=True,
                total=total,
                limit=limit,
                offset=offset,
                subscribers=[_sub_to_dict(x) for x in subs],
                fallback=True,
            )

        # Template o fallback visual premium
        if _template_exists("marketing_admin.html"):
            return render_template("marketing_admin.html", subscribers=subs, total=total, limit=limit, offset=offset, fallback=True)

        return Response(
            _fallback_admin_html([_sub_to_dict(x) for x in subs], total=total, limit=limit, offset=offset),
            mimetype="text/html; charset=utf-8",
        )

    q = SubscriberModel.query
    order_col = getattr(SubscriberModel, "created_at", None) or getattr(SubscriberModel, "email", None)
    if order_col is None:
        order_col = SubscriberModel.email  # type: ignore

    subs = q.order_by(order_col.desc()).offset(offset).limit(limit).all()
    total = q.count()

    if wants_json or not _template_exists("marketing_admin.html"):
        return jsonify(
            ok=True,
            total=total,
            limit=limit,
            offset=offset,
            subscribers=[_sub_to_dict(x) for x in subs],
        )

    return render_template(
        "marketing_admin.html",
        subscribers=subs,
        total=total,
        limit=limit,
        offset=offset,
    )


# ============================================================
# Export CSV (streaming)
# ============================================================


def _csv_rows(items: Iterable[Any]) -> Iterable[str]:
    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(["email", "status", "source", "created_at", "unsubscribed_at"])
    yield output.getvalue()
    output.seek(0)
    output.truncate(0)

    for s in items:
        w.writerow(
            [
                getattr(s, "email", ""),
                getattr(s, "status", ""),
                getattr(s, "source", ""),
                getattr(s, "created_at", ""),
                getattr(s, "unsubscribed_at", ""),
            ]
        )
        yield output.getvalue()
        output.seek(0)
        output.truncate(0)


@marketing_bp.get("/marketing/export.csv")
def marketing_export_csv():
    gate = _require_admin()
    if gate:
        return gate

    SubscriberModel = _get_subscriber_model()

    if SubscriberModel is None:
        items = list(_FALLBACK_STORE.values())
        gen = _csv_rows(items)
        # BOM UTF-8 (Excel friendly)
        def with_bom(g: Iterable[str]) -> Iterable[bytes]:
            first = True
            for chunk in g:
                if first:
                    first = False
                    yield ("\ufeff" + chunk).encode("utf-8")
                else:
                    yield chunk.encode("utf-8")

        return Response(
            with_bom(gen),
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=subscribers.csv"},
        )

    items = SubscriberModel.query.order_by(SubscriberModel.email.asc()).yield_per(1000)
    gen = _csv_rows(items)

    def with_bom(g: Iterable[str]) -> Iterable[bytes]:
        first = True
        for chunk in g:
            if first:
                first = False
                yield ("\ufeff" + chunk).encode("utf-8")
            else:
                yield chunk.encode("utf-8")

    return Response(
        with_bom(gen),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=subscribers.csv"},
    )
