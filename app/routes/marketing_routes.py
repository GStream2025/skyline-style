from __future__ import annotations

import csv
import io
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional, Tuple

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
MAX_SOURCE_LEN = 64


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
    if len(email) > 254:
        return False, "Email demasiado largo."
    if not EMAIL_RE.match(email):
        return False, "Email inválido."
    return True, email


def _client_ip() -> str:
    # Respeta proxy (Render/Cloudflare) si existe
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


# ============================================================
# Rate limit simple (sin dependencias)
# ============================================================


def _rl_store() -> Dict[str, Tuple[float, int]]:
    # key -> (reset_ts, count)
    ext = current_app.extensions.setdefault("marketing_rl", {})
    if not isinstance(ext, dict):
        current_app.extensions["marketing_rl"] = {}
    return current_app.extensions["marketing_rl"]  # type: ignore


def _rate_limit(key: str, limit: int, window_seconds: int) -> bool:
    """
    True = permitido
    False = bloqueado
    """
    store = _rl_store()
    now = time.time()
    reset_ts, count = store.get(key, (now + window_seconds, 0))

    if now > reset_ts:
        reset_ts, count = now + window_seconds, 0

    count += 1
    store[key] = (reset_ts, count)
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


def _get_subscriber_model():
    """
    Se resuelve "lazy" en runtime para evitar problemas de import circular.
    """
    candidates = [
        ("app.models.subscriber", "Subscriber"),
        ("app.models.subscribers", "Subscriber"),
        ("app.models", "Subscriber"),
    ]
    for module_path, attr in candidates:
        try:
            mod = __import__(module_path, fromlist=[attr])
            return getattr(mod, attr)
        except Exception:
            continue
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
    if session.get("is_admin") is True:
        return True

    admin_key = current_app.config.get("MARKETING_ADMIN_KEY")
    if admin_key:
        got = request.headers.get("X-Admin-Key") or request.args.get("key")
        if got == admin_key:
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
    if request.is_json:
        return request.get_json(silent=True) or {}
    # fallback form
    return dict(request.form or {})


def _honeypot_triggered(payload: Dict[str, Any]) -> bool:
    """
    Campo trampa: si viene lleno, casi seguro bot.
    Front: <input type="text" name="company" style="display:none">
    """
    hp = (payload.get("company") or "").strip()
    return bool(hp)


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

    if _honeypot_triggered(payload):
        # Respondemos "ok" igual para no dar pistas a bots
        return jsonify(ok=True, subscribed=True, bot_filtered=True)

    email = payload.get("email", "") or ""
    source = (payload.get("source") or "web")[:MAX_SOURCE_LEN]

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
        unsub_url = (
            url_for("marketing.unsubscribe", token=token, _external=True)
            if token
            else None
        )

        html = (
            render_template(
                "emails/subscribed.html", email=email_norm, unsubscribe_url=unsub_url
            )
            if _template_exists("emails/subscribed.html")
            else f"<p>Gracias por suscribirte.</p><p><a href='{unsub_url}'>Darme de baja</a></p>"
        )

        _try_send_email(
            to_email=email_norm,
            subject="Suscripción confirmada — Skyline Store",
            html=html,
            text=f"Para darte de baja: {unsub_url}",
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
    ttl = int(current_app.config.get("MARKETING_UNSUB_TTL_SECONDS", 60 * 60 * 24 * 365))

    try:
        email = _decode_unsubscribe_token(token, ttl)
    except (SignatureExpired, BadSignature):
        return render_template(
            "unsubscribe.html", ok=False, message="Link inválido o expirado."
        )

    SubscriberModel = _get_subscriber_model()

    if SubscriberModel is None:
        sub = _FALLBACK_STORE.get(email)
        if sub:
            sub.status = "unsubscribed"
            sub.unsubscribed_at = utcnow()
        return render_template(
            "unsubscribe.html", ok=True, message="Baja realizada.", email=email
        )

    try:
        sub = SubscriberModel.query.filter_by(email=email).first()
        if sub:
            if hasattr(sub, "status"):
                sub.status = "unsubscribed"
            if hasattr(sub, "unsubscribed_at"):
                sub.unsubscribed_at = utcnow()
            db.session.commit()

        return render_template(
            "unsubscribe.html", ok=True, message="Baja confirmada.", email=email
        )

    except Exception as exc:
        db.session.rollback()
        current_app.logger.exception("Unsubscribe error: %s", exc)
        return (
            render_template(
                "unsubscribe.html", ok=False, message="Error al procesar la baja."
            ),
            500,
        )


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
    limit = min(int(request.args.get("limit", 200)), 500)
    offset = max(int(request.args.get("offset", 0)), 0)

    if SubscriberModel is None:
        # fallback view
        subs = list(_FALLBACK_STORE.values())[offset : offset + limit]
        if not _template_exists("marketing_admin.html"):
            return jsonify(
                ok=True,
                total=len(_FALLBACK_STORE),
                subscribers=[_sub_to_dict(x) for x in subs],
                fallback=True,
            )
        return render_template("marketing_admin.html", subscribers=subs, fallback=True)

    q = SubscriberModel.query
    order_col = getattr(SubscriberModel, "created_at", None) or getattr(
        SubscriberModel, "email"
    )

    subs = q.order_by(order_col.desc()).offset(offset).limit(limit).all()
    total = q.count()

    if not _template_exists("marketing_admin.html"):
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
        return Response(
            gen,
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=subscribers.csv"},
        )

    items = SubscriberModel.query.order_by(SubscriberModel.email.asc()).yield_per(1000)
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
