# app/routes/marketing_routes.py
"""
Marketing (Admin) + Subscribe/Unsubscribe (PRO)

Incluye:
- Panel admin: /marketing
- API: /marketing/subscribers, /marketing/export.csv
- Subscribe: POST /marketing/subscribe
- Unsubscribe: GET /unsubscribe/<token>

Requisitos:
- SECRET_KEY en config
- SQLAlchemy (db) inicializado en app/__init__.py

Opcional (si existen en tu proyecto, los usa):
- app.models.subscriber.Subscriber (o modelos equivalentes)
- app.services.email_service.send_email (o equivalente)
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, Optional, Tuple

from flask import (
    Blueprint,
    Response,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app import db  # tu SQLAlchemy global

marketing_bp = Blueprint("marketing", __name__)

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


# -----------------------------------------------------------------------------
# Opcional: Email Service (si existe en tu proyecto)
# -----------------------------------------------------------------------------
def _try_send_email(to_email: str, subject: str, html: str, text: str = "") -> bool:
    """
    Intenta enviar email usando tu servicio si existe.
    Si no existe, loguea y devuelve False (NO rompe la app).
    """
    try:
        # Cambiá este import si tu servicio tiene otro path/nombre
        from app.services.email_service import send_email  # type: ignore

        send_email(
            to=to_email,
            subject=subject,
            html=html,
            text=text or "",
        )
        return True
    except Exception as exc:
        current_app.logger.info("Email service no disponible o falló: %s", exc)
        return False


# -----------------------------------------------------------------------------
# Opcional: Modelo Subscriber (si existe) - con fallback seguro
# -----------------------------------------------------------------------------
def _get_subscriber_model():
    """
    Devuelve el modelo Subscriber si existe.
    Si no existe, retorna None (y endpoints funcionan como "no-op" sin crashear).
    """
    # Intentos típicos (ajustá según tu estructura real)
    candidates = [
        ("app.models.subscriber", "Subscriber"),
        ("app.models", "Subscriber"),
        ("app.models.subscribers", "Subscriber"),
    ]
    for module_path, attr in candidates:
        try:
            mod = __import__(module_path, fromlist=[attr])
            return getattr(mod, attr)
        except Exception:
            continue
    return None


SubscriberModel = _get_subscriber_model()


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def _serializer() -> URLSafeTimedSerializer:
    secret = current_app.config.get("SECRET_KEY")
    if not secret:
        raise RuntimeError("SECRET_KEY no está configurado. (Necesario para tokens de unsubscribe)")
    salt = current_app.config.get("MARKETING_TOKEN_SALT", "skyline-marketing")
    return URLSafeTimedSerializer(secret_key=secret, salt=salt)


def _is_admin() -> bool:
    """
    Protección simple: si tenés auth real, adaptalo acá.
    Por defecto:
      - session['is_admin'] == True
      - o session['user_role'] == 'admin'
      - o config MARKETING_ADMIN_KEY + header/query opcional
    """
    if session.get("is_admin") is True:
        return True
    if session.get("user_role") == "admin":
        return True

    admin_key = current_app.config.get("MARKETING_ADMIN_KEY")
    if admin_key:
        # permite ?key=... o header X-Admin-Key
        got = request.args.get("key") or request.headers.get("X-Admin-Key")
        if got and got == admin_key:
            return True

    return False


def _require_admin() -> Optional[Response]:
    if _is_admin():
        return None
    return jsonify(error="forbidden", message="Acceso restringido (admin)."), 403


def _normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def _validate_email(email: str) -> Tuple[bool, str]:
    email = _normalize_email(email)
    if not email:
        return False, "Email requerido."
    if not EMAIL_RE.match(email):
        return False, "Email inválido."
    return True, email


def _unsubscribe_token(email: str) -> str:
    return _serializer().dumps({"email": _normalize_email(email)})


def _decode_unsubscribe_token(token: str, max_age_seconds: int) -> str:
    data = _serializer().loads(token, max_age=max_age_seconds)
    email = _normalize_email((data or {}).get("email", ""))
    if not email:
        raise BadSignature("Token sin email")
    return email


# -----------------------------------------------------------------------------
# Fallback dataclass (si NO hay modelo)
# -----------------------------------------------------------------------------
@dataclass
class _SubscriberFallback:
    email: str
    status: str = "subscribed"
    created_at: datetime = datetime.utcnow()
    unsubscribed_at: Optional[datetime] = None


# -----------------------------------------------------------------------------
# Routes públicas: Subscribe / Unsubscribe
# -----------------------------------------------------------------------------
@marketing_bp.route("/marketing/subscribe", methods=["POST"])
def subscribe():
    """
    Suscripción simple:
    - JSON: { "email": "...", "source": "footer" }
    - Form: email=...&source=...
    """
    payload = request.get_json(silent=True) or {}
    email = payload.get("email") or request.form.get("email") or ""
    source = (payload.get("source") or request.form.get("source") or "web").strip()[:64]

    ok, email_norm_or_msg = _validate_email(email)
    if not ok:
        return jsonify(ok=False, error=email_norm_or_msg), 400

    email_norm = email_norm_or_msg

    # Si no existe modelo, devolvemos ok igual (no rompemos la web)
    if SubscriberModel is None:
        current_app.logger.warning("Subscriber model no existe. Guardado omitido (fallback). email=%s", email_norm)
        return jsonify(ok=True, subscribed=True, email=email_norm, note="Subscriber model missing"), 200

    try:
        # Intentamos campos comunes; si tu modelo es distinto, adaptá acá.
        q = SubscriberModel.query.filter_by(email=email_norm).first()

        if q and getattr(q, "status", "subscribed") == "subscribed":
            return jsonify(ok=True, subscribed=True, email=email_norm, already=True), 200

        if q:
            setattr(q, "status", "subscribed")
            if hasattr(q, "unsubscribed_at"):
                setattr(q, "unsubscribed_at", None)
            if hasattr(q, "source"):
                setattr(q, "source", source)
        else:
            sub = SubscriberModel(email=email_norm)
            if hasattr(sub, "status"):
                setattr(sub, "status", "subscribed")
            if hasattr(sub, "source"):
                setattr(sub, "source", source)
            db.session.add(sub)

        db.session.commit()

        # Email opcional: link de unsubscribe
        token = _unsubscribe_token(email_norm)
        unsub_url = url_for("marketing.unsubscribe", token=token, _external=True)

        html = render_template(
            "emails/subscribed.html",
            email=email_norm,
            unsubscribe_url=unsub_url,
        ) if _template_exists("emails/subscribed.html") else f"""
            <p>¡Gracias por suscribirte a Skyline Store!</p>
            <p>Si querés dejar de recibir emails, podés darte de baja acá:</p>
            <p><a href="{unsub_url}">{unsub_url}</a></p>
        """

        _try_send_email(
            to_email=email_norm,
            subject="✅ Suscripción confirmada — Skyline Store",
            html=html,
            text=f"Suscripción confirmada. Unsubscribe: {unsub_url}",
        )

        return jsonify(ok=True, subscribed=True, email=email_norm), 200

    except Exception as exc:
        current_app.logger.exception("Error subscribe marketing: %s", exc)
        db.session.rollback()
        return jsonify(ok=False, error="No se pudo suscribir en este momento."), 500


@marketing_bp.route("/unsubscribe/<token>", methods=["GET"])
def unsubscribe(token: str):
    """
    Unsubscribe firmado con itsdangerous.
    TTL configurable en MARKETING_UNSUB_TTL_SECONDS (default 365 días).
    """
    ttl = int(current_app.config.get("MARKETING_UNSUB_TTL_SECONDS", 60 * 60 * 24 * 365))

    try:
        email = _decode_unsubscribe_token(token, max_age_seconds=ttl)
    except SignatureExpired:
        return render_template("unsubscribe.html", ok=False, message="El link expiró."), 400
    except BadSignature:
        return render_template("unsubscribe.html", ok=False, message="Link inválido."), 400
    except Exception:
        return render_template("unsubscribe.html", ok=False, message="No se pudo procesar la solicitud."), 400

    # Si no hay modelo, mostramos ok igual
    if SubscriberModel is None:
        return render_template(
            "unsubscribe.html",
            ok=True,
            message="Listo. Te dimos de baja (modo fallback).",
            email=email,
        )

    try:
        sub = SubscriberModel.query.filter_by(email=email).first()
        if not sub:
            # No existe: consideramos que ya está fuera
            return render_template(
                "unsubscribe.html",
                ok=True,
                message="Listo. Ya estabas dado de baja.",
                email=email,
            )

        if hasattr(sub, "status"):
            setattr(sub, "status", "unsubscribed")
        if hasattr(sub, "unsubscribed_at"):
            setattr(sub, "unsubscribed_at", datetime.utcnow())

        db.session.commit()

        return render_template(
            "unsubscribe.html",
            ok=True,
            message="Listo. Te dimos de baja.",
            email=email,
        )

    except Exception as exc:
        current_app.logger.exception("Error unsubscribe: %s", exc)
        db.session.rollback()
        return render_template("unsubscribe.html", ok=False, message="No se pudo dar de baja en este momento."), 500


# -----------------------------------------------------------------------------
# Admin panel + API
# -----------------------------------------------------------------------------
@marketing_bp.route("/marketing", methods=["GET"])
def marketing_admin():
    gate = _require_admin()
    if gate:
        return gate

    subs = []
    total = 0

    if SubscriberModel is not None:
        try:
            total = SubscriberModel.query.count()
            subs = (
                SubscriberModel.query
                .order_by(getattr(SubscriberModel, "created_at", SubscriberModel.email).desc())
                .limit(200)
                .all()
            )
        except Exception as exc:
            current_app.logger.info("No se pudo listar subscribers: %s", exc)

    # Si no tenés template, devolvemos JSON usable
    if not _template_exists("marketing_admin.html"):
        return jsonify(
            ok=True,
            total=total,
            subscribers=[_sub_to_dict(x) for x in subs],
            note="Crea templates/marketing_admin.html para UI",
        )

    return render_template(
        "marketing_admin.html",
        total=total,
        subscribers=subs,
    )


@marketing_bp.route("/marketing/subscribers", methods=["GET"])
def marketing_subscribers_json():
    gate = _require_admin()
    if gate:
        return gate

    limit = min(int(request.args.get("limit", 200)), 1000)
    offset = max(int(request.args.get("offset", 0)), 0)

    if SubscriberModel is None:
        return jsonify(ok=True, total=0, subscribers=[], note="Subscriber model missing")

    q = SubscriberModel.query
    total = q.count()
    items = q.order_by(getattr(SubscriberModel, "created_at", SubscriberModel.email).desc()).offset(offset).limit(limit).all()
    return jsonify(ok=True, total=total, subscribers=[_sub_to_dict(x) for x in items])


@marketing_bp.route("/marketing/export.csv", methods=["GET"])
def marketing_export_csv():
    gate = _require_admin()
    if gate:
        return gate

    if SubscriberModel is None:
        return jsonify(ok=False, error="Subscriber model missing"), 400

    try:
        items = SubscriberModel.query.order_by(SubscriberModel.email.asc()).all()
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["email", "status", "source", "created_at", "unsubscribed_at"])

        for s in items:
            w.writerow([
                getattr(s, "email", ""),
                getattr(s, "status", ""),
                getattr(s, "source", ""),
                _dt(getattr(s, "created_at", None)),
                _dt(getattr(s, "unsubscribed_at", None)),
            ])

        csv_bytes = buf.getvalue().encode("utf-8")
        return Response(
            csv_bytes,
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=subscribers.csv"},
        )
    except Exception as exc:
        current_app.logger.exception("Export CSV error: %s", exc)
        return jsonify(ok=False, error="No se pudo exportar."), 500


# -----------------------------------------------------------------------------
# Utils internos
# -----------------------------------------------------------------------------
def _template_exists(name: str) -> bool:
    try:
        current_app.jinja_env.get_template(name)
        return True
    except Exception:
        return False


def _dt(value: Any) -> str:
    if not value:
        return ""
    if isinstance(value, datetime):
        return value.isoformat()
    try:
        return str(value)
    except Exception:
        return ""


def _sub_to_dict(s: Any) -> Dict[str, Any]:
    return {
        "email": getattr(s, "email", ""),
        "status": getattr(s, "status", ""),
        "source": getattr(s, "source", ""),
        "created_at": _dt(getattr(s, "created_at", None)),
        "unsubscribed_at": _dt(getattr(s, "unsubscribed_at", None)),
    }
