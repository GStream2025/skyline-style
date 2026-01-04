# app/routes/auth_routes.py
from __future__ import annotations

import re
import time
import secrets
from urllib.parse import urlparse
from typing import Optional

from flask import Blueprint, flash, redirect, render_template, request, session, url_for, jsonify
from werkzeug.routing import BuildError

from app.models import db, User

auth_bp = Blueprint("auth", __name__)

# ----------------------------
# Seguridad / anti-abuso
# ----------------------------
MAX_LOGIN_ATTEMPTS = 5
LOCK_TIME_SECONDS = 300
RATE_LIMIT_SECONDS = 2

# ✅ Mejora real #1: Anti-bot / double submit simple (sin librerías)
FORM_NONCE_TTL = 20 * 60  # 20 min

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ============================================================
# Helpers
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


def _json_or_redirect(message: str, category: str, endpoint: str, **kwargs):
    if _wants_json():
        status = 400 if category in {"error", "warning"} else 200
        return jsonify({"ok": category not in {"error"}, "message": message}), status
    flash(message, category)
    return redirect(url_for(endpoint, **kwargs))


def _is_safe_next(nxt: str) -> bool:
    """Previene open-redirect: solo paths internos."""
    if not nxt:
        return False
    nxt = nxt.strip()
    if not nxt.startswith("/"):
        return False
    p = urlparse(nxt)
    return p.scheme == "" and p.netloc == ""


def _next_url(default: str) -> str:
    nxt = (request.args.get("next") or request.form.get("next") or "").strip()
    return nxt if _is_safe_next(nxt) else default


def _clear_session_keep_csrf() -> None:
    """✅ Mejora real #2: no rompe CSRF (no borra el token)"""
    csrf = session.get("csrf_token")
    session.clear()
    if csrf:
        session["csrf_token"] = csrf


def _safe_email(email_raw: str) -> str:
    """Normaliza email sin romper si el modelo no tiene helper."""
    email_raw = (email_raw or "").strip()
    if not email_raw:
        return ""
    email = email_raw.lower()
    if hasattr(User, "normalize_email"):
        try:
            email = User.normalize_email(email_raw)  # type: ignore[attr-defined]
        except Exception:
            pass
    return (email or "").strip().lower()


def _rate_limit_ok() -> bool:
    now = time.time()
    last = session.get("last_login_try", 0)
    try:
        last = float(last)
    except Exception:
        last = 0.0

    if (now - last) < RATE_LIMIT_SECONDS:
        return False

    session["last_login_try"] = now
    return True


def _get_current_user() -> Optional[User]:
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        uid_int = int(uid)
    except Exception:
        _clear_session_keep_csrf()
        return None

    u = db.session.get(User, uid_int)
    if not u:
        _clear_session_keep_csrf()
        return None
    return u


def _set_session_user(user: User) -> None:
    """Session mínima y consistente (sin romper CSRF)."""
    csrf = session.get("csrf_token")
    session.clear()
    if csrf:
        session["csrf_token"] = csrf

    session["user_id"] = int(user.id)
    session["user_email"] = (getattr(user, "email", "") or "").lower()
    session["is_admin"] = bool(getattr(user, "is_admin", False))
    session["login_at"] = int(time.time())
    session.permanent = True


def _post_login_redirect(user: User) -> str:
    """Destino post-login con fallback (no rompe si falta un endpoint)."""
    try:
        if bool(getattr(user, "is_admin", False)):
            return url_for("admin.dashboard")
        return url_for("account.account_home")
    except BuildError:
        try:
            return url_for("shop.shop")
        except BuildError:
            return "/"


def _commit_safe() -> bool:
    try:
        db.session.commit()
        return True
    except Exception:
        db.session.rollback()
        return False


# ✅ Mejora real #3: nonce por formulario (anti doble submit / bots)
def _new_form_nonce(key: str) -> str:
    tok = secrets.token_urlsafe(20)
    session[f"nonce:{key}"] = {"v": tok, "ts": int(time.time())}
    return tok


def _check_form_nonce(key: str) -> bool:
    raw = session.get(f"nonce:{key}") or {}
    if not isinstance(raw, dict):
        return False
    v = (raw.get("v") or "").strip()
    ts = raw.get("ts") or 0
    try:
        ts = int(ts)
    except Exception:
        ts = 0

    token = (request.form.get("nonce") or "").strip()
    if not v or not token:
        return False
    if not secrets.compare_digest(v, token):
        return False
    if (int(time.time()) - ts) > FORM_NONCE_TTL:
        return False

    # one-time
    session.pop(f"nonce:{key}", None)
    return True


def _valid_email(email: str) -> bool:
    if not email:
        return False
    if len(email) > 254:
        return False
    return bool(EMAIL_RE.match(email))


# ============================================================
# Login
# ============================================================

@auth_bp.get("/login")
def login():
    u = _get_current_user()
    if u:
        return redirect(_post_login_redirect(u))

    nxt = _next_url(url_for("shop.shop"))
    nonce = _new_form_nonce("login")
    return render_template("auth/login.html", next=nxt, nonce=nonce)


@auth_bp.post("/login")
def login_post():
    # ✅ si faltó nonce -> evita doble submit / bots
    if not _check_form_nonce("login"):
        return _json_or_redirect(
            "Solicitud inválida. Recargá la página e intentá de nuevo.",
            "error",
            "auth.login",
            next=_next_url(""),
        )

    if not _rate_limit_ok():
        return _json_or_redirect(
            "Esperá un momento antes de intentar de nuevo.",
            "warning",
            "auth.login",
            next=_next_url(""),
        )

    email = _safe_email(request.form.get("email") or "")
    password = (request.form.get("password") or "").strip()
    nxt_safe = _next_url("")

    # Validaciones sin filtrar info
    if not _valid_email(email) or not password:
        return _json_or_redirect(
            "Email o contraseña incorrectos.",
            "error",
            "auth.login",
            next=nxt_safe,
        )

    user = db.session.query(User).filter(User.email == email).first()

    # lock antes de password
    if user and hasattr(user, "locked_until"):
        try:
            locked_until = float(getattr(user, "locked_until") or 0)
        except Exception:
            locked_until = 0
        if locked_until and locked_until > time.time():
            return _json_or_redirect(
                "Cuenta temporalmente bloqueada. Intentá más tarde.",
                "error",
                "auth.login",
            )

    # Mensaje único -> no filtra si existe el email
    if not user or not user.check_password(password):
        if user and hasattr(user, "failed_login_count"):
            try:
                user.failed_login_count = int(getattr(user, "failed_login_count") or 0) + 1
            except Exception:
                user.failed_login_count = 1

            if user.failed_login_count >= MAX_LOGIN_ATTEMPTS and hasattr(user, "locked_until"):
                try:
                    user.locked_until = time.time() + LOCK_TIME_SECONDS
                except Exception:
                    pass

            _commit_safe()

        return _json_or_redirect(
            "Email o contraseña incorrectos.",
            "error",
            "auth.login",
            next=nxt_safe,
        )

    # can_login opcional
    if hasattr(user, "can_login"):
        try:
            if not user.can_login():
                return _json_or_redirect(
                    "Cuenta temporalmente bloqueada. Intentá más tarde.",
                    "error",
                    "auth.login",
                )
        except Exception:
            pass

    # is_active opcional
    if hasattr(user, "is_active"):
        try:
            if not bool(getattr(user, "is_active")):
                return _json_or_redirect(
                    "Tu cuenta está desactivada.",
                    "error",
                    "auth.login",
                )
        except Exception:
            pass

    # Login OK: reset counters + mark_login
    if hasattr(user, "failed_login_count"):
        try:
            user.failed_login_count = 0
        except Exception:
            pass
    if hasattr(user, "locked_until"):
        try:
            user.locked_until = 0
        except Exception:
            pass
    if hasattr(user, "mark_login"):
        try:
            user.mark_login()
        except Exception:
            pass

    _commit_safe()

    _set_session_user(user)
    if _wants_json():
        return jsonify({"ok": True, "redirect": (nxt_safe or _post_login_redirect(user))}), 200

    flash("Bienvenido 👋", "success")
    return redirect(nxt_safe or _post_login_redirect(user))


# ============================================================
# Register
# ============================================================

@auth_bp.get("/register")
def register():
    u = _get_current_user()
    if u:
        return redirect(_post_login_redirect(u))

    nxt = _next_url(url_for("shop.shop"))
    nonce = _new_form_nonce("register")
    return render_template("auth/register.html", next=nxt, nonce=nonce)


@auth_bp.post("/register")
def register_post():
    if not _check_form_nonce("register"):
        return _json_or_redirect(
            "Solicitud inválida. Recargá la página e intentá de nuevo.",
            "error",
            "auth.register",
            next=_next_url(""),
        )

    email = _safe_email(request.form.get("email") or "")
    password = (request.form.get("password") or "").strip()
    name = (request.form.get("name") or "").strip()
    nxt_safe = _next_url("")

    if not _valid_email(email):
        return _json_or_redirect("Email inválido.", "warning", "auth.register", next=nxt_safe)

    # ✅ Mejora real #4: política mínima + mejor UX (sin complejidad absurda)
    if len(password) < 8:
        return _json_or_redirect(
            "La contraseña debe tener al menos 8 caracteres.",
            "warning",
            "auth.register",
            next=nxt_safe,
        )

    if name:
        name = name[:120]

    # ya existe
    if db.session.query(User).filter(User.email == email).first():
        return _json_or_redirect(
            "Ese email ya está registrado. Iniciá sesión.",
            "info",
            "auth.login",
            next=nxt_safe,
        )

    user = User(email=email)

    if hasattr(user, "name") and name:
        try:
            user.name = name
        except Exception:
            pass

    # password
    try:
        user.set_password(password)
    except Exception:
        # si tu modelo no lo soporta por alguna razón, evitamos crashear
        return _json_or_redirect(
            "No se pudo crear la cuenta (password inválida). Probá otra.",
            "error",
            "auth.register",
            next=nxt_safe,
        )

    # flags opcionales
    if hasattr(user, "is_active"):
        try:
            user.is_active = True
        except Exception:
            pass
    if hasattr(user, "failed_login_count"):
        try:
            user.failed_login_count = 0
        except Exception:
            pass
    if hasattr(user, "locked_until"):
        try:
            user.locked_until = 0
        except Exception:
            pass

    if hasattr(user, "subscribe_email"):
        try:
            user.subscribe_email()
        except Exception:
            pass

    # ✅ Mejora real #5: commit robusto + mensaje claro
    try:
        db.session.add(user)
        db.session.commit()
    except Exception:
        db.session.rollback()
        return _json_or_redirect(
            "Error creando la cuenta. Probá de nuevo.",
            "error",
            "auth.register",
            next=nxt_safe,
        )

    _set_session_user(user)

    if _wants_json():
        return jsonify({"ok": True, "redirect": (nxt_safe or _post_login_redirect(user))}), 200

    flash("Cuenta creada con éxito ✅", "success")
    return redirect(nxt_safe or _post_login_redirect(user))


# ============================================================
# Logout
# ============================================================

@auth_bp.get("/logout")
def logout():
    _clear_session_keep_csrf()
    if _wants_json():
        return jsonify({"ok": True}), 200
    flash("Sesión cerrada.", "info")
    try:
        return redirect(url_for("main.home"))
    except BuildError:
        return redirect("/")


__all__ = ["auth_bp"]
