# app/routes/address_routes.py — Skyline Store (ULTRA PRO / FINAL / NO BREAK)
from __future__ import annotations

import re
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse

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
from sqlalchemy.exc import SQLAlchemyError

from app.models import db, User, UserAddress

log = current_app.logger if "current_app" in globals() else None  # safe for linters

address_bp = Blueprint("address", __name__, url_prefix="/account", template_folder="../templates")
address_bp.strict_slashes = False

_TRUE = {"1", "true", "yes", "y", "on", "checked"}
_FALSE = {"0", "false", "no", "n", "off", "unchecked"}

PHONE_RE = re.compile(r"^[0-9+() \-]{6,40}$")

_SESSION_CSRF_KEY = "csrf_token"
_SESSION_RL_KEY = "addr_rl_v2"
_SESSION_DEDUPE_KEY = "addr_dedupe_v2"

_MAX_STR_50 = 50
_MAX_STR_80 = 80
_MAX_STR_120 = 120
_MAX_STR_200 = 200
_MAX_STR_300 = 300

_RL_KEYS_CAP = 220
_DEDUPE_CAP = 180

RL_NEW_LIMIT = 8
RL_NEW_WINDOW = 25
RL_UPDATE_LIMIT = 14
RL_UPDATE_WINDOW = 40
RL_DELETE_LIMIT = 10
RL_DELETE_WINDOW = 45
RL_DEFAULT_LIMIT = 18
RL_DEFAULT_WINDOW = 60

_CACHE_HEADERS = {
    "Cache-Control": "no-store, max-age=0, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
    "Vary": "Accept, Cookie",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "X-Frame-Options": "DENY",
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _now() -> int:
    return int(time.time())


def _s(v: Any, max_len: int, *, default: str = "") -> str:
    if v is None:
        return default
    s = v if isinstance(v, str) else str(v)
    s = s.replace("\x00", "").replace("\u200b", "").strip()
    s = s.replace("\r", "").replace("\n", "").replace("\t", "")
    if not s:
        return default
    s = " ".join(s.split())
    return s[: max(0, int(max_len))]


def _bool(v: Any) -> bool:
    if v is None:
        return False
    if isinstance(v, bool):
        return v
    s = _s(v, 16).lower()
    if not s or s in _FALSE:
        return False
    return s in _TRUE or s == "1"


def _wants_json() -> bool:
    try:
        if request.is_json:
            return True
    except Exception:
        pass

    fmt = _s(request.args.get("format"), 24).lower()
    if fmt == "json":
        return True

    accept = _s(request.headers.get("Accept"), 200).lower()
    if "application/json" in accept or "text/json" in accept:
        return True

    xrw = _s(request.headers.get("X-Requested-With"), 60).lower()
    if xrw == "xmlhttprequest":
        return True

    try:
        best = request.accept_mimetypes.best_match(["application/json", "text/html"])
        if best == "application/json" and request.accept_mimetypes[best] > request.accept_mimetypes["text/html"]:
            return True
    except Exception:
        pass

    return False


def _json(payload: Dict[str, Any], status: int = 200) -> Response:
    r = jsonify(payload)
    r.status_code = int(status)
    if r.status_code == 429 and "retry_after" in payload:
        try:
            r.headers["Retry-After"] = str(int(payload.get("retry_after") or 0))
        except Exception:
            pass
    return r


def _flash_ok(msg: str) -> None:
    flash(_s(msg, 240, default="OK"), "success")


def _flash_warn(msg: str) -> None:
    flash(_s(msg, 240, default="Atención"), "warning")


def _flash_err(msg: str) -> None:
    flash(_s(msg, 240, default="Error"), "error")


def _no_store(resp: Response) -> Response:
    try:
        for k, v in _CACHE_HEADERS.items():
            resp.headers.setdefault(k, v)
    except Exception:
        pass
    return resp


def _endpoint_exists(endpoint: str) -> bool:
    try:
        return endpoint in (current_app.view_functions or {})
    except Exception:
        return False


def _url_for_safe(endpoint: str, **values: Any) -> str:
    try:
        if _endpoint_exists(endpoint):
            return url_for(endpoint, **values)
    except Exception:
        pass
    return ""


def _safe_redirect(endpoint: str, **values: Any) -> Response:
    u = _url_for_safe(endpoint, **values)
    if u:
        return redirect(u, code=302)
    return redirect("/", code=302)


def _safe_next(raw: Any, *, default: str = "/account/addresses") -> str:
    s = _s(raw, 512, default="")
    if not s:
        return default

    if not s.startswith("/") or s.startswith("//"):
        return default
    if any(c in s for c in ("\x00", "\\", "\r", "\n", "\t", " ")):
        return default
    if "://" in s or ".." in s:
        return default

    try:
        p = urlparse(s)
        if p.scheme or p.netloc:
            return default
        path = (p.path or "").strip()
    except Exception:
        return default

    if not path.startswith("/") or path.startswith("//"):
        return default

    # sin loops
    if path.startswith("/auth/") or path.startswith("/admin/"):
        return default

    return path or default


def _redirect_login(*, next_url: str) -> Response:
    nxt = _safe_next(next_url, default="/account/addresses")
    u = _url_for_safe("auth.login_get", next=nxt) or _url_for_safe("auth.login", next=nxt)
    if u:
        return redirect(u, code=302)
    return redirect("/auth/login?" + urlencode({"next": nxt}), code=302)


def _login_required() -> Optional[Response]:
    if session.get("user_id"):
        return None
    if _wants_json():
        return _json({"ok": False, "error": "auth_required"}, 401)
    _flash_warn("Iniciá sesión para gestionar tus direcciones.")
    return _redirect_login(next_url=request.path or "/account/addresses")


def _current_user() -> Optional[User]:
    try:
        uid = int(session.get("user_id") or 0)
    except Exception:
        uid = 0
    if uid <= 0:
        return None
    try:
        return db.session.get(User, uid)
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        return None


def _ensure_csrf() -> str:
    tok = session.get(_SESSION_CSRF_KEY)
    if not isinstance(tok, str) or len(tok) < 24:
        tok = secrets.token_urlsafe(32)
        session[_SESSION_CSRF_KEY] = tok
        session.permanent = True
        session.modified = True
    return tok


def _csrf_from_request() -> str:
    h = _s(request.headers.get("X-CSRF-Token") or request.headers.get("X-CSRFToken"), 512, default="")
    if h:
        return h
    f = _s(request.form.get("csrf_token"), 512, default="")
    if f:
        return f
    try:
        if request.is_json:
            j = request.get_json(silent=True) or {}
            if isinstance(j, dict):
                return _s(j.get("csrf_token"), 512, default="")
    except Exception:
        pass
    return ""


def _check_csrf() -> bool:
    sess = _s(session.get(_SESSION_CSRF_KEY), 512, default="")
    got = _csrf_from_request()
    if not sess or not got:
        return False
    try:
        return secrets.compare_digest(sess, got)
    except Exception:
        return False


def _csrf_required() -> Optional[Response]:
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not _check_csrf():
        if _wants_json():
            return _json({"ok": False, "error": "csrf_invalid"}, 400)
        _flash_warn("Token inválido. Recargá la página e intentá de nuevo.")
        return _safe_redirect("address.addresses_page")
    return None


def _rl_store() -> Dict[str, Dict[str, int]]:
    store = session.get(_SESSION_RL_KEY)
    if not isinstance(store, dict):
        store = {}
    if len(store) > _RL_KEYS_CAP:
        items: List[Tuple[int, str]] = []
        for k, v in list(store.items()):
            if isinstance(v, dict):
                try:
                    items.append((int(v.get("t") or 0), str(k)))
                except Exception:
                    items.append((0, str(k)))
            else:
                items.append((0, str(k)))
        items.sort()
        for _, k in items[: max(0, len(store) - _RL_KEYS_CAP)]:
            store.pop(k, None)
    session[_SESSION_RL_KEY] = store
    session.modified = True
    return store  # type: ignore[return-value]


def _rate_limit(bucket: str, limit: int, window: int) -> Tuple[bool, int]:
    now = _now()
    uid = _s(session.get("user_id"), 40, default="anon")
    ip = _s((request.headers.get("X-Forwarded-For") or "").split(",")[0].strip(), 80, default="")
    if not ip:
        ip = _s(request.remote_addr, 80, default="unknown")

    key = f"{bucket}:{uid}:{ip}"
    store = _rl_store()

    b = store.get(key)
    if not isinstance(b, dict):
        store[key] = {"t": now, "n": 1}
        session[_SESSION_RL_KEY] = store
        session.modified = True
        return True, 0

    try:
        t0 = int(b.get("t") or now)
    except Exception:
        t0 = now
    try:
        n = int(b.get("n") or 0)
    except Exception:
        n = 0

    elapsed = now - t0
    if elapsed >= int(window) or elapsed < 0:
        store[key] = {"t": now, "n": 1}
        session[_SESSION_RL_KEY] = store
        session.modified = True
        return True, 0

    if n >= int(limit):
        return False, int(max(1, int(window) - elapsed))

    b["n"] = n + 1
    store[key] = b
    session[_SESSION_RL_KEY] = store
    session.modified = True
    return True, 0


def _dedupe_store() -> Dict[str, Dict[str, int]]:
    store = session.get(_SESSION_DEDUPE_KEY)
    if not isinstance(store, dict):
        store = {}
    if len(store) > _DEDUPE_CAP:
        items: List[Tuple[int, str]] = []
        for k, v in list(store.items()):
            if isinstance(v, dict):
                try:
                    items.append((int(v.get("t") or 0), str(k)))
                except Exception:
                    items.append((0, str(k)))
            else:
                items.append((0, str(k)))
        items.sort()
        for _, k in items[: max(0, len(store) - _DEDUPE_CAP)]:
            store.pop(k, None)
    session[_SESSION_DEDUPE_KEY] = store
    session.modified = True
    return store  # type: ignore[return-value]


def _dedupe_guard(user_id: int, signature: str, *, ttl: int = 12) -> bool:
    now = _now()
    store = _dedupe_store()
    bucket = store.get(str(user_id))
    if not isinstance(bucket, dict):
        bucket = {}

    for sig, ts in list(bucket.items()):
        try:
            if now - int(ts or 0) > int(ttl):
                bucket.pop(sig, None)
        except Exception:
            bucket.pop(sig, None)

    if signature in bucket:
        return False

    bucket[signature] = now
    store[str(user_id)] = bucket
    session[_SESSION_DEDUPE_KEY] = store
    session.modified = True
    return True


def _clean_str(v: Any, max_len: int) -> Optional[str]:
    s = _s(v, max_len, default="")
    return s if s else None


def _clean_country(v: Any) -> Optional[str]:
    s = _s(v, 8, default="")
    if not s:
        return None
    s = s.upper()
    if len(s) < 2 or not s[:2].isalpha():
        return None
    return s[:2]


def _clean_phone(v: Any) -> Optional[str]:
    s = _clean_str(v, 80)
    if not s:
        return None
    s2 = s[:40]
    if PHONE_RE.match(s2):
        return s2
    return s2  # suave (no rompe UX)


def _payload_from_request() -> Dict[str, Any]:
    payload: Dict[str, Any] = {}
    try:
        if request.is_json:
            j = request.get_json(silent=True) or {}
            if isinstance(j, dict):
                payload = j
    except Exception:
        payload = {}

    def g(name: str) -> Any:
        if payload:
            return payload.get(name)
        return request.form.get(name)

    is_default = _bool(g("is_default"))

    line1_raw = _s(g("line1"), _MAX_STR_200, default="")
    data = {
        "label": _clean_str(g("label"), _MAX_STR_50),
        "full_name": _clean_str(g("full_name"), _MAX_STR_120),
        "phone": _clean_phone(g("phone")),
        "line1": line1_raw,
        "line2": _clean_str(g("line2"), _MAX_STR_200),
        "city": _clean_str(g("city"), _MAX_STR_120),
        "state": _clean_str(g("state"), _MAX_STR_120),
        "postal_code": _clean_str(g("postal_code"), _MAX_STR_80),
        "country": _clean_country(g("country")),
        "is_default": bool(is_default),
    }
    return data


def _validate_payload(data: Dict[str, Any]) -> List[Dict[str, str]]:
    errors: List[Dict[str, str]] = []
    if not _s(data.get("line1"), 220, default="").strip():
        errors.append({"field": "line1", "error": "required"})
    ph = _s(data.get("phone"), 60, default="").strip()
    if ph and (len(ph) < 6 or len(ph) > 40):
        errors.append({"field": "phone", "error": "invalid"})
    cc = data.get("country")
    if cc and (not isinstance(cc, str) or len(cc) != 2):
        errors.append({"field": "country", "error": "invalid"})
    return errors


def _addr_to_dict(a: UserAddress) -> Dict[str, Any]:
    created = getattr(a, "created_at", None)
    return {
        "id": int(getattr(a, "id", 0) or 0),
        "label": getattr(a, "label", None),
        "full_name": getattr(a, "full_name", None),
        "phone": getattr(a, "phone", None),
        "line1": getattr(a, "line1", None),
        "line2": getattr(a, "line2", None),
        "city": getattr(a, "city", None),
        "state": getattr(a, "state", None),
        "postal_code": getattr(a, "postal_code", None),
        "country": getattr(a, "country", None),
        "is_default": bool(getattr(a, "is_default", False)),
        "created_at": created.isoformat() if isinstance(created, datetime) else None,
    }


def _set_default_address(user_id: int, addr_id: int) -> None:
    db.session.query(UserAddress).filter_by(user_id=user_id).update({"is_default": False})
    a = db.session.get(UserAddress, int(addr_id))
    if a and int(getattr(a, "user_id", 0) or 0) == int(user_id):
        a.is_default = True


def _ensure_default_exists(user_id: int) -> None:
    has_def = db.session.query(UserAddress).filter_by(user_id=user_id, is_default=True).first()
    if has_def:
        return
    last = (
        db.session.query(UserAddress)
        .filter_by(user_id=user_id)
        .order_by(UserAddress.id.desc())
        .first()
    )
    if last:
        last.is_default = True


def _normalize_default(user_id: int, preferred_id: Optional[int] = None) -> None:
    if preferred_id:
        _set_default_address(int(user_id), int(preferred_id))
    _ensure_default_exists(int(user_id))


@address_bp.before_request
def _before_addr():
    _ensure_csrf()
    return None


@address_bp.after_request
def _after_addr(resp: Response):
    return _no_store(resp)


@address_bp.get("/addresses")
def addresses_page():
    guard = _login_required()
    if guard:
        return guard

    user = _current_user()
    if not user:
        session.clear()
        return _redirect_login(next_url=request.path or "/account/addresses")

    csrf = _ensure_csrf()

    try:
        items = (
            db.session.query(UserAddress)
            .filter_by(user_id=int(user.id))
            .order_by(UserAddress.is_default.desc(), UserAddress.id.desc())
            .all()
        )
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        items = []

    return render_template(
        "account/addresses.html",
        user=user,
        addresses=items,
        csrf_token=csrf,
        next=_safe_next(request.args.get("next"), default="/account/addresses"),
    )


@address_bp.get("/addresses.json")
def addresses_json():
    guard = _login_required()
    if guard:
        return guard

    user = _current_user()
    if not user:
        return _json({"ok": False, "error": "session_invalid"}, 401)

    try:
        items = (
            db.session.query(UserAddress)
            .filter_by(user_id=int(user.id))
            .order_by(UserAddress.is_default.desc(), UserAddress.id.desc())
            .all()
        )
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        items = []

    return _json({"ok": True, "addresses": [_addr_to_dict(a) for a in items]}, 200)


@address_bp.post("/addresses/new")
def address_create():
    guard = _login_required()
    if guard:
        return guard

    gate = _csrf_required()
    if gate:
        return gate

    ok, retry = _rate_limit("new", RL_NEW_LIMIT, RL_NEW_WINDOW)
    if not ok:
        if _wants_json():
            return _json({"ok": False, "error": "rate_limited", "retry_after": retry}, 429)
        _flash_warn("Muy rápido 😅 Esperá un momento y reintentá.")
        r = _safe_redirect("address.addresses_page")
        try:
            r.headers["Retry-After"] = str(int(retry))
        except Exception:
            pass
        return r

    user = _current_user()
    if not user:
        return _redirect_login(next_url="/account/addresses")

    data = _payload_from_request()
    errors = _validate_payload(data)
    if errors:
        if _wants_json():
            return _json({"ok": False, "error": "validation_failed", "fields": errors}, 400)
        _flash_warn("Revisá los datos de la dirección (faltan campos).")
        return _safe_redirect("address.addresses_page")

    sig = f"{_s(data.get('line1'), 220).lower()}|{_s(data.get('city'), 140).lower()}|{_s(data.get('postal_code'), 60).lower()}|{_s(data.get('country'), 8).lower()}"
    if not _dedupe_guard(int(user.id), sig, ttl=12):
        if _wants_json():
            return _json({"ok": False, "error": "duplicate_request"}, 409)
        _flash_warn("Parece que ya enviaste esa dirección recién. Revisá y reintentá.")
        return _safe_redirect("address.addresses_page")

    addr: Optional[UserAddress] = None
    try:
        with db.session.begin():
            addr = UserAddress(user_id=int(user.id), **data)
            db.session.add(addr)
            db.session.flush()

            _normalize_default(int(user.id), preferred_id=int(addr.id) if data.get("is_default") else None)

        session["addr_last_action"] = "create"
        session["addr_last_id"] = int(getattr(addr, "id", 0) or 0)
        session.modified = True
    except SQLAlchemyError as exc:
        current_app.logger.exception("address_create SQLAlchemyError: %s", exc)
        try:
            db.session.rollback()
        except Exception:
            pass
        if _wants_json():
            return _json({"ok": False, "error": "save_failed"}, 500)
        _flash_err("No se pudo guardar la dirección.")
        return _safe_redirect("address.addresses_page")
    except Exception as exc:
        current_app.logger.exception("address_create error: %s", exc)
        try:
            db.session.rollback()
        except Exception:
            pass
        if _wants_json():
            return _json({"ok": False, "error": "save_failed"}, 500)
        _flash_err("No se pudo guardar la dirección.")
        return _safe_redirect("address.addresses_page")

    if _wants_json():
        return _json({"ok": True, "created": True, "address": _addr_to_dict(addr)}, 201)  # type: ignore[arg-type]

    _flash_ok("Dirección guardada ✅")
    return _safe_redirect("address.addresses_page")


@address_bp.post("/addresses/<int:addr_id>/update")
def address_update(addr_id: int):
    guard = _login_required()
    if guard:
        return guard

    gate = _csrf_required()
    if gate:
        return gate

    ok, retry = _rate_limit("update", RL_UPDATE_LIMIT, RL_UPDATE_WINDOW)
    if not ok:
        if _wants_json():
            return _json({"ok": False, "error": "rate_limited", "retry_after": retry}, 429)
        _flash_warn("Muy rápido 😅 Esperá un momento y reintentá.")
        r = _safe_redirect("address.addresses_page")
        try:
            r.headers["Retry-After"] = str(int(retry))
        except Exception:
            pass
        return r

    user = _current_user()
    if not user:
        return _redirect_login(next_url="/account/addresses")

    addr = db.session.get(UserAddress, int(addr_id))
    if not addr or int(getattr(addr, "user_id", 0) or 0) != int(user.id):
        if _wants_json():
            return _json({"ok": False, "error": "not_found"}, 404)
        _flash_warn("Dirección no encontrada.")
        return _safe_redirect("address.addresses_page")

    data = _payload_from_request()
    errors = _validate_payload(data)
    if errors:
        if _wants_json():
            return _json({"ok": False, "error": "validation_failed", "fields": errors}, 400)
        _flash_warn("Revisá los datos de la dirección (faltan campos).")
        return _safe_redirect("address.addresses_page")

    sig = f"upd:{addr_id}:{_s(data.get('line1'), 220).lower()}|{_s(data.get('city'), 140).lower()}|{_s(data.get('postal_code'), 60).lower()}|{_s(data.get('country'), 8).lower()}"
    if not _dedupe_guard(int(user.id), sig, ttl=10):
        if _wants_json():
            return _json({"ok": False, "error": "duplicate_request"}, 409)
        _flash_warn("Parece que ya enviaste esa actualización recién.")
        return _safe_redirect("address.addresses_page")

    try:
        with db.session.begin():
            for k, v in data.items():
                setattr(addr, k, v)

            _normalize_default(int(user.id), preferred_id=int(addr.id) if data.get("is_default") else None)

        session["addr_last_action"] = "update"
        session["addr_last_id"] = int(addr_id)
        session.modified = True
    except SQLAlchemyError as exc:
        current_app.logger.exception("address_update SQLAlchemyError: %s", exc)
        try:
            db.session.rollback()
        except Exception:
            pass
        if _wants_json():
            return _json({"ok": False, "error": "save_failed"}, 500)
        _flash_err("No se pudo actualizar la dirección.")
        return _safe_redirect("address.addresses_page")
    except Exception as exc:
        current_app.logger.exception("address_update error: %s", exc)
        try:
            db.session.rollback()
        except Exception:
            pass
        if _wants_json():
            return _json({"ok": False, "error": "save_failed"}, 500)
        _flash_err("No se pudo actualizar la dirección.")
        return _safe_redirect("address.addresses_page")

    if _wants_json():
        return _json({"ok": True, "updated": True, "address": _addr_to_dict(addr)}, 200)

    _flash_ok("Dirección actualizada ✅")
    return _safe_redirect("address.addresses_page")


@address_bp.post("/addresses/<int:addr_id>/delete")
def address_delete(addr_id: int):
    guard = _login_required()
    if guard:
        return guard

    gate = _csrf_required()
    if gate:
        return gate

    ok, retry = _rate_limit("delete", RL_DELETE_LIMIT, RL_DELETE_WINDOW)
    if not ok:
        if _wants_json():
            return _json({"ok": False, "error": "rate_limited", "retry_after": retry}, 429)
        _flash_warn("Muy rápido 😅 Esperá un momento y reintentá.")
        r = _safe_redirect("address.addresses_page")
        try:
            r.headers["Retry-After"] = str(int(retry))
        except Exception:
            pass
        return r

    user = _current_user()
    if not user:
        return _redirect_login(next_url="/account/addresses")

    addr = db.session.get(UserAddress, int(addr_id))
    if not addr or int(getattr(addr, "user_id", 0) or 0) != int(user.id):
        if _wants_json():
            return _json({"ok": False, "error": "not_found"}, 404)
        _flash_warn("Dirección no encontrada.")
        return _safe_redirect("address.addresses_page")

    was_default = bool(getattr(addr, "is_default", False))

    try:
        with db.session.begin():
            db.session.delete(addr)
            db.session.flush()
            if was_default:
                _normalize_default(int(user.id))

        session["addr_last_action"] = "delete"
        session["addr_last_id"] = int(addr_id)
        session.modified = True
    except SQLAlchemyError as exc:
        current_app.logger.exception("address_delete SQLAlchemyError: %s", exc)
        try:
            db.session.rollback()
        except Exception:
            pass
        if _wants_json():
            return _json({"ok": False, "error": "delete_failed"}, 500)
        _flash_err("No se pudo eliminar la dirección.")
        return _safe_redirect("address.addresses_page")
    except Exception as exc:
        current_app.logger.exception("address_delete error: %s", exc)
        try:
            db.session.rollback()
        except Exception:
            pass
        if _wants_json():
            return _json({"ok": False, "error": "delete_failed"}, 500)
        _flash_err("No se pudo eliminar la dirección.")
        return _safe_redirect("address.addresses_page")

    if _wants_json():
        return _json({"ok": True, "deleted": True, "id": int(addr_id)}, 200)

    _flash_ok("Dirección eliminada 🗑️")
    return _safe_redirect("address.addresses_page")


@address_bp.post("/addresses/<int:addr_id>/default")
def address_set_default(addr_id: int):
    guard = _login_required()
    if guard:
        return guard

    gate = _csrf_required()
    if gate:
        return gate

    ok, retry = _rate_limit("default", RL_DEFAULT_LIMIT, RL_DEFAULT_WINDOW)
    if not ok:
        if _wants_json():
            return _json({"ok": False, "error": "rate_limited", "retry_after": retry}, 429)
        _flash_warn("Muy rápido 😅 Esperá un momento y reintentá.")
        r = _safe_redirect("address.addresses_page")
        try:
            r.headers["Retry-After"] = str(int(retry))
        except Exception:
            pass
        return r

    user = _current_user()
    if not user:
        return _redirect_login(next_url="/account/addresses")

    addr = db.session.get(UserAddress, int(addr_id))
    if not addr or int(getattr(addr, "user_id", 0) or 0) != int(user.id):
        if _wants_json():
            return _json({"ok": False, "error": "not_found"}, 404)
        _flash_warn("Dirección no encontrada.")
        return _safe_redirect("address.addresses_page")

    try:
        with db.session.begin():
            _normalize_default(int(user.id), preferred_id=int(addr_id))

        session["addr_last_action"] = "default"
        session["addr_last_id"] = int(addr_id)
        session.modified = True
    except SQLAlchemyError as exc:
        current_app.logger.exception("address_set_default SQLAlchemyError: %s", exc)
        try:
            db.session.rollback()
        except Exception:
            pass
        if _wants_json():
            return _json({"ok": False, "error": "save_failed"}, 500)
        _flash_err("No se pudo actualizar la dirección predeterminada.")
        return _safe_redirect("address.addresses_page")
    except Exception as exc:
        current_app.logger.exception("address_set_default error: %s", exc)
        try:
            db.session.rollback()
        except Exception:
            pass
        if _wants_json():
            return _json({"ok": False, "error": "save_failed"}, 500)
        _flash_err("No se pudo actualizar la dirección predeterminada.")
        return _safe_redirect("address.addresses_page")

    if _wants_json():
        return _json({"ok": True, "default_set": True, "id": int(addr_id)}, 200)

    _flash_ok("Dirección predeterminada ✅")
    return _safe_redirect("address.addresses_page")


@address_bp.get("/addresses/csrf")
def addresses_csrf_token():
    guard = _login_required()
    if guard:
        return guard
    return _json({"ok": True, "csrf_token": _ensure_csrf()}, 200)


__all__ = ["address_bp"]
