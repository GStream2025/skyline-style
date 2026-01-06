from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Mapping, Optional, Tuple

from flask import (
    Blueprint,
    current_app,
    flash,
    render_template,
    request,
    session,
    jsonify,
)

from app.printful_client import PrintfulClient, PrintfulError
from app.utils.printful_mapper import CATEGORY_LABELS, guess_category_from_printful

printful_bp = Blueprint("printful", __name__, url_prefix="/printful")

# ============================================================
# Const / config
# ============================================================

CACHE_VERSION = "v4"
MAX_PAGE = 10_000
DEFAULT_LIMIT = 24
MAX_LIMIT = 100

# rate limits (sin deps)
RL_PRODUCTS_LIMIT = 50  # hits
RL_PRODUCTS_WINDOW = 60  # seconds
RL_REFRESH_LIMIT = 10
RL_REFRESH_WINDOW = 60

SORT_WHITELIST = {"id", "id_desc", "name", "name_desc"}


# ============================================================
# Small utils
# ============================================================


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def _clamp(n: int, min_n: int, max_n: int) -> int:
    return max(min(n, max_n), min_n)


def _normalize_str(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback
    if isinstance(value, str):
        v = value.strip()
        return v if v else fallback
    v = str(value).strip()
    return v if v else fallback


def _client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


# ============================================================
# Rate limit simple
# ============================================================


def _rl_store() -> Dict[str, Tuple[float, int]]:
    ext = current_app.extensions.setdefault("printful_rl", {})
    if not isinstance(ext, dict):
        current_app.extensions["printful_rl"] = {}
    return current_app.extensions["printful_rl"]  # type: ignore


def _rate_limit(key: str, limit: int, window_seconds: int) -> bool:
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
# Admin gate (igual estilo marketing)
# ============================================================


def _is_admin() -> bool:
    if session.get("is_admin") is True:
        return True

    admin_key = current_app.config.get("MARKETING_ADMIN_KEY") or current_app.config.get(
        "PRINTFUL_ADMIN_KEY"
    )
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
# Cache helpers (best effort)
# ============================================================


def _cache_get(key: str):
    cache = current_app.extensions.get("cache")
    if not cache:
        return None
    try:
        return cache.get(key)
    except Exception:
        return None


def _cache_set(key: str, value: Any, ttl: int):
    cache = current_app.extensions.get("cache")
    if not cache:
        return
    try:
        cache.set(key, value, timeout=ttl)
    except Exception:
        pass


def _cache_clear_best_effort() -> None:
    cache = current_app.extensions.get("cache")
    if not cache:
        return
    try:
        cache.clear()
    except Exception:
        pass


def _get_ttl() -> int:
    raw = os.getenv("PRINTFUL_CACHE_TTL") or str(
        current_app.config.get("PRINTFUL_CACHE_TTL", "300")
    )
    ttl = _safe_int(raw, 300)
    return _clamp(ttl, 30, 60 * 60)  # 30s..1h


# ============================================================
# Response parsing
# ============================================================


def _extract_list_response(
    result: Any,
) -> Tuple[List[Mapping[str, Any]], Optional[int]]:
    total_count: Optional[int] = None

    if isinstance(result, Mapping):
        payload: Any = result.get("result", result)

        if isinstance(payload, Mapping):
            items = (
                payload.get("sync_products")
                or payload.get("items")
                or payload.get("data")
                or []
            )
            total_raw = (
                payload.get("total")
                or payload.get("total_count")
                or payload.get("count")
            )
            if total_raw is not None:
                total_count = _safe_int(total_raw, 0)

            if isinstance(items, list):
                return [x for x in items if isinstance(x, Mapping)], total_count
            return [], total_count

        if isinstance(payload, list):
            return [x for x in payload if isinstance(x, Mapping)], None

    if isinstance(result, list):
        return [x for x in result if isinstance(x, Mapping)], None

    return [], None


def _best_thumbnail(product_data: Mapping[str, Any], item: Mapping[str, Any]) -> str:
    thumb = _normalize_str(product_data.get("thumbnail") or item.get("thumbnail"), "")
    if thumb:
        return thumb

    files = product_data.get("files") or item.get("files")
    if isinstance(files, list) and files:
        f0 = files[0] if isinstance(files[0], Mapping) else None
        if f0:
            return _normalize_str(f0.get("preview_url") or f0.get("url"), "")

    variants = item.get("sync_variants")
    if isinstance(variants, list) and variants:
        v0 = variants[0] if isinstance(variants[0], Mapping) else None
        if v0:
            vfiles = v0.get("files")
            if isinstance(vfiles, list) and vfiles:
                vf0 = vfiles[0] if isinstance(vfiles[0], Mapping) else None
                if vf0:
                    return _normalize_str(vf0.get("preview_url") or vf0.get("url"), "")
    return ""


def _simplify_printful_product(item: Mapping[str, Any]) -> Dict[str, Any]:
    product_data: Mapping[str, Any] = item
    sync_product = item.get("sync_product")
    if isinstance(sync_product, Mapping):
        product_data = sync_product

    pid = product_data.get("id") or item.get("id")
    pid_int = _safe_int(pid, 0)

    name = _normalize_str(
        product_data.get("name") or item.get("name"),
        fallback=f"Producto {pid_int or 's/n'}",
    )
    thumbnail = _best_thumbnail(product_data, item)

    category = guess_category_from_printful(product_data)
    category_label = CATEGORY_LABELS.get(category, "Otros")

    return {
        "id": pid_int,
        "name": name,
        "thumbnail": thumbnail,
        "category": category,
        "category_label": category_label,
    }


# ============================================================
# Filters + sort
# ============================================================


def _valid_category(cat: str) -> str:
    c = (cat or "").strip().lower()
    if not c or c == "all":
        return "all"
    # allow only known categories
    if c in {k.lower() for k in CATEGORY_LABELS.keys()}:
        return c
    return "all"


def _apply_filters(
    productos: List[Dict[str, Any]], q: str, category: str
) -> List[Dict[str, Any]]:
    q_norm = (q or "").strip().lower()
    category_norm = _valid_category(category)

    out = productos
    if category_norm != "all":
        out = [p for p in out if str(p.get("category", "")).lower() == category_norm]

    if q_norm:
        out = [
            p
            for p in out
            if q_norm in str(p.get("name", "")).lower()
            or q_norm in str(p.get("category_label", "")).lower()
            or q_norm in str(p.get("id", "")).lower()
        ]
    return out


def _apply_sort(productos: List[Dict[str, Any]], sort: str) -> List[Dict[str, Any]]:
    s = (sort or "").strip().lower()
    if s not in SORT_WHITELIST:
        s = "id"

    if s == "name":
        return sorted(productos, key=lambda p: str(p.get("name", "")).lower())
    if s == "name_desc":
        return sorted(
            productos, key=lambda p: str(p.get("name", "")).lower(), reverse=True
        )
    if s == "id_desc":
        return sorted(productos, key=lambda p: int(p.get("id", 0)), reverse=True)
    return sorted(productos, key=lambda p: int(p.get("id", 0)))


# ============================================================
# Pagination params
# ============================================================


def _get_pagination_params(
    default_limit: int = DEFAULT_LIMIT, max_limit: int = MAX_LIMIT
) -> Tuple[int, int, int]:
    page = _safe_int(request.args.get("page", 1), 1)
    limit = _safe_int(request.args.get("limit", default_limit), default_limit)
    page = _clamp(page, 1, MAX_PAGE)
    limit = _clamp(limit, 1, max_limit)
    offset = (page - 1) * limit
    return page, limit, offset


# ============================================================
# Core: fetch products (2 modos)
# - Sin filtros: offset real contra API (rápido)
# - Con filtros: scan N páginas y filtra local
# ============================================================


def _cache_key(
    mode: str, page: int, limit: int, q: str, category: str, sort: str
) -> str:
    qn = (q or "").strip().lower()
    cn = _valid_category(category)
    sn = (sort or "id").strip().lower()
    if sn not in SORT_WHITELIST:
        sn = "id"
    return f"printful:products:{CACHE_VERSION}:{mode}:p={page}:l={limit}:q={qn}:c={cn}:s={sn}"


def _fetch_page_from_api(
    client: PrintfulClient, limit: int, offset: int
) -> Tuple[List[Dict[str, Any]], Optional[int]]:
    result = client.get_synced_products(limit=limit, offset=offset)
    items, total = _extract_list_response(result)
    productos = [_simplify_printful_product(x) for x in items]
    return productos, total


def _scan_from_api(
    client: PrintfulClient,
    scan_pages: int,
    scan_limit: int,
    need_items: int,
) -> List[Dict[str, Any]]:
    """
    Escanea páginas hasta:
    - completar scan_pages o
    - no venir items o
    - juntar need_items (corte temprano)
    """
    out: List[Dict[str, Any]] = []
    for i in range(scan_pages):
        api_offset = i * scan_limit
        result = client.get_synced_products(limit=scan_limit, offset=api_offset)
        items, _total = _extract_list_response(result)
        if not items:
            break
        out.extend(_simplify_printful_product(x) for x in items)
        if len(out) >= need_items:
            break
    return out


# ============================================================
# Route: productos
# ============================================================


@printful_bp.get("/productos")
def listar_productos_printful():
    rl = _rate_limit_or_429(
        "products", limit=RL_PRODUCTS_LIMIT, window_seconds=RL_PRODUCTS_WINDOW
    )
    if rl:
        return rl

    q = _normalize_str(request.args.get("q"), "")
    category = _normalize_str(request.args.get("category"), "all")
    sort = _normalize_str(request.args.get("sort"), "id")
    if sort.strip().lower() not in SORT_WHITELIST:
        sort = "id"

    page, limit, offset = _get_pagination_params(
        default_limit=DEFAULT_LIMIT, max_limit=MAX_LIMIT
    )
    ttl = _get_ttl()

    needs_local_filter = bool(q.strip()) or (_valid_category(category) != "all")

    # Cache mode:
    # - "api" (sin filtros) cache por page/limit
    # - "scan" (con filtros) cache por query/cat/sort + page/limit
    mode = "scan" if needs_local_filter else "api"
    key = _cache_key(mode, page, limit, q, category, sort)

    cached = _cache_get(key)
    if cached is not None:
        return render_template(
            "printful_products.html",
            **cached,
        )

    # stale cache (fail-open) por si API cae
    stale_key = key + ":stale"
    stale = _cache_get(stale_key)

    try:
        client = PrintfulClient()
    except Exception:
        current_app.logger.exception("PrintfulClient init failed")
        flash("No se pudo inicializar Printful. Revisá PRINTFUL_API_KEY.", "error")
        if stale:
            flash("Mostrando datos guardados (cache) por falla temporal ✅", "warning")
            return render_template("printful_products.html", **stale)
        return render_template(
            "printful_products.html",
            productos=[],
            page=page,
            limit=limit,
            next_page=None,
            prev_page=None,
            has_next=False,
            has_prev=(page > 1),
            total_count=None,
            total_pages=None,
            q=q,
            category=category,
            sort=sort,
            categories=CATEGORY_LABELS,
            sort_options={
                "id": "ID (asc)",
                "id_desc": "ID (desc)",
                "name": "Nombre (A→Z)",
                "name_desc": "Nombre (Z→A)",
            },
        )

    try:
        if not needs_local_filter:
            # modo rápido: trae SOLO la página actual del API
            productos_raw, total_count_api = _fetch_page_from_api(
                client, limit=limit, offset=offset
            )
            productos_page = _apply_sort(productos_raw, sort=sort)

            total_count_ui = total_count_api
            total_pages = None
            has_next = False
            if isinstance(total_count_ui, int) and total_count_ui >= 0:
                total_pages = max((total_count_ui + limit - 1) // limit, 1)
                has_next = page < total_pages
            else:
                # sin total: heurística (si vino lleno, probablemente hay siguiente)
                has_next = len(productos_raw) == limit
                total_pages = None

        else:
            # modo scan: escanea lo suficiente para construir la página actual filtrada
            # corte temprano: necesito al menos end items antes de paginar local
            start = (page - 1) * limit
            end = start + limit
            need_items = max(end, limit)

            scan_pages = _clamp(
                _safe_int(os.getenv("PRINTFUL_SCAN_PAGES", "8"), 8), 1, 50
            )
            scan_limit = min(limit, 100)

            productos_all = _scan_from_api(
                client,
                scan_pages=scan_pages,
                scan_limit=scan_limit,
                need_items=need_items,
            )
            productos_all = _apply_filters(productos_all, q=q, category=category)
            productos_all = _apply_sort(productos_all, sort=sort)

            productos_page = productos_all[start:end]

            total_count_ui = len(productos_all)
            total_pages = max((total_count_ui + limit - 1) // limit, 1)
            has_next = page < total_pages

        has_prev = page > 1
        prev_page = page - 1 if has_prev else None
        next_page = page + 1 if has_next else None

        payload = dict(
            productos=productos_page,
            page=page,
            limit=limit,
            next_page=next_page,
            prev_page=prev_page,
            has_next=has_next,
            has_prev=has_prev,
            total_count=total_count_ui,
            total_pages=total_pages,
            q=q,
            category=_valid_category(category),
            sort=sort,
            categories=CATEGORY_LABELS,
            sort_options={
                "id": "ID (asc)",
                "id_desc": "ID (desc)",
                "name": "Nombre (A→Z)",
                "name_desc": "Nombre (Z→A)",
            },
        )

        # set cache normal + stale mirror
        _cache_set(key, payload, ttl=ttl)
        _cache_set(stale_key, payload, ttl=max(ttl, 600))

        return render_template("printful_products.html", **payload)

    except PrintfulError:
        current_app.logger.exception("Printful API error")
        flash(
            "Printful está ocupado o hubo un error. Probá de nuevo en unos segundos.",
            "error",
        )
        if stale:
            flash("Mostrando datos guardados (cache) ✅", "warning")
            return render_template("printful_products.html", **stale)
        return render_template(
            "printful_products.html",
            productos=[],
            page=page,
            limit=limit,
            next_page=None,
            prev_page=None,
            has_next=False,
            has_prev=(page > 1),
            total_count=None,
            total_pages=None,
            q=q,
            category=category,
            sort=sort,
            categories=CATEGORY_LABELS,
            sort_options={
                "id": "ID (asc)",
                "id_desc": "ID (desc)",
                "name": "Nombre (A→Z)",
                "name_desc": "Nombre (Z→A)",
            },
        )
    except Exception:
        current_app.logger.exception("Printful error inesperado")
        flash("No se pudieron cargar los productos de Printful.", "error")
        if stale:
            flash("Mostrando datos guardados (cache) ✅", "warning")
            return render_template("printful_products.html", **stale)
        return render_template(
            "printful_products.html",
            productos=[],
            page=page,
            limit=limit,
            next_page=None,
            prev_page=None,
            has_next=False,
            has_prev=(page > 1),
            total_count=None,
            total_pages=None,
            q=q,
            category=category,
            sort=sort,
            categories=CATEGORY_LABELS,
            sort_options={
                "id": "ID (asc)",
                "id_desc": "ID (desc)",
                "name": "Nombre (A→Z)",
                "name_desc": "Nombre (Z→A)",
            },
        )


# ============================================================
# Route: refresh cache (PROTEGIDA)
# ============================================================


@printful_bp.post("/refresh")
def refresh_printful_cache():
    rl = _rate_limit_or_429(
        "refresh", limit=RL_REFRESH_LIMIT, window_seconds=RL_REFRESH_WINDOW
    )
    if rl:
        return rl

    gate = _require_admin()
    if gate:
        return gate

    _cache_clear_best_effort()
    flash("Cache de Printful limpiada ✅", "success")
    return render_template("printful_refresh.html")
