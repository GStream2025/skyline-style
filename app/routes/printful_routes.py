# app/routes/printful_routes.py
"""
Skyline Store — Printful Routes (PRO)

✅ Vista interna ADMIN para listar productos sincronizados desde Printful
✅ NO escribe en DB (solo lectura)
✅ Paginación segura: ?page=1&limit=50
✅ Filtros: ?q=texto&category=slug|all
✅ Sort: ?sort=id|id_desc|name|name_desc
✅ Cache opcional (SimpleCache/Redis) si Flask-Caching está instalado
✅ Output JSON opcional: ?format=json
✅ Manejo de errores + logs claros

Ruta:
- /printful/productos
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

from flask import Blueprint, current_app, flash, jsonify, render_template, request

from app.printful_client import PrintfulClient
from app.utils.printful_mapper import CATEGORY_LABELS, guess_category_from_printful

# 🔒 Protegemos admin (tu sistema ya lo tiene según dijiste)
from app.utils.admin_guard import admin_required  # ajustable si tu guard está en otro lado


printful_bp = Blueprint("printful", __name__, url_prefix="/printful")


# -------------------------------------------------------------------
# Config / helpers
# -------------------------------------------------------------------
@dataclass(frozen=True)
class _Page:
    page: int
    limit: int
    offset: int


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))


def _normalize_str(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback
    if isinstance(value, str):
        v = value.strip()
        return v if v else fallback
    v = str(value).strip()
    return v if v else fallback


def _get_pagination(default_limit: int = 50, max_limit: int = 100) -> _Page:
    page = _safe_int(request.args.get("page", 1), 1)
    limit = _safe_int(request.args.get("limit", default_limit), default_limit)

    page = _clamp(page, 1, 100_000)
    limit = _clamp(limit, 1, max_limit)

    return _Page(page=page, limit=limit, offset=(page - 1) * limit)


def _extract_list_response(result: Any) -> Tuple[List[Mapping[str, Any]], Optional[int]]:
    """
    Soporta:
    - {"sync_products":[...], "total":123}
    - {"result":{"sync_products":[...], "total":123}}
    - {"result":[...]}
    - [...]
    """
    total_count: Optional[int] = None

    if isinstance(result, Mapping):
        payload: Any = result

        # unwrap "result" si existe
        if isinstance(payload.get("result"), (Mapping, list)):
            payload = payload["result"]

        # Mapping con items
        if isinstance(payload, Mapping):
            items = payload.get("sync_products") or payload.get("items") or payload.get("data") or []
            total_raw = payload.get("total") or payload.get("total_count") or payload.get("count")
            if total_raw is not None:
                total_count = _safe_int(total_raw, 0)

            if isinstance(items, list):
                return [x for x in items if isinstance(x, Mapping)], total_count
            return [], total_count

        # List directo
        if isinstance(payload, list):
            return [x for x in payload if isinstance(x, Mapping)], None

    if isinstance(result, list):
        return [x for x in result if isinstance(x, Mapping)], None

    return [], None


def _best_thumbnail(product_data: Mapping[str, Any], item: Mapping[str, Any]) -> str:
    thumb = _normalize_str(product_data.get("thumbnail") or item.get("thumbnail"), "")
    if thumb:
        return thumb

    # files
    files = product_data.get("files") or item.get("files")
    if isinstance(files, list) and files:
        f0 = files[0] if isinstance(files[0], Mapping) else None
        if f0:
            t = _normalize_str(f0.get("preview_url") or f0.get("url"), "")
            if t:
                return t

    # variants -> files
    variants = item.get("sync_variants")
    if isinstance(variants, list) and variants:
        v0 = variants[0] if isinstance(variants[0], Mapping) else None
        if v0:
            vfiles = v0.get("files")
            if isinstance(vfiles, list) and vfiles:
                vf0 = vfiles[0] if isinstance(vfiles[0], Mapping) else None
                if vf0:
                    t = _normalize_str(vf0.get("preview_url") or vf0.get("url"), "")
                    if t:
                        return t

    return ""


def _simplify(item: Mapping[str, Any]) -> Dict[str, Any]:
    """
    Normaliza un producto (sync_product o item directo) a estructura simple para template.
    """
    product_data: Mapping[str, Any] = item

    sync_product = item.get("sync_product")
    if isinstance(sync_product, Mapping):
        product_data = sync_product

    pid = product_data.get("id") or item.get("id")
    pid_int = _safe_int(pid, 0)

    name = _normalize_str(product_data.get("name") or item.get("name"), fallback=f"Producto {pid_int or 's/n'}")
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


def _apply_filters(products: List[Dict[str, Any]], q: str, category: str) -> List[Dict[str, Any]]:
    qn = q.strip().lower()
    cn = category.strip().lower()

    out = products

    if cn and cn != "all":
        out = [p for p in out if str(p.get("category", "")).lower() == cn]

    if qn:
        out = [
            p for p in out
            if qn in str(p.get("name", "")).lower()
            or qn in str(p.get("category_label", "")).lower()
            or qn in str(p.get("id", "")).lower()
        ]

    return out


def _apply_sort(products: List[Dict[str, Any]], sort: str) -> List[Dict[str, Any]]:
    s = (sort or "").strip().lower()

    if s == "name":
        return sorted(products, key=lambda p: str(p.get("name", "")).lower())
    if s == "name_desc":
        return sorted(products, key=lambda p: str(p.get("name", "")).lower(), reverse=True)
    if s == "id_desc":
        return sorted(products, key=lambda p: int(p.get("id", 0)), reverse=True)

    return sorted(products, key=lambda p: int(p.get("id", 0)))


def _cache_get(key: str) -> Optional[Any]:
    """
    Cache opcional si Flask-Caching está instalado e inicializado.
    """
    cache = current_app.extensions.get("cache")
    if not cache:
        return None
    try:
        return cache.get(key)
    except Exception:
        return None


def _cache_set(key: str, value: Any, ttl: int) -> None:
    cache = current_app.extensions.get("cache")
    if not cache:
        return
    try:
        cache.set(key, value, timeout=ttl)
    except Exception:
        pass


# -------------------------------------------------------------------
# Route
# -------------------------------------------------------------------
@printful_bp.get("/productos")
@admin_required
def listar_productos_printful():
    """
    Vista interna admin: lista productos sincronizados desde Printful.

    Query params:
    - page, limit
    - q, category
    - sort: id | id_desc | name | name_desc
    - format=json
    - nocache=1
    """
    fmt = _normalize_str(request.args.get("format"), "html").lower()
    q = _normalize_str(request.args.get("q"), "")
    category = _normalize_str(request.args.get("category"), "")
    sort = _normalize_str(request.args.get("sort"), "id")
    nocache = _normalize_str(request.args.get("nocache"), "") in {"1", "true", "yes", "y", "on"}

    pg = _get_pagination(default_limit=50, max_limit=100)

    # Cache key (por página/limit)
    ttl = _safe_int(current_app.config.get("PRINTFUL_CACHE_TTL") or 60, 60)
    cache_key = f"printful:sync_products:p={pg.page}:l={pg.limit}:o={pg.offset}"

    total_count: Optional[int] = None
    simplified: List[Dict[str, Any]] = []

    try:
        data = None if (nocache or ttl <= 0) else _cache_get(cache_key)

        if data is None:
            client = PrintfulClient()
            result = client.get_synced_products(limit=pg.limit, offset=pg.offset)
            sync_products, total_count = _extract_list_response(result)

            simplified = [_simplify(item) for item in sync_products]

            # guardamos en cache solo la data raw simplificada + total
            if not nocache and ttl > 0:
                _cache_set(cache_key, {"items": simplified, "total": total_count}, ttl=ttl)
        else:
            simplified = list(data.get("items") or [])
            total_count = data.get("total")

        # Filtros/orden solo UI
        simplified = _apply_filters(simplified, q=q, category=category)
        simplified = _apply_sort(simplified, sort=sort)

    except Exception:
        current_app.logger.exception(
            "Printful error: get_synced_products failed",
            extra={"page": pg.page, "limit": pg.limit, "offset": pg.offset},
        )

        if fmt == "json":
            return jsonify(
                {
                    "ok": False,
                    "error": "No se pudieron cargar los productos de Printful.",
                    "page": pg.page,
                    "limit": pg.limit,
                }
            ), 502

        flash("No se pudieron cargar los productos de Printful. Probá de nuevo en unos segundos.", "error")
        return render_template(
            "printful_products.html",
            productos=[],
            page=pg.page,
            limit=pg.limit,
            next_page=None,
            prev_page=pg.page - 1 if pg.page > 1 else None,
            has_next=False,
            has_prev=(pg.page > 1),
            total_count=None,
            total_pages=None,
            q=q,
            category=category,
            sort=sort,
        )

    # Paginación UI
    has_prev = pg.page > 1
    prev_page = pg.page - 1 if has_prev else None

    total_pages: Optional[int] = None
    has_next = False
    next_page: Optional[int] = None

    if total_count is not None:
        total_pages = max((int(total_count) + pg.limit - 1) // pg.limit, 1)
        has_next = pg.page < total_pages
        next_page = pg.page + 1 if has_next else None
    else:
        # heurística: si vinieron "limit" items, podría haber más
        has_next = len(simplified) >= pg.limit
        next_page = pg.page + 1 if has_next else None

    if fmt == "json":
        return jsonify(
            {
                "ok": True,
                "page": pg.page,
                "limit": pg.limit,
                "offset": pg.offset,
                "q": q,
                "category": category,
                "sort": sort,
                "total_count": total_count,
                "total_pages": total_pages,
                "has_next": has_next,
                "has_prev": has_prev,
                "items": simplified,
            }
        )

    return render_template(
        "printful_products.html",
        productos=simplified,
        page=pg.page,
        limit=pg.limit,
        next_page=next_page,
        prev_page=prev_page,
        has_next=has_next,
        has_prev=has_prev,
        total_count=total_count,
        total_pages=total_pages,
        q=q,
        category=category,
        sort=sort,
    )
