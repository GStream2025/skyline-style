from __future__ import annotations

import os
from typing import Any, Dict, List, Mapping, Optional, Tuple

from flask import Blueprint, current_app, flash, render_template, request

from app.printful_client import PrintfulClient, PrintfulError
from app.utils.printful_mapper import CATEGORY_LABELS, guess_category_from_printful

printful_bp = Blueprint("printful", __name__, url_prefix="/printful")

# -------------------------
# Utils
# -------------------------
def _safe_int(value: Any, default: int) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default

def _clamp(n: int, min_n: int, max_n: int) -> int:
    return max(min(n, max_n), min_n)

def _get_pagination_params(default_limit: int = 24, max_limit: int = 100) -> Tuple[int, int, int]:
    page = _safe_int(request.args.get("page", 1), 1)
    limit = _safe_int(request.args.get("limit", default_limit), default_limit)
    page = _clamp(page, 1, 10_000)
    limit = _clamp(limit, 1, max_limit)
    offset = (page - 1) * limit
    return page, limit, offset

def _normalize_str(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback
    if isinstance(value, str):
        v = value.strip()
        return v if v else fallback
    v = str(value).strip()
    return v if v else fallback

def _extract_list_response(result: Any) -> Tuple[List[Mapping[str, Any]], Optional[int]]:
    total_count: Optional[int] = None

    if isinstance(result, Mapping):
        payload: Any = result.get("result", result)
        if isinstance(payload, Mapping):
            items = payload.get("sync_products") or payload.get("items") or payload.get("data") or []
            total_raw = payload.get("total") or payload.get("total_count") or payload.get("count")
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

def _apply_filters(productos: List[Dict[str, Any]], q: str, category: str) -> List[Dict[str, Any]]:
    q_norm = (q or "").strip().lower()
    category_norm = (category or "").strip().lower()

    out = productos
    if category_norm and category_norm != "all":
        out = [p for p in out if str(p.get("category", "")).lower() == category_norm]

    if q_norm:
        out = [
            p for p in out
            if q_norm in str(p.get("name", "")).lower()
            or q_norm in str(p.get("category_label", "")).lower()
            or q_norm in str(p.get("id", "")).lower()
        ]
    return out

def _apply_sort(productos: List[Dict[str, Any]], sort: str) -> List[Dict[str, Any]]:
    s = (sort or "").strip().lower()
    if s == "name":
        return sorted(productos, key=lambda p: str(p.get("name", "")).lower())
    if s == "name_desc":
        return sorted(productos, key=lambda p: str(p.get("name", "")).lower(), reverse=True)
    if s == "id_desc":
        return sorted(productos, key=lambda p: int(p.get("id", 0)), reverse=True)
    return sorted(productos, key=lambda p: int(p.get("id", 0)))

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

@printful_bp.get("/productos")
def listar_productos_printful():
    q = _normalize_str(request.args.get("q"), "")
    category = _normalize_str(request.args.get("category"), "all")
    sort = _normalize_str(request.args.get("sort"), "id")

    page, limit, _offset_ui = _get_pagination_params(default_limit=24, max_limit=100)

    ttl = _safe_int(os.getenv("PRINTFUL_CACHE_TTL", "300"), 300)

    needs_local_filter = bool(q.strip()) or (category.strip().lower() not in {"", "all"})
    scan_pages = 5 if needs_local_filter else 1
    scan_limit = min(limit, 100)
    scan_max_items = scan_pages * scan_limit

    cache_key = f"printful:products:v2:scan={scan_max_items}:q={q.lower()}:cat={category.lower()}:sort={sort.lower()}"

    productos_all = _cache_get(cache_key)
    if productos_all is None:
        try:
            client = PrintfulClient()
        except Exception:
            current_app.logger.exception("PrintfulClient init failed")
            flash("No se pudo inicializar Printful. Revisá PRINTFUL_API_KEY.", "error")
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
            )

        productos_all = []
        try:
            for i in range(scan_pages):
                api_offset = i * scan_limit
                result = client.get_synced_products(limit=scan_limit, offset=api_offset)
                sync_products, _total_count = _extract_list_response(result)
                for item in sync_products:
                    productos_all.append(_simplify_printful_product(item))
                if not sync_products:
                    break
        except PrintfulError:
            current_app.logger.exception("Printful API error")
            flash("Printful está ocupado o hubo un error. Probá de nuevo en unos segundos.", "error")
            productos_all = []
        except Exception:
            current_app.logger.exception("Printful error inesperado")
            flash("No se pudieron cargar los productos de Printful.", "error")
            productos_all = []

        productos_all = _apply_filters(productos_all, q=q, category=category)
        productos_all = _apply_sort(productos_all, sort=sort)
        _cache_set(cache_key, productos_all, ttl=ttl)

    # paginación UI
    start = (page - 1) * limit
    end = start + limit
    productos_page = productos_all[start:end]

    total_count_ui = len(productos_all)
    total_pages = max((total_count_ui + limit - 1) // limit, 1)

    has_prev = page > 1
    prev_page = page - 1 if has_prev else None
    has_next = page < total_pages
    next_page = page + 1 if has_next else None

    return render_template(
        "printful_products.html",
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

@printful_bp.post("/refresh")
def refresh_printful_cache():
    _cache_clear_best_effort()
    flash("Cache de Printful limpiada ✅", "success")
    return render_template("printful_refresh.html")
