# app/routes/printful_routes.py
"""
Rutas relacionadas con Printful:
- Listado de productos sincronizados directamente desde la API de Printful.
- Preparación de datos simplificados para mostrarlos en una vista interna.

Esta vista NO escribe en la base de datos: solo sirve para visualizar rápidamente
lo que viene de Printful (id, nombre, thumbnail, categoría, etc.).
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from flask import Blueprint, current_app, flash, render_template, request

from app.printful_client import PrintfulClient
from app.utils.printful_mapper import CATEGORY_LABELS, guess_category_from_printful

printful_bp = Blueprint("printful", __name__, url_prefix="/printful")


# ----------------------------
# Helpers: parsing & safety
# ----------------------------
def _safe_int(value: str, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _clamp(n: int, min_n: int, max_n: int) -> int:
    return max(min(n, max_n), min_n)


def _get_pagination_params(
    default_limit: int = 50,
    max_limit: int = 100,
) -> Tuple[int, int, int]:
    """
    Lee parámetros (?page=&limit=) y devuelve (page, limit, offset) seguros.
    - page base 1
    - limit con tope en max_limit
    """
    page = _safe_int(request.args.get("page", "1"), 1)
    limit = _safe_int(request.args.get("limit", str(default_limit)), default_limit)

    page = _clamp(page, 1, 10_000)  # evita números absurdos
    limit = _clamp(limit, 1, max_limit)

    offset = (page - 1) * limit
    return page, limit, offset


def _normalize_str(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback
    if isinstance(value, str):
        v = value.strip()
        return v if v else fallback
    return str(value).strip() or fallback


def _extract_list_response(result: Any) -> Tuple[List[Mapping[str, Any]], Optional[int]]:
    """
    Printful puede devolverte cosas distintas según implementación del cliente.
    Soportamos:
    - {"sync_products":[...], "total":123}
    - {"result":{"sync_products":[...], "total":123}}
    - {"result":[...]} (lista)
    - [...] (lista)
    """
    total_count: Optional[int] = None

    if isinstance(result, Mapping):
        payload = result

        # Algunos clientes envuelven en "result"
        if isinstance(payload.get("result"), (Mapping, list)):
            payload = payload["result"]

        if isinstance(payload, Mapping):
            items = payload.get("sync_products") or payload.get("items") or payload.get("data") or []
            total_raw = payload.get("total") or payload.get("total_count") or payload.get("count")
            if total_raw is not None:
                total_count = _safe_int(str(total_raw), 0)
            if isinstance(items, list):
                return [x for x in items if isinstance(x, Mapping)], total_count
            return [], total_count

        if isinstance(payload, list):
            return [x for x in payload if isinstance(x, Mapping)], None

    if isinstance(result, list):
        return [x for x in result if isinstance(x, Mapping)], None

    return [], None


def _best_thumbnail(product_data: Mapping[str, Any], item: Mapping[str, Any]) -> str:
    """
    Thumbnail puede venir en:
    - product_data["thumbnail"]
    - item["thumbnail"]
    - product_data["files"][0]["preview_url"] / ["url"]
    - item["sync_variants"][0]["files"][0]...
    """
    thumb = _normalize_str(product_data.get("thumbnail") or item.get("thumbnail"), "")
    if thumb:
        return thumb

    # buscar en files
    files = product_data.get("files") or item.get("files")
    if isinstance(files, list) and files:
        f0 = files[0] if isinstance(files[0], Mapping) else None
        if f0:
            return _normalize_str(f0.get("preview_url") or f0.get("url"), "")

    # buscar en variantes
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
    """
    Convierte un item de Printful a una estructura simple para templates.
    """
    product_data: Mapping[str, Any] = item

    # Printful suele anidar en sync_product
    sync_product = item.get("sync_product")
    if isinstance(sync_product, Mapping):
        product_data = sync_product

    pid = product_data.get("id") or item.get("id")
    pid_int = _safe_int(str(pid), 0)

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


def _apply_filters(
    productos: List[Dict[str, Any]],
    q: str,
    category: str,
) -> List[Dict[str, Any]]:
    q_norm = q.strip().lower()
    category_norm = category.strip().lower()

    filtered = productos

    if category_norm and category_norm != "all":
        filtered = [p for p in filtered if str(p.get("category", "")).lower() == category_norm]

    if q_norm:
        filtered = [
            p for p in filtered
            if q_norm in str(p.get("name", "")).lower()
            or q_norm in str(p.get("category_label", "")).lower()
            or q_norm in str(p.get("id", "")).lower()
        ]

    return filtered


def _apply_sort(productos: List[Dict[str, Any]], sort: str) -> List[Dict[str, Any]]:
    sort = (sort or "").strip().lower()

    if sort == "name":
        return sorted(productos, key=lambda p: str(p.get("name", "")).lower())
    if sort == "name_desc":
        return sorted(productos, key=lambda p: str(p.get("name", "")).lower(), reverse=True)
    if sort == "id_desc":
        return sorted(productos, key=lambda p: int(p.get("id", 0)), reverse=True)

    # default: id asc
    return sorted(productos, key=lambda p: int(p.get("id", 0)))


# ----------------------------
# Route
# ----------------------------
@printful_bp.get("/productos")
def listar_productos_printful():
    """
    Lista productos sincronizados desde Printful (vista interna).
    - paginación: ?page=1&limit=50
    - filtros: ?q= &category=
    - sort: ?sort=id|id_desc|name|name_desc
    """
    client = PrintfulClient()

    # filtros / sort
    q = _normalize_str(request.args.get("q"), "")
    category = _normalize_str(request.args.get("category"), "")
    sort = _normalize_str(request.args.get("sort"), "id")

    page, limit, offset = _get_pagination_params(default_limit=50, max_limit=100)

    productos_simplificados: List[Dict[str, Any]] = []
    total_count: Optional[int] = None

    try:
        result = client.get_synced_products(limit=limit, offset=offset)
        sync_products, total_count = _extract_list_response(result)

        for item in sync_products:
            productos_simplificados.append(_simplify_printful_product(item))

        # filtros/orden solo a nivel UI
        productos_simplificados = _apply_filters(productos_simplificados, q=q, category=category)
        productos_simplificados = _apply_sort(productos_simplificados, sort=sort)

    except Exception:
        current_app.logger.exception(
            "Printful error: get_synced_products failed",
            extra={"page": page, "limit": limit, "offset": offset},
        )
        flash("No se pudieron cargar los productos de Printful. Probá de nuevo en unos segundos.", "error")
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
        )

    # paginación
    has_prev = page > 1
    next_page: Optional[int] = None
    prev_page: Optional[int] = page - 1 if has_prev else None

    total_pages: Optional[int] = None
    has_next = False

    if total_count is not None:
        total_pages = max((int(total_count) + limit - 1) // limit, 1)
        has_next = page < total_pages
        next_page = page + 1 if has_next else None
    else:
        # heurística: si Printful devolvió "limit" items, probablemente haya más
        has_next = len(productos_simplificados) >= limit
        next_page = page + 1 if has_next else None

    return render_template(
        "printful_products.html",
        productos=productos_simplificados,
        page=page,
        limit=limit,
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
