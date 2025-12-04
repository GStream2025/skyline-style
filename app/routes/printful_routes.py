# app/routes/printful_routes.py

"""
Rutas relacionadas con Printful:
- Listado de productos sincronizados directamente desde la API de Printful.
- Preparación de datos simplificados para mostrarlos en una vista interna.

Esta vista NO escribe en la base de datos: solo sirve para visualizar rápidamente
lo que viene de Printful (id, nombre, thumbnail, categoría, etc.).
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Tuple

from flask import (
    Blueprint,
    current_app,
    flash,
    render_template,
    request,
)

from app.printful_client import PrintfulClient
from app.utils.printful_mapper import (
    guess_category_from_printful,
    CATEGORY_LABELS,
)

printful_bp = Blueprint("printful", __name__)


def _get_pagination_params(
    default_limit: int = 50,
    max_limit: int = 100,
) -> Tuple[int, int]:
    """
    Lee parámetros de query (?page=&limit=) y devuelve (limit, offset) seguros.

    - page: número de página, base 1 (por defecto 1).
    - limit: cantidad por página, tope en max_limit.

    Si los parámetros son inválidos, se usan los valores por defecto.
    """
    try:
        page = int(request.args.get("page", "1"))
    except ValueError:
        page = 1

    try:
        limit = int(request.args.get("limit", str(default_limit)))
    except ValueError:
        limit = default_limit

    if page < 1:
        page = 1

    if limit < 1:
        limit = default_limit
    elif limit > max_limit:
        limit = max_limit

    offset = (page - 1) * limit
    return limit, offset


def _simplify_printful_product(item: Mapping[str, Any]) -> Dict[str, Any]:
    """
    Convierte un item devuelto por Printful (sync product) en un dict simplificado
    para usar en templates.

    Estructura devuelta:
        {
            "id": int,
            "name": str,
            "thumbnail": str,
            "category": str,         # clave interna (buzos, remeras, etc.)
            "category_label": str,   # etiqueta bonita para la UI
        }
    """
    # Algunos endpoints de Printful devuelven "sync_product" adentro del item
    # o "product" con info adicional. Intentamos ser tolerantes.
    product_data: Mapping[str, Any] = item

    # A veces viene como "sync_product": {...}
    if isinstance(item.get("sync_product"), Mapping):
        product_data = item["sync_product"]

    pid = product_data.get("id") or item.get("id")
    name = product_data.get("name") or item.get("name") or f"Producto {pid}"

    # Thumbnail puede venir en varios campos
    thumbnail = (
        product_data.get("thumbnail")
        or item.get("thumbnail")
        or ""
    )

    category = guess_category_from_printful(product_data)
    category_label = CATEGORY_LABELS.get(category, "Otros")

    return {
        "id": pid,
        "name": name,
        "thumbnail": thumbnail,
        "category": category,
        "category_label": category_label,
    }


@printful_bp.route("/productos")
def listar_productos_printful():
    """
    Lista productos sincronizados desde Printful en una vista interna.

    - Usa paginación por query params (?page=1&limit=50).
    - Muestra productos simplificados: id, nombre, thumbnail, categoría.
    - No guarda nada en la base de datos.
    """
    client = PrintfulClient()
    productos_simplificados: List[Dict[str, Any]] = []

    limit, offset = _get_pagination_params(default_limit=50, max_limit=100)

    page: int = (offset // limit) + 1
    next_page: Optional[int] = None
    prev_page: Optional[int] = None

    try:
        # Llamada al cliente de Printful
        result = client.get_synced_products(limit=limit, offset=offset)

        # result puede ser dict o lista dependiendo de cómo lo tengas implementado
        if isinstance(result, Mapping):
            sync_products = result.get("sync_products", []) or []
            total_count = result.get("total", None)
        else:
            sync_products = list(result or [])
            total_count = None

        # Simplificar productos
        for item in sync_products:
            if not isinstance(item, Mapping):
                continue
            productos_simplificados.append(_simplify_printful_product(item))

        # Calcular paginación básica si tenemos total
        if total_count is not None:
            # Número total de páginas (redondeo hacia arriba)
            total_pages = max((int(total_count) + limit - 1) // limit, 1)
            if page < total_pages:
                next_page = page + 1
            if page > 1:
                prev_page = page - 1
        else:
            # Si no tenemos total, usamos heurística sencilla:
            if len(sync_products) == limit:
                next_page = page + 1
            if page > 1:
                prev_page = page - 1

    except Exception as e:
        current_app.logger.exception("Error al obtener productos de Printful")
        flash("No se pudieron cargar los productos de Printful en este momento.", "error")
        # Devolvemos la vista vacía pero sin romper
        return render_template(
            "printful_products.html",
            productos=[],
            page=page,
            next_page=None,
            prev_page=None,
            limit=limit,
        )

    # Renderizamos la plantilla con paginación y lista simplificada
    return render_template(
        "printful_products.html",
        productos=productos_simplificados,
        page=page,
        next_page=next_page,
        prev_page=prev_page,
        limit=limit,
    )
