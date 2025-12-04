# app/routes/main_routes.py
from __future__ import annotations

import time
from collections import defaultdict
from typing import Any, DefaultDict, Dict, List, Mapping

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    url_for,
)

from app.models import Product
from app.printful_client import PrintfulClient
from app.utils.printful_mapper import guess_category_from_printful

# ==========================================
#  BLUEPRINT PRINCIPAL DE LA WEB PÚBLICA
# ==========================================
main_bp = Blueprint("main", __name__)

# =================================================
#   PRODUCTOS DEMO (fallback si falla Printful)
#   - Ya vienen con categorías aproximadas
# =================================================
PRODUCTS_DEMO: List[Product] = [
    Product(
        id=1,
        name="Hoodie Skyline Negro",
        price=1490,
        category="buzos",
        image="/static/img/skyline_team.jpg",
        description="Hoodie unisex negro con logo Skyline, corte cómodo y urbano.",
    ),
    Product(
        id=2,
        name="Remera Skyline Blanca",
        price=990,
        category="remeras",
        image="/static/img/skyline_team.jpg",
        description="Remera blanca statement con branding Skyline frontal.",
    ),
    Product(
        id=3,
        name="Gorra Skyline Logo",
        price=790,
        category="gorros",
        image="/static/img/skyline_team.jpg",
        description="Gorra urbana con logo Skyline bordado.",
    ),
]

# =================================================
#   CACHÉ SIMPLE DE PRODUCTOS PRINTFUL (RAM)
#   - Evita pegarle a la API en cada request
#   - TTL (tiempo de vida) configurable
# =================================================
CacheType = Dict[str, Any]

_PRINTFUL_CACHE: CacheType = {
    "timestamp": 0.0,
    "products": None,  # type: ignore[assignment]
}
PRINTFUL_TTL_SECONDS: int = 300  # 5 minutos aprox.


def _usd_to_uyu(usd: float) -> int:
    """
    Conversión aproximada de USD a UYU.
    Ajustá el factor según el cambio real.
    """
    factor = 40  # EJEMPLO: 1 USD ~ 40 UYU
    return round(usd * factor)


def _normalize_category_for_demo(category: str) -> str:
    """
    Normaliza categorías sueltas (Hoodie, Remera, Accesorio)
    a las categorías internas canónicas usadas en la tienda.
    """
    c = (category or "").strip().lower()

    if "hoodie" in c or "buzo" in c:
        return "buzos"
    if "remera" in c or "t-shirt" in c or "tee" in c:
        return "remeras"
    if "gorra" in c or "hat" in c or "cap" in c:
        return "gorros"
    if "campera" in c or "jacket" in c:
        return "camperas"
    return "otros"


# ===================================================
#   FUNCIÓN: cargar productos desde Printful
# ===================================================
def load_printful_products(force_refresh: bool = False) -> List[Product]:
    """
    Trae productos reales de Printful listos para usar en la web.

    - Usa get_synced_products() para listado base.
    - Usa get_synced_product(id) para obtener el precio (primer variante).
    - Asigna categoría interna usando guess_category_from_printful.
    - Aplica caché en memoria para no llamar a la API en cada request.
    - Si algo falla, devuelve PRODUCTS_DEMO.
    """
    # ---------- CACHÉ ----------
    now = time.time()
    if (
        not force_refresh
        and _PRINTFUL_CACHE.get("products") is not None
        and now - float(_PRINTFUL_CACHE.get("timestamp", 0.0)) < PRINTFUL_TTL_SECONDS
    ):
        return _PRINTFUL_CACHE["products"]  # type: ignore[return-value]

    try:
        client = PrintfulClient()
        data = client.get_synced_products(limit=50, offset=0)

        productos_printful: List[Product] = []

        # Según cómo esté implementado tu cliente, data puede ser lista o dict
        if isinstance(data, list):
            items = data
        elif isinstance(data, Mapping):
            # Si alguna vez cambiás a la versión que devuelve {"sync_products": [...]}
            items = data.get("sync_products", []) or []
        else:
            items = []

        for item in items:
            if not isinstance(item, Mapping):
                continue

            product_id = item.get("id")
            if not product_id:
                continue

            # Nombre
            name = item.get("name") or "Producto Skyline"

            # Imagen (Printful suele usar 'thumbnail' o 'thumbnail_url')
            thumbnail = (
                item.get("thumbnail_url")
                or item.get("thumbnail")
                or "/static/img/skyline_team.jpg"
            )

            # --- Precio aproximado en UYU (opcional, si tenés el endpoint de detalle) ---
            price_uyu: int | None = None
            try:
                detail = client.get_synced_product(product_id)
                # detail es un dict con 'sync_variants'
                sync_variants = detail.get("sync_variants") or []
                if isinstance(sync_variants, list) and sync_variants:
                    first_variant = sync_variants[0] or {}
                    retail_str = first_variant.get("retail_price")
                    if retail_str:
                        retail_usd = float(retail_str)
                        price_uyu = _usd_to_uyu(retail_usd)
            except Exception as e:  # noqa: BLE001
                current_app.logger.warning(
                    "Error obteniendo detalle de producto %s: %s", product_id, e
                )

            # Categoría interna (buzos, remeras, gorros, camperas, otros)
            category = guess_category_from_printful(item)

            productos_printful.append(
                Product(
                    id=product_id,
                    name=name,
                    price=price_uyu or 0,
                    category=category,
                    image=thumbnail,
                    description="Colección oficial Skyline Style.",
                )
            )

        # Si Printful devolvió algo, actualizamos caché
        if productos_printful:
            _PRINTFUL_CACHE["products"] = productos_printful
            _PRINTFUL_CACHE["timestamp"] = now
            return productos_printful

        # Si la lista vino vacía, usamos DEMO
        current_app.logger.warning(
            "Printful devolvió lista vacía. Usando productos demo."
        )
        return PRODUCTS_DEMO

    except Exception as e:  # noqa: BLE001
        current_app.logger.exception("Error al cargar productos de Printful: %s", e)
        return PRODUCTS_DEMO


# ======================
#       HOME
# ======================
@main_bp.route("/", endpoint="home")
def home():
    """
    Landing principal con destacados.
    Muestra los primeros 6 productos como "destacados".
    """
    featured_products = load_printful_products()[:6]
    return render_template("index.html", featured_products=featured_products)


# Alias opcional para compatibilidad (main.index → /index)
@main_bp.route("/index", endpoint="index")
def index_alias():
    """
    Alias de / para compatibilidad con código viejo (main.index).
    """
    return redirect(url_for("main.home"))


# ======================
#     TIENDA GENERAL
# ======================
@main_bp.route("/shop", endpoint="shop")
def shop():
    """
    Tienda general Skyline.

    - Carga productos desde Printful (o demo).
    - Los agrupa por categoría interna.
    - Envía grouped_products al template para que los filtros
      de la tienda funcionen (buzos, remeras, gorros, etc.).
    """
    products = load_printful_products()

    grouped: DefaultDict[str, List[Product]] = defaultdict(list)
    for p in products:
        cat = _normalize_category_for_demo(getattr(p, "category", "") or "otros")
        grouped[cat].append(p)

    # Pasamos también la lista plana por si la querés usar en otro momento
    return render_template(
        "shop.html",
        grouped_products=dict(grouped),
        products=products,
    )


# Alias opcional /tienda
@main_bp.route("/tienda", endpoint="shop_alias")
def shop_alias():
    return redirect(url_for("main.shop"))


# ======================
#       LA MARCA
# ======================
@main_bp.route("/about", endpoint="about")
def about():
    """
    Página 'La marca' / Sobre Skyline Style.
    """
    return render_template("about.html")


# ======================
#      CARRITO
# ======================
@main_bp.route("/cart", endpoint="cart")
def cart():
    """
    Carrito de compras (por ahora demo).
    """
    cart_items: List[dict] = []  # TODO: integrar con sesión / base de datos
    return render_template("cart.html", cart_items=cart_items)


# ======================
#   PRODUCTO INDIVIDUAL
# ======================
@main_bp.route("/product/<int:product_id>", endpoint="product_detail")
def product_detail(product_id: int):
    """
    Vista de producto individual.
    Busca el producto en la lista de Printful (o demo).
    """
    products = load_printful_products()
    product = next((p for p in products if p.id == product_id), None)

    if not product:
        flash("El producto no existe o no está disponible.", "error")
        return redirect(url_for("main.shop"))

    return render_template("product_detail.html", product=product)


# ======================
#   TEST PRINTFUL JSON
# ======================
@main_bp.route("/printful/test", endpoint="printful_test")
def printful_test():
    """
    Endpoint de prueba para ver el JSON crudo que devuelve Printful.
    Útil para debug.
    """
    try:
        client = PrintfulClient()
        data = client.get_synced_products(limit=50, offset=0)
        return jsonify({"status": "ok", "data": data})
    except Exception as e:  # noqa: BLE001
        current_app.logger.exception("Error en /printful/test: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 500
