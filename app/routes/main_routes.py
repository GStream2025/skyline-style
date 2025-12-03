# app/routes/main_routes.py
from __future__ import annotations

import time
from typing import Any, Dict, List

from flask import Blueprint, render_template, jsonify, flash, redirect, url_for

from app.models import Product
from app.printful_client import PrintfulClient

# ==========================================
#  BLUEPRINT PRINCIPAL DE LA WEB PÚBLICA
# ==========================================
main_bp = Blueprint("main", __name__)

# =================================================
#   PRODUCTOS DEMO (fallback si falla Printful)
# =================================================
PRODUCTS_DEMO: List[Product] = [
    Product(
        id=1,
        name="Hoodie Skyline Negro",
        price=1490,
        category="Hoodie",
        image="/static/img/skyline_team.jpg",
        description="Hoodie unisex negro con logo Skyline, corte cómodo y urbano.",
    ),
    Product(
        id=2,
        name="Remera Skyline Blanca",
        price=990,
        category="Remera",
        image="/static/img/skyline_team.jpg",
        description="Remera blanca statement con branding Skyline frontal.",
    ),
    Product(
        id=3,
        name="Gorra Skyline Logo",
        price=790,
        category="Accesorio",
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
    "products": None,
}
PRINTFUL_TTL_SECONDS: int = 300  # 5 minutos aprox.


def _usd_to_uyu(usd: float) -> int:
    """
    Conversión aproximada de USD a UYU.
    Ajustá el factor según el cambio real.
    """
    factor = 40  # EJEMPLO: 1 USD ~ 40 UYU
    return round(usd * factor)


# ===================================================
#   FUNCIÓN: cargar productos desde Printful
# ===================================================
def load_printful_products(force_refresh: bool = False) -> List[Product]:
    """
    Trae productos reales de Printful.

    - Usa /store/products para listado
    - Usa /store/products/{id} para obtener el precio (primer variante)
    - Si algo falla, vuelve a PRODUCTS_DEMO
    - Usa un caché simple en memoria para no llamar
      a la API en cada request.
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

        # data debe ser lista de productos; si no, usamos lista vacía
        items = data if isinstance(data, list) else []

        for item in items:
            product_id = item.get("id")
            if not product_id:
                continue

            # Nombre
            name = item.get("name") or "Producto Skyline"

            # Imagen (Printful usa normalmente 'thumbnail_url')
            thumbnail = item.get("thumbnail_url") or item.get("thumbnail")
            if not thumbnail:
                thumbnail = "/static/img/skyline_team.jpg"

            # --- Precio aproximado en UYU ---
            price_uyu: int | None = None
            try:
                detail = client.get_synced_product(product_id)
                # detail es un dict con 'sync_variants'
                sync_variants = detail.get("sync_variants") or []
                if sync_variants:
                    first_variant = sync_variants[0]
                    retail_str = first_variant.get("retail_price")
                    if retail_str:
                        retail_usd = float(retail_str)
                        price_uyu = _usd_to_uyu(retail_usd)
            except Exception as e:
                print(f"⚠ Error obteniendo detalle de producto {product_id}: {e}")

            productos_printful.append(
                Product(
                    id=product_id,
                    name=name,
                    price=price_uyu,
                    category="Skyline Style",  # tu marca, no "Printful"
                    image=thumbnail,
                    description="Colección oficial Skyline Style",
                )
            )

        # Si Printful devolvió algo, actualizamos caché
        if productos_printful:
            _PRINTFUL_CACHE["products"] = productos_printful
            _PRINTFUL_CACHE["timestamp"] = now
            return productos_printful

        # Si la lista vino vacía, usamos DEMO
        print("⚠ Printful devolvió lista vacía. Usando productos demo.")
        return PRODUCTS_DEMO

    except Exception as e:
        print(f"⚠ Error al cargar productos de Printful: {e}")
        return PRODUCTS_DEMO


# ======================
#       HOME
# ======================
@main_bp.route("/", endpoint="home")
def home():
    """
    Landing principal con destacados.
    Endpoint oficial: main.home
    """
    featured_products = load_printful_products()[:6]
    # Template principal: index.html (ya contiene el hero + secciones)
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
    Listado general de productos.
    """
    products = load_printful_products()
    return render_template("shop.html", products=products)


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
    cart_items: List[dict] = []  # TODO: integrar con sesión
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
        # Redirigimos a la tienda en lugar de mostrar un 404 seco
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
    except Exception as e:
        print(f"⚠ Error en /printful/test: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500
