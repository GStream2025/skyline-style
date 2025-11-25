# app/routes/main_routes.py

from flask import Blueprint, render_template, jsonify, flash
from app.models import Product
from app.printful_client import PrintfulClient

main_bp = Blueprint("main", __name__)

# =============================
#   PRODUCTOS DEMO (fallback)
# =============================
PRODUCTS_DEMO = [
    Product(
        id=1,
        name="Hoodie Skyline Negro",
        price=1490,
        category="Hoodie",
        image="/static/img/skyline_team.jpg",
        description="Hoodie unisex negro con logo Skyline, corte cómodo y urbano."
    ),
    Product(
        id=2,
        name="Remera Skyline Blanca",
        price=990,
        category="Remera",
        image="/static/img/skyline_team.jpg",
        description="Remera blanca statement con branding Skyline frontal."
    ),
    Product(
        id=3,
        name="Gorra Skyline Logo",
        price=790,
        category="Accesorio",
        image="/static/img/skyline_team.jpg",
        description="Gorra urbana con logo Skyline bordado."
    ),
]


# ===================================================
#   FUNCIÓN: cargar productos desde Printful
# ===================================================
def load_printful_products():
    """
    Trae productos reales de Printful.
    - Usa /store/products para listado
    - Usa /store/products/{id} para obtener el precio (primer variante)
    - Si algo falla, vuelve a PRODUCTS_DEMO
    """
    try:
        client = PrintfulClient()
        data = client.get_synced_products(limit=50, offset=0)

        productos_printful: list[Product] = []

        # data viene como LISTA de productos de tienda
        items = data if isinstance(data, list) else []

        for item in items:
            product_id = item.get("id")
            if not product_id:
                continue

            # Nombre
            name = item.get("name") or "Producto sin nombre"

            # Imagen (Printful usa normalmente 'thumbnail_url')
            thumbnail = (
                item.get("thumbnail_url")
                or item.get("thumbnail")
            )

            # --- Precio aproximado en UYU ---
            price_uyu = None
            try:
                detail = client.get_synced_product(product_id)
                # detail es un dict con 'sync_variants'
                sync_variants = detail.get("sync_variants") or []
                if sync_variants:
                    first_variant = sync_variants[0]
                    retail_str = first_variant.get("retail_price")
                    if retail_str:
                        retail_usd = float(retail_str)
                        # Conversión aproximada a UYU (ajustá factor si querés)
                        price_uyu = round(retail_usd * 40)  # USD -> UYU aprox.
            except Exception as e:
                print(f"⚠ Error obteniendo detalle de producto {product_id}: {e}")

            productos_printful.append(
                Product(
                    id=product_id,
                    name=name,
                    price=price_uyu,
                    category="Skyline Style",  # tu marca, no "Printful"
                    image=thumbnail,
                    description="Colección oficial Skyline Style"
                )
            )

        return productos_printful if productos_printful else PRODUCTS_DEMO

    except Exception as e:
        print(f"⚠ Error al cargar productos de Printful: {e}")
        return PRODUCTS_DEMO


# ======================
#       HOME
# ======================
@main_bp.route("/")
def index():
    featured_products = load_printful_products()[:6]
    return render_template("index.html", featured_products=featured_products)


# ======================
#     TIENDA GENERAL
# ======================
@main_bp.route("/shop")
def shop():
    products = load_printful_products()
    return render_template("shop.html", products=products)


# ======================
#      CARRITO
# ======================
@main_bp.route("/cart")
def cart():
    cart_items = []  # demo
    return render_template("cart.html", cart_items=cart_items)


# ======================
#   PRODUCTO INDIVIDUAL
# ======================
@main_bp.route("/product/<int:product_id>")
def product_detail(product_id: int):
    products = load_printful_products()
    product = next((p for p in products if p.id == product_id), None)

    if not product:
        flash("El producto no existe o no está disponible.", "error")
        return render_template("product_detail.html", product=None), 404

    return render_template("product_detail.html", product=product)


# ======================
#   TEST PRINTFUL JSON
# ======================
@main_bp.route("/printful/test")
def printful_test():
    try:
        client = PrintfulClient()
        data = client.get_synced_products(limit=50, offset=0)
        return jsonify({"status": "ok", "data": data})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
