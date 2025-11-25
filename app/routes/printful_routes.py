# app/routes/printful_routes.py

from flask import Blueprint, render_template, flash
from app.printful_client import PrintfulClient

printful_bp = Blueprint("printful", __name__)


@printful_bp.route("/productos")
def listar_productos_printful():
    client = PrintfulClient()
    productos_simplificados = []

    try:
        result = client.get_synced_products(limit=50, offset=0)
        sync_products = result.get("sync_products", []) if isinstance(result, dict) else result

        for item in sync_products:
            productos_simplificados.append({
                "id": item.get("id"),
                "name": item.get("name"),
                "thumbnail": item.get("thumbnail"),
            })

    except Exception as e:
        print(f"Error al obtener productos de Printful: {e}")
        flash("No se pudieron cargar los productos en este momento.", "error")

    return render_template(
        "printful_products.html",
        productos=productos_simplificados,
    )
