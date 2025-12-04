"""
Herramientas para clasificar productos de Printful en categorías internas.

Este módulo NO llama a la API de Printful: solamente recibe datos
(ya sea un dict del producto o strings sueltos) y devuelve una
categoría interna consistente.

Categorías canónicas que manejamos:
    - "buzos"
    - "remeras"
    - "gorros"
    - "camperas"
    - "otros"

Uso típico desde el sync de Printful:

    from app.utils.printful_mapper import (
        guess_category_from_printful,
        guess_category_from_text,
        CATEGORY_LABELS,
    )

    category = guess_category_from_printful(printful_product)
    # o
    category = guess_category_from_text(name, ptype, tags)

De esta forma, lo que se guarda en la base de datos es estable y fácil
de usar en la tienda / filtros / secciones.
"""

from __future__ import annotations

from typing import Iterable, Mapping, Optional, Dict, Any

# Categorías canónicas internas (keys que guardamos en la BD)
CATEGORY_BUZOS = "buzos"
CATEGORY_REMERAS = "remeras"
CATEGORY_GORROS = "gorros"
CATEGORY_CAMPERAS = "camperas"
CATEGORY_OTROS = "otros"

# Etiquetas bonitas para mostrar en la UI (puede usarse en templates)
CATEGORY_LABELS: Dict[str, str] = {
    CATEGORY_BUZOS: "Buzos / Hoodies",
    CATEGORY_REMERAS: "Remeras",
    CATEGORY_GORROS: "Gorros",
    CATEGORY_CAMPERAS: "Camperas",
    CATEGORY_OTROS: "Otros",
}


def _normalize(text: Optional[str]) -> str:
    """Convierte un string a lower seguro, siempre devolviendo string."""
    if not text:
        return ""
    return str(text).strip().lower()


def _any_in(text: str, keywords: Iterable[str]) -> bool:
    """Devuelve True si alguno de los keywords aparece en el texto."""
    if not text:
        return False
    return any(kw in text for kw in keywords)


def guess_category_from_text(
    name: Optional[str] = None,
    product_type: Optional[str] = None,
    tags: Optional[Iterable[str]] = None,
    sku: Optional[str] = None,
) -> str:
    """
    Clasifica una prenda a partir de texto: nombre, tipo, tags y/o SKU.

    Se intenta ser lo más robusto posible con keywords típicas de Printful
    (en inglés) y nombres que puedas haber puesto vos (en español).

    :param name: Nombre del producto ("Unisex Hoodie", "Remera Skyline", etc.)
    :param product_type: Tipo que devuelva Printful (si está disponible)
    :param tags: Lista de tags relacionados al producto
    :param sku: SKU de la variante o del producto
    :return: categoría interna canónica (buzos, remeras, gorros, camperas u otros)
    """

    n = _normalize(name)
    t = _normalize(product_type)
    s = _normalize(sku)

    tags_text = " ".join(_normalize(tag) for tag in (tags or []))

    # Unificamos todo en un solo texto largo para buscar keywords
    blob = " ".join(filter(None, [n, t, tags_text, s]))

    # ---------- BUZOS / HOODIES ----------
    if _any_in(
        blob,
        [
            "hoodie",
            "pullover",
            "sweatshirt",
            "crewneck",
            "hooded",
            "buzo",
        ],
    ):
        return CATEGORY_BUZOS

    # ---------- CAMPERAS / JACKETS ----------
    if _any_in(
        blob,
        [
            "jacket",
            "zip hoodie",
            "bomber",
            "windbreaker",
            "campera",
            "coach jacket",
        ],
    ):
        return CATEGORY_CAMPERAS

    # ---------- REMERAS / T-SHIRTS ----------
    if _any_in(
        blob,
        [
            "t-shirt",
            "t shirt",
            "tee",
            "short-sleeve",
            "short sleeve",
            "long sleeve",
            "shirt",
            "remera",
            "tank top",
        ],
    ):
        return CATEGORY_REMERAS

    # ---------- GORROS / CAPS / BEANIES ----------
    if _any_in(
        blob,
        [
            "cap",
            "snapback",
            "dad hat",
            "trucker hat",
            "hat",
            "beanie",
            "gorra",
            "bucket hat",
        ],
    ):
        return CATEGORY_GORROS

    # Si en el nombre pusiste algo explícito en castellano, lo respetamos
    if "buzo" in n:
        return CATEGORY_BUZOS
    if "campera" in n:
        return CATEGORY_CAMPERAS
    if "remera" in n:
        return CATEGORY_REMERAS
    if "gorra" in n:
        return CATEGORY_GORROS

    # Fallback
    return CATEGORY_OTROS


def guess_category_from_printful(product: Mapping[str, Any]) -> str:
    """
    Recibe un dict devuelto por Printful y devuelve la categoría interna.

    Soporta estructuras comunes de Printful, por ejemplo:

        {
            "id": 123,
            "name": "Unisex Premium Hoodie",
            "type": "Hoodie",
            "tags": ["Unisex", "Hoodie", "Streetwear"],
            "variants": [
                {
                    "id": 456,
                    "sku": "SS-HOODIE-BLACK-M",
                    ...
                }
            ],
            "product": {
                "sku": "SS-HOODIE-GLOBAL"
            }
        }

    Si algún campo no existe, se maneja de forma segura.
    """

    if not isinstance(product, Mapping):
        return CATEGORY_OTROS

    name = product.get("name") or product.get("title")
    product_type = product.get("type") or product.get("product_type")

    # Tags puede venir como "tags": ["Hoodies", "Unisex"] o como string
    raw_tags = product.get("tags") or []
    if isinstance(raw_tags, str):
        tags: Iterable[str] = [raw_tags]
    else:
        tags = list(raw_tags)

    # Intentamos sacar SKU de algún lado razonable
    sku: Optional[str] = None

    # a) Product global
    if isinstance(product.get("product"), Mapping):
        sku = product["product"].get("sku") or sku

    # b) Primera variante
    variants = product.get("variants")
    if isinstance(variants, list) and variants:
        first_variant = variants[0]
        if isinstance(first_variant, Mapping):
            sku = first_variant.get("sku") or sku

    return guess_category_from_text(
        name=name,
        product_type=product_type,
        tags=tags,
        sku=sku,
    )


__all__ = [
    "CATEGORY_BUZOS",
    "CATEGORY_REMERAS",
    "CATEGORY_GORROS",
    "CATEGORY_CAMPERAS",
    "CATEGORY_OTROS",
    "CATEGORY_LABELS",
    "guess_category_from_text",
    "guess_category_from_printful",
]
