"""
Modelo de producto de dominio para Skyline Style.

Este modelo está pensado para:
    - Representar un producto de forma limpia y tipada.
    - Ser independiente de la base de datos (no es un modelo ORM).
    - Integrarse fácil con Printful y con la capa de presentación (templates, APIs).

Características:
    - Normaliza y valida datos en __post_init__.
    - Usa Decimal para manejar precios correctamente.
    - Expone helpers para UI: price_formatted, short_name, seo_slug.
    - Incluye factoría desde estructuras típicas de Printful.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal, ROUND_HALF_UP, InvalidOperation
from typing import Any, Dict, Mapping, Optional

import re
from urllib.parse import urlparse

# Si ya tenés el mapper que hicimos antes, podés usarlo:
# from app.utils.printful_mapper import (
#     guess_category_from_printful,
#     CATEGORY_LABELS,
# )

# Si preferís que este archivo sea 100% independiente, podés
# dejar estas constantes así y usar guess_category_from_text
# dentro de este mismo archivo.

CATEGORY_BUZOS = "buzos"
CATEGORY_REMERAS = "remeras"
CATEGORY_GORROS = "gorros"
CATEGORY_CAMPERAS = "camperas"
CATEGORY_OTROS = "otros"

CATEGORY_LABELS: Dict[str, str] = {
    CATEGORY_BUZOS: "Buzos / Hoodies",
    CATEGORY_REMERAS: "Remeras",
    CATEGORY_GORROS: "Gorros",
    CATEGORY_CAMPERAS: "Camperas",
    CATEGORY_OTROS: "Otros",
}


def _normalize_str(value: Optional[str]) -> str:
    """Convierte un valor a string limpio, sin espacios extras."""
    if value is None:
        return ""
    return str(value).strip()


def _normalize_category(category: Optional[str]) -> str:
    """Normaliza categoría a las canónicas internas."""
    c = _normalize_str(category).lower()

    if c in (CATEGORY_BUZOS, "hoodie", "hoodies", "sweatshirt", "buzo", "buzos"):
        return CATEGORY_BUZOS
    if c in (CATEGORY_REMERAS, "t-shirt", "tshirt", "tee", "remera", "remeras"):
        return CATEGORY_REMERAS
    if c in (CATEGORY_GORROS, "cap", "hat", "beanie", "gorra", "gorras"):
        return CATEGORY_GORROS
    if c in (CATEGORY_CAMPERAS, "jacket", "campera", "camperas", "zip hoodie"):
        return CATEGORY_CAMPERAS

    return CATEGORY_OTROS


def _parse_price(value: Any) -> Decimal:
    """
    Convierte un valor numérico o string a Decimal con 2 decimales.

    Acepta:
        - float
        - int
        - str ("1290", "1290.50")
        - Decimal

    Si no se puede convertir, devuelve 0.00.
    """
    if isinstance(value, Decimal):
        price = value
    else:
        try:
            price = Decimal(str(value))
        except (InvalidOperation, TypeError, ValueError):
            price = Decimal("0.00")

    # Redondeo estándar a 2 decimales
    return price.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def _is_valid_url(url: str) -> bool:
    """Validación simple de URL (para evitar cosas muy rotas)."""
    if not url:
        return False
    parsed = urlparse(url)
    return bool(parsed.scheme and parsed.netloc)


def _slugify(text: str) -> str:
    """
    Genera un slug SEO-friendly a partir del nombre del producto.
    Ej: "Buzo Skyline Ámbar v2" -> "buzo-skyline-ambar-v2"
    """
    text = _normalize_str(text).lower()
    # Reemplazar caracteres no alfanuméricos por guiones
    text = re.sub(r"[^a-z0-9áéíóúñ]+", "-", text)
    # Quitar guiones extremos
    text = text.strip("-")
    # Normalización simple: reemplazar acentos -> letras sin acento
    replacements = {
        "á": "a",
        "é": "e",
        "í": "i",
        "ó": "o",
        "ú": "u",
        "ñ": "n",
    }
    for src, dst in replacements.items():
        text = text.replace(src, dst)
    return text


@dataclass(slots=True)
class Product:
    """
    Modelo de producto de dominio.

    NOTA: Este modelo no es el modelo de la base de datos.
    Podés convertirlo a/desde tu modelo SQLAlchemy sin problema.

    Attributes:
        id: Identificador interno (puede ser el de la BD o el de Printful).
        name: Nombre del producto visible para el usuario.
        price: Precio en Decimal (2 decimales, en currency).
        currency: Código de moneda (por defecto "UYU").
        category: Categoría interna canónica (buzos, remeras, gorros, camperas, otros).
        image: URL de la imagen principal del producto.
        description: Descripción corta o larga.
        is_active: Indica si el producto está disponible para mostrarse.
        metadata: Diccionario libre con datos adicionales (ej: printful_id, sku, tags).
    """

    id: int
    name: str
    price: Decimal
    category: str
    image: str
    description: str = ""
    currency: str = "UYU"
    is_active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Normalizamos strings básicos
        self.name = _normalize_str(self.name)
        self.description = _normalize_str(self.description)
        self.currency = _normalize_str(self.currency).upper() or "UYU"

        # Normalizar categoría
        self.category = _normalize_category(self.category)

        # Asegurar que el precio sea Decimal bien formado
        self.price = _parse_price(self.price)

        # Validar URL de imagen (si está vacía, la dejamos tal cual para que
        # la capa superior decida un placeholder por defecto)
        self.image = _normalize_str(self.image)
        if self.image and not _is_valid_url(self.image):
            # Si no es una URL válida, podrías:
            #  - dejarla tal cual (quizás es ruta relativa)
            #  - o limpiar (ejemplo de limpieza: quitar espacios)
            self.image = self.image.strip()

    # --------- Helpers de presentación ---------

    @property
    def category_label(self) -> str:
        """Etiqueta amigable para mostrar en la tienda."""
        return CATEGORY_LABELS.get(self.category, "Otros")

    @property
    def price_formatted(self) -> str:
        """Precio formateado con moneda, ej: 'UYU 1.290,00'."""
        # Esto es súper básico; podés ajustar a tus necesidades
        # (por ejemplo usar babel para formateo local).
        amount = f"{self.price:.2f}".replace(".", ",")
        return f"{self.currency} {amount}"

    @property
    def short_name(self) -> str:
        """Nombre acortado para mostrar en tarjetas (ej: hasta 40 caracteres)."""
        max_len = 40
        if len(self.name) <= max_len:
            return self.name
        return self.name[: max_len - 1].rstrip() + "…"

    @property
    def seo_slug(self) -> str:
        """Slug SEO para URLs amigables."""
        return _slugify(self.name) or f"producto-{self.id}"

    # --------- Serialización ---------

    def to_dict(self) -> Dict[str, Any]:
        """
        Convierte el producto a un dict simple, ideal para JSON o APIs.
        """
        return {
            "id": self.id,
            "name": self.name,
            "short_name": self.short_name,
            "slug": self.seo_slug,
            "price": str(self.price),  # como string para no romper JSON
            "price_formatted": self.price_formatted,
            "currency": self.currency,
            "category": self.category,
            "category_label": self.category_label,
            "image": self.image,
            "description": self.description,
            "is_active": self.is_active,
            "metadata": self.metadata,
        }

    # --------- Factorías ---------

    @classmethod
    def from_printful(
        cls,
        product_data: Mapping[str, Any],
        *,
        default_currency: str = "UYU",
        override_id: Optional[int] = None,
        category_hint: Optional[str] = None,
    ) -> "Product":
        """
        Crea un Product a partir de un dict típico devuelto por Printful.

        Ejemplo de estructura de Printful simplificada:

            {
                "id": 123,
                "name": "Unisex Premium Hoodie",
                "type": "Hoodie",
                "variants": [
                    {
                        "id": 456,
                        "retail_price": "45.00",
                        "currency": "USD",
                        "sku": "SS-HOODIE-BLACK-M",
                        "files": [
                            {"preview_url": "https://..."}
                        ]
                    }
                ],
                "tags": ["Hoodie", "Unisex", "Streetwear"]
            }

        :param product_data: dict devuelto por Printful.
        :param default_currency: moneda por defecto si no viene de Printful.
        :param override_id: permite forzar un ID interno distinto al de Printful.
        :param category_hint: categoría explícita (si querés forzar una).
        """
        # ID: usamos override si viene; si no, el ID de Printful
        pid = override_id if override_id is not None else int(product_data.get("id", 0))

        name = product_data.get("name") or product_data.get("title") or f"Producto {pid}"
        ptype = product_data.get("type") or product_data.get("product_type") or ""

        # Variantes: tomamos la primera como referencia
        variants = product_data.get("variants") or []
        first_variant: Mapping[str, Any] = variants[0] if variants else {}

        raw_price = (
            first_variant.get("retail_price")
            or product_data.get("retail_price")
            or "0.00"
        )
        currency = (
            first_variant.get("currency")
            or product_data.get("currency")
            or default_currency
        )

        # Imagen: intentamos obtener una preview
        image_url = ""
        files = first_variant.get("files") or product_data.get("files") or []
        if isinstance(files, list) and files:
            file_0 = files[0] or {}
            image_url = (
                file_0.get("preview_url")
                or file_0.get("thumbnail_url")
                or file_0.get("url")
                or ""
            )

        # Tags para metadata y posible clasificación
        tags = product_data.get("tags") or []
        if isinstance(tags, str):
            tags_list = [tags]
        else:
            tags_list = list(tags)

        # Categoría: si viene forzada, la usamos; si no, tratamos de deducirla
        if category_hint:
            category = _normalize_category(category_hint)
        else:
            # Deducción muy simple: combinamos name, type y tags
            blob = " ".join(
                [_normalize_str(name), _normalize_str(ptype)]
                + [_normalize_str(t) for t in tags_list]
            ).lower()

            if any(k in blob for k in ["hoodie", "sweatshirt", "buzo"]):
                category = CATEGORY_BUZOS
            elif any(k in blob for k in ["jacket", "campera", "bomber"]):
                category = CATEGORY_CAMPERAS
            elif any(k in blob for k in ["t-shirt", "tee", "remera", "shirt"]):
                category = CATEGORY_REMERAS
            elif any(k in blob for k in ["hat", "cap", "beanie", "gorra"]):
                category = CATEGORY_GORROS
            else:
                category = CATEGORY_OTROS

        metadata = {
            "printful_id": product_data.get("id"),
            "printful_type": ptype,
            "printful_tags": tags_list,
            "printful_raw": product_data,
            "variant_id": first_variant.get("id"),
            "variant_sku": first_variant.get("sku"),
        }

        return cls(
            id=pid,
            name=name,
            price=_parse_price(raw_price),
            category=category,
            image=image_url,
            description=_normalize_str(product_data.get("description", "")),
            currency=currency,
            metadata=metadata,
        )
