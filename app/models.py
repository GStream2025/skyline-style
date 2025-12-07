"""
======================================================
  Modelo de dominio: Product (Skyline Style)
  - Independiente de la base de datos (no ORM).
  - Pensado para integrarse con Printful y la capa web.
  - Enfocado en datos limpios, tipados y listos para UI.
======================================================
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal, ROUND_HALF_UP, InvalidOperation
from typing import Any, Dict, Mapping, Optional, Sequence, List

import re
import unicodedata
from urllib.parse import urlparse

# ---------------------------------------------------
# Categorías internas canónicas
# ---------------------------------------------------
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


# ---------------------------------------------------
# Helpers internos
# ---------------------------------------------------
def _normalize_str(value: Optional[str]) -> str:
    """Convierte cualquier valor a string limpio (sin None, sin espacios extremos)."""
    if value is None:
        return ""
    return str(value).strip()


def _normalize_category(category: Optional[str]) -> str:
    """
    Normaliza la categoría que venga de cualquier lado (Printful, BD, etc.)
    a una de las categorías internas canónicas.
    """
    c = _normalize_str(category).lower()

    if c in (CATEGORY_BUZOS, "hoodie", "hoodies", "sweatshirt", "buzo", "buzos"):
        return CATEGORY_BUZOS
    if c in (CATEGORY_REMERAS, "t-shirt", "tshirt", "tee", "remera", "remeras", "shirt"):
        return CATEGORY_REMERAS
    if c in (CATEGORY_GORROS, "cap", "hat", "beanie", "gorra", "gorras"):
        return CATEGORY_GORROS
    if c in (CATEGORY_CAMPERAS, "jacket", "campera", "camperas", "zip hoodie", "bomber"):
        return CATEGORY_CAMPERAS

    return CATEGORY_OTROS


def _parse_price(value: Any) -> Decimal:
    """
    Convierte un valor genérico a Decimal con 2 decimales.

    Acepta:
        - float, int
        - str ("1290", "1290.50")
        - Decimal

    Si no se puede convertir, devuelve Decimal("0.00").
    """
    if isinstance(value, Decimal):
        price = value
    else:
        try:
            price = Decimal(str(value))
        except (InvalidOperation, TypeError, ValueError):
            price = Decimal("0.00")

    return price.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def _is_valid_url(url: str) -> bool:
    """Validación simple de URL (evita cosas muy rotas)."""
    if not url:
        return False
    parsed = urlparse(url)
    return bool(parsed.scheme and parsed.netloc)


_slug_pattern = re.compile(r"[^a-z0-9]+")


def _slugify(text: str) -> str:
    """
    Genera un slug SEO-friendly a partir de un texto.

    Ej:
        "Buzo Skyline Ámbar v2" -> "buzo-skyline-ambar-v2"
    """
    text = _normalize_str(text).lower()

    # Normaliza acentos y caracteres raros (á -> a, ñ -> n, etc.)
    text = unicodedata.normalize("NFKD", text)
    text = "".join(ch for ch in text if not unicodedata.combining(ch))

    # Reemplazar todo lo que NO sea a-z0-9 por guiones
    text = _slug_pattern.sub("-", text)

    # Quitar guiones extremos
    return text.strip("-")


# ---------------------------------------------------
# Modelo de dominio
# ---------------------------------------------------
@dataclass(slots=True)
class Product:
    """
    Modelo de producto de dominio para Skyline Style.

    NOTA: Este modelo NO es el modelo de la base de datos.
    Podés mapearlo fácilmente a/desde tu modelo SQLAlchemy.

    Atributos:
        id: Identificador interno (puede ser de BD o Printful).
        name: Nombre visible del producto.
        price: Precio como Decimal con 2 decimales.
        category: Categoría interna canónica.
        image: URL o ruta de la imagen principal.
        description: Descripción corta o larga.
        currency: Código de moneda (por defecto "UYU").
        is_active: Si está disponible para mostrarse en tienda.
        metadata: Datos adicionales (printful_id, sku, tags, etc.).
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

    # -----------------------------
    # Normalización post-init
    # -----------------------------
    def __post_init__(self) -> None:
        # Nombre siempre limpio y no vacío
        self.name = _normalize_str(self.name) or f"Producto {self.id}"

        self.description = _normalize_str(self.description)
        self.currency = (_normalize_str(self.currency) or "UYU").upper()

        # Categoría normalizada a las internas
        self.category = _normalize_category(self.category)

        # Precio siempre como Decimal con 2 decimales
        self.price = _parse_price(self.price)

        # Imagen principal: aceptamos URL absoluta o ruta relativa
        self.image = _normalize_str(self.image)
        if self.image and not _is_valid_url(self.image) and not self.image.startswith("/"):
            # No tocamos rutas relativas válidas ("/static/..."),
            # sólo limpiamos basura obvia.
            self.image = self.image.strip()

        # Metadata nunca None
        if self.metadata is None:
            self.metadata = {}

    # -----------------------------
    # Helpers de presentación
    # -----------------------------
    @property
    def category_label(self) -> str:
        """Etiqueta amigable para mostrar en la tienda."""
        return CATEGORY_LABELS.get(self.category, CATEGORY_LABELS[CATEGORY_OTROS])

    @property
    def price_formatted(self) -> str:
        """Precio formateado con moneda, ej: 'UYU 1.290,00'."""
        amount = f"{self.price:.2f}".replace(".", ",")
        return f"{self.currency} {amount}"

    @property
    def short_name(self) -> str:
        """Nombre acortado para cards (ej. máximo 40 caracteres)."""
        max_len = 40
        if len(self.name) <= max_len:
            return self.name
        return self.name[: max_len - 1].rstrip() + "…"

    @property
    def seo_slug(self) -> str:
        """Slug SEO para URLs amigables."""
        slug = _slugify(self.name)
        return slug or f"producto-{self.id}"

    # -----------------------------
    # Serialización
    # -----------------------------
    def to_dict(self) -> Dict[str, Any]:
        """
        Convierte el producto a un dict simple, ideal para JSON o APIs.
        """
        return {
            "id": self.id,
            "name": self.name,
            "short_name": self.short_name,
            "slug": self.seo_slug,
            "price": str(self.price),           # string para JSON seguro
            "price_formatted": self.price_formatted,
            "currency": self.currency,
            "category": self.category,
            "category_label": self.category_label,
            "image": self.image,
            "description": self.description,
            "is_active": self.is_active,
            "metadata": self.metadata,
        }

    # -----------------------------
    # Factoría desde Printful
    # -----------------------------
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
        Construye un `Product` a partir de la estructura típica devuelta por Printful.

        Ejemplo de estructura simplificada de producto Printful:

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
                "tags": ["Hoodie", "Unisex", "Streetwear"],
                "description": "Hoodie premium con..."
            }

        :param product_data: dict devuelto por Printful.
        :param default_currency: moneda por defecto si no viene.
        :param override_id: permite forzar un ID interno distinto al de Printful.
        :param category_hint: categoría explícita a forzar (opcional).
        """
        # ID interno
        pid_raw = override_id if override_id is not None else product_data.get("id", 0)
        try:
            pid = int(pid_raw)
        except (TypeError, ValueError):
            pid = 0

        # Nombre y tipo
        name = (
            product_data.get("name")
            or product_data.get("title")
            or f"Producto {pid or 'sin-id'}"
        )
        ptype = product_data.get("type") or product_data.get("product_type") or ""

        # Variantes: usamos la primera como referencia
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

        # Imagen principal: buscamos preview / thumbnail / url
        image_url = ""
        files: Sequence[Mapping[str, Any]] = (
            first_variant.get("files")
            or product_data.get("files")
            or []
        )
        if isinstance(files, Sequence) and files:
            file0 = files[0] or {}
            image_url = (
                file0.get("preview_url")
                or file0.get("thumbnail_url")
                or file0.get("url")
                or ""
            )

        # Tags
        tags_raw = product_data.get("tags") or []
        if isinstance(tags_raw, str):
            tags: List[str] = [tags_raw]
        else:
            tags = [str(t) for t in tags_raw]

        # Categoría: hint explícito > deducción automática
        if category_hint:
            category = _normalize_category(category_hint)
        else:
            # Combinamos nombre, tipo y tags para deducir
            blob = " ".join(
                filter(
                    None,
                    [
                        _normalize_str(name),
                        _normalize_str(ptype),
                        *[_normalize_str(t) for t in tags],
                    ],
                )
            ).lower()

            if any(k in blob for k in ("hoodie", "sweatshirt", "buzo", "hoodies")):
                category = CATEGORY_BUZOS
            elif any(k in blob for k in ("jacket", "campera", "bomber")):
                category = CATEGORY_CAMPERAS
            elif any(k in blob for k in ("t-shirt", "tee", "remera", "shirt")):
                category = CATEGORY_REMERAS
            elif any(k in blob for k in ("hat", "cap", "beanie", "gorra")):
                category = CATEGORY_GORROS
            else:
                category = CATEGORY_OTROS

        # Metadata enriquecida
        metadata: Dict[str, Any] = {
            "printful_id": product_data.get("id"),
            "printful_type": ptype,
            "printful_tags": tags,
            "printful_raw": dict(product_data),  # snapshot completo
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
