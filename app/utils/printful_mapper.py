from __future__ import annotations

import unicodedata
from typing import Iterable, Mapping, Optional, Dict, Any, List


# ============================================================
# Categorías canónicas internas (DB-safe)
# ============================================================

CATEGORY_BUZOS = "buzos"
CATEGORY_REMERAS = "remeras"
CATEGORY_GORROS = "gorros"
CATEGORY_CAMPERAS = "camperas"
CATEGORY_OTROS = "otros"


# ============================================================
# Labels UI (solo presentación)
# ============================================================

CATEGORY_LABELS: Dict[str, str] = {
    CATEGORY_BUZOS: "Buzos / Hoodies",
    CATEGORY_REMERAS: "Remeras",
    CATEGORY_GORROS: "Gorros",
    CATEGORY_CAMPERAS: "Camperas",
    CATEGORY_OTROS: "Otros",
}


# ============================================================
# Keywords (separadas y priorizadas)
# ============================================================

_KEYWORDS = {
    CATEGORY_CAMPERAS: [
        "jacket",
        "bomber",
        "windbreaker",
        "coach jacket",
        "zip hoodie",
        "campera",
    ],
    CATEGORY_BUZOS: [
        "hoodie",
        "pullover",
        "sweatshirt",
        "crewneck",
        "hooded",
        "buzo",
    ],
    CATEGORY_REMERAS: [
        "t-shirt",
        "t shirt",
        "tee",
        "short sleeve",
        "short-sleeve",
        "long sleeve",
        "tank top",
        "shirt",
        "remera",
    ],
    CATEGORY_GORROS: [
        "cap",
        "snapback",
        "dad hat",
        "trucker hat",
        "bucket hat",
        "beanie",
        "hat",
        "gorra",
    ],
}


# ============================================================
# Helpers internos (defensivos)
# ============================================================

def _normalize(text: Optional[str]) -> str:
    """
    Normaliza texto:
    - lower
    - sin acentos
    - sin unicode raro
    - nunca None
    """
    if not text:
        return ""
    text = str(text).strip().lower()
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c))
    return text


def _join_tags(tags: Iterable[Any]) -> str:
    out: List[str] = []
    for t in tags:
        if t:
            out.append(_normalize(str(t)))
    return " ".join(out)


def _any_in(text: str, keywords: Iterable[str]) -> bool:
    if not text:
        return False
    return any(kw in text for kw in keywords)


# ============================================================
# Clasificación por texto
# ============================================================

def guess_category_from_text(
    name: Optional[str] = None,
    product_type: Optional[str] = None,
    tags: Optional[Iterable[str]] = None,
    sku: Optional[str] = None,
) -> str:
    """
    Clasifica un producto a partir de texto libre.

    ✔ Español / Inglés
    ✔ Robusto a ruido
    ✔ No depende de Printful
    """

    blob = " ".join(
        filter(
            None,
            [
                _normalize(name),
                _normalize(product_type),
                _join_tags(tags or []),
                _normalize(sku),
            ],
        )
    )

    # Orden IMPORTA (camperas antes que hoodies)
    for category in (
        CATEGORY_CAMPERAS,
        CATEGORY_BUZOS,
        CATEGORY_REMERAS,
        CATEGORY_GORROS,
    ):
        if _any_in(blob, _KEYWORDS.get(category, [])):
            return category

    return CATEGORY_OTROS


# ============================================================
# Clasificación directa desde Printful
# ============================================================

def guess_category_from_printful(product: Mapping[str, Any]) -> str:
    """
    Recibe un dict de Printful y devuelve categoría interna.

    ✔ Tolera estructuras incompletas
    ✔ No rompe si cambia Printful
    """

    if not isinstance(product, Mapping):
        return CATEGORY_OTROS

    name = product.get("name") or product.get("title")
    product_type = product.get("type") or product.get("product_type")

    # Tags: list | string | mixed
    raw_tags = product.get("tags") or []
    if isinstance(raw_tags, str):
        tags = [raw_tags]
    elif isinstance(raw_tags, list):
        tags = raw_tags
    else:
        tags = []

    # SKU (varios lugares posibles)
    sku: Optional[str] = None

    # a) Producto global
    prod = product.get("product")
    if isinstance(prod, Mapping):
        sku = prod.get("sku") or sku

    # b) Variantes (busca la primera con SKU válido)
    variants = product.get("variants")
    if isinstance(variants, list):
        for v in variants:
            if isinstance(v, Mapping) and v.get("sku"):
                sku = v["sku"]
                break

    return guess_category_from_text(
        name=name,
        product_type=product_type,
        tags=tags,
        sku=sku,
    )


# ============================================================
# Export público estable
# ============================================================

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
