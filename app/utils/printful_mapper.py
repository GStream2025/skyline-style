from __future__ import annotations

import json
import os
import re
import unicodedata
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple


# ============================================================
# Categorías canónicas internas (DB-safe)
# ============================================================

CATEGORY_BUZOS = "buzos"
CATEGORY_REMERAS = "remeras"
CATEGORY_GORROS = "gorros"
CATEGORY_CAMPERAS = "camperas"
CATEGORY_OTROS = "otros"

ALL_CATEGORIES: Tuple[str, ...] = (
    CATEGORY_CAMPERAS,
    CATEGORY_BUZOS,
    CATEGORY_REMERAS,
    CATEGORY_GORROS,
    CATEGORY_OTROS,
)

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
# Keywords (priorizadas)
# - OJO: se matchea por palabras/frases (no substrings sueltos)
# ============================================================

_KEYWORDS: Dict[str, List[str]] = {
    CATEGORY_CAMPERAS: [
        "jacket",
        "bomber",
        "windbreaker",
        "coach jacket",
        "campera",
        "chaqueta",
        "rompeviento",
        "cazadora",
        "zip jacket",
        "zip-up jacket",
    ],
    CATEGORY_BUZOS: [
        "hoodie",
        "pullover",
        "sweatshirt",
        "crewneck",
        "buzo",
        "canguro",
        "hooded sweatshirt",
    ],
    CATEGORY_REMERAS: [
        "t-shirt",
        "t shirt",
        "tee",
        "short sleeve",
        "short-sleeve",
        "long sleeve",
        "long-sleeve",
        "tank top",
        "shirt",
        "remera",
        "camiseta",
        "playera",
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
        "gorro",
    ],
}

# ============================================================
# “Conflictos” comunes / reglas extra
# ============================================================
# Hoodie con cierre a veces llega como “zip hoodie” y puede confundirse con campera.
# Acá lo tratamos como BUZO, salvo que también diga jacket/windbreaker/etc.
_ZIP_HOODIE_PHRASES = {"zip hoodie", "zip-up hoodie", "zippered hoodie"}

# ============================================================
# Normalización / Tokenización
# ============================================================

_WORD_RE = re.compile(r"[a-z0-9]+", re.IGNORECASE)


def _normalize(text: Optional[str]) -> str:
    if not text:
        return ""
    s = str(text).strip().lower()
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    return s


def _tokens(text: str) -> List[str]:
    # tokens alfanuméricos
    return _WORD_RE.findall(text or "")


def _blob(*parts: str) -> str:
    return " ".join([p for p in parts if p]).strip()


def _join_tags(tags: Iterable[Any]) -> str:
    out: List[str] = []
    for t in tags:
        if not t:
            continue
        # tags a veces vienen dict o cosas raras
        if isinstance(t, Mapping):
            # intenta algo razonable
            v = t.get("name") or t.get("tag") or ""
            out.append(_normalize(v))
        else:
            out.append(_normalize(str(t)))
    return " ".join([x for x in out if x])


def _split_sku(sku: str) -> str:
    # separa SKU por separadores típicos para mejorar match
    s = _normalize(sku)
    if not s:
        return ""
    return " ".join(re.split(r"[\s\-\_\/\|\.\:]+", s))


# ============================================================
# Overrides opcionales por ENV (sin tocar código)
# CATEGORY_OVERRIDES_JSON='{"hoodie zip":"buzos","windbreaker":"camperas"}'
# ============================================================


def _load_overrides() -> List[Tuple[str, str]]:
    raw = (os.getenv("CATEGORY_OVERRIDES_JSON") or "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            return []
        out: List[Tuple[str, str]] = []
        for k, v in data.items():
            kk = _normalize(str(k))
            vv = _normalize(str(v))
            if kk and vv in ALL_CATEGORIES:
                out.append((kk, vv))
        return out
    except Exception:
        return []


_OVERRIDES = _load_overrides()

# ============================================================
# Precompilación de patterns (frases/palabras)
# ============================================================


def _kw_to_token_list(kw: str) -> List[str]:
    return _tokens(_normalize(kw))


_KEYWORD_TOKENS: Dict[str, List[List[str]]] = {
    cat: [_kw_to_token_list(kw) for kw in kws if _kw_to_token_list(kw)]
    for cat, kws in _KEYWORDS.items()
}

_ZIP_HOODIE_TOKENS = [
    tuple(_kw_to_token_list(x)) for x in _ZIP_HOODIE_PHRASES if _kw_to_token_list(x)
]


# ============================================================
# Matching por secuencias de tokens (evita falsos positivos)
# ============================================================


def _contains_phrase(tokens: List[str], phrase_tokens: List[str]) -> bool:
    if not tokens or not phrase_tokens:
        return False
    n = len(phrase_tokens)
    if n == 1:
        return phrase_tokens[0] in tokens
    # sliding window
    for i in range(0, len(tokens) - n + 1):
        if tokens[i : i + n] == phrase_tokens:
            return True
    return False


def _score_category(tokens: List[str], cat: str) -> int:
    score = 0
    for pt in _KEYWORD_TOKENS.get(cat, []):
        if _contains_phrase(tokens, pt):
            # frases más largas valen más
            score += 3 if len(pt) >= 2 else 2
    return score


def is_valid_category(cat: str) -> bool:
    return (cat or "").strip().lower() in ALL_CATEGORIES


def list_categories() -> List[str]:
    return list(ALL_CATEGORIES)


# ============================================================
# Clasificación por texto (con scoring + pesos)
# ============================================================


def guess_category_from_text(
    name: Optional[str] = None,
    product_type: Optional[str] = None,
    tags: Optional[Iterable[str]] = None,
    sku: Optional[str] = None,
) -> str:
    """
    Clasifica un producto por texto libre.

    - Usa scoring + pesos por campo:
      name(3x) > product_type(2x) > tags(1x) > sku(1x)
    - Overrides por ENV si existen
    - Resuelve conflicto zip hoodie: por defecto BUZO
    """

    n = _normalize(name)
    t = _normalize(product_type)
    g = _join_tags(tags or [])
    s = _split_sku(sku or "")

    # Overrides primero (si el texto contiene la key, forzamos)
    blob_all = _blob(n, t, g, s)
    for needle, cat in _OVERRIDES:
        if needle and needle in blob_all:
            return cat

    tokens_name = _tokens(n)
    tokens_type = _tokens(t)
    tokens_tags = _tokens(g)
    tokens_sku = _tokens(s)

    scores: Dict[str, int] = {c: 0 for c in ALL_CATEGORIES}

    # pesos por campo
    for c in (CATEGORY_CAMPERAS, CATEGORY_BUZOS, CATEGORY_REMERAS, CATEGORY_GORROS):
        scores[c] += 3 * _score_category(tokens_name, c)
        scores[c] += 2 * _score_category(tokens_type, c)
        scores[c] += 1 * _score_category(tokens_tags, c)
        scores[c] += 1 * _score_category(tokens_sku, c)

    # Regla especial: zip hoodie => BUZO salvo que también haya señales de CAMPERA
    if tokens_name or tokens_type:
        all_tokens = tokens_name + tokens_type + tokens_tags
        has_zip_hoodie = any(
            _contains_phrase(all_tokens, list(z)) for z in _ZIP_HOODIE_TOKENS
        )
        if has_zip_hoodie:
            # si también menciona jacket/windbreaker/etc, dejamos que gane campera
            campera_hint = scores[CATEGORY_CAMPERAS] > 0
            if not campera_hint:
                return CATEGORY_BUZOS

    # Elegir el mejor score
    best_cat = CATEGORY_OTROS
    best_score = 0

    # Orden de desempate (tu preferencia original)
    tie_order = (CATEGORY_CAMPERAS, CATEGORY_BUZOS, CATEGORY_REMERAS, CATEGORY_GORROS)

    for c in tie_order:
        sc = scores.get(c, 0)
        if sc > best_score:
            best_cat, best_score = c, sc

    return best_cat if best_score > 0 else CATEGORY_OTROS


# ============================================================
# Clasificación directa desde Printful (tolerante)
# ============================================================


def guess_category_from_printful(product: Mapping[str, Any]) -> str:
    """
    Recibe un dict de Printful y devuelve categoría interna.

    Tolera:
    - product no dict
    - tags raros
    - sku en product o en variants
    """

    if not isinstance(product, Mapping):
        return CATEGORY_OTROS

    name = product.get("name") or product.get("title") or ""
    product_type = product.get("type") or product.get("product_type") or ""

    # Tags: list | string | mixed
    raw_tags = product.get("tags") or []
    if isinstance(raw_tags, str):
        tags = [raw_tags]
    elif isinstance(raw_tags, list):
        tags = raw_tags
    else:
        tags = []

    sku: Optional[str] = None

    # a) Producto global
    prod = product.get("product")
    if isinstance(prod, Mapping):
        sku = prod.get("sku") or sku

    # b) Variantes (primera con SKU)
    variants = product.get("variants")
    if isinstance(variants, list):
        for v in variants:
            if isinstance(v, Mapping):
                vs = v.get("sku")
                if vs:
                    sku = str(vs)
                    break

    return guess_category_from_text(
        name=str(name),
        product_type=str(product_type),
        tags=tags,  # dejamos mixed (el join lo tolera)
        sku=sku,
    )


__all__ = [
    "CATEGORY_BUZOS",
    "CATEGORY_REMERAS",
    "CATEGORY_GORROS",
    "CATEGORY_CAMPERAS",
    "CATEGORY_OTROS",
    "ALL_CATEGORIES",
    "CATEGORY_LABELS",
    "is_valid_category",
    "list_categories",
    "guess_category_from_text",
    "guess_category_from_printful",
]
