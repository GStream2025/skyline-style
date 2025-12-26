# app/services/dropshipping_service.py
from __future__ import annotations

import os
import json
from typing import Any, Dict, List, Tuple
import requests


class DropshippingService:
    """
    Dropshipping genérico (feed):
    - Soporta:
      * DROPSHIPPING_FEED_URL (JSON)
      * o DROPSHIPPING_FEED_FILE (path local)
    - El feed debe ser una lista de productos con campos similares a:
      external_id, title, description, price, compare_at_price, currency,
      image_url, category_slug, stock, status, tags
    """

    def __init__(self) -> None:
        self.feed_url = os.getenv("DROPSHIPPING_FEED_URL", "").strip()
        self.feed_file = os.getenv("DROPSHIPPING_FEED_FILE", "").strip()

    def fetch_feed_products(self) -> Tuple[bool, Any]:
        try:
            if self.feed_url:
                r = requests.get(self.feed_url, timeout=20)
                if r.status_code >= 400:
                    return False, f"HTTP {r.status_code}: {r.text[:180]}"
                data = r.json()
            elif self.feed_file:
                with open(self.feed_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
            else:
                return False, "Definí DROPSHIPPING_FEED_URL o DROPSHIPPING_FEED_FILE en .env"

            if not isinstance(data, list):
                return False, "El feed debe ser una lista JSON de productos."

            normalized: List[Dict[str, Any]] = []
            for it in data:
                normalized.append({
                    "external_id": str(it.get("external_id") or it.get("id") or "").strip(),
                    "title": (it.get("title") or it.get("name") or "").strip(),
                    "description": (it.get("description") or "").strip(),
                    "price": it.get("price", 0),
                    "compare_at_price": it.get("compare_at_price"),
                    "currency": (it.get("currency") or "UYU").strip(),
                    "image_url": (it.get("image_url") or it.get("image") or "").strip(),
                    "category_slug": (it.get("category_slug") or it.get("category") or "").strip(),
                    "stock": it.get("stock", 0),
                    "status": (it.get("status") or "active").strip(),
                    "tags": (it.get("tags") or "dropshipping").strip() if isinstance(it.get("tags"), str) else "dropshipping",
                })

            # filtramos los inválidos
            normalized = [x for x in normalized if x.get("external_id") and x.get("title")]
            return True, normalized

        except Exception as e:
            return False, f"Error Dropshipping: {e}"
