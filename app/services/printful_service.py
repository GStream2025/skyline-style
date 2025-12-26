# app/services/printful_service.py
from __future__ import annotations

import os
from typing import Any, Dict, List, Tuple

import requests


class PrintfulService:
    """
    Printful API (simple):
    - Usa PRINTFUL_API_KEY en tu .env
    - Trae productos del store y los normaliza al formato del ProductService.
    """

    BASE = "https://api.printful.com"

    def __init__(self) -> None:
        self.api_key = os.getenv("PRINTFUL_API_KEY", "").strip()

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _ok_ready(self) -> Tuple[bool, str]:
        if not self.api_key:
            return False, "Falta PRINTFUL_API_KEY en .env"
        return True, ""

    def fetch_store_products(self) -> Tuple[bool, Any]:
        """
        Devuelve lista normalizada:
        {
          external_id, title, description, price, compare_at_price, currency,
          image_url, category_slug, stock, status, tags
        }
        """
        ok, msg = self._ok_ready()
        if not ok:
            return False, msg

        try:
            # Endpoint típico: /store/products
            r = requests.get(f"{self.BASE}/store/products", headers=self._headers(), timeout=20)
            if r.status_code >= 400:
                return False, f"HTTP {r.status_code}: {r.text[:180]}"
            data = r.json()

            items = data.get("result") or []
            normalized: List[Dict[str, Any]] = []

            for it in items:
                # it suele tener: id, name, thumbnail_url...
                external_id = str(it.get("id") or "").strip()
                title = (it.get("name") or "Printful item").strip()
                image = (it.get("thumbnail_url") or "").strip()
                # Printful no siempre trae precios directos aquí -> dejamos 0 y lo ajustás o lo enriquecés con otro endpoint
                normalized.append({
                    "external_id": external_id,
                    "title": title,
                    "description": (it.get("description") or "").strip(),
                    "price": 0,
                    "compare_at_price": None,
                    "currency": "USD",
                    "image_url": image,
                    "category_slug": "skyline",  # podés mapear por tags/collections
                    "stock": 999,
                    "status": "active",
                    "tags": "printful",
                })

            return True, normalized

        except Exception as e:
            return False, f"Error Printful: {e}"
