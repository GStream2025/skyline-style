# app/services/dropshipping_service.py
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import requests

from app.models import db, Product, Category, ProductMedia, Tag  # ajusta si tus imports difieren


@dataclass(frozen=True)
class DropProduct:
    external_id: str
    title: str
    description: str
    price: float
    compare_at_price: Optional[float]
    currency: str
    image_url: str
    category_slug: str
    stock: int
    status: str
    tags: str


class DropshippingService:
    DEFAULT_TIMEOUT = 20
    DEFAULT_CURRENCY = "UYU"
    DEFAULT_STATUS = "active"

    def __init__(self) -> None:
        self.feed_url = (os.getenv("DROPSHIPPING_FEED_URL") or "").strip()
        self.feed_file = (os.getenv("DROPSHIPPING_FEED_FILE") or "").strip()
        self.timeout = self._to_int(os.getenv("DROPSHIPPING_TIMEOUT"), self.DEFAULT_TIMEOUT)
        self.user_agent = (os.getenv("DROPSHIPPING_USER_AGENT") or "SkylineStore/1.0 (+dropshipping-feed)").strip()

        # comportamiento
        self.auto_create_categories = self._to_bool(os.getenv("DROPSHIPPING_AUTO_CREATE_CATEGORIES"), True)
        self.update_existing_manual = self._to_bool(os.getenv("DROPSHIPPING_UPDATE_MANUAL"), False)  # por defecto NO
        self.default_supplier_name = (os.getenv("DROPSHIPPING_SUPPLIER_NAME") or "Dropshipping").strip()

    # =========================
    # API
    # =========================
    def fetch_feed_products(self) -> Tuple[bool, Any]:
        try:
            data = self._load_feed()
            if not isinstance(data, list):
                return False, "El feed debe ser una lista JSON (array)."

            normalized: List[DropProduct] = []
            for it in data:
                p = self._normalize_item(it)
                if p:
                    normalized.append(p)

            if not normalized:
                return False, "Feed leído pero sin productos válidos (external_id + title)."

            # devolvemos dicts para compatibilidad
            return True, [self._as_dict(p) for p in normalized]

        except Exception as e:
            return False, f"Error Dropshipping: {e}"

    def sync_to_db(self) -> Dict[str, Any]:
        """
        Sincroniza el feed en la DB:
        - Upsert por Product.external_id
        - source='dropship'
        - No pisa manual/printful a menos que DROPSHIPPING_UPDATE_MANUAL=true
        """
        ok, data = self.fetch_feed_products()
        if not ok:
            return {"ok": False, "error": data}

        products: List[Dict[str, Any]] = data
        created = 0
        updated = 0
        skipped = 0
        errors: List[str] = []

        for it in products:
            try:
                external_id = (it.get("external_id") or "").strip()
                if not external_id:
                    skipped += 1
                    continue

                # 1) buscamos por external_id
                p: Optional[Product] = db.session.query(Product).filter(Product.external_id == external_id).first()

                # 2) si existe, validamos si se puede actualizar
                if p is not None:
                    # Si es manual o printful y no queremos tocarlo:
                    if (p.source or "").lower() != "dropship" and not self.update_existing_manual:
                        skipped += 1
                        continue
                    self._apply_fields(p, it)
                    self._apply_category(p, it.get("category_slug") or "")
                    self._apply_tags(p, it.get("tags") or "")
                    self._apply_main_image(p, it.get("image_url") or "")
                    updated += 1
                else:
                    # 3) crear nuevo dropship
                    p = Product(
                        external_id=external_id,
                        title=(it.get("title") or "").strip(),
                        slug=self._safe_slug(external_id, (it.get("title") or "").strip()),
                        source="dropship",
                        status=(it.get("status") or "active").strip().lower(),
                        currency=(it.get("currency") or "UYU").strip().upper(),
                        price=self._to_float(it.get("price"), 0.0) or 0.0,
                        compare_at_price=self._to_float(it.get("compare_at_price"), None),
                        stock_mode="finite",
                        stock_qty=self._to_int(it.get("stock"), 0),
                        supplier_name=self.default_supplier_name,
                        external_url=self._external_url_from_id(external_id),
                        short_description=(it.get("description") or "").strip()[:260] if hasattr(Product, "short_description") else None,
                        description_html=(it.get("description") or "").strip(),
                    )
                    db.session.add(p)
                    db.session.flush()  # obtener p.id para media

                    self._apply_category(p, it.get("category_slug") or "")
                    self._apply_tags(p, it.get("tags") or "")
                    self._apply_main_image(p, it.get("image_url") or "")

                    created += 1

            except Exception as e:
                errors.append(f"{it.get('external_id')}: {e}")

        if errors:
            db.session.rollback()
            return {"ok": False, "created": created, "updated": updated, "skipped": skipped, "errors": errors}

        db.session.commit()
        return {"ok": True, "created": created, "updated": updated, "skipped": skipped}

    # =========================
    # Apply helpers
    # =========================
    def _apply_fields(self, p: Product, it: Dict[str, Any]) -> None:
        p.title = (it.get("title") or p.title or "").strip()
        p.status = (it.get("status") or p.status or "active").strip().lower()
        p.currency = (it.get("currency") or p.currency or "UYU").strip().upper()

        price = self._to_float(it.get("price"), None)
        if price is not None:
            p.price = price

        cap = self._to_float(it.get("compare_at_price"), None)
        p.compare_at_price = cap

        desc = (it.get("description") or "").strip()
        if hasattr(p, "short_description"):
            p.short_description = desc[:260] if desc else p.short_description
        if hasattr(p, "description_html"):
            p.description_html = desc or getattr(p, "description_html", None)

        # stock
        p.stock_mode = "finite"
        p.stock_qty = self._to_int(it.get("stock"), int(getattr(p, "stock_qty", 0) or 0))

        # metadata dropship
        p.source = "dropship"
        p.supplier_name = self.default_supplier_name
        p.external_url = self._external_url_from_id(it.get("external_id") or "")

    def _apply_category(self, p: Product, slug: str) -> None:
        slug = self._to_str(slug).lower()
        if not slug:
            return

        cat = db.session.query(Category).filter(Category.slug == slug).first()
        if not cat and self.auto_create_categories:
            cat = Category(name=slug.replace("-", " ").title(), slug=slug)
            db.session.add(cat)
            db.session.flush()

        if cat:
            p.category_id = cat.id

    def _apply_main_image(self, p: Product, url: str) -> None:
        url = self._to_str(url)
        if not url:
            return

        # si ya tiene media image 1, actualizamos; si no, creamos
        existing = None
        if hasattr(p, "media") and p.media:
            images = [m for m in p.media if (m.type or "") == "image"]
            images.sort(key=lambda x: x.sort_order or 0)
            existing = images[0] if images else None

        if existing:
            existing.url = url
            existing.sort_order = 0
        else:
            pm = ProductMedia(product_id=p.id, type="image", url=url, sort_order=0)
            db.session.add(pm)

    def _apply_tags(self, p: Product, tags: str) -> None:
        tags = (tags or "").strip()
        if not tags:
            tags = "dropshipping"

        # soporta "a,b,c"
        parts = [x.strip() for x in tags.replace(";", ",").split(",") if x.strip()]
        if not parts:
            parts = ["dropshipping"]

        # si tu modelo tiene relación many-to-many tags
        if not hasattr(p, "tags"):
            return

        tag_objs: List[Tag] = []
        for name in parts[:12]:
            slug = self._slugify(name)
            t = db.session.query(Tag).filter(Tag.slug == slug).first()
            if not t:
                t = Tag(name=name, slug=slug)
                db.session.add(t)
                db.session.flush()
            tag_objs.append(t)

        p.tags = tag_objs  # reemplaza por set actual (más simple y consistente)

    # =========================
    # Feed loading
    # =========================
    def _load_feed(self) -> Any:
        if self.feed_url:
            return self._load_from_url(self.feed_url)
        if self.feed_file:
            return self._load_from_file(self.feed_file)
        raise RuntimeError("Definí DROPSHIPPING_FEED_URL o DROPSHIPPING_FEED_FILE en .env")

    def _load_from_url(self, url: str) -> Any:
        headers = {"User-Agent": self.user_agent, "Accept": "application/json"}
        r = requests.get(url, headers=headers, timeout=self.timeout)
        if r.status_code >= 400:
            snippet = (r.text or "")[:240].replace("\n", " ").strip()
            raise RuntimeError(f"Feed URL HTTP {r.status_code}: {snippet}")
        try:
            return r.json()
        except Exception:
            snippet = (r.text or "")[:240].replace("\n", " ").strip()
            raise RuntimeError(f"El feed remoto no es JSON válido. Respuesta: {snippet}")

    def _load_from_file(self, path: str) -> Any:
        if not os.path.exists(path):
            raise RuntimeError(f"El archivo de feed no existe: {path}")
        with open(path, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError as e:
                raise RuntimeError(f"El feed local no es JSON válido: {e}")

    # =========================
    # Normalization
    # =========================
    def _normalize_item(self, it: Any) -> Optional[DropProduct]:
        if not isinstance(it, dict):
            return None

        external_id = self._to_str(it.get("external_id") or it.get("id"))
        title = self._to_str(it.get("title") or it.get("name"))
        if not external_id or not title:
            return None

        description = self._to_str(it.get("description"))
        currency = self._to_currency(it.get("currency") or self.DEFAULT_CURRENCY)
        price = self._to_float(it.get("price"), default=0.0) or 0.0
        compare = self._to_float(it.get("compare_at_price"), default=None)

        image_url = self._to_str(it.get("image_url") or it.get("image") or it.get("thumbnail") or "")
        category_slug = self._to_str(it.get("category_slug") or it.get("category") or "")
        stock = self._to_int(it.get("stock"), default=0)
        status = self._to_status(it.get("status") or self.DEFAULT_STATUS)
        tags = self._to_tags(it.get("tags"))

        return DropProduct(
            external_id=external_id,
            title=title,
            description=description,
            price=price,
            compare_at_price=compare,
            currency=currency,
            image_url=image_url,
            category_slug=category_slug,
            stock=stock,
            status=status,
            tags=tags,
        )

    @staticmethod
    def _as_dict(p: DropProduct) -> Dict[str, Any]:
        return {
            "external_id": p.external_id,
            "title": p.title,
            "description": p.description,
            "price": p.price,
            "compare_at_price": p.compare_at_price,
            "currency": p.currency,
            "image_url": p.image_url,
            "category_slug": p.category_slug,
            "stock": p.stock,
            "status": p.status,
            "tags": p.tags,
        }

    # =========================
    # Utils
    # =========================
    @staticmethod
    def _to_str(v: Any) -> str:
        return "" if v is None else str(v).strip()

    @staticmethod
    def _to_int(v: Any, default: int) -> int:
        if v is None or v == "":
            return default
        try:
            return int(float(str(v).strip()))
        except Exception:
            return default

    @staticmethod
    def _to_float(v: Any, default: Optional[float]) -> Optional[float]:
        if v is None or v == "":
            return default
        try:
            return float(str(v).strip().replace(",", "."))
        except Exception:
            return default

    @staticmethod
    def _to_currency(v: Any) -> str:
        s = (str(v).strip().upper() if v is not None else "").strip()
        return s if len(s) == 3 else "UYU"

    @staticmethod
    def _to_status(v: Any) -> str:
        s = (str(v).strip().lower() if v is not None else "").strip()
        if s in {"active", "enabled", "public", "published"}:
            return "active"
        if s in {"hidden", "disabled", "private", "unpublished"}:
            return "hidden"
        if s in {"draft", "pending"}:
            return "draft"
        return "active"

    @staticmethod
    def _to_tags(v: Any) -> str:
        if v is None:
            return "dropshipping"
        if isinstance(v, list):
            cleaned = [str(x).strip() for x in v if str(x).strip()]
            return ", ".join(cleaned) if cleaned else "dropshipping"
        if isinstance(v, str):
            s = v.strip()
            return s if s else "dropshipping"
        return "dropshipping"

    @staticmethod
    def _to_bool(v: Any, default: bool) -> bool:
        if v is None:
            return default
        s = str(v).strip().lower()
        if s in {"1", "true", "yes", "y", "on"}:
            return True
        if s in {"0", "false", "no", "n", "off"}:
            return False
        return default

    @staticmethod
    def _slugify(s: str) -> str:
        s = (s or "").strip().lower()
        out = []
        last_dash = False
        for ch in s:
            if ch.isalnum():
                out.append(ch)
                last_dash = False
            else:
                if not last_dash:
                    out.append("-")
                    last_dash = True
        slug = "".join(out).strip("-")
        return slug[:160] if slug else "tag"

    def _safe_slug(self, external_id: str, title: str) -> str:
        # slug estable: external_id manda (evita duplicados)
        base = self._slugify(title)[:120]
        eid = self._slugify(external_id)[:60]
        slug = f"{base}-{eid}".strip("-") if base else eid
        return slug[:200] if slug else eid[:200]

    @staticmethod
    def _external_url_from_id(external_id: str) -> str:
        # si tu feed trae URL real podés cambiarlo: acá lo dejamos vacío/placeholder
        return ""
