# app/admin/admin_routes.py
from __future__ import annotations

import os
from functools import wraps
from datetime import datetime
from typing import Optional

from flask import (
    Blueprint, render_template, request, redirect,
    url_for, session, flash, current_app
)

from app.services.product_service import ProductService
from app.services.printful_service import PrintfulService
from app.services.dropshipping_service import DropshippingService


admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def _admin_user() -> str:
    return os.getenv("ADMIN_USER", "Gabriel")


def _admin_pass() -> str:
    # No hardcodeamos contraseñas en repo. Se define en .env
    return os.getenv("ADMIN_PASS", "change_me")


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("admin_ok"):
            return redirect(url_for("admin.login", next=request.path))
        return view(*args, **kwargs)
    return wrapper


@admin_bp.get("/login")
def login():
    if session.get("admin_ok"):
        return redirect(url_for("admin.dashboard"))
    return render_template("admin/login.html", admin_user=_admin_user())


@admin_bp.post("/login")
def login_post():
    u = (request.form.get("username") or "").strip()
    p = (request.form.get("password") or "").strip()

    if u == _admin_user() and p == _admin_pass():
        session["admin_ok"] = True
        session["admin_user"] = u
        session["admin_login_at"] = datetime.utcnow().isoformat()
        flash("Bienvenido, administrador ✅", "ok")
        nxt = request.args.get("next") or url_for("admin.dashboard")
        return redirect(nxt)

    flash("Usuario o contraseña incorrectos.", "err")
    return redirect(url_for("admin.login"))


@admin_bp.get("/logout")
def logout():
    session.clear()
    flash("Sesión cerrada.", "ok")
    return redirect(url_for("admin.login"))


@admin_bp.get("/")
@admin_required
def dashboard():
    ps = ProductService()
    stats = ps.get_stats()

    return render_template(
        "admin/dashboard.html",
        stats=stats,
        admin_user=session.get("admin_user", _admin_user()),
    )


# -------------------- PRODUCTS --------------------

@admin_bp.get("/products")
@admin_required
def products():
    q = (request.args.get("q") or "").strip()
    category = (request.args.get("category") or "").strip()
    source = (request.args.get("source") or "").strip()  # skyline/printful/dropshipping
    status = (request.args.get("status") or "").strip()  # active/draft/archived

    ps = ProductService()
    products = ps.list_products(q=q, category_slug=category, source=source, status=status)
    categories = ps.list_categories()

    return render_template(
        "admin/products.html",
        products=products,
        categories=categories,
        q=q,
        category=category,
        source=source,
        status=status,
    )


@admin_bp.post("/products/create")
@admin_required
def products_create():
    ps = ProductService()

    payload = {
        "title": (request.form.get("title") or "").strip(),
        "slug": (request.form.get("slug") or "").strip(),
        "description": (request.form.get("description") or "").strip(),
        "price": request.form.get("price") or "0",
        "compare_at_price": request.form.get("compare_at_price") or "",
        "currency": (request.form.get("currency") or "UYU").strip(),
        "category_slug": (request.form.get("category_slug") or "").strip(),
        "image_url": (request.form.get("image_url") or "").strip(),
        "stock": request.form.get("stock") or "0",
        "status": (request.form.get("status") or "active").strip(),
        "source": (request.form.get("source") or "skyline").strip(),
        "external_id": (request.form.get("external_id") or "").strip(),
        "tags": (request.form.get("tags") or "").strip(),
    }

    ok, msg = ps.create_product(payload)
    flash(msg, "ok" if ok else "err")
    return redirect(url_for("admin.products"))


@admin_bp.post("/products/update/<int:product_id>")
@admin_required
def products_update(product_id: int):
    ps = ProductService()
    payload = {
        "title": (request.form.get("title") or "").strip(),
        "slug": (request.form.get("slug") or "").strip(),
        "description": (request.form.get("description") or "").strip(),
        "price": request.form.get("price") or "0",
        "compare_at_price": request.form.get("compare_at_price") or "",
        "currency": (request.form.get("currency") or "UYU").strip(),
        "category_slug": (request.form.get("category_slug") or "").strip(),
        "image_url": (request.form.get("image_url") or "").strip(),
        "stock": request.form.get("stock") or "0",
        "status": (request.form.get("status") or "active").strip(),
        "source": (request.form.get("source") or "skyline").strip(),
        "external_id": (request.form.get("external_id") or "").strip(),
        "tags": (request.form.get("tags") or "").strip(),
    }
    ok, msg = ps.update_product(product_id, payload)
    flash(msg, "ok" if ok else "err")
    return redirect(url_for("admin.products"))


@admin_bp.post("/products/delete/<int:product_id>")
@admin_required
def products_delete(product_id: int):
    ps = ProductService()
    ok, msg = ps.delete_product(product_id)
    flash(msg, "ok" if ok else "err")
    return redirect(url_for("admin.products"))


# -------------------- OFFERS --------------------

@admin_bp.get("/offers")
@admin_required
def offers():
    ps = ProductService()
    offers = ps.list_offers()
    products = ps.list_products(limit=500)
    return render_template("admin/offers.html", offers=offers, products=products)


@admin_bp.post("/offers/create")
@admin_required
def offers_create():
    ps = ProductService()

    payload = {
        "title": (request.form.get("title") or "").strip(),
        "badge": (request.form.get("badge") or "Oferta").strip(),
        "product_id": request.form.get("product_id") or "",
        "starts_at": (request.form.get("starts_at") or "").strip(),
        "ends_at": (request.form.get("ends_at") or "").strip(),
        "discount_type": (request.form.get("discount_type") or "percent").strip(),  # percent / fixed
        "discount_value": request.form.get("discount_value") or "0",
        "active": True if (request.form.get("active") == "on") else False,
    }

    ok, msg = ps.create_offer(payload)
    flash(msg, "ok" if ok else "err")
    return redirect(url_for("admin.offers"))


@admin_bp.post("/offers/toggle/<int:offer_id>")
@admin_required
def offers_toggle(offer_id: int):
    ps = ProductService()
    ok, msg = ps.toggle_offer(offer_id)
    flash(msg, "ok" if ok else "err")
    return redirect(url_for("admin.offers"))


@admin_bp.post("/offers/delete/<int:offer_id>")
@admin_required
def offers_delete(offer_id: int):
    ps = ProductService()
    ok, msg = ps.delete_offer(offer_id)
    flash(msg, "ok" if ok else "err")
    return redirect(url_for("admin.offers"))


# -------------------- SYNC (PRINTFUL / DROPSHIPPING) --------------------

@admin_bp.post("/sync/printful")
@admin_required
def sync_printful():
    pf = PrintfulService()
    ps = ProductService()

    ok, items_or_err = pf.fetch_store_products()
    if not ok:
        flash(f"No pude sincronizar Printful: {items_or_err}", "err")
        return redirect(url_for("admin.products"))

    synced = 0
    for it in items_or_err:
        ok2, _ = ps.upsert_external_product(it, source="printful")
        if ok2:
            synced += 1

    flash(f"Printful sincronizado ✅ ({synced} productos actualizados)", "ok")
    return redirect(url_for("admin.products", source="printful"))


@admin_bp.post("/sync/dropshipping")
@admin_required
def sync_dropshipping():
    ds = DropshippingService()
    ps = ProductService()

    ok, items_or_err = ds.fetch_feed_products()
    if not ok:
        flash(f"No pude sincronizar Dropshipping: {items_or_err}", "err")
        return redirect(url_for("admin.products"))

    synced = 0
    for it in items_or_err:
        ok2, _ = ps.upsert_external_product(it, source="dropshipping")
        if ok2:
            synced += 1

    flash(f"Dropshipping sincronizado ✅ ({synced} productos actualizados)", "ok")
    return redirect(url_for("admin.products", source="dropshipping"))
