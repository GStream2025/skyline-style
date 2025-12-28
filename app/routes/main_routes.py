from __future__ import annotations

from flask import Blueprint, render_template

main_bp = Blueprint("main", __name__)

# Home (landing)
@main_bp.get("/")
def home():
    # Listita “featured” para la home (usa assets locales para que NUNCA explote)
    featured = [
        {"img": "hero-hoodie.png", "title": "Hoodies Premium", "tag": "Streetwear", "tag_cls": "tag--cyan", "price": "$ 1.990", "desc": "Calidad pro + envío rápido.", "href": "/shop"},
        {"img": "hero-sneakers.png", "title": "Zapatillas", "tag": "Dropshipping", "tag_cls": "tag--amber", "price": "$ 2.590", "desc": "Tendencia + stock limitado.", "href": "/shop"},
        {"img": "hero-headphones.png", "title": "Audio", "tag": "Tech", "tag_cls": "tag--violet", "price": "$ 1.290", "desc": "Sonido potente, look premium.", "href": "/shop"},
        {"img": "hero-watch.png", "title": "Smartwatch", "tag": "Gadgets", "tag_cls": "tag--green", "price": "$ 1.490", "desc": "Para tu día a día.", "href": "/shop"},
    ]
    return render_template("index.html", featured=featured)

@main_bp.get("/about")
def about():
    return render_template("about.html")

@main_bp.get("/contact")
def contact():
    return render_template("contact.html")
