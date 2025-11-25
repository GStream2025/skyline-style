from flask import Blueprint, render_template

# Blueprint principal de la web
main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    return render_template('index.html')

@main_bp.route('/shop')
def shop():
    return render_template('shop.html')

@main_bp.route('/cart')
def cart():
    return render_template('cart.html')

@main_bp.route('/product/<int:product_id>')
def product_detail(product_id):
    return render_template('product_detail.html', product_id=product_id)
