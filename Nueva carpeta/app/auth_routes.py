from flask import Blueprint, render_template, request, redirect, url_for, flash

# Blueprint de autenticación (login, register, logout)
auth_bp = Blueprint(
    'auth',
    __name__,
    url_prefix='/auth'   # Todas las rutas quedarán /auth/login, /auth/register, etc.
)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Si es POST significa que enviaron el formulario
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Validaciones simples
        if not email or not password:
            flash("Todos los campos son obligatorios.", "error")
            return redirect(url_for('auth.login'))

        # En el futuro: validar usuario en la BD
        flash("Inicio de sesión exitoso (placeholder).", "success")
        return redirect(url_for('main.index'))

    # Si es GET solo mostramos el formulario
    return render_template('auth/login.html')


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash("Completa todos los campos.", "error")
            return redirect(url_for('auth.register'))

        # FUTURO: guardar usuario en la BD
        flash("Cuenta creada (placeholder).", "success")
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html')
