def test_templates_render(app):
    """
    Verifica que los templates principales:
    - Compilan
    - Renderizan sin errores
    - Soportan contexto real (request, csrf, current_user)
    """

    with app.test_request_context("/"):
        # base.html debe renderizar sin variables extra
        base = app.jinja_env.get_template("base.html").render()
        assert isinstance(base, str)
        assert "<html" in base.lower()

        # auth/account.html extiende base y usa contextos reales
        account = app.jinja_env.get_template("auth/account.html").render(
            active_tab="login",
            next="/",
            prefill_email="test@example.com",
        )

        assert isinstance(account, str)
        assert "mi cuenta" in account.lower() or "login" in account.lower()
