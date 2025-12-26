<!-- templates/admin/offers.html -->
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Ofertas · Admin</title>
  <style>
    :root{
      --bg0:#0b1220; --bg1:#070b14;
      --card: rgba(255,255,255,.06);
      --stroke: rgba(255,255,255,.12);
      --ink:#eaf0ff;
      --muted: rgba(234,240,255,.70);
      --a:#2563eb; --b:#06b6d4; --c:#f59e0b; --d:#22c55e;
      --r: 18px;
      --ease: cubic-bezier(.2,.9,.2,1);
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      min-height:100vh;
      background:
        radial-gradient(1100px 800px at 10% 10%, rgba(37,99,235,.25), transparent 60%),
        radial-gradient(900px 700px at 90% 10%, rgba(6,182,212,.20), transparent 60%),
        radial-gradient(900px 700px at 50% 90%, rgba(245,158,11,.16), transparent 60%),
        linear-gradient(180deg, var(--bg0), var(--bg1));
      color: var(--ink);
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
    }
    .topbar{
      position:sticky; top:0; z-index:10;
      backdrop-filter: blur(10px);
      background: rgba(11,18,32,.70);
      border-bottom:1px solid rgba(255,255,255,.10);
    }
    .wrap{ width:min(1200px, 92vw); margin:0 auto; padding:16px 0; display:flex; align-items:center; justify-content:space-between; gap:12px;}
    .brand{ display:flex; align-items:center; gap:10px; font-weight:1000; }
    .dot{ width:10px;height:10px;border-radius:999px;background:linear-gradient(135deg,var(--a),var(--b)); box-shadow:0 0 0 6px rgba(37,99,235,.18);}
    .nav{ display:flex; gap:10px; flex-wrap:wrap;}
    a.btn, button.btn{
      text-decoration:none;
      padding:10px 14px;
      border-radius:999px;
      border:1px solid rgba(255,255,255,.12);
      background: rgba(255,255,255,.06);
      color: var(--ink);
      font-weight:950;
      cursor:pointer;
      transition: transform .18s var(--ease), border-color .18s var(--ease);
    }
    a.btn:hover, button.btn:hover{ transform: translateY(-2px); border-color: rgba(34,211,238,.45); }
    .main{ width:min(1200px, 92vw); margin:0 auto; padding: 20px 0 44px; }
    h1{ margin:0; font-size: clamp(1.5rem, 2.6vw, 2rem); letter-spacing:-.5px;}
    .sub{ margin:8px 0 0; color: var(--muted); }

    .panel{
      margin-top:14px;
      border-radius: var(--r);
      border:1px solid rgba(255,255,255,.12);
      background: rgba(255,255,255,.06);
      padding: 14px;
    }
    label{ font-weight:900; font-size:.85rem; color: rgba(234,240,255,.85); }
    input, select{
      width:100%;
      padding: 10px 12px;
      border-radius: 14px;
      border:1px solid rgba(255,255,255,.14);
      background: rgba(15,23,42,.55);
      color: var(--ink);
      outline:none;
    }
    .formgrid{
      display:grid;
      grid-template-columns: repeat(12, 1fr);
      gap:10px;
      margin-top:10px;
    }
    .col6{ grid-column: span 6; }
    .col4{ grid-column: span 4; }
    .col3{ grid-column: span 3; }
    .col12{ grid-column: span 12; }
    @media(max-width:980px){ .col6,.col4,.col3{ grid-column: span 12; } }

    .grid{
      margin-top:14px;
      display:grid;
      grid-template-columns: repeat(12, 1fr);
      gap:12px;
    }
    .card{
      grid-column: span 4;
      border-radius: var(--r);
      border:1px solid rgba(255,255,255,.12);
      background: rgba(255,255,255,.06);
      padding: 12px;
    }
    @media(max-width:980px){ .card{ grid-column: span 6; } }
    @media(max-width:640px){ .card{ grid-column: span 12; } }

    .title{ font-weight:1050; letter-spacing:-.3px; }
    .meta{ margin-top:6px; color: var(--muted); font-size:.92rem; line-height:1.5; }
    .pill{
      display:inline-flex; gap:8px; align-items:center;
      padding:6px 10px;
      border-radius:999px;
      border:1px solid rgba(255,255,255,.12);
      background: rgba(255,255,255,.06);
      font-weight:950;
      font-size:.78rem;
      margin-top:8px;
    }
    .ok{ border-color: rgba(34,197,94,.35)!important; }
    .warn{ border-color: rgba(245,158,11,.35)!important; }
    .danger{ border-color: rgba(239,68,68,.35)!important; }
    .flash{ margin-top:10px; padding: 10px 12px; border-radius: 14px; border:1px solid rgba(255,255,255,.14); background: rgba(255,255,255,.06); }
    .flash.ok{ border-color: rgba(34,197,94,.35); }
    .flash.err{ border-color: rgba(239,68,68,.35); }
  </style>
</head>
<body>
  <div class="topbar">
    <div class="wrap">
      <div class="brand"><span class="dot"></span> Ofertas</div>
      <div class="nav">
        <a class="btn" href="{{ url_for('admin.dashboard') }}">Dashboard</a>
        <a class="btn" href="{{ url_for('admin.products') }}">Productos</a>
        <a class="btn" href="{{ url_for('admin.logout') }}">Salir</a>
      </div>
    </div>
  </div>

  <main class="main">
    <h1>Ofertas + precio tachado</h1>
    <p class="sub">Creá promos por producto (porcentaje o monto fijo), con fechas y activar/desactivar.</p>

    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for cat, msg in messages %}
          <div class="flash {{ cat }}">{{ msg }}</div>
        {% endfor %}
      {% endif %}
    {% endwith %}

    <section class="panel">
      <h2 style="margin:0;font-size:1.05rem;">➕ Crear oferta</h2>
      <form method="post" action="{{ url_for('admin.offers_create') }}">
        <div class="formgrid">
          <div class="col6">
            <label>Título</label>
            <input name="title" required placeholder="Ej: Weekend Sale">
          </div>
          <div class="col6">
            <label>Badge</label>
            <input name="badge" value="Oferta" placeholder="Oferta / HOT / -20%">
          </div>

          <div class="col6">
            <label>Producto</label>
            <select name="product_id">
              <option value="">(Aplicación general / futuro)</option>
              {% for p in products %}
                <option value="{{ p.id }}">{{ p.title }} · {{ p.currency }} {{ "%.2f"|format(p.price) }}</option>
              {% endfor %}
            </select>
          </div>

          <div class="col3">
            <label>Tipo</label>
            <select name="discount_type">
              <option value="percent">%</option>
              <option value="fixed">Monto fijo</option>
            </select>
          </div>
          <div class="col3">
            <label>Valor</label>
            <input name="discount_value" value="0" inputmode="decimal">
          </div>

          <div class="col6">
            <label>Desde (opcional)</label>
            <input type="datetime-local" name="starts_at">
          </div>
          <div class="col6">
            <label>Hasta (opcional)</label>
            <input type="datetime-local" name="ends_at">
          </div>

          <div class="col12" style="display:flex;align-items:center;gap:10px;">
            <label style="display:flex;align-items:center;gap:10px;">
              <input type="checkbox" name="active" style="width:auto;"> Activa
            </label>
            <button class="btn ok" type="submit">Crear oferta</button>
          </div>
        </div>
      </form>
    </section>

    <section class="grid">
      {% for o in offers %}
      <article class="card">
        <div class="title">{{ o.title }}</div>
        <div class="meta">
          Badge: <b>{{ o.badge }}</b><br>
          Tipo: <b>{{ o.discount_type }}</b> · Valor: <b>{{ o.discount_value }}</b><br>
          Producto: <b>{{ o.product_id or "—" }}</b><br>
          Activa: <b>{{ "Sí" if o.active else "No" }}</b>
        </div>

        <div class="pill {% if o.active %}ok{% else %}warn{% endif %}">
          {% if o.active %}✅ Activa{% else %}⏸️ Pausada{% endif %}
        </div>

        <div style="margin-top:10px; display:flex; gap:10px; flex-wrap:wrap;">
          <form method="post" action="{{ url_for('admin.offers_toggle', offer_id=o.id) }}">
            <button class="btn {% if o.active %}warn{% else %}ok{% endif %}" type="submit">
              {% if o.active %}Pausar{% else %}Activar{% endif %}
            </button>
          </form>
          <form method="post" action="{{ url_for('admin.offers_delete', offer_id=o.id) }}" onsubmit="return confirm('¿Eliminar esta oferta?');">
            <button class="btn danger" type="submit">Eliminar</button>
          </form>
        </div>
      </article>
      {% endfor %}
    </section>
  </main>
</body>
</html>
