{% extends "base.html" %}
{% block title %}Verificar correo · {{ (APP_NAME or "Skyline Store")|e }}{% endblock %}

{% block extra_head %}
<meta name="robots" content="{{ 'index,follow' if (ENV|default('')|lower == 'production') else 'noindex,nofollow' }}">
{% set _nonce = (csp_nonce if csp_nonce is defined and csp_nonce else (nonce if nonce is defined and nonce else '')) %}

{% set _vf = (view_functions if view_functions is defined and view_functions else {}) %}
{% macro safe_url(ep, fb='') -%}
  {%- if ep and ep in _vf -%}{{ url_for(ep) }}{%- else -%}{{ fb }}{%- endif -%}
{%- endmacro %}

{% set _csrf = '' %}
{% if csrf_token is defined and csrf_token %}
  {% set _csrf = csrf_token() %}
{% elif csrf_token_value is defined and csrf_token_value %}
  {% set _csrf = csrf_token_value %}
{% endif %}
<meta name="csrf-token" content="{{ (_csrf|string)|e }}">

<style{% if _nonce %} nonce="{{ _nonce|e }}"{% endif %}>
.ss-ve{min-height:70vh;display:grid;place-items:center;padding:32px 14px;background:transparent}
.ss-ve__card{max-width:560px;width:100%;border-radius:26px;border:1px solid rgba(148,163,184,.22);background:rgba(255,255,255,.92);box-shadow:0 22px 60px rgba(2,6,23,.12);overflow:hidden}
.ss-ve__head{padding:20px;border-bottom:1px solid rgba(148,163,184,.16)}
.ss-ve__body{padding:20px}
.ss-ve__title{margin:0;font-size:clamp(1.4rem,3vw,1.9rem);font-weight:950;letter-spacing:-.3px}
.ss-ve__sub{margin:.4rem 0 0;color:rgba(11,18,32,.72);font-weight:750;line-height:1.5}
.ss-ve__flash{margin-top:12px;padding:10px 12px;border-radius:14px;font-weight:850;border:1px solid rgba(148,163,184,.18)}
.ss-ve__flash.error{background:rgba(239,68,68,.08);border-color:rgba(239,68,68,.20)}
.ss-ve__flash.success{background:rgba(34,197,94,.10);border-color:rgba(34,197,94,.22)}
.ss-ve__flash.info{background:rgba(47,123,255,.08);border-color:rgba(47,123,255,.18)}
.ss-ve__note{margin-top:14px;padding:12px;border-radius:16px;border:1px dashed rgba(148,163,184,.32);font-size:.86rem;color:rgba(11,18,32,.78);font-weight:750;line-height:1.45}
.ss-ve__actions{display:grid;gap:10px;margin-top:16px}
.ss-ve__btn{display:inline-flex;align-items:center;justify-content:center;gap:10px;padding:12px 14px;border-radius:999px;border:1px solid rgba(15,23,42,.14);background:rgba(255,255,255,.9);font-weight:900;cursor:pointer;text-decoration:none;color:rgba(11,18,32,.92)}
.ss-ve__btn--primary{background:linear-gradient(135deg,#2563eb,#0ea5e9);border-color:transparent;color:#fff;box-shadow:0 18px 44px rgba(37,99,235,.22)}
.ss-ve__btn:hover{filter:brightness(1.01);transform:translateY(-1px)}
.ss-ve__btn:active{transform:translateY(0)}
.ss-ve__btn[disabled],.ss-ve__btn[aria-disabled="true"]{opacity:.65;cursor:not-allowed;transform:none}
.ss-ve__live{display:none;margin-top:12px;font-size:.86rem;font-weight:850;color:rgba(11,18,32,.76)}
.ss-ve__live.is-on{display:block}
.ss-ve__spin{width:16px;height:16px;border-radius:999px;border:2px solid rgba(255,255,255,.35);border-top-color:rgba(255,255,255,.95);animation:spin .85s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
@media(prefers-reduced-motion:reduce){.ss-ve__btn{transform:none!important}.ss-ve__spin{animation:none}}
@media (prefers-color-scheme: dark){
  .ss-ve__card{background:rgba(15,23,42,.72);border-color:rgba(148,163,184,.22);box-shadow:0 30px 74px rgba(0,0,0,.55)}
  .ss-ve__sub,.ss-ve__note,.ss-ve__live{color:rgba(226,232,240,.78)}
  .ss-ve__title{color:rgba(226,232,240,.96)}
  .ss-ve__btn{background:rgba(15,23,42,.62);border-color:rgba(148,163,184,.22);color:rgba(226,232,240,.92)}
}
</style>
{% endblock %}

{% block content %}
{% set email = (user.email if user is defined and user and user.email is defined else '')|string|trim %}
{% set home_url = safe_url('main.home','/') %}
{% set shop_url = safe_url('shop.shop','/shop') %}
{% set resend_json = safe_url('auth.resend_verification_json','') %}
{% set resend_post = safe_url('auth.resend_verification','') %}
{% set resend_ep = resend_json if resend_json else resend_post %}
{% set resend_is_json = true if resend_json else false %}

<section class="ss-ve" aria-label="Verificación de correo">
  <div class="ss-ve__card">
    <div class="ss-ve__head">
      <h1 class="ss-ve__title">Verificá tu correo</h1>
      <p class="ss-ve__sub">
        {% if email %}Enviamos un enlace a <b>{{ email|e }}</b>.{% else %}Enviamos un enlace a tu correo.{% endif %}
        Confirmalo para activar tu cuenta.
      </p>
    </div>

    <div class="ss-ve__body">
      {% with msgs = get_flashed_messages(with_categories=true) %}
        {% if msgs %}
          {% for c,m in msgs %}
            {% set k = (c|string|lower|trim) %}
            {% if k not in ['error','success','info'] %}{% set k = 'info' %}{% endif %}
            <div class="ss-ve__flash {{ k }}" role="status" aria-live="polite">{{ m }}</div>
          {% endfor %}
        {% endif %}
      {% endwith %}

      <div class="ss-ve__note" role="note">
        Revisá Spam o Promociones. El enlace puede tardar unos minutos. Si pedís reenvío, esperá 30s.
      </div>

      <div id="veLive" class="ss-ve__live" role="status" aria-live="polite"></div>

      <form id="resendForm" method="post" action="{{ resend_ep }}">
        <input type="hidden" name="csrf_token" value="{{ (_csrf|string)|e }}">
        {% if email %}<input type="hidden" name="email" value="{{ email|e }}">{% endif %}
      </form>

      <div class="ss-ve__actions" aria-label="Acciones">
        <button id="btnResend" class="ss-ve__btn ss-ve__btn--primary" type="button"
                {% if not resend_ep %}disabled aria-disabled="true"{% endif %}>
          <span id="veSpin" class="ss-ve__spin" style="display:none" aria-hidden="true"></span>
          <span id="btnTxt">{% if resend_ep %}Reenviar correo{% else %}Reenvío no disponible{% endif %}</span>
        </button>

        <a class="ss-ve__btn" href="{{ home_url|e }}">Volver al inicio</a>
        <a class="ss-ve__btn" href="{{ shop_url|e }}">Ir a la tienda</a>
      </div>

      <p class="ss-ve__note" style="margin-top:12px">
        ¿Ya verificaste? Cerrá sesión y volvé a entrar.
      </p>
    </div>
  </div>
</section>
{% endblock %}

{% block extra_js %}
<script{% if _nonce %} nonce="{{ _nonce|e }}"{% endif %}>
(() => {
  const btn = document.getElementById('btnResend');
  const txt = document.getElementById('btnTxt');
  const spin = document.getElementById('veSpin');
  const live = document.getElementById('veLive');
  const form = document.getElementById('resendForm');

  const endpoint = {{ (resend_ep or '')|tojson }};
  const isJson = {{ resend_is_json|tojson }};
  const COOLDOWN = 30000;
  const KEY = "ss_verify_cd_v1";

  const say = (m) => {
    if(!live) return;
    live.textContent = m || '';
    live.classList.toggle('is-on', !!m);
  };

  const now = () => Date.now();
  const getCd = () => {
    try { return parseInt(localStorage.getItem(KEY) || "0", 10) || 0; }
    catch(e){ return 0; }
  };
  const setCd = (t) => {
    try { localStorage.setItem(KEY, String(t)); } catch(e) {}
  };

  const setDisabled = (v) => {
    if(!btn) return;
    btn.disabled = !!v;
    btn.setAttribute('aria-disabled', v ? 'true' : 'false');
  };

  const updateBtn = () => {
    const left = Math.ceil((getCd() - now()) / 1000);
    if(left > 0){
      setDisabled(true);
      if(txt) txt.textContent = `Reenviar en ${left}s`;
    }else{
      setDisabled(!endpoint);
      if(txt) txt.textContent = endpoint ? "Reenviar correo" : "Reenvío no disponible";
    }
  };

  const startLoading = () => { if(spin) spin.style.display = 'inline-block'; };
  const stopLoading  = () => { if(spin) spin.style.display = 'none'; };

  const send = async () => {
    if(!endpoint) return;
    if(btn && btn.disabled) return;

    setCd(now() + COOLDOWN);
    updateBtn();
    startLoading();
    say("Enviando correo…");

    if(!isJson){
      try{ form && form.submit(); }catch(e){}
      stopLoading();
      return;
    }

    try{
      const csrf = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
      const r = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/json",
          "X-CSRF-Token": csrf
        },
        credentials: "same-origin",
        body: JSON.stringify({})
      });

      let j = null;
      try{ j = await r.json(); }catch(e){ j = null; }

      const ok = r.ok && (!j || j.ok !== false);
      if(!ok){
        const msg = (j && (j.message || j.error)) ? String(j.message || j.error) : "No se pudo reenviar.";
        throw new Error(msg);
      }

      say("Correo reenviado. Revisá tu email.");
    }catch(e){
      say("No se pudo reenviar automáticamente. Probá nuevamente en unos minutos.");
    }finally{
      stopLoading();
      updateBtn();
    }
  };

  if(btn){
    btn.addEventListener('click', send, {passive:true});
  }

  let t = 0;
  const tick = () => { updateBtn(); t = window.setTimeout(tick, 500); };
  tick();
})();
</script>
{% endblock %}
