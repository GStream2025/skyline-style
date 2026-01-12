/* static/js/login.js — Skyline Store (ULTRA PRO / NO BREAK · v45)
   Objetivo: UX excelente SIN romper CSRF.
   - NO usamos fetch para login (evita token mismatch)
   - Anti doble submit + loading + a11y
   - Validación liviana + hints
   - Toggle pass accesible
   - Guardado email (opt-in suave) via localStorage
*/

(() => {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);

  const form = $("#loginForm");
  if (!form) return;

  const email = $("#email", form);
  const pass = $("#password", form);
  const submit = $("#submitBtn", form);
  const toggle = $("#togglePass", form);
  const emailHint = $("#emailHint", form);
  const passHint = $("#passHint", form);

  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const csrfToken = (csrfMeta && typeof csrfMeta.content === "string") ? csrfMeta.content : "";

  // ---- Helpers
  const isSmall = () => window.matchMedia && window.matchMedia("(max-width: 560px)").matches;

  const setHint = (el, text, kind) => {
    if (!el) return;
    el.textContent = text;
    el.classList.remove("bad", "ok");
    if (kind === "bad") el.classList.add("bad");
    if (kind === "ok") el.classList.add("ok");
  };

  const setInvalid = (input, yes) => {
    if (!input) return;
    input.setAttribute("aria-invalid", yes ? "true" : "false");
  };

  const trim = (v) => (v || "").toString().trim();

  const validEmail = (v) => {
    const s = trim(v).toLowerCase();
    if (s.length < 6 || s.length > 254) return false;
    // regex simple, suficiente UX
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
  };

  const validPass = (v) => {
    const s = (v || "").toString();
    return s.length >= 8 && s.length <= 256;
  };

  const withSpinner = (btn, on) => {
    if (!btn) return;
    const busy = on ? "true" : "false";
    btn.setAttribute("aria-busy", busy);
    btn.disabled = !!on;

    if (on) {
      const original = btn.dataset.label || btn.textContent || "Entrar";
      btn.dataset.label = original;
      btn.innerHTML = `<span class="ss-login__spinner" aria-hidden="true"></span> <span>Ingresando…</span>`;
    } else {
      btn.textContent = btn.dataset.label || "Entrar";
    }
  };

  // ---- CSRF hidden guard: si falta input csrf_token, lo agregamos
  (() => {
    const existing = form.querySelector('input[name="csrf_token"]');
    if (existing) {
      if (!existing.value && csrfToken) existing.value = csrfToken;
      return;
    }
    const i = document.createElement("input");
    i.type = "hidden";
    i.name = "csrf_token";
    i.value = csrfToken || "";
    form.appendChild(i);
  })();

  // ---- Restore saved email (si existe)
  const LS_KEY = "ss_login_email";
  try {
    const saved = localStorage.getItem(LS_KEY);
    if (email && !email.value && saved) email.value = saved;
  } catch (_) {}

  // ---- Focus inteligente
  (() => {
    if (!email) return;
    if (isSmall()) return;
    // si hay flash error, enfocá email
    try { email.focus({ preventScroll: true }); } catch (_) { try { email.focus(); } catch (__) {} }
  })();

  // ---- Toggle password (a11y + teclado)
  if (toggle && pass) {
    const setState = (show) => {
      pass.type = show ? "text" : "password";
      toggle.setAttribute("aria-pressed", show ? "true" : "false");
      toggle.setAttribute("aria-label", show ? "Ocultar contraseña" : "Mostrar contraseña");
      toggle.textContent = show ? "🙈" : "👁";
    };

    let showing = false;
    setState(showing);

    toggle.addEventListener("click", () => {
      showing = !showing;
      setState(showing);
      try { pass.focus({ preventScroll: true }); } catch (_) { try { pass.focus(); } catch (__) {} }
    });

    toggle.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        toggle.click();
      }
    });
  }

  // ---- Live validation (suave)
  if (email) {
    email.addEventListener("input", () => {
      const v = email.value;
      if (!v) {
        setInvalid(email, false);
        setHint(emailHint, "Requerido", "");
        return;
      }
      if (validEmail(v)) {
        setInvalid(email, false);
        setHint(emailHint, "Ok", "ok");
      } else {
        setInvalid(email, true);
        setHint(emailHint, "Email inválido", "bad");
      }
    }, { passive: true });

    email.addEventListener("blur", () => {
      const v = trim(email.value);
      if (v && validEmail(v)) {
        try { localStorage.setItem(LS_KEY, v.toLowerCase()); } catch (_) {}
      }
    }, { passive: true });
  }

  if (pass) {
    pass.addEventListener("input", () => {
      const v = pass.value;
      if (!v) {
        setInvalid(pass, false);
        setHint(passHint, "Requerido", "");
        return;
      }
      if (validPass(v)) {
        setInvalid(pass, false);
        setHint(passHint, "Ok", "ok");
      } else {
        setInvalid(pass, true);
        setHint(passHint, "Mínimo 8 caracteres", "bad");
      }
    }, { passive: true });
  }

  // ---- Anti doble submit + submit seguro (sin fetch)
  let inflight = false;

  form.addEventListener("submit", (e) => {
    if (inflight) {
      e.preventDefault();
      return;
    }

    // Honeypot anti-bot
    const honey = form.querySelector('input[name="website"]');
    if (honey && honey.value) {
      e.preventDefault();
      return;
    }

    // Validación UX (NO reemplaza backend)
    const ev = email ? email.value : "";
    const pv = pass ? pass.value : "";

    let ok = true;

    if (email) {
      if (!validEmail(ev)) {
        ok = false;
        setInvalid(email, true);
        setHint(emailHint, ev ? "Email inválido" : "Requerido", "bad");
        try { email.focus({ preventScroll: true }); } catch (_) { try { email.focus(); } catch (__) {} }
      }
    }

    if (ok && pass) {
      if (!validPass(pv)) {
        ok = false;
        setInvalid(pass, true);
        setHint(passHint, pv ? "Mínimo 8 caracteres" : "Requerido", "bad");
        try { pass.focus({ preventScroll: true }); } catch (_) { try { pass.focus(); } catch (__) {} }
      }
    }

    // CSRF presence (si está vacío, mejor recargar antes de mandar)
    const csrfInput = form.querySelector('input[name="csrf_token"]');
    const csrfVal = csrfInput ? (csrfInput.value || "") : "";
    if (ok && !csrfVal) {
      ok = false;
      // evita mandar request que seguro falla
      e.preventDefault();
      try { window.location.reload(); } catch (_) {}
      return;
    }

    if (!ok) {
      e.preventDefault();
      return;
    }

    inflight = true;
    withSpinner(submit, true);

    // Si tarda mucho, dejamos al usuario cancelar con refresh sin romper
    window.setTimeout(() => {
      if (inflight) {
        // re-habilitá el botón por si el navegador canceló navegación
        inflight = false;
        withSpinner(submit, false);
      }
    }, 12000);
    // dejamos que el POST normal continúe
  });

  // ---- Enter key polish: si estás en email y apretás Enter, pasa a pass
  if (email && pass) {
    email.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        // si email válido, mover a password, si no, no
        if (validEmail(email.value)) {
          e.preventDefault();
          try { pass.focus({ preventScroll: true }); } catch (_) { try { pass.focus(); } catch (__) {} }
        }
      }
    });
  }

  // ---- Seguridad UX: deshabilita pegado de espacios raros (solo trim al blur)
  if (email) {
    email.addEventListener("blur", () => {
      const v = trim(email.value);
      if (v !== email.value) email.value = v;
    }, { passive: true });
  }
})();
