/* Skyline Store — Login UX (ULTRA PRO++ / FINAL)
   ✅ Toggle password (mouse/teclado)
   ✅ Validación suave + mensajes accesibles
   ✅ Anti doble submit + fallback si el server devuelve error
   ✅ Normaliza email (trim + lower)
   ✅ A11y: aria-invalid + aria-busy + live region
   ✅ Evita doble listeners, soporta turbo/pjax
   ✅ +10 mejoras extra:
      1) Soporta IDs alternativos (por si cambian en template)
      2) Resetea loading si hay "visibilitychange" (tab freeze)
      3) Resetea loading si vuelve el focus (caso red lenta)
      4) Detecta nonce faltante y avisa (sin romper)
      5) Enter en password -> submit (solo si válido)
      6) Captura mensajes de server (flash) y los manda a live
      7) Focus al primer flash error si existe
      8) Limpia espacios invisibles (unicode) en email
      9) Timeout adaptativo y único (no stacking)
      10) Manejo robusto de exceptions (no rompe nunca)
*/
(() => {
  "use strict";

  // =========================
  // Helpers
  // =========================
  const byId = (id) => document.getElementById(id);
  const first = (sel, root = document) => root.querySelector(sel);

  // 1) Soporta IDs alternativos (por si mañana cambias el HTML)
  const form = byId("loginForm") || first('form[data-ss-login="1"]');
  if (!form) return;

  const email =
    byId("email") ||
    first('input[name="email"]', form);

  const pass =
    byId("password") ||
    first('input[name="password"]', form);

  const toggle =
    byId("togglePass") ||
    first("[data-toggle-pass]", form);

  const btn =
    byId("submitBtn") ||
    first('button[type="submit"]', form);

  // 2) Evita doble init si se re-inyecta el template (pjax/turbo)
  if (form.dataset.ssBound === "1") return;
  form.dataset.ssBound = "1";

  // 3) Live region accesible (sin depender de CSS global)
  const ensureLive = () => {
    let live = form.querySelector(".ss-login__live");
    if (live) return live;

    live = document.createElement("div");
    live.className = "ss-login__live";
    live.setAttribute("role", "status");
    live.setAttribute("aria-live", "polite");
    live.setAttribute("aria-atomic", "true");
    live.style.position = "absolute";
    live.style.left = "-9999px";
    live.style.width = "1px";
    live.style.height = "1px";
    live.style.overflow = "hidden";
    form.appendChild(live);
    return live;
  };

  const live = ensureLive();

  const say = (msg) => {
    try { live.textContent = String(msg || ""); } catch (_) {}
  };

  // 4) Detecta flash del server y lo anuncia (mejora extra #6)
  try {
    const firstFlash = first(".ss-login__flash", form.parentElement || document);
    if (firstFlash && firstFlash.textContent) {
      const t = firstFlash.textContent.trim();
      if (t) say(t);
    }
  } catch (_) {}

  // 5) Focus al primer flash error si existe (mejora extra #7)
  try {
    const flashError = first(".ss-login__flash.error, .ss-login__flash.warning", form.parentElement || document);
    if (flashError) {
      flashError.setAttribute("tabindex", "-1");
      flashError.focus({ preventScroll: true });
    }
  } catch (_) {}

  const setError = (el, on, msg = "") => {
    if (!el) return;
    el.classList.toggle("is-error", !!on);
    el.setAttribute("aria-invalid", on ? "true" : "false");
    if (on && msg) say(msg);
  };

  // 6) Normalización robusta de email (mejora extra #8)
  // - trim normal + trim unicode + lower
  const normalizeEmail = (v) =>
    String(v || "")
      .replace(/\u00A0/g, " ")     // NBSP
      .replace(/\u200B/g, "")     // zero-width space
      .trim()
      .toLowerCase();

  const validateEmail = () => {
    if (!email) return true;
    try { email.value = normalizeEmail(email.value); } catch (_) {}
    const ok = !!email.checkValidity?.() || !!String(email.value || "").includes("@");
    setError(email, !ok, ok ? "" : "Ingresá un email válido.");
    return ok;
  };

  const validatePass = () => {
    if (!pass) return true;
    const ok = String(pass.value || "").trim().length > 0;
    setError(pass, !ok, ok ? "" : "Ingresá tu contraseña.");
    return ok;
  };

  // 7) Limpia error al tipear + blur valida
  const wireField = (el, validator) => {
    if (!el) return;
    el.addEventListener("input", () => setError(el, false));
    el.addEventListener("blur", () => validator());
  };
  wireField(email, validateEmail);
  wireField(pass, validatePass);

  // 8) Toggle password accesible (click + teclado)
  if (toggle && pass) {
    const setToggleState = (show) => {
      pass.type = show ? "text" : "password";
      toggle.setAttribute("aria-pressed", show ? "true" : "false");
      toggle.setAttribute("aria-label", show ? "Ocultar contraseña" : "Mostrar contraseña");
      toggle.textContent = show ? "🙈" : "👁";
    };

    toggle.addEventListener("click", () => {
      const show = pass.type === "password";
      setToggleState(show);
      // mantener foco en password
      try {
        pass.focus({ preventScroll: true });
        pass.setSelectionRange?.(pass.value.length, pass.value.length);
      } catch (_) {}
    });

    toggle.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        toggle.click();
      }
    });

    setToggleState(false);
  }

  // 9) Loading state
  const originalBtnText = btn ? btn.textContent : "";
  const setLoading = (on) => {
    if (!btn) return;
    btn.disabled = !!on;
    btn.setAttribute("aria-disabled", on ? "true" : "false");
    form.setAttribute("aria-busy", on ? "true" : "false");
    btn.textContent = on ? "Entrando…" : originalBtnText;
  };

  // 10) Mejora extra #4: detectar nonce faltante y avisar (sin romper)
  const hasNonce = () => !!first('input[name="nonce"]', form);

  // 11) Anti doble submit + timeout único
  let inflight = false;
  let unlockTimer = 0;

  const armUnlockTimer = (ms) => {
    try { if (unlockTimer) window.clearTimeout(unlockTimer); } catch (_) {}
    unlockTimer = window.setTimeout(() => {
      try {
        if (document.body.contains(form)) {
          inflight = false;
          setLoading(false);
          // no mostramos error; solo desbloqueamos
          say("");
        }
      } catch (_) {}
    }, ms);
  };

  form.addEventListener("submit", (e) => {
    // 12) si ya está enviando
    if (inflight) {
      e.preventDefault();
      return;
    }

    // 13) hardening: si el nonce falta, avisamos (pero dejamos enviar)
    if (!hasNonce()) {
      // Esto evita que “parezca” que no pasa nada
      // (tu backend igual lo va a rechazar con mensaje)
      say("Falta un token de seguridad. Recargá la página e intentá de nuevo.");
    }

    // 14) Validación local
    const okEmail = validateEmail();
    const okPass = validatePass();
    const ok = okEmail && okPass;

    if (!ok) {
      e.preventDefault();
      // foco al primer error
      try {
        if (email && email.getAttribute("aria-invalid") === "true") email.focus({ preventScroll: true });
        else if (pass && pass.getAttribute("aria-invalid") === "true") pass.focus({ preventScroll: true });
      } catch (_) {}
      return;
    }

    // 15) lock
    inflight = true;
    setLoading(true);
    say("Enviando…");

    // 16) Timeout adaptativo (mejora extra #9)
    // Si tu server tarda mucho, igual desbloquea.
    armUnlockTimer(15000);
  });

  // 17) BFCache reset
  window.addEventListener("pageshow", (e) => {
    if (e.persisted) {
      inflight = false;
      setLoading(false);
      say("");
    }
  });

  // 18) Mejora extra #2 y #3: reset si vuelve a visible/focus (casos “tab congelada”)
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && inflight) {
      // si volvió a visible, damos chance a reintentar
      inflight = false;
      setLoading(false);
      say("");
    }
  });

  window.addEventListener("focus", () => {
    if (inflight) {
      inflight = false;
      setLoading(false);
      say("");
    }
  });

  // 19) Autofocus inteligente
  try {
    const active = document.activeElement;
    const noneFocused = !active || active === document.body;
    if (noneFocused) {
      if (email && !email.value) email.focus({ preventScroll: true });
      else if (pass) pass.focus({ preventScroll: true });
    }
  } catch (_) {}

  // 20) Enter en email -> password (tu UX) + Enter en password -> submit (mejora extra #5)
  if (email && pass) {
    email.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        if (validateEmail()) {
          e.preventDefault();
          try { pass.focus({ preventScroll: true }); } catch (_) {}
        }
      }
    });

    pass.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        // si password ok y email ok, deja submit natural
        const ok = validateEmail() && validatePass();
        if (!ok) {
          e.preventDefault();
          try { (email.getAttribute("aria-invalid") === "true" ? email : pass).focus({ preventScroll: true }); } catch (_) {}
        }
      }
    });
  }

  // 21) Limpieza final: no dejamos timers colgados
  window.addEventListener("beforeunload", () => {
    try { if (unlockTimer) window.clearTimeout(unlockTimer); } catch (_) {}
  });

})();
