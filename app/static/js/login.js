/* Skyline Store — Login JS (ULTRA PRO / v3 / NO BREAK)
   ✅ Anti doble submit real
   ✅ Toggle password (a11y)
   ✅ Validación UX suave (no bloquea servidor innecesariamente)
   ✅ Respeta autofill / Enter
   ✅ Lee CSRF desde meta si luego hacés fetch()
   ✅ No rompe si falta algún elemento
*/
(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);

  const form = $("loginForm");
  const btn = $("submitBtn");
  const email = $("email");
  const pass = $("password");
  const toggle = $("togglePass");

  if (!form || !btn) return;

  // Evita doble bind si el template se inyecta o se re-renderiza
  if (form.dataset.bound === "1") return;
  form.dataset.bound = "1";

  const metaCsrf = document.querySelector('meta[name="csrf-token"]');
  const csrfToken = metaCsrf ? (metaCsrf.getAttribute("content") || "") : "";

  // Helpers
  const setBusy = (busy, label) => {
    if (!btn) return;
    if (busy) {
      btn.disabled = true;
      btn.setAttribute("aria-busy", "true");
      btn.innerHTML =
        '<span class="ss-login__spinner" aria-hidden="true"></span> ' +
        (label || "Ingresando...");
    } else {
      btn.disabled = false;
      btn.removeAttribute("aria-busy");
      btn.textContent = label || "Entrar";
    }
  };

  const markInvalid = (el, bad) => {
    if (!el) return;
    el.setAttribute("aria-invalid", bad ? "true" : "false");
  };

  const isEmailish = (v) => {
    const s = (v || "").trim();
    if (s.length < 6) return false;
    // regex simple (sin volverse loco)
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
  };

  // Toggle password (a11y + no rompe)
  if (toggle && pass) {
    toggle.addEventListener("click", () => {
      const willShow = pass.type === "password";
      pass.type = willShow ? "text" : "password";
      toggle.setAttribute("aria-pressed", String(willShow));
      toggle.setAttribute("aria-label", willShow ? "Ocultar contraseña" : "Mostrar contraseña");
      // mantiene foco útil
      try { pass.focus({ preventScroll: true }); } catch (_) {}
    }, { passive: true });
  }

  // UX: limpiar error al tipear
  const bindLiveClear = (el, validator) => {
    if (!el) return;
    el.addEventListener("input", () => {
      const ok = validator ? validator(el.value) : true;
      markInvalid(el, !ok);
    }, { passive: true });

    el.addEventListener("blur", () => {
      const ok = validator ? validator(el.value) : true;
      markInvalid(el, !ok);
    }, { passive: true });
  };

  bindLiveClear(email, isEmailish);
  bindLiveClear(pass, (v) => (v || "").length >= 8);

  // Anti doble submit + validación mínima
  form.addEventListener("submit", (ev) => {
    // Honeypot
    const hp = form.querySelector('input[name="website"]');
    if (hp && (hp.value || "").trim()) {
      // bot detected -> no hacemos nada, dejamos que el server lo bloquee si querés
      ev.preventDefault();
      ev.stopPropagation();
      return;
    }

    const eVal = email ? email.value : "";
    const pVal = pass ? pass.value : "";

    const eok = email ? isEmailish(eVal) : true;
    const pok = pass ? (pVal.length >= 8) : true;

    markInvalid(email, !eok);
    markInvalid(pass, !pok);

    if (!eok || !pok) {
      ev.preventDefault();
      ev.stopPropagation();
      // feedback visual leve
      setBusy(false, "Entrar");
      return;
    }

    // Doble submit guard (la causa #1 de CSRF mismatch)
    if (btn.disabled) {
      ev.preventDefault();
      ev.stopPropagation();
      return;
    }

    setBusy(true, "Ingresando...");
  }, { passive: false });

  // Bonus: Enter en email -> foco pass (mejor UX)
  if (email && pass) {
    email.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        // si email parece ok, movemos a pass; si no, dejamos submit normal
        if (isEmailish(email.value)) {
          e.preventDefault();
          try { pass.focus({ preventScroll: true }); } catch (_) {}
        }
      }
    });
  }

  // Exponer token CSRF de forma segura por si luego hacés fetch() (opcional)
  // window.SS_CSRF = csrfToken;  // si querés usarlo global, descomentá
  // Si no, queda sólo local.
  void csrfToken;
})();
