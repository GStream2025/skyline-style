(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);

  const form = $("loginForm");
  if (!form) return;

  const email = $("email");
  const pw = $("password");
  const submitBtn = $("submitBtn");
  const togglePw = $("togglePw");
  const eyeOn = $("eyeOn");
  const eyeOff = $("eyeOff");

  const normalizeEmail = (v) => String(v ?? "").trim().toLowerCase().slice(0, 254);
  const validEmail = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizeEmail(v));

  let busyTimer = 0;

  const setBusy = (busy) => {
    if (!submitBtn) return;
    if (!submitBtn.dataset._txt) {
      submitBtn.dataset._txt = submitBtn.textContent || "Iniciar sesión";
    }
    submitBtn.disabled = !!busy;
    submitBtn.textContent = busy ? "Ingresando…" : submitBtn.dataset._txt;
  };

  const clearBusyTimer = () => {
    if (busyTimer) {
      clearTimeout(busyTimer);
      busyTimer = 0;
    }
  };

  // Toggle password (solo si existen los elementos)
  if (togglePw && pw) {
    togglePw.addEventListener("click", () => {
      const isPw = pw.type === "password";
      pw.type = isPw ? "text" : "password";

      if (eyeOn) eyeOn.style.display = isPw ? "none" : "";
      if (eyeOff) eyeOff.style.display = isPw ? "" : "none";

      try {
        pw.focus({ preventScroll: true });
      } catch {
        pw.focus();
      }
    });
  }

  // Submit guard (no rompe si faltan inputs)
  form.addEventListener("submit", (ev) => {
    // Si no hay campos, no bloqueamos: dejamos que el backend responda.
    if (!email || !pw) return;

    const e = normalizeEmail(email.value);
    email.value = e;

    if (!validEmail(e)) {
      ev.preventDefault();
      email.focus();
      return;
    }

    if (!pw.value || pw.value.length < 8) {
      ev.preventDefault();
      pw.focus();
      return;
    }

    setBusy(true);
    clearBusyTimer();
    busyTimer = setTimeout(() => setBusy(false), 12000);
  });

  // Remember last email (seguro)
  try {
    if (email && !email.value) {
      const last = localStorage.getItem("last_email") || "";
      if (validEmail(last)) email.value = last;
    }

    if (email) {
      email.addEventListener("input", () => {
        const v = normalizeEmail(email.value);
        if (validEmail(v)) localStorage.setItem("last_email", v);
      });
    }
  } catch {}

  // Cuando volvés atrás o recarga bfcache
  window.addEventListener("pageshow", () => {
    clearBusyTimer();
    setBusy(false);
  });

  // Si cambia la visibilidad (ej: navegación), soltamos “busy”
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") {
      clearBusyTimer();
      setBusy(false);
    }
  });
})();
