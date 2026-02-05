(function () {
  const $ = (id) => document.getElementById(id);

  const form = $("loginForm");
  const email = $("email");
  const pw = $("password");
  const submitBtn = $("submitBtn");
  const togglePw = $("togglePw");
  const eyeOn = $("eyeOn");
  const eyeOff = $("eyeOff");

  if (!form) return;

  const normalizeEmail = (v) =>
    String(v || "").trim().toLowerCase().slice(0, 254);

  const validEmail = (v) =>
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizeEmail(v));

  const setBusy = (busy) => {
    if (!submitBtn) return;
    submitBtn.disabled = !!busy;
    submitBtn.textContent = busy
      ? "Ingresando…"
      : submitBtn.dataset._txt || "Iniciar sesión";
  };

  if (submitBtn) {
    submitBtn.dataset._txt = submitBtn.textContent || "Iniciar sesión";
  }

  togglePw?.addEventListener("click", () => {
    const isPw = pw.type === "password";
    pw.type = isPw ? "text" : "password";
    if (eyeOn) eyeOn.style.display = isPw ? "none" : "";
    if (eyeOff) eyeOff.style.display = isPw ? "" : "none";
    pw.focus({ preventScroll: true });
  });

  form.addEventListener("submit", (ev) => {
    const e = normalizeEmail(email?.value);
    if (email) email.value = e;

    if (!validEmail(e)) {
      ev.preventDefault();
      email?.focus();
      return;
    }

    if (!pw?.value || pw.value.length < 8) {
      ev.preventDefault();
      pw?.focus();
      return;
    }

    setBusy(true);
    setTimeout(() => setBusy(false), 9000);
  });

  try {
    if (email && !email.value) {
      const last = localStorage.getItem("last_email") || "";
      if (validEmail(last)) email.value = last;
    }

    email?.addEventListener("input", () => {
      const v = normalizeEmail(email.value);
      if (validEmail(v)) localStorage.setItem("last_email", v);
    });
  } catch (_) {}

  window.addEventListener("pageshow", () => setBusy(false));
})();
