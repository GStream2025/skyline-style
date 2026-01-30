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
  const formError = $("#formError", form); // opcional en template
  const nextInput = form.querySelector('input[name="next"]');

  // CSRF desde meta (si existe)
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const csrfToken = (csrfMeta && typeof csrfMeta.content === "string") ? csrfMeta.content.trim() : "";

  // --- Helpers
  const trim = (v) => (v == null ? "" : String(v)).trim();
  const normEmail = (v) => trim(v).toLowerCase();

  const isSmall = () => {
    try {
      return !!(window.matchMedia && window.matchMedia("(max-width: 560px)").matches);
    } catch (_) {
      return false;
    }
  };

  const safeText = (v, max = 240) => {
    const s = trim(v).replace(/\u0000/g, "").replace(/\s+/g, " ");
    return s.length > max ? s.slice(0, max) : s;
  };

  const setHint = (el, text, kind) => {
    if (!el) return;
    el.textContent = safeText(text, 120);
    el.classList.remove("bad", "ok");
    if (kind === "bad") el.classList.add("bad");
    if (kind === "ok") el.classList.add("ok");
  };

  const setInvalid = (input, yes) => {
    if (!input) return;
    input.setAttribute("aria-invalid", yes ? "true" : "false");
  };

  const setFormError = (msg) => {
    if (!formError) return;
    const text = safeText(msg, 240);
    formError.textContent = text;
    formError.hidden = !text;
    if (text) {
      formError.setAttribute("role", "alert");
      formError.setAttribute("aria-live", "polite");
    }
  };

  const clearFormError = () => setFormError("");

  const validEmail = (v) => {
    const s = normEmail(v);
    if (s.length < 6 || s.length > 254) return false;
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
  };

  const validPass = (v) => {
    const s = String(v || "");
    return s.length >= 8 && s.length <= 256;
  };

  const withSpinner = (btn, on) => {
    if (!btn) return;
    btn.disabled = !!on;
    btn.setAttribute("aria-busy", on ? "true" : "false");

    if (on) {
      const original = btn.dataset.label || btn.textContent || "Entrar";
      btn.dataset.label = original;
      btn.innerHTML = `<span class="ss-login__spinner" aria-hidden="true"></span> <span>Ingresando…</span>`;
    } else {
      btn.textContent = btn.dataset.label || "Entrar";
    }
  };

  const focusSafe = (el) => {
    if (!el) return;
    try { el.focus({ preventScroll: true }); }
    catch (_) { try { el.focus(); } catch (__) {} }
  };

  // --- CSRF hidden guard (si falta input csrf_token, lo agregamos)
  (() => {
    const existing = form.querySelector('input[name="csrf_token"]');
    if (existing) {
      if (!trim(existing.value) && csrfToken) existing.value = csrfToken;
      return;
    }
    const i = document.createElement("input");
    i.type = "hidden";
    i.name = "csrf_token";
    i.value = csrfToken || "";
    form.appendChild(i);
  })();

  // --- Harden NEXT (evitar “next” raro que genera loops o cosas externas)
  const cleanNext = (raw) => {
    const s = trim(raw);
    if (!s) return "";
    if (!s.startsWith("/") || s.startsWith("//")) return "";
    if (/[\\\u0000\r\n\t ]/.test(s)) return "";
    if (s.includes("..")) return "";
    // OJO: no te dejes mandar al propio auth/admin porque puede generar loops
    if (s.startsWith("/auth/") || s.startsWith("/admin/")) return "";
    return s.split("?", 1)[0].split("#", 1)[0].slice(0, 512);
  };

  if (nextInput) {
    const fixed = cleanNext(nextInput.value);
    if (fixed !== nextInput.value) nextInput.value = fixed;
  }

  // --- Restore saved email
  const LS_KEY = "ss_login_email";
  try {
    const saved = localStorage.getItem(LS_KEY);
    if (email && !email.value && saved) email.value = saved;
  } catch (_) {}

  // --- bfcache: si el navegador vuelve atrás, re-habilitar botón
  window.addEventListener("pageshow", (e) => {
    if (e && e.persisted) {
      inflight = false;
      withSpinner(submit, false);
    }
  });

  // --- Focus inteligente (si no es mobile)
  (() => {
    if (!email) return;
    if (isSmall()) return;
    focusSafe(email);
  })();

  // --- Toggle password a11y
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
      focusSafe(pass);
    });

    toggle.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        toggle.click();
      }
    });
  }

  // --- Live validation
  if (email) {
    email.addEventListener("input", () => {
      clearFormError();
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
      const v = normEmail(email.value);
      if (v && validEmail(v)) {
        try { localStorage.setItem(LS_KEY, v); } catch (_) {}
      }
      if (v !== email.value) email.value = v;
    }, { passive: true });
  }

  if (pass) {
    pass.addEventListener("input", () => {
      clearFormError();
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

  // --- Enter behavior: si email válido, pasa a pass
  if (email && pass) {
    email.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && validEmail(email.value)) {
        e.preventDefault();
        focusSafe(pass);
      }
    });
  }

  // --- Anti double submit + submit seguro (SIN fetch)
  let inflight = false;

  const ensureCsrfPresent = () => {
    const csrfInput = form.querySelector('input[name="csrf_token"]');
    const v = csrfInput ? trim(csrfInput.value) : "";
    if (v) return true;
    // si el meta está, intentar setearlo
    if (csrfInput && csrfToken) {
      csrfInput.value = csrfToken;
      return true;
    }
    return false;
  };

  form.addEventListener("submit", (e) => {
    if (inflight) {
      e.preventDefault();
      return;
    }

    clearFormError();

    // Honeypot anti-bot
    const honey = form.querySelector('input[name="website"]');
    if (honey && trim(honey.value)) {
      e.preventDefault();
      return;
    }

    // Validación UX
    const ev = email ? email.value : "";
    const pv = pass ? pass.value : "";

    let ok = true;

    if (email && !validEmail(ev)) {
      ok = false;
      setInvalid(email, true);
      setHint(emailHint, ev ? "Email inválido" : "Requerido", "bad");
      focusSafe(email);
    }

    if (ok && pass && !validPass(pv)) {
      ok = false;
      setInvalid(pass, true);
      setHint(passHint, pv ? "Mínimo 8 caracteres" : "Requerido", "bad");
      focusSafe(pass);
    }

    // CSRF guard: si falta, no mandes (te evita 400/loop raro)
    if (ok && !ensureCsrfPresent()) {
      ok = false;
      e.preventDefault();
      setFormError("Sesión vencida. Recargá la página e intentá de nuevo.");
      try { window.location.reload(); } catch (_) {}
      return;
    }

    if (!ok) {
      e.preventDefault();
      return;
    }

    inflight = true;
    withSpinner(submit, true);

    // fallback: si el navegador canceló navegación, re-habilitar
    window.setTimeout(() => {
      if (inflight) {
        inflight = false;
        withSpinner(submit, false);
      }
    }, 12000);
    // POST normal continúa
  });
})();
