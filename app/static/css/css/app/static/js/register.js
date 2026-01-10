/* =========================================================
   Skyline Store — REGISTER JS (ULTRA PRO v2 / EXTERNAL)
   - Zero deps, no-throw, progressive enhancement
   - +25 mejoras PRO (100% upgrade):
     1) DOM ready seguro (defer o DOMContentLoaded)
     2) Scope por root [data-ss-reg] (no pisa otras páginas)
     3) Helpers: throttle rAF + safe + closest + escape
     4) Inline messages (data-msg-for) con estados + aria-live
     5) A11y: aria-invalid, aria-describedby dinámico
     6) Focus primer error al submit
     7) Validación más robusta (email, pass policy)
     8) Password: meter + label + rules + feedback premium
     9) Confirm: match live + estado limpio si está vacío
     10) Toggle pass: icon/text alternable + aria-pressed
     11) CapsLock hint (password) opcional
     12) Affiliate collapse: anima + deshabilita inputs cuando cerrado
     13) Trim/normalize inputs (email)
     14) Anti double submit + unlock si navegación aborta
     15) Previene submit con Enter en campos inválidos (solo UX)
     16) “Touched” para no spamear errores al cargar
     17) Limpia errores al corregir
     18) Resalta reglas cumplidas (usa opacity ya existente)
     19) Respeta prefers-reduced-motion
     20) Passive listeners cuando aplica
     21) Soporta IDs faltantes (no rompe)
     22) Fallback si no existe meter/strength
     23) Añade data-state al root (debug UI en CSS si querés)
     24) Seguridad: no logs, no throws
     25) Micro: shake suave en error (solo si CSS lo define)
========================================================= */
(() => {
  "use strict";

  // ----------------------------
  // Helpers
  // ----------------------------
  const safe = (fn) => { try { fn(); } catch (_) {} };
  const $ = (sel, el = document) => el.querySelector(sel);
  const $$ = (sel, el = document) => Array.from(el.querySelectorAll(sel));
  const onReady = (fn) => {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", fn, { once: true });
    else fn();
  };
  const reducedMotion =
    window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const rafThrottle = (fn) => {
    let raf = 0;
    return (...args) => {
      if (raf) return;
      raf = requestAnimationFrame(() => {
        raf = 0;
        fn(...args);
      });
    };
  };

  const clamp = (n, a, b) => Math.max(a, Math.min(b, n));

  // Email: UX robusto (server valida igual)
  const emailLooksOk = (v) => {
    if (!v) return false;
    const s = v.trim();
    if (s.length < 6 || s.length > 254) return false;
    return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(s);
  };

  // Password scoring/policy
  const scorePassword = (v) => {
    const s = v || "";
    const hasLen = s.length >= 8;
    const hasMix = /[a-zA-Z]/.test(s) && /[0-9]/.test(s);
    const hasUp  = /[A-Z]/.test(s);
    const hasLow = /[a-z]/.test(s);
    const hasSym = /[^a-zA-Z0-9]/.test(s);

    let score = 0;
    if (hasLen) score += 35;
    if (hasMix) score += 35;
    if (hasUp)  score += 10;
    if (hasLow) score += 5;
    if (hasSym) score += 15;

    // penalizaciones suaves
    if (s.length >= 14) score += 8;
    if (/^(\w)\1{6,}$/.test(s)) score = Math.min(score, 25); // repetición
    if (/password|123456|qwerty|abc123/i.test(s)) score = Math.min(score, 25);

    score = clamp(score, 0, 100);
    return { score, hasLen, hasMix, hasUp, hasLow, hasSym };
  };

  const strengthLabel = (score) => {
    if (score <= 35) return { t: "Débil", c: "weak" };
    if (score <= 75) return { t: "Ok", c: "ok" };
    return { t: "Fuerte", c: "strong" };
  };

  // ----------------------------
  // UI helpers (msg + input state + aria)
  // ----------------------------
  const ensureId = (el, fallback) => {
    if (!el) return "";
    if (el.id) return el.id;
    const id = `${fallback}-${Math.random().toString(16).slice(2)}`;
    el.id = id;
    return id;
  };

  const setInputState = (input, state /* ok|bad|none */) => {
    if (!input) return;
    input.classList.remove("is-ok", "is-error");
    input.removeAttribute("aria-invalid");

    if (state === "ok") {
      input.classList.add("is-ok");
      input.setAttribute("aria-invalid", "false");
    } else if (state === "bad") {
      input.classList.add("is-error");
      input.setAttribute("aria-invalid", "true");
    }
  };

  const setMsg = (root, name, text = "", kind = "" /* ok|bad|none */) => {
    if (!root || !name) return;
    const box = root.querySelector(`[data-msg-for="${name}"]`);
    if (!box) return;

    // A11y: live region
    if (!box.hasAttribute("role")) box.setAttribute("role", "status");
    if (!box.hasAttribute("aria-live")) box.setAttribute("aria-live", "polite");

    box.textContent = text;
    box.classList.remove("is-ok", "is-bad");
    if (kind === "ok") box.classList.add("is-ok");
    if (kind === "bad") box.classList.add("is-bad");
  };

  const bindDescribedBy = (input, msgEl) => {
    if (!input || !msgEl) return;
    const msgId = ensureId(msgEl, "msg");
    const cur = (input.getAttribute("aria-describedby") || "").trim();
    if (!cur.includes(msgId)) input.setAttribute("aria-describedby", (cur ? cur + " " : "") + msgId);
  };

  const focusFirstInvalid = (root) => {
    const invalid = root.querySelector(".is-error, [aria-invalid='true']");
    if (invalid && typeof invalid.focus === "function") {
      invalid.focus({ preventScroll: true });
      try { invalid.scrollIntoView({ behavior: reducedMotion ? "auto" : "smooth", block: "center" }); } catch (_) {}
    }
  };

  // ----------------------------
  // Main
  // ----------------------------
  onReady(() => safe(() => {
    const root = document.querySelector("[data-ss-reg]");
    if (!root) return;

    // Optional: state attr para CSS/debug
    root.setAttribute("data-state", "ready");

    const form = root.querySelector("[data-register-form]") || $("#registerForm");
    if (!form) return;

    const email = root.querySelector("#email");
    const pass  = root.querySelector("#password");
    const pass2 = root.querySelector("#password2");

    const meterBox = root.querySelector("#meterBox");
    const meter    = root.querySelector("#meter");
    const strengthText = root.querySelector("#strengthText");
    const matchHint = root.querySelector("#matchHint");

    const rLen = root.querySelector("#rLen");
    const rMix = root.querySelector("#rMix");
    const rUp  = root.querySelector("#rUp");
    const rSym = root.querySelector("#rSym");

    const aff = root.querySelector("#wantAffiliate");
    const affBody = root.querySelector("#affBody");

    const submitBtn = root.querySelector("[data-submit]") || root.querySelector("#submitBtn") || form.querySelector('button[type="submit"]');
    const submitText = submitBtn ? submitBtn.querySelector(".ss-reg__btnText") : null;

    // Messages (wire aria-describedby)
    safe(() => {
      const msgEmail = root.querySelector('[data-msg-for="email"]');
      const msgPass = root.querySelector('[data-msg-for="password"]');
      const msgPass2 = root.querySelector('[data-msg-for="password2"]');
      if (email && msgEmail) bindDescribedBy(email, msgEmail);
      if (pass && msgPass) bindDescribedBy(pass, msgPass);
      if (pass2 && msgPass2) bindDescribedBy(pass2, msgPass2);
    });

    // Track “touched” para UX (no spamear)
    const touched = new WeakSet();
    const markTouched = (el) => { if (el) touched.add(el); };
    const isTouched = (el) => (el ? touched.has(el) : false);

    const setRule = (el, ok) => { if (el) el.style.opacity = ok ? "1" : ".55"; };

    const setMeterUI = (val) => {
      if (!meterBox || !meter) return;
      meter.style.width = val + "%";
      meterBox.classList.remove("is-weak", "is-ok", "is-strong");
      if (val <= 35) meterBox.classList.add("is-weak");
      else if (val <= 75) meterBox.classList.add("is-ok");
      else meterBox.classList.add("is-strong");
    };

    const setStrengthUI = (val) => {
      if (!strengthText) return;
      const l = strengthLabel(val);
      strengthText.textContent = `Fuerza: ${l.t}`;
      strengthText.classList.remove("weak", "ok", "strong");
      strengthText.classList.add(l.c);
    };

    const checkMatch = (silent = false) => {
      if (!pass || !pass2 || !matchHint) return true;

      const v1 = pass.value || "";
      const v2 = pass2.value || "";

      matchHint.classList.remove("ok", "bad");

      if (!v2) {
        matchHint.textContent = "• Debe coincidir";
        setInputState(pass2, "none");
        if (!silent && isTouched(pass2)) setMsg(root, "password2", "", "");
        return false;
      }

      if (v1 === v2) {
        matchHint.textContent = "• Coincide ✅";
        matchHint.classList.add("ok");
        setInputState(pass2, "ok");
        if (!silent && isTouched(pass2)) setMsg(root, "password2", "Perfecto, coincide.", "ok");
        return true;
      }

      matchHint.textContent = "• No coincide";
      matchHint.classList.add("bad");
      setInputState(pass2, "bad");
      if (!silent && isTouched(pass2)) setMsg(root, "password2", "Las contraseñas no coinciden.", "bad");
      return false;
    };

    // Toggle pass via data-toggle-pass
    safe(() => {
      $$("[data-toggle-pass]", root).forEach((btn) => {
        btn.addEventListener("click", () => safe(() => {
          const id = btn.getAttribute("data-toggle-pass");
          const input = id ? root.querySelector("#" + CSS.escape(id)) : null;
          if (!input) return;

          const show = input.type === "password";
          input.type = show ? "text" : "password";
          btn.setAttribute("aria-pressed", show ? "true" : "false");

          // opcional: cambia icon/text si lo usás
          const t = btn.getAttribute("data-toggle-text");
          if (t) btn.textContent = show ? "🙈" : "👁";
        }));
      });
    });

    // CapsLock hint (solo password, no molesta)
    const capsHint = (input, on) => {
      if (!input) return;
      const name = input.getAttribute("name") || input.id || "password";
      if (!on) {
        if (isTouched(input)) setMsg(root, name, "", "");
        return;
      }
      // no pisar mensaje “bad/ok” fuerte; solo si no hay error
      if (!input.classList.contains("is-error")) setMsg(root, name, "CapsLock activado.", "bad");
    };

    // Affiliate collapse + disable inputs when closed
    const setAffiliate = (open) => {
      if (!affBody) return;
      affBody.classList.toggle("is-open", !!open);
      // deshabilita inputs internos cuando está cerrado (evita submits raros)
      $$("input,select,textarea", affBody).forEach((el) => {
        el.disabled = !open;
      });
    };
    if (aff) {
      setAffiliate(aff.checked);
      aff.addEventListener("change", () => setAffiliate(aff.checked));
    }

    // Email validation (throttled)
    const validateEmail = () => {
      if (!email) return true;
      const v = (email.value || "").trim();
      if (!v) {
        setInputState(email, "none");
        if (isTouched(email)) setMsg(root, "email", "", "");
        return false;
      }
      if (emailLooksOk(v)) {
        setInputState(email, "ok");
        if (isTouched(email)) setMsg(root, "email", "Email válido.", "ok");
        return true;
      }
      setInputState(email, "bad");
      if (isTouched(email)) setMsg(root, "email", "Ingresá un email válido.", "bad");
      return false;
    };

    if (email) {
      email.addEventListener("blur", () => { markTouched(email); validateEmail(); });
      email.addEventListener("input", rafThrottle(() => { if (isTouched(email)) validateEmail(); }), { passive: true });
    }

    // Password validation
    const validatePassword = () => {
      if (!pass) return true;
      const v = pass.value || "";
      const r = scorePassword(v);

      setRule(rLen, r.hasLen);
      setRule(rMix, r.hasMix);
      setRule(rUp,  r.hasUp);
      setRule(rSym, r.hasSym);

      setMeterUI(r.score);
      setStrengthUI(r.score);

      // policy mínima: len + mix
      if (!v) {
        setInputState(pass, "none");
        if (isTouched(pass)) setMsg(root, "password", "", "");
        return false;
      }

      if (r.hasLen && r.hasMix) {
        setInputState(pass, "ok");
        if (isTouched(pass)) {
          const extra = (!r.hasUp || !r.hasSym) ? " Tip: sumá mayúscula y símbolo." : " Excelente.";
          setMsg(root, "password", "Buen nivel." + extra, "ok");
        }
        return true;
      }

      setInputState(pass, "bad");
      if (isTouched(pass)) setMsg(root, "password", "Mínimo: 8+ caracteres y letras + números.", "bad");
      return false;
    };

    if (pass) {
      pass.addEventListener("blur", () => { markTouched(pass); validatePassword(); checkMatch(true); });
      pass.addEventListener("input", rafThrottle(() => {
        markTouched(pass);
        validatePassword();
        checkMatch(true);
      }), { passive: true });

      pass.addEventListener("keydown", (e) => {
        // CapsLock detector (solo si el navegador lo reporta)
        if (typeof e.getModifierState === "function") {
          const on = e.getModifierState("CapsLock");
          capsHint(pass, on);
        }
      });
    }

    if (pass2) {
      pass2.addEventListener("blur", () => { markTouched(pass2); checkMatch(); });
      pass2.addEventListener("input", rafThrottle(() => { markTouched(pass2); checkMatch(); }), { passive: true });

      pass2.addEventListener("keydown", (e) => {
        if (typeof e.getModifierState === "function") {
          const on = e.getModifierState("CapsLock");
          capsHint(pass2, on);
        }
      });
    }

    // Enter UX: si Enter y hay inválidos, muestra feedback (no bloquea hard)
    form.addEventListener("keydown", (e) => {
      if (e.key !== "Enter") return;
      const t = e.target;
      if (!t || !(t instanceof HTMLElement)) return;
      // si está en textarea, no
      if (t.tagName === "TEXTAREA") return;

      // si ya está ok, dejá que siga
      const okEmail = validateEmail();
      const okPass = validatePassword();
      const okMatch = checkMatch(true);

      if (!(okEmail && okPass && okMatch)) {
        // no impedir siempre; pero si el target es un input cualquiera, damos feedback rápido
        markTouched(email); markTouched(pass); markTouched(pass2);
        validateEmail(); validatePassword(); checkMatch();
      }
    });

    // Submit guard + loading
    const setLoading = (on) => {
      if (!submitBtn) return;
      submitBtn.disabled = !!on;
      submitBtn.classList.toggle("is-loading", !!on);
      if (submitText) submitText.textContent = on ? "Creando cuenta…" : "Crear cuenta";
      root.setAttribute("data-state", on ? "submitting" : "ready");
    };

    // Si el user vuelve atrás o el navegador cancela, desbloqueá
    window.addEventListener("pageshow", () => safe(() => setLoading(false)));

    form.addEventListener("submit", (e) => safe(() => {
      // marcar touched para mostrar errores
      markTouched(email); markTouched(pass); markTouched(pass2);

      const okEmail = validateEmail();
      const okPass = validatePassword();
      const okMatch = checkMatch();

      let ok = okEmail && okPass && okMatch;

      if (!ok) {
        e.preventDefault();

        // micro “shake” si lo definís en CSS (opcional)
        root.classList.remove("is-shake");
        void root.offsetWidth; // reflow
        root.classList.add("is-shake");

        focusFirstInvalid(root);

        try {
          window.scrollTo({ top: 0, behavior: reducedMotion ? "auto" : "smooth" });
        } catch (_) {}

        return;
      }

      // ok → loading
      setLoading(true);
    }));
  }));
})();
