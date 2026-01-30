(() => {
  "use strict";

  const safe = (fn) => { try { return fn(); } catch (_) { return undefined; } };
  const $ = (sel, el = document) => safe(() => el.querySelector(sel)) || null;
  const $$ = (sel, el = document) => safe(() => Array.from(el.querySelectorAll(sel))) || [];
  const onReady = (fn) => {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", fn, { once: true });
    else fn();
  };

  const prefersReduced = safe(() => window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) || false;

  const rafThrottle = (fn) => {
    let raf = 0;
    return (...args) => {
      if (raf) return;
      raf = requestAnimationFrame(() => {
        raf = 0;
        safe(() => fn(...args));
      });
    };
  };

  const clamp = (n, a, b) => Math.max(a, Math.min(b, n));
  const trim = (v) => (v == null ? "" : String(v)).trim();
  const safeText = (v, max = 220) => {
    const s = trim(v).replace(/\u0000/g, "").replace(/\s+/g, " ");
    return s.length > max ? s.slice(0, max) : s;
  };

  const emailLooksOk = (v) => {
    const s = trim(v);
    if (!s || s.length < 6 || s.length > 254) return false;
    return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(s);
  };

  const scorePassword = (v) => {
    const s = String(v || "");
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
    if (s.length >= 14) score += 8;

    if (/^(\w)\1{6,}$/.test(s)) score = Math.min(score, 25);
    if (/password|123456|qwerty|abc123/i.test(s)) score = Math.min(score, 25);

    score = clamp(score, 0, 100);
    return { score, hasLen, hasMix, hasUp, hasLow, hasSym };
  };

  const strengthLabel = (score) => {
    if (score <= 35) return { t: "Débil", c: "weak" };
    if (score <= 75) return { t: "Ok", c: "ok" };
    return { t: "Fuerte", c: "strong" };
  };

  const ensureId = (el, fallback) => {
    if (!el) return "";
    if (el.id) return el.id;
    const id = `${fallback}-${Math.random().toString(16).slice(2)}`;
    el.id = id;
    return id;
  };

  const setInputState = (input, state) => {
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

  const setMsg = (root, name, text = "", kind = "") => {
    if (!root || !name) return;
    const box = root.querySelector(`[data-msg-for="${name}"]`);
    if (!box) return;

    if (!box.hasAttribute("role")) box.setAttribute("role", "status");
    if (!box.hasAttribute("aria-live")) box.setAttribute("aria-live", "polite");

    box.textContent = safeText(text, 180);
    box.classList.remove("is-ok", "is-bad");
    if (kind === "ok") box.classList.add("is-ok");
    if (kind === "bad") box.classList.add("is-bad");
  };

  const bindDescribedBy = (input, msgEl) => {
    if (!input || !msgEl) return;
    const msgId = ensureId(msgEl, "msg");
    const cur = trim(input.getAttribute("aria-describedby") || "");
    if (!cur.includes(msgId)) input.setAttribute("aria-describedby", (cur ? cur + " " : "") + msgId);
  };

  const focusSafe = (el) => {
    if (!el || typeof el.focus !== "function") return;
    try { el.focus({ preventScroll: true }); } catch (_) { try { el.focus(); } catch (__) {} }
  };

  const scrollToEl = (el) => {
    if (!el || typeof el.scrollIntoView !== "function") return;
    try { el.scrollIntoView({ behavior: prefersReduced ? "auto" : "smooth", block: "center" }); } catch (_) {}
  };

  const focusFirstInvalid = (root) => {
    const invalid = root.querySelector(".is-error, [aria-invalid='true']");
    if (invalid) {
      focusSafe(invalid);
      scrollToEl(invalid);
    }
  };

  const setRule = (el, ok) => { if (el) el.style.opacity = ok ? "1" : ".55"; };

  const getCsrfFromMeta = () => {
    const meta = document.querySelector('meta[name="csrf-token"]');
    const v = meta && typeof meta.content === "string" ? meta.content.trim() : "";
    return v || "";
  };

  const ensureCsrfInput = (form) => {
    if (!form) return true;
    const existing = form.querySelector('input[name="csrf_token"]');
    if (existing) {
      if (!trim(existing.value)) {
        const meta = getCsrfFromMeta();
        if (meta) existing.value = meta;
      }
      return !!trim(existing.value);
    }
    const meta = getCsrfFromMeta();
    const i = document.createElement("input");
    i.type = "hidden";
    i.name = "csrf_token";
    i.value = meta || "";
    form.appendChild(i);
    return !!trim(i.value);
  };

  onReady(() => safe(() => {
    const root = document.querySelector("[data-ss-reg]");
    if (!root) return;

    root.setAttribute("data-state", "ready");

    const form = root.querySelector("[data-register-form]") || document.querySelector("#registerForm");
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

    const submitBtn =
      root.querySelector("[data-submit]") ||
      root.querySelector("#submitBtn") ||
      form.querySelector('button[type="submit"]');

    const submitText = submitBtn ? submitBtn.querySelector(".ss-reg__btnText") : null;

    safe(() => {
      const msgEmail = root.querySelector('[data-msg-for="email"]');
      const msgPass = root.querySelector('[data-msg-for="password"]');
      const msgPass2 = root.querySelector('[data-msg-for="password2"]');
      if (email && msgEmail) bindDescribedBy(email, msgEmail);
      if (pass && msgPass) bindDescribedBy(pass, msgPass);
      if (pass2 && msgPass2) bindDescribedBy(pass2, msgPass2);
    });

    const touched = new WeakSet();
    const markTouched = (el) => { if (el) touched.add(el); };
    const isTouched = (el) => (el ? touched.has(el) : false);

    const setMeterUI = (val) => {
      if (!meterBox || !meter) return;
      const v = clamp(Number(val) || 0, 0, 100);
      meter.style.width = v + "%";
      meterBox.classList.remove("is-weak", "is-ok", "is-strong");
      if (v <= 35) meterBox.classList.add("is-weak");
      else if (v <= 75) meterBox.classList.add("is-ok");
      else meterBox.classList.add("is-strong");
    };

    const setStrengthUI = (val) => {
      if (!strengthText) return;
      const l = strengthLabel(clamp(Number(val) || 0, 0, 100));
      strengthText.textContent = `Fuerza: ${l.t}`;
      strengthText.classList.remove("weak", "ok", "strong");
      strengthText.classList.add(l.c);
    };

    const checkMatch = (silent = false) => {
      if (!pass || !pass2 || !matchHint) return true;

      const v1 = String(pass.value || "");
      const v2 = String(pass2.value || "");

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

    safe(() => {
      $$("[data-toggle-pass]", root).forEach((btn) => {
        btn.addEventListener("click", () => safe(() => {
          const id = btn.getAttribute("data-toggle-pass") || "";
          if (!id) return;

          const input = root.querySelector("#" + id) || root.querySelector(`[name="${id}"]`);
          if (!input) return;

          const show = input.type === "password";
          input.type = show ? "text" : "password";
          btn.setAttribute("aria-pressed", show ? "true" : "false");

          const t = btn.getAttribute("data-toggle-text");
          if (t) btn.textContent = show ? "🙈" : "👁";
        }));
      });
    });

    const capsHint = (input, on) => {
      if (!input) return;
      const name = input.getAttribute("name") || input.id || "password";
      if (!on) {
        if (isTouched(input)) setMsg(root, name, "", "");
        return;
      }
      if (!input.classList.contains("is-error")) setMsg(root, name, "CapsLock activado.", "bad");
    };

    const setAffiliate = (open) => {
      if (!affBody) return;
      affBody.classList.toggle("is-open", !!open);
      $$("input,select,textarea", affBody).forEach((el) => { el.disabled = !open; });
    };

    if (aff) {
      setAffiliate(!!aff.checked);
      aff.addEventListener("change", () => setAffiliate(!!aff.checked));
    }

    const validateEmail = () => {
      if (!email) return true;
      const v = trim(email.value);
      if (!v) {
        setInputState(email, "none");
        if (isTouched(email)) setMsg(root, "email", "Requerido.", "bad");
        return false;
      }
      if (emailLooksOk(v)) {
        const normalized = v.toLowerCase();
        if (normalized !== email.value) email.value = normalized;
        setInputState(email, "ok");
        if (isTouched(email)) setMsg(root, "email", "Email válido.", "ok");
        return true;
      }
      setInputState(email, "bad");
      if (isTouched(email)) setMsg(root, "email", "Ingresá un email válido.", "bad");
      return false;
    };

    const validatePassword = () => {
      if (!pass) return true;
      const v = String(pass.value || "");
      const r = scorePassword(v);

      setRule(rLen, r.hasLen);
      setRule(rMix, r.hasMix);
      setRule(rUp,  r.hasUp);
      setRule(rSym, r.hasSym);

      setMeterUI(r.score);
      setStrengthUI(r.score);

      if (!v) {
        setInputState(pass, "none");
        if (isTouched(pass)) setMsg(root, "password", "Requerido.", "bad");
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

    if (email) {
      email.addEventListener("blur", () => { markTouched(email); validateEmail(); }, { passive: true });
      email.addEventListener("input", rafThrottle(() => { if (isTouched(email)) validateEmail(); }), { passive: true });
    }

    if (pass) {
      pass.addEventListener("blur", () => { markTouched(pass); validatePassword(); checkMatch(true); }, { passive: true });
      pass.addEventListener("input", rafThrottle(() => {
        markTouched(pass);
        validatePassword();
        checkMatch(true);
      }), { passive: true });
      pass.addEventListener("keydown", (e) => {
        if (typeof e.getModifierState === "function") capsHint(pass, !!e.getModifierState("CapsLock"));
      });
    }

    if (pass2) {
      pass2.addEventListener("blur", () => { markTouched(pass2); checkMatch(); }, { passive: true });
      pass2.addEventListener("input", rafThrottle(() => { markTouched(pass2); checkMatch(); }), { passive: true });
      pass2.addEventListener("keydown", (e) => {
        if (typeof e.getModifierState === "function") capsHint(pass2, !!e.getModifierState("CapsLock"));
      });
    }

    form.addEventListener("keydown", (e) => {
      if (e.key !== "Enter") return;
      const t = e.target;
      if (!t || !(t instanceof HTMLElement)) return;
      if (t.tagName === "TEXTAREA") return;

      const okEmail = validateEmail();
      const okPass = validatePassword();
      const okMatch = checkMatch(true);

      if (!(okEmail && okPass && okMatch)) {
        markTouched(email); markTouched(pass); markTouched(pass2);
        validateEmail(); validatePassword(); checkMatch();
      }
    });

    let inflight = false;

    const setLoading = (on) => {
      inflight = !!on;
      if (!submitBtn) return;
      submitBtn.disabled = !!on;
      submitBtn.classList.toggle("is-loading", !!on);
      submitBtn.setAttribute("aria-busy", on ? "true" : "false");
      if (submitText) submitText.textContent = on ? "Creando cuenta…" : "Crear cuenta";
      root.setAttribute("data-state", on ? "submitting" : "ready");
    };

    window.addEventListener("pageshow", () => safe(() => setLoading(false)));

    form.addEventListener("submit", (e) => safe(() => {
      if (inflight) {
        e.preventDefault();
        return;
      }

      markTouched(email); markTouched(pass); markTouched(pass2);

      const okEmail = validateEmail();
      const okPass = validatePassword();
      const okMatch = checkMatch();

      const okCsrf = ensureCsrfInput(form);

      if (!(okEmail && okPass && okMatch && okCsrf)) {
        e.preventDefault();

        if (!okCsrf) {
          setMsg(root, "email", "Sesión vencida. Recargá la página.", "bad");
          try { window.location.reload(); } catch (_) {}
        }

        root.classList.remove("is-shake");
        void root.offsetWidth;
        root.classList.add("is-shake");

        focusFirstInvalid(root);
        try { window.scrollTo({ top: 0, behavior: prefersReduced ? "auto" : "smooth" }); } catch (_) {}
        return;
      }

      setLoading(true);

      window.setTimeout(() => {
        if (inflight) setLoading(false);
      }, 12000);
    }));

    // Si querés: auto focus si no hay errores visibles
    safe(() => {
      const first = email || pass || pass2;
      if (first) focusSafe(first);
    });
  }));
})();
