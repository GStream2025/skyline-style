(() => {
  "use strict";

  /* =========================================================
     Skyline Store — Register JS (ULTRA PRO v2.1)
     ✅ Robust / CSP-safe / NO-500 / anti-double-submit / a11y
     ✅ FIX: affiliate hidden value, Enter prevent, CSRF handling
  ========================================================= */

  const safe = (fn, fallback) => {
    try { return fn(); } catch (_) { return fallback; }
  };

  const trim = (v) => (v == null ? "" : String(v)).trim();
  const clamp = (n, a, b) => Math.max(a, Math.min(b, n));

  const onReady = (fn) => {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn, { once: true });
    } else {
      fn();
    }
  };

  const prefersReduced = safe(
    () => window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches,
    false
  );

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

  const safeText = (v, max = 180) => {
    const s = trim(v).replace(/\u0000/g, "").replace(/\s+/g, " ");
    return s.length > max ? s.slice(0, max) : s;
  };

  const q = (sel, root = document) => safe(() => root.querySelector(sel), null);
  const qa = (sel, root = document) => safe(() => Array.from(root.querySelectorAll(sel)), []);

  const focusSafe = (el) => {
    if (!el || typeof el.focus !== "function") return;
    try { el.focus({ preventScroll: true }); } catch (_) { try { el.focus(); } catch (__) {} }
  };

  const scrollToEl = (el) => {
    if (!el || typeof el.scrollIntoView !== "function") return;
    try { el.scrollIntoView({ behavior: prefersReduced ? "auto" : "smooth", block: "center" }); } catch (_) {}
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

    // penalizaciones
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
    if (!cur.split(/\s+/).includes(msgId)) {
      input.setAttribute("aria-describedby", (cur ? cur + " " : "") + msgId);
    }
  };

  const focusFirstInvalid = (root) => {
    const invalid = root.querySelector(".is-error, [aria-invalid='true']");
    if (invalid) {
      focusSafe(invalid);
      scrollToEl(invalid);
    }
  };

  // sin usar inline styles: depende de tu CSS
  const setRule = (el, ok) => {
    if (!el) return;
    el.classList.toggle("is-ok", !!ok);
    el.classList.toggle("is-off", !ok);
  };

  const getCsrfFromMeta = () => {
    const meta = document.querySelector('meta[name="csrf-token"]');
    const v = meta && typeof meta.content === "string" ? meta.content.trim() : "";
    return v || "";
  };

  const ensureCsrfInput = (form) => {
    if (!form) return true;

    let input = form.querySelector('input[name="csrf_token"]');
    const meta = getCsrfFromMeta();

    if (!input) {
      input = document.createElement("input");
      input.type = "hidden";
      input.name = "csrf_token";
      form.appendChild(input);
    }

    if (!trim(input.value) && meta) input.value = meta;
    return !!trim(input.value);
  };

  const findField = (root, id, name) => (
    q(`#${id}`, root) ||
    (name ? q(`[name="${name}"]`, root) : null) ||
    null
  );

  onReady(() => safe(() => {
    const root =
      document.querySelector("[data-ss-reg]") ||
      document.querySelector("[data-page='auth-register']") ||
      document;

    if (root && root.setAttribute) root.setAttribute("data-state", "ready");

    const form =
      q("[data-register-form]", root) ||
      q("#registerForm", root) ||
      q("form", root);

    if (!form) return;

    const email = findField(root, "email", "email");
    const pass  = findField(root, "password", "password");
    const pass2 = findField(root, "password2", "password2");

    const meterBox = q("#meterBox", root);
    const meter = q("#meter", root);
    const strengthText = q("#strengthText", root);
    const matchHint = q("#matchHint", root);

    const rLen = q("#rLen", root);
    const rMix = q("#rMix", root);
    const rUp  = q("#rUp", root);
    const rSym = q("#rSym", root);

    const roleSel = q("#role", root);
    const wantAff = q("#wantAffiliate", root); // hidden 0/1

    const submitBtn =
      q("[data-submit]", root) ||
      q("#submitBtn", root) ||
      q('button[type="submit"]', form);

    // aria-describedby
    safe(() => {
      const msgEmail = q('[data-msg-for="email"]', root);
      const msgPass  = q('[data-msg-for="password"]', root);
      const msgPass2 = q('[data-msg-for="password2"]', root);
      if (email && msgEmail) bindDescribedBy(email, msgEmail);
      if (pass  && msgPass)  bindDescribedBy(pass, msgPass);
      if (pass2 && msgPass2) bindDescribedBy(pass2, msgPass2);
    });

    // touched state
    const touched = new WeakSet();
    const markTouched = (el) => { if (el) touched.add(el); };
    const isTouched = (el) => (el ? touched.has(el) : false);

    // affiliate sync FIX (role select => hidden wantAffiliate)
    const syncAffiliate = () => {
      if (!roleSel || !wantAff) return;
      const v = trim(roleSel.value);
      wantAff.value = (v === "affiliate") ? "1" : "0";
    };
    if (roleSel && wantAff) {
      roleSel.addEventListener("change", syncAffiliate, { passive: true });
      syncAffiliate();
    }

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
      if (!pass || !pass2) return true;

      const v1 = String(pass.value || "");
      const v2 = String(pass2.value || "");

      if (matchHint) matchHint.classList.remove("ok", "bad");

      if (!v2) {
        if (matchHint) matchHint.textContent = "• Debe coincidir";
        setInputState(pass2, "none");
        if (!silent && isTouched(pass2)) setMsg(root, "password2", "", "");
        return false;
      }

      if (v1 === v2) {
        if (matchHint) {
          matchHint.textContent = "• Coincide ✅";
          matchHint.classList.add("ok");
        }
        setInputState(pass2, "ok");
        if (!silent && isTouched(pass2)) setMsg(root, "password2", "Perfecto, coincide.", "ok");
        return true;
      }

      if (matchHint) {
        matchHint.textContent = "• No coincide";
        matchHint.classList.add("bad");
      }
      setInputState(pass2, "bad");
      if (!silent && isTouched(pass2)) setMsg(root, "password2", "Las contraseñas no coinciden.", "bad");
      return false;
    };

    // Toggle pass
    qa("[data-toggle-pass]", root).forEach((btn) => {
      btn.addEventListener("click", () => safe(() => {
        const id = trim(btn.getAttribute("data-toggle-pass") || "");
        if (!id) return;

        const input = q(`#${id}`, root) || q(`[name="${id}"]`, root);
        if (!input) return;

        const showing = input.type === "password";
        input.type = showing ? "text" : "password";
        btn.setAttribute("aria-pressed", showing ? "true" : "false");

        // si querés cambiar icono sin inline scripts:
        // (deja “👁” si no hay data)
        const onText = btn.getAttribute("data-text-on") || "🙈";
        const offText = btn.getAttribute("data-text-off") || "👁";
        btn.textContent = showing ? onText : offText;

        focusSafe(input);
      }));
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

    // listeners
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
        if (e && typeof e.getModifierState === "function") capsHint(pass, !!e.getModifierState("CapsLock"));
      });
    }

    if (pass2) {
      pass2.addEventListener("blur", () => { markTouched(pass2); checkMatch(); }, { passive: true });
      pass2.addEventListener("input", rafThrottle(() => { markTouched(pass2); checkMatch(); }), { passive: true });
      pass2.addEventListener("keydown", (e) => {
        if (e && typeof e.getModifierState === "function") capsHint(pass2, !!e.getModifierState("CapsLock"));
      });
    }

    // Enter: si falla, prevenir submit y enfocar
    form.addEventListener("keydown", (e) => {
      if (!e || e.key !== "Enter") return;

      const t = e.target;
      const tag = t && t.tagName ? String(t.tagName).toUpperCase() : "";
      if (tag === "TEXTAREA") return;

      const okEmail = validateEmail();
      const okPass = validatePassword();
      const okMatch = checkMatch(true);

      if (!(okEmail && okPass && okMatch)) {
        e.preventDefault();
        markTouched(email); markTouched(pass); markTouched(pass2);
        validateEmail(); validatePassword(); checkMatch();
        focusFirstInvalid(root);
      }
    });

    let inflight = false;

    const setLoading = (on) => {
      inflight = !!on;
      if (submitBtn) {
        submitBtn.disabled = !!on;
        submitBtn.classList.toggle("is-loading", !!on);
        submitBtn.setAttribute("aria-busy", on ? "true" : "false");
      }
      if (root && root.setAttribute) root.setAttribute("data-state", on ? "submitting" : "ready");
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

        // solo si CSRF realmente falta => sugerimos recargar
        if (!okCsrf) {
          setMsg(root, "email", "Sesión vencida. Recargá la página e intentá de nuevo.", "bad");
        }

        if (root && root.classList) {
          root.classList.remove("is-shake");
          void root.offsetWidth;
          root.classList.add("is-shake");
        }

        focusFirstInvalid(root);
        safe(() => window.scrollTo({ top: 0, behavior: prefersReduced ? "auto" : "smooth" }));
        return;
      }

      setLoading(true);

      // failsafe
      window.setTimeout(() => {
        if (inflight) setLoading(false);
      }, 12000);
    })));

    // autofocus
    safe(() => {
      const first = email || pass || pass2;
      if (first) focusSafe(first);
    });
  }));
})();
