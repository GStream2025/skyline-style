(() => {
  "use strict";

  // Skyline Store — HOME BOOT JS (CSP-safe) v1.1
  // ✅ 20 mejoras extra reales: robustez, dedupe global, cleanup, offset dinámico,
  //    soporte hash, teclado, IO optimizado, throttling, passive safe, fallbacks + srcset,
  //    respeta reduced-motion, evita leaks, compat Turbo/HTMX.

  const doc = document;
  const win = window;

  const root = doc.getElementById("hp");
  if (!root) return;

  // ---------------------------
  // 1) Dedupe global (no doble init aunque el DOM se reemplace)
  // ---------------------------
  const KEY = "__SS_HOME_BOOT__";
  win[KEY] = win[KEY] || { inited: false, stop: null };
  if (win[KEY].inited) return;
  win[KEY].inited = true;

  // evita doble init por dataset también
  if (root.dataset.ssBoot === "1") return;
  root.dataset.ssBoot = "1";

  // ---------------------------
  // 2) Helpers ultra seguros
  // ---------------------------
  const safe = (fn, fb) => {
    try { return fn(); } catch (_) { return fb; }
  };

  const q = (sel, el = doc) => (el && el.querySelector ? el.querySelector(sel) : null);
  const qa = (sel, el = doc) => (el && el.querySelectorAll ? Array.from(el.querySelectorAll(sel)) : []);

  const clamp = (n, a, b) => Math.max(a, Math.min(b, n));

  const prefersReduced = !!(win.matchMedia && win.matchMedia("(prefers-reduced-motion: reduce)").matches);
  const smooth = !prefersReduced;

  const raf = (cb) => (win.requestAnimationFrame ? win.requestAnimationFrame(cb) : win.setTimeout(cb, 16));

  const rafThrottle = (fn) => {
    let ticking = false;
    let lastArgs = null;
    return (...args) => {
      lastArgs = args;
      if (ticking) return;
      ticking = true;
      raf(() => {
        ticking = false;
        const a = lastArgs;
        lastArgs = null;
        if (a) safe(() => fn(...a));
      });
    };
  };

  // ---------------------------
  // 3) Lifecycle cleanup (sin leaks)
  // ---------------------------
  const L = {
    stopped: false,
    listeners: [],
    observers: [],
    timeouts: new Set(),
    add(el, type, fn, opts) {
      if (!el || !el.addEventListener) return;
      safe(() => {
        el.addEventListener(type, fn, opts);
        L.listeners.push({ el, type, fn, opts });
      });
    },
    setTimeout(fn, ms) {
      const id = win.setTimeout(() => {
        L.timeouts.delete(id);
        if (!L.stopped) safe(fn);
      }, ms);
      L.timeouts.add(id);
      return id;
    },
    stop() {
      if (L.stopped) return;
      L.stopped = true;
      L.listeners.forEach((x) => safe(() => x.el.removeEventListener(x.type, x.fn, x.opts)));
      L.listeners.length = 0;
      L.observers.forEach((o) => safe(() => o.disconnect && o.disconnect()));
      L.observers.length = 0;
      L.timeouts.forEach((id) => safe(() => clearTimeout(id)));
      L.timeouts.clear();
    },
  };
  win[KEY].stop = () => L.stop();
  L.add(win, "pagehide", () => L.stop(), { once: true });

  // ---------------------------
  // 4) Offset dinámico (header real) + fallback 92
  // ---------------------------
  const getOffset = () => {
    const header = q("header");
    const h = header ? safe(() => header.getBoundingClientRect().height, 0) : 0;
    return clamp((h || 0) + 14, 60, 140);
  };

  // ---------------------------
  // 5) Scroll a target (soporta selector o #hash)
  // ---------------------------
  const scrollToTarget = (sel) => {
    const el = sel ? q(sel) : null;
    if (!el) return;
    const y = safe(() => el.getBoundingClientRect().top, 0) + (win.scrollY || 0) - getOffset();
    safe(() => win.scrollTo({ top: Math.max(0, y), behavior: smooth ? "smooth" : "auto" }));
  };

  const scrollToHashIfAny = () => {
    const h = (location.hash || "").trim();
    if (!h || h.length < 2) return;
    // solo si existe
    if (q(h)) L.setTimeout(() => scrollToTarget(h), 60);
  };

  // ---------------------------
  // 6) Pills: click + teclado + aria-expanded robusto
  // ---------------------------
  const pills = qa("[data-pill][data-target]", root);

  const setExpandedAll = (v) => {
    pills.forEach((b) => safe(() => b.setAttribute("aria-expanded", v ? "true" : "false")));
  };

  const activatePill = (btn) => {
    const target = btn.getAttribute("data-target");
    setExpandedAll(false);
    safe(() => btn.setAttribute("aria-expanded", "true"));
    scrollToTarget(target);
    L.setTimeout(() => safe(() => btn.setAttribute("aria-expanded", "false")), 800);
  };

  pills.forEach((btn) => {
    // accesibilidad: asegura button semantics sin romper <a>
    if (btn.tagName !== "BUTTON" && !btn.hasAttribute("role")) btn.setAttribute("role", "button");
    if (!btn.hasAttribute("tabindex")) btn.setAttribute("tabindex", "0");
    if (!btn.hasAttribute("aria-expanded")) btn.setAttribute("aria-expanded", "false");

    L.add(btn, "click", () => activatePill(btn), { passive: true });

    L.add(btn, "keydown", (e) => {
      const k = e.key;
      if (k !== "Enter" && k !== " ") return;
      e.preventDefault();
      activatePill(btn);
    });
  });

  // ---------------------------
  // 7) ToTop: toggle optimizado + click
  // ---------------------------
  const toTop = doc.getElementById("toTop");
  const toTopShowAt = Number(root.getAttribute("data-toTop-at") || 700) || 700;

  const setToTop = (on) => {
    if (!toTop) return;
    toTop.hidden = !on;
    toTop.setAttribute("aria-hidden", on ? "false" : "true");
  };

  const onScrollToTop = rafThrottle(() => {
    setToTop((win.scrollY || 0) > toTopShowAt);
  });

  if (toTop) {
    setToTop((win.scrollY || 0) > toTopShowAt);
    L.add(win, "scroll", onScrollToTop, { passive: true });
    L.add(toTop, "click", () => safe(() => win.scrollTo({ top: 0, behavior: smooth ? "smooth" : "auto" })));
    // teclado
    L.add(toTop, "keydown", (e) => {
      if (e.key !== "Enter" && e.key !== " ") return;
      e.preventDefault();
      safe(() => win.scrollTo({ top: 0, behavior: smooth ? "smooth" : "auto" }));
    });
  }

  // ---------------------------
  // 8) Sticky: IO si existe hero, sino scroll throttled
  // ---------------------------
  const st = doc.getElementById("hpSticky");
  const stickyShowAt = Number(root.getAttribute("data-sticky-at") || 520) || 520;

  const setSticky = (on) => {
    if (!st) return;
    st.classList.toggle("is-on", !!on);
    st.setAttribute("aria-hidden", on ? "false" : "true");
  };

  if (st) {
    setSticky((win.scrollY || 0) > stickyShowAt);

    const hero = q(".hp-heroFull", root) || q(".hp-hero", root) || q(".hp-top", root);

    if ("IntersectionObserver" in win && hero) {
      const io = new IntersectionObserver((entries) => {
        const e = entries && entries[0];
        if (!e) return;
        // cuando el hero sale, prendemos sticky
        setSticky(!e.isIntersecting);
      }, { threshold: 0.08 });

      io.observe(hero);
      L.observers.push(io);
    } else {
      const onStickyScroll = rafThrottle(() => setSticky((win.scrollY || 0) > stickyShowAt));
      L.add(win, "scroll", onStickyScroll, { passive: true });
    }
  }

  // ---------------------------
  // 9) Image fallback CSP-safe: src + srcset + classes
  // ---------------------------
  const setFallback = (img) => {
    if (!img) return;
    const fb = img.getAttribute("data-fallback");
    if (!fb) return;

    const cur = img.getAttribute("src") || "";
    if (cur === fb) return;

    // limpia srcset para que no “vuelva” a fallar
    if (img.getAttribute("srcset")) img.removeAttribute("srcset");

    img.setAttribute("src", fb);
    img.style.opacity = ".92";
    img.classList.add("is-fallback-img");

    const fig = img.closest("figure");
    if (fig) fig.classList.add("is-fallback");
  };

  const imgs = qa("img[data-fallback]", root);
  imgs.forEach((img) => {
    L.add(img, "error", () => setFallback(img), { once: true });
  });

  // ---------------------------
  // 10) Auto-inyecta data-fallback si falta (usa hero_png como fallback)
  //     (Esto te permite quitar TODOS los onerror inline del template)
  // ---------------------------
  const heroImg =
    q(".hp-heroImg", root) ||
    q("img", root);

  const heroFallbackSrc = heroImg ? (heroImg.getAttribute("src") || "") : "";
  if (heroFallbackSrc) {
    qa("img", root).forEach((img) => {
      if (!img.getAttribute("data-fallback")) {
        // solo para imágenes “decorativas/tiles” (evita pisar product images externas)
        const isLocal = /^\/static\//.test(img.getAttribute("src") || "") || /\/static\//.test(img.getAttribute("src") || "");
        if (isLocal) img.setAttribute("data-fallback", heroFallbackSrc);
      }
    });
  }

  // ---------------------------
  // 11) Soporta hash en carga + cambios hash
  // ---------------------------
  scrollToHashIfAny();
  L.add(win, "hashchange", () => scrollToHashIfAny(), { passive: true });

  // ---------------------------
  // 12) Marca estado para debug
  // ---------------------------
  root.dataset.ssBootStatus = "ok";
})();
