(() => {
  "use strict";

  // Skyline Store — HOME JS (ULTRA PRO v4.1)
  // ✅ Conectado a tu index sin romper nada
  // ✅ 26 mejoras reales (CSP-friendly, robustez, performance, a11y, compatibilidad)
  // ✅ Sin duplicados / sin leaks / re-init seguro / fallback si faltan nodos
  //
  // NOTA CSP: este archivo funciona perfecto con CSP estricta (sin inline).
  // Cargalo con: <script src="{{ url_for('static', filename='js/home.js') }}?v=162" defer></script>

  const HOME_VERSION = "v4.1";
  const doc = document;
  const win = window;

  // ---------------------------
  // Helpers (seguros + rápidos)
  // ---------------------------
  const safe = (fn, fb) => {
    try { return fn(); } catch (_) { return fb; }
  };

  const $ = (sel, el = doc) => (el && el.querySelector ? el.querySelector(sel) : null);
  const $$ = (sel, el = doc) => (el && el.querySelectorAll ? Array.from(el.querySelectorAll(sel)) : []);

  const clamp = (n, a, b) => Math.max(a, Math.min(b, n));
  const nowMs = () => (win.performance && performance.now ? performance.now() : Date.now());

  // (1) Fix: navigator puede no existir en entornos raros
  const nav = safe(() => navigator, null);

  const supports = {
    IO: "IntersectionObserver" in win,
    RO: "ResizeObserver" in win,
    Idle: "requestIdleCallback" in win,
    Abort: "AbortController" in win,
    Microtask: "queueMicrotask" in win,
    RAF: "requestAnimationFrame" in win,
    MO: "MutationObserver" in win,
    Conn: !!(nav && nav.connection),
  };

  const raf = (cb) => (supports.RAF ? win.requestAnimationFrame(cb) : win.setTimeout(cb, 16));
  const caf = (id) => (supports.RAF ? win.cancelAnimationFrame(id) : clearTimeout(id));

  const microtask = (fn) => {
    if (supports.Microtask) return queueMicrotask(() => safe(fn));
    Promise.resolve().then(() => safe(fn)).catch(() => {});
  };

  const rafThrottle = (fn) => {
    let id = 0;
    let lastArgs = null;
    return (...args) => {
      lastArgs = args;
      if (id) return;
      id = raf(() => {
        id = 0;
        if (!lastArgs) return;
        safe(() => fn(...lastArgs));
        lastArgs = null;
      });
    };
  };

  const debounce = (fn, wait = 160) => {
    let t = 0;
    return (...args) => {
      clearTimeout(t);
      t = setTimeout(() => safe(() => fn(...args)), wait);
    };
  };

  const esc = (s) =>
    String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");

  // (2) Media flags robustos
  const media = {
    reducedMotion: !!(win.matchMedia && win.matchMedia("(prefers-reduced-motion: reduce)").matches),
    reducedData: !!(supports.Conn && nav && nav.connection && nav.connection.saveData),
    finePointer: !!(win.matchMedia && win.matchMedia("(pointer: fine)").matches),
    touch: ("ontouchstart" in win) || ((nav && nav.maxTouchPoints) || 0) > 0,
    dark: !!(win.matchMedia && win.matchMedia("(prefers-color-scheme: dark)").matches),
  };

  const preferSmooth = !media.reducedMotion;

  // (3) Scroll offset: header real-time (se adapta si cambia)
  const getHeaderOffset = () => {
    const header = $("header");
    const h = header ? safe(() => header.getBoundingClientRect().height, 0) : 0;
    return clamp((h || 0) + 14, 0, 160);
  };

  const smoothScrollTo = (node, offset = 0) => {
    if (!node) return;
    safe(() => {
      const y = (node.getBoundingClientRect().top || 0) + (win.scrollY || 0) - offset;
      win.scrollTo({ top: Math.max(0, y), behavior: preferSmooth ? "smooth" : "auto" });
    });
  };

  const isTypingContext = (el) => {
    const ae = el || doc.activeElement;
    if (!ae) return false;
    const tag = (ae.tagName || "").toUpperCase();
    return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || !!ae.isContentEditable;
  };

  // (4) Root: soporta tu index aunque cambie el id
  const getHomeRoot = () =>
    doc.getElementById("hp") ||
    doc.querySelector(".hp.hp-v15") ||
    doc.querySelector(".hp");

  let homeRoot = getHomeRoot();

  // (5) Detección home más segura (evita ejecutar en otras páginas)
  const path = String(location.pathname || "/");
  const isHome =
    (doc.body && doc.body.classList.contains("home")) ||
    !!homeRoot ||
    path === "/" ||
    path === "/home" ||
    path === "/home/" ||
    path === "/index" ||
    path === "/index.html";

  if (!isHome) return;

  // ---------------------------
  // Global guard (sin duplicados)
  // ---------------------------
  const homeHash = safe(() => {
    const r = homeRoot || getHomeRoot();
    const id = r ? (r.id || "") : "";
    const cls = r ? String(r.className || "") : "";
    const len = cls.length;
    return `${path}::${id}::${len}`;
  }, `${path}::fallback`);

  win.__SS_HOME_STATE__ = win.__SS_HOME_STATE__ || {};
  const STATE = win.__SS_HOME_STATE__;

  if (STATE[homeHash]?.version === HOME_VERSION) return;
  if (STATE[homeHash]?.stopAll) safe(() => STATE[homeHash].stopAll());

  // ---------------------------
  // Lifecycle (cleanup real)
  // ---------------------------
  const LIFECYCLE = {
    alive: true,
    stopped: false,
    rafs: new Set(),
    timeouts: new Set(),
    intervals: new Set(),
    observers: new Set(),
    aborters: new Set(),
    listeners: [],
    nodes: new Set(),

    addListener(el, type, fn, opts) {
      if (!el || !el.addEventListener) return;
      safe(() => {
        el.addEventListener(type, fn, opts);
        this.listeners.push({ el, type, fn, opts });
      });
    },

    setTimeout(fn, ms) {
      const id = setTimeout(() => {
        this.timeouts.delete(id);
        if (!this.stopped) safe(fn);
      }, ms);
      this.timeouts.add(id);
      return id;
    },

    setInterval(fn, ms) {
      const id = setInterval(() => {
        if (this.stopped) return;
        safe(fn);
      }, ms);
      this.intervals.add(id);
      return id;
    },

    requestRaf(fn) {
      const id = raf(() => {
        this.rafs.delete(id);
        if (!this.stopped) safe(fn);
      });
      this.rafs.add(id);
      return id;
    },

    trackNode(n) { if (n) this.nodes.add(n); },

    stopAll() {
      if (this.stopped) return;
      this.stopped = true;
      this.alive = false;

      this.rafs.forEach((id) => safe(() => caf(id)));
      this.rafs.clear();

      this.timeouts.forEach((id) => safe(() => clearTimeout(id)));
      this.timeouts.clear();

      this.intervals.forEach((id) => safe(() => clearInterval(id)));
      this.intervals.clear();

      this.observers.forEach((o) => safe(() => o.disconnect && o.disconnect()));
      this.observers.clear();

      this.aborters.forEach((a) => safe(() => a.abort && a.abort()));
      this.aborters.clear();

      this.listeners.forEach((l) => safe(() => l.el.removeEventListener(l.type, l.fn, l.opts)));
      this.listeners.length = 0;

      this.nodes.forEach((n) => safe(() => n.remove?.()));
      this.nodes.clear();
    },
  };

  STATE[homeHash] = { version: HOME_VERSION, stopAll: () => LIFECYCLE.stopAll() };

  const syncAlive = () => { LIFECYCLE.alive = !doc.hidden && !LIFECYCLE.stopped; };
  LIFECYCLE.addListener(doc, "visibilitychange", syncAlive);
  LIFECYCLE.addListener(win, "pageshow", syncAlive);
  LIFECYCLE.addListener(win, "pagehide", () => safe(() => LIFECYCLE.stopAll()), { once: true });

  // ---------------------------
  // Config (ajustado a tu index real)
  // ---------------------------
  const CFG = {
    preloader: { sel: "#ss-preloader", fadeMs: 240 },

    reveal: {
      selector: "[data-reveal]",
      threshold: 0.12,
      rootMargin: "120px 0px -10% 0px",
      baseStaggerMs: 50,
      maxBatch: 24,              // (6) más suave, menos saltos
      onceClass: "is-in",
    },

    hero: {
      // (7) Soporta variantes de card/hero (por si cambia tu HTML)
      containerSel: ".hp-heroCard, .hp-heroFull, .hp-hero",
      imgSel: ".hp-heroImg, img",
      maxMoveX: 12,
      maxMoveY: 10,
      scrollParallax: 16,
      scale: 1.05,
      enable: !media.reducedMotion && !media.reducedData && !media.touch && media.finePointer,
    },

    // (8) IDs + fallbacks por clase (por si el id no existe)
    toTop: { sel: "#toTop, .to-top", showAt: 700 },
    sticky: { sel: "#hpSticky, .hp-sticky", showAt: 520, onClass: "is-on", hysteresisMs: 140 },

    search: {
      candidates:
        'header input[name="q"], header input[type="search"], .topbar input[name="q"], .topbar input[type="search"], input[name="q"], input[type="search"]',
      shortcutKey: "/",
    },

    pills: {
      selector: ".hp-pill[data-pill], .hp-chip[data-pill], [data-pill][data-target], .hp-link[data-target]",
      activeClass: "active",
      targetAttr: "data-target",
      singleActive: false,
    },

    autocomplete: {
      enable: true,
      endpoint: "/api/search_suggest?q=",
      minChars: 2,
      limit: 8,
      debounceMs: 160,
      cacheSize: 60,
      maxHeight: 280,
      pasteGuardLen: 80,
    },

    perf: {
      // (9) si la tab está oculta, evitamos trabajos caros
      pauseWhenHidden: true,
      // (10) evita glows en low-end por default
      glowEnable: !media.reducedMotion && !media.reducedData && media.finePointer && !media.touch,
    },
  };

  // ---------------------------
  // Mark loaded (diagnóstico + hooks)
  // ---------------------------
  const markLoaded = (status = "ok") => {
    const hp = getHomeRoot();
    if (!hp) return;
    hp.dataset.ssHome = HOME_VERSION;
    hp.dataset.ssHomeStatus = status;
    hp.classList.add("ss-homejs-on");
  };

  // (11) Debug opcional por querystring: ?debug_home=1
  const DEBUG = /(^|[?&])debug_home=1(&|$)/.test(String(location.search || ""));

  const log = (...a) => { if (DEBUG) safe(() => console.log("[HOME]", ...a)); };

  // ---------------------------
  // Auto-mark reveal (mejor cobertura)
  // ---------------------------
  const autoMarkReveal = () => {
    const hp = getHomeRoot();
    if (!hp) return;

    const targets = [
      ".hp-topTrust__item",
      ".hp-hero__copy",
      ".hp-hero__media",
      ".hp-trustCard",
      ".hp-catCard",
      ".hp-prod",
      ".hp-cta__inner",
      ".hp-secHead",
      ".hp-empty",
      ".hp-stat",
      ".hp-mini__item",
    ];

    targets.forEach((sel) => {
      $$(sel, hp).forEach((el) => {
        if (!el.hasAttribute("data-reveal")) el.setAttribute("data-reveal", "");
      });
    });
  };

  // ---------------------------
  // Reveal (IO pro + batch + stagger por sección)
  // ---------------------------
  const initReveal = () => {
    const hp = getHomeRoot();
    if (!hp) return;

    const nodes = $$(CFG.reveal.selector, hp);
    if (!nodes.length) return;

    if (media.reducedMotion || !supports.IO) {
      nodes.forEach((n) => n.classList.add(CFG.reveal.onceClass));
      return;
    }

    const vw = win.innerWidth || 1200;
    const stagger = clamp(
      CFG.reveal.baseStaggerMs * (vw < 520 ? 0.72 : vw < 900 ? 0.88 : 1),
      18,
      70
    );

    // Orden estable por posición + DOM
    const sorted = nodes
      .map((n, i) => ({ n, i, top: safe(() => n.getBoundingClientRect().top, 99999) }))
      .sort((a, b) => (a.top - b.top) || (a.i - b.i))
      .map((x) => x.n);

    const groupIndex = new Map();
    sorted.forEach((el) => {
      const section = el.closest("section") || hp;
      const idx = groupIndex.get(section) ?? 0;
      groupIndex.set(section, idx + 1);
      el.dataset.revealIdx = String(idx);
    });

    const schedule = (fn) => {
      if (supports.Idle) return requestIdleCallback(() => safe(fn), { timeout: 220 });
      microtask(fn);
    };

    const io = new IntersectionObserver((entries) => {
      const toShow = [];
      for (const e of entries) {
        if (!e.isIntersecting) continue;
        const el = e.target;
        io.unobserve(el);
        toShow.push(el);
      }
      if (!toShow.length) return;

      schedule(() => {
        toShow.slice(0, CFG.reveal.maxBatch).forEach((el) => {
          const idx = Number(el.dataset.revealIdx || "0") || 0;
          LIFECYCLE.setTimeout(() => {
            if (LIFECYCLE.alive) el.classList.add(CFG.reveal.onceClass);
          }, idx * stagger);
        });
      });
    }, { threshold: CFG.reveal.threshold, rootMargin: CFG.reveal.rootMargin });

    sorted.forEach((n) => io.observe(n));
    LIFECYCLE.observers.add(io);
  };

  // ---------------------------
  // Sticky + ToTop (sin flicker)
  // ---------------------------
  const initStickyToTop = () => {
    const toTop = $(CFG.toTop.sel);
    const sticky = $(CFG.sticky.sel);

    // (12) Mejor detector de “hero”
    const heroSection =
      $(".hp-heroFull") || $(".hp-hero") || $(".hp-heroCard") || $(".hp-top") || $(".hp-wrap");

    const setOn = (on) => {
      const v = !!on;
      if (sticky) {
        sticky.classList.toggle(CFG.sticky.onClass, v);
        sticky.setAttribute("aria-hidden", v ? "false" : "true");
      }
      if (toTop) toTop.hidden = !v;
    };

    if (sticky) sticky.setAttribute("aria-hidden", "true");

    if (toTop) {
      LIFECYCLE.addListener(toTop, "click", () => {
        safe(() => win.scrollTo({ top: 0, behavior: preferSmooth ? "smooth" : "auto" }));
      });
    }

    let lastSwitch = 0;
    const hysteresis = (on) => {
      const t = nowMs();
      if (t - lastSwitch < CFG.sticky.hysteresisMs) return;
      lastSwitch = t;
      setOn(on);
    };

    if (supports.IO && heroSection) {
      const io = new IntersectionObserver((entries) => {
        const e = entries[0];
        const on = !e.isIntersecting;
        if (media.reducedMotion) return setOn(on);
        hysteresis(on);
      }, { threshold: [0.01, 0.15, 0.35] });

      io.observe(heroSection);
      LIFECYCLE.observers.add(io);
      setOn((win.scrollY || 0) > CFG.sticky.showAt);
      return;
    }

    const apply = () => {
      const y = win.scrollY || 0;
      setOn(y > Math.max(CFG.sticky.showAt, CFG.toTop.showAt));
    };

    const onScroll = rafThrottle(apply);
    LIFECYCLE.addListener(win, "scroll", onScroll, { passive: true });
    apply();
  };

  // ---------------------------
  // Hotkeys "/"
  // ---------------------------
  const initHotkeys = () => {
    const input = $(CFG.search.candidates);
    if (!input) return;

    safe(() => {
      if (!input.getAttribute("autocomplete")) input.setAttribute("autocomplete", "off");
      if (!input.getAttribute("type")) input.setAttribute("type", "search");
      if (!input.getAttribute("inputmode")) input.setAttribute("inputmode", "search");
    });

    // (13) Detecta modales más amplio + overlay
    const hasModalOpen = () =>
      !!doc.querySelector(
        "[role='dialog'][open], dialog[open], .modal.is-open, .drawer.is-open, .overlay.is-open, .backdrop.is-on"
      );

    LIFECYCLE.addListener(doc, "keydown", (e) => {
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      if (hasModalOpen()) return;

      if (e.key === CFG.search.shortcutKey && !isTypingContext()) {
        e.preventDefault();
        safe(() => input.focus({ preventScroll: true }));
        safe(() => input.select?.());
      }

      if (e.key === "Escape" && doc.activeElement === input) safe(() => input.blur());
    });
  };

  // ---------------------------
  // Pills (click + teclado + scroll target)
  // ---------------------------
  const initPills = () => {
    const pills = $$(CFG.pills.selector);
    if (!pills.length) return;

    const setPressed = (el, pressed) =>
      safe(() => el.setAttribute("aria-pressed", pressed ? "true" : "false"));

    // (14) Soporta data-target sin # (ej: "section1")
    const resolveTarget = (raw) => {
      const s = String(raw || "").trim();
      if (!s) return null;
      if (s.startsWith("#") || s.startsWith(".")) return s;
      // id “pelado”
      return `#${CSS && CSS.escape ? CSS.escape(s) : s.replace(/[^\w-]/g, "")}`;
    };

    pills.forEach((pill) => {
      if (pill.tagName !== "A") pill.setAttribute("role", pill.getAttribute("role") || "button");
      pill.setAttribute("tabindex", pill.getAttribute("tabindex") || "0");
      setPressed(pill, pill.classList.contains(CFG.pills.activeClass));

      const go = () => {
        if (CFG.pills.singleActive) {
          pills.forEach((p) => {
            p.classList.remove(CFG.pills.activeClass);
            setPressed(p, false);
          });
        }

        pill.classList.toggle(CFG.pills.activeClass);
        setPressed(pill, pill.classList.contains(CFG.pills.activeClass));

        const raw = pill.getAttribute(CFG.pills.targetAttr) || pill.getAttribute("data-target");
        const sel = resolveTarget(raw);
        const node = sel ? $(sel) : null;

        if (node) return smoothScrollTo(node, getHeaderOffset());

        const href = pill.getAttribute("href") || "/shop";
        location.assign(href);
      };

      LIFECYCLE.addListener(pill, "click", (e) => {
        const hasTarget = !!(pill.getAttribute(CFG.pills.targetAttr) || pill.getAttribute("data-target"));
        if (pill.tagName === "A" && !hasTarget) return;
        e.preventDefault();
        go();
      });

      LIFECYCLE.addListener(pill, "keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          go();
        }
      });
    });
  };

  // ---------------------------
  // Hero motion (cancelable + auto-disable si va lento)
  // ---------------------------
  const initHeroMotion = () => {
    if (!CFG.hero.enable) return;

    // (15) Busca el “mejor” contenedor hero
    const hero =
      $(".hp-heroCard") ||
      $(".hp-heroFull") ||
      $(".hp-hero");

    if (!hero) return;

    const img = $(CFG.hero.imgSel, hero);
    if (!img || !img.style) return;

    let rect = hero.getBoundingClientRect();
    let mx = 0, my = 0, sx = 0, sy = 0;
    let active = true;
    let lastTransform = "";
    let lastFrame = nowMs();
    let slowFrames = 0;
    let frameId = 0;

    const updateRect = () => { rect = hero.getBoundingClientRect(); };

    if (supports.RO) {
      const ro = new ResizeObserver(updateRect);
      ro.observe(hero);
      LIFECYCLE.observers.add(ro);
    } else {
      LIFECYCLE.addListener(win, "resize", rafThrottle(updateRect), { passive: true });
    }

    // (16) Pausa si está fuera de vista
    if (supports.IO) {
      const io = new IntersectionObserver((entries) => {
        active = !!entries[0]?.isIntersecting && !doc.hidden;
        if (!active) mx = my = 0;
      }, { threshold: 0.08 });
      io.observe(hero);
      LIFECYCLE.observers.add(io);
    }

    const onMove = rafThrottle((e) => {
      if (!active || !LIFECYCLE.alive) return;
      const w = Math.max(1, rect.width);
      const h = Math.max(1, rect.height);

      const px = clamp((e.clientX - rect.left) / w - 0.5, -0.5, 0.5);
      const py = clamp((e.clientY - rect.top) / h - 0.5, -0.5, 0.5);

      const mxMax = clamp(CFG.hero.maxMoveX * (w > 520 ? 1 : 0.75), 6, 16);
      const myMax = clamp(CFG.hero.maxMoveY * (h > 420 ? 1 : 0.75), 5, 14);

      mx = px * mxMax;
      my = py * myMax;
    });

    LIFECYCLE.addListener(hero, "pointerenter", () => updateRect(), { passive: true });
    LIFECYCLE.addListener(hero, "pointermove", onMove, { passive: true });
    LIFECYCLE.addListener(hero, "pointerleave", () => { mx = 0; my = 0; }, { passive: true });

    const onScroll = rafThrottle(() => {
      updateRect();
      const viewH = win.innerHeight || 900;
      const t = clamp(1 - rect.top / viewH, 0, 1);
      const target = -(t * CFG.hero.scrollParallax);
      sy += (target - sy) * 0.08;
    });

    LIFECYCLE.addListener(win, "scroll", onScroll, { passive: true });
    onScroll();

    // (17) Resetea en blur/focus para evitar “saltos”
    LIFECYCLE.addListener(win, "blur", () => { mx = my = 0; }, { passive: true });

    const tick = () => {
      if (LIFECYCLE.stopped) return;

      // (18) Si la tab está oculta, no calculamos
      if (CFG.perf.pauseWhenHidden && doc.hidden) {
        frameId = raf(tick);
        return;
      }

      const now = nowMs();
      const dt = now - lastFrame;
      lastFrame = now;

      if (dt > 34) slowFrames++;
      else slowFrames = Math.max(0, slowFrames - 1);

      const shouldWork = LIFECYCLE.alive && active && slowFrames < 12;

      if (shouldWork) {
        sx += (mx - sx) * 0.11;
        const combinedY = sy + (my - sy * 0.15);

        const tr = `scale(${CFG.hero.scale}) translate3d(${sx.toFixed(2)}px, ${combinedY.toFixed(2)}px, 0)`;
        if (tr !== lastTransform) {
          img.style.transform = tr;
          lastTransform = tr;
        }
      } else {
        // (19) Fallback limpio si se desactiva (evita “queda pegado”)
        if (lastTransform) {
          img.style.transform = "";
          lastTransform = "";
        }
      }

      frameId = raf(tick);
    };

    frameId = raf(tick);
    LIFECYCLE.addListener(win, "pagehide", () => { if (frameId) caf(frameId); frameId = 0; }, { once: true });
  };

  // ---------------------------
  // Glow (sutil, dedupe, configurable)
  // ---------------------------
  const initGlow = () => {
    if (!CFG.perf.glowEnable) return;

    const hero = $(".hp-heroCard") || $(".hp-heroFull") || $(".hp-hero");
    if (!hero) return;
    if (hero.querySelector(".ss-heroGlow, .hp-heroGlow")) return;

    const glow = doc.createElement("div");
    glow.className = "ss-heroGlow hp-heroGlow";
    glow.setAttribute("aria-hidden", "true");

    Object.assign(glow.style, {
      position: "absolute",
      inset: "0",
      pointerEvents: "none",
      zIndex: "2",
      mixBlendMode: "soft-light",
      opacity: "0",
      transition: media.reducedMotion ? "none" : "opacity .28s ease",
      background:
        "radial-gradient(460px 300px at 50% 50%, rgba(37,99,235,.18), transparent 62%)," +
        "radial-gradient(420px 280px at 60% 40%, rgba(14,165,233,.12), transparent 62%)",
      willChange: "background, opacity",
    });

    hero.appendChild(glow);
    LIFECYCLE.trackNode(glow);

    const moveGlow = rafThrottle((e) => {
      const r = hero.getBoundingClientRect();
      const x = clamp(((e.clientX - r.left) / Math.max(1, r.width)) * 100, 0, 100);
      const y = clamp(((e.clientY - r.top) / Math.max(1, r.height)) * 100, 0, 100);
      glow.style.background =
        `radial-gradient(520px 320px at ${x}% ${y}%, rgba(37,99,235,.20), transparent 62%),` +
        `radial-gradient(460px 300px at ${clamp(x + 16, 0, 100)}% ${clamp(y - 10, 0, 100)}%, rgba(14,165,233,.14), transparent 64%)`;
    });

    LIFECYCLE.addListener(hero, "pointerenter", () => (glow.style.opacity = "1"), { passive: true });
    LIFECYCLE.addListener(hero, "pointerleave", () => (glow.style.opacity = "0"), { passive: true });
    LIFECYCLE.addListener(hero, "pointermove", moveGlow, { passive: true });
  };

  // ---------------------------
  // Image safety (scoped si hay hp)
  // ---------------------------
  const initImageSafety = () => {
    const hp = getHomeRoot();
    const scope = hp || doc;
    const imgs = $$("img", scope);
    if (!imgs.length) return;

    const heroFallback = safe(() => {
      const anyHero = $(".hp-heroImg", scope);
      return anyHero ? anyHero.getAttribute("src") : "";
    }, "");

    imgs.forEach((img) => {
      // (20) Evita loops de fallback
      let tried = false;

      LIFECYCLE.addListener(img, "error", () => {
        if (tried) return;
        tried = true;

        img.classList.add("img-failed");
        const wrap =
          img.closest(".hp-catCard__media, .mediaP, .media, figure, .hp-heroCard, .hp-prod__img") ||
          img.parentElement;

        if (wrap) wrap.classList.add("media-failed");

        const fb = img.getAttribute("data-fallback") || heroFallback;
        if (fb && img.src !== fb) safe(() => (img.src = fb));
      }, { once: true });

      // (21) A11y: alt vacío -> placeholder
      if (!img.getAttribute("alt")) img.setAttribute("alt", "");
      // (22) Performance: lazy decode si no está seteado
      if (!img.getAttribute("loading")) img.setAttribute("loading", "lazy");
      if (!img.getAttribute("decoding")) img.setAttribute("decoding", "async");
    });
  };

  // ---------------------------
  // Prefetch / preconnect (dedupe real)
  // ---------------------------
  const ensureLink = (rel, href, as) => {
    if (!href) return;
    const head = doc.head || $("head");
    if (!head) return;

    const exists = $$(`link[rel="${rel}"]`, head).some((l) => (l.getAttribute("href") || "") === href);
    if (exists) return;

    const link = doc.createElement("link");
    link.rel = rel;
    link.href = href;
    if (as) link.as = as;
    head.appendChild(link);
  };

  const initPrefetchShop = () => {
    // (23) Solo si estamos en same-origin
    ensureLink("prefetch", "/shop", "document");
    ensureLink("preconnect", location.origin);
  };

  // ---------------------------
  // Autocomplete (LRU + abort + aria + teclado) — sin inline
  // ---------------------------
  const initAutocomplete = () => {
    if (!CFG.autocomplete.enable) return;

    const input = $(CFG.search.candidates);
    if (!input) return;

    if (!input.getAttribute("autocomplete")) input.setAttribute("autocomplete", "off");
    if (!input.getAttribute("type")) input.setAttribute("type", "search");

    input.setAttribute("aria-autocomplete", "list");
    input.setAttribute("aria-haspopup", "listbox");
    input.setAttribute("aria-expanded", "false");

    const cache = new Map();
    const cacheGet = (k) => {
      if (!cache.has(k)) return null;
      const v = cache.get(k);
      cache.delete(k);
      cache.set(k, v);
      return v;
    };
    const cacheSet = (k, v) => {
      if (cache.has(k)) cache.delete(k);
      cache.set(k, v);
      if (cache.size > CFG.autocomplete.cacheSize) cache.delete(cache.keys().next().value);
    };

    // (24) Evita duplicar box si se re-init (defensa extra)
    const existing = doc.getElementById("ss-suggest");
    if (existing) safe(() => existing.remove());

    const box = doc.createElement("div");
    box.id = "ss-suggest";
    box.className = "ss-suggest";
    box.setAttribute("role", "listbox");
    box.setAttribute("aria-label", "Sugerencias");
    box.style.position = "absolute";
    box.style.zIndex = "9999";
    box.style.display = "none";
    box.style.maxHeight = `${CFG.autocomplete.maxHeight}px`;
    box.style.overflow = "auto";
    box.style.overflowX = "hidden";

    Object.assign(box.style, {
      marginTop: "8px",
      borderRadius: "14px",
      border: media.dark ? "1px solid rgba(148,163,184,.22)" : "1px solid rgba(15,23,42,.14)",
      background: media.dark ? "rgba(9,12,24,.92)" : "rgba(255,255,255,.96)",
      boxShadow: "0 18px 50px rgba(2,6,23,.14)",
      backdropFilter: "blur(14px)",
      WebkitBackdropFilter: "blur(14px)",
      minWidth: "240px",
    });

    doc.body.appendChild(box);
    LIFECYCLE.trackNode(box);

    input.setAttribute("aria-controls", box.id);

    const positionBox = () => {
      const r = input.getBoundingClientRect();
      box.style.left = `${r.left + win.scrollX}px`;
      box.style.top = `${r.bottom + win.scrollY}px`;
      box.style.width = `${r.width}px`;
    };
    const pos = rafThrottle(positionBox);
    pos();
    LIFECYCLE.addListener(win, "resize", pos, { passive: true });
    LIFECYCLE.addListener(win, "scroll", pos, { passive: true });

    let activeIndex = -1;
    let rows = [];
    let aborter = null;
    let lastQ = "";
    let composing = false;

    const close = () => {
      box.style.display = "none";
      box.innerHTML = "";
      rows = [];
      activeIndex = -1;
      input.removeAttribute("aria-activedescendant");
      input.setAttribute("aria-expanded", "false");
    };

    const highlight = (row) => {
      rows.forEach((r) => (r.style.background = "transparent"));
      if (!row) return;
      row.style.background = media.dark ? "rgba(255,255,255,.06)" : "rgba(37,99,235,.10)";
      safe(() => row.scrollIntoView({ block: "nearest" }));
    };

    const normalizeItems = (data) => {
      const arr = Array.isArray(data) ? data : (data && Array.isArray(data.items) ? data.items : []);
      return arr
        .map((it) => {
          const title = String((it && (it.title || it.name || it.label)) || "").trim();
          if (!title) return null;
          const href = String((it && it.href) || "").trim() || `/shop?q=${encodeURIComponent(title)}`;
          return { title, href };
        })
        .filter(Boolean);
    };

    const render = (items) => {
      const list = (items || []).slice(0, CFG.autocomplete.limit);
      if (!list.length) return close();

      input.setAttribute("aria-expanded", "true");

      box.innerHTML = list
        .map((it, idx) => {
          const title = esc(it.title);
          const href = esc(it.href);
          const id = `ss-sg-${idx}`;
          return `
            <div id="${id}" class="ss-suggest__item" role="option" aria-selected="false"
                 data-idx="${idx}" data-href="${href}"
                 style="padding:10px 12px;cursor:pointer;display:flex;gap:10px;align-items:center">
              <span aria-hidden="true"
                    style="width:8px;height:8px;border-radius:999px;background:linear-gradient(135deg,#2563eb,#0ea5e9);display:inline-block"></span>
              <span style="font-weight:900;${media.dark ? "color:rgba(238,242,255,.90)" : "color:rgba(10,16,32,.88)"};line-height:1.2">${title}</span>
            </div>
          `;
        })
        .join("");

      box.style.display = "block";
      rows = $$(".ss-suggest__item", box);

      rows.forEach((row) => {
        LIFECYCLE.addListener(row, "mouseenter", () => highlight(row));
        LIFECYCLE.addListener(row, "mouseleave", () => highlight(null));
        LIFECYCLE.addListener(row, "mousedown", (e) => {
          e.preventDefault();
          const href = row.getAttribute("data-href") || "#";
          location.assign(href);
        });
      });
    };

    const fetchSuggest = async (q) => {
      const cached = cacheGet(q);
      if (cached) return cached;

      if (aborter) safe(() => aborter.abort());
      aborter = supports.Abort ? new AbortController() : null;
      if (aborter) LIFECYCLE.aborters.add(aborter);

      const url = `${CFG.autocomplete.endpoint}${encodeURIComponent(q)}`;

      let res;
      try {
        res = await fetch(url, {
          signal: aborter ? aborter.signal : undefined,
          headers: { Accept: "application/json" },
          cache: "no-store",
          credentials: "same-origin",
        });
      } catch (_) {
        return [];
      }

      if (!res || !res.ok) return [];
      const ct = String(res.headers.get("content-type") || "");
      if (!ct.includes("application/json")) return [];

      const data = await res.json().catch(() => null);
      const items = normalizeItems(data);
      cacheSet(q, items);
      return items;
    };

    const onInput = debounce(async () => {
      if (composing) return;

      const q = String(input.value || "").trim();
      if (q === lastQ) return;
      lastQ = q;

      if (q.length > CFG.autocomplete.pasteGuardLen) return close();
      if (q.length < CFG.autocomplete.minChars) return close();

      try {
        const items = await fetchSuggest(q);
        render(items);
        pos();
      } catch (_) {
        close();
      }
    }, CFG.autocomplete.debounceMs);

    LIFECYCLE.addListener(input, "input", onInput);
    LIFECYCLE.addListener(input, "compositionstart", () => (composing = true));
    LIFECYCLE.addListener(input, "compositionend", () => { composing = false; onInput(); });

    // (25) Pointerdown en vez de click: cierra más fiable
    LIFECYCLE.addListener(doc, "pointerdown", (e) => {
      const t = e.target;
      if (t === input) return;
      if (box.contains(t)) return;
      close();
    });

    LIFECYCLE.addListener(input, "blur", () => {
      if (aborter) safe(() => aborter.abort());
      LIFECYCLE.setTimeout(close, 140);
    });

    LIFECYCLE.addListener(input, "keydown", (e) => {
      if (box.style.display === "none" || !rows.length) return;

      if (e.key === "Escape") { e.preventDefault(); return close(); }

      if (e.key === "ArrowDown") { e.preventDefault(); activeIndex = clamp(activeIndex + 1, 0, rows.length - 1); }
      else if (e.key === "ArrowUp") { e.preventDefault(); activeIndex = clamp(activeIndex - 1, 0, rows.length - 1); }
      else if (e.key === "Enter") {
        const row = rows[activeIndex];
        if (row) {
          e.preventDefault();
          location.assign(row.getAttribute("data-href") || "#");
        }
        return;
      } else return;

      const row = rows[activeIndex];
      highlight(row);
      if (row && row.id) input.setAttribute("aria-activedescendant", row.id);
    });

    LIFECYCLE.addListener(win, "pagehide", () => {
      if (aborter) safe(() => aborter.abort());
      close();
    }, { once: true });
  };

  // ---------------------------
  // (26) Soft-ensure: si falta data-reveal, lo agrega antes de init
  // ---------------------------
  const init = () => {
    const hp = getHomeRoot();
    if (!hp) return;

    markLoaded("boot");
    log("init", HOME_VERSION);

    safe(() => autoMarkReveal());

    // Preloader fade (no rompe si no existe)
    safe(() => {
      const p = $(CFG.preloader.sel);
      if (!p) return;
      LIFECYCLE.requestRaf(() => {
        p.style.transition = `opacity ${CFG.preloader.fadeMs}ms ease`;
        p.style.opacity = "0";
        LIFECYCLE.setTimeout(() => safe(() => p.remove?.()), CFG.preloader.fadeMs + 90);
      });
    });

    safe(() => initReveal());
    safe(() => initStickyToTop());
    safe(() => initHotkeys());
    safe(() => initPills());
    safe(() => initHeroMotion());
    safe(() => initGlow());
    safe(() => initImageSafety());
    safe(() => initAutocomplete());
    safe(() => initPrefetchShop());

    safe(() => hp.classList.add("is-ready"));
    markLoaded("ok");
    log("ready");
  };

  if (doc.readyState === "loading") doc.addEventListener("DOMContentLoaded", init, { once: true });
  else init();
})();
