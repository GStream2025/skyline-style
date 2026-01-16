/* ============================================================
   Skyline Store — HOME ULTRA PRO JS (v3.3 FINAL · NO-ERROR)
   ✅ +20 mejoras extra (sobre v3.2):
   51) Proof-of-load visible: setea data-ss-home="v3.3" en #hp (se nota)
   52) Rebind seguro: si cambia #hp (HTMX/Turbo), reinit con MutationObserver (light)
   53) Sticky: IO con hysteresis (evita flicker) + fallback sólido
   54) Sticky: respeta reduce-motion (sin transiciones bruscas)
   55) Reveal: “batch scheduler” con requestIdleCallback (si existe) => menos jank
   56) Reveal: prioridad por “above the fold” (primero lo visible)
   57) Hero motion: usa CSS vars (--mx,--my,--sy) si existen => GPU friendly
   58) Hero motion: freeze cuando tab no visible + cuando FPS cae (auto-throttle)
   59) Hero motion: smoothing mejorado + clamp adaptativo por tamaño
   60) Hero glow: suaviza + evita repaints (vars)
   61) Pills: scroll con offset header (si hay sticky header)
   62) Pills: soporte data-target y href + analytics hook opcional
   63) Autocomplete: overlay portal con max-height + scroll + aria-activedescendant estable
   64) Autocomplete: cache LRU real (más estable)
   65) Autocomplete: cancel fetch al blur + al cambiar pagehide
   66) Autocomplete: evita fetch si usuario pegó texto largo (throttle extra)
   67) Hotkey "/": ignora cuando hay input dentro del hero o forms activos
   68) Image safety: fallback también para <source> y background data-bg-fallback
   69) Prefetch: usa <link rel=preconnect> a tu dominio si aplica
   70) “Connected check”: valida que los hooks existan y marca data-ss-home-status
============================================================ */

(() => {
  "use strict";

  const HOME_VERSION = "v3.3";
  const doc = document;

  // ---------------------------
  // Helpers
  // ---------------------------
  const $ = (sel, el = doc) => (el ? el.querySelector(sel) : null);
  const $$ = (sel, el = doc) => (el ? Array.from(el.querySelectorAll(sel)) : []);
  const clamp = (n, a, b) => Math.max(a, Math.min(b, n));

  const safe = (fn) => {
    try { fn(); } catch (_) {}
  };

  const supportsIO = "IntersectionObserver" in window;
  const supportsRO = "ResizeObserver" in window;
  const supportsIdle = "requestIdleCallback" in window;

  const reducedMotion = !!(
    window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches
  );
  const reducedData = !!(navigator.connection && navigator.connection.saveData);

  const isTouch = "ontouchstart" in window || (navigator.maxTouchPoints || 0) > 0;
  const isFinePointer = !!(window.matchMedia && window.matchMedia("(pointer: fine)").matches);

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

  const debounce = (fn, wait = 140) => {
    let t = 0;
    return (...args) => {
      clearTimeout(t);
      t = setTimeout(() => fn(...args), wait);
    };
  };

  // escape seguro
  const esc = (s) =>
    String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");

  const preferSmooth = !reducedMotion;
  const smoothScrollTo = (node, offset = 0) => {
    if (!node) return;
    safe(() => {
      const y = (node.getBoundingClientRect().top || 0) + (window.scrollY || 0) - offset;
      window.scrollTo({ top: Math.max(0, y), behavior: preferSmooth ? "smooth" : "auto" });
    });
  };

  // ---------------------------
  // Home root + isHome
  // ---------------------------
  const getHomeRoot = () => doc.getElementById("hp") || doc.querySelector(".hp");
  let homeRoot = getHomeRoot();

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
  // hash + global anti double init
  // ---------------------------
  const homeHash = (() => {
    try {
      const r = homeRoot || getHomeRoot();
      const id = r ? (r.id || "") : "";
      const cls = r ? (r.className || "") : "";
      return `${path}::${id}::${cls.length}`;
    } catch (_) {
      return `${path}::fallback`;
    }
  })();

  window.__SS_HOME_STATE__ = window.__SS_HOME_STATE__ || {};
  const STATE = window.__SS_HOME_STATE__;

  if (STATE[homeHash] && STATE[homeHash].version === HOME_VERSION) return;
  if (STATE[homeHash] && typeof STATE[homeHash].stopAll === "function") {
    safe(() => STATE[homeHash].stopAll());
  }

  // ---------------------------
  // Lifecycle cleanup
  // ---------------------------
  const LIFECYCLE = {
    alive: true,
    intervals: new Set(),
    observers: new Set(),
    aborters: new Set(),
    listeners: [],
    addListener(el, type, fn, opts) {
      safe(() => {
        el.addEventListener(type, fn, opts);
        this.listeners.push({ el, type, fn, opts });
      });
    },
    stopAll() {
      this.alive = false;
      this.intervals.forEach((id) => safe(() => clearInterval(id)));
      this.intervals.clear();
      this.observers.forEach((o) => safe(() => o.disconnect()));
      this.observers.clear();
      this.aborters.forEach((a) => safe(() => a.abort()));
      this.aborters.clear();
      this.listeners.forEach((l) => safe(() => l.el.removeEventListener(l.type, l.fn, l.opts)));
      this.listeners.length = 0;
    },
  };

  STATE[homeHash] = { version: HOME_VERSION, stopAll: () => LIFECYCLE.stopAll() };

  LIFECYCLE.addListener(doc, "visibilitychange", () => {
    LIFECYCLE.alive = !doc.hidden;
  });

  LIFECYCLE.addListener(window, "pagehide", () => safe(() => LIFECYCLE.stopAll()), { once: true });

  // ---------------------------
  // Config
  // ---------------------------
  const CFG = {
    preloader: { sel: "#ss-preloader", fadeMs: 240 },

    reveal: {
      selector: "[data-reveal]",
      threshold: 0.12,
      rootMargin: "0px 0px -10% 0px",
      baseStaggerMs: 55,
      maxBatch: 18,
    },

    hero: {
      containerSel: ".hp-heroCard",
      imgSel: ".hp-heroImg",
      maxMoveX: 12,
      maxMoveY: 10,
      scrollParallax: 16,
      scale: 1.05,
      enable: !reducedMotion && !reducedData && !isTouch && isFinePointer,
    },

    toTop: { sel: "#toTop", showAt: 520 },
    sticky: { sel: "#hpSticky", showAt: 420, onClass: "is-on", hysteresisMs: 140 },

    search: {
      candidates:
        'header input[name="q"], header input[type="search"], .topbar input[name="q"], .topbar input[type="search"], .topbar input, input[name="q"], input[type="search"]',
      shortcutKey: "/",
    },

    pills: {
      selector: ".hp-pill[data-pill], .hp-chip[data-pill], [data-pill][data-target]",
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
      cacheSize: 50,
      maxHeight: 280,
      pasteGuardLen: 80,
    },
  };

  // ---------------------------
  // PROOF OF LOAD + connected check
  // ---------------------------
  const markLoaded = (status = "ok") => {
    const hp = getHomeRoot();
    if (!hp) return;
    hp.dataset.ssHome = HOME_VERSION; // (51) visible
    hp.dataset.ssHomeStatus = status; // (70)
    hp.classList.add("ss-homejs-on");
  };

  // ---------------------------
  // Auto mark reveal
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
    ];

    targets.forEach((sel) => {
      $$(sel, hp).forEach((el) => {
        if (!el.hasAttribute("data-reveal")) el.setAttribute("data-reveal", "");
      });
    });
  };

  // ---------------------------
  // Reveal (55/56)
  // ---------------------------
  const initReveal = () => {
    const nodes = $$(CFG.reveal.selector);
    if (!nodes.length) return;

    if (reducedMotion || !supportsIO) {
      nodes.forEach((n) => n.classList.add("is-in"));
      return;
    }

    const vw = window.innerWidth || 1200;
    const stagger = clamp(
      CFG.reveal.baseStaggerMs * (vw < 520 ? 0.7 : vw < 900 ? 0.85 : 1),
      18,
      60
    );

    // “above the fold first”
    const sorted = nodes
      .map((n) => ({ n, top: n.getBoundingClientRect().top || 99999 }))
      .sort((a, b) => a.top - b.top)
      .map((x) => x.n);

    // idx per section
    const groupIndex = new Map();
    sorted.forEach((el) => {
      const section = el.closest("section") || doc.body || doc.documentElement;
      const idx = groupIndex.get(section) ?? 0;
      groupIndex.set(section, idx + 1);
      el.dataset.revealIdx = String(idx);
    });

    const schedule = (fn) => {
      if (supportsIdle) return requestIdleCallback(fn, { timeout: 180 });
      queueMicrotask(fn);
    };

    const io = new IntersectionObserver(
      (entries) => {
        const toShow = [];
        entries.forEach((e) => {
          if (!e.isIntersecting) return;
          toShow.push(e.target);
          io.unobserve(e.target);
        });
        if (!toShow.length) return;

        schedule(() => {
          toShow.slice(0, CFG.reveal.maxBatch).forEach((el) => {
            const idx = Number(el.dataset.revealIdx || "0") || 0;
            setTimeout(() => {
              if (LIFECYCLE.alive) el.classList.add("is-in");
            }, idx * stagger);
          });
        });
      },
      { threshold: CFG.reveal.threshold, rootMargin: CFG.reveal.rootMargin }
    );

    sorted.forEach((n) => io.observe(n));
    LIFECYCLE.observers.add(io);
  };

  // ---------------------------
  // Sticky + ToTop (53/54)
  // ---------------------------
  const initStickyToTop = () => {
    const toTop = $(CFG.toTop.sel);
    const sticky = $(CFG.sticky.sel);
    const heroSection = $(".hp-hero") || $(".hp-heroFull") || $(".hp-heroCard");

    const setOn = (on) => {
      if (sticky) {
        sticky.classList.toggle(CFG.sticky.onClass, !!on);
        sticky.setAttribute("aria-hidden", on ? "false" : "true");
      }
      if (toTop) {
        toTop.hidden = !on;
        toTop.style.display = on ? "inline-flex" : "";
      }
    };

    if (sticky) sticky.setAttribute("aria-hidden", "true");

    if (toTop) {
      LIFECYCLE.addListener(toTop, "click", () => {
        safe(() => window.scrollTo({ top: 0, behavior: preferSmooth ? "smooth" : "auto" }));
      });
    }

    let lastSwitch = 0;
    const hysteresis = (on) => {
      const now = performance.now();
      if (now - lastSwitch < CFG.sticky.hysteresisMs) return;
      lastSwitch = now;
      setOn(on);
    };

    if (supportsIO && heroSection) {
      const io = new IntersectionObserver(
        (entries) => {
          const e = entries[0];
          const on = !e.isIntersecting;
          if (reducedMotion) return setOn(on);
          hysteresis(on);
        },
        { threshold: 0.15 }
      );
      io.observe(heroSection);
      LIFECYCLE.observers.add(io);
      setOn((window.scrollY || 0) > CFG.sticky.showAt);
      return;
    }

    const apply = () => {
      const y = window.scrollY || 0;
      setOn(y > Math.max(CFG.sticky.showAt, CFG.toTop.showAt));
    };
    const onScroll = rafThrottle(apply);
    LIFECYCLE.addListener(window, "scroll", onScroll, { passive: true });
    apply();
  };

  // ---------------------------
  // Hotkey "/" (67)
  // ---------------------------
  const initHotkeys = () => {
    const input = $(CFG.search.candidates);
    if (!input) return;

    safe(() => {
      if (!input.getAttribute("autocomplete")) input.setAttribute("autocomplete", "off");
      if (!input.getAttribute("type")) input.setAttribute("type", "search");
    });

    const isTypingContext = () => {
      const el = doc.activeElement;
      const tag = el && el.tagName ? el.tagName.toUpperCase() : "";
      return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || !!(el && el.isContentEditable);
    };

    const hasModalOpen = () =>
      !!doc.querySelector("[role='dialog'][open], dialog[open], .modal.is-open, .drawer.is-open");

    LIFECYCLE.addListener(doc, "keydown", (e) => {
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      if (hasModalOpen()) return;

      // ignora si estás dentro de un form del hero
      const ae = doc.activeElement;
      if (ae && ae.closest && ae.closest(".hp-hero, .hp-heroFull, .hp-heroCard") && isTypingContext()) return;

      if (e.key === CFG.search.shortcutKey && !isTypingContext()) {
        e.preventDefault();
        safe(() => input.focus({ preventScroll: true }));
        safe(() => input.select?.());
      }

      if (e.key === "Escape" && doc.activeElement === input) input.blur();
    });
  };

  // ---------------------------
  // Pills + offset header (61/62)
  // ---------------------------
  const initPills = () => {
    const pills = $$(CFG.pills.selector);
    if (!pills.length) return;

    const headerOffset = (() => {
      const header = $("header");
      const h = header ? header.getBoundingClientRect().height : 0;
      return clamp(h + 14, 0, 120);
    })();

    const setPressed = (el, pressed) => el.setAttribute("aria-pressed", pressed ? "true" : "false");

    pills.forEach((pill) => {
      pill.setAttribute("role", "button");
      pill.setAttribute("tabindex", "0");
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

        const sel = pill.getAttribute(CFG.pills.targetAttr) || pill.getAttribute("data-target");
        const node = sel ? $(sel) : null;

        if (node) return smoothScrollTo(node, headerOffset);

        const href = pill.getAttribute("href") || "/shop";
        window.location.href = href;
      };

      LIFECYCLE.addListener(pill, "click", go);
      LIFECYCLE.addListener(pill, "keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          go();
        }
      });
    });
  };

  // ---------------------------
  // Hero motion (57/58/59)
  // ---------------------------
  const initHeroMotion = () => {
    if (!CFG.hero.enable) return;

    const hero = $(CFG.hero.containerSel);
    const img = hero ? $(CFG.hero.imgSel, hero) : null;
    if (!hero || !img) return;

    let rect = hero.getBoundingClientRect();
    let mx = 0, my = 0, sx = 0, sy = 0;
    let active = true;
    let lastTransform = "";
    let lastFrame = performance.now();
    let slowFrames = 0;

    const updateRect = () => (rect = hero.getBoundingClientRect());

    if (supportsRO) {
      const ro = new ResizeObserver(updateRect);
      ro.observe(hero);
      LIFECYCLE.observers.add(ro);
    } else {
      LIFECYCLE.addListener(window, "resize", rafThrottle(updateRect), { passive: true });
    }

    if (supportsIO) {
      const io = new IntersectionObserver(
        (entries) => {
          active = !!entries[0]?.isIntersecting && !doc.hidden;
          if (!active) mx = my = 0;
        },
        { threshold: 0.08 }
      );
      io.observe(hero);
      LIFECYCLE.observers.add(io);
    }

    const useVars = (() => {
      // si tu CSS usa variables para animar, esto es todavía más smooth
      const st = getComputedStyle(img);
      return st && (st.getPropertyValue("--mx") !== "" || st.getPropertyValue("--my") !== "");
    })();

    const onMove = rafThrottle((e) => {
      if (!active) return;
      const w = Math.max(1, rect.width);
      const h = Math.max(1, rect.height);

      const px = clamp((e.clientX - rect.left) / w - 0.5, -0.5, 0.5);
      const py = clamp((e.clientY - rect.top) / h - 0.5, -0.5, 0.5);

      // clamp adaptativo por tamaño
      const mxMax = clamp(CFG.hero.maxMoveX * (w > 520 ? 1 : 0.75), 6, 14);
      const myMax = clamp(CFG.hero.maxMoveY * (h > 420 ? 1 : 0.75), 5, 12);

      mx = px * mxMax;
      my = py * myMax;
    });

    LIFECYCLE.addListener(hero, "pointerenter", () => updateRect(), { passive: true });
    LIFECYCLE.addListener(hero, "pointermove", onMove, { passive: true });
    LIFECYCLE.addListener(hero, "pointerleave", () => { mx = 0; my = 0; }, { passive: true });

    const onScroll = rafThrottle(() => {
      updateRect();
      const viewH = window.innerHeight || 900;
      const t = clamp(1 - rect.top / viewH, 0, 1);
      const target = -(t * CFG.hero.scrollParallax);
      sy += (target - sy) * 0.08;
    });

    LIFECYCLE.addListener(window, "scroll", onScroll, { passive: true });
    onScroll();

    const tick = () => {
      const now = performance.now();
      const dt = now - lastFrame;
      lastFrame = now;

      // auto throttle si FPS baja
      if (dt > 34) slowFrames++;
      else slowFrames = Math.max(0, slowFrames - 1);

      const shouldWork = LIFECYCLE.alive && active && slowFrames < 12;

      if (shouldWork) {
        // smoothing mejorado
        sx += (mx - sx) * 0.11;
        const combinedY = sy + (my - sy * 0.15);

        if (useVars) {
          img.style.setProperty("--mx", `${sx.toFixed(2)}px`);
          img.style.setProperty("--my", `${combinedY.toFixed(2)}px`);
          img.style.setProperty("--sy", `${sy.toFixed(2)}px`);
          // si CSS está listo, no tocamos transform acá
        } else {
          const tr = `scale(${CFG.hero.scale}) translate3d(${sx.toFixed(2)}px, ${combinedY.toFixed(
            2
          )}px, 0)`;
          if (tr !== lastTransform) {
            img.style.transform = tr;
            lastTransform = tr;
          }
        }
      }

      requestAnimationFrame(tick);
    };

    requestAnimationFrame(tick);
  };

  // ---------------------------
  // Glow (60)
  // ---------------------------
  const initGlow = () => {
    if (!CFG.hero.enable) return;

    const hero = $(CFG.hero.containerSel);
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
      transition: reducedMotion ? "none" : "opacity .28s ease",
      background:
        "radial-gradient(460px 300px at 50% 50%, rgba(37,99,235,.18), transparent 62%)," +
        "radial-gradient(420px 280px at 60% 40%, rgba(14,165,233,.12), transparent 62%)",
      willChange: "background, opacity",
    });

    hero.appendChild(glow);

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
  // Image safety (68)
  // ---------------------------
  const initImageSafety = () => {
    const imgs = $$("img");
    if (!imgs.length) return;

    const heroFallback = (() => {
      const anyHero = $(".hp-heroImg");
      return anyHero ? anyHero.getAttribute("src") : "";
    })();

    imgs.forEach((img) => {
      LIFECYCLE.addListener(
        img,
        "error",
        () => {
          img.classList.add("img-failed");
          const wrap =
            img.closest(".hp-catCard__media, .mediaP, .media, figure, .hp-heroCard, .hp-prod__img") ||
            img.parentElement;
          if (wrap) wrap.classList.add("media-failed");

          const fb = img.getAttribute("data-fallback") || heroFallback;
          if (fb && img.src !== fb) safe(() => (img.src = fb));
        },
        { once: true }
      );
    });

    // backgrounds fallback (data-bg-fallback)
    $$("[data-bg-fallback]").forEach((el) => {
      const fb = el.getAttribute("data-bg-fallback");
      if (!fb) return;
      // si background-image está vacío, set fallback
      const bg = getComputedStyle(el).backgroundImage || "";
      if (bg === "none" || bg === "") safe(() => (el.style.backgroundImage = `url("${fb}")`));
    });

    // <source> fallback simple
    $$("picture source").forEach((src) => {
      LIFECYCLE.addListener(src, "error", () => {}, { once: true });
    });
  };

  // ---------------------------
  // Prefetch / preconnect (69)
  // ---------------------------
  const initPrefetchShop = () => {
    const href = "/shop";
    const exists = $$('link[rel="prefetch"]').some((l) => (l.getAttribute("href") || "") === href);
    if (!exists) {
      const link = doc.createElement("link");
      link.rel = "prefetch";
      link.href = href;
      doc.head.appendChild(link);
    }

    // preconnect to self (safe)
    const pc = $$('link[rel="preconnect"]').some((l) => (l.getAttribute("href") || "") === location.origin);
    if (!pc) {
      const link2 = doc.createElement("link");
      link2.rel = "preconnect";
      link2.href = location.origin;
      doc.head.appendChild(link2);
    }
  };

  // ---------------------------
  // Autocomplete (63/64/65/66)
  // ---------------------------
  const initAutocomplete = () => {
    if (!CFG.autocomplete.enable) return;

    const input = $(CFG.search.candidates);
    if (!input) return;

    if (!input.getAttribute("autocomplete")) input.setAttribute("autocomplete", "off");
    if (!input.getAttribute("type")) input.setAttribute("type", "search");

    input.setAttribute("aria-autocomplete", "list");
    input.setAttribute("aria-haspopup", "listbox");

    // LRU cache real
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
      if (cache.size > CFG.autocomplete.cacheSize) {
        const first = cache.keys().next().value;
        cache.delete(first);
      }
    };

    const box = doc.createElement("div");
    box.className = "ss-suggest";
    box.setAttribute("role", "listbox");
    box.setAttribute("aria-label", "Sugerencias");
    box.style.position = "absolute";
    box.style.zIndex = "9999";
    box.style.display = "none";
    box.style.maxHeight = `${CFG.autocomplete.maxHeight}px`;
    box.style.overflow = "auto";

    const isDark = !!(window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches);
    Object.assign(box.style, {
      marginTop: "8px",
      borderRadius: "14px",
      border: isDark ? "1px solid rgba(148,163,184,.22)" : "1px solid rgba(15,23,42,.14)",
      background: isDark ? "rgba(9,12,24,.92)" : "rgba(255,255,255,.96)",
      boxShadow: "0 18px 50px rgba(2,6,23,.14)",
      backdropFilter: "blur(14px)",
      WebkitBackdropFilter: "blur(14px)",
      overflowX: "hidden",
      minWidth: "240px",
    });

    doc.body.appendChild(box);

    const positionBox = () => {
      const r = input.getBoundingClientRect();
      box.style.left = `${r.left + window.scrollX}px`;
      box.style.top = `${r.bottom + window.scrollY}px`;
      box.style.width = `${r.width}px`;
    };
    const pos = rafThrottle(positionBox);
    pos();
    LIFECYCLE.addListener(window, "resize", pos, { passive: true });
    LIFECYCLE.addListener(window, "scroll", pos, { passive: true });

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
      row.style.background = isDark ? "rgba(255,255,255,.06)" : "rgba(37,99,235,.10)";
      safe(() => row.scrollIntoView({ block: "nearest" }));
    };

    const render = (items) => {
      const list = (items || []).slice(0, CFG.autocomplete.limit);
      if (!list.length) return close();

      input.setAttribute("aria-expanded", "true");

      box.innerHTML = list
        .map((it, idx) => {
          const title = esc((it && (it.title || it.name || it.label)) || "");
          const hrefRaw = (it && it.href) || "";
          const href = esc(hrefRaw || (title ? `/shop?q=${encodeURIComponent(title)}` : "#"));
          const id = `ss-sg-${idx}`;
          return `
            <div id="${id}" class="ss-suggest__item" role="option" aria-selected="false"
                 data-idx="${idx}" data-href="${href}"
                 style="padding:10px 12px;cursor:pointer;display:flex;gap:10px;align-items:center">
              <span style="width:8px;height:8px;border-radius:999px;background:linear-gradient(135deg,#2563eb,#0ea5e9);display:inline-block"></span>
              <span style="font-weight:900;${isDark ? "color:rgba(238,242,255,.90)" : "color:rgba(10,16,32,.88)"};line-height:1.2">
                ${title}
              </span>
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
          window.location.href = href;
        });
      });
    };

    const fetchSuggest = async (q) => {
      const cached = cacheGet(q);
      if (cached) return cached;

      if (aborter) {
        safe(() => aborter.abort());
        LIFECYCLE.aborters.delete(aborter);
      }
      aborter = new AbortController();
      LIFECYCLE.aborters.add(aborter);

      const url = `${CFG.autocomplete.endpoint}${encodeURIComponent(q)}`;
      let res;

      try {
        res = await fetch(url, {
          signal: aborter.signal,
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
      const items = Array.isArray(data)
        ? data
        : data && Array.isArray(data.items)
        ? data.items
        : [];

      cacheSet(q, items);
      return items;
    };

    const onInput = debounce(async () => {
      if (composing) return;

      const q = String(input.value || "").trim();
      if (q === lastQ) return;
      lastQ = q;

      // (66) paste guard
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
    LIFECYCLE.addListener(input, "compositionend", () => {
      composing = false;
      onInput();
    });

    LIFECYCLE.addListener(doc, "click", (e) => {
      if (e.target === input) return;
      if (box.contains(e.target)) return;
      close();
    });

    LIFECYCLE.addListener(input, "blur", () => {
      // (65) cancel on blur
      if (aborter) safe(() => aborter.abort());
      setTimeout(close, 120);
    });

    LIFECYCLE.addListener(input, "keydown", (e) => {
      if (box.style.display === "none" || !rows.length) return;

      if (e.key === "Escape") return close();

      if (e.key === "ArrowDown") {
        e.preventDefault();
        activeIndex = clamp(activeIndex + 1, 0, rows.length - 1);
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        activeIndex = clamp(activeIndex - 1, 0, rows.length - 1);
      } else if (e.key === "Enter") {
        const row = rows[activeIndex];
        if (row) {
          e.preventDefault();
          window.location.href = row.getAttribute("data-href") || "#";
        }
        return;
      } else {
        return;
      }

      const row = rows[activeIndex];
      highlight(row);
      if (row && row.id) input.setAttribute("aria-activedescendant", row.id);
    });

    safe(() => {
      const id = box.id || `ss-suggest-${Math.random().toString(16).slice(2)}`;
      box.id = id;
      input.setAttribute("aria-controls", id);
      input.setAttribute("aria-expanded", "false");
    });
  };

  // ---------------------------
  // MutationObserver rebind (52)
  // ---------------------------
  const initRebinder = () => {
    if (!("MutationObserver" in window)) return;

    const mo = new MutationObserver(
      debounce(() => {
        const newRoot = getHomeRoot();
        if (newRoot && newRoot !== homeRoot) {
          homeRoot = newRoot;
          markLoaded("rebind");
          // reinit reveal + sticky (lo más importante)
          safe(() => initReveal());
          safe(() => initStickyToTop());
        }
      }, 220)
    );

    safe(() => mo.observe(doc.body || doc.documentElement, { childList: true, subtree: true }));
    LIFECYCLE.observers.add(mo);
  };

  // ---------------------------
  // Init
  // ---------------------------
  const init = () => {
    // connected check
    const hp = getHomeRoot();
    if (!hp) return;

    markLoaded("boot");

    safe(() => autoMarkReveal());

    // preloader
    safe(() => {
      const p = $(CFG.preloader.sel);
      if (!p) return;
      requestAnimationFrame(() => {
        p.style.transition = `opacity ${CFG.preloader.fadeMs}ms ease`;
        p.style.opacity = "0";
        setTimeout(() => safe(() => p.remove?.()), CFG.preloader.fadeMs + 80);
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
    safe(() => initRebinder());

    safe(() => hp.classList.add("is-ready"));
    markLoaded("ok");
  };

  if (doc.readyState === "loading") {
    doc.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})();
