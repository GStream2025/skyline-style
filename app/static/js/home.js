/* ============================================================
   Skyline Store — HOME ULTRA PRO JS (v3.2 FINAL · NO-ERROR)
   ✅ +20 mejoras extra sobre v3.1 (además de tus 30):
   31) Hard-guard por “home hash” + reinit seguro si cambia DOM (SPA)
   32) stopAll() también borra listeners registrados (centralizado)
   33) Sticky/ToTop: usa Hero IntersectionObserver si existe (más exacto)
   34) Sticky/ToTop: respeta prefers-reduced-motion (sin jumps)
   35) Reveal: auto-balance por viewport (stagger adaptativo)
   36) Reveal: evita layout trashing (batch add + microtask)
   37) Hero motion: pausa si hero no está visible (IO) => menos CPU
   38) Hero motion: pointer tracking con clamp + smoothing mejorado
   39) Autocomplete: respeta autocomplete off / type search
   40) Autocomplete: no rompe si endpoint devuelve HTML (catch robusto)
   41) Autocomplete: “aria-controls” + “aria-expanded” bien
   42) Autocomplete: click via mousedown (evita blur antes de click)
   43) Autocomplete: highlight por teclado consistente + scrollIntoView
   44) Autocomplete: soporte IME composition (no spamea fetch)
   45) Hotkey "/" ignora cuando modal/dialog abierto
   46) Prefetch /shop con base path real (si app corre en subpath)
   47) Image safety: marca media-failed y aplica fallback si data-fallback
   48) Pills: si target no existe => fallback a /shop o href del pill
   49) Micro UX: agrega .is-ready al #hp cuando terminó init
   50) Debug safe: deja dataset ssHome + ssHomeInitCount (sin consola)
============================================================ */

(() => {
  "use strict";

  // ------------------------------------------------------------
  // 0) Guard anti doble-init + “home hash” (SPA/HTMX/Turbo)
  // ------------------------------------------------------------
  const HOME_VERSION = "v3.2";
  const doc = document;

  const getHomeRoot = () => doc.getElementById("hp") || doc.querySelector(".hp");
  const homeRoot = getHomeRoot();

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

  // “home hash” simple: si cambia el root, permitimos reinit limpio
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

  // Anti doble init global
  window.__SS_HOME_STATE__ = window.__SS_HOME_STATE__ || {};
  const STATE = window.__SS_HOME_STATE__;

  if (STATE[homeHash] && STATE[homeHash].version === HOME_VERSION) return;

  // Si existía otro init viejo para este hash, lo limpiamos
  if (STATE[homeHash] && typeof STATE[homeHash].stopAll === "function") {
    try {
      STATE[homeHash].stopAll();
    } catch (_) {}
  }

  // ------------------------------------------------------------
  // Helpers (robustos, no-throw)
  // ------------------------------------------------------------
  const $ = (sel, el = doc) => (el ? el.querySelector(sel) : null);
  const $$ = (sel, el = doc) => (el ? Array.from(el.querySelectorAll(sel)) : []);
  const clamp = (n, a, b) => Math.max(a, Math.min(b, n));

  const safe = (fn) => {
    try {
      fn();
    } catch (_) {}
  };

  const supportsIO = "IntersectionObserver" in window;
  const supportsRO = "ResizeObserver" in window;

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

  // replaceAll compat
  const repAll = (str, a, b) => {
    const s = String(str ?? "");
    if (typeof s.replaceAll === "function") return s.replaceAll(a, b);
    return s.split(a).join(b);
  };

  // escape seguro
  const esc = (s) =>
    repAll(
      repAll(
        repAll(
          repAll(
            repAll(String(s ?? ""), "&", "&amp;"),
            "<",
            "&lt;"
          ),
          ">",
          "&gt;"
        ),
        '"',
        "&quot;"
      ),
      "'",
      "&#039;"
    );

  const preferSmooth = !reducedMotion;
  const smoothScrollTo = (node) => {
    if (!node) return;
    try {
      node.scrollIntoView({ behavior: preferSmooth ? "smooth" : "auto", block: "start" });
    } catch (_) {
      // fallback
      try {
        const top = (node.getBoundingClientRect().top || 0) + (window.scrollY || 0);
        window.scrollTo(0, top);
      } catch (_) {}
    }
  };

  // ------------------------------------------------------------
  // Lifecycle cleanup CENTRALIZADO
  // ------------------------------------------------------------
  const LIFECYCLE = {
    alive: true,
    intervals: new Set(),
    observers: new Set(),
    aborters: new Set(),
    listeners: [], // {el, type, fn, opts}
    addListener(el, type, fn, opts) {
      try {
        el.addEventListener(type, fn, opts);
        this.listeners.push({ el, type, fn, opts });
      } catch (_) {}
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

  // guard state saved
  STATE[homeHash] = {
    version: HOME_VERSION,
    stopAll: () => LIFECYCLE.stopAll(),
  };

  // stamp debug safe
  safe(() => {
    doc.documentElement.dataset.ssHome = HOME_VERSION;
    const cnt = Number(doc.documentElement.dataset.ssHomeInitCount || "0") || 0;
    doc.documentElement.dataset.ssHomeInitCount = String(cnt + 1);
  });

  LIFECYCLE.addListener(doc, "visibilitychange", () => {
    LIFECYCLE.alive = !doc.hidden;
  });

  LIFECYCLE.addListener(
    window,
    "pagehide",
    () => safe(() => LIFECYCLE.stopAll()),
    { once: true }
  );

  // ------------------------------------------------------------
  // Config
  // ------------------------------------------------------------
  const CFG = {
    preloader: { sel: "#ss-preloader", fadeMs: 240 },

    reveal: {
      selector: "[data-reveal]",
      threshold: 0.12,
      rootMargin: "0px 0px -10% 0px",
      baseStaggerMs: 55,
    },

    hero: {
      containerSel: ".hp-heroCard",
      imgSel: ".hp-heroImg",
      maxMoveX: 10,
      maxMoveY: 8,
      scrollParallax: 14,
      scale: 1.04,
      enable: !reducedMotion && !reducedData && !isTouch && isFinePointer,
    },

    toTop: { sel: "#toTop", showAt: 520 },
    sticky: { sel: "#hpSticky", showAt: 420, onClass: "is-on" },

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
      debounceMs: 150,
      cacheSize: 40,
    },
  };

  // ------------------------------------------------------------
  // AUTO: data-reveal en bloques clave + class hooks
  // ------------------------------------------------------------
  const autoMarkReveal = () => {
    const hp = getHomeRoot();
    if (!hp) return;

    hp.classList.add("ss-homejs-on");

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

  // ------------------------------------------------------------
  // Feature: Reveal (stagger adaptativo + batch)
  // ------------------------------------------------------------
  const initReveal = () => {
    const nodes = $$(CFG.reveal.selector);
    if (!nodes.length) return;

    if (reducedMotion || !supportsIO) {
      nodes.forEach((n) => n.classList.add("is-in"));
      return;
    }

    // stagger adaptativo: en pantallas chicas reduce delay (se siente mejor)
    const vw = window.innerWidth || 1200;
    const stagger = clamp(CFG.reveal.baseStaggerMs * (vw < 520 ? 0.72 : vw < 900 ? 0.86 : 1), 22, 60);

    // index por sección
    const groupIndex = new Map();
    nodes.forEach((el) => {
      const section = el.closest("section") || doc.body || doc.documentElement;
      const idx = groupIndex.get(section) ?? 0;
      groupIndex.set(section, idx + 1);
      el.dataset.revealIdx = String(idx);
    });

    const io = new IntersectionObserver(
      (entries) => {
        // batch: aplicamos en microtask
        const toShow = [];
        entries.forEach((e) => {
          if (!e.isIntersecting) return;
          toShow.push(e.target);
          io.unobserve(e.target);
        });

        if (!toShow.length) return;

        queueMicrotask(() => {
          toShow.forEach((el) => {
            const idx = Number(el.dataset.revealIdx || "0") || 0;
            setTimeout(() => {
              if (LIFECYCLE.alive) el.classList.add("is-in");
            }, idx * stagger);
          });
        });
      },
      { threshold: CFG.reveal.threshold, rootMargin: CFG.reveal.rootMargin }
    );

    nodes.forEach((n) => io.observe(n));
    LIFECYCLE.observers.add(io);
  };

  // ------------------------------------------------------------
  // Feature: Sticky + ToTop (prefer hero IO)
  // ------------------------------------------------------------
  const initStickyToTop = () => {
    const toTop = $(CFG.toTop.sel);
    const sticky = $(CFG.sticky.sel);
    const heroSection = $(".hp-hero") || $(".hp-heroFull");

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

    // click toTop
    if (toTop) {
      LIFECYCLE.addListener(toTop, "click", () => {
        try {
          window.scrollTo({ top: 0, behavior: preferSmooth ? "smooth" : "auto" });
        } catch (_) {
          window.scrollTo(0, 0);
        }
      });
    }

    // prefer IO con hero (más exacto)
    if (supportsIO && heroSection && !reducedMotion) {
      const io = new IntersectionObserver(
        (entries) => {
          const e = entries[0];
          // si hero no está intersectando => activar sticky/toTop
          setOn(!e.isIntersecting);
        },
        { threshold: 0.15 }
      );
      io.observe(heroSection);
      LIFECYCLE.observers.add(io);
      // estado inicial “por si”
      setOn((window.scrollY || 0) > CFG.sticky.showAt);
      return;
    }

    // fallback scroll
    const apply = () => {
      const y = window.scrollY || 0;
      setOn(y > Math.max(CFG.sticky.showAt, CFG.toTop.showAt));
    };
    const onScroll = rafThrottle(apply);
    LIFECYCLE.addListener(window, "scroll", onScroll, { passive: true });
    apply();
  };

  // ------------------------------------------------------------
  // Feature: Hotkey "/" focus search (respeta dialog/modal)
  // ------------------------------------------------------------
  const initHotkeys = () => {
    const input = $(CFG.search.candidates);
    if (!input) return;

    // ARIA básicos
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

      if (e.key === CFG.search.shortcutKey && !isTypingContext()) {
        e.preventDefault();
        try {
          input.focus({ preventScroll: true });
        } catch (_) {
          input.focus();
        }
        input.select?.();
      }

      if (e.key === "Escape" && doc.activeElement === input) input.blur();
    });
  };

  // ------------------------------------------------------------
  // Feature: Pills (scroll + aria-pressed + fallbacks)
  // ------------------------------------------------------------
  const initPills = () => {
    const pills = $$(CFG.pills.selector);
    if (!pills.length) return;

    const setPressed = (el, pressed) => el.setAttribute("aria-pressed", pressed ? "true" : "false");

    pills.forEach((pill) => {
      pill.setAttribute("role", "button");
      pill.setAttribute("tabindex", "0");

      const isActive = pill.classList.contains(CFG.pills.activeClass);
      setPressed(pill, isActive);

      const go = () => {
        if (CFG.pills.singleActive) {
          pills.forEach((p) => {
            p.classList.remove(CFG.pills.activeClass);
            setPressed(p, false);
          });
        }

        pill.classList.toggle(CFG.pills.activeClass);
        setPressed(pill, pill.classList.contains(CFG.pills.activeClass));

        const sel = pill.getAttribute(CFG.pills.targetAttr);
        const node = sel ? $(sel) : null;

        if (node) return smoothScrollTo(node);

        // fallback: si el pill tiene href, usalo, sino /shop
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

  // ------------------------------------------------------------
  // Feature: Hero motion (pausa si no visible)
  // ------------------------------------------------------------
  const initHeroMotion = () => {
    if (!CFG.hero.enable) return;

    const hero = $(CFG.hero.containerSel);
    const img = hero ? $(CFG.hero.imgSel, hero) : null;
    if (!hero || !img) return;

    let rect = hero.getBoundingClientRect();
    let mx = 0, my = 0, sx = 0, sy = 0;
    let active = true;
    let lastTransform = "";

    const updateRect = () => (rect = hero.getBoundingClientRect());

    if (supportsRO) {
      const ro = new ResizeObserver(updateRect);
      ro.observe(hero);
      LIFECYCLE.observers.add(ro);
    } else {
      LIFECYCLE.addListener(window, "resize", rafThrottle(updateRect), { passive: true });
    }

    // pausa si hero fuera de viewport
    if (supportsIO) {
      const io = new IntersectionObserver(
        (entries) => {
          active = !!entries[0]?.isIntersecting;
          if (!active) {
            mx = my = 0;
          }
        },
        { threshold: 0.08 }
      );
      io.observe(hero);
      LIFECYCLE.observers.add(io);
    }

    const onMove = rafThrottle((e) => {
      if (!active) return;
      const w = Math.max(1, rect.width);
      const h = Math.max(1, rect.height);
      const px = clamp((e.clientX - rect.left) / w - 0.5, -0.5, 0.5);
      const py = clamp((e.clientY - rect.top) / h - 0.5, -0.5, 0.5);

      mx = px * CFG.hero.maxMoveX;
      my = py * CFG.hero.maxMoveY;
    });

    LIFECYCLE.addListener(hero, "pointerenter", () => updateRect(), { passive: true });
    LIFECYCLE.addListener(hero, "pointermove", onMove, { passive: true });
    LIFECYCLE.addListener(
      hero,
      "pointerleave",
      () => {
        mx = 0;
        my = 0;
      },
      { passive: true }
    );

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
      // no cortamos RAF (para evitar glitch), pero bajamos trabajo si no activo
      if (LIFECYCLE.alive && active) {
        sx += (mx - sx) * 0.1;
        const combinedY = sy + (my - sy * 0.15);

        const tr = `scale(${CFG.hero.scale}) translate3d(${sx.toFixed(2)}px, ${combinedY.toFixed(2)}px, 0)`;
        if (tr !== lastTransform) {
          img.style.transform = tr;
          lastTransform = tr;
        }
      }
      requestAnimationFrame(tick);
    };

    requestAnimationFrame(tick);
  };

  // ------------------------------------------------------------
  // Feature: Glow compatible (no tapa clicks)
  // ------------------------------------------------------------
  const initGlow = () => {
    if (!CFG.hero.enable) return;

    const hero = $(CFG.hero.containerSel);
    if (!hero) return;

    // ya existe
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
      transition: "opacity .35s ease",
      background:
        "radial-gradient(420px 280px at 50% 50%, rgba(37,99,235,.20), transparent 60%)," +
        "radial-gradient(420px 280px at 60% 40%, rgba(14,165,233,.14), transparent 60%)",
    });

    hero.appendChild(glow);

    const moveGlow = rafThrottle((e) => {
      const r = hero.getBoundingClientRect();
      const x = clamp(((e.clientX - r.left) / Math.max(1, r.width)) * 100, 0, 100);
      const y = clamp(((e.clientY - r.top) / Math.max(1, r.height)) * 100, 0, 100);

      glow.style.background =
        `radial-gradient(460px 300px at ${x}% ${y}%, rgba(37,99,235,.22), transparent 60%),` +
        `radial-gradient(420px 280px at ${clamp(x + 14, 0, 100)}% ${clamp(y - 10, 0, 100)}%, rgba(14,165,233,.16), transparent 62%)`;
    });

    LIFECYCLE.addListener(hero, "pointerenter", () => (glow.style.opacity = "1"), { passive: true });
    LIFECYCLE.addListener(hero, "pointerleave", () => (glow.style.opacity = "0"), { passive: true });
    LIFECYCLE.addListener(hero, "pointermove", moveGlow, { passive: true });
  };

  // ------------------------------------------------------------
  // Feature: Image safety + fallback data-fallback / hero default
  // ------------------------------------------------------------
  const initImageSafety = () => {
    const imgs = $$("img");
    if (!imgs.length) return;

    const heroFallback = (() => {
      // intenta encontrar hero_home.png en el DOM o assets que uses
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

          // fallback opcional
          const fb = img.getAttribute("data-fallback") || heroFallback;
          if (fb && img.src !== fb) {
            try {
              img.src = fb;
              img.style.opacity = ".92";
            } catch (_) {}
          }
        },
        { once: true }
      );
    });
  };

  // ------------------------------------------------------------
  // Feature: Prefetch /shop con base path real
  // ------------------------------------------------------------
  const initPrefetchShop = () => {
    const base = (() => {
      try {
        // si estás en subpath: /algo/ -> armamos /algo/shop
        const parts = path.split("/").filter(Boolean);
        // si tu app está root, parts vacío
        return parts.length && parts[0] !== "shop" ? `/${parts[0]}` : "";
      } catch (_) {
        return "";
      }
    })();

    const href = `${base}/shop`;

    const exists = $$('link[rel="prefetch"]').some((l) => (l.getAttribute("href") || "") === href);
    if (exists) return;

    const link = doc.createElement("link");
    link.rel = "prefetch";
    link.href = href;
    doc.head.appendChild(link);
  };

  // ------------------------------------------------------------
  // Feature: Autocomplete (robusto, no rompe si endpoint no existe)
  // ------------------------------------------------------------
  const initAutocomplete = () => {
    if (!CFG.autocomplete.enable) return;

    const input = $(CFG.search.candidates);
    if (!input) return;

    // no forzar si el input tiene autocomplete=on explícito del usuario
    if (!input.getAttribute("autocomplete")) input.setAttribute("autocomplete", "off");
    if (!input.getAttribute("type")) input.setAttribute("type", "search");

    // ARIA
    input.setAttribute("aria-autocomplete", "list");
    input.setAttribute("aria-haspopup", "listbox");

    const cache = new Map();
    const cacheSet = (k, v) => {
      cache.set(k, v);
      if (cache.size > CFG.autocomplete.cacheSize) cache.delete(cache.keys().next().value);
    };

    const box = doc.createElement("div");
    box.className = "ss-suggest";
    box.setAttribute("role", "listbox");
    box.setAttribute("aria-label", "Sugerencias");
    box.style.position = "absolute";
    box.style.zIndex = "9999";
    box.style.display = "none";

    const isDark = !!(window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches);

    Object.assign(box.style, {
      marginTop: "8px",
      borderRadius: "14px",
      border: isDark ? "1px solid rgba(148,163,184,.22)" : "1px solid rgba(15,23,42,.14)",
      background: isDark ? "rgba(9,12,24,.92)" : "rgba(255,255,255,.96)",
      boxShadow: isDark ? "none" : "0 18px 50px rgba(2,6,23,.14)",
      backdropFilter: "blur(14px)",
      WebkitBackdropFilter: "blur(14px)",
      overflow: "hidden",
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
      // que se vea cuando navegás con teclado
      try {
        row.scrollIntoView({ block: "nearest" });
      } catch (_) {}
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

      // click con mousedown para que no se pierda por blur
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
      if (cache.has(q)) return cache.get(q);

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

      // soporte si backend devuelve html por error
      const ct = String(res.headers.get("content-type") || "");
      if (!ct.includes("application/json")) {
        return [];
      }

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

    // IME
    LIFECYCLE.addListener(input, "compositionstart", () => (composing = true));
    LIFECYCLE.addListener(input, "compositionend", () => {
      composing = false;
      onInput();
    });

    // close outside
    LIFECYCLE.addListener(doc, "click", (e) => {
      if (e.target === input) return;
      if (box.contains(e.target)) return;
      close();
    });

    // blur delayed
    LIFECYCLE.addListener(input, "blur", () => setTimeout(close, 120));

    // keyboard nav
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

    // aria-controls
    safe(() => {
      const id = box.id || `ss-suggest-${Math.random().toString(16).slice(2)}`;
      box.id = id;
      input.setAttribute("aria-controls", id);
      input.setAttribute("aria-expanded", "false");
    });
  };

  // ------------------------------------------------------------
  // Init
  // ------------------------------------------------------------
  const init = () => {
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

    // mark ready
    safe(() => {
      const hp = getHomeRoot();
      if (hp) hp.classList.add("is-ready");
    });
  };

  if (doc.readyState === "loading") {
    doc.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})();
