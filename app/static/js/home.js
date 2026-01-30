(() => {
  "use strict";

  const HOME_VERSION = "v3.4";
  const doc = document;

  // ---------------------------
  // Helpers
  // ---------------------------
  const safe = (fn) => { try { return fn(); } catch (_) { return undefined; } };
  const $ = (sel, el = doc) => (el ? el.querySelector(sel) : null);
  const $$ = (sel, el = doc) => (el ? Array.from(el.querySelectorAll(sel)) : []);
  const clamp = (n, a, b) => Math.max(a, Math.min(b, n));
  const nowMs = () => (typeof performance !== "undefined" && performance.now ? performance.now() : Date.now());

  const supports = {
    IO: "IntersectionObserver" in window,
    RO: "ResizeObserver" in window,
    Idle: "requestIdleCallback" in window,
    Abort: "AbortController" in window,
    Microtask: "queueMicrotask" in window,
    RAF: "requestAnimationFrame" in window,
    MO: "MutationObserver" in window,
  };

  const raf = (cb) => {
    const r = window.requestAnimationFrame;
    if (typeof r === "function") return r(cb);
    return window.setTimeout(cb, 16);
  };

  const caf = (id) => {
    const c = window.cancelAnimationFrame;
    if (typeof c === "function") return c(id);
    clearTimeout(id);
  };

  const microtask = (fn) => {
    if (supports.Microtask) return queueMicrotask(fn);
    Promise.resolve().then(fn).catch(() => {});
  };

  const rafThrottle = (fn) => {
    let id = 0;
    return (...args) => {
      if (id) return;
      id = raf(() => {
        id = 0;
        fn(...args);
      });
    };
  };

  const debounce = (fn, wait = 160) => {
    let t = 0;
    return (...args) => {
      clearTimeout(t);
      t = setTimeout(() => fn(...args), wait);
    };
  };

  const esc = (s) =>
    String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");

  const reducedMotion = !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  const reducedData = !!(navigator.connection && navigator.connection.saveData);
  const preferSmooth = !reducedMotion;

  const smoothScrollTo = (node, offset = 0) => {
    if (!node) return;
    safe(() => {
      const y = (node.getBoundingClientRect().top || 0) + (window.scrollY || 0) - offset;
      window.scrollTo({ top: Math.max(0, y), behavior: preferSmooth ? "smooth" : "auto" });
    });
  };

  const isTouch = "ontouchstart" in window || (navigator.maxTouchPoints || 0) > 0;
  const isFinePointer = !!(window.matchMedia && window.matchMedia("(pointer: fine)").matches);

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
  // global init guard (per DOM signature)
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
  if (STATE[homeHash] && typeof STATE[homeHash].stopAll === "function") safe(() => STATE[homeHash].stopAll());

  // ---------------------------
  // Lifecycle cleanup
  // ---------------------------
  const LIFECYCLE = {
    alive: true,
    stopped: false,
    intervals: new Set(),
    observers: new Set(),
    aborters: new Set(),
    listeners: [],
    nodes: new Set(),
    addListener(el, type, fn, opts) {
      if (!el) return;
      safe(() => {
        el.addEventListener(type, fn, opts);
        this.listeners.push({ el, type, fn, opts });
      });
    },
    trackNode(n) { if (n) this.nodes.add(n); },
    stopAll() {
      if (this.stopped) return;
      this.stopped = true;
      this.alive = false;

      this.intervals.forEach((id) => safe(() => clearInterval(id)));
      this.intervals.clear();

      this.observers.forEach((o) => safe(() => o.disconnect()));
      this.observers.clear();

      this.aborters.forEach((a) => safe(() => a.abort()));
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
  LIFECYCLE.addListener(window, "pageshow", syncAlive);
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
  // Proof-of-load + connected check
  // ---------------------------
  const markLoaded = (status = "ok") => {
    const hp = getHomeRoot();
    if (!hp) return;
    hp.dataset.ssHome = HOME_VERSION;
    hp.dataset.ssHomeStatus = status;
    hp.classList.add("ss-homejs-on");
  };

  // ---------------------------
  // Auto mark reveal (scoped)
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
  // Reveal (scoped + idle batch)
  // ---------------------------
  const initReveal = () => {
    const hp = getHomeRoot();
    if (!hp) return;

    const nodes = $$(CFG.reveal.selector, hp);
    if (!nodes.length) return;

    if (reducedMotion || !supports.IO) {
      nodes.forEach((n) => n.classList.add("is-in"));
      return;
    }

    const vw = window.innerWidth || 1200;
    const stagger = clamp(
      CFG.reveal.baseStaggerMs * (vw < 520 ? 0.7 : vw < 900 ? 0.85 : 1),
      18,
      60
    );

    const sorted = nodes
      .map((n) => ({ n, top: n.getBoundingClientRect().top || 99999 }))
      .sort((a, b) => a.top - b.top)
      .map((x) => x.n);

    const groupIndex = new Map();
    sorted.forEach((el) => {
      const section = el.closest("section") || hp;
      const idx = groupIndex.get(section) ?? 0;
      groupIndex.set(section, idx + 1);
      el.dataset.revealIdx = String(idx);
    });

    const schedule = (fn) => {
      if (supports.Idle) return requestIdleCallback(fn, { timeout: 180 });
      microtask(fn);
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
  // Sticky + ToTop (stable state)
  // ---------------------------
  const initStickyToTop = () => {
    const toTop = $(CFG.toTop.sel);
    const sticky = $(CFG.sticky.sel);
    const heroSection = $(".hp-hero") || $(".hp-heroFull") || $(".hp-heroCard");

    const setOn = (on) => {
      const v = !!on;
      if (sticky) {
        sticky.classList.toggle(CFG.sticky.onClass, v);
        sticky.setAttribute("aria-hidden", v ? "false" : "true");
      }
      if (toTop) {
        toTop.hidden = !v;
        toTop.style.display = v ? "inline-flex" : "";
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
      const t = nowMs();
      if (t - lastSwitch < CFG.sticky.hysteresisMs) return;
      lastSwitch = t;
      setOn(on);
    };

    if (supports.IO && heroSection) {
      const io = new IntersectionObserver(
        (entries) => {
          const e = entries[0];
          const on = !e.isIntersecting;
          if (reducedMotion) return setOn(on);
          hysteresis(on);
        },
        { threshold: [0.01, 0.15, 0.35] }
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
  // Hotkey "/"
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
  // Pills + offset header
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
  // Hero motion (cancelable)
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
    let lastFrame = nowMs();
    let slowFrames = 0;
    let frameId = 0;

    const updateRect = () => (rect = hero.getBoundingClientRect());

    if (supports.RO) {
      const ro = new ResizeObserver(updateRect);
      ro.observe(hero);
      LIFECYCLE.observers.add(ro);
    } else {
      LIFECYCLE.addListener(window, "resize", rafThrottle(updateRect), { passive: true });
    }

    if (supports.IO) {
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

    const useVars = safe(() => {
      const st = getComputedStyle(img);
      return st && (st.getPropertyValue("--mx") !== "" || st.getPropertyValue("--my") !== "");
    }) === true;

    const onMove = rafThrottle((e) => {
      if (!active || !LIFECYCLE.alive) return;

      const w = Math.max(1, rect.width);
      const h = Math.max(1, rect.height);

      const px = clamp((e.clientX - rect.left) / w - 0.5, -0.5, 0.5);
      const py = clamp((e.clientY - rect.top) / h - 0.5, -0.5, 0.5);

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
      if (LIFECYCLE.stopped) return;

      const now = nowMs();
      const dt = now - lastFrame;
      lastFrame = now;

      if (dt > 34) slowFrames++;
      else slowFrames = Math.max(0, slowFrames - 1);

      const shouldWork = LIFECYCLE.alive && active && slowFrames < 12;

      if (shouldWork) {
        sx += (mx - sx) * 0.11;
        const combinedY = sy + (my - sy * 0.15);

        if (useVars) {
          img.style.setProperty("--mx", `${sx.toFixed(2)}px`);
          img.style.setProperty("--my", `${combinedY.toFixed(2)}px`);
          img.style.setProperty("--sy", `${sy.toFixed(2)}px`);
        } else {
          const tr = `scale(${CFG.hero.scale}) translate3d(${sx.toFixed(2)}px, ${combinedY.toFixed(2)}px, 0)`;
          if (tr !== lastTransform) {
            img.style.transform = tr;
            lastTransform = tr;
          }
        }
      }

      frameId = raf(tick);
    };

    frameId = raf(tick);

    // Ensure stop cancels animation loop
    const stop = () => { if (frameId) caf(frameId); frameId = 0; };
    LIFECYCLE.intervals.add(setTimeout(() => {}, 0)); // keep set API consistent
    LIFECYCLE.addListener(window, "pagehide", stop, { once: true });
  };

  // ---------------------------
  // Glow
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
  // Image safety
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

    $$("[data-bg-fallback]").forEach((el) => {
      const fb = el.getAttribute("data-bg-fallback");
      if (!fb) return;
      const bg = getComputedStyle(el).backgroundImage || "";
      if (bg === "none" || bg === "") safe(() => (el.style.backgroundImage = `url("${fb}")`));
    });
  };

  // ---------------------------
  // Prefetch / preconnect (dedupe)
  // ---------------------------
  const ensureLink = (rel, href) => {
    if (!href) return;
    const exists = $$(`link[rel="${rel}"]`).some((l) => (l.getAttribute("href") || "") === href);
    if (exists) return;
    const link = doc.createElement("link");
    link.rel = rel;
    link.href = href;
    doc.head.appendChild(link);
  };

  const initPrefetchShop = () => {
    ensureLink("prefetch", "/shop");
    ensureLink("preconnect", location.origin);
  };

  // ---------------------------
  // Autocomplete (LRU + cleanup)
  // ---------------------------
  const initAutocomplete = () => {
    if (!CFG.autocomplete.enable) return;

    const input = $(CFG.search.candidates);
    if (!input) return;

    if (!input.getAttribute("autocomplete")) input.setAttribute("autocomplete", "off");
    if (!input.getAttribute("type")) input.setAttribute("type", "search");

    input.setAttribute("aria-autocomplete", "list");
    input.setAttribute("aria-haspopup", "listbox");

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
    LIFECYCLE.trackNode(box);

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
              <span style="width:8px;height:8px;border-radius:999px;background:linear-gradient(135deg,#2563eb,#0ea5e9);display:inline-block"></span>
              <span style="font-weight:900;${isDark ? "color:rgba(238,242,255,.90)" : "color:rgba(10,16,32,.88)"};line-height:1.2">${title}</span>
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

    LIFECYCLE.addListener(doc, "click", (e) => {
      if (e.target === input) return;
      if (box.contains(e.target)) return;
      close();
    });

    LIFECYCLE.addListener(input, "blur", () => {
      if (aborter) safe(() => aborter.abort());
      setTimeout(close, 120);
    });

    LIFECYCLE.addListener(input, "keydown", (e) => {
      if (box.style.display === "none" || !rows.length) return;

      if (e.key === "Escape") return close();

      if (e.key === "ArrowDown") { e.preventDefault(); activeIndex = clamp(activeIndex + 1, 0, rows.length - 1); }
      else if (e.key === "ArrowUp") { e.preventDefault(); activeIndex = clamp(activeIndex - 1, 0, rows.length - 1); }
      else if (e.key === "Enter") {
        const row = rows[activeIndex];
        if (row) {
          e.preventDefault();
          window.location.href = row.getAttribute("data-href") || "#";
        }
        return;
      } else return;

      const row = rows[activeIndex];
      highlight(row);
      if (row && row.id) input.setAttribute("aria-activedescendant", row.id);
    });

    const ensureAria = () => {
      const id = box.id || `ss-suggest-${Math.random().toString(16).slice(2)}`;
      box.id = id;
      input.setAttribute("aria-controls", id);
      input.setAttribute("aria-expanded", "false");
    };
    ensureAria();

    // Cleanup extra safety
    LIFECYCLE.addListener(window, "pagehide", () => {
      if (aborter) safe(() => aborter.abort());
      close();
    }, { once: true });
  };

  // ---------------------------
  // Rebind (clean re-init)
  // ---------------------------
  const initRebinder = () => {
    if (!supports.MO) return;

    const mo = new MutationObserver(
      debounce(() => {
        const newRoot = getHomeRoot();
        if (!newRoot || newRoot === homeRoot) return;

        // hard reset everything for previous instance (prevents dup)
        safe(() => LIFECYCLE.stopAll());

        // new run: clear global guard for this hash and re-run fully
        homeRoot = newRoot;
        delete STATE[homeHash];
        location.reload(); // safest for HTMX/Turbo swaps that replaced #hp entirely
      }, 260)
    );

    safe(() => mo.observe(doc.body || doc.documentElement, { childList: true, subtree: true }));
    LIFECYCLE.observers.add(mo);
  };

  // ---------------------------
  // Init
  // ---------------------------
  const init = () => {
    const hp = getHomeRoot();
    if (!hp) return;

    markLoaded("boot");

    safe(() => autoMarkReveal());

    safe(() => {
      const p = $(CFG.preloader.sel);
      if (!p) return;
      raf(() => {
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

    // Rebind: por defecto OFF (porque el reload es la opción más segura).
    // Si querés rebind sin reload, te lo adapto a tu stack (HTMX/Turbo específico).
    // safe(() => initRebinder());

    safe(() => hp.classList.add("is-ready"));
    markLoaded("ok");
  };

  if (doc.readyState === "loading") doc.addEventListener("DOMContentLoaded", init, { once: true });
  else init();
})();
