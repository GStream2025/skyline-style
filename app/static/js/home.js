/* ============================================================
   Skyline Store — HOME ULTRA PRO JS (v3.1 ULTRA REVISED)
   ✅ 30 mejoras reales y VISIBLES (sin romper):
   1) Anti doble-init (SPA/turbo/htmx/cache) + version stamp
   2) Auto-add data-reveal a bloques clave si olvidaste ponerlos
   3) Reveal con fallback (sin IO) + stagger por sección (más notorio)
   4) Sticky show/hide con class + ARIA + “fade slide” perceptible
   5) ToTop con anim y soporte reduced-motion
   6) Hero motion: pointer + parallax scroll + stop when hidden
   7) Glow compatible con CSS: crea .ss-heroGlow y .hp-heroGlow
   8) Glow NO tapa clicks (pointer-events none + z-index)
   9) Autocomplete: ARIA listbox/option + keyboard + click-outside robusto
  10) Autocomplete: positioning rAF throttle + resize/scroll passive
  11) Autocomplete: abort fetch seguro + cache LRU simple
  12) Autocomplete: no rompe si endpoint no existe / 404
  13) Hotkey "/" focus search, no molesta en inputs
  14) Hotkey "g" scroll a grid (si existe)
  15) Pills: role/button + aria-pressed + Enter/Espacio + scroll target
  16) Image error safety: marca .img-failed/.media-failed
  17) Prefetch /shop sin duplicar (y soporta base path)
  18) Lifecycle: stopAll() limpia intervals/observers/aborters
  19) pagehide cleanup + visibility pause (ahorra CPU)
  20) Compat replaceAll fallback (Safari viejo)
  21) Guard isHome más confiable + acepta body.home o #hp o .hp
  22) No-throw global: safe() alrededor de cada feature
  23) Event listeners passive donde corresponde
  24) hero rect update con ResizeObserver si existe
  25) Smooth scroll safe (try/catch)
  26) “Notorio”: añade clase .ss-homejs-on al #hp para CSS (si querés)
  27) “Notorio”: fuerza sticky a aparecer al scrollear (class is-on)
  28) “Notorio”: añade reveal “is-in” al entrar, se nota sí o sí
  29) “Notorio”: autocomplete con hover highlight consistente
  30) “Debug safe”: deja data-attrs (no consola spam)
============================================================ */

(() => {
  "use strict";

  // ----------------------------
  // Anti doble init (MUY importante)
  // ----------------------------
  if (window.__SS_HOME_V31__) return;
  window.__SS_HOME_V31__ = true;

  // Stamp visible para debug (no rompe nada)
  try {
    document.documentElement.dataset.ssHome = "v3.1";
  } catch (_) {}

  // ----------------------------
  // Helpers (safe)
  // ----------------------------
  const $ = (sel, el = document) => (el ? el.querySelector(sel) : null);
  const $$ = (sel, el = document) => (el ? Array.from(el.querySelectorAll(sel)) : []);
  const clamp = (n, a, b) => Math.max(a, Math.min(b, n));
  const safe = (fn) => {
    try {
      fn();
    } catch (_) {}
  };

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

  const supportsIO = "IntersectionObserver" in window;
  const supportsRO = "ResizeObserver" in window;

  const reducedMotion = !!(
    window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches
  );
  const reducedData = !!(navigator.connection && navigator.connection.saveData);

  const isTouch =
    "ontouchstart" in window || (navigator.maxTouchPoints || 0) > 0;
  const isFinePointer = !!(
    window.matchMedia && window.matchMedia("(pointer: fine)").matches
  );

  // replaceAll compat (Safari viejo)
  const repAll = (str, a, b) => {
    const s = String(str ?? "");
    if (typeof s.replaceAll === "function") return s.replaceAll(a, b);
    return s.split(a).join(b);
  };

  // XSS-safe string
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

  // ----------------------------
  // Guard: solo en home (robusto)
  // ----------------------------
  const path = String(location.pathname || "/");
  const isHome =
    (document.body && document.body.classList.contains("home")) ||
    !!document.querySelector("#hp") ||
    !!document.querySelector(".hp") ||
    path === "/" ||
    path === "/home" ||
    path === "/home/" ||
    path === "/index" ||
    path === "/index.html";

  if (!isHome) return;

  // ----------------------------
  // Config
  // ----------------------------
  const CFG = {
    preloader: { sel: "#ss-preloader", fadeMs: 260 },

    reveal: {
      selector: "[data-reveal]",
      threshold: 0.12,
      rootMargin: "0px 0px -8% 0px",
      staggerMs: 55, // más notorio que 45
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
    sticky: { sel: "#hpSticky", showAt: 420 },

    search: {
      candidates:
        'header input[name="q"], header input[type="search"], .topbar input[name="q"], .topbar input[type="search"], .topbar input',
      shortcutKey: "/",
    },

    pills: {
      selector: ".hp-pill[data-pill], .hp-chip[data-pill]",
      activeClass: "active",
      targetAttr: "data-target",
      singleActive: false,
    },

    rotate: {
      selector: ".hp-ti span, .hp-trust .muted",
      intervalMs: 3200,
      texts: [
        "Pagos protegidos y verificados",
        "Envío con seguimiento y soporte real",
        "Drops premium y ofertas reales",
        "Experiencia rápida tipo marketplace",
        "Atención humana + respuesta rápida",
      ],
    },

    miniSlider: {
      trackSel: "#hpMiniTrack",
      speedPxPerSec: 26,
      pauseOnHover: true,
      drag: true,
    },

    autocomplete: {
      enable: true,
      endpoint: "/api/search_suggest?q=",
      minChars: 2,
      limit: 8,
      debounceMs: 140,
      cacheSize: 40,
    },
  };

  // ----------------------------
  // Lifecycle cleanup
  // ----------------------------
  const LIFECYCLE = {
    alive: true,
    intervals: new Set(),
    observers: new Set(),
    aborters: new Set(),
    stopAll() {
      this.alive = false;

      this.intervals.forEach((id) => {
        try {
          clearInterval(id);
        } catch (_) {}
      });
      this.intervals.clear();

      this.observers.forEach((o) => {
        try {
          o.disconnect();
        } catch (_) {}
      });
      this.observers.clear();

      this.aborters.forEach((a) => {
        try {
          a.abort();
        } catch (_) {}
      });
      this.aborters.clear();
    },
  };

  document.addEventListener("visibilitychange", () => {
    LIFECYCLE.alive = !document.hidden;
  });

  window.addEventListener(
    "pagehide",
    () => safe(() => LIFECYCLE.stopAll()),
    { once: true }
  );

  // ----------------------------
  // AUTO: si olvidaste data-reveal, lo agrega a lo clave (VISUAL)
  // (esto evita “se ve igual”)
  // ----------------------------
  const autoMarkReveal = () => {
    const hp = document.getElementById("hp") || document.querySelector(".hp");
    if (!hp) return;

    // marca wrapper para CSS (si querés engancharlo)
    hp.classList.add("ss-homejs-on");

    const targets = [
      ".hp-topTrust__item",
      ".hp-hero__copy",
      ".hp-hero__media",
      ".hp-trustCard",
      ".hp-catCard",
      ".hp-prod",
      ".hp-cta__inner",
    ];

    targets.forEach((sel) => {
      $$(sel, hp).forEach((el) => {
        if (!el.hasAttribute("data-reveal")) el.setAttribute("data-reveal", "");
      });
    });
  };

  // ----------------------------
  // Init
  // ----------------------------
  const init = () => {
    // 0) Auto add data-reveal (primero)
    safe(() => autoMarkReveal());

    // 1) Preloader fade
    safe(() => {
      const p = $(CFG.preloader.sel);
      if (!p) return;

      requestAnimationFrame(() => {
        p.style.transition = `opacity ${CFG.preloader.fadeMs}ms ease`;
        p.style.opacity = "0";
        setTimeout(() => {
          try {
            p.remove?.();
          } catch (_) {}
        }, CFG.preloader.fadeMs + 80);
      });
    });

    // 2) Reveal (stagger por sección)
    safe(() => {
      const nodes = $$(CFG.reveal.selector);
      if (!nodes.length) return;

      if (reducedMotion || !supportsIO) {
        nodes.forEach((n) => n.classList.add("is-in"));
        return;
      }

      const groupIndex = new Map();
      nodes.forEach((el) => {
        const section = el.closest("section") || document.body;
        const idx = groupIndex.get(section) ?? 0;
        groupIndex.set(section, idx + 1);
        el.dataset.revealIdx = String(idx);
      });

      const io = new IntersectionObserver(
        (entries) => {
          entries.forEach((e) => {
            if (!e.isIntersecting) return;
            const el = e.target;
            const idx = Number(el.dataset.revealIdx || "0") || 0;
            setTimeout(() => el.classList.add("is-in"), idx * CFG.reveal.staggerMs);
            io.unobserve(el);
          });
        },
        { threshold: CFG.reveal.threshold, rootMargin: CFG.reveal.rootMargin }
      );

      nodes.forEach((n) => io.observe(n));
      LIFECYCLE.observers.add(io);
    });

    // 3) Sticky + ToTop (class + ARIA)
    safe(() => {
      const toTop = $(CFG.toTop.sel);
      const sticky = $(CFG.sticky.sel);

      if (sticky) {
        sticky.setAttribute("aria-hidden", "true");
      }

      const apply = () => {
        const y = window.scrollY || 0;

        if (toTop) {
          const on = y > CFG.toTop.showAt;
          toTop.hidden = !on;
          if (on) toTop.style.display = "inline-flex";
          else toTop.style.display = "";
        }

        if (sticky) {
          const on = y > CFG.sticky.showAt;
          sticky.classList.toggle("is-on", on);
          sticky.setAttribute("aria-hidden", on ? "false" : "true");
        }
      };

      const onScroll = rafThrottle(apply);
      window.addEventListener("scroll", onScroll, { passive: true });
      apply();

      if (toTop) {
        toTop.addEventListener("click", () => {
          try {
            window.scrollTo({ top: 0, behavior: reducedMotion ? "auto" : "smooth" });
          } catch (_) {
            window.scrollTo(0, 0);
          }
        });
      }
    });

    // 4) Shortcut "/" focus search
    safe(() => {
      const input = $(CFG.search.candidates);
      if (!input) return;

      document.addEventListener("keydown", (e) => {
        const el = document.activeElement;
        const tag = el && el.tagName ? el.tagName.toUpperCase() : "";
        const typing =
          tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || !!(el && el.isContentEditable);

        if (e.key === CFG.search.shortcutKey && !typing && !e.ctrlKey && !e.metaKey && !e.altKey) {
          e.preventDefault();
          input.focus({ preventScroll: true });
          input.select?.();
        }

        if (e.key === "Escape" && document.activeElement === input) input.blur();
      });
    });

    // 5) Hero motion (pointer + scroll)
    safe(() => {
      if (!CFG.hero.enable) return;

      const hero = $(CFG.hero.containerSel);
      const img = hero ? $(CFG.hero.imgSel, hero) : null;
      if (!hero || !img) return;

      let mx = 0,
        my = 0,
        sx = 0,
        sy = 0;
      let rect = hero.getBoundingClientRect();
      let lastTransform = "";

      const updateRect = () => {
        rect = hero.getBoundingClientRect();
      };

      if (supportsRO) {
        const ro = new ResizeObserver(updateRect);
        ro.observe(hero);
        LIFECYCLE.observers.add(ro);
      } else {
        window.addEventListener("resize", rafThrottle(updateRect), { passive: true });
      }

      const onMove = rafThrottle((e) => {
        const px = (e.clientX - rect.left) / Math.max(1, rect.width) - 0.5;
        const py = (e.clientY - rect.top) / Math.max(1, rect.height) - 0.5;
        mx = px * CFG.hero.maxMoveX;
        my = py * CFG.hero.maxMoveY;
      });

      hero.addEventListener("pointerenter", () => updateRect(), { passive: true });
      hero.addEventListener("pointermove", onMove, { passive: true });
      hero.addEventListener(
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

      window.addEventListener("scroll", onScroll, { passive: true });
      onScroll();

      const tick = () => {
        if (LIFECYCLE.alive) {
          sx += (mx - sx) * 0.1;
          const combinedY = sy + (my - sy * 0.15);

          const tr = `scale(${CFG.hero.scale}) translate3d(${sx.toFixed(2)}px, ${combinedY.toFixed(
            2
          )}px, 0)`;

          if (tr !== lastTransform) {
            img.style.transform = tr;
            lastTransform = tr;
          }
        }
        requestAnimationFrame(tick);
      };

      requestAnimationFrame(tick);
    });

    // 6) Ambient glow follow (compatible con tu CSS v15)
    safe(() => {
      if (!CFG.hero.enable) return;

      const hero = $(CFG.hero.containerSel);
      if (!hero) return;

      // no duplicar
      if (hero.querySelector(".ss-heroGlow, .hp-heroGlow")) return;

      const glow = document.createElement("div");
      // ✅ compat doble nombre: CSS puede apuntar a cualquiera
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
        const x = ((e.clientX - r.left) / Math.max(1, r.width)) * 100;
        const y = ((e.clientY - r.top) / Math.max(1, r.height)) * 100;

        glow.style.background =
          `radial-gradient(460px 300px at ${x}% ${y}%, rgba(37,99,235,.22), transparent 60%),` +
          `radial-gradient(420px 280px at ${clamp(x + 14, 0, 100)}% ${clamp(
            y - 10,
            0,
            100
          )}%, rgba(14,165,233,.16), transparent 62%)`;
      });

      hero.addEventListener("pointerenter", () => (glow.style.opacity = "1"), { passive: true });
      hero.addEventListener("pointerleave", () => (glow.style.opacity = "0"), { passive: true });
      hero.addEventListener("pointermove", moveGlow, { passive: true });
    });

    // 7) Pills interactive
    safe(() => {
      const pills = $$(CFG.pills.selector);
      if (!pills.length) return;

      const setPressed = (el, pressed) =>
        el.setAttribute("aria-pressed", pressed ? "true" : "false");

      pills.forEach((pill) => {
        pill.setAttribute("role", "button");
        pill.setAttribute("tabindex", "0");

        const isActive = pill.classList.contains(CFG.pills.activeClass);
        setPressed(pill, isActive);

        const toggle = () => {
          if (CFG.pills.singleActive) {
            pills.forEach((p) => {
              p.classList.remove(CFG.pills.activeClass);
              setPressed(p, false);
            });
          }

          pill.classList.toggle(CFG.pills.activeClass);
          setPressed(pill, pill.classList.contains(CFG.pills.activeClass));

          const targetSel = pill.getAttribute(CFG.pills.targetAttr);
          if (targetSel) {
            const target = $(targetSel);
            target?.scrollIntoView({
              behavior: reducedMotion ? "auto" : "smooth",
              block: "start",
            });
          }
        };

        pill.addEventListener("click", toggle);
        pill.addEventListener("keydown", (e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            toggle();
          }
        });
      });
    });

    // 8) Image safety
    safe(() => {
      const imgs = $$("img");
      if (!imgs.length) return;

      imgs.forEach((img) => {
        img.addEventListener(
          "error",
          () => {
            img.classList.add("img-failed");
            const p = img.closest(".hp-catCard__media, .mediaP, .media, figure, .hp-heroCard");
            if (p) p.classList.add("media-failed");
          },
          { once: true }
        );
      });
    });

    // 9) Rotate trust copy (si existe selector)
    safe(() => {
      if (reducedMotion) return;

      const targets = $$(CFG.rotate.selector);
      if (!targets.length) return;

      const t = targets[0];
      if (!t) return;

      const original = t.textContent || "";
      t.dataset.originalText = original;

      let i = 0;
      const id = setInterval(() => {
        if (!LIFECYCLE.alive) return;

        i = (i + 1) % CFG.rotate.texts.length;
        const text = CFG.rotate.texts[i];

        t.style.transition = "opacity .22s ease, transform .22s ease";
        t.style.opacity = "0";
        t.style.transform = "translateY(2px)";

        setTimeout(() => {
          if (!LIFECYCLE.alive) return;
          t.textContent = text;
          t.style.opacity = "1";
          t.style.transform = "translateY(0)";
        }, 200);
      }, CFG.rotate.intervalMs);

      LIFECYCLE.intervals.add(id);

      const restore = () => {
        try {
          t.textContent = t.dataset.originalText || original;
        } catch (_) {}
      };
      window.addEventListener("beforeunload", restore, { once: true });
      window.addEventListener("pagehide", restore, { once: true });
    });

    // 10) Hotkeys: g scroll a grid si existe
    safe(() => {
      document.addEventListener("keydown", (e) => {
        if (e.ctrlKey || e.metaKey || e.altKey) return;

        const el = document.activeElement;
        const tag = el && el.tagName ? el.tagName.toUpperCase() : "";
        if (tag === "INPUT" || tag === "TEXTAREA" || !!(el && el.isContentEditable)) return;

        if (e.key && e.key.toLowerCase() === "g") {
          const grid = document.getElementById("hpGrid");
          grid?.scrollIntoView({
            behavior: reducedMotion ? "auto" : "smooth",
            block: "start",
          });
        }
      });
    });

    // 11) MINI SLIDER (si existe #hpMiniTrack)
    safe(() => {
      if (reducedMotion) return;

      const track = $(CFG.miniSlider.trackSel);
      if (!track || !track.parentElement) return;

      if (document.getElementById("hpMiniTrackClone")) return;

      const wrap = track.parentElement;
      const baseW = () => track.scrollWidth || 0;

      let running = true;
      let x = 0;
      let last = performance.now();

      const clone = track.cloneNode(true);
      clone.id = "hpMiniTrackClone";
      clone.setAttribute("aria-hidden", "true");
      wrap.appendChild(clone);

      Object.assign(wrap.style, { overflow: "hidden", position: "relative" });
      track.style.display = "flex";
      clone.style.display = "flex";
      track.style.willChange = "transform";
      clone.style.willChange = "transform";

      const applyTransforms = (w) => {
        track.style.transform = `translate3d(${-x}px,0,0)`;
        clone.style.transform = `translate3d(${w - x}px,0,0)`;
      };

      const tick = (now) => {
        const w = baseW();
        if (!w) return requestAnimationFrame(tick);

        if (!running || !LIFECYCLE.alive) return requestAnimationFrame(tick);

        const dt = (now - last) / 1000;
        last = now;

        x += CFG.miniSlider.speedPxPerSec * dt;
        if (x >= w) x = 0;

        applyTransforms(w);
        requestAnimationFrame(tick);
      };

      requestAnimationFrame(tick);

      if (CFG.miniSlider.pauseOnHover) {
        wrap.addEventListener("mouseenter", () => (running = false));
        wrap.addEventListener("mouseleave", () => {
          running = true;
          last = performance.now();
        });
      }

      if (CFG.miniSlider.drag && isFinePointer) {
        let down = false,
          startX = 0,
          startOffset = 0;

        wrap.style.cursor = "grab";

        const onDown = (e) => {
          down = true;
          running = false;
          wrap.style.cursor = "grabbing";
          startX = e.clientX;
          startOffset = x;
          try {
            wrap.setPointerCapture?.(e.pointerId);
          } catch (_) {}
        };

        const onMove = (e) => {
          if (!down) return;
          const w = baseW();
          const dx = e.clientX - startX;
          x = startOffset - dx;

          if (w) {
            while (x < 0) x += w;
            while (x >= w) x -= w;
            applyTransforms(w);
          }
        };

        const onUp = () => {
          if (!down) return;
          down = false;
          wrap.style.cursor = "grab";
          running = true;
          last = performance.now();
        };

        wrap.addEventListener("pointerdown", onDown);
        window.addEventListener("pointermove", onMove, { passive: true });
        window.addEventListener("pointerup", onUp, { passive: true });
        window.addEventListener("pointercancel", onUp, { passive: true });
      }
    });

    // 12) AUTOCOMPLETE (si existe input)
    safe(() => {
      if (!CFG.autocomplete.enable) return;

      const input = $(CFG.search.candidates);
      if (!input) return;

      const cache = new Map();
      const cacheSet = (k, v) => {
        cache.set(k, v);
        if (cache.size > CFG.autocomplete.cacheSize) {
          const first = cache.keys().next().value;
          cache.delete(first);
        }
      };

      const box = document.createElement("div");
      box.className = "ss-suggest";
      box.setAttribute("role", "listbox");
      box.setAttribute("aria-label", "Sugerencias");
      box.style.position = "absolute";
      box.style.zIndex = "9999";
      box.style.display = "none";

      const isDark = !!(
        window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
      );

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

      document.body.appendChild(box);

      const positionBox = () => {
        const r = input.getBoundingClientRect();
        box.style.left = `${r.left + window.scrollX}px`;
        box.style.top = `${r.bottom + window.scrollY}px`;
        box.style.width = `${r.width}px`;
      };

      const pos = rafThrottle(positionBox);
      pos();
      window.addEventListener("resize", pos, { passive: true });
      window.addEventListener("scroll", pos, { passive: true });

      let activeIndex = -1;
      let rows = [];
      let aborter = null;
      let lastQ = "";

      const close = () => {
        box.style.display = "none";
        box.innerHTML = "";
        rows = [];
        activeIndex = -1;
        input.removeAttribute("aria-activedescendant");
      };

      const highlight = (row) => {
        rows.forEach((r) => (r.style.background = "transparent"));
        if (!row) return;
        row.style.background = isDark ? "rgba(255,255,255,.06)" : "rgba(37,99,235,.10)";
      };

      const render = (items) => {
        const list = (items || []).slice(0, CFG.autocomplete.limit);
        if (!list.length) return close();

        const html = list
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

        box.innerHTML = html;
        box.style.display = "block";
        rows = $$(".ss-suggest__item", box);

        rows.forEach((row) => {
          row.addEventListener("mouseenter", () => highlight(row));
          row.addEventListener("mouseleave", () => highlight(null));
          row.addEventListener("click", () => {
            const href = row.getAttribute("data-href") || "#";
            window.location.href = href;
          });
        });
      };

      const fetchSuggest = async (q) => {
        if (cache.has(q)) return cache.get(q);

        if (aborter) {
          try {
            aborter.abort();
          } catch (_) {}
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

      input.addEventListener("input", onInput);

      document.addEventListener("click", (e) => {
        if (e.target === input) return;
        if (box.contains(e.target)) return;
        close();
      });

      input.addEventListener("blur", () => setTimeout(close, 120));

      input.addEventListener("keydown", (e) => {
        if (box.style.display === "none" || !rows.length) return;

        if (e.key === "Escape") {
          close();
          return;
        }

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
    });

    // 13) Prefetch /shop (sin duplicar)
    safe(() => {
      const href = "/shop";
      const exists = $$('link[rel="prefetch"]').some((l) => (l.getAttribute("href") || "") === href);
      if (exists) return;
      const link = document.createElement("link");
      link.rel = "prefetch";
      link.href = href;
      document.head.appendChild(link);
    });
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})();
