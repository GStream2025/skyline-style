/* ============================================================
   Skyline Store — HOME ULTRA PRO JS (v2)
   - Zero dependencies
   - No-throw design (si falta algo, NO rompe)
   - Motion safe (prefers-reduced-motion)
   - Performance: passive listeners + rAF throttle + pause on hidden
   - Extras: preloader, mini slider, autocomplete (si existen)
============================================================ */

(() => {
  "use strict";

  // ----------------------------
  // Helpers (safe)
  // ----------------------------
  const $ = (sel, el = document) => el.querySelector(sel);
  const $$ = (sel, el = document) => Array.from(el.querySelectorAll(sel));
  const clamp = (n, a, b) => Math.max(a, Math.min(b, n));

  const safe = (fn) => {
    try { fn(); } catch (_) { /* never throw */ }
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

  const reducedMotion =
    window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const reducedData =
    (navigator.connection && navigator.connection.saveData) || false;

  const isTouch =
    "ontouchstart" in window ||
    (navigator.maxTouchPoints || 0) > 0;

  const log = (..._args) => {
    // enable if you need debug
    // console.log("[home.js]", ..._args);
  };

  // ----------------------------
  // Guard: solo en home (opcional)
  // ----------------------------
  const isHome =
    document.body.classList.contains("home") ||
    document.querySelector(".home-pro") ||
    location.pathname === "/" ||
    location.pathname === "/home";

  if (!isHome) return;

  // ----------------------------
  // Config
  // ----------------------------
  const CFG = {
    preloader: { sel: "#ss-preloader", fadeMs: 280 },

    reveal: {
      selector: "[data-reveal]",
      threshold: 0.12,
      rootMargin: "0px 0px -8% 0px",
      staggerMs: 45,
    },

    hero: {
      containerSel: ".hp-heroMain",
      imgSel: "#hpHeroImg",
      maxMoveX: 10,
      maxMoveY: 8,
      scrollParallax: 14,
      scale: 1.06,
      enable: !reducedMotion && !isTouch && !reducedData,
    },

    toTop: { sel: "#toTop", showAt: 520 },
    sticky: { sel: "#hpSticky", showAt: 420 },

    search: {
      candidates:
        'header input[name="q"], header input[type="search"], .topbar input[name="q"], .topbar input[type="search"], .topbar input',
      shortcutKey: "/",
    },

    pills: {
      selector: ".hp-pill[data-pill]",
      activeClass: "active",
      targetAttr: "data-target",
      singleActive: false, // true = solo una pill activa a la vez
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
    },
  };

  // ----------------------------
  // Lifecycle: pause when tab hidden
  // ----------------------------
  const LIFECYCLE = {
    alive: true,
    intervals: new Set(),
    observers: new Set(),
    aborters: new Set(),
    stopAll() {
      this.alive = false;
      this.intervals.forEach((id) => clearInterval(id));
      this.intervals.clear();

      this.observers.forEach((o) => {
        try { o.disconnect(); } catch(_) {}
      });
      this.observers.clear();

      this.aborters.forEach((a) => {
        try { a.abort(); } catch(_) {}
      });
      this.aborters.clear();
    },
  };

  document.addEventListener("visibilitychange", () => {
    // cuando vuelve visible, no reiniciamos todo; solo evitamos loops pesados
    LIFECYCLE.alive = !document.hidden;
  });

  // ----------------------------
  // Init (extra safe)
  // ----------------------------
  const init = () => {
    // 0) Preloader fade
    safe(() => {
      const p = $(CFG.preloader.sel);
      if (!p) return;
      // deja que pinte el primer frame
      requestAnimationFrame(() => {
        p.style.transition = `opacity ${CFG.preloader.fadeMs}ms ease`;
        p.style.opacity = "0";
        setTimeout(() => { p.remove?.(); }, CFG.preloader.fadeMs + 50);
      });
    });

    // 1) Reveal ULTRA (stagger + IO + group)
    safe(() => {
      const nodes = $$(CFG.reveal.selector);
      if (!nodes.length) return;

      if (reducedMotion || !supportsIO) {
        nodes.forEach((n) => n.classList.add("is-in"));
        return;
      }

      // agrupar por secciones para stagger más “natural”
      const groups = new Map();
      nodes.forEach((el) => {
        const section = el.closest("section") || document.body;
        if (!groups.has(section)) groups.set(section, []);
        groups.get(section).push(el);
      });

      const io = new IntersectionObserver(
        (entries) => {
          const visible = entries.filter((e) => e.isIntersecting);
          if (!visible.length) return;

          visible
            .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)
            .forEach((e) => {
              const el = e.target;
              const section = el.closest("section") || document.body;
              const list = groups.get(section) || [el];
              const idx = list.indexOf(el);

              setTimeout(() => el.classList.add("is-in"), Math.max(0, idx) * CFG.reveal.staggerMs);
              io.unobserve(el);
            });
        },
        { threshold: CFG.reveal.threshold, rootMargin: CFG.reveal.rootMargin }
      );

      nodes.forEach((n) => io.observe(n));
      LIFECYCLE.observers.add(io);
    });

    // 2) Sticky CTA + ToTop (rAF + no flicker)
    safe(() => {
      const toTop = $(CFG.toTop.sel);
      const sticky = $(CFG.sticky.sel);

      const onScroll = rafThrottle(() => {
        const y = window.scrollY || 0;
        if (toTop) toTop.style.display = y > CFG.toTop.showAt ? "inline-flex" : "none";
        if (sticky) sticky.classList.toggle("is-on", y > CFG.sticky.showAt);
      });

      window.addEventListener("scroll", onScroll, { passive: true });
      onScroll();

      if (toTop) {
        toTop.addEventListener("click", () => {
          window.scrollTo({ top: 0, behavior: reducedMotion ? "auto" : "smooth" });
        });
      }
    });

    // 3) Shortcut "/" focus search (robusto)
    safe(() => {
      const input = $(CFG.search.candidates);
      if (!input) return;

      document.addEventListener("keydown", (e) => {
        const tag = (document.activeElement && document.activeElement.tagName) || "";
        const typing = tag === "INPUT" || tag === "TEXTAREA";

        if (e.key === CFG.search.shortcutKey && !typing && !e.ctrlKey && !e.metaKey && !e.altKey) {
          e.preventDefault();
          input.focus({ preventScroll: true });
          input.select?.();
        }

        if (e.key === "Escape" && document.activeElement === input) {
          input.blur();
        }
      });
    });

    // 4) Hero Parallax ULTRA (mouse + scroll + pause on hidden)
    safe(() => {
      if (!CFG.hero.enable) return;

      const hero = $(CFG.hero.containerSel);
      const img = $(CFG.hero.imgSel);
      if (!hero || !img) return;

      let mx = 0, my = 0, sx = 0, sy = 0;
      let rect = hero.getBoundingClientRect();

      const updateRect = () => { rect = hero.getBoundingClientRect(); };

      if (supportsRO) {
        const ro = new ResizeObserver(updateRect);
        ro.observe(hero);
        LIFECYCLE.observers.add(ro);
      } else {
        window.addEventListener("resize", rafThrottle(updateRect), { passive: true });
      }

      const onMove = (e) => {
        // pointermove > mousemove (mejor)
        const px = (e.clientX - rect.left) / rect.width - 0.5;
        const py = (e.clientY - rect.top) / rect.height - 0.5;
        mx = px * CFG.hero.maxMoveX;
        my = py * CFG.hero.maxMoveY;
      };

      hero.addEventListener("pointermove", rafThrottle(onMove), { passive: true });
      hero.addEventListener("mouseleave", () => { mx = 0; my = 0; });

      // scroll parallax sutil
      const onScroll = rafThrottle(() => {
        const r = hero.getBoundingClientRect();
        const viewH = window.innerHeight || 900;
        const t = clamp(1 - r.top / viewH, 0, 1);
        sy += (-(t * CFG.hero.scrollParallax) - sy) * 0.02;
      });
      window.addEventListener("scroll", onScroll, { passive: true });
      onScroll();

      // loop con guard de visibilidad
      const tick = () => {
        if (LIFECYCLE.alive) {
          sx += (mx - sx) * 0.08;
          const combinedY = sy + (my - (sy * 0.15));
          img.style.transform = `scale(${CFG.hero.scale}) translate3d(${sx}px, ${combinedY}px, 0)`;
        }
        requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    });

    // 5) Ambient Glow follow (liviano + pointer)
    safe(() => {
      if (!CFG.hero.enable) return;

      const hero = $(CFG.hero.containerSel);
      if (!hero) return;

      const glow = document.createElement("div");
      glow.setAttribute("aria-hidden", "true");
      glow.style.position = "absolute";
      glow.style.inset = "0";
      glow.style.pointerEvents = "none";
      glow.style.zIndex = "2";
      glow.style.mixBlendMode = "soft-light";
      glow.style.opacity = "0";
      glow.style.transition = "opacity .35s ease";
      glow.style.background =
        "radial-gradient(420px 280px at 50% 50%, rgba(37,99,235,.20), transparent 60%), radial-gradient(420px 280px at 60% 40%, rgba(14,165,233,.14), transparent 60%)";

      hero.appendChild(glow);

      const moveGlow = rafThrottle((e) => {
        const r = hero.getBoundingClientRect();
        const x = ((e.clientX - r.left) / r.width) * 100;
        const y = ((e.clientY - r.top) / r.height) * 100;
        glow.style.background =
          `radial-gradient(460px 300px at ${x}% ${y}%, rgba(37,99,235,.22), transparent 60%),` +
          `radial-gradient(420px 280px at ${clamp(x + 14, 0, 100)}% ${clamp(y - 10, 0, 100)}%, rgba(14,165,233,.16), transparent 62%)`;
      });

      hero.addEventListener("mouseenter", () => (glow.style.opacity = "1"));
      hero.addEventListener("mouseleave", () => (glow.style.opacity = "0"));
      hero.addEventListener("pointermove", moveGlow, { passive: true });
    });

    // 6) Pills interactive (toggle + scroll + aria)
    safe(() => {
      const pills = $$(CFG.pills.selector);
      if (!pills.length) return;

      pills.forEach((pill) => {
        pill.setAttribute("role", "button");
        pill.setAttribute("tabindex", "0");
        pill.setAttribute("aria-pressed", pill.classList.contains(CFG.pills.activeClass) ? "true" : "false");

        const toggle = () => {
          if (CFG.pills.singleActive) {
            pills.forEach((p) => {
              p.classList.remove(CFG.pills.activeClass);
              p.setAttribute("aria-pressed", "false");
            });
          }

          pill.classList.toggle(CFG.pills.activeClass);
          pill.setAttribute("aria-pressed", pill.classList.contains(CFG.pills.activeClass) ? "true" : "false");

          const targetSel = pill.getAttribute(CFG.pills.targetAttr);
          if (targetSel) {
            const target = $(targetSel);
            if (target) {
              target.scrollIntoView({
                behavior: reducedMotion ? "auto" : "smooth",
                block: "start",
              });
            }
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

    // 7) Smart image safety
    safe(() => {
      $$("img").forEach((img) => {
        img.addEventListener(
          "error",
          () => {
            img.classList.add("img-failed");
            const p = img.closest(".media, .hpMedia");
            if (p) p.classList.add("media-failed");
          },
          { once: true }
        );
      });
    });

    // 8) Rotate trust copy (con restore)
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

        t.style.transition = "opacity .25s ease, transform .25s ease";
        t.style.opacity = "0";
        t.style.transform = "translateY(2px)";

        setTimeout(() => {
          if (!LIFECYCLE.alive) return;
          t.textContent = text;
          t.style.opacity = "1";
          t.style.transform = "translateY(0)";
        }, 220);
      }, CFG.rotate.intervalMs);

      LIFECYCLE.intervals.add(id);

      window.addEventListener("beforeunload", () => {
        try { t.textContent = t.dataset.originalText || original; } catch(_) {}
      });
    });

    // 9) Hotkeys (g = grid)
    safe(() => {
      document.addEventListener("keydown", (e) => {
        if (e.ctrlKey || e.metaKey || e.altKey) return;
        const tag = (document.activeElement && document.activeElement.tagName) || "";
        if (tag === "INPUT" || tag === "TEXTAREA") return;

        if (e.key.toLowerCase() === "g") {
          const grid = document.getElementById("hpGrid");
          if (grid) {
            grid.scrollIntoView({
              behavior: reducedMotion ? "auto" : "smooth",
              block: "start",
            });
          }
        }
      });
    });

    // 10) MINI SLIDER (si existe #hpMiniTrack)
    safe(() => {
      const track = $(CFG.miniSlider.trackSel);
      if (!track) return;

      let running = true;
      let x = 0;
      let last = performance.now();

      const items = $$(".hp-miniItem", track);
      if (items.length < 2) return;

      // duplicamos contenido para loop suave
      const clone = track.cloneNode(true);
      clone.id = "hpMiniTrackClone";
      clone.setAttribute("aria-hidden", "true");
      track.parentElement.appendChild(clone);

      const wrap = track.parentElement;
      wrap.style.overflow = "hidden";
      wrap.style.position = "relative";
      track.style.display = "flex";
      clone.style.display = "flex";

      const layout = () => {
        // alinear en fila
        track.style.gap = "10px";
        clone.style.gap = "10px";
      };
      layout();

      const tick = (now) => {
        if (!running || !LIFECYCLE.alive) return requestAnimationFrame(tick);

        const dt = (now - last) / 1000;
        last = now;

        x += CFG.miniSlider.speedPxPerSec * dt;
        const w = track.scrollWidth;

        if (x >= w) x = 0;

        track.style.transform = `translate3d(${-x}px,0,0)`;
        clone.style.transform = `translate3d(${w - x}px,0,0)`;

        requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);

      if (CFG.miniSlider.pauseOnHover) {
        wrap.addEventListener("mouseenter", () => (running = false));
        wrap.addEventListener("mouseleave", () => {
          running = true;
          last = performance.now();
          requestAnimationFrame(tick);
        });
      }

      // drag (mouse)
      if (CFG.miniSlider.drag && !isTouch) {
        let down = false, startX = 0, startOffset = 0;
        wrap.style.cursor = "grab";

        wrap.addEventListener("mousedown", (e) => {
          down = true;
          running = false;
          wrap.style.cursor = "grabbing";
          startX = e.clientX;
          startOffset = x;
        });

        window.addEventListener("mouseup", () => {
          if (!down) return;
          down = false;
          wrap.style.cursor = "grab";
          running = true;
          last = performance.now();
          requestAnimationFrame(tick);
        });

        window.addEventListener("mousemove", (e) => {
          if (!down) return;
          const dx = e.clientX - startX;
          x = clamp(startOffset - dx, 0, track.scrollWidth);
          track.style.transform = `translate3d(${-x}px,0,0)`;
          clone.style.transform = `translate3d(${track.scrollWidth - x}px,0,0)`;
        });
      }
    });

    // 11) AUTOCOMPLETE (si existe input y endpoint)
    safe(() => {
      if (!CFG.autocomplete.enable) return;

      const input = $(CFG.search.candidates);
      if (!input) return;

      const host = input.closest("form") || input.parentElement || document.body;

      const box = document.createElement("div");
      box.className = "ss-suggest";
      box.setAttribute("role", "listbox");
      box.setAttribute("aria-label", "Sugerencias");
      box.style.position = "absolute";
      box.style.zIndex = "999";
      box.style.display = "none";

      // Estilos inline mínimos (lo ideal es CSS global, pero esto evita “sin estilo”)
      box.style.marginTop = "8px";
      box.style.borderRadius = "14px";
      box.style.border = "1px solid rgba(15,23,42,.14)";
      box.style.background = "rgba(255,255,255,.96)";
      box.style.boxShadow = "0 18px 50px rgba(2,6,23,.14)";
      box.style.backdropFilter = "blur(14px)";
      box.style.webkitBackdropFilter = "blur(14px)";
      box.style.overflow = "hidden";
      box.style.minWidth = "240px";

      // positioning
      const positionBox = () => {
        const r = input.getBoundingClientRect();
        box.style.left = `${r.left + window.scrollX}px`;
        box.style.top = `${r.bottom + window.scrollY}px`;
        box.style.width = `${r.width}px`;
      };

      document.body.appendChild(box);
      positionBox();
      window.addEventListener("resize", rafThrottle(positionBox), { passive: true });
      window.addEventListener("scroll", rafThrottle(positionBox), { passive: true });

      let activeIndex = -1;
      let lastItems = [];
      let aborter = null;

      const close = () => {
        box.style.display = "none";
        box.innerHTML = "";
        activeIndex = -1;
        lastItems = [];
      };

      const render = (items) => {
        lastItems = items || [];
        activeIndex = -1;

        if (!lastItems.length) return close();

        box.innerHTML = lastItems
          .slice(0, CFG.autocomplete.limit)
          .map((it, idx) => {
            const title = (it && (it.title || it.name || it.label)) || "";
            const href = (it && it.href) || (title ? `/shop?q=${encodeURIComponent(title)}` : "#");
            return `
              <div class="ss-suggest__item" role="option" data-idx="${idx}" data-href="${href}"
                   style="padding:10px 12px;cursor:pointer;display:flex;gap:10px;align-items:center">
                <span style="width:8px;height:8px;border-radius:999px;background:linear-gradient(135deg,#2563eb,#0ea5e9);display:inline-block"></span>
                <span style="font-weight:900;color:rgba(10,16,32,.88);line-height:1.2">${title}</span>
              </div>
            `;
          })
          .join("");

        // hover style
        $$(".ss-suggest__item", box).forEach((row) => {
          row.addEventListener("mouseenter", () => {
            $$(".ss-suggest__item", box).forEach((r) => (r.style.background = "transparent"));
            row.style.background = "rgba(37,99,235,.08)";
          });
          row.addEventListener("click", () => {
            const href = row.getAttribute("data-href") || "#";
            window.location.href = href;
          });
        });

        box.style.display = "block";
      };

      const fetchSuggest = async (q) => {
        if (aborter) {
          try { aborter.abort(); } catch(_) {}
        }
        aborter = new AbortController();
        LIFECYCLE.aborters.add(aborter);

        const url = `${CFG.autocomplete.endpoint}${encodeURIComponent(q)}`;

        const res = await fetch(url, {
          signal: aborter.signal,
          headers: { "Accept": "application/json" },
          cache: "no-store",
        });

        if (!res.ok) return [];
        const data = await res.json();

        // soporta varios formatos:
        // {items:[...]} o [...] directo
        if (Array.isArray(data)) return data;
        if (data && Array.isArray(data.items)) return data.items;
        return [];
      };

      const onInput = debounce(async () => {
        const q = (input.value || "").trim();
        if (q.length < CFG.autocomplete.minChars) return close();

        try {
          const items = await fetchSuggest(q);
          render(items);
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

      input.addEventListener("keydown", (e) => {
        if (box.style.display === "none") return;

        const rows = $$(".ss-suggest__item", box);
        if (!rows.length) return;

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
            window.location.href = row.getAttribute("data-href");
          }
          return;
        } else {
          return;
        }

        rows.forEach((r) => (r.style.background = "transparent"));
        const row = rows[activeIndex];
        if (row) row.style.background = "rgba(37,99,235,.10)";
      });
    });

    // 12) Prefetch shop (micro performance)
    safe(() => {
      const link = document.createElement("link");
      link.rel = "prefetch";
      link.href = "/shop";
      document.head.appendChild(link);
    });

    log("home.js v2 ready");
  };

  // double-safe init
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }

})();
