/* ============================================================
   Skyline Store — HOME ULTRA PRO JS (v3)
   - Zero dependencies
   - No-throw design (si falta algo, NO rompe)
   - Motion safe + data saver
   - Performance: passive listeners + rAF throttle + pause on hidden
   - Features: preloader, reveal, sticky/toTop, hero motion, slider, autocomplete
============================================================ */

(() => {
  "use strict";

  // ----------------------------
  // Helpers (safe)
  // ----------------------------
  const $ = (sel, el = document) => (el ? el.querySelector(sel) : null);
  const $$ = (sel, el = document) => (el ? Array.from(el.querySelectorAll(sel)) : []);
  const clamp = (n, a, b) => Math.max(a, Math.min(b, n));

  const safe = (fn) => { try { fn(); } catch (_) {} };

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

  const reducedMotion = !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  const reducedData = !!(navigator.connection && navigator.connection.saveData);

  const isTouch = ("ontouchstart" in window) || (navigator.maxTouchPoints || 0) > 0;
  const isFinePointer = !!(window.matchMedia && window.matchMedia("(pointer: fine)").matches);

  const log = (..._args) => {
    // console.log("[home.js]", ..._args);
  };

  // ----------------------------
  // Guard: solo en home (robusto)
  // ----------------------------
  const path = String(location.pathname || "/");
  const isHome =
    (document.body && document.body.classList.contains("home")) ||
    !!document.querySelector("#hp") ||
    !!document.querySelector(".hp") ||
    path === "/" || path === "/home" || path === "/home/" || path === "/index" || path === "/index.html";

  if (!isHome) return;

  // ----------------------------
  // Config (alineado a tu index.html)
  // ----------------------------
  const CFG = {
    preloader: { sel: "#ss-preloader", fadeMs: 260 },

    reveal: {
      selector: "[data-reveal]",
      threshold: 0.12,
      rootMargin: "0px 0px -8% 0px",
      staggerMs: 45,
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

      this.intervals.forEach((id) => { try { clearInterval(id); } catch (_) {} });
      this.intervals.clear();

      this.observers.forEach((o) => { try { o.disconnect(); } catch (_) {} });
      this.observers.clear();

      this.aborters.forEach((a) => { try { a.abort(); } catch (_) {} });
      this.aborters.clear();
    },
  };

  document.addEventListener("visibilitychange", () => {
    LIFECYCLE.alive = !document.hidden;
  });

  // Safari/mobile friendly: cleanup on pagehide
  window.addEventListener("pagehide", () => safe(() => LIFECYCLE.stopAll()), { once: true });

  // ----------------------------
  // Small util: safe text injection (XSS-safe)
  // ----------------------------
  const esc = (s) =>
    String(s ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");

  // ----------------------------
  // Init
  // ----------------------------
  const init = () => {
    // 0) Preloader fade
    safe(() => {
      const p = $(CFG.preloader.sel);
      if (!p) return;

      requestAnimationFrame(() => {
        p.style.transition = `opacity ${CFG.preloader.fadeMs}ms ease`;
        p.style.opacity = "0";
        setTimeout(() => { try { p.remove?.(); } catch (_) {} }, CFG.preloader.fadeMs + 60);
      });
    });

    // 1) Reveal (stagger por sección)
    safe(() => {
      const nodes = $$(CFG.reveal.selector);
      if (!nodes.length) return;

      if (reducedMotion || !supportsIO) {
        nodes.forEach((n) => n.classList.add("is-in"));
        return;
      }

      // index por sección para stagger O(n)
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

    // 2) Sticky + ToTop (hidden + class)
    safe(() => {
      const toTop = $(CFG.toTop.sel);
      const sticky = $(CFG.sticky.sel);

      const apply = () => {
        const y = window.scrollY || 0;

        if (toTop) {
          const on = y > CFG.toTop.showAt;
          toTop.hidden = !on;
          if (on) toTop.style.display = "inline-flex";
          else toTop.style.display = "";
        }

        if (sticky) {
          sticky.classList.toggle("is-on", y > CFG.sticky.showAt);
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

    // 3) Shortcut "/" focus search
    safe(() => {
      const input = $(CFG.search.candidates);
      if (!input) return;

      document.addEventListener("keydown", (e) => {
        const el = document.activeElement;
        const tag = (el && el.tagName) ? el.tagName.toUpperCase() : "";
        const typing =
          tag === "INPUT" ||
          tag === "TEXTAREA" ||
          tag === "SELECT" ||
          !!(el && el.isContentEditable);

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

    // 4) Hero motion (pointer + scroll), pausado cuando hidden
    safe(() => {
      if (!CFG.hero.enable) return;

      const hero = $(CFG.hero.containerSel);
      const img = hero ? $(CFG.hero.imgSel, hero) : null;
      if (!hero || !img) return;

      let mx = 0, my = 0, sx = 0, sy = 0;
      let rect = hero.getBoundingClientRect();
      let lastTransform = "";

      const updateRect = () => { rect = hero.getBoundingClientRect(); };
      const onResize = rafThrottle(updateRect);

      if (supportsRO) {
        const ro = new ResizeObserver(updateRect);
        ro.observe(hero);
        LIFECYCLE.observers.add(ro);
      } else {
        window.addEventListener("resize", onResize, { passive: true });
      }

      const onMove = rafThrottle((e) => {
        const px = (e.clientX - rect.left) / Math.max(1, rect.width) - 0.5;
        const py = (e.clientY - rect.top) / Math.max(1, rect.height) - 0.5;
        mx = px * CFG.hero.maxMoveX;
        my = py * CFG.hero.maxMoveY;
      });

      hero.addEventListener("pointerenter", () => updateRect(), { passive: true });
      hero.addEventListener("pointermove", onMove, { passive: true });
      hero.addEventListener("pointerleave", () => { mx = 0; my = 0; }, { passive: true });

      const onScroll = rafThrottle(() => {
        updateRect();
        const r = rect;
        const viewH = window.innerHeight || 900;
        const t = clamp(1 - r.top / viewH, 0, 1);
        // targetY scroll
        const target = -(t * CFG.hero.scrollParallax);
        sy += (target - sy) * 0.08;
      });

      window.addEventListener("scroll", onScroll, { passive: true });
      onScroll();

      const tick = () => {
        if (LIFECYCLE.alive) {
          sx += (mx - sx) * 0.10;
          const combinedY = sy + (my - (sy * 0.15));

          const tr = `scale(${CFG.hero.scale}) translate3d(${sx.toFixed(2)}px, ${combinedY.toFixed(2)}px, 0)`;
          if (tr !== lastTransform) {
            img.style.transform = tr;
            lastTransform = tr;
          }
        }
        requestAnimationFrame(tick);
      };

      requestAnimationFrame(tick);
    });

    // 5) Ambient glow follow (liviano)
    safe(() => {
      if (!CFG.hero.enable) return;

      const hero = $(CFG.hero.containerSel);
      if (!hero) return;

      // no duplicar
      if (hero.querySelector(".ss-heroGlow")) return;

      const glow = document.createElement("div");
      glow.className = "ss-heroGlow";
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
          `radial-gradient(420px 280px at ${clamp(x + 14, 0, 100)}% ${clamp(y - 10, 0, 100)}%, rgba(14,165,233,.16), transparent 62%)`;
      });

      hero.addEventListener("pointerenter", () => (glow.style.opacity = "1"), { passive: true });
      hero.addEventListener("pointerleave", () => (glow.style.opacity = "0"), { passive: true });
      hero.addEventListener("pointermove", moveGlow, { passive: true });
    });

    // 6) Pills interactive (toggle + scroll + aria)
    safe(() => {
      const pills = $$(CFG.pills.selector);
      if (!pills.length) return;

      const setPressed = (el, pressed) => el.setAttribute("aria-pressed", pressed ? "true" : "false");

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

    // 7) Image safety (solo si hay errores)
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

    // 8) Rotate trust copy
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
        try { t.textContent = t.dataset.originalText || original; } catch (_) {}
      };
      window.addEventListener("beforeunload", restore, { once: true });
      window.addEventListener("pagehide", restore, { once: true });
    });

    // 9) Hotkeys (g = scroll a grid si existe)
    safe(() => {
      document.addEventListener("keydown", (e) => {
        if (e.ctrlKey || e.metaKey || e.altKey) return;

        const el = document.activeElement;
        const tag = (el && el.tagName) ? el.tagName.toUpperCase() : "";
        if (tag === "INPUT" || tag === "TEXTAREA" || !!(el && el.isContentEditable)) return;

        if (e.key && e.key.toLowerCase() === "g") {
          const grid = document.getElementById("hpGrid");
          grid?.scrollIntoView({ behavior: reducedMotion ? "auto" : "smooth", block: "start" });
        }
      });
    });

    // 10) MINI SLIDER (si existe #hpMiniTrack)
    safe(() => {
      if (reducedMotion) return;

      const track = $(CFG.miniSlider.trackSel);
      if (!track || !track.parentElement) return;

      // evitar duplicar
      if (document.getElementById("hpMiniTrackClone")) return;

      const wrap = track.parentElement;
      const baseW = () => track.scrollWidth || 0;

      let running = true;
      let x = 0;
      let last = performance.now();

      // duplicamos contenido para loop suave
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

      // drag (pointer)
      if (CFG.miniSlider.drag && isFinePointer) {
        let down = false, startX = 0, startOffset = 0;

        wrap.style.cursor = "grab";

        const onDown = (e) => {
          down = true;
          running = false;
          wrap.style.cursor = "grabbing";
          startX = e.clientX;
          startOffset = x;
          try { wrap.setPointerCapture?.(e.pointerId); } catch (_) {}
        };

        const onMove = (e) => {
          if (!down) return;
          const w = baseW();
          const dx = e.clientX - startX;
          x = startOffset - dx;
          // wrap
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

    // 11) AUTOCOMPLETE (si existe input)
    safe(() => {
      if (!CFG.autocomplete.enable) return;

      const input = $(CFG.search.candidates);
      if (!input) return;

      // Cache simple
      const cache = new Map();

      const cacheSet = (k, v) => {
        cache.set(k, v);
        if (cache.size > CFG.autocomplete.cacheSize) {
          const first = cache.keys().next().value;
          cache.delete(first);
        }
      };

      const host = input.closest("form") || input.parentElement || document.body;

      const box = document.createElement("div");
      box.className = "ss-suggest";
      box.setAttribute("role", "listbox");
      box.setAttribute("aria-label", "Sugerencias");
      box.style.position = "absolute";
      box.style.zIndex = "9999";
      box.style.display = "none";

      // minimal styles + dark support
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
              <div id="${id}" class="ss-suggest__item" role="option" data-idx="${idx}" data-href="${href}"
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
          row.addEventListener("mouseenter", () => {
            rows.forEach((r) => (r.style.background = "transparent"));
            row.style.background = isDark ? "rgba(255,255,255,.06)" : "rgba(37,99,235,.08)";
          });
          row.addEventListener("click", () => {
            const href = row.getAttribute("data-href") || "#";
            window.location.href = href;
          });
        });
      };

      const fetchSuggest = async (q) => {
        if (cache.has(q)) return cache.get(q);

        if (aborter) {
          try { aborter.abort(); } catch (_) {}
          LIFECYCLE.aborters.delete(aborter);
        }
        aborter = new AbortController();
        LIFECYCLE.aborters.add(aborter);

        const url = `${CFG.autocomplete.endpoint}${encodeURIComponent(q)}`;
        const res = await fetch(url, {
          signal: aborter.signal,
          headers: { Accept: "application/json" },
          cache: "no-store",
          credentials: "same-origin",
        });

        if (!res.ok) return [];
        const data = await res.json().catch(() => null);

        const items = Array.isArray(data) ? data : (data && Array.isArray(data.items) ? data.items : []);
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

      // close on click outside
      document.addEventListener("click", (e) => {
        if (e.target === input) return;
        if (box.contains(e.target)) return;
        close();
      });

      // close on blur (with small delay to allow click)
      input.addEventListener("blur", () => setTimeout(close, 120));

      // keyboard nav
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

        rows.forEach((r) => (r.style.background = "transparent"));
        const row = rows[activeIndex];
        if (row) {
          row.style.background = isDark ? "rgba(255,255,255,.06)" : "rgba(37,99,235,.10)";
          input.setAttribute("aria-activedescendant", row.id || "");
        }
      });
    });

    // 12) Prefetch shop (micro perf, no dup)
    safe(() => {
      const exists = $$('link[rel="prefetch"]').some((l) => (l.getAttribute("href") || "") === "/shop");
      if (exists) return;
      const link = document.createElement("link");
      link.rel = "prefetch";
      link.href = "/shop";
      document.head.appendChild(link);
    });

    log("home.js v3 ready");
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})();
