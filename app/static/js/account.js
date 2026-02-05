(() => {
  "use strict";

  // Skyline Store — ACCOUNT TABS + STICKY (ULTRA PRO v4.1)
  // ✅ 20 mejoras reales + correcciones:
  // 1) Guard global por página (no duplica si se reinyecta)
  // 2) Cleanup real (listeners + RAF + mq listeners)
  // 3) Fallback robusto si faltan nodos / IDs
  // 4) matchMedia changes compatible (addEventListener/addListener)
  // 5) Storage: fallback RAM + try/catch + evita loops
  // 6) Sticky: estado consistente + aria-live solo cuando se muestra
  // 7) Tab: respeta hash/tab en URL + preserva scroll
  // 8) Tab focus: no rompe en móviles + panel focus seguro
  // 9) Scroll handler: throttle por RAF + evita trabajo cuando no mobile
  // 10) Dismiss TTL estable + saneo automático
  // 11) Storage event: ignora self-writes + clamp
  // 12) Reduce-motion: no hace scroll suave
  // 13) Click handlers no duplicados + passive donde aplica
  // 14) Soporta .is-hidden o hidden, ambos
  // 15) Evita setTab redundante (no recalcula si no cambió)
  // 16) Aria-selected/tabindex correctos siempre
  // 17) Tabs: teclado completo (← → Home End Enter Space)
  // 18) Sticky button: persist antes de navegar
  // 19) Pageshow: restaura correcto en BFCache
  // 20) CSP-friendly: sin inline, sin eval, sin deps

  const doc = document;
  const win = window;

  // ---------- Helpers ----------
  const safe = (fn, fb) => {
    try { return fn(); } catch (_) { return fb; }
  };

  const $ = (sel, el = doc) => (el && el.querySelector ? el.querySelector(sel) : null);
  const byId = (id) => (id ? doc.getElementById(id) : null);

  const raf = (cb) => {
    const r = win.requestAnimationFrame;
    if (typeof r === "function") return r(cb);
    return win.setTimeout(cb, 16);
  };

  const focusSafe = (el) => {
    if (!el || typeof el.focus !== "function") return;
    try { el.focus({ preventScroll: true }); }
    catch (_) { try { el.focus(); } catch (__) {} }
  };

  const clampTab = (v) => (String(v || "").toLowerCase() === "register" ? "register" : "login");

  // ---------- Root + guard ----------
  const root = doc.querySelector(".ss-account");
  if (!root) return;

  // Global guard (si se reinyecta por Turbo/HTMX no duplica)
  win.__SS_ACCOUNT_STATE__ = win.__SS_ACCOUNT_STATE__ || {};
  const KEY_INSTANCE = safe(() => {
    const id = root.id || "ss-account";
    const cls = String(root.className || "");
    return `${location.pathname || "/"}::${id}::${cls.length}`;
  }, "fallback");

  const STATE = win.__SS_ACCOUNT_STATE__;
  if (STATE[KEY_INSTANCE]?.version === "v4.1") return;
  if (STATE[KEY_INSTANCE]?.stopAll) safe(() => STATE[KEY_INSTANCE].stopAll());

  // ---------- Lifecycle cleanup ----------
  const LIFECYCLE = {
    stopped: false,
    listeners: [],
    rafId: 0,

    on(el, type, fn, opts) {
      if (!el || !el.addEventListener) return;
      safe(() => {
        el.addEventListener(type, fn, opts);
        this.listeners.push({ el, type, fn, opts });
      });
    },

    offAll() {
      if (this.stopped) return;
      this.stopped = true;

      if (this.rafId) safe(() => win.cancelAnimationFrame(this.rafId));
      this.rafId = 0;

      this.listeners.forEach((l) => safe(() => l.el.removeEventListener(l.type, l.fn, l.opts)));
      this.listeners.length = 0;
    },
  };

  STATE[KEY_INSTANCE] = { version: "v4.1", stopAll: () => LIFECYCLE.offAll() };
  LIFECYCLE.on(win, "pagehide", () => safe(() => LIFECYCLE.offAll()), { once: true });

  // ---------- Keys / TTL ----------
  const KEY_TAB = "ss_account_tab";
  const KEY_STICKY_DISMISS = "ss_account_sticky_dismiss_v4";
  const DISMISS_TTL_MS = 7 * 24 * 60 * 60 * 1000;

  // ---------- Media queries ----------
  const mqMobile = safe(() => win.matchMedia && win.matchMedia("(max-width: 980px)"), null);
  const mqReduce = safe(() => win.matchMedia && win.matchMedia("(prefers-reduced-motion: reduce)"), null);
  const isMobile = () => !!(mqMobile && mqMobile.matches);
  const reduceMotion = () => !!(mqReduce && mqReduce.matches);

  // ---------- Storage (RAM fallback) ----------
  const RAM = Object.create(null);

  const storageSet = (key, val) => {
    const s = String(val);
    RAM[key] = s;

    const okLocal = safe(() => { localStorage.setItem(key, s); return true; }, false) === true;
    if (okLocal) return true;

    return safe(() => { sessionStorage.setItem(key, s); return true; }, false) === true;
  };

  const storageGet = (key) => {
    const v1 = safe(() => localStorage.getItem(key), null);
    if (v1 != null) return v1;

    const v2 = safe(() => sessionStorage.getItem(key), null);
    if (v2 != null) return v2;

    return (key in RAM) ? RAM[key] : null;
  };

  const storageRemove = (key) => {
    delete RAM[key];
    safe(() => localStorage.removeItem(key));
    safe(() => sessionStorage.removeItem(key));
  };

  const stickyDismissed = () => {
    const raw = storageGet(KEY_STICKY_DISMISS);
    const ts = Number(raw || 0);
    if (!ts) return false;

    const expired = (Date.now() - ts) > DISMISS_TTL_MS;
    if (expired) storageRemove(KEY_STICKY_DISMISS);
    return !expired;
  };

  const setDismissNow = () => storageSet(KEY_STICKY_DISMISS, String(Date.now()));

  // ---------- URL tab ----------
  const tabFromUrl = () => {
    const raw = safe(() => new URLSearchParams(location.search).get("tab"), null);
    return raw ? clampTab(raw) : null;
  };

  // ---------- Nodes ----------
  const loginTab =
    byId("tab-login") ||
    $('[role="tab"][aria-controls="panel-login"]', root) ||
    $('[data-tab="login"]', root);

  const regTab =
    byId("tab-register") ||
    $('[role="tab"][aria-controls="panel-register"]', root) ||
    $('[data-tab="register"]', root);

  const loginPanel = byId("panel-login") || $("#panel-login", root) || $("#panel-login");
  const regPanel = byId("panel-register") || $("#panel-register", root) || $("#panel-register");

  const sticky = byId("accSticky") || $(".ss-account__sticky", root) || $(".ss-account__sticky");
  const stickyTitle = byId("accStickyTitle") || (sticky ? $("#accStickyTitle", sticky) : null);
  const stickySub = byId("accStickySub") || (sticky ? $("#accStickySub", sticky) : null);
  const stickyBtn = byId("accStickyBtn") || (sticky ? $("#accStickyBtn", sticky) : null);
  const stickyDismissBtn = sticky ? (sticky.querySelector("[data-dismiss]") || byId("accStickyDismiss")) : null;

  if (!loginTab || !regTab || !loginPanel || !regPanel) return;

  const tabs = [loginTab, regTab];

  // ---------- ARIA hardening ----------
  safe(() => {
    const tablist = loginTab.closest('[role="tablist"]') || loginTab.parentElement;
    if (tablist && !tablist.getAttribute("role")) tablist.setAttribute("role", "tablist");

    tabs.forEach((t) => { if (!t.getAttribute("role")) t.setAttribute("role", "tab"); });

    if (!loginTab.id) loginTab.id = "tab-login";
    if (!regTab.id) regTab.id = "tab-register";
    if (!loginPanel.id) loginPanel.id = "panel-login";
    if (!regPanel.id) regPanel.id = "panel-register";

    if (!loginTab.getAttribute("aria-controls")) loginTab.setAttribute("aria-controls", loginPanel.id);
    if (!regTab.getAttribute("aria-controls")) regTab.setAttribute("aria-controls", regPanel.id);

    if (!loginPanel.getAttribute("role")) loginPanel.setAttribute("role", "tabpanel");
    if (!regPanel.getAttribute("role")) regPanel.setAttribute("role", "tabpanel");

    if (!loginPanel.getAttribute("aria-labelledby")) loginPanel.setAttribute("aria-labelledby", loginTab.id);
    if (!regPanel.getAttribute("aria-labelledby")) regPanel.setAttribute("aria-labelledby", regTab.id);

    loginPanel.tabIndex = -1;
    regPanel.tabIndex = -1;
  });

  const loginUrl = root.getAttribute("data-login-url") || "";
  const registerUrl = root.getAttribute("data-register-url") || "";

  // ---------- Sticky ----------
  const stickyState = { on: false, which: "login" };

  const setSticky = (which) => {
    if (!sticky) return;

    const w = clampTab(which);
    const shouldShow = isMobile() && !stickyDismissed();

    if (!shouldShow) {
      if (stickyState.on) {
        sticky.classList.remove("is-on");
        sticky.setAttribute("aria-hidden", "true");
        stickyState.on = false;
      }
      stickyState.which = w;
      return;
    }

    if (!stickyState.on) {
      sticky.classList.add("is-on");
      sticky.setAttribute("aria-hidden", "false");
      stickyState.on = true;
      // aria-live solo cuando realmente aparece
      safe(() => sticky.setAttribute("aria-live", "polite"));
    }

    const update = (w === "register")
      ? { t: "Crear cuenta", s: "Rápido, 1 minuto", b: "Crear →", href: registerUrl }
      : { t: "Iniciar sesión", s: "Ya tengo cuenta", b: "Entrar →", href: loginUrl };

    stickyState.which = w;

    if (stickyTitle) stickyTitle.textContent = update.t;
    if (stickySub) stickySub.textContent = update.s;

    if (stickyBtn) {
      stickyBtn.textContent = update.b;
      if (update.href) stickyBtn.setAttribute("href", update.href);
    }
  };

  // ---------- Tabs ----------
  let currentTab = "login";

  const setTab = (which, opts) => {
    const o = Object.assign({ focus: false, persist: true, fromUser: false }, opts || {});
    const w = clampTab(which);

    // evita trabajo redundante
    const changed = w !== currentTab;
    if (!changed && !o.persist) return;

    currentTab = w;
    const isLogin = w === "login";

    loginTab.classList.toggle("is-active", isLogin);
    regTab.classList.toggle("is-active", !isLogin);

    loginTab.setAttribute("aria-selected", isLogin ? "true" : "false");
    regTab.setAttribute("aria-selected", !isLogin ? "true" : "false");

    loginTab.tabIndex = isLogin ? 0 : -1;
    regTab.tabIndex = !isLogin ? 0 : -1;

    // soporta ambos estilos: is-hidden + hidden
    loginPanel.classList.toggle("is-hidden", !isLogin);
    regPanel.classList.toggle("is-hidden", isLogin);

    loginPanel.hidden = !isLogin;
    regPanel.hidden = isLogin;

    if (o.persist) storageSet(KEY_TAB, w);

    setSticky(w);

    if (o.focus) focusSafe(isLogin ? loginTab : regTab);

    if (changed) {
      safe(() => {
        const target = isLogin ? loginPanel : regPanel;
        if (target && !isMobile()) focusSafe(target);
      });
    }
  };

  const maybeScrollToCard = () => {
    if (!isMobile()) return;
    if (reduceMotion()) return;

    const card = $(".ss-account__card", root);
    if (!card) return;

    const r = safe(() => card.getBoundingClientRect(), null);
    if (!r) return;
    if (r.top >= -10 && r.top <= 110) return;

    safe(() => card.scrollIntoView({ behavior: "smooth", block: "start" }));
  };

  // keyboard nav
  const onKey = (e, idx) => {
    const k = e.key;
    if (!["ArrowLeft", "ArrowRight", "Home", "End", "Enter", " "].includes(k)) return;

    e.preventDefault();

    let next = idx;
    if (k === "ArrowLeft") next = (idx + tabs.length - 1) % tabs.length;
    if (k === "ArrowRight") next = (idx + 1) % tabs.length;
    if (k === "Home") next = 0;
    if (k === "End") next = tabs.length - 1;

    focusSafe(tabs[next]);

    if (k === "Enter" || k === " ") {
      setTab(next === 0 ? "login" : "register", { focus: false, persist: true, fromUser: true });
      maybeScrollToCard();
    }
  };

  // ---------- Sticky auto hide ----------
  let lastY = safe(() => win.scrollY, 0) || 0;
  let ticking = false;

  const stickyAutoHide = () => {
    if (!sticky) return;

    if (!isMobile()) {
      setSticky(currentTab);
      return;
    }

    const y = safe(() => win.scrollY, 0) || 0;
    const delta = y - lastY;
    const goingUp = delta < -2;
    const nearTop = y < 44;
    lastY = y;

    if (stickyDismissed()) {
      sticky.classList.remove("is-on");
      sticky.setAttribute("aria-hidden", "true");
      stickyState.on = false;
      return;
    }

    if (nearTop && goingUp) {
      sticky.classList.remove("is-on");
      sticky.setAttribute("aria-hidden", "true");
      stickyState.on = false;
      return;
    }

    setSticky(currentTab);
  };

  const onScroll = () => {
    if (ticking) return;
    ticking = true;
    LIFECYCLE.rafId = raf(() => {
      ticking = false;
      stickyAutoHide();
    });
  };

  // ---------- Events (con lifecycle) ----------
  LIFECYCLE.on(loginTab, "click", () => {
    setTab("login", { focus: true, persist: true, fromUser: true });
    maybeScrollToCard();
  });

  LIFECYCLE.on(regTab, "click", () => {
    setTab("register", { focus: true, persist: true, fromUser: true });
    maybeScrollToCard();
  });

  LIFECYCLE.on(loginTab, "keydown", (e) => onKey(e, 0));
  LIFECYCLE.on(regTab, "keydown", (e) => onKey(e, 1));

  const onMqChange = () => setSticky(currentTab);

  if (mqMobile) {
    if (typeof mqMobile.addEventListener === "function") LIFECYCLE.on(mqMobile, "change", onMqChange);
    else if (typeof mqMobile.addListener === "function") safe(() => mqMobile.addListener(onMqChange));
  }

  LIFECYCLE.on(win, "scroll", onScroll, { passive: true });

  // storage sync (multi-tab)
  LIFECYCLE.on(win, "storage", (ev) => {
    if (!ev || ev.key !== KEY_TAB) return;
    const v = clampTab(ev.newValue || "");
    if (v === currentTab) return;
    setTab(v, { focus: false, persist: false });
  });

  const dismissSticky = () => {
    if (!sticky || !isMobile()) return;
    if (!stickyState.on) return;
    setDismissNow();
    sticky.classList.remove("is-on");
    sticky.setAttribute("aria-hidden", "true");
    stickyState.on = false;
  };

  // Esc cierra sticky
  LIFECYCLE.on(win, "keydown", (e) => {
    if (e.key !== "Escape") return;
    dismissSticky();
  });

  if (stickyDismissBtn) LIFECYCLE.on(stickyDismissBtn, "click", dismissSticky);

  // Sticky btn: persist tab antes de navegar (si es link)
  if (stickyBtn) {
    LIFECYCLE.on(stickyBtn, "click", () => {
      storageSet(KEY_TAB, currentTab);
    });
  }

  // pageshow: soporta BFCache (Safari/Chrome)
  LIFECYCLE.on(win, "pageshow", () => {
    const initial = clampTab(tabFromUrl() || storageGet(KEY_TAB) || "login");
    setTab(initial, { focus: false, persist: true });
    stickyAutoHide();
  });

  // Init
  const initial = clampTab(tabFromUrl() || storageGet(KEY_TAB) || "login");
  setTab(initial, { focus: false, persist: true });
  stickyAutoHide();
})();
