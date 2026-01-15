/* Skyline Store — Account Tabs (ULTRA PRO v4 FINAL)
   ✅ accesible + teclado (roving tabindex)
   ✅ guarda elección (localStorage -> sessionStorage -> RAM)
   ✅ sticky mobile robusto + auto-hide (rAF throttled)
   ✅ TTL para dismiss (no queda muerto para siempre)
   ✅ sync entre pestañas + BFCache safe
   ✅ no rompe si faltan nodos / init ultra safe
*/
(function () {
  "use strict";

  // -----------------------
  // Root guard (por instancia)
  // -----------------------
  const root = document.querySelector(".ss-account");
  if (!root) return;

  // evita doble init si el DOM no cambió
  if (root.dataset.ssAccountInit === "1") return;
  root.dataset.ssAccountInit = "1";

  // -----------------------
  // Helpers
  // -----------------------
  const safe = (fn) => { try { return fn(); } catch (_) { return undefined; } };
  const $ = (sel, el) => (el || document).querySelector(sel);
  const byId = (id) => document.getElementById(id);

  const KEY_TAB = "ss_account_tab";
  const KEY_STICKY_DISMISS = "ss_account_sticky_dismiss_v2"; // guarda timestamp (ms)
  const DISMISS_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 días

  const mqMobile = window.matchMedia ? window.matchMedia("(max-width: 980px)") : null;
  const mqReduceMotion = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : null;

  const clampTab = (v) => (v === "register" ? "register" : "login");

  const isMobile = () => !!(mqMobile && mqMobile.matches);

  // -----------------------
  // Storage (local -> session -> RAM)
  // -----------------------
  const RAM = Object.create(null);

  const storageSet = (key, val) => {
    RAM[key] = String(val);
    let ok = false;

    ok = safe(() => { localStorage.setItem(key, String(val)); return true; }) === true;
    if (ok) return;

    safe(() => { sessionStorage.setItem(key, String(val)); });
  };

  const storageGet = (key) => {
    const vLocal = safe(() => localStorage.getItem(key));
    if (vLocal !== undefined && vLocal !== null) return vLocal;

    const vSess = safe(() => sessionStorage.getItem(key));
    if (vSess !== undefined && vSess !== null) return vSess;

    return (key in RAM) ? RAM[key] : null;
  };

  const storageRemove = (key) => {
    delete RAM[key];
    safe(() => localStorage.removeItem(key));
    safe(() => sessionStorage.removeItem(key));
  };

  // Dismiss con TTL
  const stickyDismissed = () => {
    const raw = storageGet(KEY_STICKY_DISMISS);
    const ts = Number(raw || 0);
    if (!ts) return false;
    const expired = (Date.now() - ts) > DISMISS_TTL_MS;
    if (expired) storageRemove(KEY_STICKY_DISMISS);
    return !expired;
  };

  const setDismissNow = () => storageSet(KEY_STICKY_DISMISS, String(Date.now()));

  // lee tab desde URL (?tab=login/register) como override suave
  const tabFromUrl = () => {
    const qs = safe(() => new URLSearchParams(location.search));
    if (!qs) return null;
    const t = clampTab(qs.get("tab") || "");
    return t;
  };

  // -----------------------
  // Nodes (IDs primary, fallback selectors)
  // -----------------------
  const loginTab = byId("tab-login") || $('[role="tab"][aria-controls="panel-login"]') || $('[data-tab="login"]');
  const regTab = byId("tab-register") || $('[role="tab"][aria-controls="panel-register"]') || $('[data-tab="register"]');

  const loginPanel = byId("panel-login") || $("#panel-login");
  const regPanel = byId("panel-register") || $("#panel-register");

  const sticky = byId("accSticky") || $(".ss-account__sticky");
  const stickyTitle = byId("accStickyTitle") || (sticky ? $("#accStickyTitle", sticky) : null);
  const stickySub = byId("accStickySub") || (sticky ? $("#accStickySub", sticky) : null);
  const stickyBtn = byId("accStickyBtn") || (sticky ? $("#accStickyBtn", sticky) : null);

  if (!loginTab || !regTab || !loginPanel || !regPanel) return;

  const tabs = [loginTab, regTab];

  // A11y: tablist + roles si faltan
  safe(() => {
    const tablist = loginTab.closest('[role="tablist"]') || loginTab.parentElement;
    if (tablist && !tablist.getAttribute("role")) tablist.setAttribute("role", "tablist");

    tabs.forEach((t) => {
      if (!t.getAttribute("role")) t.setAttribute("role", "tab");
    });

    if (!loginTab.getAttribute("aria-controls")) loginTab.setAttribute("aria-controls", "panel-login");
    if (!regTab.getAttribute("aria-controls")) regTab.setAttribute("aria-controls", "panel-register");

    if (!loginPanel.getAttribute("role")) loginPanel.setAttribute("role", "tabpanel");
    if (!regPanel.getAttribute("role")) regPanel.setAttribute("role", "tabpanel");

    if (!loginPanel.id) loginPanel.id = "panel-login";
    if (!regPanel.id) regPanel.id = "panel-register";

    // link tab <-> panel
    if (!loginPanel.getAttribute("aria-labelledby")) loginPanel.setAttribute("aria-labelledby", loginTab.id || "tab-login");
    if (!regPanel.getAttribute("aria-labelledby")) regPanel.setAttribute("aria-labelledby", regTab.id || "tab-register");
  });

  // URLs desde dataset (ya vienen resueltas en el template)
  const loginUrl = root.getAttribute("data-login-url") || "";
  const registerUrl = root.getAttribute("data-register-url") || "";

  // -----------------------
  // Sticky state (evita DOM updates repetidos)
  // -----------------------
  const stickyState = { on: false, which: "login" };

  const setSticky = (which) => {
    if (!sticky) return;

    const w = clampTab(which);

    // apagar condiciones
    if (!isMobile() || stickyDismissed()) {
      if (stickyState.on) {
        sticky.classList.remove("is-on");
        sticky.setAttribute("aria-hidden", "true");
        stickyState.on = false;
      }
      stickyState.which = w;
      return;
    }

    // encender si está apagado
    if (!stickyState.on) {
      sticky.classList.add("is-on");
      sticky.setAttribute("aria-hidden", "false");
      stickyState.on = true;
      // opcional: anunciar cambios suaves
      safe(() => sticky.setAttribute("aria-live", "polite"));
    }

    // actualizar contenido solo si cambió
    if (stickyState.which !== w) {
      stickyState.which = w;

      if (w === "register") {
        if (stickyTitle) stickyTitle.textContent = "Crear cuenta";
        if (stickySub) stickySub.textContent = "Rápido, 1 minuto";
        if (stickyBtn) {
          stickyBtn.textContent = "Crear →";
          if (registerUrl) stickyBtn.href = registerUrl;
        }
      } else {
        if (stickyTitle) stickyTitle.textContent = "Iniciar sesión";
        if (stickySub) stickySub.textContent = "Ya tengo cuenta";
        if (stickyBtn) {
          stickyBtn.textContent = "Entrar →";
          if (loginUrl) stickyBtn.href = loginUrl;
        }
      }
    }
  };

  // -----------------------
  // Tabs
  // -----------------------
  let currentTab = "login";

  const setTab = (which, opts) => {
    const options = Object.assign({ focus: false, persist: true, fromUser: false }, opts || {});
    const w = clampTab(which);

    // no hacer trabajo si no cambia
    if (w === currentTab && options.persist === false) {
      setSticky(w);
      return;
    }

    currentTab = w;
    const isLogin = w === "login";

    // classes
    loginTab.classList.toggle("is-active", isLogin);
    regTab.classList.toggle("is-active", !isLogin);

    // aria
    loginTab.setAttribute("aria-selected", isLogin ? "true" : "false");
    regTab.setAttribute("aria-selected", !isLogin ? "true" : "false");

    // roving tabindex
    loginTab.tabIndex = isLogin ? 0 : -1;
    regTab.tabIndex = !isLogin ? 0 : -1;

    // panels (hidden + class)
    loginPanel.classList.toggle("is-hidden", !isLogin);
    regPanel.classList.toggle("is-hidden", isLogin);

    loginPanel.hidden = !isLogin;
    regPanel.hidden = isLogin;

    if (options.persist) storageSet(KEY_TAB, w);

    // si el usuario cambió tab manualmente, opcionalmente re-habilitar sticky
    if (options.fromUser) {
      // si estaba dismiss, no lo levantamos forzado (mantiene opt-out)
      // pero si querés “reactivar” al interactuar, descomentá:
      // storageRemove(KEY_STICKY_DISMISS);
    }

    setSticky(w);

    if (options.focus) {
      (isLogin ? loginTab : regTab).focus({ preventScroll: true });
    }
  };

  const onKey = (e, idx) => {
    const k = e.key;
    const allowed = ["ArrowLeft", "ArrowRight", "Home", "End", "Enter", " "];
    if (!allowed.includes(k)) return;

    e.preventDefault();

    let next = idx;
    if (k === "ArrowLeft") next = (idx + tabs.length - 1) % tabs.length;
    if (k === "ArrowRight") next = (idx + 1) % tabs.length;
    if (k === "Home") next = 0;
    if (k === "End") next = tabs.length - 1;

    tabs[next].focus({ preventScroll: true });

    if (k === "Enter" || k === " ") {
      setTab(next === 0 ? "login" : "register", { focus: false, persist: true, fromUser: true });
      maybeScrollToCard();
    }
  };

  // -----------------------
  // Sticky auto-hide (rAF throttled)
  // -----------------------
  let lastY = window.scrollY || 0;
  let ticking = false;

  const stickyAutoHide = () => {
    if (!sticky) return;

    // si no es mobile: off
    if (!isMobile()) {
      setSticky(currentTab);
      return;
    }

    const y = window.scrollY || 0;
    const delta = y - lastY;
    const goingUp = delta < -2;
    const goingDown = delta > 2;
    const nearTop = y < 44;
    lastY = y;

    if (stickyDismissed()) {
      sticky.classList.remove("is-on");
      sticky.setAttribute("aria-hidden", "true");
      stickyState.on = false;
      return;
    }

    // cerca del top: escondemos para que no tape
    if (nearTop && goingUp) {
      sticky.classList.remove("is-on");
      sticky.setAttribute("aria-hidden", "true");
      stickyState.on = false;
      return;
    }

    // si está scrolleando hacia abajo fuerte, puede auto-hide sutil (opcional)
    if (!nearTop && goingDown && stickyState.on) {
      // leve hide si querés efecto “auto-hide”
      // sticky.classList.remove("is-on");
      // sticky.setAttribute("aria-hidden", "true");
      // stickyState.on = false;
      // return;
    }

    setSticky(currentTab);
  };

  const onScroll = () => {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(() => {
      ticking = false;
      stickyAutoHide();
    });
  };

  // -----------------------
  // Optional: scroll suave al cambiar tab
  // -----------------------
  const maybeScrollToCard = () => {
    if (mqReduceMotion && mqReduceMotion.matches) return;
    if (!isMobile()) return;

    const card = $(".ss-account__card", root);
    if (!card) return;

    const r = card.getBoundingClientRect();
    // solo si está fuera de vista
    if (r.top < -10 || r.top > 90) {
      card.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };

  // -----------------------
  // Events
  // -----------------------
  loginTab.addEventListener("click", () => {
    setTab("login", { focus: true, persist: true, fromUser: true });
    maybeScrollToCard();
  });

  regTab.addEventListener("click", () => {
    setTab("register", { focus: true, persist: true, fromUser: true });
    maybeScrollToCard();
  });

  loginTab.addEventListener("keydown", (e) => onKey(e, 0));
  regTab.addEventListener("keydown", (e) => onKey(e, 1));

  // media query change
  const onMqChange = () => setSticky(currentTab);
  if (mqMobile) {
    if (typeof mqMobile.addEventListener === "function") mqMobile.addEventListener("change", onMqChange);
    else if (typeof mqMobile.addListener === "function") mqMobile.addListener(onMqChange);
  }

  window.addEventListener("scroll", onScroll, { passive: true });

  // sync entre pestañas (solo dispara en otras pestañas)
  window.addEventListener("storage", (ev) => {
    if (!ev || ev.key !== KEY_TAB) return;
    const v = clampTab(ev.newValue || "");
    if (v === currentTab) return;
    setTab(v, { focus: false, persist: false });
  });

  // ESC: “soft dismiss” del sticky (TTL)
  window.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    if (!sticky || !isMobile()) return;
    if (!stickyState.on) return;

    setDismissNow();
    sticky.classList.remove("is-on");
    sticky.setAttribute("aria-hidden", "true");
    stickyState.on = false;
  });

  // click sticky mantiene coherencia con tab actual (no prevenimos navegación)
  if (stickyBtn) {
    stickyBtn.addEventListener("click", () => {
      storageSet(KEY_TAB, currentTab);
    });
  }

  // BFCache: resync al volver
  window.addEventListener("pageshow", () => {
    const saved = clampTab(storageGet(KEY_TAB) || "login");
    currentTab = saved;
    setTab(saved, { focus: false, persist: true });
    stickyAutoHide();
  });

  // cleanup para evitar duplicados si la página se guarda/restaura
  window.addEventListener("pagehide", () => {
    safe(() => { root.dataset.ssAccountInit = "0"; });
  }, { once: true });

  // -----------------------
  // Init
  // -----------------------
  const initial = clampTab(tabFromUrl() || storageGet(KEY_TAB) || "login");
  setTab(initial, { focus: false, persist: true });
  stickyAutoHide();
})();
