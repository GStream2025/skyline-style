/* Skyline Store — Account Tabs (ULTRA PRO v3 FINAL)
   ✅ accesible + teclado (roving tabindex)
   ✅ guarda elección (localStorage -> sessionStorage fallback)
   ✅ sticky mobile robusto + auto-hide (rAF throttled)
   ✅ no rompe si faltan nodos / init safe
*/
(function () {
  "use strict";

  // ---- prevent double init (por cache, turbo, htmx, etc.) ----
  // Si tu sitio NO usa navegación tipo SPA, esto alcanza perfecto.
  if (window.__SS_ACCOUNT_INIT__) return;
  window.__SS_ACCOUNT_INIT__ = true;

  const root = document.querySelector(".ss-account");
  if (!root) return;

  // -----------------------
  // Helpers
  // -----------------------
  const $ = (sel, el) => (el || document).querySelector(sel);
  const byId = (id) => document.getElementById(id);

  const KEY_TAB = "ss_account_tab";
  const KEY_STICKY_DISMISS = "ss_account_sticky_dismiss"; // soft opt-out

  const mqMobile = window.matchMedia("(max-width: 980px)");
  const mqReduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

  const clampTab = (v) => (v === "register" ? "register" : "login");

  function isMobile() {
    return !!mqMobile.matches;
  }

  function storageSet(key, val) {
    try {
      localStorage.setItem(key, val);
      return;
    } catch (e) {}
    try {
      sessionStorage.setItem(key, val);
    } catch (e) {}
  }

  function storageGet(key) {
    try {
      const v = localStorage.getItem(key);
      if (v !== null) return v;
    } catch (e) {}
    try {
      return sessionStorage.getItem(key);
    } catch (e) {
      return null;
    }
  }

  function stickyDismissed() {
    return storageGet(KEY_STICKY_DISMISS) === "1";
  }

  // -----------------------
  // Nodes (IDs primary, fallback selectors)
  // -----------------------
  const loginTab =
    byId("tab-login") || $('[role="tab"][aria-controls="panel-login"]');
  const regTab =
    byId("tab-register") || $('[role="tab"][aria-controls="panel-register"]');

  const loginPanel = byId("panel-login") || $("#panel-login");
  const regPanel = byId("panel-register") || $("#panel-register");

  const sticky = byId("accSticky") || $(".ss-account__sticky");
  const stickyTitle =
    byId("accStickyTitle") || (sticky ? $("#accStickyTitle", sticky) : null);
  const stickySub =
    byId("accStickySub") || (sticky ? $("#accStickySub", sticky) : null);
  const stickyBtn =
    byId("accStickyBtn") || (sticky ? $("#accStickyBtn", sticky) : null);

  if (!loginTab || !regTab || !loginPanel || !regPanel) return;

  const tabs = [loginTab, regTab];

  // URLs desde dataset (ya vienen resueltas en el template)
  const loginUrl = root.getAttribute("data-login-url") || "";
  const registerUrl = root.getAttribute("data-register-url") || "";

  // -----------------------
  // Sticky state (evita DOM updates repetidos)
  // -----------------------
  let stickyState = {
    on: false,
    which: "login",
  };

  function setSticky(which) {
    if (!sticky || !stickyTitle || !stickySub || !stickyBtn) return;

    const w = clampTab(which);

    // condiciones para apagar
    if (!isMobile() || stickyDismissed()) {
      if (stickyState.on) {
        sticky.classList.remove("is-on");
        sticky.setAttribute("aria-hidden", "true");
        stickyState.on = false;
      }
      stickyState.which = w;
      return;
    }

    // encender (si estaba off)
    if (!stickyState.on) {
      sticky.classList.add("is-on");
      sticky.setAttribute("aria-hidden", "false");
      stickyState.on = true;
    }

    // actualizar contenido solo si cambió
    if (stickyState.which !== w) {
      stickyState.which = w;

      if (w === "register") {
        stickyTitle.textContent = "Crear cuenta";
        stickySub.textContent = "Rápido, 1 minuto";
        stickyBtn.textContent = "Crear →";
        if (registerUrl) stickyBtn.href = registerUrl;
      } else {
        stickyTitle.textContent = "Iniciar sesión";
        stickySub.textContent = "Ya tengo cuenta";
        stickyBtn.textContent = "Entrar →";
        if (loginUrl) stickyBtn.href = loginUrl;
      }
    }
  }

  // -----------------------
  // Tabs
  // -----------------------
  function setTab(which, opts) {
    const options = Object.assign({ focus: false, persist: true }, opts || {});
    const w = clampTab(which);
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

    // panels
    loginPanel.classList.toggle("is-hidden", !isLogin);
    regPanel.classList.toggle("is-hidden", isLogin);

    if (options.persist) storageSet(KEY_TAB, w);

    setSticky(w);

    if (options.focus) {
      (isLogin ? loginTab : regTab).focus({ preventScroll: true });
    }
  }

  function onKey(e, idx) {
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
      setTab(next === 0 ? "login" : "register", { focus: false, persist: true });
    }
  }

  // -----------------------
  // Sticky auto-hide (rAF throttled)
  // -----------------------
  let lastY = window.scrollY || 0;
  let ticking = false;

  function stickyAutoHide() {
    if (!sticky) return;
    if (!isMobile()) {
      setSticky(clampTab(storageGet(KEY_TAB)));
      return;
    }

    const y = window.scrollY || 0;
    const goingUp = y < lastY;
    const nearTop = y < 40;
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

    const saved = clampTab(storageGet(KEY_TAB));
    setSticky(saved);
  }

  function onScroll() {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(() => {
      ticking = false;
      stickyAutoHide();
    });
  }

  // -----------------------
  // Optional: scroll suave al cambiar tab (solo si NO reduce motion)
  // -----------------------
  function maybeScrollToCard() {
    if (mqReduceMotion.matches) return;
    if (!isMobile()) return;

    const card = $(".ss-account__card", root);
    if (!card) return;

    const r = card.getBoundingClientRect();
    if (r.top < 0 || r.top > 80) {
      card.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  // -----------------------
  // Events
  // -----------------------
  loginTab.addEventListener("click", () => {
    setTab("login", { focus: true, persist: true });
    maybeScrollToCard();
  });

  regTab.addEventListener("click", () => {
    setTab("register", { focus: true, persist: true });
    maybeScrollToCard();
  });

  loginTab.addEventListener("keydown", (e) => onKey(e, 0));
  regTab.addEventListener("keydown", (e) => onKey(e, 1));

  // mobile query change (mejor que resize)
  if (typeof mqMobile.addEventListener === "function") {
    mqMobile.addEventListener("change", () => {
      const saved = clampTab(storageGet(KEY_TAB));
      setSticky(saved);
    });
  } else if (typeof mqMobile.addListener === "function") {
    mqMobile.addListener(() => {
      const saved = clampTab(storageGet(KEY_TAB));
      setSticky(saved);
    });
  }

  window.addEventListener("scroll", onScroll, { passive: true });

  // sync entre pestañas (solo dispara en otras pestañas)
  window.addEventListener("storage", (ev) => {
    if (!ev || ev.key !== KEY_TAB) return;
    const v = clampTab(ev.newValue || "");
    setTab(v, { focus: false, persist: false });
  });

  // ESC: “soft dismiss” del sticky (no bloquea tabs)
  window.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    if (!sticky || !isMobile()) return;

    storageSet(KEY_STICKY_DISMISS, "1");
    sticky.classList.remove("is-on");
    sticky.setAttribute("aria-hidden", "true");
    stickyState.on = false;
  });

  // Si el usuario hace click en el sticky, mantené coherencia con tab actual
  if (stickyBtn) {
    stickyBtn.addEventListener("click", () => {
      const saved = clampTab(storageGet(KEY_TAB));
      storageSet(KEY_TAB, saved);
      // no prevenimos navegación
    });
  }

  // -----------------------
  // Init
  // -----------------------
  const saved = clampTab(storageGet(KEY_TAB));
  setTab(saved, { focus: false, persist: true });
  stickyAutoHide();
})();
