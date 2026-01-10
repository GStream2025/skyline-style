/* Skyline Store — Account Tabs (ULTRA PRO v2 FINAL)
   ✅ accesible + teclado
   ✅ guarda elección (localStorage -> sessionStorage fallback)
   ✅ sticky mobile robusto + auto-hide inteligente
   ✅ no rompe si faltan nodos / doble init safe
*/
(function () {
  "use strict";

  // ---- prevent double init (por cache, turbo, htmx, etc.) ----
  if (window.__SS_ACCOUNT_INIT__) return;
  window.__SS_ACCOUNT_INIT__ = true;

  const root = document.querySelector(".ss-account");
  if (!root) return;

  // ---- helpers ----
  const $ = (sel, el = document) => el.querySelector(sel);
  const byId = (id) => document.getElementById(id);

  const KEY = "ss_account_tab";
  const KEY_STICKY_DISMISS = "ss_account_sticky_dismiss"; // soft opt-out

  const mqMobile = window.matchMedia("(max-width: 980px)");
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

  // ---- nodes (IDs primary, fallback selectors) ----
  const loginTab = byId("tab-login") || $('[role="tab"][aria-controls="panel-login"]');
  const regTab = byId("tab-register") || $('[role="tab"][aria-controls="panel-register"]');
  const loginPanel = byId("panel-login") || byId("panel-login");
  const regPanel = byId("panel-register") || byId("panel-register");

  const sticky = byId("accSticky") || $(".ss-account__sticky");
  const stickyTitle = byId("accStickyTitle") || $("#accSticky b", sticky || document);
  const stickySub = byId("accStickySub") || $("#accSticky span", sticky || document);
  const stickyBtn = byId("accStickyBtn") || $("#accSticky a", sticky || document);

  if (!loginTab || !regTab || !loginPanel || !regPanel) return;

  const tabs = [loginTab, regTab];

  // URLs desde dataset (ya vienen resueltas en el template)
  const loginUrl = root.getAttribute("data-login-url") || "";
  const registerUrl = root.getAttribute("data-register-url") || "";

  function storageSet(key, val) {
    try { localStorage.setItem(key, val); return; } catch (e) {}
    try { sessionStorage.setItem(key, val); } catch (e) {}
  }
  function storageGet(key) {
    try {
      const v = localStorage.getItem(key);
      if (v !== null) return v;
    } catch (e) {}
    try { return sessionStorage.getItem(key); } catch (e) { return null; }
  }

  function clampTab(v) {
    return v === "register" ? "register" : "login";
  }

  function isMobile() {
    return !!mqMobile.matches;
  }

  function stickyDismissed() {
    return storageGet(KEY_STICKY_DISMISS) === "1";
  }

  function setSticky(which) {
    if (!sticky || !stickyTitle || !stickySub || !stickyBtn) return;

    if (!isMobile() || stickyDismissed()) {
      sticky.classList.remove("is-on");
      sticky.setAttribute("aria-hidden", "true");
      return;
    }

    sticky.classList.add("is-on");
    sticky.setAttribute("aria-hidden", "false");

    if (which === "register") {
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

  function setTab(which, opts = { focus: false, persist: true }) {
    const w = clampTab(which);
    const isLogin = w === "login";

    // classes
    loginTab.classList.toggle("is-active", isLogin);
    regTab.classList.toggle("is-active", !isLogin);

    // aria
    loginTab.setAttribute("aria-selected", isLogin ? "true" : "false");
    regTab.setAttribute("aria-selected", !isLogin ? "true" : "false");

    // tabIndex for a11y roving tabindex
    loginTab.tabIndex = isLogin ? 0 : -1;
    regTab.tabIndex = !isLogin ? 0 : -1;

    // panels (tu CSS extra hace transición aunque estén "hidden")
    loginPanel.classList.toggle("is-hidden", !isLogin);
    regPanel.classList.toggle("is-hidden", isLogin);

    if (opts.persist) storageSet(KEY, w);
    setSticky(w);

    if (opts.focus) {
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

  // ---- sticky auto-hide (rAF throttled) ----
  let lastY = window.scrollY || 0;
  let ticking = false;

  function stickyAutoHide() {
    if (!sticky) return;
    if (!isMobile()) return;

    const y = window.scrollY || 0;
    const goingUp = y < lastY;
    const nearTop = y < 40;
    lastY = y;

    if (stickyDismissed()) {
      sticky.classList.remove("is-on");
      sticky.setAttribute("aria-hidden", "true");
      return;
    }

    if (nearTop && goingUp) {
      sticky.classList.remove("is-on");
      sticky.setAttribute("aria-hidden", "true");
      return;
    }

    const saved = clampTab(storageGet(KEY));
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

  // ---- events ----
  loginTab.addEventListener("click", () => setTab("login", { focus: true, persist: true }));
  regTab.addEventListener("click", () => setTab("register", { focus: true, persist: true }));

  loginTab.addEventListener("keydown", (e) => onKey(e, 0));
  regTab.addEventListener("keydown", (e) => onKey(e, 1));

  // mobile query change (mejor que resize)
  if (typeof mqMobile.addEventListener === "function") {
    mqMobile.addEventListener("change", () => {
      const saved = clampTab(storageGet(KEY));
      setSticky(saved);
    });
  } else if (typeof mqMobile.addListener === "function") {
    mqMobile.addListener(() => {
      const saved = clampTab(storageGet(KEY));
      setSticky(saved);
    });
  }

  window.addEventListener("scroll", onScroll, { passive: true });

  // sync entre pestañas
  window.addEventListener("storage", (ev) => {
    if (!ev || ev.key !== KEY) return;
    const v = clampTab(ev.newValue);
    setTab(v, { focus: false, persist: false });
  });

  // ESC: “soft dismiss” del sticky (no bloquea tabs)
  window.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    if (!sticky || !isMobile()) return;
    storageSet(KEY_STICKY_DISMISS, "1");
    sticky.classList.remove("is-on");
    sticky.setAttribute("aria-hidden", "true");
  });

  // Si el usuario hace click en el sticky, mantené coherencia con tab actual
  if (stickyBtn) {
    stickyBtn.addEventListener("click", () => {
      // no prevenimos navegación, solo aseguramos que el estado guardado coincide
      const saved = clampTab(storageGet(KEY));
      storageSet(KEY, saved);
    });
  }

  // ---- init ----
  let saved = clampTab(storageGet(KEY));
  setTab(saved, { focus: false, persist: true });

  // sticky initial state (si carga scrolleado)
  stickyAutoHide();

  // optional: scroll suave al cambiar tab (solo si NO reduce motion)
  // (no hace nada si ya está visible; lo dejo ultra safe)
  function maybeScrollToCard() {
    if (reduceMotion.matches) return;
    const card = $(".ss-account__card", root);
    if (!card || !isMobile()) return;
    const r = card.getBoundingClientRect();
    if (r.top < 0 || r.top > 80) {
      card.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  loginTab.addEventListener("click", maybeScrollToCard);
  regTab.addEventListener("click", maybeScrollToCard);
})();
