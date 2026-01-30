(() => {
  "use strict";

  const safe = (fn) => { try { return fn(); } catch (_) { return undefined; } };
  const $ = (sel, el = document) => safe(() => el.querySelector(sel)) || null;
  const byId = (id) => (id ? document.getElementById(id) : null);

  const root = document.querySelector(".ss-account");
  if (!root) return;

  if (root.dataset.ssAccountInit === "1") return;
  root.dataset.ssAccountInit = "1";

  const KEY_TAB = "ss_account_tab";
  const KEY_STICKY_DISMISS = "ss_account_sticky_dismiss_v3";
  const DISMISS_TTL_MS = 7 * 24 * 60 * 60 * 1000;

  const raf = (cb) => {
    const r = window.requestAnimationFrame;
    if (typeof r === "function") return r(cb);
    return window.setTimeout(cb, 16);
  };

  const focusSafe = (el) => {
    if (!el || typeof el.focus !== "function") return;
    try { el.focus({ preventScroll: true }); }
    catch (_) { try { el.focus(); } catch (__) {} }
  };

  const clampTab = (v) => (String(v || "").toLowerCase() === "register" ? "register" : "login");

  const mqMobile = safe(() => window.matchMedia && window.matchMedia("(max-width: 980px)")) || null;
  const mqReduce = safe(() => window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)")) || null;

  const isMobile = () => !!(mqMobile && mqMobile.matches);

  const RAM = Object.create(null);

  const storageSet = (key, val) => {
    const s = String(val);
    RAM[key] = s;
    const okLocal = safe(() => { localStorage.setItem(key, s); return true; }) === true;
    if (okLocal) return true;
    return safe(() => { sessionStorage.setItem(key, s); return true; }) === true;
  };

  const storageGet = (key) => {
    const v1 = safe(() => localStorage.getItem(key));
    if (v1 != null) return v1;
    const v2 = safe(() => sessionStorage.getItem(key));
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

  const tabFromUrl = () => {
    const raw = safe(() => new URLSearchParams(location.search).get("tab"));
    if (!raw) return null;
    return clampTab(raw);
  };

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
      safe(() => sticky.setAttribute("aria-live", "polite"));
    }

    const update = (w === "register")
      ? { t: "Crear cuenta", s: "Rápido, 1 minuto", b: "Crear →", href: registerUrl }
      : { t: "Iniciar sesión", s: "Ya tengo cuenta", b: "Entrar →", href: loginUrl };

    if (stickyState.which !== w) stickyState.which = w;

    if (stickyTitle) stickyTitle.textContent = update.t;
    if (stickySub) stickySub.textContent = update.s;
    if (stickyBtn) {
      stickyBtn.textContent = update.b;
      if (update.href) stickyBtn.href = update.href;
    }
  };

  let currentTab = "login";

  const setTab = (which, opts) => {
    const o = Object.assign({ focus: false, persist: true, fromUser: false }, opts || {});
    const w = clampTab(which);

    const changed = w !== currentTab;
    currentTab = w;

    const isLogin = w === "login";

    loginTab.classList.toggle("is-active", isLogin);
    regTab.classList.toggle("is-active", !isLogin);

    loginTab.setAttribute("aria-selected", isLogin ? "true" : "false");
    regTab.setAttribute("aria-selected", !isLogin ? "true" : "false");

    loginTab.tabIndex = isLogin ? 0 : -1;
    regTab.tabIndex = !isLogin ? 0 : -1;

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
        if (target && !isMobile()) target.focus({ preventScroll: true });
      });
    }
  };

  const maybeScrollToCard = () => {
    if (!isMobile()) return;
    if (mqReduce && mqReduce.matches) return;

    const card = $(".ss-account__card", root);
    if (!card) return;

    const r = safe(() => card.getBoundingClientRect());
    if (!r) return;
    if (r.top >= -10 && r.top <= 110) return;

    safe(() => card.scrollIntoView({ behavior: "smooth", block: "start" }));
  };

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

  let lastY = safe(() => window.scrollY) || 0;
  let ticking = false;

  const stickyAutoHide = () => {
    if (!sticky) return;

    if (!isMobile()) {
      setSticky(currentTab);
      return;
    }

    const y = safe(() => window.scrollY) || 0;
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
    raf(() => {
      ticking = false;
      stickyAutoHide();
    });
  };

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

  const onMqChange = () => setSticky(currentTab);
  if (mqMobile) {
    if (typeof mqMobile.addEventListener === "function") mqMobile.addEventListener("change", onMqChange);
    else if (typeof mqMobile.addListener === "function") mqMobile.addListener(onMqChange);
  }

  window.addEventListener("scroll", onScroll, { passive: true });

  window.addEventListener("storage", (ev) => {
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

  window.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    dismissSticky();
  });

  if (stickyDismissBtn) stickyDismissBtn.addEventListener("click", dismissSticky);

  if (stickyBtn) {
    stickyBtn.addEventListener("click", () => {
      storageSet(KEY_TAB, currentTab);
    });
  }

  window.addEventListener("pageshow", () => {
    const initial = clampTab(tabFromUrl() || storageGet(KEY_TAB) || "login");
    setTab(initial, { focus: false, persist: true });
    stickyAutoHide();
  });

  const initial = clampTab(tabFromUrl() || storageGet(KEY_TAB) || "login");
  setTab(initial, { focus: false, persist: true });
  stickyAutoHide();
})();
