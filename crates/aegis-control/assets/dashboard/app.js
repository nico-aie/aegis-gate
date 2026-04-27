// Aegis WAF dashboard — vanilla SPA router + i18n loader (D-M1).
//
// Pure ES modules, no build step. Each route maps to a dynamic
// import() of the matching page module so the initial bundle stays
// small. The History API drives navigation; back / forward / deep
// links all work without a server round-trip. The server falls
// through every /dashboard/<path> to index.html — see
// crates/aegis-control/src/dashboard/dispatch.rs (D-M1-T1.3).
//
// i18n (D-M1-T1.8): on init we fetch /dashboard/assets/i18n/en.json
// and await it before mounting the first page. All UI strings live
// behind data-i18n="key" attributes (or dataset.i18n in JS); no
// hardcoded English text in this file or in index.html. Adding a
// language ships another JSON file and selects on Accept-Language.

export const DEFAULT_ROUTE = "overview";

const PREFIX = "/dashboard/";

// Path → page-module loader. Order matches the sidebar order in
// docs/dashboard-enterprise/layout.md so the test that walks this
// table can read top-to-bottom.
export const ROUTES = {
  overview:  () => import("/dashboard/assets/pages/overview.js"),
  live:      () => import("/dashboard/assets/pages/live.js"),
  attacks:   () => import("/dashboard/assets/pages/attacks.js"),
  analytics: () => import("/dashboard/assets/pages/analytics.js"),
  audit:     () => import("/dashboard/assets/pages/audit.js"),
  rules:     () => import("/dashboard/assets/pages/rules.js"),
  tiers:     () => import("/dashboard/assets/pages/tiers.js"),
  blacklist: () => import("/dashboard/assets/pages/blacklist.js"),
  whitelist: () => import("/dashboard/assets/pages/whitelist.js"),
  settings:  () => import("/dashboard/assets/pages/settings.js"),
  tracking:  () => import("/dashboard/assets/pages/tracking.js"),
};

// Currently-mounted page; cleared in destroy() before the next mount.
let current = null;

// Translation table. Populated by loadI18n() before first render.
let TRANSLATIONS = {};

// Module-level EventSource for the status-bar pill (D-M2-T2.8).
// Opened once on init() and reused across navigations — the SPA
// doesn't tear down between routes, so a single SSE connection
// covers the whole session.
let sseSource = null;

/** Translate a key. Returns the key unchanged if missing — visible
 *  fallback so the gap is obvious in the UI. */
export function t(key) {
  const v = TRANSLATIONS[key];
  return typeof v === "string" ? v : key;
}

/** Fetch and cache the i18n payload. Called once on init. */
async function loadI18n() {
  try {
    const res = await fetch("/dashboard/assets/i18n/en.json", {
      cache: "no-store",
      credentials: "same-origin",
    });
    if (!res.ok) throw new Error(`i18n http ${res.status}`);
    const json = await res.json();
    TRANSLATIONS = json && typeof json === "object" ? json : {};
  } catch (err) {
    console.error("i18n load failed", err);
    TRANSLATIONS = {};
  }
}

/** Walk a subtree and apply translations to every [data-i18n]. */
export function applyI18n(root) {
  const els = (root || document).querySelectorAll("[data-i18n]");
  for (const el of els) {
    const key = el.dataset.i18n;
    if (!key) continue;
    const value = t(key);
    el.textContent = value;
  }
}

/** Update the status-bar connection pill. State is one of
 *  "connected" | "reconnecting" | "disconnected". */
export function setConnectionState(state) {
  const pill = document.querySelector('.aegis-statusbar [data-slot="connection"]');
  if (!pill) return;
  const dot = pill.querySelector(".aegis-status-dot");
  if (dot) dot.dataset.state = state;
  const label = pill.querySelector("[data-i18n]");
  if (!label) return;
  // Three explicit branches so each i18n key is a literal string
  // the asset-test extractor can find (it scans for the assignment
  // pattern; example string omitted to avoid a false-positive match).
  if (state === "connected") {
    label.dataset.i18n = "status.connected";
    label.textContent = t("status.connected");
  } else if (state === "reconnecting") {
    label.dataset.i18n = "status.reconnecting";
    label.textContent = t("status.reconnecting");
  } else {
    label.dataset.i18n = "status.disconnected";
    label.textContent = t("status.disconnected");
  }
}

/** Open the dashboard SSE stream and reflect its state in the
 *  status-bar pill. The browser handles backoff/retry transparently;
 *  we only translate readyState into a UI label. */
function startSse() {
  if (typeof EventSource === "undefined") {
    setConnectionState("disconnected");
    return;
  }
  setConnectionState("reconnecting");
  try {
    sseSource = new EventSource("/dashboard/sse");
  } catch (err) {
    console.error("SSE construction failed", err);
    setConnectionState("disconnected");
    return;
  }
  sseSource.addEventListener("open", () => setConnectionState("connected"));
  sseSource.addEventListener("error", () => {
    if (sseSource && sseSource.readyState === EventSource.CLOSED) {
      setConnectionState("disconnected");
    } else {
      setConnectionState("reconnecting");
    }
  });
}

/** Parse a URL pathname to a route key, `null` for "not found". */
export function parseRoute(pathname) {
  if (!pathname.startsWith(PREFIX) && pathname !== "/dashboard") {
    return DEFAULT_ROUTE;
  }
  const tail = pathname.slice(PREFIX.length).split("/")[0] || DEFAULT_ROUTE;
  return Object.prototype.hasOwnProperty.call(ROUTES, tail) ? tail : null;
}

/** Toggle the `aegis-nav-active` class on the matching sidebar link. */
function setActiveLink(route) {
  const links = document.querySelectorAll("a[data-route]");
  for (const a of links) {
    const li = a.closest("li");
    if (li) li.classList.toggle("aegis-nav-active", a.dataset.route === route);
  }
}

/** Render the 404 placeholder into the page mount slot. */
function render404(mountEl) {
  const p = document.createElement("p");
  p.dataset.i18n = "error.notFound";
  p.textContent = t("error.notFound");
  mountEl.replaceChildren(p);
}

/** Mount the page module for `route`, tearing down any previous one. */
async function mountRoute(route) {
  const mountEl = document.querySelector('[data-slot="page"]');
  if (!mountEl) throw new Error("missing [data-slot=\"page\"] mount point");

  // Always destroy the previous page first so its event listeners
  // and timers don't outlive the navigation.
  if (current && current.page && typeof current.page.destroy === "function") {
    try { current.page.destroy(); } catch (e) { console.error("destroy() threw", e); }
  }
  current = null;
  mountEl.replaceChildren();

  if (route === null) {
    render404(mountEl);
    return;
  }

  const mod = await ROUTES[route]();
  const page = mod.default;
  if (!page || typeof page.mount !== "function") {
    throw new Error(`page module ${route} missing default.mount()`);
  }
  page.mount(mountEl, { route, t });
  current = { route, page };
  setActiveLink(route);

  // Translate any data-i18n attributes the page just rendered.
  applyI18n(mountEl);

  const app = document.getElementById("aegis-app");
  if (app) app.dataset.appState = "ready";
}

/** Navigate to `href` — internal sidebar links + back/forward call this. */
export async function navigate(href, push = true) {
  const url = new URL(href, window.location.origin);
  if (push && url.pathname + url.search !== window.location.pathname + window.location.search) {
    window.history.pushState({}, "", url.pathname + url.search);
  }
  await mountRoute(parseRoute(url.pathname));
}

/** Intercept clicks on internal links + chrome action buttons. */
function onClick(e) {
  // Theme toggle in the user menu — defers all the work to theme.js
  // so persistence + system-preference logic stay in one place.
  const themeBtn = e.target.closest('[data-action="toggle-theme"]');
  if (themeBtn) {
    e.preventDefault();
    if (window.AegisTheme && typeof window.AegisTheme.cycle === "function") {
      window.AegisTheme.cycle();
    }
    return;
  }

  // Internal SPA navigation.
  const a = e.target.closest('a[href^="/dashboard/"]');
  if (!a) return;
  if (a.target === "_blank" || a.hasAttribute("download")) return;
  if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return;
  e.preventDefault();
  navigate(a.getAttribute("href"));
}

async function init() {
  // Normalise bare /dashboard or /dashboard/ to the default route so
  // a reload always lands on a real page.
  const path = window.location.pathname;
  if (path === "/dashboard" || path === "/dashboard/") {
    window.history.replaceState({}, "", PREFIX + DEFAULT_ROUTE);
  }

  // Load i18n BEFORE first render so static chrome strings (sidebar
  // labels, status pills) appear in the user's language without a
  // flash of un-translated text.
  await loadI18n();
  applyI18n(document);

  // Wire interactions.
  document.addEventListener("click", onClick);
  window.addEventListener("popstate", () => navigate(window.location.href, false));

  // Status-bar SSE pill — runs alongside the route mount.
  startSse();

  try {
    await navigate(window.location.href, false);
  } catch (err) {
    console.error("initial mount failed", err);
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
