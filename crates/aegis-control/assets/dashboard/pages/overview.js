// Overview page (D-M2-T2.7 + D-M2-T2.9).
//
// Mounts four KPI tiles, a traffic line-chart, an attack-distribution
// donut, and a top-attackers table. The components live in
// `/dashboard/assets/components/*` and are dynamically imported on
// first use so the page module stays small.
//
// Polling cadence aligned with `docs/dashboard-enterprise/pages/overview.md`:
// - /api/stats every 1s
// - /api/stats/timeseries every 5s
// - /api/attacks/distribution every 10s
// - /api/attacks/top every 10s
// - /api/about once on mount (to fill version + env slots)
//
// Polling pauses while the tab is hidden (Chrome battery friendliness)
// and resumes immediately on visibilitychange.

const ENDPOINTS = {
  stats:        { path: "/api/stats",                                interval_ms: 1000 },
  timeseries:   { path: "/api/stats/timeseries?window=900&step=5",   interval_ms: 5000 },
  distribution: { path: "/api/attacks/distribution?window=900",      interval_ms: 10000 },
  top:          { path: "/api/attacks/top?window=900&limit=5",       interval_ms: 10000 },
};

let timers = [];
let abortControllers = [];
let visibilityHandler = null;
let mountEl = null;

// Component handles + module references (lazy-loaded on first refresh).
let lineChartMod = null;
let lineChartState = null;
let donutMod = null;
let donutState = null;
let tableMod = null;
let tableState = null;

async function fetchJson(url) {
  const ctrl = new AbortController();
  abortControllers.push(ctrl);
  try {
    const res = await fetch(url, {
      cache: "no-store",
      credentials: "same-origin",
      signal: ctrl.signal,
    });
    if (!res.ok) return null;
    return await res.json();
  } catch (e) {
    if (e.name !== "AbortError") console.error("overview fetch failed", url, e);
    return null;
  }
}

function formatNumber(n) {
  if (typeof n !== "number" || !Number.isFinite(n)) return "—";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(Math.round(n * 100) / 100);
}

function formatPct(n) {
  if (typeof n !== "number" || !Number.isFinite(n)) return "—";
  return `${(Math.round(n * 10) / 10).toFixed(1)}%`;
}

function setSlot(slot, value) {
  if (!mountEl) return;
  const el = mountEl.querySelector(`[data-slot="${slot}"]`);
  if (el) el.textContent = value;
}

function setTopbarSlot(slot, value) {
  const el = document.querySelector(`.aegis-topbar [data-slot="${slot}"]`);
  if (el) el.textContent = value;
}

async function refreshAbout() {
  const about = await fetchJson("/api/about");
  if (!about) return;
  if (about.version) setTopbarSlot("version", `v${about.version}`);
  if (about.environment) setTopbarSlot("environment", about.environment);
}

async function refreshStats() {
  const stats = await fetchJson(ENDPOINTS.stats.path);
  if (!stats) return;
  setSlot("stat-request-rate", formatNumber(stats.request_rate));
  setSlot("stat-blocks-total", formatNumber(stats.blocks_total));
  setSlot("stat-block-rate", formatPct(stats.block_rate_pct));
  setSlot("stat-active-threats", formatNumber(stats.active_threats));
}

async function refreshTimeseries() {
  const ts = await fetchJson(ENDPOINTS.timeseries.path);
  if (!ts || !mountEl) return;
  const slot = mountEl.querySelector('[data-slot="traffic-chart"]');
  if (!slot) return;
  const points = (ts.points || []).map((p) => ({
    ts: p.ts,
    value: p.total || 0,
  }));
  const blocked = (ts.points || []).map((p) => ({
    ts: p.ts,
    value: p.blocked || 0,
  }));
  const props = {
    ariaLabel: "Traffic over the last 15 minutes",
    series: [
      { name: "total",   color: "var(--color-info)", points },
      { name: "blocked", color: "var(--color-err)",  points: blocked },
    ],
  };
  if (!lineChartMod) lineChartMod = (await import("/dashboard/assets/components/line-chart.js")).default;
  if (!lineChartState) {
    lineChartState = lineChartMod.mount(slot, props);
  } else {
    lineChartMod.update(lineChartState, props);
  }
}

async function refreshDistribution() {
  const dist = await fetchJson(ENDPOINTS.distribution.path);
  if (!dist || !mountEl) return;
  const slot = mountEl.querySelector('[data-slot="attack-distribution"]');
  if (!slot) return;
  const slices = (dist.categories || []).map((c) => ({
    name: c.name,
    value: c.count || 0,
  }));
  const props = {
    ariaLabel: "Attack distribution by category",
    emptyMessage: "No attacks in window — quiet is good.",
    slices,
  };
  if (!donutMod) donutMod = (await import("/dashboard/assets/components/donut.js")).default;
  if (!donutState) {
    donutState = donutMod.mount(slot, props);
  } else {
    donutMod.update(donutState, props);
  }
}

async function refreshTop() {
  const top = await fetchJson(ENDPOINTS.top.path);
  if (!top || !mountEl) return;
  const slot = mountEl.querySelector('[data-slot="top-attackers"]');
  if (!slot) return;
  const rows = (top.attackers || []).map((a) => ({
    identifier: a.identifier,
    hits: a.hits,
    categories: (a.categories || []).join(", "),
    risk: a.risk,
  }));
  const props = {
    ariaLabel: "Top attackers by hits",
    emptyMessage: "No active attackers in window.",
    columns: [
      { key: "identifier", label: "Source" },
      { key: "hits",       label: "Hits" },
      { key: "categories", label: "Categories", sortable: false },
      { key: "risk",       label: "Risk" },
    ],
    rows,
    sortBy: { key: "hits", dir: "desc" },
  };
  if (!tableMod) tableMod = (await import("/dashboard/assets/components/table.js")).default;
  if (!tableState) {
    tableState = tableMod.mount(slot, props);
  } else {
    tableMod.update(tableState, props);
  }
}

function startPolling(name, fn) {
  // First fetch immediately so the page isn't blank during the
  // initial interval window.
  fn();
  const id = setInterval(() => {
    if (document.visibilityState === "visible") fn();
  }, ENDPOINTS[name].interval_ms);
  timers.push(id);
}

function renderShell() {
  mountEl.replaceChildren();
  const wrap = document.createElement("div");
  wrap.className = "aegis-overview";
  wrap.innerHTML = `
    <header class="aegis-overview-header">
      <h1 tabindex="-1">Overview</h1>
    </header>
    <section class="aegis-stat-grid" aria-label="Key performance indicators">
      <article class="aegis-stat" role="group" aria-label="Request rate">
        <h3>Request rate</h3>
        <div class="aegis-stat-value" data-slot="stat-request-rate" aria-live="polite">—</div>
        <div class="aegis-stat-unit">req/s</div>
      </article>
      <article class="aegis-stat" role="group" aria-label="Blocks total">
        <h3>Blocks total</h3>
        <div class="aegis-stat-value" data-slot="stat-blocks-total" aria-live="polite">—</div>
      </article>
      <article class="aegis-stat" role="group" aria-label="Block rate">
        <h3>Block rate</h3>
        <div class="aegis-stat-value" data-slot="stat-block-rate" aria-live="polite">—</div>
      </article>
      <article class="aegis-stat" role="group" aria-label="Active threats">
        <h3>Active threats</h3>
        <div class="aegis-stat-value" data-slot="stat-active-threats" aria-live="polite">—</div>
      </article>
    </section>
    <section class="aegis-overview-grid">
      <article class="aegis-card" aria-label="Traffic over 15 minutes">
        <h2>Traffic (15m)</h2>
        <div class="aegis-card-body" data-slot="traffic-chart">Loading…</div>
      </article>
      <article class="aegis-card" aria-label="Attack distribution">
        <h2>Attacks by category</h2>
        <div class="aegis-card-body" data-slot="attack-distribution">Loading…</div>
      </article>
      <article class="aegis-card aegis-card-wide" aria-label="Top attackers">
        <h2>Top attackers</h2>
        <div class="aegis-card-body" data-slot="top-attackers">Loading…</div>
      </article>
    </section>
  `;
  mountEl.appendChild(wrap);
}

function setupVisibility() {
  visibilityHandler = () => {
    if (document.visibilityState === "visible") {
      refreshStats();
      refreshTimeseries();
      refreshDistribution();
      refreshTop();
    }
  };
  document.addEventListener("visibilitychange", visibilityHandler);
}

export default {
  mount(el) {
    mountEl = el;
    renderShell();
    setupVisibility();
    refreshAbout();
    startPolling("stats", refreshStats);
    startPolling("timeseries", refreshTimeseries);
    startPolling("distribution", refreshDistribution);
    startPolling("top", refreshTop);
  },
  destroy() {
    for (const id of timers) clearInterval(id);
    for (const ctrl of abortControllers) ctrl.abort();
    timers = [];
    abortControllers = [];
    if (visibilityHandler) {
      document.removeEventListener("visibilitychange", visibilityHandler);
      visibilityHandler = null;
    }
    if (lineChartMod && lineChartState) lineChartMod.destroy(lineChartState);
    if (donutMod && donutState) donutMod.destroy(donutState);
    if (tableMod && tableState) tableMod.destroy(tableState);
    lineChartState = null;
    donutState = null;
    tableState = null;
    mountEl = null;
  },
};
