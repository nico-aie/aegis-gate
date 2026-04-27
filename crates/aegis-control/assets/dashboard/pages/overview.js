// Overview page (D-M2-T2.7).
//
// Mounts four KPI tiles, a traffic line-chart slot, an
// attack-distribution donut slot, and a top-attackers table slot.
// Real chart rendering lands in D-M2-T2.9 (stat-card + line-chart +
// donut + table component implementations); for now the page
// renders the data into simple text + a small list/table so the
// page works end-to-end without Chart.js.
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
  if (!ts) return;
  // Component swap target — D-M2-T2.9 renders the line chart here.
  if (!mountEl) return;
  const slot = mountEl.querySelector('[data-slot="traffic-chart"]');
  if (!slot) return;
  const points = ts.points || [];
  const total = points.reduce((acc, p) => acc + (p.total || 0), 0);
  const blocked = points.reduce((acc, p) => acc + (p.blocked || 0), 0);
  slot.textContent = `${total} requests · ${blocked} blocked (last ${ts.window_seconds}s, ${points.length} buckets)`;
}

async function refreshDistribution() {
  const dist = await fetchJson(ENDPOINTS.distribution.path);
  if (!dist || !mountEl) return;
  const slot = mountEl.querySelector('[data-slot="attack-distribution"]');
  if (!slot) return;
  const cats = dist.categories || [];
  if (cats.length === 0) {
    slot.textContent = "No attacks in window — quiet is good.";
    return;
  }
  slot.replaceChildren();
  const ul = document.createElement("ul");
  ul.className = "aegis-distribution-list";
  for (const c of cats) {
    const li = document.createElement("li");
    li.textContent = `${c.name}: ${c.count} (${formatPct(c.pct)})`;
    ul.appendChild(li);
  }
  slot.appendChild(ul);
}

async function refreshTop() {
  const top = await fetchJson(ENDPOINTS.top.path);
  if (!top || !mountEl) return;
  const slot = mountEl.querySelector('[data-slot="top-attackers"]');
  if (!slot) return;
  const attackers = top.attackers || [];
  if (attackers.length === 0) {
    slot.textContent = "No active attackers in window.";
    return;
  }
  slot.replaceChildren();
  const table = document.createElement("table");
  table.className = "aegis-table";
  const tbody = document.createElement("tbody");
  for (const a of attackers) {
    const tr = document.createElement("tr");
    const id = document.createElement("td");
    id.textContent = a.identifier;
    const hits = document.createElement("td");
    hits.textContent = String(a.hits);
    const cats = document.createElement("td");
    cats.textContent = (a.categories || []).join(", ");
    const risk = document.createElement("td");
    risk.textContent = String(a.risk);
    tr.append(id, hits, cats, risk);
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  slot.appendChild(table);
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
    mountEl = null;
  },
};
