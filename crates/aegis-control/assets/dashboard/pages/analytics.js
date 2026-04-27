// Analytics page (D-M3-T3.10).
//
// Six allow-listed PromQL chart cards plus a time-range selector.
// Backed by /api/analytics/query?expr=<key>&start=&end=&step=.
//
// In v1 the in-process query layer returns 0 for instantaneous
// queries and 503 (no_history_backend) for range queries until an
// external Prometheus is configured. The page renders gracefully:
// scalars become a single value, matrices render via the line-chart
// component, and 503s show a "history backend not configured"
// banner without breaking the rest of the page.

const RANGES = [
  { label: "1h",  seconds: 3_600,    step: 60 },
  { label: "6h",  seconds: 21_600,   step: 300 },
  { label: "24h", seconds: 86_400,   step: 600 },
  { label: "7d",  seconds: 604_800,  step: 3600 },
  { label: "30d", seconds: 2_592_000, step: 14400 },
];

const CARDS = [
  { id: "requests_rate",        title: "Requests / sec" },
  { id: "block_ratio",          title: "Block ratio" },
  { id: "latency_p99",          title: "Latency p99" },
  { id: "errors_by_route",      title: "Errors by route" },
  { id: "slo_budget_remaining", title: "SLO budget" },
  { id: "cert_days_to_expiry",  title: "Cert days to expiry" },
];

let mountEl = null;
let abortControllers = [];
let currentRange = RANGES[2]; // 24h default
let lineChartMod = null;
let chartStates = new Map(); // expr -> state

async function fetchJson(url) {
  const ctrl = new AbortController();
  abortControllers.push(ctrl);
  try {
    const res = await fetch(url, {
      cache: "no-store",
      credentials: "same-origin",
      signal: ctrl.signal,
    });
    if (res.status === 503) {
      const body = await res.json().catch(() => ({}));
      return { _no_backend: true, _body: body };
    }
    if (!res.ok) return null;
    return await res.json();
  } catch (e) {
    if (e.name !== "AbortError") console.error("analytics fetch failed", url, e);
    return null;
  }
}

async function ensureLineChart() {
  if (!lineChartMod) {
    lineChartMod = (await import("/dashboard/assets/components/line-chart.js")).default;
  }
  return lineChartMod;
}

function rangeBounds() {
  const end = Math.floor(Date.now() / 1000);
  const start = end - currentRange.seconds;
  return { start, end, step: currentRange.step };
}

function showBackendBanner() {
  if (!mountEl) return;
  const banner = mountEl.querySelector('[data-slot="backend-banner"]');
  if (!banner) return;
  banner.hidden = false;
}

function hideBackendBanner() {
  if (!mountEl) return;
  const banner = mountEl.querySelector('[data-slot="backend-banner"]');
  if (!banner) return;
  banner.hidden = true;
}

async function refreshCard(card) {
  if (!mountEl) return;
  const slot = mountEl.querySelector(`[data-card="${card.id}"] [data-slot="card-body"]`);
  if (!slot) return;
  const { start, end, step } = rangeBounds();
  const url =
    `/api/analytics/query?expr=${encodeURIComponent(card.id)}` +
    `&start=${start}&end=${end}&step=${step}`;
  const data = await fetchJson(url);

  if (!data) {
    slot.textContent = "Error loading data.";
    return;
  }
  if (data._no_backend) {
    showBackendBanner();
    slot.textContent = "—";
    return;
  }

  if (data.result_type === "scalar") {
    slot.textContent = formatScalar(data.value);
    return;
  }
  if (data.result_type === "matrix") {
    const points = (data.points || []).map((p) => ({
      ts: p.ts,
      value: p.value,
    }));
    if (points.length === 0) {
      slot.textContent = "No data in range.";
      return;
    }
    const chart = await ensureLineChart();
    const props = {
      ariaLabel: card.title,
      series: [{ name: card.id, color: "var(--color-info)", points }],
    };
    let state = chartStates.get(card.id);
    if (!state) {
      state = chart.mount(slot, props);
      chartStates.set(card.id, state);
    } else {
      chart.update(state, props);
    }
    return;
  }
  slot.textContent = "Unknown result type.";
}

function formatScalar(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) return "—";
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)}k`;
  if (value >= 1) return value.toFixed(2);
  return value.toFixed(4);
}

function refreshAll() {
  hideBackendBanner();
  for (const card of CARDS) refreshCard(card);
}

function setupRangeSelector() {
  if (!mountEl) return;
  const select = mountEl.querySelector('select[data-action="range"]');
  if (!select) return;
  select.addEventListener("change", () => {
    const found = RANGES.find((r) => r.label === select.value);
    if (!found) return;
    currentRange = found;
    // Tear down existing charts so the next refresh re-mounts with
    // a fresh state (avoids stale series from the previous range).
    if (lineChartMod) {
      for (const state of chartStates.values()) lineChartMod.destroy(state);
    }
    chartStates.clear();
    refreshAll();
  });
}

function renderShell() {
  mountEl.replaceChildren();
  const wrap = document.createElement("div");
  wrap.className = "aegis-analytics";
  const cardsHtml = CARDS
    .map(
      (c) => `
      <article class="aegis-card" data-card="${c.id}" aria-label="${c.title}">
        <h2>${c.title}</h2>
        <div class="aegis-card-body" data-slot="card-body">Loading…</div>
      </article>`
    )
    .join("");
  wrap.innerHTML = `
    <header class="aegis-overview-header">
      <h1 tabindex="-1">Analytics</h1>
      <label class="aegis-range">
        <span>Range</span>
        <select data-action="range">
          ${RANGES.map(
            (r) =>
              `<option value="${r.label}" ${r === currentRange ? "selected" : ""}>${r.label}</option>`
          ).join("")}
        </select>
      </label>
    </header>
    <p class="aegis-banner" data-slot="backend-banner" hidden>
      No history backend configured. Set
      <code>admin.prometheus_url</code> in
      <code>waf.yaml</code> to enable range queries.
    </p>
    <section class="aegis-overview-grid aegis-analytics-grid">
      ${cardsHtml}
    </section>
  `;
  mountEl.appendChild(wrap);
}

export default {
  mount(el) {
    mountEl = el;
    abortControllers = [];
    chartStates = new Map();
    renderShell();
    setupRangeSelector();
    refreshAll();
  },
  destroy() {
    for (const ctrl of abortControllers) ctrl.abort();
    abortControllers = [];
    if (lineChartMod) {
      for (const state of chartStates.values()) lineChartMod.destroy(state);
    }
    chartStates.clear();
    mountEl = null;
  },
};
