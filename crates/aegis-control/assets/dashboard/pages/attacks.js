// Attack Events page (D-M3-T3.3).
//
// Four widgets:
//   1. Detector breakdown donut    /api/attacks/by-detector
//   2. Top firing rules table      /api/attacks/top
//   3. Threat-intel hits table     /api/threat-intel/hits
//   4. Bot mix donut               /api/bots/mix
//
// Polling cadence aligned with the data freshness needs of the page —
// every endpoint has `Cache-Control: max-age=10` server-side so a 10 s
// poll matches the cache window without amplifying load. Pauses
// polling while the tab is hidden.

const ENDPOINTS = {
  byDetector:   { path: "/api/attacks/by-detector?window=900",          interval_ms: 10000 },
  topRules:     { path: "/api/attacks/top?window=900&limit=10",         interval_ms: 10000 },
  threatIntel:  { path: "/api/threat-intel/hits?window=3600&limit=20",  interval_ms: 15000 },
  botMix:       { path: "/api/bots/mix?window=3600",                    interval_ms: 15000 },
};

let timers = [];
let abortControllers = [];
let visibilityHandler = null;
let mountEl = null;
let donutMod = null;
let tableMod = null;
let detectorDonut = null;
let topRulesTable = null;
let threatIntelTable = null;
let botMixDonut = null;

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
    if (e.name !== "AbortError") console.error("attacks fetch failed", url, e);
    return null;
  }
}

async function ensureDonut() {
  if (!donutMod) {
    donutMod = (await import("/dashboard/assets/components/donut.js")).default;
  }
  return donutMod;
}

async function ensureTable() {
  if (!tableMod) {
    tableMod = (await import("/dashboard/assets/components/table.js")).default;
  }
  return tableMod;
}

async function refreshDetectors() {
  const r = await fetchJson(ENDPOINTS.byDetector.path);
  if (!r || !mountEl) return;
  const slot = mountEl.querySelector('[data-slot="detector-breakdown"]');
  if (!slot) return;
  const donut = await ensureDonut();
  const slices = (r.detectors || []).map((d) => ({ name: d.name, value: d.count }));
  const props = {
    ariaLabel: "Detections by detector",
    emptyMessage: "No detections in window — quiet is good.",
    slices,
  };
  if (!detectorDonut) {
    detectorDonut = donut.mount(slot, props);
  } else {
    donut.update(detectorDonut, props);
  }
}

async function refreshTopRules() {
  const r = await fetchJson(ENDPOINTS.topRules.path);
  if (!r || !mountEl) return;
  const slot = mountEl.querySelector('[data-slot="top-rules"]');
  if (!slot) return;
  const table = await ensureTable();
  const rows = (r.attackers || []).map((a) => ({
    identifier: a.identifier,
    hits: a.hits,
    categories: (a.categories || []).join(", "),
    risk: a.risk,
  }));
  const props = {
    ariaLabel: "Top attackers (proxy for top firing rules)",
    emptyMessage: "No attackers in window.",
    columns: [
      { key: "identifier", label: "Source" },
      { key: "hits",       label: "Hits" },
      { key: "categories", label: "Detectors", sortable: false },
      { key: "risk",       label: "Risk" },
    ],
    rows,
    sortBy: { key: "hits", dir: "desc" },
  };
  if (!topRulesTable) {
    topRulesTable = table.mount(slot, props);
  } else {
    table.update(topRulesTable, props);
  }
}

async function refreshThreatIntel() {
  const r = await fetchJson(ENDPOINTS.threatIntel.path);
  if (!r || !mountEl) return;
  const slot = mountEl.querySelector('[data-slot="threat-intel"]');
  if (!slot) return;
  const table = await ensureTable();
  const rows = (r.hits || []).map((h) => ({
    feed:      h.feed,
    indicator: h.indicator,
    hits:      h.hits,
    last_seen: (h.last_seen || "").replace("T", " ").replace("Z", ""),
  }));
  const props = {
    ariaLabel: "Threat-intel hits",
    emptyMessage: "No threat-intel hits in window.",
    columns: [
      { key: "feed",      label: "Feed" },
      { key: "indicator", label: "Indicator" },
      { key: "hits",      label: "Hits" },
      { key: "last_seen", label: "Last seen", sortable: false },
    ],
    rows,
    sortBy: { key: "hits", dir: "desc" },
  };
  if (!threatIntelTable) {
    threatIntelTable = table.mount(slot, props);
  } else {
    table.update(threatIntelTable, props);
  }
}

async function refreshBotMix() {
  const r = await fetchJson(ENDPOINTS.botMix.path);
  if (!r || !mountEl) return;
  const slot = mountEl.querySelector('[data-slot="bot-mix"]');
  if (!slot) return;
  const donut = await ensureDonut();
  const slices = (r.categories || []).map((c) => ({ name: c.name, value: c.count }));
  const props = {
    ariaLabel: "Bot classification mix",
    emptyMessage: "No bot signals in window.",
    slices,
  };
  if (!botMixDonut) {
    botMixDonut = donut.mount(slot, props);
  } else {
    donut.update(botMixDonut, props);
  }
}

function startPolling(name, fn) {
  fn();
  const id = setInterval(() => {
    if (document.visibilityState === "visible") fn();
  }, ENDPOINTS[name].interval_ms);
  timers.push(id);
}

function renderShell() {
  mountEl.replaceChildren();
  const wrap = document.createElement("div");
  wrap.className = "aegis-attacks";
  wrap.innerHTML = `
    <header class="aegis-overview-header">
      <h1 tabindex="-1">Attack Events</h1>
    </header>
    <section class="aegis-overview-grid">
      <article class="aegis-card" aria-label="Detector breakdown">
        <h2>By detector (15m)</h2>
        <div class="aegis-card-body" data-slot="detector-breakdown">Loading…</div>
      </article>
      <article class="aegis-card" aria-label="Bot classification mix">
        <h2>Bot mix (1h)</h2>
        <div class="aegis-card-body" data-slot="bot-mix">Loading…</div>
      </article>
      <article class="aegis-card aegis-card-wide" aria-label="Top attackers / firing rules">
        <h2>Top attackers (15m)</h2>
        <div class="aegis-card-body" data-slot="top-rules">Loading…</div>
      </article>
      <article class="aegis-card aegis-card-wide" aria-label="Threat-intel hits">
        <h2>Threat-intel hits (1h)</h2>
        <div class="aegis-card-body" data-slot="threat-intel">Loading…</div>
      </article>
    </section>
  `;
  mountEl.appendChild(wrap);
}

function setupVisibility() {
  visibilityHandler = () => {
    if (document.visibilityState === "visible") {
      refreshDetectors();
      refreshTopRules();
      refreshThreatIntel();
      refreshBotMix();
    }
  };
  document.addEventListener("visibilitychange", visibilityHandler);
}

export default {
  mount(el) {
    mountEl = el;
    renderShell();
    setupVisibility();
    startPolling("byDetector",  refreshDetectors);
    startPolling("topRules",    refreshTopRules);
    startPolling("threatIntel", refreshThreatIntel);
    startPolling("botMix",      refreshBotMix);
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
    if (donutMod) {
      if (detectorDonut) donutMod.destroy(detectorDonut);
      if (botMixDonut) donutMod.destroy(botMixDonut);
    }
    if (tableMod) {
      if (topRulesTable) tableMod.destroy(topRulesTable);
      if (threatIntelTable) tableMod.destroy(threatIntelTable);
    }
    detectorDonut = null;
    topRulesTable = null;
    threatIntelTable = null;
    botMixDonut = null;
    mountEl = null;
  },
};
