// Audit Log page (D-M3-T3.7).
//
// Cursor-paginated table backed by /api/audit/since. Two status pills
// (witness lag, chain health), a filter chip strip populated from
// /api/filters, and an Export NDJSON button that streams the visible
// page to a downloadable blob.
//
// Cursor pagination model: the page maintains a `cursor` cursor; "Older"
// fetches starting from cursor 0 forward; "Newer" appends events with
// seq > current_max. Audit chain status comes from /api/audit/verify
// when present (existing endpoint); falls back to "unknown" otherwise.

const PAGE_SIZE = 100;
const REFRESH_INTERVAL_MS = 5000;

let mountEl = null;
let timers = [];
let abortControllers = [];
let visibilityHandler = null;
let drawerMod = null;
let drawer = null;
let tableMod = null;
let tableState = null;

let rows = [];        // currently rendered events (with `seq`)
let highWater = 0;    // largest seq seen
let filter = { classes: new Set(), actions: new Set() };

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
    if (e.name !== "AbortError") console.error("audit fetch failed", url, e);
    return null;
  }
}

function applyFilters(events) {
  return events.filter((ev) => {
    if (filter.classes.size > 0 && !filter.classes.has(ev.class)) return false;
    if (filter.actions.size > 0 && !filter.actions.has(ev.action)) return false;
    return true;
  });
}

async function refreshNewer() {
  const url = `/api/audit/since?cursor=${highWater}&limit=${PAGE_SIZE}`;
  const data = await fetchJson(url);
  if (!data) return;
  const incoming = data.events || [];
  if (incoming.length === 0) return;
  for (const ev of incoming) {
    if (ev.seq > highWater) highWater = ev.seq;
    rows.unshift(ev);
  }
  if (rows.length > PAGE_SIZE * 5) rows.length = PAGE_SIZE * 5;
  await renderRows();
  if (data.gap) {
    flashStatus("Stream gap — older events dropped");
  }
}

async function loadInitial() {
  const data = await fetchJson(`/api/audit/since?cursor=0&limit=${PAGE_SIZE}`);
  if (!data) return;
  rows = (data.events || []).slice().reverse(); // newest first
  if (rows.length > 0) highWater = rows[0].seq;
  await renderRows();
}

async function refreshWitness() {
  const data = await fetchJson("/api/audit/witness");
  if (!data || !mountEl) return;
  const pill = mountEl.querySelector('[data-slot="witness-pill"]');
  if (!pill) return;
  if (data.lag_seconds == null) {
    pill.textContent = "Witness: not signed";
    pill.dataset.state = "unknown";
    return;
  }
  const lag = Number(data.lag_seconds);
  pill.textContent = `Witness: ${formatLag(lag)}`;
  pill.dataset.state = lag < 0 ? "warn" : lag < 60 ? "ok" : lag < 600 ? "warn" : "err";
}

async function refreshChainStatus() {
  // /api/audit/verify is part of the existing M3 audit chain
  // surface. If unreachable, leave the pill as "unknown".
  const data = await fetchJson("/api/audit/verify");
  if (!mountEl) return;
  const pill = mountEl.querySelector('[data-slot="chain-pill"]');
  if (!pill) return;
  if (!data) {
    pill.textContent = "Chain: unknown";
    pill.dataset.state = "unknown";
    return;
  }
  const ok = data.ok === true || data.valid === true;
  pill.textContent = ok ? "Chain: OK" : "Chain: TAMPERED";
  pill.dataset.state = ok ? "ok" : "err";
}

async function refreshFilters() {
  const data = await fetchJson("/api/filters");
  if (!data || !mountEl) return;
  // Keep the strip simple for v1: we render the static class/action
  // chips at mount; the filter response surfaces what's available
  // for future use (chip dropdowns).
  const env = mountEl.querySelector('[data-slot="filter-summary"]');
  if (!env) return;
  const counts = [
    `${(data.classes || []).length} classes`,
    `${(data.actors || []).length} actors`,
    `${(data.actions || []).length} actions`,
    `${(data.routes || []).length} routes`,
  ];
  env.textContent = counts.join(" · ");
}

async function ensureTable() {
  if (!tableMod) {
    tableMod = (await import("/dashboard/assets/components/table.js")).default;
  }
  return tableMod;
}

async function renderRows() {
  if (!mountEl) return;
  const slot = mountEl.querySelector('[data-slot="audit-rows"]');
  if (!slot) return;
  const table = await ensureTable();
  const filtered = applyFilters(rows);
  const tableRows = filtered.map((ev) => ({
    seq: ev.seq,
    ts: (ev.ts || "").replace("T", " ").replace("Z", ""),
    class: ev.class,
    action: ev.action,
    ip: ev.client_ip || "—",
    rule: ev.rule_id || "—",
    raw: ev,
  }));
  const props = {
    ariaLabel: "Audit log",
    emptyMessage: "No audit events.",
    columns: [
      { key: "seq",    label: "#" },
      { key: "ts",     label: "Time", sortable: false },
      { key: "class",  label: "Class" },
      { key: "action", label: "Action" },
      { key: "ip",     label: "Source" },
      { key: "rule",   label: "Rule" },
    ],
    rows: tableRows,
    sortBy: { key: "seq", dir: "desc" },
  };
  if (!tableState) {
    tableState = table.mount(slot, props);
    slot.addEventListener("aegis:row-click", openDrawer);
  } else {
    table.update(tableState, props);
  }
}

async function openDrawer(e) {
  if (!drawerMod) {
    drawerMod = (await import("/dashboard/assets/components/drawer.js")).default;
  }
  const row = e.detail;
  if (!row || !row.raw) return;
  if (drawer) drawer.close();
  drawer = drawerMod.open({
    title: `Audit #${row.seq}`,
    body: row.raw,
    onClose: () => {
      drawer = null;
    },
  });
}

function exportNdjson() {
  const filtered = applyFilters(rows);
  const lines = filtered.map((ev) => {
    const { seq: _seq, ...rest } = ev;
    return JSON.stringify(rest);
  });
  const blob = new Blob([lines.join("\n")], { type: "application/x-ndjson" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `audit-${new Date().toISOString()}.ndjson`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function flashStatus(text) {
  if (!mountEl) return;
  const banner = mountEl.querySelector('[data-slot="status-flash"]');
  if (!banner) return;
  banner.textContent = text;
  banner.hidden = false;
  setTimeout(() => {
    banner.hidden = true;
    banner.textContent = "";
  }, 4000);
}

function formatLag(seconds) {
  const n = Math.abs(seconds);
  if (n < 60) return `${n}s ago`;
  if (n < 3600) return `${Math.round(n / 60)}m ago`;
  return `${Math.round(n / 3600)}h ago`;
}

function setupFilterStrip() {
  if (!mountEl) return;
  mountEl.querySelectorAll('button[data-filter]').forEach((btn) => {
    btn.addEventListener("click", async () => {
      const kind = btn.dataset.filter;
      const value = btn.dataset.value;
      if (!kind || !value || !filter[kind]) return;
      if (filter[kind].has(value)) filter[kind].delete(value);
      else filter[kind].add(value);
      btn.dataset.active = filter[kind].has(value) ? "true" : "false";
      await renderRows();
    });
  });
  const exportBtn = mountEl.querySelector('button[data-action="export"]');
  if (exportBtn) exportBtn.addEventListener("click", exportNdjson);
}

function startPolling() {
  const id = setInterval(() => {
    if (document.visibilityState !== "visible") return;
    refreshNewer();
    refreshWitness();
    refreshChainStatus();
    refreshFilters();
  }, REFRESH_INTERVAL_MS);
  timers.push(id);
}

function renderShell() {
  mountEl.replaceChildren();
  const wrap = document.createElement("div");
  wrap.className = "aegis-audit";
  wrap.innerHTML = `
    <header class="aegis-overview-header">
      <h1 tabindex="-1">Audit Log</h1>
      <div class="aegis-pill-row">
        <span class="aegis-pill" data-slot="chain-pill" data-state="unknown">Chain: unknown</span>
        <span class="aegis-pill" data-slot="witness-pill" data-state="unknown">Witness: not signed</span>
      </div>
    </header>
    <section class="aegis-filter-strip" aria-label="Filter audit log">
      <fieldset>
        <legend>Class</legend>
        <button type="button" data-filter="classes" data-value="detection" data-active="false">Detection</button>
        <button type="button" data-filter="classes" data-value="admin" data-active="false">Admin</button>
        <button type="button" data-filter="classes" data-value="access" data-active="false">Access</button>
        <button type="button" data-filter="classes" data-value="system" data-active="false">System</button>
      </fieldset>
      <fieldset>
        <legend>Action</legend>
        <button type="button" data-filter="actions" data-value="block" data-active="false">Block</button>
        <button type="button" data-filter="actions" data-value="allow" data-active="false">Allow</button>
        <button type="button" data-filter="actions" data-value="challenge" data-active="false">Challenge</button>
      </fieldset>
      <div class="aegis-filter-actions">
        <button type="button" data-action="export">Export NDJSON</button>
      </div>
    </section>
    <p class="aegis-status-flash" data-slot="status-flash" hidden></p>
    <p class="aegis-filter-summary" data-slot="filter-summary"></p>
    <section class="aegis-card" aria-label="Audit events">
      <div class="aegis-card-body" data-slot="audit-rows">Loading…</div>
    </section>
  `;
  mountEl.appendChild(wrap);
}

function setupVisibility() {
  visibilityHandler = () => {
    if (document.visibilityState !== "visible") return;
    refreshNewer();
    refreshWitness();
    refreshChainStatus();
  };
  document.addEventListener("visibilitychange", visibilityHandler);
}

export default {
  mount(el) {
    mountEl = el;
    rows = [];
    highWater = 0;
    filter = { classes: new Set(), actions: new Set() };
    renderShell();
    setupFilterStrip();
    setupVisibility();
    loadInitial();
    refreshWitness();
    refreshChainStatus();
    refreshFilters();
    startPolling();
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
    if (drawer) {
      drawer.close();
      drawer = null;
    }
    if (tableMod && tableState) {
      tableMod.destroy(tableState);
      tableState = null;
    }
    rows = [];
    highWater = 0;
    mountEl = null;
  },
};
