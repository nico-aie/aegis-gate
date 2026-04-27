// Tier Config page (D-M4-T4.4).
//
// Lists the four canonical tiers with their pipelines + thresholds.
// Save (PUT /api/tiers/{name}) is deferred until the M3 audit-mutation
// pipeline is integrated.

let mountEl = null;
let abortControllers = [];
let tableMod = null;
let tableState = null;
let drawerMod = null;
let drawer = null;
let pollTimer = null;

async function fetchJson(url) {
  const ctrl = new AbortController();
  abortControllers.push(ctrl);
  try {
    const res = await fetch(url, { cache: "no-store", signal: ctrl.signal });
    if (!res.ok) return null;
    return await res.json();
  } catch (e) {
    if (e.name !== "AbortError") console.error("tiers fetch failed", url, e);
    return null;
  }
}

async function refresh() {
  const data = await fetchJson("/api/tiers");
  if (!data || !mountEl) return;
  const slot = mountEl.querySelector('[data-slot="tiers-table"]');
  if (!tableMod) {
    tableMod = (await import("/dashboard/assets/components/table.js")).default;
  }
  const rows = (data.tiers || []).map((t) => ({
    name: t.name,
    pipeline: (t.pipeline || []).join(", "),
    risk: t.risk_threshold,
    block: t.block_threshold,
    raw: t,
  }));
  const props = {
    ariaLabel: "Tiers",
    columns: [
      { key: "name",     label: "Tier" },
      { key: "pipeline", label: "Pipeline", sortable: false },
      { key: "risk",     label: "Risk threshold" },
      { key: "block",    label: "Block threshold" },
    ],
    rows,
    sortBy: { key: "name", dir: "asc" },
  };
  if (!tableState) {
    tableState = tableMod.mount(slot, props);
    slot.addEventListener("aegis:row-click", async (e) => {
      if (!drawerMod) {
        drawerMod = (await import("/dashboard/assets/components/drawer.js")).default;
      }
      if (drawer) drawer.close();
      drawer = drawerMod.open({
        title: `Tier ${e.detail.name}`,
        body: e.detail.raw,
        onClose: () => { drawer = null; },
      });
    });
  } else {
    tableMod.update(tableState, props);
  }
}

function renderShell() {
  mountEl.replaceChildren();
  const wrap = document.createElement("div");
  wrap.className = "aegis-tiers";
  wrap.innerHTML = `
    <header class="aegis-overview-header"><h1 tabindex="-1">Tier Config</h1></header>
    <p class="aegis-banner" role="status">Read-only until M3 audit-mutation pipeline lands.</p>
    <section class="aegis-card" aria-label="Tiers">
      <div class="aegis-card-body" data-slot="tiers-table">Loading…</div>
    </section>
  `;
  mountEl.appendChild(wrap);
}

export default {
  mount(el) { mountEl = el; renderShell(); refresh();
    pollTimer = setInterval(() => { if (document.visibilityState === "visible") refresh(); }, 30000);
  },
  destroy() {
    if (pollTimer) clearInterval(pollTimer); pollTimer = null;
    for (const c of abortControllers) c.abort(); abortControllers = [];
    if (drawer) { drawer.close(); drawer = null; }
    if (tableMod && tableState) { tableMod.destroy(tableState); tableState = null; }
    mountEl = null;
  },
};
