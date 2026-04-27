// Rule Manager page (D-M4-T4.1).
//
// Lists rules; selecting a row opens a drawer with the rule body
// and a Validate button. v1 surfaces the read path; mutation calls
// (POST /api/rules/validate, PUT /api/rules/{id}) require the M3
// audit-mutation pipeline before they're wired client-side.

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
    if (e.name !== "AbortError") console.error("rules fetch failed", url, e);
    return null;
  }
}

async function ensureTable() {
  if (!tableMod) {
    tableMod = (await import("/dashboard/assets/components/table.js")).default;
  }
  return tableMod;
}

async function ensureDrawer() {
  if (!drawerMod) {
    drawerMod = (await import("/dashboard/assets/components/drawer.js")).default;
  }
  return drawerMod;
}

async function refresh() {
  const data = await fetchJson("/api/rules");
  if (!data || !mountEl) return;
  const slot = mountEl.querySelector('[data-slot="rules-table"]');
  const table = await ensureTable();
  const rows = (data.rules || []).map((r) => ({
    id: r.id,
    enabled: r.enabled ? "✓" : "—",
    body: r.body,
    updated: (r.updated_at || "").replace("T", " ").replace("Z", ""),
    raw: r,
  }));
  const props = {
    ariaLabel: "Rules",
    emptyMessage: "No rules configured.",
    columns: [
      { key: "id", label: "ID" },
      { key: "enabled", label: "Enabled" },
      { key: "updated", label: "Updated" },
    ],
    rows,
    sortBy: { key: "id", dir: "asc" },
  };
  if (!tableState) {
    tableState = table.mount(slot, props);
    slot.addEventListener("aegis:row-click", openRule);
  } else {
    table.update(tableState, props);
  }
}

async function openRule(e) {
  const drawer_ = await ensureDrawer();
  const row = e.detail;
  if (!row || !row.raw) return;
  if (drawer) drawer.close();
  drawer = drawer_.open({
    title: `Rule ${row.id}`,
    body: row.raw,
    onClose: () => { drawer = null; },
  });
}

function renderShell() {
  mountEl.replaceChildren();
  const wrap = document.createElement("div");
  wrap.className = "aegis-rules";
  wrap.innerHTML = `
    <header class="aegis-overview-header"><h1 tabindex="-1">Rule Manager</h1></header>
    <p class="aegis-banner" role="status">
      Mutation endpoints (validate, save, delete) require the M3
      audit-mutation pipeline — currently read-only.
    </p>
    <section class="aegis-card" aria-label="Rules">
      <div class="aegis-card-body" data-slot="rules-table">Loading…</div>
    </section>
  `;
  mountEl.appendChild(wrap);
}

export default {
  mount(el) {
    mountEl = el;
    renderShell();
    refresh();
    pollTimer = setInterval(() => {
      if (document.visibilityState === "visible") refresh();
    }, 10000);
  },
  destroy() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = null;
    for (const c of abortControllers) c.abort();
    abortControllers = [];
    if (drawer) { drawer.close(); drawer = null; }
    if (tableMod && tableState) { tableMod.destroy(tableState); tableState = null; }
    mountEl = null;
  },
};
