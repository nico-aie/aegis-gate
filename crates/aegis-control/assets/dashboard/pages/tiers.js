// Tier Config page (D-M4-T4.4 + P3 per-tier detector overrides).
//
// Top section lists the four canonical tiers with their pipelines
// and thresholds. Bottom section shows per-tier detector class
// overrides backed by /api/detectors {GET, PUT}. The Save flow
// goes through the AuditedMutate pipeline (P1) so each per-tier
// flip lands an admin chain entry.

let mountEl = null;
let abortControllers = [];
let tableMod = null;
let tableState = null;
let drawerMod = null;
let drawer = null;
let pollTimer = null;
let detectorState = null;

const DETECTOR_TIERS = [
  { key: "critical", label: "Critical" },
  { key: "high",     label: "High" },
  { key: "medium",   label: "Medium" },
  { key: "catch_all",label: "Catch-all" },
];
const DETECTOR_LABELS = {
  sqli: "SQL injection",
  xss: "Cross-site scripting (XSS)",
  path_traversal: "Path traversal",
  ssrf: "SSRF",
  header_injection: "Header injection",
  body_abuse: "Body abuse",
  recon: "Reconnaissance",
  brute_force: "Brute force",
};

async function fetchJson(url, init) {
  const ctrl = new AbortController();
  abortControllers.push(ctrl);
  try {
    const res = await fetch(url, Object.assign({ cache: "no-store", signal: ctrl.signal }, init || {}));
    if (!res.ok) return { ok: false, status: res.status, body: await res.json().catch(() => null) };
    return { ok: true, status: res.status, body: await res.json() };
  } catch (e) {
    if (e.name !== "AbortError") console.error("tiers fetch failed", url, e);
    return { ok: false, status: 0, body: null };
  }
}
function readCookie(name) {
  for (const p of document.cookie.split(/;\s*/)) {
    if (p.startsWith(name + "=")) return p.slice(name.length + 1);
  }
  return null;
}

async function refreshTable() {
  const data = (await fetchJson("/api/tiers")).body;
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

async function refreshDetectors() {
  const res = await fetchJson("/api/detectors");
  if (!res.ok || !res.body || !mountEl) return;
  detectorState = res.body;
  renderOverrides();
}

function effectiveMaskFor(tierKey) {
  if (!detectorState) return null;
  const override = detectorState.overrides && detectorState.overrides[tierKey];
  return override || detectorState.mask;
}

function renderOverrides() {
  if (!detectorState || !mountEl) return;
  const wrap = mountEl.querySelector('[data-slot="tier-overrides"]');
  if (!wrap) return;
  wrap.replaceChildren();
  const locked = new Set(detectorState.locked_classes || []);
  for (const t of DETECTOR_TIERS) {
    const card = document.createElement("section");
    card.className = "aegis-card aegis-tier-override";
    card.setAttribute("aria-label", `${t.label} tier detector overrides`);
    const has = !!(detectorState.overrides && detectorState.overrides[t.key]);
    const effective = effectiveMaskFor(t.key);

    const head = document.createElement("header");
    head.className = "aegis-tier-override-head";
    const h2 = document.createElement("h3");
    h2.textContent = t.label;
    head.appendChild(h2);
    const pill = document.createElement("span");
    pill.className = "aegis-pill";
    pill.dataset.state = has ? "warn" : "ok";
    pill.textContent = has ? "override active" : "uses base";
    head.appendChild(pill);
    if (has) {
      const clear = document.createElement("button");
      clear.type = "button";
      clear.className = "aegis-button-secondary";
      clear.textContent = "Clear override";
      clear.addEventListener("click", () => clearOverride(t.key));
      head.appendChild(clear);
    } else {
      const seed = document.createElement("button");
      seed.type = "button";
      seed.className = "aegis-button-secondary";
      seed.textContent = "Add override";
      seed.addEventListener("click", () => addOverride(t.key));
      head.appendChild(seed);
    }
    card.appendChild(head);

    if (has) {
      const grid = document.createElement("div");
      grid.className = "aegis-toggle-grid";
      for (const cls of Object.keys(DETECTOR_LABELS)) {
        const row = document.createElement("div");
        row.className = "aegis-toggle-row";
        const id = `tier-${t.key}-${cls}`;
        const input = document.createElement("input");
        input.type = "checkbox";
        input.id = id;
        input.checked = !!effective[cls];
        input.disabled = locked.has(cls);
        input.dataset.tier = t.key;
        input.dataset.class = cls;
        input.addEventListener("change", () => applyTierOverride(t.key));
        const label = document.createElement("label");
        label.htmlFor = id;
        label.textContent = DETECTOR_LABELS[cls];
        row.appendChild(input);
        row.appendChild(label);
        grid.appendChild(row);
      }
      card.appendChild(grid);
    }
    wrap.appendChild(card);
  }
}

async function applyTierOverride(tierKey) {
  if (!mountEl) return;
  const inputs = mountEl.querySelectorAll(`input[data-tier="${tierKey}"]`);
  const body = {};
  inputs.forEach((el) => { body[el.dataset.class] = el.checked; });
  await sendDetectors({ overrides: { [tierKey]: body } }, `Updated ${tierKey} override.`);
}

async function clearOverride(tierKey) {
  await sendDetectors({ overrides: { [tierKey]: null } }, `Cleared ${tierKey} override.`);
}

async function addOverride(tierKey) {
  if (!detectorState) return;
  // Seed override from current base mask.
  const seeded = Object.assign({}, detectorState.mask);
  await sendDetectors({ overrides: { [tierKey]: seeded } }, `Added ${tierKey} override.`);
}

async function sendDetectors(payload, successMsg) {
  const status = mountEl.querySelector('[data-slot="overrides-status"]');
  const csrf = readCookie("aegis_csrf") || "";
  const res = await fetchJson("/api/detectors", {
    method: "PUT",
    headers: { "content-type": "application/json", "x-csrf-token": csrf },
    credentials: "same-origin",
    body: JSON.stringify(payload),
  });
  if (res.ok) {
    if (status) status.textContent = successMsg;
    if (res.body) {
      detectorState = res.body;
      renderOverrides();
    }
  } else {
    const msg = (res.body && res.body.message) || `PUT failed (status ${res.status})`;
    if (status) status.textContent = `Error: ${msg}`;
    // Re-render from last good state to revert any optimistic UI flip.
    renderOverrides();
  }
}

function renderShell() {
  mountEl.replaceChildren();
  const wrap = document.createElement("div");
  wrap.className = "aegis-tiers";
  wrap.innerHTML = `
    <header class="aegis-overview-header"><h1 tabindex="-1">Tier Config</h1></header>
    <section class="aegis-card" aria-label="Tiers">
      <div class="aegis-card-body" data-slot="tiers-table">Loading…</div>
    </section>
    <header class="aegis-section-header"><h2>Per-tier detector overrides</h2></header>
    <p data-slot="overrides-status" class="aegis-banner" role="status">Loading…</p>
    <div data-slot="tier-overrides" class="aegis-tier-overrides"></div>
  `;
  mountEl.appendChild(wrap);
}

async function refresh() {
  await refreshTable();
  await refreshDetectors();
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
    mountEl = null; detectorState = null;
  },
};
