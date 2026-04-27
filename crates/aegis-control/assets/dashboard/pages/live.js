// Live Feed page (D-M3-T3.1).
//
// Server-Sent Events stream consumer with a filter strip + a
// row-detail drawer. Filters are applied server-side: the page
// closes the EventSource and reopens it with a fresh
// `?class=&action=&route=` query when the user toggles a chip,
// matching the predicate in `src/dashboard/sse.rs::EventFilter`.
//
// Row appends are batched to `requestAnimationFrame` so a 1k-event
// burst doesn't choke the main thread. The visible window is capped
// at 200 rows; older rows fall off the back.

const MAX_ROWS = 200;
const RAF_BATCH_LIMIT = 100;
const STREAM_PATH = "/dashboard/sse";

const STATE = {
  el: null,
  source: null,
  filter: { classes: new Set(), actions: new Set(), routes: new Set() },
  rows: [],          // newest-first
  pending: [],       // events buffered for the next RAF tick
  paused: false,
  rafQueued: false,
  drawer: null,
  drawerMod: null,
  visibilityHandler: null,
  decoder: new TextDecoder(),
};

function buildQuery(filter) {
  const parts = [];
  for (const c of filter.classes) parts.push(`class=${encodeURIComponent(c)}`);
  for (const a of filter.actions) parts.push(`action=${encodeURIComponent(a)}`);
  for (const r of filter.routes)  parts.push(`route=${encodeURIComponent(r)}`);
  return parts.length === 0 ? STREAM_PATH : `${STREAM_PATH}?${parts.join("&")}`;
}

function reopenStream() {
  if (STATE.source) {
    STATE.source.close();
    STATE.source = null;
  }
  if (typeof EventSource === "undefined") return;
  const url = buildQuery(STATE.filter);
  try {
    STATE.source = new EventSource(url);
  } catch (e) {
    console.error("Live Feed SSE failed to open", e);
    return;
  }
  STATE.source.addEventListener("message", onSseMessage);
}

function onSseMessage(e) {
  if (STATE.paused) return;
  let payload;
  try {
    payload = JSON.parse(e.data);
  } catch (_) {
    return; // ignore non-JSON keepalives
  }
  STATE.pending.push(payload);
  if (!STATE.rafQueued) {
    STATE.rafQueued = true;
    requestAnimationFrame(flushPending);
  }
}

function flushPending() {
  STATE.rafQueued = false;
  if (STATE.pending.length === 0) return;
  const batch = STATE.pending.splice(0, RAF_BATCH_LIMIT);
  // Newest-first: prepend in receive order so the visible top row
  // is the most recently received event.
  for (const ev of batch) STATE.rows.unshift(ev);
  if (STATE.rows.length > MAX_ROWS) STATE.rows.length = MAX_ROWS;
  renderRows();
  // If more events arrived during this frame, queue another flush.
  if (STATE.pending.length > 0 && !STATE.rafQueued) {
    STATE.rafQueued = true;
    requestAnimationFrame(flushPending);
  }
}

function renderRows() {
  if (!STATE.el) return;
  const slot = STATE.el.querySelector('[data-slot="live-rows"]');
  if (!slot) return;
  slot.replaceChildren();
  if (STATE.rows.length === 0) {
    const empty = document.createElement("p");
    empty.className = "aegis-empty";
    empty.textContent = "Listening for events…";
    slot.appendChild(empty);
    return;
  }
  const ul = document.createElement("ol");
  ul.className = "aegis-live-list";
  ul.setAttribute("role", "log");
  ul.setAttribute("aria-live", "polite");
  ul.setAttribute("aria-relevant", "additions");
  for (const ev of STATE.rows) {
    const li = document.createElement("li");
    li.className = "aegis-live-row";
    li.dataset.class = ev.class || "system";
    const ts = document.createElement("span");
    ts.className = "aegis-live-ts";
    ts.textContent = (ev.ts || "").replace("T", " ").replace("Z", "");
    const klass = document.createElement("span");
    klass.className = "aegis-live-class";
    klass.textContent = `[${ev.class || "?"}]`;
    const msg = document.createElement("span");
    msg.className = "aegis-live-msg";
    msg.textContent = `${ev.action || ""}: ${ev.reason || ""}`;
    li.append(ts, klass, msg);
    li.addEventListener("click", () => openDrawer(ev));
    ul.appendChild(li);
  }
  slot.appendChild(ul);
}

async function openDrawer(ev) {
  if (!STATE.drawerMod) {
    STATE.drawerMod = (await import("/dashboard/assets/components/drawer.js")).default;
  }
  if (STATE.drawer) STATE.drawer.close();
  STATE.drawer = STATE.drawerMod.open({
    title: `${ev.class || "event"} · ${ev.request_id || ""}`,
    body: ev,
    onClose: () => {
      STATE.drawer = null;
    },
  });
}

function toggleSetMember(setObj, value) {
  if (setObj.has(value)) setObj.delete(value);
  else setObj.add(value);
}

function setupFilterStrip() {
  if (!STATE.el) return;
  STATE.el.querySelectorAll('button[data-filter]').forEach((btn) => {
    btn.addEventListener("click", () => {
      const kind = btn.dataset.filter;
      const value = btn.dataset.value;
      if (!kind || !value) return;
      const set = STATE.filter[kind];
      if (!set) return;
      toggleSetMember(set, value);
      btn.dataset.active = set.has(value) ? "true" : "false";
      reopenStream();
    });
  });
  const pauseBtn = STATE.el.querySelector('button[data-action="pause"]');
  if (pauseBtn) {
    pauseBtn.addEventListener("click", () => {
      STATE.paused = !STATE.paused;
      pauseBtn.textContent = STATE.paused ? "Resume" : "Pause";
      pauseBtn.dataset.paused = STATE.paused ? "true" : "false";
    });
  }
  const clearBtn = STATE.el.querySelector('button[data-action="clear"]');
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      STATE.rows = [];
      STATE.pending = [];
      renderRows();
    });
  }
}

function renderShell() {
  STATE.el.replaceChildren();
  const wrap = document.createElement("div");
  wrap.className = "aegis-live";
  wrap.innerHTML = `
    <header class="aegis-overview-header">
      <h1 tabindex="-1">Live Feed</h1>
    </header>
    <section class="aegis-filter-strip" aria-label="Filter live feed">
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
        <button type="button" data-action="pause" data-paused="false">Pause</button>
        <button type="button" data-action="clear">Clear</button>
      </div>
    </section>
    <section class="aegis-card" aria-label="Live event stream">
      <div class="aegis-card-body" data-slot="live-rows">Listening for events…</div>
    </section>
  `;
  STATE.el.appendChild(wrap);
}

export default {
  mount(el) {
    STATE.el = el;
    renderShell();
    setupFilterStrip();
    reopenStream();
  },
  destroy() {
    if (STATE.source) {
      STATE.source.close();
      STATE.source = null;
    }
    if (STATE.drawer) {
      STATE.drawer.close();
      STATE.drawer = null;
    }
    STATE.rows = [];
    STATE.pending = [];
    STATE.rafQueued = false;
    STATE.paused = false;
    STATE.el = null;
  },
};
