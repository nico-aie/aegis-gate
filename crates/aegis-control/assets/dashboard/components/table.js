// Table component (D-M2-T2.9).
//
// Sortable, accessible HTML table. Pagination + virtualization land
// later (D-M3 Live Feed needs them); v1 covers the simple cases —
// Overview top-attackers, Tracking pool list, etc.
//
// Props (`mount(el, props)`):
//   columns: [{ key, label, render?(row): string|Node, sortable?: bool }]
//   rows: object[]
//   sortBy?: { key, dir: 'asc'|'desc' }
//   onRowClick?: (row) => void  // optional; emits `aegis:row-click` either way
//   ariaLabel?: string
//
// `aegis:row-click` CustomEvent bubbles up the row object as detail
// so page modules can subscribe without a callback prop. Header
// clicks emit `aegis:sort` with the new sort key/dir.

function clearChildren(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
}

function compareValues(a, b) {
  if (a == null && b == null) return 0;
  if (a == null) return -1;
  if (b == null) return 1;
  if (typeof a === "number" && typeof b === "number") return a - b;
  return String(a).localeCompare(String(b));
}

function sortRows(rows, sortBy) {
  if (!sortBy || !sortBy.key) return rows.slice();
  const dir = sortBy.dir === "desc" ? -1 : 1;
  const sorted = rows.slice();
  sorted.sort((a, b) => dir * compareValues(a[sortBy.key], b[sortBy.key]));
  return sorted;
}

function renderCell(td, col, row) {
  td.dataset.col = col.key;
  if (typeof col.render === "function") {
    const out = col.render(row);
    if (out instanceof Node) {
      td.replaceChildren(out);
    } else {
      td.textContent = out == null ? "" : String(out);
    }
  } else {
    td.textContent = row[col.key] == null ? "" : String(row[col.key]);
  }
}

function buildHead(state) {
  const thead = document.createElement("thead");
  const tr = document.createElement("tr");
  for (const col of state.props.columns || []) {
    const th = document.createElement("th");
    th.scope = "col";
    th.textContent = col.label;
    th.dataset.col = col.key;
    const sortable = col.sortable !== false;
    if (sortable) {
      th.setAttribute("role", "button");
      th.tabIndex = 0;
      const sortBy = state.props.sortBy;
      if (sortBy && sortBy.key === col.key) {
        th.setAttribute("aria-sort", sortBy.dir === "desc" ? "descending" : "ascending");
      }
      const onSort = () => {
        const current = state.props.sortBy;
        const dir = current && current.key === col.key && current.dir === "asc" ? "desc" : "asc";
        const next = { ...state.props, sortBy: { key: col.key, dir } };
        state.host.dispatchEvent(
          new CustomEvent("aegis:sort", { bubbles: true, detail: { key: col.key, dir } })
        );
        state.props = next;
        render(state);
      };
      th.addEventListener("click", onSort);
      th.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onSort();
        }
      });
    }
    tr.appendChild(th);
  }
  thead.appendChild(tr);
  return thead;
}

function buildBody(state, rows) {
  const tbody = document.createElement("tbody");
  for (const row of rows) {
    const tr = document.createElement("tr");
    for (const col of state.props.columns || []) {
      const td = document.createElement("td");
      renderCell(td, col, row);
      tr.appendChild(td);
    }
    tr.addEventListener("click", () => {
      state.host.dispatchEvent(
        new CustomEvent("aegis:row-click", { bubbles: true, detail: row })
      );
      if (typeof state.props.onRowClick === "function") state.props.onRowClick(row);
    });
    tbody.appendChild(tr);
  }
  return tbody;
}

function render(state) {
  const { host, props } = state;
  clearChildren(host);
  const wrap = document.createElement("div");
  wrap.className = "aegis-table-wrap";
  wrap.dataset.component = "table";
  const table = document.createElement("table");
  table.className = "aegis-table";
  table.setAttribute("role", "table");
  if (props.ariaLabel) table.setAttribute("aria-label", props.ariaLabel);
  table.appendChild(buildHead(state));
  const rows = sortRows(props.rows || [], props.sortBy);
  table.appendChild(buildBody(state, rows));
  if (rows.length === 0) {
    const empty = document.createElement("p");
    empty.className = "aegis-table-empty";
    empty.textContent = props.emptyMessage || "No rows.";
    wrap.appendChild(empty);
  } else {
    wrap.appendChild(table);
  }
  host.appendChild(wrap);
}

export default {
  mount(el, props) {
    const state = { host: el, props: props || { columns: [], rows: [] } };
    render(state);
    return state;
  },
  update(state, nextProps) {
    if (!state) return;
    state.props = nextProps;
    render(state);
  },
  destroy(state) {
    if (!state) return;
    clearChildren(state.host);
  },
};
