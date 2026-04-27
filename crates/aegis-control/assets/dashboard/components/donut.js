// Donut chart component (D-M2-T2.9).
//
// Vanilla SVG; renders proportional ring segments + a legend.
// Inner radius 60% per docs/dashboard-enterprise/components.md.
// Click on a segment dispatches `aegis:slice-click` with detail
// `{ name, value, pct }` so page modules don't need a callback prop.

const SVG_NS = "http://www.w3.org/2000/svg";
const VIEW = 100; // viewBox is 100x100
const OUTER_R = 48;
const INNER_R = OUTER_R * 0.6;
const CENTER = VIEW / 2;
// Default palette — overridden per-slice via the `color` prop.
const DEFAULT_COLORS = [
  "var(--color-info)",
  "var(--color-violet)",
  "var(--color-pink)",
  "var(--color-warn)",
  "var(--color-err)",
  "var(--color-teal)",
  "var(--color-ok)",
];

function svg(name, attrs = {}) {
  const el = document.createElementNS(SVG_NS, name);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
}

function clearChildren(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
}

/** Build an annulus-segment path from (start, end) angles in radians. */
function segmentPath(start, end) {
  if (end - start <= 0) return "";
  const ox1 = CENTER + Math.cos(start) * OUTER_R;
  const oy1 = CENTER + Math.sin(start) * OUTER_R;
  const ox2 = CENTER + Math.cos(end) * OUTER_R;
  const oy2 = CENTER + Math.sin(end) * OUTER_R;
  const ix1 = CENTER + Math.cos(end) * INNER_R;
  const iy1 = CENTER + Math.sin(end) * INNER_R;
  const ix2 = CENTER + Math.cos(start) * INNER_R;
  const iy2 = CENTER + Math.sin(start) * INNER_R;
  const large = end - start > Math.PI ? 1 : 0;
  return [
    `M ${ox1.toFixed(3)} ${oy1.toFixed(3)}`,
    `A ${OUTER_R} ${OUTER_R} 0 ${large} 1 ${ox2.toFixed(3)} ${oy2.toFixed(3)}`,
    `L ${ix1.toFixed(3)} ${iy1.toFixed(3)}`,
    `A ${INNER_R} ${INNER_R} 0 ${large} 0 ${ix2.toFixed(3)} ${iy2.toFixed(3)}`,
    "Z",
  ].join(" ");
}

function buildLegend(slices, total, host) {
  const ul = document.createElement("ul");
  ul.className = "aegis-donut-legend";
  slices.forEach((s, i) => {
    const li = document.createElement("li");
    const swatch = document.createElement("span");
    swatch.className = "aegis-donut-swatch";
    swatch.style.background = s.color || DEFAULT_COLORS[i % DEFAULT_COLORS.length];
    li.appendChild(swatch);
    const label = document.createElement("span");
    const pct = total > 0 ? ((Number(s.value) || 0) / total) * 100 : 0;
    label.textContent = `${s.name}: ${s.value} (${pct.toFixed(1)}%)`;
    li.appendChild(label);
    li.addEventListener("click", () => {
      host.dispatchEvent(
        new CustomEvent("aegis:slice-click", { bubbles: true, detail: { name: s.name, value: s.value, pct } })
      );
    });
    ul.appendChild(li);
  });
  return ul;
}

function renderEmpty(host, message) {
  clearChildren(host);
  const empty = document.createElement("p");
  empty.className = "aegis-donut-empty";
  empty.textContent = message;
  host.appendChild(empty);
}

function render(state) {
  const { host, props } = state;
  clearChildren(host);

  const slices = (props.slices || []).filter((s) => Number(s.value) > 0);
  const total = slices.reduce((acc, s) => acc + Number(s.value), 0);

  if (slices.length === 0 || total === 0) {
    renderEmpty(host, props.emptyMessage || "No data in window.");
    return;
  }

  const root = svg("svg", {
    viewBox: `0 0 ${VIEW} ${VIEW}`,
    role: "img",
    "aria-label": props.ariaLabel || "Donut chart",
    class: "aegis-donut",
  });

  let cursor = -Math.PI / 2; // start at 12 o'clock
  slices.forEach((s, i) => {
    const angle = (Number(s.value) / total) * Math.PI * 2;
    const seg = svg("path", {
      d: segmentPath(cursor, cursor + angle),
      fill: s.color || DEFAULT_COLORS[i % DEFAULT_COLORS.length],
      "data-slice": s.name,
    });
    seg.addEventListener("click", () => {
      host.dispatchEvent(
        new CustomEvent("aegis:slice-click", {
          bubbles: true,
          detail: {
            name: s.name,
            value: s.value,
            pct: (Number(s.value) / total) * 100,
          },
        })
      );
    });
    root.appendChild(seg);
    cursor += angle;
  });

  // Centre label: total events.
  const text = svg("text", {
    x: CENTER,
    y: CENTER + 4,
    "text-anchor": "middle",
    fill: "var(--text-primary)",
    "font-size": "12",
    "font-weight": "600",
  });
  text.textContent = String(total);
  root.appendChild(text);

  const wrap = document.createElement("div");
  wrap.className = "aegis-donut-host";
  wrap.dataset.component = "donut";
  wrap.appendChild(root);
  wrap.appendChild(buildLegend(slices, total, wrap));
  host.appendChild(wrap);
}

export default {
  mount(el, props) {
    const state = { host: el, props };
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
