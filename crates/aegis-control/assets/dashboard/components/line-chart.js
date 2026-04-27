// Line chart component (D-M2-T2.9).
//
// Vanilla SVG implementation. The original spec calls for Chart.js,
// but vendoring the binary is deferred — for the Overview chart's
// needs (one or two series, time-bucketed counts) SVG is more than
// sufficient and keeps the asset surface small + the CSP tight (no
// `style-src 'unsafe-inline'`).
//
// Props (`mount(el, props)`):
//   series: [{
//     name: string,
//     color: string,             // CSS colour, e.g. "var(--color-info)"
//     points: [{ ts: <iso|epoch>, value: number }, ...]
//   }, ...]
//   ariaLabel?: string

const SVG_NS = "http://www.w3.org/2000/svg";
const PADDING = { top: 12, right: 12, bottom: 24, left: 36 };

function svg(name, attrs = {}) {
  const el = document.createElementNS(SVG_NS, name);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
}

function clearChildren(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
}

function pointToXY(point) {
  const x = typeof point.ts === "number" ? point.ts : Date.parse(point.ts);
  const y = Number(point.value);
  return Number.isFinite(x) && Number.isFinite(y) ? { x, y } : null;
}

function bounds(series) {
  let minX = Infinity, maxX = -Infinity, maxY = 0;
  for (const s of series) {
    for (const p of s.points || []) {
      const xy = pointToXY(p);
      if (!xy) continue;
      if (xy.x < minX) minX = xy.x;
      if (xy.x > maxX) maxX = xy.x;
      if (xy.y > maxY) maxY = xy.y;
    }
  }
  if (!Number.isFinite(minX) || minX === maxX) {
    minX = 0;
    maxX = 1;
  }
  if (maxY === 0) maxY = 1;
  return { minX, maxX, minY: 0, maxY };
}

function pathD(series, b, w, h) {
  const innerW = w - PADDING.left - PADDING.right;
  const innerH = h - PADDING.top - PADDING.bottom;
  const xRange = b.maxX - b.minX;
  const yRange = b.maxY - b.minY;
  let d = "";
  for (const p of series.points || []) {
    const xy = pointToXY(p);
    if (!xy) continue;
    const x = PADDING.left + ((xy.x - b.minX) / xRange) * innerW;
    const y = PADDING.top + innerH - ((xy.y - b.minY) / yRange) * innerH;
    d += d.length === 0
      ? `M ${x.toFixed(2)} ${y.toFixed(2)}`
      : ` L ${x.toFixed(2)} ${y.toFixed(2)}`;
  }
  return d;
}

function render(state) {
  const { container, props, width, height } = state;
  clearChildren(container);

  const root = svg("svg", {
    viewBox: `0 0 ${width} ${height}`,
    role: "img",
    "aria-label": props.ariaLabel || "Line chart",
    class: "aegis-line-chart",
    preserveAspectRatio: "none",
  });

  const allSeries = props.series || [];
  const b = bounds(allSeries);

  // 4 horizontal gridlines + Y-axis tick labels.
  const innerH = height - PADDING.top - PADDING.bottom;
  for (let i = 0; i <= 4; i++) {
    const y = PADDING.top + (innerH * i) / 4;
    root.appendChild(svg("line", {
      x1: PADDING.left,
      y1: y.toFixed(1),
      x2: width - PADDING.right,
      y2: y.toFixed(1),
      stroke: "var(--border-subtle)",
      "stroke-width": "1",
    }));
    const value = b.maxY - ((b.maxY - b.minY) * i) / 4;
    const text = svg("text", {
      x: PADDING.left - 4,
      y: y + 4,
      "text-anchor": "end",
      class: "aegis-chart-tick",
      fill: "var(--text-muted)",
      "font-size": "10",
    });
    text.textContent = String(Math.round(value));
    root.appendChild(text);
  }

  for (const s of allSeries) {
    const path = svg("path", {
      d: pathD(s, b, width, height),
      fill: "none",
      stroke: s.color || "var(--color-info)",
      "stroke-width": "2",
      "stroke-linecap": "round",
      "stroke-linejoin": "round",
    });
    if (s.name) path.setAttribute("data-series", s.name);
    root.appendChild(path);
  }

  const caption = svg("title");
  const total = allSeries.reduce(
    (acc, s) => acc + (s.points || []).reduce((a, p) => a + (Number(p.value) || 0), 0),
    0
  );
  caption.textContent = `${allSeries.length} series, ${total} total events.`;
  root.appendChild(caption);

  container.appendChild(root);
}

export default {
  /** Returns a `state` handle the page passes back to `update()` / `destroy()`. */
  mount(el, props) {
    const container = document.createElement("div");
    container.className = "aegis-chart-host";
    container.dataset.component = "line-chart";
    el.replaceChildren(container);

    const measure = () => {
      const rect = container.getBoundingClientRect();
      return {
        width: Math.max(120, Math.round(rect.width)),
        height: Math.max(120, Math.round(rect.height || 200)),
      };
    };
    const { width, height } = measure();
    const state = { container, props, width, height };
    render(state);
    return state;
  },

  update(state, nextProps) {
    if (!state) return;
    state.props = nextProps;
    const rect = state.container.getBoundingClientRect();
    state.width = Math.max(120, Math.round(rect.width));
    state.height = Math.max(120, Math.round(rect.height || 200));
    render(state);
  },

  destroy(state) {
    if (!state) return;
    clearChildren(state.container);
    state.container.remove();
  },
};
