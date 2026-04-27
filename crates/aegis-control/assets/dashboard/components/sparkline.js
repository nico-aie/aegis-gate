// Sparkline component (D-M2-T2.9).
//
// 60×20 SVG line; no axes, no tooltip — used inside table rows for
// per-row trend visualisation. Props:
//   points: number[]
//   color?: string

const SVG_NS = "http://www.w3.org/2000/svg";
const W = 60;
const H = 20;

function buildPath(points) {
  if (!Array.isArray(points) || points.length === 0) return "";
  let max = -Infinity;
  let min = Infinity;
  for (const v of points) {
    const n = Number(v);
    if (!Number.isFinite(n)) continue;
    if (n > max) max = n;
    if (n < min) min = n;
  }
  if (!Number.isFinite(max)) return "";
  const range = max - min || 1;
  const step = points.length > 1 ? W / (points.length - 1) : 0;
  let d = "";
  points.forEach((raw, i) => {
    const n = Number(raw);
    if (!Number.isFinite(n)) return;
    const x = i * step;
    const y = H - ((n - min) / range) * H;
    d += d.length === 0 ? `M ${x.toFixed(1)} ${y.toFixed(1)}` : ` L ${x.toFixed(1)} ${y.toFixed(1)}`;
  });
  return d;
}

export default {
  /** @param {{ points: number[], color?: string, ariaLabel?: string }} props */
  create(props) {
    const root = document.createElementNS(SVG_NS, "svg");
    root.setAttribute("viewBox", `0 0 ${W} ${H}`);
    root.setAttribute("width", String(W));
    root.setAttribute("height", String(H));
    root.setAttribute("class", "aegis-sparkline");
    root.setAttribute("role", "img");
    root.setAttribute("aria-label", (props && props.ariaLabel) || "Trend");
    root.dataset.component = "sparkline";

    const path = document.createElementNS(SVG_NS, "path");
    path.setAttribute("d", buildPath((props && props.points) || []));
    path.setAttribute("fill", "none");
    path.setAttribute("stroke", (props && props.color) || "var(--color-info)");
    path.setAttribute("stroke-width", "1.5");
    path.setAttribute("stroke-linecap", "round");
    path.setAttribute("stroke-linejoin", "round");
    root.appendChild(path);
    return root;
  },

  update(el, nextProps) {
    if (!el) return;
    const path = el.querySelector("path");
    if (path) path.setAttribute("d", buildPath((nextProps && nextProps.points) || []));
    if (path && nextProps && nextProps.color) path.setAttribute("stroke", nextProps.color);
  },

  destroy(_el) {
    /* no listeners */
  },
};
