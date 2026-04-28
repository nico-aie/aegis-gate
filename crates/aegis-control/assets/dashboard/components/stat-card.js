// Stat card component (D-M2-T2.9).
//
// Markup matches docs/control-plane/enterprise/components.md §"Stat card".
// Single-purpose: a labelled KPI tile with optional status colouring.
// `create()` returns a fresh element; `update(el, props)` mutates an
// existing one without re-creating the node so live updates keep
// focus/animation state.

const STATUSES = new Set(["ok", "warn", "err", "info", "none"]);

function applyValue(el, value) {
  const v = el.querySelector(".aegis-stat__value");
  if (v) v.textContent = value == null || value === "" ? "—" : String(value);
}

function applySubtitle(el, subtitle) {
  const s = el.querySelector(".aegis-stat__sub");
  if (!s) return;
  s.textContent = subtitle ?? "";
  s.hidden = !subtitle;
}

function applyStatus(el, status) {
  const cls = STATUSES.has(status) ? status : "none";
  el.dataset.status = cls;
}

export default {
  /**
   * @param {{
   *   title: string,
   *   value?: string|number,
   *   subtitle?: string,
   *   icon?: string,           // sprite symbol id, e.g. "icon-activity"
   *   status?: 'ok'|'warn'|'err'|'info'|'none',
   *   href?: string
   * }} props
   */
  create(props) {
    const { title, value = "", subtitle = "", icon, status = "none", href } = props || {};
    const root = document.createElement(href ? "a" : "div");
    root.className = "aegis-stat";
    root.setAttribute("role", "group");
    root.setAttribute("aria-label", title || "");
    root.dataset.component = "stat-card";
    if (href) root.setAttribute("href", href);

    const head = document.createElement("div");
    head.className = "aegis-stat__head";

    const h = document.createElement("h3");
    h.textContent = title || "";
    head.appendChild(h);

    if (icon) {
      const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      svg.classList.add("aegis-stat__icon", "aegis-icon");
      svg.setAttribute("aria-hidden", "true");
      const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
      use.setAttribute("href", `#${icon}`);
      svg.appendChild(use);
      head.appendChild(svg);
    }

    root.appendChild(head);

    const valueEl = document.createElement("div");
    valueEl.className = "aegis-stat__value";
    valueEl.setAttribute("aria-live", "polite");
    valueEl.textContent = value === "" ? "—" : String(value);
    root.appendChild(valueEl);

    const sub = document.createElement("div");
    sub.className = "aegis-stat__sub";
    sub.textContent = subtitle;
    sub.hidden = !subtitle;
    root.appendChild(sub);

    applyStatus(root, status);
    return root;
  },

  /** Mutate an existing card without rebuilding it. */
  update(el, props) {
    if (!el || !props) return;
    if (Object.prototype.hasOwnProperty.call(props, "value")) applyValue(el, props.value);
    if (Object.prototype.hasOwnProperty.call(props, "subtitle")) applySubtitle(el, props.subtitle);
    if (Object.prototype.hasOwnProperty.call(props, "status")) applyStatus(el, props.status);
    if (Object.prototype.hasOwnProperty.call(props, "title")) {
      const h = el.querySelector(".aegis-stat__head h3");
      if (h) h.textContent = props.title || "";
      el.setAttribute("aria-label", props.title || "");
    }
  },

  destroy(_el) {
    /* no listeners attached; nothing to clean up */
  },
};
