// Drawer component (D-M3-T3.1).
//
// Right-anchored 480px overlay per docs/dashboard-enterprise/components.md.
// Trapped focus, ESC closes, click-out closes (unless `dismissable: false`).
// Renders body content as a string, a Node, or a JSON-serialisable object
// (objects render as a pretty-printed `<pre>`). The Live Feed page uses
// the JSON-object branch to display the full audit event payload.
//
// API:
//   open(props): returns a `state` handle with .close() and .update(next)
//   props: { title, body, footer?, dismissable?, onClose? }

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), input:not([disabled]), ' +
  'select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

function clearChildren(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
}

function asNode(body) {
  if (body == null) return document.createTextNode("");
  if (body instanceof Node) return body;
  if (typeof body === "string") {
    const p = document.createElement("p");
    p.textContent = body;
    return p;
  }
  // Object/array: pretty-print into a <pre>.
  const pre = document.createElement("pre");
  pre.className = "aegis-drawer-json";
  try {
    pre.textContent = JSON.stringify(body, null, 2);
  } catch (_) {
    pre.textContent = String(body);
  }
  return pre;
}

function renderShell(props) {
  const root = document.createElement("div");
  root.className = "aegis-drawer-overlay";
  root.dataset.component = "drawer";

  const dialog = document.createElement("div");
  dialog.className = "aegis-drawer";
  dialog.setAttribute("role", "dialog");
  dialog.setAttribute("aria-modal", "true");
  dialog.tabIndex = -1;
  if (props.title) dialog.setAttribute("aria-label", props.title);

  const header = document.createElement("header");
  header.className = "aegis-drawer-header";
  const titleEl = document.createElement("h2");
  titleEl.textContent = props.title || "";
  header.appendChild(titleEl);

  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "aegis-drawer-close";
  closeBtn.setAttribute("aria-label", "Close drawer");
  closeBtn.textContent = "×";
  header.appendChild(closeBtn);

  dialog.appendChild(header);

  const body = document.createElement("div");
  body.className = "aegis-drawer-body";
  body.appendChild(asNode(props.body));
  dialog.appendChild(body);

  if (props.footer != null) {
    const footer = document.createElement("footer");
    footer.className = "aegis-drawer-footer";
    footer.appendChild(asNode(props.footer));
    dialog.appendChild(footer);
  }

  root.appendChild(dialog);
  return { root, dialog, body, closeBtn };
}

/** Open a drawer. Returns a state handle with `close()` and `update()`. */
export function open(props) {
  const config = props || {};
  const dismissable = config.dismissable !== false;
  const restoreFocus = document.activeElement;
  const elements = renderShell(config);
  document.body.appendChild(elements.root);

  function focusFirst() {
    const target =
      elements.dialog.querySelector(FOCUSABLE_SELECTOR) || elements.dialog;
    if (target && typeof target.focus === "function") target.focus();
  }
  setTimeout(focusFirst, 0);

  function trapTab(e) {
    if (e.key !== "Tab") return;
    const focusables = Array.from(
      elements.dialog.querySelectorAll(FOCUSABLE_SELECTOR)
    ).filter((el) => !el.hasAttribute("disabled"));
    if (focusables.length === 0) {
      e.preventDefault();
      elements.dialog.focus();
      return;
    }
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }

  function onKeydown(e) {
    if (e.key === "Escape" && dismissable) {
      e.preventDefault();
      close();
    } else {
      trapTab(e);
    }
  }

  function onOverlayClick(e) {
    if (!dismissable) return;
    if (e.target === elements.root) close();
  }

  function close() {
    document.removeEventListener("keydown", onKeydown);
    elements.root.removeEventListener("click", onOverlayClick);
    elements.closeBtn.removeEventListener("click", close);
    elements.root.remove();
    if (restoreFocus && typeof restoreFocus.focus === "function") {
      restoreFocus.focus();
    }
    if (typeof config.onClose === "function") config.onClose();
  }

  document.addEventListener("keydown", onKeydown);
  elements.root.addEventListener("click", onOverlayClick);
  elements.closeBtn.addEventListener("click", close);

  return {
    close,
    update(nextProps) {
      const next = nextProps || {};
      if (next.title !== undefined) {
        const h = elements.dialog.querySelector(".aegis-drawer-header h2");
        if (h) h.textContent = next.title || "";
      }
      if (next.body !== undefined) {
        clearChildren(elements.body);
        elements.body.appendChild(asNode(next.body));
      }
    },
  };
}

export default { open };
