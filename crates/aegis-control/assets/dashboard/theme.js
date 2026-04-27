// Aegis WAF dashboard — theme bootstrap (D-M1-T1.4).
//
// Loaded as a CLASSIC script (no `type=module`) in <head> before the
// stylesheet so the data-theme attribute is set on <html> before
// first paint, eliminating flash-of-wrong-theme. ES `import`/`export`
// would force module semantics (deferred) and reintroduce the flash.
//
// Persistence key documented in docs/dashboard-enterprise/theme.md
// §"Theme toggle". Three preferences: "light" | "dark" | "system".
// Default = "dark" (matches the screenshot reference).
//
// Also publishes window.AegisTheme.chart so chart pages (D-M2+) read
// the design-token palette without re-parsing CSS variables.

(function () {
  var KEY = "aegis.dashboard.theme";

  function readPref() {
    try {
      var raw = window.localStorage.getItem(KEY);
      if (raw === "light" || raw === "dark" || raw === "system") return raw;
    } catch (_) { /* private mode / disabled */ }
    return "dark";
  }

  function resolve(pref) {
    if (pref !== "system") return pref;
    if (window.matchMedia &&
        window.matchMedia("(prefers-color-scheme: light)").matches) {
      return "light";
    }
    return "dark";
  }

  function apply(pref) {
    var resolved = resolve(pref);
    document.documentElement.setAttribute("data-theme", resolved);
    document.documentElement.dataset.themePref = pref;
  }

  // Initial bootstrap — run synchronously before paint.
  apply(readPref());

  // React to OS-level theme changes when the user picked "system".
  if (window.matchMedia) {
    var mq = window.matchMedia("(prefers-color-scheme: light)");
    var onChange = function () {
      var pref = document.documentElement.dataset.themePref || "dark";
      if (pref === "system") apply(pref);
    };
    if (mq.addEventListener) mq.addEventListener("change", onChange);
    else if (mq.addListener) mq.addListener(onChange);  // older browsers
  }

  window.AegisTheme = {
    /** Chart.js palette — see docs/dashboard-enterprise/theme.md §charts. */
    chart: {
      line: {
        traffic: "var(--color-info)",
        blocked: "var(--color-err)"
      },
      area: { fill: "rgba(96, 165, 250, .12)" },
      pie: {
        recon:          "var(--color-violet)",
        ssrf:           "var(--color-violet)",
        ssti:           "var(--color-pink)",
        path_traversal: "var(--color-warn)",
        cmdi:           "var(--color-err)",
        lfi:            "var(--color-teal)",
        honeypot:       "var(--color-err)"
      },
      grid: "var(--border-subtle)",
      text: "var(--text-secondary)"
    },

    /** Read the current preference ("light" | "dark" | "system"). */
    getPref: function () {
      return document.documentElement.dataset.themePref || "dark";
    },

    /** Set a preference, persist it, and apply it. */
    setTheme: function (next) {
      if (next !== "light" && next !== "dark" && next !== "system") return;
      try { window.localStorage.setItem(KEY, next); } catch (_) {}
      apply(next);
    },

    /** Cycle dark → light → system → dark. Returns the new preference. */
    cycle: function () {
      var pref = this.getPref();
      var next = pref === "dark" ? "light"
               : pref === "light" ? "system"
               : "dark";
      this.setTheme(next);
      return next;
    }
  };
})();
