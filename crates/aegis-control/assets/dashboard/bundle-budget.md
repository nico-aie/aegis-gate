# Dashboard bundle budget

The Aegis WAF Console ships as a single pre-compiled `app.js` plus the
React UMD bundles, a CSS file, a small HTML shell, and `i18n.json`. Two
tests in `crates/aegis-control/tests/dashboard_polish.rs` gate the size:

| Test | What it caps | Constant |
|---|---|---|
| `app_js_under_per_bundle_budget` | `app.js` alone | `APP_JS_BUDGET` |
| `bundle_under_documented_budget` | all six assets, raw bytes | `RAW_BUDGET_BYTES` |

## Why `app.js` is large and not code-split

`build.sh` runs esbuild as a **JSX transform, not a bundler**. Every
page and widget is concatenated into one file because the design wires
cross-module globals via `Object.assign(window, { PageX, … })` and the
hash-router looks those names up at runtime. That rules out two of the
usual size levers:

- **No code-splitting / lazy routes** — the router needs every page
  symbol present on `window` at mount.
- **No identifier minification** (`--minify-identifiers` is off) —
  renaming `PageX` → `a` would break the router lookup.

What esbuild *does* apply: `--minify-whitespace` + `--minify-syntax`.
So the bundle is already minified as far as is safe; remaining size is
genuine feature surface, not un-minified slack or dependency bloat.

## Bump policy

The budget tracks real growth with modest headroom. **Bump the
constant + add a dated line below when a real feature lands** — never
silently raise it to dodge a red test, and never add a heavyweight
dependency (a new React-tier lib) without calling it out here.

If a future bump is driven by a *dependency* rather than feature code,
that's the signal to reconsider code-splitting or trimming the
dependency instead of bumping.

## History

| Date | `APP_JS_BUDGET` | `RAW_BUDGET_BYTES` | Driver |
|---|---|---|---|
| 2026-05-10 | 444 KB | 624 KB | Strike-Block PUT surface + GateExplain strips |
| 2026-06-01 | 540 KB | 720 KB | Cumulative growth since 2026-05-10: AI `confidence_threshold` tuning row, cluster config-plane version card + Scaling page, multi-node metrics aggregation UI, and the R2-009 feature-off AI-row polish. Measured `app.js` 506 KB / raw 682 KB; budgets set ~6 % above actual to leave headroom without masking a dependency add. |
