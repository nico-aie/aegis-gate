# Milestone 0 — Foundations

> **Status:** Queued — M0 detail. Track does not start until Phase B closes.
>
> See [`README.md`](../../README.md) for the track status board.

> **Goal.** Replace the current chrome (sidebar, topbar,
> status bar, command palette) and the 14 components with
> the token set + grammar in
> [`design-system.md`](./design-system.md). After M0 lands,
> every page milestone (M1..M10) is *page work*, not chrome
> work.
>
> **Effort.** ~5 days serial.
>
> **Blocks.** Every page milestone.

## Why M0 first

The current chrome leaks into every page module. The status
bar sometimes hosts the connection pill, sometimes carries
load-mode + verbosity (added in P7 + P8 as drop-ins). The
sidebar nav uses ad-hoc CSS that no other component shares.
Every page that imports a component picks up legacy spacing.

Refreshing 11 pages on top of legacy chrome means refreshing
the chrome 11 times. Refresh once, sequence the pages.

## Scope

### In

| Surface | What changes |
|---|---|
| Tokens | Replace the `aegis.css` `:root` block with the OKLCH set from `design-system.md` |
| Sidebar | Re-spacing, route-active state, collapse/expand toggle |
| Topbar | Remove the cluster of one-off buttons; route-title + breadcrumbs + command-palette trigger only |
| Status bar | Three slots only: connection pill, load-mode pill, verbosity pill. Audit-chain pill folds into the chain page. |
| Command palette | Rebuild `cmdk.js` from stub. Cmd+K opens, fuzzy-matches on (a) sidebar routes, (b) admin actions |
| Components | Refresh per `design-system.md` § 8 — `stat-card`, `table`, `drawer`, `cmdk` get rebuilt; the rest get token migrations |
| Theme switching | Move from JS `theme.js` swap to CSS-variable-driven `data-theme` |
| Bundle | Total raw < 700 KB (already enforced). Per-page < 32 KB (already enforced). M0 must not regress headroom by more than 10 %. |

### Out

| Surface | Why not |
|---|---|
| Per-page redesign | Each page is its own milestone (M1..M10) |
| New i18n strings | Translate as pages land |
| Chart vendor decision | Stays SVG-only (D-M2-T2.9 deferral upheld) — covered in M5 if it changes |
| Login page | Blocked on F-T1 (`POST /admin/login` route). When that lands, login UX is M0.5 — small enough to fold into M0's tail or a follow-up commit |

## Work units

### M0-W1 — Token migration (~1 day)

- Replace the `:root` block in
  `crates/aegis-control/assets/dashboard/aegis.css` with the
  OKLCH token set.
- Add `[data-theme="dark"]` block with the dark surface +
  text deltas.
- Migrate every legacy `--aegis-*` reference inside
  `aegis.css` and the 11 page modules to the new names.
- Delete `theme.js`. Replace with a minimal inline script in
  `index.html`'s `<head>`:
  ```js
  (function(){
    const v = localStorage.getItem("aegis_theme")
            || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    document.documentElement.dataset.theme = v;
  })();
  ```
- Acceptance: every existing page still renders without
  visual regression *worse than* what we already ship. Some
  pages get worse-looking — that's fine, M1+ fixes them.

### M0-W2 — Chrome rebuild (~1.5 days)

- Sidebar redesign per `design-system.md` § 7. Route-active
  uses `--signal-accent` border-left + bold weight, no
  background fill.
- Topbar reduced to: page title, breadcrumbs (when nested
  drawer is open), command-palette trigger,
  account-menu dropdown.
- Status bar three-slot: connection (left), load-mode
  (center), verbosity (right). Audit-chain pill removed —
  surfaces on the audit page itself instead.
- Acceptance: keyboard tab order goes sidebar → topbar →
  content → status; ESC always closes the drawer-most
  surface.

### M0-W3 — Component refresh (~1.5 days)

- Refresh `stat-card.js` per `design-system.md` § 8: feature
  numerals, sparkline slot, trend pill that mirrors the
  signal palette.
- Rebuild `table.js`: sticky header, virtual rows on >500
  entries, sortable column headers via `aria-sort`,
  arrow-key row navigation, `Enter` opens the drawer.
- Rebuild `drawer.js`: right-side, max-width `min(560px,
  60vw)`, focus trap, ESC + outside-click close, deep-link
  via `?drawer=<id>` query param.
- Refresh remaining components: `badge`, `banner`,
  `confirm`, `modal`, `donut`, `line-chart`, `sparkline`,
  `skeleton`, `toast` — all token migrations + visual
  cleanup. No behavioural change.
- Acceptance: every component test in
  `tests/dashboard_polish.rs` passes; new component
  structure tests added for `stat-card`, `table`, `drawer`.

### M0-W4 — Command palette (~1 day)

- Rebuild `cmdk.js` from the stub. Open with Cmd+K /
  Ctrl+K. Closes on ESC. Fuzzy-matches against (a) sidebar
  routes, (b) hard-coded admin actions ("Pin load mode to
  Critical", "Reset risk for IP…", "Set verbosity to
  silent"). Each action confirms in `confirm.js` before
  firing the audit-mutated PUT.
- Acceptance: search index covers every route + every P1–P8
  admin action. Empty-state copy when no match.
- New k6 / Playwright test: open palette → type "load" →
  hit Enter → confirm → load mode flips to elevated.
  Optional: defer to M10's settings test if Playwright
  isn't wired yet.

## Acceptance — milestone

- `cargo test -p aegis-control --lib dashboard` passes.
- `cargo test --test dashboard_polish` passes.
- `cargo clippy --workspace -- -D warnings` clean.
- Per-page bundle < 32 KB raw (no page module gets fatter
  than its current size).
- Total bundle < 700 KB raw.
- Cmd+K flow works on Chrome, Firefox, Safari (manual
  smoke).
- Both themes look intentional under the screenshot review
  (workflow stage 4) at 1280 / 1440 / 1920.
- An updated `docs/control-plane/enterprise/theme.md` and
  `components.md` reflect the M0 outcomes (these docs are
  the contract — they must move when the code does).

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Token migration touches every page; merge conflicts on parallel page work | high | M0 must be a single PR, then rebase any in-flight page work on top |
| Component rebuild breaks an existing page's data binding | medium | Per-page structure tests in `tests/dashboard_polish.rs` already enforce shape; expand them in M0-W3 |
| Cmd+K shortcut conflicts with browser default (Chrome's address bar focus) | known | Use both Cmd+K and `/` as triggers; document; allow disable via setting |
| Theme switch flickers on first paint | known | The inline `<head>` script in M0-W1 sets `data-theme` *before* CSS loads, eliminating FOUC |

## Hand-off to M1

When M0 ships, leave a "Foundation tokens / chrome / cmdk
locked" comment block at the top of `aegis.css` with the
M0 PR SHA. Page milestones reference it instead of asking
"is this still the canonical token set?".
