# Overview & Design Principles

## What we have today

`crates/aegis-control/src/dashboard/mod.rs` ships a single embedded
HTML page rendered from `DASHBOARD_HTML`. It shows three stat tiles
(Status, Events, Blocks) and a live event tail driven by
`/dashboard/sse`. There is no navigation, no charting, no
configuration view, no audit search. The image the user shared (an
"AI-WAF" console with sidebar nav, traffic chart, attack-distribution
pie, top attacker IPs) is the target.

## What we are building

A multi-page operator console served from the same control-plane
listener, with no change to the auth model. From the operator's
perspective the dashboard becomes:

- A persistent **left sidebar** of pages.
- A persistent **top bar** with the WAF identity (name + version),
  global health LED, environment label, signed-in user, sign-out.
- A **content frame** that swaps page contents without a full reload
  (client-side router, history API, no SPA framework).

## Design principles

1. **Latency budget over decoration.** First paint < 300 ms over LAN,
   page swap < 50 ms. No skeletons that animate longer than the data
   takes to arrive. No layout shift after data lands.
2. **Plain HTML, plain CSS, vanilla JS.** No build step. No
   transpiler. The SPA shell is one `index.html` plus a small
   `app.js` that mounts page modules. Each page is a separate
   `pages/<name>.js` file embedded via `include_bytes!`.
3. **Everything is a read until proven otherwise.** Mutating routes
   (`POST`/`PUT`/`DELETE`) require explicit confirm + CSRF token.
   Read views never mutate.
4. **Live, not magic.** SSE for audit events, polling for stats.
   Documented in [`api.md`](api.md). No secret WebSocket multiplex.
5. **Diff before apply.** Every config edit shows the unified diff
   and the validator outcome before the operator can submit.
6. **Disclosure over density.** Top-level pages show <= 6 widgets;
   detail panes open in a side drawer. Anything denser belongs in
   Grafana.
7. **No telemetry leaks.** No third-party trackers. Charting library
   is loaded from a pinned CDN with SRI; offline mode (assets bundled
   in the binary) documented in [`assets.md`](assets.md).
8. **Accessibility is non-negotiable.** Keyboard-only navigation,
   visible focus rings, AA contrast minimum. Spec in
   [`accessibility.md`](accessibility.md).

## What this work does NOT change

- The control-plane listener address (`cfg.admin.bind`).
- `/dashboard/sse` event format — same `AuditEvent` JSON.
- `/api/config`, `/api/rules`, `/api/audit*`, `/healthz/*`, `/metrics`
  contracts.
- The auth flow in [`../dashboard-auth.md`](../dashboard-auth.md).
- The deferral of RBAC and multi-tenancy.

## What this work DOES introduce

- New SPA shell at `/dashboard/` (replacing the current single-file).
- Per-page asset bundles served at `/dashboard/assets/*` (cacheable,
  embedded in the binary).
- A handful of new read-only endpoints under `/api/` (see
  [`api.md`](api.md)) — for example `/api/stats`, `/api/upstreams`,
  `/api/cluster`, `/api/blacklist`, `/api/whitelist`. None of these
  break existing behaviour.
- A new `crates/aegis-control/src/dashboard/assets.rs` module for
  embedding bytes, plus per-page Rust handlers under
  `crates/aegis-control/src/dashboard/pages/*.rs` for any page that
  needs a server-side data shape distinct from existing endpoints.

## Backward-compat plan

The existing `DASHBOARD_HTML` constant in
`crates/aegis-control/src/dashboard/mod.rs` remains exported for one
release as `DASHBOARD_HTML_V1` so any external script that scrapes
the shell continues to work. The new shell is exposed at the same
URL `/dashboard/` and opt-out is via a new
`admin.dashboard.legacy_shell: true` config knob (defaults to
`false`). Removed in the release after.

## Success criteria

- All ten pages listed in [`README.md`](README.md) load, navigate,
  and render real data — not just mocks.
- Lighthouse desktop score >= 95 (perf, a11y, best-practices) on a
  fresh load against a local instance.
- p99 page-render latency < 200 ms measured client-side.
- No new clippy warnings in `aegis-control`.
- Existing 1,477-test suite still green; new tests cover each new
  endpoint and the asset embedder.
