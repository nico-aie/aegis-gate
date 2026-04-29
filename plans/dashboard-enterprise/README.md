# Enterprise Dashboard — Task Plan

> **Status:** Closed — D-M1..D-M6 shipped — enterprise SPA bundled into the binary. Reference only.
>
> See [`README.md`](../README.md) for the track status board.

> **Read first:**
> 1. [`../../README.md`](../../README.md)
> 2. [`../../Implement-Progress.md`](../../Implement-Progress.md)
> 3. [`../plan.md`](../plan.md) — assistant guide (session startup,
>    progress protocol, execution rules)
> 4. [`../control.md`](../control.md) — current control-plane plan
>    (this track only touches `aegis-control`)
> 5. [`../../docs/control-plane/enterprise/README.md`](../../docs/control-plane/enterprise/README.md)
>    — design spec for this work
>
> This plan is the **execution** companion to the design under
> `docs/control-plane/enterprise/`. The design tells us *what* to build;
> this plan slices the work into shippable milestones.

## Mission

Replace the current single-file dashboard shell with a multi-page
operator console matching the AI-WAF reference screenshot, without
breaking any existing endpoint or auth contract. Single crate
touched: `aegis-control`. No new external deps in `Cargo.toml`.

## Crate scope

- **In scope:** `crates/aegis-control/src/dashboard/**`,
  `crates/aegis-control/src/api/**`,
  `crates/aegis-control/src/server.rs` (route registration only),
  new `crates/aegis-control/assets/dashboard/**`.
- **Out of scope:** `aegis-proxy`, `aegis-security`, `aegis-core`,
  `aegis-bin`. The auth middleware is unchanged. Audit chain
  format is unchanged. No new compliance profiles.

## Constraints

- No new top-level dependency in any `Cargo.toml`. (Chart.js is
  vendored as bytes, not a Rust crate.)
- No SPA build step. No Node.js. No bundler.
- Tests stay under `cargo test -p aegis-control`. All 1,477
  workspace tests must remain green.
- Clippy clean: `cargo clippy -p aegis-control -- -D warnings`.
- Existing API routes unchanged; new routes are additive.

## Milestones

| # | File | Outcome | Tests added (approx) |
|---|------|---------|----------------------|
| M1 | [`milestone-1-shell.md`](milestone-1-shell.md) | SPA shell, asset embedder, sidebar + top bar, router | 20 |
| M2 | [`milestone-2-overview.md`](milestone-2-overview.md) | Overview page wired to new `/api/stats*` and `/api/attacks*` | 24 |
| M3 | [`milestone-3-operator-views.md`](milestone-3-operator-views.md) | Live Feed, Attack Events, Audit Log, Analytics | 30 |
| M4 | [`milestone-4-config-management.md`](milestone-4-config-management.md) | Rule Manager, Tier Config, Blacklist, Whitelist, Settings | 36 |
| M5 | [`milestone-5-tracking.md`](milestone-5-tracking.md) | Tracking page (SLO, upstreams, cluster, certs, GitOps, alerts) | 22 |
| M6 | [`milestone-6-polish.md`](milestone-6-polish.md) | Accessibility, security headers, perf budget, docs touch-up, legacy shell removal | 18 |

Each milestone is independently shippable. Operators can use the
SPA after M1 (shell-only with placeholder pages) and gain real
value from M2 onward.

## Definition of Done (overall)

- All 11 sidebar pages load, navigate, and render real data.
- `cargo test -p aegis-control` green; full workspace test suite
  still 1,477+ passing.
- `cargo clippy --workspace -- -D warnings` clean.
- Lighthouse desktop score ≥ 95 on perf/a11y/best-practices.
- Asset bundle ≤ 220KB gzipped total.
- `Implement-Progress.md` updated at each milestone exit.
- New entries in `docs/control-plane/enterprise/` referenced from
  `docs/control-plane/dashboard.md` and `docs/README.md`.

## Cross-references

- Design spec — [`docs/control-plane/enterprise/`](../../docs/control-plane/enterprise/)
- Existing dashboard contract — [`docs/control-plane/dashboard.md`](../../docs/control-plane/dashboard.md)
- Auth flow (unchanged) — [`docs/control-plane/dashboard-auth.md`](../../docs/control-plane/dashboard-auth.md)
- Audit chain — [`docs/observability/audit-logging.md`](../../docs/observability/audit-logging.md)
- SLO / SLI — [`docs/observability/slo-sli-alerting.md`](../../docs/observability/slo-sli-alerting.md)
- Observability — [`docs/observability/prometheus-otel.md`](../../docs/observability/prometheus-otel.md)

## Progress protocol

Per [`../plan.md`](../plan.md) §0.3, after each task:

1. Overwrite `Implement-Progress.md` (never append).
2. Move the task into the Completed Tasks Log.
3. Set `## Next Task` to the next item from the milestone in
   progress.

Task IDs follow the pattern `D-M{n}-T{x}.{y}` where `D` denotes
the dashboard track, distinct from the `M{n}-T{x}.{y}` IDs used
by milestones M1/M2/M3 of the original implementation.
