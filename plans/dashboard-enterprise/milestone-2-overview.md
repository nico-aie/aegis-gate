# Milestone D-M2 — Overview Page

**Goal.** Wire the Overview page to real data: 4 stat tiles,
realtime traffic line chart, attack-distribution donut, top
attacker IPs table.

**Crate touched.** `aegis-control`.
**Verification.** `cargo test -p aegis-control && cargo clippy -p aegis-control -- -D warnings`.

**Reference.**
[`docs/control-plane/enterprise/pages/overview.md`](../../docs/control-plane/enterprise/pages/overview.md),
[`docs/control-plane/enterprise/api.md`](../../docs/control-plane/enterprise/api.md).

---

## New endpoints

| Method | Path | Owner |
|--------|------|-------|
| GET | `/api/about` | `src/api/about.rs` |
| GET | `/api/stats?window=` | `src/api/stats.rs` |
| GET | `/api/stats/timeseries?window=&step=` | `src/api/stats.rs` |
| GET | `/api/upstreams/summary` | `src/api/upstreams.rs` |
| GET | `/api/attacks/distribution?window=` | `src/api/attacks.rs` |
| GET | `/api/attacks/top?limit=&window=` | `src/api/attacks.rs` |

All endpoints are read-only. All return `application/json` with
`Cache-Control: private, max-age=1` for `/api/stats*` and
`max-age=10` for distribution/top.

## Tasks

### D-M2-T2.1 `/api/stats`

- File: `src/api/stats.rs`
- Backed by the existing `MetricsRegistry` snapshot. Adds a
  small in-process aggregator that maintains:
  - rolling 10s request count
  - rolling block count + ratio
  - active_threats counter (number of distinct client_ips with
    risk_score >= configured threshold over the last 5m).
- Aggregator updates from the audit bus subscriber the same way
  the SSE handler does; no extra hot-path cost.
- Cache layer: 1s `Mutex<Option<(Instant, StatsResponse)>>`.
- Test: emit a fixed sequence of audit events; assert
  `block_rate_pct` and `active_threats` match expected.

### D-M2-T2.2 `/api/stats/timeseries`

- File: `src/api/stats.rs`
- Maintains a circular buffer of `(window/step)` buckets. On
  request, returns the requested window snapshot.
- Window options: `1m`, `5m`, `15m`, `1h`. Step capped at
  `window / 60` to keep payload bounded.
- Test: feed events, assert returned points sum to expected
  totals.

### D-M2-T2.3 `/api/upstreams/summary`

- File: `src/api/upstreams.rs`
- Reads upstream pool health from the
  `cluster::pool_health_snapshot()` already exposed by
  `aegis-proxy`. (The control plane already imports
  `aegis-proxy` per `Cargo.toml` for cluster membership.)
- Returns `{ state, healthy_members, total_members, pools: [{name, healthy, total}] }`.
- Test: with a mock pool snapshot, assert correct rollup.

### D-M2-T2.4 `/api/attacks/distribution`

- File: `src/api/attacks.rs`
- Maintains a per-detector counter in a 15m sliding window
  (driven by audit bus, indexed by `rule_id` prefix or
  `class=Detection` + a `detector` field on the audit event).
- Confirm the audit event already carries enough info; if not,
  add a `detector: Option<String>` to `AuditEvent` in
  `aegis-core` (this is the **only** change outside
  `aegis-control` and is opt-in via `serde(default)`).
- Test: feed mixed-detector events, assert percentages.

### D-M2-T2.5 `/api/attacks/top`

- File: `src/api/attacks.rs`
- Top-N attackers ranked by detection count over the requested
  window.
- Identifier picks `client_ip` if present and not RFC 1918
  bounce, otherwise `fp:<ja4>` from the existing fingerprint
  field.
- Returns `[{ identifier, hits, categories: [str], risk, last_seen }]`.
- Test: feed events with mixed IP/fingerprint, assert top
  selection.

### D-M2-T2.6 `/api/about`

- File: `src/api/about.rs`
- Returns `{ name: "Aegis WAF", version: env!("CARGO_PKG_VERSION"),
  build_sha: option_env!("AEGIS_BUILD_SHA"),
  environment: cfg.admin.environment }`.
- Test: response shape stable.

### D-M2-T2.7 Overview page module

- File: `assets/dashboard/pages/overview.js`
- Mounts the four stat-card components, the line chart, the
  donut, and the top-IPs table.
- Polls each endpoint at the cadence in
  [`docs/control-plane/enterprise/pages/overview.md`](../../docs/control-plane/enterprise/pages/overview.md).
- Uses `requestAnimationFrame` for chart updates; pauses polling
  when `document.visibilityState !== "visible"`.
- Test: a Rust integration test boots the server with seeded
  audit events, fetches `/api/stats`, asserts shape; a separate
  test asserts `/api/attacks/distribution` percentages sum to
  100.

### D-M2-T2.8 Wire SSE status pill

- File: `assets/dashboard/app.js` (status bar from M1).
- Connects to `/dashboard/sse` once at boot, renders Connected /
  Reconnecting / Offline pill in the status bar.
- Test: not strictly Rust-testable; covered by an axe-driven
  smoke that asserts the pill text changes after a server-side
  emit.

### D-M2-T2.9 Stat-card and line-chart components

- Files: `assets/dashboard/components/{stat-card,line-chart,donut,sparkline,table}.js`
- Replace the M1 stubs with the real implementations described
  in [`docs/control-plane/enterprise/components.md`](../../docs/control-plane/enterprise/components.md).
- Pull Chart.js from `/dashboard/assets/chart.umd.min.js` (vendored).
- SRI hash assertion test as described in
  [`docs/control-plane/enterprise/security.md`](../../docs/control-plane/enterprise/security.md).

## Exit gate

- `/dashboard/overview` matches the AI-WAF reference
  screenshot, populated with real data from a running server.
- `cargo test -p aegis-control` green; new tests for each
  endpoint pass.
- Lighthouse perf ≥ 95 on a fresh dashboard load.
- Bundle delta ≤ +90KB gzipped (Chart.js is the bulk).

## Implement-Progress.md update

```
## Last Completed
- Task: D-M2 Overview page wired to real data
- Crate: aegis-control
- Files changed: <list>
- Status: DONE

## Next Task
- Task: D-M3-T3.1 Live Feed page (drawer + filters)
- Plan: plans/dashboard-enterprise/milestone-3-operator-views.md
```
