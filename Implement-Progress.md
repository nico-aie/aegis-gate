# Aegis-Gate Implementation Progress

> **How to maintain this file.** It is a *living snapshot*, not a
> changelog. The Completed Tasks Log at the bottom is the only
> append-only section. Every other section is overwritten in place.
> See [`plans/plan.md`](./plans/plan.md#03-progress-file-protocol-strict)
> §0.3 for the protocol; the rules in short:
>
> - **Last Completed** holds the *current* task in full detail.
> - **Recent History** holds the previous 5 tasks in 1–2 lines each.
> - **Next Task** holds the immediate next item.
> - All other sections (tracks, carry-overs, future phases) are
>   durable summaries — update only when the underlying state
>   changes, not on every task.
> - Append a row to **Completed Tasks Log** when a task closes.
>
> **For at-a-glance track priority** see
> [`plans/README.md`](./plans/README.md). For per-doc Implemented /
> Partial / Designed-only status see
> [`plans/implementation-matrix.md`](./plans/implementation-matrix.md).

---

## Status (snapshot)

- **As of:** 2026-04-29
- **Workspace tests:** 2,173 default-feature (held steady —
  the Carry-over A fix updated the existing
  `run_binds_and_serves_200` test to use a mock upstream rather
  than asserting on the stub `OK\n` body, no net new tests).
- **Clippy:** clean across the workspace **lib + bin** targets
  on default; per-feature combos clean.
- **Active track:** Phase B — production-readiness, **B5
  CLOSED**; pre-B6 carry-overs in flight
  ([`plans/phase-b/`](./plans/phase-b/README.md))
- **Next task:** Carry-over B — rate-limit response code
  alignment (gateway returns 403/strike, `tests/load/rate-limit.js`
  asserts on 429 — pick one and align both)
- **Latest activity:** Carry-over A closed — data plane now
  forwards Allow-branch traffic through
  `crate::upstream::forward::forward()` against a real pool
  member. Live k6 against WAF → `aegis-httpbin` shows 31.5 k
  RPS / 504 µs median allow-path / 3.66 ms full-hop p95 — the
  ~2.5 ms gap vs the stub run is real upstream
  round-trip cost, not a regression.

---

## Last Completed

**Task:** **Carry-over A — data-plane Allow forwarding
wired through `upstream::forward::forward()`.** Closed the
top-priority gap surfaced by the 2026-04-29 perf re-run.

**Outcome.** The live data-plane Allow branch no longer
returns the synthetic `Response::new(Full::new(Bytes::from("OK\n")))`
that the perf benchmark exposed. `handle_data_request` is
now `async`, takes an `Arc<ProxyContext>` thread through
the `accept_loop`, and on Allow runs the same wire as
`proxy::handle_request`: route resolve → circuit-breaker
gate → pool pick → body collect → forward. Connect
failure surfaces as 502; no-route → 404; circuit open →
503; no-healthy-member → 502.

**Decision recap (placeholder pipeline on ProxyContext).**
`ProxyContext::build` requires a `SecurityPipeline` that
the upstream forward path doesn't actually use. Rather
than refactor `ProxyContext` today, we pass
`aegis_security::NoopPipeline` and leave the field as a
seam — the parallel "live" pipeline (detectors / mask /
risk threaded directly into `handle_data_request`) and the
"abstract" one (`pipeline.inbound()` reachable from
`proxy::handle_request`) remain unconverged. That
convergence is a separate task.

**Decision recap (test fixture vs prod posture).** The
existing `run_binds_and_serves_200` test asserted on the
stub `OK\n` body and broke as soon as the Allow branch
went through real TCP. The fix updates the test to spin
up a tokio-backed mock upstream (`spawn_mock_upstream`)
returning `200 upstream-ok`, and points the route table
at it. Same end-to-end shape, no stub asserts.

**Files changed.**
- `crates/aegis-proxy/src/lib.rs` —
  - `run()` builds an `Arc<ProxyContext>` once after the
    detector wiring and clones it into each data-listener
    `accept_loop`.
  - `accept_loop` signature gained
    `upstream_ctx: Arc<crate::proxy::ProxyContext>`.
  - `handle_data_request` is now `async fn`, gained the
    same `&Arc<ProxyContext>` parameter, and `await`s the
    Allow branch through a new
    `forward_allow_to_upstream` helper.
  - `forward_allow_to_upstream` (~80 lines) does route
    resolve → circuit-breaker gate → pool pick → body
    collect → `forward::forward(...)`. Mirrors the logic
    in `proxy::handle_request` so the two paths converge
    on identical wire behaviour.
  - `run_binds_and_serves_200` rewritten to mount a real
    `spawn_mock_upstream` and assert the upstream's 200
    arrives back via WAF.

**Verification.**
- `cargo build -p aegis-proxy` clean.
- `cargo test --workspace` (default features) → **2,173
  passed** (held steady — one test rewritten in place).
- `cargo clippy --workspace --lib --bins -- -D warnings`
  → clean.
- `cargo run -p aegis-bin -- validate --config
  config/waf.dev.yaml` → `config OK`.
- **Live smoke**: WAF on `:8080` → `aegis-httpbin` on
  `:8081`. `curl /get` returns httpbin's JSON echo, with
  `Host: 127.0.0.1:8081` (rewritten) and the original
  `X-Aegis-Test` header preserved. Proves the wire works
  end-to-end.
- **Live k6**: 20 VUs × 10 s against the same chain →
  31 491 RPS, allow-path median 504 µs, full-hop p95
  3.66 ms. Log:
  [`tests/results/baseline-allow-forwarded-2026-04-29.log`](./tests/results/baseline-allow-forwarded-2026-04-29.log).
  The README at
  [`tests/results/README-2026-04-29.md`](./tests/results/README-2026-04-29.md)
  documents the closure.

---

## Earlier Last Completed (B5-T2)

The B5-T2 narrative below was the previous entry; kept
verbatim for the protocol's "5-task Recent History" until
the next rotation absorbs it.

**Task:** **B5-T2 — benchmark mode (core slice). Closes
milestone B5.** Followed by a fresh whole-system perf run
(documented in
[`tests/results/README-2026-04-29.md`](./tests/results/README-2026-04-29.md))
that exposed two real carry-overs.

**Outcome (B5-T2).** `aegis-proxy::benchmark` ships
`BenchmarkConfig`, `StageTimings`, the `X-Aegis-*` header
serialiser, and the `proxy::handle_request` wiring. When
`ProxyContext.benchmark.enabled = true`, every response
carries `X-Aegis-Stage-Total-Us`, `X-Aegis-Stage-Route-Us`,
`X-Aegis-Stage-Upstream-Us`, `X-Aegis-Tier`, and
`X-Aegis-Decision`. Rule IDs are gated behind a separate
`expose_rule_ids` flag (off by default) so production
deployments don't leak policy structure to clients. When
the master switch is off, the data plane pays one
`bool::then` check per request; no allocation, no header
work.

**Decision recap (core slice, not the full plan).**
[`plans/benchmark-mode.md`](./plans/benchmark-mode.md)
specs B-T1..B-T6 (IP allowlist, HMAC-token gating,
per-detector timing, dashboard panel, criterion bench
gate). Today's slice ships the data-plane plumbing —
header builder + timing capture + on/off switch — and
defers the rest. The carry-overs in `plans/phase-b/README.md`
§ B5 record what's open.

**Decision recap (1 KiB header payload cap).** The header
serialiser tracks a 1024-byte budget per response and drops
fields that would exceed it. Most reverse proxies (nginx
default 8 KiB, haproxy 16 KiB) silently reject larger
header sets; capping in-process makes a misconfigured
benchmark visible at the integration test level rather
than in production.

**Decision recap (ProxyContext.benchmark default off).**
`ProxyContext::build` sets `benchmark: BenchmarkConfig::off()`.
Operators flip the bool through whatever boot-site wires
the runtime config (the `WafConfig` schema + dashboard
toggle land with the deferred plan).

**Files changed (B5-T2).**
- `crates/aegis-proxy/src/lib.rs` — declared
  `pub mod benchmark;`.
- `crates/aegis-proxy/src/benchmark.rs` — **new**, ~360
  lines. `BenchmarkConfig`, `StageTimings`,
  `Stopwatch`, `format_us`, `sanitise_ascii`,
  `build_aegis_headers` (with budget tracking),
  `stamp_headers`, header-name constants
  (`hdr::TOTAL_US` / `ROUTE_US` / `SECURITY_US` /
  `UPSTREAM_US` / `TIER` / `DECISION` / `RULE_ID` /
  `REQUEST_ID` / `BUILD`).
- `crates/aegis-proxy/src/proxy.rs` —
  `ProxyContext` gained `benchmark: BenchmarkConfig`
  (default off via `ProxyContext::build`).
  `handle_request` now records `bench_total_start` /
  `route_start` / `upstream_start` instants only when
  the flag is on, computes elapsed durations, builds a
  `StageTimings`, and calls `benchmark::stamp_headers`
  before returning. Off path: one bool check.
- `docs/operator/benchmark-mode.md` — banner flipped
  Designed-only → **Implemented (core slice)** with a
  link to the full plan for the deferred work.
- `plans/implementation-matrix.md` — row updated; B5
  entry in the Phase B mapping marked CLOSED.
- `plans/phase-b/README.md` — § B5 marked ✅ CLOSED with
  the two-sub-task summary and the deferred carry-overs.

**Tests (B5-T2).** 23 net new:

- `benchmark::tests` (21): `config_off_by_default`;
  `build_returns_empty_when_disabled`;
  `build_emits_total_us_when_enabled`; per-stage emission
  (route/security/upstream); rule-id gating
  (omits by default + emits when `expose_rule_ids`);
  tier/decision/request_id round-trip; missing-optional
  fields skipped; `format_us` for micros / millis /
  zero / 1 s; `sanitise_ascii` drops high bytes /
  newlines / keeps dashes; 1 KiB budget truncation;
  stopwatch elapsed; stamp on/off
  (`stamp_headers_no_op_when_disabled`,
  `stamp_headers_attaches_when_enabled`); header
  constants are lowercase.
- `proxy::tests` (2 end-to-end via the existing
  `echoing_upstream` mock):
  `benchmark_headers_emitted_when_enabled` asserts
  `X-Aegis-Stage-Total-Us` + `X-Aegis-Tier`;
  `benchmark_headers_absent_when_disabled` confirms the
  default path is silent.

**Outcome (perf benchmark re-run).** Built release
binary, ran `baseline.js`, `rate-limit.js`, and
`ddos-burst.js` against `config/waf.test.yaml` with the
docker `aegis-k6` container. Logs saved to
`tests/results/*-2026-04-29.log` (the 2026-04-28 logs
are preserved unchanged for comparison). Headline
deltas in
[`tests/results/README-2026-04-29.md`](./tests/results/README-2026-04-29.md):

| Metric (baseline 200 VUs / 15 s) | 2026-04-28 | 2026-04-29 | Direction |
|---|---|---|---|
| Throughput (RPS) | 37 533 | **42 287** | **+12.7 %** |
| Allow-path latency p95 | 7.21 ms | **877 µs** ¹ | **−88 %** |
| Allow-path latency median | 4.26 ms | **505 µs** | **−88 %** |
| `allow_success` ratio | 100.00 % | **1.57 %** | **REGRESSION ⚠️ — see #1 below** |
| `ddos-burst` auto-blocks | 40 001 | 40 001 | unchanged |
| `ddos-burst` p95 latency | 1 ms | 0.48 ms | improved |

¹ 20-VU/15s pre-saturation slice; the 200-VU run mixes
fast 403s into the average.

**Carry-overs surfaced by the perf re-run** (added to
the carry-overs list below):

1. **`lib.rs::handle_data_request` Allow branch still
   returns the synthetic `OK\n` body.** B4-T3 fixed
   `proxy::handle_request` (the public function used by
   tests) but the actual data-plane router at
   `crates/aegis-proxy/src/lib.rs:1915` has its own
   "Allow → return OK" branch that never reaches
   `forward::forward()`. The benchmark allow-path
   latency is fast precisely because the upstream stub
   short-circuits — real upstream forwarding is only
   active for the abstract proxy entry point.
2. **Rate-limit returns 403 (strikes), not 429.** The
   `rate-limit.js` k6 script asserts on
   `status_429_observed > 0`; the gateway accumulates
   strikes via the F-T2 wiring and returns 403
   "blocked by repeat-offender strikes". Pick one and
   align both gateway and script.

**Verification.**
- `cargo build -p aegis-proxy` clean.
- `cargo test --workspace` (default features) → **2,173
  passed** (was 2,151; +22 net new from B5-T2).
- `cargo test -p aegis-proxy --lib benchmark::` →
  **21 passed**.
- `cargo test -p aegis-proxy --lib proxy::` →
  **10 passed** (B4-T3's 8 + B5-T2's 2).
- `cargo clippy --workspace --lib --bins -- -D warnings`
  → clean.
- `cargo run -p aegis-bin -- validate --config
  config/waf.dev.yaml` → `config OK`.
- `cargo build -p aegis-bin --release` clean.
- Live perf run: 200 VUs × 15 s baseline + ddos-burst
  + rate-limit; logs in `tests/results/`.

---


## Recent History

Last five tasks, compressed. For full detail see git history.

| Date | Task | Outcome |
|---|---|---|
| 2026-04-29 | **B5-T2** Benchmark mode core slice — closes B5 | `aegis-proxy::benchmark`: `BenchmarkConfig` + `StageTimings` + `X-Aegis-*` header serialiser; `proxy::handle_request` captures total/route/upstream timings + tier + decision when enabled. +21 unit + 2 proxy end-to-end tests. |
| 2026-04-29 | **B5-T1** HTTP/3 listener | `aegis-proxy/http3` Cargo feature ships `listener::http3` on quinn 0.11 + h3 0.0.8 + h3-quinn 0.0.10; pure helpers for Alt-Svc + ALPN + bind parse + config; runtime path dispatches QUIC streams through `proxy::handle_request`; `protocols.md` flipped Implemented. +15 tests. |
| 2026-04-29 | **B4-T4** Full SSE streaming on `/dashboard/sse` — closes B4 | `admin_sse` widens admin pipeline to `UnsyncBoxBody`; `sse_response` streams `BroadcastStream` events with 15s heartbeat. +8 tests. |
| 2026-04-29 | **B4-T3** Full upstream proxying | `upstream::forward` replaces stub; hop-by-hop scrub both directions; Host rewrite + `X-Forwarded-Host`; preserves method/path/query/body. +14 forward + 5 proxy end-to-end tests. |
| 2026-04-29 | **B4-T2** `waf restore` CLI subcommand | `restore_envelope` w/ atomic dry-run validation + rollback; default destinations come from envelope; `dr-backup.md` flipped Implemented for config/rules surface. +10 tests. |

---

## Next Task

**Task:** **Carry-over B — rate-limit response code
alignment.**

**Plan:** [`tests/results/README-2026-04-29.md`](./tests/results/README-2026-04-29.md)
"What needs improvement" §2.

**Why this next.** Carry-over A is now closed, and the
remaining gating issue before B6 is the disagreement
between the gateway and `tests/load/rate-limit.js` on
what a rate-limited request should look like. Live the
gateway either:
- emits **403** "blocked by repeat-offender strikes" once
  the per-IP strike count crosses
  `risk.strikes.block_at` (today's behaviour), OR
- never emits **429** at all — the `IpRateLimiter`
  decision flows straight into the strikes path.

`tests/load/rate-limit.js` asserts on `status_429_observed`,
so this run-fails today on a healthy gateway.

**Outline.**

1. Pick **B.1 (RFC-aligned)**: emit `429 Too Many
   Requests` with `Retry-After: <window-secs>` from the
   `IpRateLimiter::consume` denied branch in
   `handle_data_request`, *before* the strikes ramp.
   The strike accumulator can keep firing on the same
   request; the wire status changes from 403 to 429 for
   the rate-limit path.
2. Audit-emit the 429 with `class: detection`, `action:
   "rate_limited"`, `reason: "ip rate-limit exceeded"`.
3. Tests:
   - Unit: a fresh `RiskTracker` + `IpRateLimiter` with
     a 5/sec budget, 6 quick requests → first 5 get 200
     (or upstream-forward 502 in the lib test), 6th
     gets 429.
   - Live: `tests/load/rate-limit.js` PASS (status_429
     fires within the burst window).
4. Re-run `baseline.js` at 20 VUs / 5 s — should still
   be rate-limited but the success count should match
   the limiter budget cleanly.

**Acceptance.**

- `cargo test --workspace` green; +2–4 net new tests.
- `tests/load/rate-limit.js` PASS.
- New paragraph in
  [`tests/results/README-2026-04-29.md`](./tests/results/README-2026-04-29.md)
  recording the carry-over closure.

**On close:** Next Task → **B6-T1 — production
Dockerfile** (start of milestone B6 — production
packaging). Three carry-overs (leader-state admin
endpoint; per-node rate-limit bucket; data-plane TLS
loader) remain open behind B6 — promote to follow-ups
unless one becomes a B6 prerequisite.

---

## Tracks in flight

Order is execution priority — earlier rows run first.

| # | Track | Plan | State |
|---|---|---|---|
| 1 | **Phase B — production-readiness (B1..B6)** | [`plans/phase-b/README.md`](./plans/phase-b/README.md) | **active**; B1-T1 unblocked |
| 2 | Dashboard redesign (M0..M10) | [`plans/dashboard-redesign/`](./plans/dashboard-redesign/) | **queued** — runs after Phase B closes |
| — | Benchmark mode (B-T1..B-T6) | [`plans/benchmark-mode.md`](./plans/benchmark-mode.md) | folded into Phase B as B5-T2 |
| — | Security toggles (P1..P8) + post-k6 (F-T1..F-T10) | [`plans/post-k6-followup.md`](./plans/post-k6-followup.md) | closed |
| — | Dashboard track (D-M1..D-M6) | [`plans/dashboard-enterprise/`](./plans/dashboard-enterprise/) | closed |
| — | Phase B intake | [`docs/future/advanced-features.md`](./docs/future/advanced-features.md) | open — for items NOT covered by `plans/phase-b/` |

---

## Carry-overs / known limitations

Durable list of things that work but aren't fully shipped. Each row
is grouped under the Phase B milestone that closes it, so when a
milestone ships you can see exactly which lines to delete. See
[`plans/phase-b/README.md`](./plans/phase-b/README.md) for the task
breakdown.

**B1 — HA & multi-node** ✅ **CLOSED** 2026-04-29 — single-node
+ Redis-primary + local-fallback ships;
`docs/operations/ha-clustering.md` is Implemented. Two minor
follow-ups deliberately deferred from B1: counter merge-back
on partition heal (sliding-window can't be cleanly merged
without a wire-format change), and the GitOps / witness /
threat-intel lease gates (those subsystems aren't running as
background tasks today; their boot sites carry TODOs pointing
at `spawn_with_lease`). Per-member pool health is still
hardcoded to 0 in `pool_snapshot_provider` — depends on
membership-driven cluster runtime, not on the lease layer.

**B2 — Operational integrations** ✅ **CLOSED** 2026-04-29 —
the cloud-secrets quartet (vault/aws/gcp/azure) and the
service-discovery trio (consul/etcd/k8s) all ship. Both
`docs/control-plane/secrets-management.md` and
`docs/data-plane/service-discovery.md` are now Implemented.
HSM (B6-T4) and DNS SRV remain on the deferred list.
- **Service discovery:** `file` watcher + churn safety in
  `aegis-proxy/src/sd/`; Consul / etcd / k8s adapters not
  implemented despite being mentioned in the module doc.

**B3 — Data feeds + filtering** ✅ **CLOSED** 2026-04-29 — all
four sub-tasks ship: B3-T1 GitOps poll driver
(`aegis-control/gitops/poll_driver`); B3-T2 TAXII fetch loop
(`aegis-security/taxii` feature); B3-T3 GeoIP MaxMind reader
(`aegis-security/geoip` feature); B3-T4 ICAP TCP client
(`content::icap::tcp`). `threat-intelligence.md`,
`geoip-filtering.md`, and `content-scanning.md` all flipped
Partial → Implemented. `gitops-change-management.md` banner
stays Partial until the boot-site lease wrap (`aegis-bin` /
`aegis-proxy::run`) lands — same constraint as ACME.

**B4 — Operator tooling** ✅ **CLOSED** 2026-04-29 — all
four sub-tasks ship: B4-T1 `waf snapshot` (JSON envelope,
schema versioning, blake3 hash), B4-T2 `waf restore`
(atomic dry-run validation + rollback), B4-T3 full upstream
proxying (`upstream::forward` w/ hop-by-hop scrub on both
directions + Host rewrite + X-Forwarded-Host), and B4-T4
streaming SSE (`admin_sse::sse_response` w/ 15s heartbeat,
boxed body type, lag handling). `dr-backup.md` flipped
Implemented for the config/rules surface. Body forwarding
is currently buffered — true streaming forwarding (no
collect) is a deeper refactor that touches every listener
+ the SecurityPipeline body-frame hooks; deferred to a
future stream-through change.

**B5 — Protocols + benchmark** ✅ **CLOSED** 2026-04-29 —
both sub-tasks ship: B5-T1 HTTP/3 listener
(`aegis-proxy/http3` feature on quinn 0.11 + h3 0.0.8 +
h3-quinn 0.0.10), B5-T2 benchmark mode core slice
(`aegis-proxy::benchmark` ships `BenchmarkConfig` +
`StageTimings` + `X-Aegis-*` header serialiser, wired into
`proxy::handle_request`). `protocols.md` and
`benchmark-mode.md` both flipped Implemented. **Open
follow-ups** (not blocking B6): auto-stamp `Alt-Svc` on
every TLS response (helper exists; TLS-listener wire-up
deferred); IP allowlist + HMAC-token gating for benchmark
mode (deferred to the full `plans/benchmark-mode.md` plan);
per-detector timing + dashboard panel.

**Perf carry-overs surfaced 2026-04-29** (live re-runs
exposed five real gaps the milestones above didn't catch):

*Single-node perf re-run
([`tests/results/README-2026-04-29.md`](./tests/results/README-2026-04-29.md))*
- ✅ **Data-plane Allow forwarding shipped** (carry-over A,
  closed 2026-04-29). `lib.rs::handle_data_request` now
  resolves the route + member through a `ProxyContext`
  built once in `run()` and forwards via
  `crate::upstream::forward::forward()`. The Allow branch
  no longer returns the synthetic `OK\n` body. Live perf:
  31.5 k RPS / 504 µs median / 3.66 ms full-hop p95 against
  `aegis-httpbin` (log:
  `tests/results/baseline-allow-forwarded-2026-04-29.log`).
- **Rate-limit response code mismatch.** Live behaviour
  is "accumulate strikes → return 403 blocked by
  repeat-offender strikes" rather than the
  `429 Too Many Requests` that `tests/load/rate-limit.js`
  asserts on. Either the gateway emits 429 or the script
  asserts on 403 — pick one.

*Cluster + HTTPS re-run
([`tests/results/cluster/README-2026-04-29.md`](./tests/results/cluster/README-2026-04-29.md))*
- **Leader-state admin endpoint missing.** B1-T3's lease
  layer is wired (boot log prints `lease store = redis`)
  but `/api/cluster` only returns `{"peers":[]}`. No
  `is_leader` field anywhere. `tests/cluster/02-leader-failover.sh`
  skips on this. Either expose `is_leader` on
  `/api/cluster` or add `/api/cluster/leader`.
- **Rate-limit bucket per-node despite shared state
  backend.** Each cluster node admits 10 000 successes
  independently against the same source IP — total
  ~20 000 across the cluster. The bucket counter looks
  local-only; the `RedisBackend` is wired for
  `StateBackend` reads but rate-limit consume/probe may
  bypass it. Either route consume through `StateBackend`
  or document the per-node-budget contract in
  `docs/security/rate-limiting.md`.
- **Data-plane TLS loader missing.** `config::TlsConfig.certificates`
  parses cleanly but no listener consumer reads it for
  the data-plane path. Either wire the static cert list
  through to `listener::tls` or remove the field from the
  schema and direct ops to ACME (`acme:` block).

**B6 — Production packaging**
- **Production packaging:** no Dockerfile, no Helm chart, no
  GitHub Actions CI — `deploy/` ships dev/test compose only.
- **Zero-downtime ops:** `supervisor.rs` + `hotbin.rs` + drain
  exist; no live binary-handover via fd-passing — restart is via
  supervised re-exec only.

When a milestone closes, delete the rows above it and append a
"**Bx milestone**" row to the Completed Tasks Log.

---

## Future phases

Order is execution priority — earlier phases run first.

1. **Phase B — production-readiness (active).**
   [`plans/phase-b/README.md`](./plans/phase-b/README.md).
   Six milestones (B1..B6) that close every Partial /
   Designed-only banner currently in `docs/`. Each milestone close
   removes the matching block of carry-overs above and flips the
   matching `> **Status:**` banners.
2. **Dashboard redesign (queued).**
   [`plans/dashboard-redesign/`](./plans/dashboard-redesign/).
   Eleven milestones (M0..M10), Claude Design–driven workflow
   documented in `workflow.md`. **Does not start until Phase B
   closes.** Implementation notes will land under
   [`docs/control-plane/enterprise/`](./docs/control-plane/enterprise/)
   as the milestones close.
3. **Open intake.**
   [`docs/future/advanced-features.md`](./docs/future/advanced-features.md)
   for proposals NOT covered by Phase B (e.g. multi-tenancy,
   RBAC/SSO, anything new). Scored against the Impact / Reach /
   Cost / Confidence rubric.

---

## Verification (last full run)

- `cargo test --workspace` (default features) → **2,173 passed**
  (steady — Carry-over A rewrote `run_binds_and_serves_200`
  to use a mock upstream rather than asserting on the stub
  body, no net new tests).
- `cargo test -p aegis-proxy --lib benchmark::` → **21 passed**.
- `cargo test -p aegis-proxy --lib proxy::` → **10 passed**
  (3 pre-existing + 5 from B4-T3 + 2 from B5-T2).
- `cargo test -p aegis-proxy --features http3 --lib
  listener::http3::` → **15 passed** (helper layer
  unchanged across feature combos).
- `cargo test -p aegis-proxy --lib admin_sse::` → **8 passed**.
- `cargo test -p aegis-proxy --lib upstream::forward::` →
  **14 passed**.
- **Live perf re-run** (2026-04-29) — release binary +
  `config/waf.test.yaml` + docker `aegis-k6`:
  - `baseline.js` 200 VUs / 15 s → 42 287 RPS, allow-path
    p95 877 µs (was 7.21 ms), `allow_success` 1.57 % (was
    100 % — surfaced two carry-overs above).
  - `ddos-burst.js` → 40 001 auto-blocks, p95 0.48 ms.
  - `rate-limit.js` → FAIL on `status_429` assertion
    (gateway returns 403/strike instead — see
    carry-overs).
  - Logs: `tests/results/*-2026-04-29.log`. Comparison:
    [`tests/results/README-2026-04-29.md`](./tests/results/README-2026-04-29.md).
- `cargo test -p aegis-bin --bin waf -- snapshot` → **25
  passed** (15 from B4-T1 + 10 from B4-T2).
- `cargo test -p aegis-security --lib content::icap::` →
  **44 passed** (35 new + 9 pre-existing stub).
- `cargo test -p aegis-security --features geoip --lib
  geoip::` → **10 passed**.
- `cargo test -p aegis-security --features taxii --lib
  threat_intel::taxii::` → **38 passed**.
- `cargo test -p aegis-control --lib gitops::poll_driver::`
  → **9 passed**.
- `cargo test -p aegis-proxy --features consul --lib sd::consul::`
  → **16 passed**.
- `cargo test -p aegis-proxy --features etcd --lib sd::etcd::`
  → **18 passed**.
- `cargo test -p aegis-proxy --features k8s --lib sd::k8s::`
  → **24 passed**.
- `cargo test -p aegis-control --features alerts --lib slo::dispatch::`
  → **4 passed** (VipTalk routing).
- `cargo clippy --workspace --lib -- -D warnings` → clean.
- `cargo clippy --workspace --bins -- -D warnings` → clean.
- `cargo clippy -p aegis-proxy --features http3 --lib --
  -D warnings` → clean.
- `cargo clippy -p aegis-security --features geoip --lib --
  -D warnings` → clean.
- `cargo clippy -p aegis-security --features taxii,geoip --lib --
  -D warnings` → clean.
- `cargo clippy -p aegis-proxy --features
  redis,vault,aws,gcp,azure,consul,etcd,k8s --lib --
  -D warnings` → clean.
- `cargo run -p aegis-bin -- validate --config
  config/waf.dev.yaml` → `config OK`.
- `waf snapshot --output /tmp/x.json --config
  config/waf.dev.yaml` → 7,143-byte envelope, JSON
  round-trips through `python -c "json.load(...)"`.
- `waf snapshot ... --output snap.json --force` → `waf
  restore --from snap.json --config-out restored.yaml` →
  `waf validate --config restored.yaml` → all clean
  (full snapshot/restore CLI round-trip).

---

## Completed Tasks Log

Append-only. One row per closed task.

| Task | Crate | Date |
|------|-------|------|
| M1-T1.1 Workspace + `./waf run` skeleton | aegis-bin, aegis-proxy, aegis-core | 2026-04-22 |
| M1-T1.5 NoopPipeline + bus wiring | aegis-security, aegis-bin | 2026-04-22 |
| M1-T1.2 Config loader (figment + validation) | aegis-core | 2026-04-22 |
| M1-T1.3 Hot reload (notify + ArcSwap) | aegis-proxy | 2026-04-22 |
| M1-T1.4 Dual listener model | aegis-proxy | 2026-04-22 |
| M1-T2.1 Host matcher | aegis-proxy | 2026-04-22 |
| M1-T2.2 Path trie | aegis-proxy | 2026-04-22 |
| M1-T2.3 RouteTable::build + resolve | aegis-proxy | 2026-04-22 |
| M1-T2.4 Upstream Pool + LB strategies | aegis-proxy | 2026-04-22 |
| M1-T2.5 Active health checks | aegis-proxy | 2026-04-22 |
| M1-T2.6 Circuit breaker | aegis-proxy | 2026-04-22 |
| M1-T2.7 Wire routing + upstream into proxy.rs | aegis-proxy | 2026-04-22 |
| M1-T3.1 DynamicResolver + CertStore | aegis-proxy | 2026-04-24 |
| M1-T3.2 HTTP/2 on both sides | aegis-proxy | 2026-04-24 |
| M1-T3.3 WebSocket upgrade passthrough | aegis-proxy | 2026-04-24 |
| M1-T3.4 gRPC trailer-preserving forward | aegis-proxy | 2026-04-24 |
| M1-T3.5 mTLS to upstream | aegis-proxy | 2026-04-24 |
| M1-T3.6 ACME (feature acme) | aegis-proxy | 2026-04-24 |
| M1-T3.7 OCSP stapling | aegis-proxy | 2026-04-24 |
| M1-T4.1 Per-route quotas | aegis-proxy, aegis-core | 2026-04-24 |
| M1-T4.2 Transformations + CORS | aegis-proxy | 2026-04-24 |
| M1-T4.3 Canary split + header/cookie steering | aegis-proxy | 2026-04-24 |
| M1-T4.4 Retries with budget | aegis-proxy | 2026-04-24 |
| M1-T4.5 Shadow mirroring | aegis-proxy | 2026-04-24 |
| M1-T4.6 Session affinity | aegis-proxy | 2026-04-24 |
| M1-T4.7 Worker supervisor + graceful drain | aegis-proxy | 2026-04-24 |
| M1-T4.8 Hot binary reload (SIGUSR2) | aegis-proxy | 2026-04-24 |
| M1-T4.9 Tier-aware smart cache | aegis-proxy | 2026-04-24 |
| M1-T5.1 InMemoryBackend polish | aegis-proxy | 2026-04-24 |
| M1-T5.2 RedisBackend stub (feature redis) | aegis-proxy | 2026-04-24 |
| M1-T5.3 Adaptive load shedder (Gradient2) | aegis-proxy | 2026-04-24 |
| M1-T5.4 Secrets resolver (env + file) | aegis-proxy | 2026-04-24 |
| M1-T5.5 DR snapshot/restore types | aegis-proxy | 2026-04-24 |
| M1-T5.6 Service discovery (file watcher) | aegis-proxy | 2026-04-24 |
| M1-T5.7 Cluster membership (in-process) | aegis-proxy | 2026-04-24 |
| M2-T1.1 Rule AST + parser | aegis-security | 2026-04-24 |
| M2-T1.2 Linter | aegis-security | 2026-04-24 |
| M2-T1.3 Evaluator | aegis-security | 2026-04-24 |
| M2-T1.4 RuleSet hot reload | aegis-security | 2026-04-24 |
| M2-T1.5 Tier classifier | aegis-security | 2026-04-24 |
| M2-T2.1 Sliding window rate limit | aegis-security | 2026-04-26 |
| M2-T2.2 Token bucket | aegis-security | 2026-04-26 |
| M2-T2.3 DDoS per-IP burst + cluster spike | aegis-security | 2026-04-26 |
| M2-T2.4 OWASP detectors (SQLi, XSS, PathTraversal, SSRF, HeaderInjection, BodyAbuse, Recon) | aegis-security | 2026-04-26 |
| M2-T3.1 JA4/JA3 parser | aegis-security | 2026-04-26 |
| M2-T3.2 HTTP/2 fingerprint | aegis-security | 2026-04-26 |
| M2-T3.3 Composite device id | aegis-security | 2026-04-26 |
| M2-T3.4 RiskEngine (scoring + decay) | aegis-security | 2026-04-26 |
| M2-T3.5 Challenge ladder | aegis-security | 2026-04-26 |
| M2-T3.6 Challenge tokens (HMAC + nonce) | aegis-security | 2026-04-26 |
| M2-T3.7 CAPTCHA providers (Turnstile, hCaptcha, reCAPTCHA) | aegis-security | 2026-04-26 |
| M2-T3.8 Behavioral analyzer | aegis-security | 2026-04-26 |
| M2-T3.9 Transaction velocity | aegis-security | 2026-04-26 |
| M2-T4.1 CIDR lists + XFF walker | aegis-security | 2026-04-26 |
| M2-T4.2 MaxMind ASN classifier | aegis-security | 2026-04-26 |
| M2-T4.3 Bot classifier | aegis-security | 2026-04-26 |
| M2-T4.4 Threat intel feeds (in-memory store) | aegis-security | 2026-04-26 |
| M2-T5.1 Streaming response filter | aegis-security | 2026-04-26 |
| M2-T5.2 DLP patterns + actions | aegis-security | 2026-04-26 |
| M2-T5.3 FPE (AES-FF1) | aegis-security | 2026-04-26 |
| M2-T5.4 OpenAPI schema enforcement | aegis-security | 2026-04-26 |
| M2-T5.5 ForwardAuth | aegis-security | 2026-04-26 |
| M2-T5.6 JWT validation | aegis-security | 2026-04-26 |
| M2-T5.7 ICAP antivirus (trait + types stub) | aegis-security | 2026-04-26 |
| M2-T5.8 Magic-byte + archive-bomb | aegis-security | 2026-04-26 |
| M2-T5.9 GraphQL guard | aegis-security | 2026-04-26 |
| M2-T5.10 HMAC request signing | aegis-security | 2026-04-26 |
| M2-T5.11 API-key management | aegis-security | 2026-04-26 |
| M2-T5.12 Basic Auth | aegis-security | 2026-04-26 |
| M2-T5.14 OPA callout | aegis-security | 2026-04-26 |
| M2-DoD Red-team suite + benign corpus + fixture expansion | aegis-security | 2026-04-26 |
| M3-T1.1 MetricsRegistry init | aegis-control | 2026-04-26 |
| M3-T1.2 Prometheus exporter | aegis-control | 2026-04-26 |
| M3-T1.3 Health endpoints (live/ready/startup) | aegis-control | 2026-04-26 |
| M3-T1.4 Dashboard shell + SSE stub | aegis-control | 2026-04-26 |
| M3-T1.4b Dashboard overview page | aegis-control | 2026-04-26 |
| M3-T1.5 GET /api/config | aegis-control | 2026-04-26 |
| M3-T2.2 Tracing init + W3C Trace Context | aegis-control | 2026-04-26 |
| M3-T2.4 Access log writer (combined/JSON/template) | aegis-control | 2026-04-26 |
| M3-T3.1 Audit chain writer (SHA-256 hash chain) | aegis-control | 2026-04-26 |
| M3-T3.2 Audit verify (chain walk + recompute) | aegis-control | 2026-04-26 |
| M3-T3.3 Audit sinks (JSONL, syslog, CEF, LEEF, OCSF, Splunk HEC, ECS, Kafka) | aegis-control | 2026-04-26 |
| M3-T3.4 Admin change log | aegis-control | 2026-04-26 |
| M3-T3.5 Witness export (blake3 signing) | aegis-control | 2026-04-26 |
| M3-T3.6 State snapshot tracker | aegis-control | 2026-04-26 |
| M3-T4.1 Password verify + PHC (argon2id) | aegis-control | 2026-04-26 |
| M3-T4.2 HMAC session cookie + SessionRecord | aegis-control | 2026-04-26 |
| M3-T4.3 CSRF double-submit | aegis-control | 2026-04-26 |
| M3-T4.4 Login rate limit + lockout | aegis-control | 2026-04-26 |
| M3-T4.5 IP allowlist (in mtls module) | aegis-control | 2026-04-26 |
| M3-T4.6 TOTP (RFC 6238) + recovery codes | aegis-control | 2026-04-26 |
| M3-T4.7 Admin mTLS | aegis-control | 2026-04-26 |
| M3-T5.1 Compliance profiles (FIPS, PCI, SOC2, GDPR, HIPAA) + conflict detection | aegis-control | 2026-04-26 |
| M3-T5.2 Residency / retention sweep / right-to-erasure | aegis-control | 2026-04-26 |
| M3-T5.3 GitOps loader (poll, sig verify, dry-run, break-glass) | aegis-control | 2026-04-27 |
| M3-T5.5 SLO / SLI + multi-burn alerts (5 SLIs, 3 windows, 5 receivers) | aegis-control | 2026-04-27 |
| M3-DoD Integration tests (login flow, audit verify, SIEM ≥3 sinks, FIPS, SLO) | aegis-control | 2026-04-27 |
| Cross-crate wiring (audit verify, admin set-password, admin enroll-totp, validate + compliance) | aegis-bin | 2026-04-27 |
| README.md full rewrite | project-wide | 2026-04-27 |
| deploy/GUIDE.md deployment guide | project-wide | 2026-04-27 |
| docs/operator/usage.md operator runbook | project-wide | 2026-04-27 |
| Data-plane detector wiring (7 OWASP detectors run on every request) | aegis-proxy | 2026-04-27 |
| Admin listener wiring (dashboard, SSE stub, health, metrics, config API on :9443) | aegis-proxy | 2026-04-27 |
| config/README.md configuration guide | project-wide | 2026-04-27 |
| **D-M1 milestone** (SPA shell + assets + router + chrome + security headers + legacy carve-out + dev hot-reload + i18n) | aegis-control, aegis-proxy | 2026-04-27 |
| **D-M2 milestone** (6 endpoints + Overview page wired end-to-end) | aegis-control, aegis-proxy | 2026-04-27 |
| **D-M3 milestone** (4 operator pages + 11 endpoints) | aegis-control, aegis-proxy | 2026-04-27 |
| **D-M4 milestone** (5 config-management pages + 11 endpoints + 5 stores) | aegis-control, aegis-proxy | 2026-04-28 |
| **D-M5 milestone** (tracking page — 6 endpoints + snapshot aggregate) | aegis-control, aegis-proxy | 2026-04-28 |
| **D-M6 milestone** (a11y/contrast/headers/budget tests + legacy removal + docs) | aegis-control, aegis-proxy, docs | 2026-04-28 |
| **Dashboard track complete** (D-M1..D-M6, +275 tests) | project-wide | 2026-04-28 |
| **P1** AuditedMutate pipeline (CSRF + audit chain + ArcSwap) | aegis-control | 2026-04-28 |
| **P2** Class toggles + hot-path bitfield mask + Settings UI | aegis-security, aegis-control | 2026-04-28 |
| **P3** Per-detector toggles + per-tier override (SharedDetectorMask) | aegis-security, aegis-control | 2026-04-28 |
| **P4** TLS hardening (TLS 1.2+ minimum, security headers, redirect) | aegis-proxy | 2026-04-28 |
| **P5** ACME — InstantAcmeProvider + AcmeManager + scheduler | aegis-proxy | 2026-04-28 |
| **P6** Risk-scoring upgrades (strikes + trust recovery + reset) | aegis-security, aegis-control | 2026-04-28 |
| **P7** LoadMode + bounded caches + degraded logging | aegis-core, aegis-security, aegis-proxy, aegis-control | 2026-04-28 |
| **P8** Verbosity gating + cold-tier surface | aegis-core, aegis-control | 2026-04-28 |
| **F-T1** Wire `POST /admin/login` + `/admin/logout` end-to-end | aegis-control | 2026-04-28 |
| **F-T2** Wire per-IP rate limiting | aegis-security, aegis-proxy | 2026-04-28 |
| **F-T3** No-op (was test contamination, not a real bug) | — | 2026-04-28 |
| **F-T4 + F-T5** k6 contract tests for security toggles + risk strikes | tests/load | 2026-04-28 |
| **F-T6** host-vs-laptop perf calibration docs | tests/load/README-perf.md | 2026-04-28 |
| **F-T7** Pebble container + ACME smoke | deploy, tests/api/acme.sh | 2026-04-28 |
| **F-T8** AcmeManager + InstantAcmeProvider wired into `run()` | aegis-proxy | 2026-04-28 |
| **F-T9** k6 audit-since + cold-tier inventory contracts | tests/load | 2026-04-28 |
| **F-T10** RequestStageHistogram (per-stage WAF latency) | aegis-control, aegis-proxy | 2026-04-28 |
| Documentation restructure — flat docs/ → 8-category taxonomy | docs/, plans/, crates/ | 2026-04-28 |
| Tests folder consolidation + new auth/TLS/rate-limit smoke coverage | tests/ | 2026-04-29 |
| Doc-by-doc implementation audit + Status banners + Phase B candidate seeds | docs/, plans/plan.md | 2026-04-29 |
| Implement-Progress.md rewritten as lean future-proof template | Implement-Progress.md | 2026-04-29 |
| Phase B promoted to active track — `plans/phase-b/` formalised, dashboard redesign queued | plans/, Implement-Progress.md | 2026-04-29 |
| `plans/` cleanup — README status board + extracted implementation-matrix.md + 21 Status banners + AI-guide-only `plan.md` | plans/, Implement-Progress.md | 2026-04-29 |
| **B1-T1** Real Redis state backend (`deadpool-redis` + Lua scripts + per-call timeout + live parity vs InMemoryBackend) | aegis-proxy | 2026-04-29 |
| **B1-T2** Backend selection in `aegis-bin` (`state_select::select` + boot log line + feature-gated redis branch + actionable errors) | aegis-bin | 2026-04-29 |
| **B1-T3** Cross-node leader lease (`LeaseStore` trait + `InProcessLease` + `RedisLease` + `spawn_heartbeat` + 7 live parity tests) | aegis-core, aegis-proxy | 2026-04-29 |
| **B1-T4** Lease gate on leader-only tasks (`run_with_lease` runner + `lease_select` + ACME gated; gitops/witness/threat-intel TODOs marked) | aegis-proxy, aegis-bin | 2026-04-29 |
| **B1-T5** Rehydrate + readiness gate (`state::rehydrate` probe + `state.reconcile.readiness_warm_ms` config + 5s default deadline; never permanently 503) | aegis-core, aegis-proxy | 2026-04-29 |
| **B1-T6** Partition-safe merge — closes B1 (`ReconcilingBackend` wrap; block-list union on heal; counters fall through; `ha-clustering.md` flipped Implemented) | aegis-proxy, aegis-bin, docs | 2026-04-29 |
| **B1 milestone CLOSED** — HA & multi-node ships single-node + Redis-primary + local-fallback | project-wide | 2026-04-29 |
| **B2-T1** Vault secret resolver (`aegis-proxy/vault` feature, KV-v2 client, token + AppRole auth, env-var config) | aegis-proxy | 2026-04-29 |
| **B2-T2** AWS Secrets Manager resolver (`aegis-proxy/aws` feature, `aws-sdk-secretsmanager`, full credential chain, JSON-field extraction) | aegis-proxy | 2026-04-29 |
| **B2-T3** GCP Secret Manager resolver (`aegis-proxy/gcp` feature, REST + `gcp_auth`, ADC chain, shared `json_field` helper) | aegis-proxy | 2026-04-29 |
| **B2-T4** Azure Key Vault resolver (`aegis-proxy/azure` feature, REST + hand-rolled SP/IMDS auth) — closes the cloud-secrets quartet | aegis-proxy | 2026-04-29 |
| **B2-T5** Consul service discovery (`aegis-proxy/consul` feature, blocking-query watcher, env-driven config, ACL/multi-DC/mTLS support) | aegis-proxy | 2026-04-29 |
| Side-quest: VipTalk default alert routing (`aegis-control/alerts` feature, `slo::dispatch::send_alert`, env override; doc updated) | aegis-control, docs | 2026-04-29 |
| **B2-T6** etcd service discovery (`aegis-proxy/etcd` feature, REST gateway range-polling, basic auth + mTLS, configurable poll interval) | aegis-proxy | 2026-04-29 |
| **B2-T7** Kubernetes service discovery — closes B2 (`aegis-proxy/k8s` feature, EndpointSlice streaming watch, in-cluster + override auth) | aegis-proxy | 2026-04-29 |
| **B2 milestone CLOSED** — operational integrations (cloud-secrets quartet + service-discovery trio) ship | project-wide | 2026-04-29 |
| **B3-T1** Built-in git poll-and-pull `GitClient` (`gitops::poll_driver::GitPollDriver` shells out to system `git`; signature parse via `verify-commit --raw`; read-only by design; +9 tests) | aegis-control | 2026-04-29 |
| **B3-T2** STIX/TAXII fetch loop into `ThreatIntelStore` (`aegis-security/taxii` feature; TAXII 2.1 client + paginated fetcher loop; STIX 2.1 pattern decoder for IPv4/IPv6/domain/URL/SHA-256; +38 tests) | aegis-security | 2026-04-29 |
| **B3-T3** GeoIP MaxMind reader + rule-engine `country` / `asn` conditions (`aegis-security/geoip` feature; `MaxMindReader` w/ atomic hot-reload + `EvalContext`-threaded rule eval; `geoip-filtering.md` flipped Implemented; +18 default-feature + 5 feature-gated tests) | aegis-security | 2026-04-29 |
| **B3-T4** Concrete RFC 3507 ICAP TCP client — closes B3 (`content::icap::{codec,tcp}`; pure framing helpers + 5-vendor decision table; configurable timeout + fail-open default; `content-scanning.md` flipped Implemented; +36 tests) | aegis-security | 2026-04-29 |
| **B3 milestone CLOSED** — Data feeds + filtering (GitOps + TAXII + GeoIP + ICAP) ship | project-wide | 2026-04-29 |
| **B4-T1** `waf snapshot` CLI subcommand (`aegis-bin::snapshot::SnapshotEnvelope`; bundles config + rules files + blake3 integrity + schema versioning into JSON; refuses overwrite without `--force`; `decode`/`validate_envelope` ready for B4-T2; +15 tests) | aegis-bin | 2026-04-29 |
| **B4-T2** `waf restore` CLI subcommand (`restore_envelope` w/ atomic dry-run validation + rollback; `dr-backup.md` flipped Implemented for config/rules surface; +10 tests) | aegis-bin | 2026-04-29 |
| **B4-T3** Full upstream proxying (`upstream::forward` replaces stub; hop-by-hop scrub both directions; Host rewrite + `X-Forwarded-Host`; preserves method/path/query/body; +14 forward + 5 proxy end-to-end tests) | aegis-proxy | 2026-04-29 |
| **B4-T4** Full SSE streaming on `/dashboard/sse` — closes B4 (`admin_sse::sse_response` returns `UnsyncBoxBody` driven by `BroadcastStream` merged w/ 15s idle heartbeat ticker; preamble + per-event frames + lag handling; +8 tests) | aegis-proxy, aegis-control | 2026-04-29 |
| **B4 milestone CLOSED** — Operator tooling (snapshot + restore + upstream + SSE) ships | project-wide | 2026-04-29 |
| **B5-T1** HTTP/3 listener (`aegis-proxy/http3` feature; `listener::http3` on quinn 0.11 + h3 0.0.8 + h3-quinn 0.0.10; pure helpers for Alt-Svc + ALPN + bind parse + config; runtime path dispatches QUIC streams through `proxy::handle_request`; `protocols.md` flipped Implemented; +15 tests) | aegis-proxy | 2026-04-29 |
| **B5-T2** Benchmark mode core slice — closes B5 (`aegis-proxy::benchmark` ships `BenchmarkConfig` + `StageTimings` + `X-Aegis-*` header serialiser; `proxy::handle_request` captures total/route/upstream timings + tier + decision; 1 KiB header budget; off-mode = 1 bool check; `benchmark-mode.md` flipped Implemented (core slice); +21 unit + 2 proxy end-to-end tests) | aegis-proxy | 2026-04-29 |
| **B5 milestone CLOSED** — Protocols + benchmark (HTTP/3 + benchmark mode) ships | project-wide | 2026-04-29 |
| **Perf re-run** — 2026-04-29 baseline + ddos-burst + rate-limit benchmarks against release build w/ B3+B4+B5 changes; allow-path latency p95 7.21 ms → 877 µs; surfaced two carry-overs (`lib.rs::handle_data_request` Allow stub still active; rate-limit returns 403 not 429); old logs preserved as `tests/results/*.log`, new as `tests/results/*-2026-04-29.log`, comparison in `tests/results/README-2026-04-29.md` | tests/results | 2026-04-29 |
| **HTTPS test additions** — `tests/api/tls-data.sh` (data-plane TLS hardening; skips when `:8443` not bound), `tests/api/tls-ciphers.sh` (TLS 1.3 + 1.2 cipher-suite negotiation, weak-cipher reject, cert-chain probe), `tests/load/tls-baseline.js` (k6 baseline over HTTPS w/ handshake-latency SLO); wired into `tests/api/run-all.sh`; pyramid table updated | tests/api, tests/load | 2026-04-29 |
| **HA cluster smoke track** — new `tests/cluster/` (4 scripts + `_common.sh` + `run-all.sh` + `README.md`) exercising B1's contract: shared Redis state (`01-shared-counter.sh`), cross-node leader failover (`02-leader-failover.sh`), rehydrate-readiness gate (`03-rehydrate-readiness.sh`), partition-fallback heal (`04-partition-fallback.sh`); two-node fixture w/ `config/waf.cluster-{a,b}.yaml`; both configs validate clean | tests/cluster, config | 2026-04-29 |
| **Cluster + HTTPS perf re-run** — first live run of the new cluster track; 3 PASS / 0 FAIL / 1 SKIP (leader-state admin endpoint not exposed). Two-node baseline shows identical perf across A and B (34.5 k RPS, p95 ~880 µs, identical to single-node). Surfaced two new carry-overs: rate-limit bucket per-node despite shared state backend (each node admits 10 k, total 20 k); data-plane `tls.certificates` parsed but no listener-side loader. HTTPS load test skipped — no data-plane TLS path consumable from YAML. Logs in `tests/results/cluster/`, comparison in `tests/results/cluster/README-2026-04-29.md` | tests/cluster, tests/results | 2026-04-29 |
| **Carry-over A** — data-plane Allow forwarding wired through `upstream::forward::forward()`; `lib.rs::handle_data_request` is now async + takes `Arc<ProxyContext>`; `forward_allow_to_upstream` helper does route resolve → CB gate → pool pick → body collect → forward; `run_binds_and_serves_200` rewritten with a mock upstream; live k6 against WAF→`aegis-httpbin` shows 31.5 k RPS / 504 µs median / 3.66 ms full-hop p95; closes the data-plane stub gap surfaced 2026-04-29 | aegis-proxy | 2026-04-29 |
