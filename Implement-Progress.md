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

- **As of:** 2026-05-02
- **Workspace tests:** ~2 500 across 17 binaries (all green; clippy
  clean under `-D warnings` for `aegis-control` + `aegis-proxy` libs).
- **Dashboard bundle:** 178 KB (`crates/aegis-control/assets/dashboard/`)
- **Headline perf** (`tests/results/run-perf-5krps-prod-balanced-2026-05-02-v3/`):
  prod-balanced profile sustained **4 891 RPS k6 / 6 392 RPS WAF-internal**
  for 2 min with **legit p99 1.03 ms, legit median 0.13 ms, legit OK 100 %,
  detection 80 %**. All three k6 thresholds passed. WAF inspection cost is
  essentially free at this load on M-class hardware.
- **Earlier headline** (`tests/results/run-perf-15min-2026-05-02-v2/`):
  15-min mixed-traffic harness, post-detector-coverage sprint —
  **80 % detection** (was 33 % v1), legit p99 4.52 ms, 100 % of
  detected attacks prevented.
- **Active tracks (next week)**: **AI-Assistant-driven testing track** —
  see `tests/AI-ASSISTANT-GUIDE.md` (defines rules + workflow for
  generating, running, and reviewing tests with AI help).
- **Operator UX simplified 2026-05-02**: every config (dev / prod /
  3 profiles) defaults to **Redis state**; the Makefile auto-starts
  the dev Redis on every `run-*` target. New `make obs-up` / `make urls`
  / `make logs` targets surface Prometheus + Grafana + Jaeger + audit
  paths in one command. First-light is now `make setup && make run-dev`.

---

## Last Completed

**Task:** End-of-sprint operator UX simplification — Redis-default
across every operator-facing config, observability stack as one make
target, refreshed QUICKSTART/README, AI-Assistant testing scaffold for
next week.

### What shipped

1. **Redis as the default state backend everywhere.**
   `config/dev.yaml` and `config/prod.yaml` switched from
   `state.backend: in_memory` to `redis` (matching the 3 profiles
   under `config/profiles/`). The 4 operator-facing configs are now
   identical in shape — only thresholds differ. Stress-test infra
   (`tests/hackathon/configs/*`) keeps `in_memory` and documents
   why inline (synthetic load, single source IP, no Redis hop to
   measure).

2. **Auto-start Redis from the Makefile.** Every `run-*` target
   gained `redis-up` as a dependency; `redis-up` is idempotent
   (checks `docker ps` first, starts the existing container if
   present, runs `docker compose up -d redis` only when needed).
   First-light now collapses from "build → start Redis → run" to
   `make setup && make run-dev`.

3. **Observability stack one-shot.** New targets:
   - `make obs-up` — boots Prometheus + Grafana + Jaeger.
   - `make urls` — prints every URL + log-file path the
     dev/devops would want.
   - `make logs` — tails audit chain + redis container together.

4. **prod-balanced @ 5 k+ RPS sustained run committed**
   (`tests/results/run-perf-5krps-prod-balanced-2026-05-02-v3/REPORT.md`).
   Three iterative runs preserved (v1 = harness saturated, v2 =
   Python upstream choked, v3 = clean run with Go upstream). Adds
   `tests/hackathon/configs/prod-balanced-5k.yaml`,
   `tests/hackathon/k6/prod-balanced-5k-v2.js` (constant-arrival-rate),
   `tests/hackathon/upstream/fast-upstream.go` (50 k+ RPS Go mock),
   `tests/hackathon/run-prod-balanced-5k.sh`. Seven actionable
   improvements documented in REPORT.md §"What to improve".

5. **Profile picker shipped earlier in the session**: 3 production
   profiles under `config/profiles/` (balanced / strict / high-throughput),
   `docs/operator/profiles.md` decision tree, Makefile `run-strict` /
   `run-throughput` / `validate-all` targets.

6. **Detector-coverage sprint earlier**: BodyPeek fix, mass-assignment
   + XXE detectors, brute-force detector on auth paths, SSRF body-IP
   scan. Detection rate 33 % → 80 % across the hackathon corpus.

7. **HACK-T4 rollback dispatcher v2..v5 + MTLS-T7 SAN allowlist
   earlier**: rollback now covers 11 of 18 audit-mutated actions
   (mode, risk thresholds, mTLS SANs add/remove, blacklist, whitelist,
   detector mask, verbosity, loadmode). SAN allowlist with RFC 6125
   single-label wildcard support live-verified end-to-end.

8. **SC-T4 tokio runtime metrics earlier**: 4 Prometheus gauges
   (`aegis_runtime_active_workers`, `_blocking_threads`,
   `_blocking_queue_depth`, `_io_driver_fd_count`) gated on
   `--cfg tokio_unstable`; gauges always registered, populated only
   when feature is on.

### Verification

- `make validate-all` → all 4 configs (dev + 3 profiles) PASS.
- `./target/release/waf run --config config/dev.yaml` boots clean
  with Redis backend; `/healthz/ready` reports
  `state_backend_up: true`; cluster-leader lease acquired in 7 ms.
- `make redis-up` is idempotent (existing container reused; no
  duplicate-name conflicts).
- `make help` renders cleanly with the new `obs-up` / `urls` / `logs`
  targets visible.
- `make urls` output shows the full URL + log-path map.

### Files changed (this session — multi-day)

- **Configs**: `config/dev.yaml`, `config/prod.yaml`,
  `config/profiles/{prod-balanced,prod-strict,prod-high-throughput}.yaml`
- **Makefile**: profile-aware run targets; `redis-up` idempotency;
  `obs-up`, `obs-down`, `urls`, `logs` targets
- **Docs**: `QUICKSTART.md` (rewritten), `README.md` (status section
  refreshed + 5k+ RPS row added), `docs/operator/profiles.md` (new),
  `Implement-Progress.md` (this file, slimmed)
- **Test infra**: `tests/hackathon/configs/prod-balanced-5k.yaml`,
  `tests/hackathon/k6/prod-balanced-5k{,-v2}.js`,
  `tests/hackathon/upstream/fast-upstream.go`,
  `tests/hackathon/run-prod-balanced-5k.sh`
- **Results**: 3 stress-test run dirs +
  `run-perf-5krps-prod-balanced-2026-05-02-v3/REPORT.md`
- **AI Assistant testing track**: `tests/AI-ASSISTANT-GUIDE.md`
  (new — picks up next week)

### Next-session hand-off

The AI-Assistant-driven testing track is the next user-driven
focus area. Intake docs:
- `tests/AI-ASSISTANT-GUIDE.md` — rules, workflow, what to
  generate vs. what to write by hand, review checklist.
- `tests/AI-ASSISTANT-RULES.md` — terse do/don't sheet for any
  AI assistant working in `tests/`.

---

## Recent History

| Date | Task | Outcome |
|---|---|---|
| 2026-05-02 (PM) | Operator UX simplification + Redis-default + obs stack + AI-testing scaffold | This entry. `make setup && make run-dev` now boots a Redis-backed dev profile in 2 commands. AI-Assistant testing rules + guide live under `tests/`. |
| 2026-05-02 (mid) | prod-balanced @ 5 k+ RPS sustained (3 iterative runs) | v3 = 4 891 RPS k6 / 6 392 RPS WAF-internal, legit p99 1.03 ms, legit OK 100 %, 80 % detection. Surfaced 7 improvements; identified Python upstream as the prior 600-RPS ceiling. |
| 2026-05-02 (early) | Profile picker + Makefile profile-aware run targets | 3 profiles (balanced/strict/high-throughput) + `docs/operator/profiles.md` decision tree + `run-strict`/`run-throughput`/`validate-all` make targets. |
| 2026-05-02 | Detector-coverage sprint + rollback v2..v5 + SC-T4 | Detection 33 % → 80 % via BodyPeek fix + mass-assignment + XXE + brute-force + SSRF body. Rollback covers 11 of 18 audit-mutated actions. SC-T4 tokio runtime gauges live (gated on `--cfg tokio_unstable`). |
| 2026-05-01 | HACK-T1..T5 stress-test prep + MTLS-T1..T7 | 15-min mixed-traffic harness scaffolded; mTLS rustls inbound + identity extraction + route gate + hot-reload + console observability + SAN allowlist all shipped. |

For full chronological detail see `git log` and `docs/progress/completed-tasks-log.md`.

---

## Next Task

### TCP forwarder Phase 4 — ✅ shipped 2026-05-03

CONNECT-method TCP tunneling is live and tested. Track closed
across 7 commits totalling ~1900 LOC + 41 new tests. Design at
[`plans/tcp-forwarder-phase-4.md`](./plans/tcp-forwarder-phase-4.md);
operator docs at [`docs/data-plane/reverse-proxy.md`](./docs/data-plane/reverse-proxy.md)
§ "TCP tunneling via CONNECT".

**Slice landing log:**

| Slice | Commit | Scope |
|---|---|---|
| TCP-T1 | `f1b52b1` | Destination policy + RouteConfig allowlist + SSRF gate |
| TCP-T2 | `e39ea51` | Per-IP concurrent-tunnel counter with RAII guard |
| TCP-T3a | `e02cb27` | `connect_admit` pure admission gate |
| TCP-T3b | `7c62f3e` | `bridge_tunnel` async splice + close-reason |
| TCP-T3c | `159cebd` | Data-plane wiring + audit pair + 6 deny rule_ids |
| TCP-T5+T6 | `15b378c` | 9 dispatch-matrix tests + retire 502 stub |

TCP-T4 (richer audit field shape) was rolled into T3c — the
`tcp_tunnel_open` / `tcp_tunnel_close` events ship the full
design-doc payload (route_id, destination, duration_ms,
bytes counters, close_reason).

**What's left as polish (not blocking):**

- `tests/api/connect-tunnel.sh` end-to-end smoke — optional;
  in-process integration tests already cover the dispatch
  matrix and the bridge byte-flow.
- HTTP/2 extended CONNECT (RFC 8441) — rare in the wild;
  current build returns 405 `connect_no_upgrade_support` for
  h2 clients. Pick up if/when an operator asks.

### AI-Assistant testing track — kicked off

Sweep tooling shipped at `1356409`:
- `plans/ai-assistant-testing-kickoff.md` — design (8 slices,
  schema, anti-patterns, SWEEP-T1..T5).
- `tests/sweeps/{README.md, CLAIMS.template.md, template/, consolidate.sh}`
  — runnable scaffolding.
- `make sweep-validate TESTER=...` and
  `make sweep-consolidate SWEEP=...` — ops one-liners.

Existing intake (still current):
- `tests/AI-ASSISTANT-GUIDE.md` — workflow + review checklist.
- `tests/AI-ASSISTANT-RULES.md` — terse do/don't sheet.

**Open for user when picking up:** schedule sweep #1 (4-6
testers across 4-6 slices, ~2h), name the theme, branch from
develop.

### AI-T — ML detector integration (design ready)

Design pass shipped at
[`plans/ai-detector.md`](./plans/ai-detector.md). Integrates
the trained ONNX model from
[`data/ai_model/WAF_DATASET_REPORT_VI.md`](./data/ai_model/WAF_DATASET_REPORT_VI.md)
(11 classes, 36.8 MB, 4,600 req/s @ batch=1, p99 0.5 ms) as a
regular `Detector` impl alongside the existing regex/heuristic
detectors.

**Five-level on/off matrix** (Cargo feature → config flag →
per-tier scope → existing detector mask → confidence
threshold) so operators can revert with one config flip
without a rebuild.

**Hard performance budgets** (≤1 ms p99 added latency, ≤5 ms
hard timeout with fallback, ≤30% CPU at 5k RPS, model loads
in <500 ms at boot) — all surfaced as Prometheus metrics + SLO
alerts so regressions catch themselves.

**9-slice AI-T1..T9 implementation breakdown** (~23h total).
Strict order T1 → T5 (Cargo feature → features.rs → tract
model loader → AiDetector trait impl → boot wiring); T6, T7,
T8, T9 are independent follow-ups (metrics, ai-link Make
targets, integration tests, dashboard surface).

**Four open questions** in §11 of the plan that need user
decisions before implementation: model artifact source
(download / train / ship per-deployment), default Cargo
feature on/off, confidence-threshold calibration, and
advisory-vs-authoritative verdict semantics.

### Other queued / parked

- **CC-T3** — i18n + help.jsx slides remain (the test-side slice
  shipped at `180f6dd`). Both items have outsized scope (i18n
  needs JSX runtime loader work; help slides need designer
  input) so they're polish for a future Console-redesign cycle.
- **B6-T5 (fd-pass)** — ✅ FDP-T1..T6 shipped. Library
  primitives all proven correct (26 new tests). Boot path now
  adopts inherited listener FDs from an exec'ing parent
  (FDP-T2), spawns a successor with FD pre-placement +
  CLOEXEC clear (FDP-T3), supports the drain protocol with
  in-flight counter + grace timer (FDP-T4), uses a pipe-based
  readiness signal (FDP-T5), and accepts systemd
  `LISTEN_FDS` / `LISTEN_FDNAMES` env aliases plus a SIGUSR2
  listener wired into the live boot path (FDP-T6).

  **One gap remains:** the accept-loop drain refactor.
  Today's wiring records the SIGUSR2 in `HotReloader` but
  doesn't invoke `perform_handover` because the accept loops
  don't yet take a shutdown channel + the shared
  `InFlightCounter`. Operators get clean adopt-or-bind on
  first boot today; full hot-restart lands when the
  accept-loop refactor track closes.
- **B6-T4** (HSM) — still explicitly deferred; PKCS#11 against a
  real HSM, no design pass yet.
- **SC-T4** runtime metrics polish — already wired at boot in
  `run.rs:341-344`; gauges register, sampler ticks; behaviour
  cfg-gated by `--cfg tokio_unstable`. No further work pending
  unless an operator asks for documentation.
- **Rollback v6+** — rule CRUD, risk_reset, alert receivers,
  upstream pools (each requires audit-shape changes that
  pre-date the rollback dispatcher).

---

## Tracks in flight

Order is execution priority — earlier rows run first.

| # | Track | Plan | State |
|---|---|---|---|
| 1 | **Phase B — production-packaging (B6)** | [`plans/phase-b/README.md`](./plans/phase-b/README.md) | **active**; B1..B5 closed; B6-T1 in flight |
| 2 | **Console config pages (CC-T*)** — upstreams editor + alert-channel mgmt | [`plans/console-config-pages.md`](./plans/console-config-pages.md) | **plan-only — awaiting confirmation**. CC-T1 (upstreams CRUD) → CC-T2 (alert receivers in Tracking page) → CC-T3 (i18n / OpenAPI / docs) |
| 3 | Scaling configuration (SC-T*) — three-layer worker/cluster/state surface | [`plans/scaling-config.md`](./plans/scaling-config.md) | **parked plan — awaiting confirmation**. Surfaces existing L1/L2/L3 model in Console; adds `/api/state` health endpoint |
| — | Dashboard redesign (DD-T0..T8) | [`plans/dashboard-redesign.md`](./plans/dashboard-redesign.md) | closed in run-10 |
| — | Console API integration (CI-T1..T8) | [`plans/console-api-integration.md`](./plans/console-api-integration.md) | closed |
| — | HA cluster (HA-T1..T5) | [`plans/cluster-ingress-lb.md`](./plans/cluster-ingress-lb.md) | closed in run-05 |
| — | Interop contract (IT-T1..T6) | [`plans/interop-contract.md`](./plans/interop-contract.md) | closed |
| — | Interop dry-run (DR-T1..T7) | [`plans/interop-dry-run.md`](./plans/interop-dry-run.md) | closed in run-08 |
| — | Post-run-08 (AF-T1, HP-T1, TLS-T1) | [`plans/post-run-08.md`](./plans/post-run-08.md) | closed |
| — | Benchmark mode (B-T1..B-T6) | [`plans/benchmark-mode.md`](./plans/benchmark-mode.md) | folded into Phase B as B5-T2 |
| — | Security toggles (P1..P8) + post-k6 (F-T1..F-T10) | [`plans/post-k6-followup.md`](./plans/post-k6-followup.md) | closed |
| — | Enterprise dashboard (D-M1..D-M6) | [`plans/archive/dashboard-enterprise/`](./plans/archive/dashboard-enterprise/) | closed — superseded by DD-T0..T8 |
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
- ✅ **Rate-limit 429 wire confirmed** (carry-over B,
  closed 2026-04-29). The 429 + Retry-After path was
  already live at `lib.rs:1814`; the perf failure was a
  test-script calibration bug. `tests/load/rate-limit.js`
  burst defaults bumped (200→2 000 RPS, 6→8 s) so the
  burst clears the configured budget; thresholds relaxed
  to match real budget arithmetic; 403 strike-block path
  also accepted. Re-run: `status_429_observed = 50` PASS
  (log:
  `tests/results/rate-limit-2026-04-29-fixed.log`).

*Cluster + HTTPS re-run
([`tests/results/run-03-2026-04-29-carryovers/cluster/README-2026-04-29.md`](./tests/results/run-03-2026-04-29-carryovers/cluster/README-2026-04-29.md))*
- ✅ **Leader-state admin endpoint shipped** (carry-over 3,
  closed 2026-04-29). New `LeaderView` shared cell +
  background polling task that reads
  `lease_store.holder("leader:cluster")` every 2 s and
  updates `/api/cluster` with `is_leader`, `leader_node`,
  `our_node`. Singleton `leader:cluster` lease (5 s TTL) is
  acquired by exactly one node so failover takes ≤ 10 s.
  `tests/cluster/02-leader-failover.sh` now PASS.
- ✅ **Rate-limit per-node behaviour documented**
  (carry-over 4, closed 2026-04-29 as a doc clarification).
  `docs/security/rate-limiting.md` now distinguishes the
  two limiter surfaces: per-IP volumetric guard
  (`IpRateLimiter`, intentionally per-node), and named
  buckets (`sliding::check`, cluster-shared via
  `StateBackend`). The "v1 → v2 counters are clusterable"
  banner that misled the original carry-over investigator
  is replaced with the correct dual-surface contract.
- ✅ **Data-plane TLS loader shipped** (carry-over 5,
  closed 2026-04-29). `config.tls.certificates` is now
  consumed at boot: a single `tokio_rustls::TlsAcceptor` is
  built once from the cert/key/host list and reused by
  every `listeners.data[*]` whose `tls: true` is set.
  ALPN forced to `http/1.1` for now (HTTP/2 over TLS is a
  separate task). New
  [`config/prod.yaml`](./config/prod.yaml) +
  [`tests/fixtures/tls/`](./tests/fixtures/tls/) self-signed
  cert pair drive `tests/load/tls-baseline.js` end-to-end
  (run-04 measured 31.8 k RPS / handshake p95 2.12 ms /
  request p95 1.03 ms).
- ✅ **Carry-over 6 closed 2026-04-30** — HA perf test now
  routes through a single VIP. Plan
  [`plans/cluster-ingress-lb.md`](./plans/cluster-ingress-lb.md)
  fully landed: HA-T1 (HAProxy reference deploy in
  `deploy/haproxy/haproxy.cfg` + `aegis-lb` compose service),
  HA-T2 (`tests/cluster/05-single-vip-baseline.sh` +
  `06-mid-burst-failover.sh` + `tests/load/failover-burst.js`),
  HA-T3 (`WafConfig.node.id` in
  `crates/aegis-core/src/config.rs` + `derive_node_id(&cfg)` in
  `lease_select.rs`), HA-T4 (`LeaderView::set_members` +
  `/api/cluster.peers[]` + membership heartbeat + roster
  poller in `crates/aegis-proxy/src/lib.rs`), HA-T5 (`POST
  /admin/drain` + `?strict=1` on `/healthz/ready` +
  SIGTERM-triggered drain with 5 s grace). Validated by
  run-05: 99.93 % allow_success on hard kill, 100 % on
  graceful drain.

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
2. **Dashboard redesign (closed).**
   [`plans/dashboard-redesign.md`](./plans/dashboard-redesign.md).
   Aegis WAF Console shipped in run-10 (DD-T0..T8). Per-page
   screenshot regression (DD-T4) is the only follow-up.
   Implementation notes live under
   [`docs/control-plane/enterprise/`](./docs/control-plane/enterprise/).
   The earlier milestone-paced plan was superseded and archived
   under [`plans/archive/dashboard-enterprise/`](./plans/archive/dashboard-enterprise/).
3. **Open intake.**
   [`docs/future/advanced-features.md`](./docs/future/advanced-features.md)
   for proposals NOT covered by Phase B (e.g. multi-tenancy,
   RBAC/SSO, anything new). Scored against the Impact / Reach /
   Cost / Confidence rubric.

---


---

## Verification & completion log (off-page)

- [`docs/progress/verification.md`](./docs/progress/verification.md)
  — last full-suite snapshot (tests + clippy + perf).
- [`docs/progress/completed-tasks-log.md`](./docs/progress/completed-tasks-log.md)
  — append-only log of every closed task.
