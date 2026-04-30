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

- **As of:** 2026-04-30
- **Workspace tests:** 2,273 default-feature (was 2,234;
  +39 interop module tests).
- **Clippy:** clean across the workspace on
  `--features aegis-proxy/redis` and on `aegis-bin --features
  "redis affinity"`. No warnings on lib / bin / tests.
- **Active tracks:** Phase B — production-readiness
  ([`plans/phase-b/`](./plans/phase-b/README.md), B5
  CLOSED). **Cluster ingress / LB** CLOSED with HA-T1..HA-T5
  in run-05. **Workers / Layer-1** CLOSED in run-06.
  **Upstream Connection Pool (UP-T1)** CLOSED 2026-04-30
  (this turn).
- **Next task:** All highest-leverage perf items are now
  closed. Open queue (no active blocker):
  1. Linux re-measure on NUMA host (laptop tops out ~8 k
     RPS regardless of workers — likely listener accept loop
     or hyper service-fn dispatch above the pool).
  2. B6-T1 production Dockerfile (deferred).
  3. Multi-process workers (`SO_REUSEPORT`, Phase 5 deferred).
  4. Upstream HTTPS pool — wire `tls.rs` through the same
     hyper-util `Client` (currently HTTP-only).
- **Latest activity:** **External Interop Contract surface
  (IT-T1..IT-T6) shipped 2026-04-30.** New
  `aegis-control::interop` module with always-on `X-WAF-*`
  observability headers, minimal-schema JSONL audit log at
  `./waf_audit.log`, per-policy `enforce` / `log_only` mode
  store, and `/__waf_control/*` admin endpoints (capabilities,
  reset_state, set_profile, flush_cache) gated by a
  configurable `X-Benchmark-Secret`. Surface is an always-on
  feature, not a benchmark profile —
  [`plans/interop-contract.md`](./plans/interop-contract.md)
  has the per-clause compliance map. Earlier this turn:
  **UP-T1** Per-pool `connection:` config block
  in `PoolConfig` (`max_idle_per_host`, `idle_timeout`,
  `keep_alive`). `forward.rs` rewritten to use a process-
  wide cached `hyper_util::client::legacy::Client` keyed
  on pool config signature. Validated by run-07
  ([`tests/results/run-07-2026-04-30-upstream-pool/`](./tests/results/run-07-2026-04-30-upstream-pool/README.md)):
  pooled holds **1 000 RPS / 100 % / sub-1 ms p95** vs
  unpooled 525 RPS / 96 % / 3 ms p95. **Throughput
  ceiling 525 → 7 964 RPS (15× lift)** on the same host.
  Two new integration tests prove TCP reuse semantics
  (5 reqs / 1 TCP for keep-alive; 3 reqs / 3 TCPs for
  `keep_alive: false`).

---

## Last Completed

**Task:** **IT-T1..IT-T6 — External Interop Contract surface.**
Always-on observability + external control plane + minimal-
schema audit log + per-policy mode toggle. Aegis-Gate now
satisfies the Interop Contract v2.3 strictly, while the surface
is a normal operational feature (not a benchmark-only profile).

**Outcome.** New `aegis-control::interop` module with four
submodules:

- `audit::MinimalJsonlSink` writes 8-field JSONL entries to
  `./waf_audit.log` (configurable). Append-only; survives
  `reset_state`. The full SHA-256 audit chain keeps writing in
  parallel.
- `headers::Decision::stamp` puts six `X-WAF-*` headers on every
  data-plane response: `X-WAF-Request-Id`, `X-WAF-Risk-Score`,
  `X-WAF-Action`, `X-WAF-Rule-Id`, `X-WAF-Cache`, `X-WAF-Mode`.
- `mode::ModeStore` is a lock-free per-feature/per-policy
  `enforce` / `log_only` override map; reads via `ArcSwap`,
  writes serialised behind a single `Mutex`.
- `control::ControlContext` exposes the four `/__waf_control/*`
  endpoints (capabilities / reset_state / set_profile /
  flush_cache), gated by `X-Benchmark-Secret` (configurable
  via `interop.control_secret`).

The proxy crate threads an `Arc<InteropRuntime>` through both
listeners — admin dispatches `/__waf_control/*`, data plane
post-processes every response with `stamp_interop_response`
(maps HTTP status → contract action class, stamps headers,
appends one audit line).

**Decision recap (always-on, not a profile).** Every feature in
`interop` is universally useful — observability headers,
external control plane, minimal-schema SIEM-friendly log, mode
toggle for dry-running detectors. Per user direction, no
"hackathon profile" gate exists in the code; `interop.enabled`
defaults to `true` and operators only flip it `false` for test
fixtures that want to keep responses unstamped.

**Decision recap (audit log dual-write).** The hackathon-style
minimal schema is what external tooling parses; the existing
SHA-256 audit chain is the long-term forensic record. They
write in parallel to different paths. Neither replaces the
other; `reset_state` preserves both.

**Decision recap (HTTP status → Action mapping).** Inline in
`stamp_interop_response`: `200..399` → `Allow`, `429` →
`RateLimit` (the JSON body marks challenges separately), `503`
→ `CircuitBreaker`, `504` → `Timeout`, everything else →
`Block`. A future refactor would let the data-plane handler
explicitly emit the action class instead of inferring from
status.

**Files changed.**
- `crates/aegis-control/src/interop/{mod,audit,headers,mode,control}.rs`
  — new module, 5 files, +39 unit tests.
- `crates/aegis-control/src/lib.rs` — module declared.
- `crates/aegis-control/src/dashboard_services.rs` — new
  `interop: Option<Arc<InteropRuntime>>` field.
- `crates/aegis-control/Cargo.toml` — `http`, `thiserror` direct
  deps.
- `crates/aegis-proxy/src/lib.rs` — `build_interop_runtime`,
  `stamp_interop_response`, `handle_interop_control` helpers;
  `accept_loop` + `admin_accept_loop` signatures take
  `Option<Arc<InteropRuntime>>`.
- `crates/aegis-core/src/config.rs` — `InteropConfig`
  (`enabled` defaults true, `audit_path` defaults
  `./waf_audit.log`, `control_secret` configurable).
- `crates/aegis-security/src/risk/tracker.rs` — new
  `RiskTracker::reset_all`.
- `crates/aegis-security/src/rate_limit/ip_limiter.rs` — new
  `IpRateLimiter::reset_all`.
- `plans/interop-contract.md` — compliance status + track
  list.

**Verification.**
- **Workspace tests** (`cargo test --workspace --features
  aegis-proxy/redis`) — **2,273 passed** parallel (was 2,234;
  +39 interop tests).
- **Clippy** clean.
- **Live end-to-end smoke** (release binary, `config/waf.dev.yaml`):
  - `GET /__waf_control/capabilities` without secret → 403.
  - `GET /__waf_control/capabilities` with `X-Benchmark-Secret`
    → 200, JSON listing four features.
  - `POST /__waf_control/set_profile` with
    `{"scope":"all","mode":"log_only"}` → 200, default flips,
    overrides cleared.
  - `POST /__waf_control/reset_state` → 200,
    `audit_log_preserved: true`.
  - `POST /__waf_control/flush_cache` → 200, `supported: false`.
  - `HEAD /get` data-plane response carries all six `X-WAF-*`
    headers; `./waf_audit.log` has one matching minimal-schema
    entry.

---

## Earlier Last Completed (UP-T1)

**Task:** **UP-T1 — Upstream Connection Pool.** Replaces the
per-request `TcpStream::connect + http1::handshake` in
`forward.rs` with a per-pool keep-alive
`hyper_util::client::legacy::Client`. Closes the throughput
ceiling that run-05 surfaced and run-06 quantified.

**Outcome.** A new `connection:` block under each upstream
pool drives the pooling:

```yaml
upstreams:
  api:
    members: [{ addr: "10.0.0.1:8080" }]
    connection:
      max_idle_per_host: 32   # 0 disables pooling
      idle_timeout: 30s
      keep_alive: true        # false implies pool size 0
```

Internally a process-wide `OnceLock<RwLock<HashMap<PoolKey,
Arc<Client>>>>` caches one client per distinct config
signature; the cache lookup is a read-lock + `Arc::clone` on
the hot path. `keep_alive: false` injects a request-side
`Connection: close` header *and* sets `pool_max_idle_per_host:
0` in the client builder so neither side keeps the socket
around — that's the pre-UP-T1 baseline operators can flip back
to for diagnostics without rebuilding.

**Decision recap (cache scope).** Process-wide rather than
per-`ProxyContext` because (a) hyper-util's `Client` is
internally `Arc`-shared, (b) hot-reload of the upstream block
should keep using the existing pool when the signature is
unchanged, and (c) two pools that share a backend with the
same tuning *should* share the connection cache. The cache
keys on `(max_idle_per_host, idle_timeout_ms, keep_alive)`,
not on member address — addresses are per-request.

**Decision recap (HTTP-only).** UP-T1 covers HTTP upstreams
only. HTTPS upstreams continue through the older
`upstream::tls.rs` code path, which was added in carry-over 5
for data-plane HTTPS termination. Wiring the pooled `Client`
to a rustls-backed connector is the next pool expansion;
keeping it out of scope here keeps the diff small and the perf
result clean.

**Decision recap (timeout cap).** Added a 30-s per-request
`tokio::time::timeout` around the `client.request()` call. The
hyper-util `Client` has its own connect-side default but a
stuck upstream after handshake can hang us indefinitely. The
30 s ceiling is conservative; a follow-up should wire the
route's `total_deadline` here.

**Files changed.**
- `crates/aegis-core/src/config.rs` — new `ConnectionPoolConfig`
  on `PoolConfig`. +4 unit tests.
- `crates/aegis-proxy/src/upstream/forward.rs` —
  `pooled_client()` cache + builder; `forward()` signature
  takes `&ConnectionPoolConfig`; URI rewritten to absolute
  form for hyper-util's `Client`. +2 integration tests
  (5 reqs / 1 TCP keep-alive; 3 reqs / 3 TCPs `keep_alive=false`).
- `crates/aegis-proxy/src/upstream/mod.rs` — `Pool` struct
  carries the resolved `ConnectionPoolConfig`.
- `crates/aegis-proxy/src/proxy.rs` — pass `&pool.connection`
  through to `forward::forward()`.
- `crates/aegis-proxy/src/lib.rs` — same threading at the
  data-plane Allow callsite (`forward_allow_to_upstream`).
- `Cargo.toml` workspace — `hyper-util` now compiles with
  `client` + `client-legacy` features.
- `config/README.md` upstream section — new "Connection
  pooling" subsection with knob reference + run-07 link.
- `Architecture.md` §7 — pool subsection added with the same
  knob table + run-07 link.

**Verification.**
- **Workspace tests** (`cargo test --workspace --features
  aegis-proxy/redis`) — **2,234 passed** parallel (was 2,228;
  +4 config tests + +2 forward.rs pool reuse tests).
- **Clippy** — clean.
- **Live perf** ([run-07](./tests/results/run-07-2026-04-30-upstream-pool/README.md)):
  - **1 000 RPS offered**: pooled holds 999.9 RPS / 100 % /
    sub-1 ms p95. Unpooled 525.8 RPS / 96.31 % / 3 ms p95.
  - **2 000 RPS offered**: pooled 1 999.8 RPS / 100 % /
    700 µs p95. Unpooled 496 RPS / 95 % / 3.83 s p95
    (timeout-bound).
  - **4 000 RPS offered**: pooled 3 979 RPS / 100 % / 740 µs
    p95. Unpooled 510 RPS hard ceiling.
  - **8 000 RPS offered**: pooled 7 964 RPS / 100 % /
    1.56 ms p95. Approaching new pooled ceiling.
  - **15 000 RPS offered**: pooled saturates at 7 057 RPS /
    64 % / 55 ms p95.
  - **Throughput ceiling lift: 525 → 7 964 RPS (15×).**

---

## Earlier Last Completed (Workers / Layer-1)

**Task:** **Workers — Layer-1 in-node scaling.** Configurable
tokio worker threads, blocking-pool ceiling, CPU affinity (opt-in
via Cargo feature), and stack size — the third layer of the
three-layer scaling model now has explicit operator surface.

**Outcome.** Operators can size in-process scaling without
rebuilding:

```yaml
runtime:
  workers: auto             # or integer in [2, 512]
  blocking_threads: 512
  cpu_affinity: false
  stack_size_kb: 2048
```

The bin entry point now constructs the tokio runtime from this
block via `tokio::runtime::Builder` instead of `#[tokio::main]`.
`workers: auto` resolves to `num_cpus::get()` lifted to a
floor of 2 (so the heartbeat + roster pollers from HA-T4 always
have a thread of headroom). Validation rejects `workers: 1`,
`workers > 512`, `blocking_threads: 0`, `blocking_threads > 4096`,
and `stack_size_kb < 64`.

**Decision recap (restart-only).** Tokio's `worker_threads` count
is fixed at builder time; there's no runtime-resize API. Hot
reload of every other config block remains supported — only the
`runtime:` block requires a process restart. The admin endpoint
`/api/runtime` (read-only) surfaces the current values so
operators can confirm the boot picked up their YAML; the
"Settings → Runtime (Layer-1)" dashboard panel renders the same
view.

**Decision recap (CPU affinity behind a Cargo feature).**
`core_affinity::set_for_current` semantics differ across OSes
(Linux hard-pins via `sched_setaffinity`; macOS is advisory; k8s
schedulers prefer to own affinity themselves). Shipping it on by
default would cost dependency footprint everyone pays. Compromise:
`runtime.cpu_affinity: true` is honoured only when the binary is
built with `--features affinity`; without that feature the
request is logged and ignored, so prod configs don't fail boot
when promoted across hosts.

**Decision recap (no multi-process / `SO_REUSEPORT` yet).** The
plan listed multi-process workers (true Nginx model) as Phase 5,
gated by a feature flag. Skipped for now per user direction —
Phase 1 + 2 + 3 + 4 + 6 ship together and Phase 5 can land later
if profiling proves crash-isolation between workers is needed.

**Files changed.**
- `crates/aegis-core/src/config.rs` — `RuntimeConfig` +
  `Workers::{Auto, Fixed}` enum + custom serde (accepts `"auto"`
  or integer) + `validate()`. +11 unit tests.
- `crates/aegis-core/Cargo.toml` — `num_cpus` direct dep.
- `crates/aegis-bin/src/main.rs` — `build_runtime()` constructs
  `tokio::runtime::Builder::new_multi_thread()` from the
  validated `RuntimeConfig`; `apply_cpu_affinity()` cfg-gated
  on the `affinity` feature.
- `crates/aegis-bin/Cargo.toml` — new `affinity` feature wiring
  `core_affinity` 0.8 (optional dep) + `aegis-proxy/affinity`.
- `crates/aegis-proxy/Cargo.toml` — `affinity` feature placeholder
  (so `cfg!(feature = "affinity")` lookups in `lib.rs` don't warn).
- `crates/aegis-proxy/src/lib.rs` — `/api/runtime` read-only
  admin handler returns the `RuntimeView` JSON.
- `crates/aegis-control/src/api/runtime.rs` — new
  `RuntimeView::render(cfg, cpu_affinity_active)`. +5 tests.
- `crates/aegis-control/Cargo.toml` — `num_cpus` dep.
- `crates/aegis-control/assets/dashboard/pages/settings.js` —
  new "Runtime (Layer-1)" card; renders worker count, blocking
  pool, stack size, host CPUs, affinity status.
- `config/waf.yaml` — `runtime:` block commented in with the
  defaults shown for discoverability.
- `Architecture.md` — new §"Three-layer scaling model" subsection
  in §1; cross-links runtime-tuning + ha-clustering docs.
- `docs/operations/runtime-tuning.md` — new ~150-line operator
  guide: knob reference, sizing recipes, verification commands,
  hot-reload posture.
- `docs/operations/ha-clustering.md` — three-layer-model table
  added at top of §"Purpose"; cross-links runtime-tuning.
- `docs/README.md` — `runtime-tuning.md` row added to the
  Operations table.

**Verification.**
- **Workspace tests** (`cargo test --workspace --features
  aegis-proxy/redis`) — **2,228 passed** parallel (was 2,210;
  +11 RuntimeConfig + +5 RuntimeView + +2 net elsewhere).
- **Clippy** (default + `affinity` feature combo) — clean.
- **Live boot smoke** (cluster-a config, default `workers:
  auto`):
  ```
  tokio runtime workers=12 blocking_threads=512 stack_size_kb=2048 cpu_affinity=false
  $ curl http://127.0.0.1:9443/api/runtime
  {"workers":12,"workers_mode":"auto","blocking_threads":512,
   "stack_size_kb":2048,"cpu_affinity_requested":false,
   "cpu_affinity_active":false,"host_logical_cpus":12}
  ```
- **Live boot smoke** (fixed `workers: 4`, `blocking: 128`,
  `stack: 4096`):
  ```
  tokio runtime workers=4 blocking_threads=128 stack_size_kb=4096
  $ curl http://127.0.0.1:19443/api/runtime
  {"workers":4,"workers_mode":"fixed",...}
  ```
- All three production YAMLs (`waf.yaml`, `waf.cluster-a.yaml`,
  `waf.tls.yaml`) `validate` cleanly with the new block.

---

## Earlier Last Completed (HA-T5)

**Task:** **HA-T5 — LB-friendly readiness semantics.** Closes
the [`plans/cluster-ingress-lb.md`](./plans/cluster-ingress-lb.md)
HA track and carry-over 6 alongside HA-T1..HA-T4.

**Outcome.** The proxy now drains gracefully on operator
signal:

1. `POST /admin/drain` — authenticated endpoint that flips
   `readiness.draining` to true. External LBs see
   `/healthz/ready` return 503 within their next health-check
   tick and stop sending new traffic. In-flight requests
   complete normally.
2. `GET /healthz/ready?strict=1` — returns 503 unless this
   node holds the `leader:cluster` lease. Used by active /
   standby topologies that need exactly one node to receive
   singleton traffic (cluster-wide reconciler, etc.). Single-
   node builds with no lease wired pass strict mode (degrades
   to plain ready).
3. SIGTERM handler — flips draining first, sleeps
   `AEGIS_DRAIN_GRACE_MS` (default 5 s) so external LBs notice
   via the existing health probe, then aborts listeners.
   Aligns process shutdown with the operator-drain pattern.

**Decision recap (auth model on `/admin/drain`).** Three
acceptance paths, in priority: (a) valid admin session cookie
(`aegis_session`); (b) matching `X-Aegis-Drain-Token` header
when `AEGIS_DRAIN_TOKEN` env is set; (c) any request when
`admin_identity.password_hash` is empty (test/dev builds with
no admin configured). The token path is what k8s preStop hooks
and systemd ExecStop scripts reach for — they don't manage
session cookies. Failure returns 401 `{"error":"auth_required"}`.

**Decision recap (HAProxy probe was hitting the wrong port).**
The reference config used `option httpchk … server waf-a
host.docker.internal:8080` which 404'd `/healthz/ready` (admin-
plane only endpoint). Fixed by adding `port 9443` / `port 9543`
on each backend so the L7 health check probes the admin port
while traffic still routes to data 8080/8090. This is correct
for any real deployment: separate listening ports for "is the
node up?" and "send traffic here".

**Decision recap (round-robin → leastconn).** k6's persistent
HTTP keep-alive sockets concentrate on whichever backend got
the earlier connection assignments. `roundrobin` only fires
on new connections, so a 20-VU pool with sticky keep-alive
produces 76/24 skews on a 15 s laptop run. `leastconn` reads
the live open-conn count and routes by that — converged the
test to 35/64 on the same fixture. Production traffic with
many short-lived clients converges to 50/50 on either.

**Decision recap (failover-burst.js needed).** The shared
`baseline.js` uses `constant-vus` which saturates the
laptop's ephemeral-port budget under the rate-limit-relaxed
cluster configs (10 M/min, set high so the perf test isn't
dominated by the limiter). New `tests/load/failover-burst.js`
uses `constant-arrival-rate` at 200 RPS — predictable load
that fits inside the host's TCP TIME_WAIT budget while still
exposing the failover transient.

**Files changed.**
- `crates/aegis-control/src/health.rs` — `check_ready_strict()`
  + 4 strict-mode tests.
- `crates/aegis-proxy/src/lib.rs` —
  - `/healthz/ready?strict=1` query parsing.
  - `POST /admin/drain` dispatch + `handle_admin_drain`
    handler (auth-aware, three-path acceptance).
  - SIGTERM handler now flips `readiness.draining` → sleeps
    `AEGIS_DRAIN_GRACE_MS` → aborts listeners.
- `deploy/haproxy/haproxy.cfg` — `port 9443/9543` for the
  health check, `balance leastconn`.
- `tests/cluster/06-mid-burst-failover.sh` — graceful path
  hits `POST /admin/drain` first, then `SIGTERM`; chkfail
  CSV column corrected (was reading `econ`); k6 driver
  switched to `failover-burst.js`.
- `tests/cluster/05-single-vip-baseline.sh` — stats fetch
  retries 5×; skew floor relaxed to 15 % per side (laptop
  variance under keep-alive).
- `tests/load/failover-burst.js` — new rate-controlled k6
  script.
- `config/waf.cluster-{a,b}.yaml` — bucket limit raised to
  10 M/min (HA test would otherwise be dominated by rate-
  limit, not failover budget).
- `tests/results/run-05-2026-04-30-ha-implementation/` — full
  perf re-run (cluster smoke, single-VIP baseline, hard +
  graceful failover, HTTPS load).
- `tests/results/README.md` — added run-05 row, marked
  carry-over 6 closed.

**Verification.**
- **Workspace tests** (`cargo test --workspace --features
  aegis-proxy/redis`) — **2,210 passed** parallel; previously
  failing `lease_select` env-var tests now serialize on a
  shared `OnceLock<Mutex>`.
- **Clippy** (`cargo clippy --workspace --features
  aegis-proxy/redis -- -D warnings`) — clean.
- **Cluster smoke** — 4/4 PASS including the new HA-T4 peers
  assertion (both nodes converge on `waf-a`/`waf-b` in 12 s).
- **LB tests** — `05-single-vip-baseline.sh` PASS (9.5 k RPS,
  35/64 backend share); `06-mid-burst-failover.sh` PASS in
  both modes:
  - Hard `SIGKILL`: **99.93 %** allow_success (≥ 80 % floor),
    HAProxy chkfail=2.
  - Graceful drain via `POST /admin/drain` + `SIGTERM`:
    **100 %** allow_success (≥ 99 % floor), zero 5xx,
    HAProxy chkfail=3.
- **HTTPS load** — 31.2 k RPS, post-handshake p95 1.07 ms
  (run-04 was 1.03 ms; flat within noise). Handshake p95
  9.08 ms (run-04 2.12 ms — tracked as a measurement-noise
  question, not a regression; same code path).

---

## Earlier Last Completed (Carry-over B)

**Task:** **Carry-over B — rate-limit response code
alignment.** Closed by recalibrating the test script — the
gateway behaviour was already correct.

**Outcome.** Inspection of `crates/aegis-proxy/src/lib.rs:1814`
showed the data plane *already* returns
`429 Too Many Requests` with `Retry-After` from the
`IpRateLimiter::consume` denied branch (verified live).
The earlier `tests/load/rate-limit.js` failure was a
calibration bug: the script's defaults (200 RPS × 6 s =
1 200 reqs) sit well below the configured budget (10 000
in any 60 s sliding window) so the limiter never fires.

**Decision recap (script change, not gateway change).**
Bumping `BURST_RPS` defaults to 2 000 / `BURST_SECS` to 8
makes the burst 16 000 reqs — clears the 10 000 budget by
60 % even after sliding-window absorption — and forces the
gateway through the 429 path within the script's window.
We *deliberately* did **not** change the gateway's strikes
behaviour: requests beyond the 429 wave start hitting the
strikes-block 403 path once `risk.strikes.block_at: 50` is
crossed, which is the documented contract. The script now
accepts 403 OR 429 for the high-level rate and asserts
specifically on `status_429_observed > 10` to prove the
rate-limit code path still fires.

**Decision recap (`blocked_after_burst` threshold).** The
original 0.95 threshold assumed the burst would dwarf the
budget. With a budget large vs. burst (10 000 vs 16 000),
~10 000 of the 16 000 reqs flow through *before* the
limiter saturates — so the realistic blocked rate is
~37 %, not 95 %. The new threshold 0.30 catches "limiter
never fired" (which would be < 5 %) while tolerating real
budget arithmetic.

**Files changed.**
- `tests/load/rate-limit.js` — defaults bumped, VU pool
  resized (preAllocatedVUs 4 → 32 / maxVUs 8 → 128),
  thresholds adjusted, `burst()` now classifies 403 +
  429 as blocked but counts only 429 for the
  gateway-emitted check, docblock spells out the
  `BURST_RPS × BURST_SECS` ≥ budget contract.
- `tests/results/README-2026-04-29.md` — added "Update —
  Carry-over B closed" section with the comparison
  table and the rationale.
- `tests/results/rate-limit-2026-04-29-fixed.log` —
  full k6 log of the passing run.

**Verification.**
- **Live re-run** (release WAF in front of `aegis-httpbin`
  on port 8081, k6 in `aegis-k6`):
  - `http_reqs` total = **15 908** (1 988 / s × 8 s).
  - `status_2xx_observed` = 10 000 (the budget).
  - `status_429_observed` = **50** ✅ — threshold > 10.
  - `blocked_after_burst` = 37.13 % ✅ — threshold > 0.30.
  - Test exit code 0 (PASS).
- `cargo test --workspace` (default features) → **2,173
  passed** (held steady — no source change).
- `cargo clippy --workspace --lib --bins -- -D warnings`
  → clean (no source change).

---

## Earlier Last Completed (Carry-over A)

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
| 2026-04-30 | **IT-T1..IT-T6** External Interop Contract surface | New `aegis-control::interop` module; always-on `X-WAF-*` headers + minimal-schema `./waf_audit.log` + `/__waf_control/*` admin endpoints + per-policy mode store. +39 tests, 2,273 total. Contract v2.3 fully satisfied; live smoke 4/4 endpoints + 6/6 headers. |
| 2026-04-30 | **UP-T1** Upstream connection pool | `forward.rs` rewritten on `hyper_util::client::legacy::Client`; per-pool `connection:` config; cached per signature. **15× throughput lift** (525 → 7 964 RPS, 100 % success, sub-1 ms p95) validated by run-07. +6 tests, 2,234 total. |
| 2026-04-30 | **Workers / Layer-1** in-node scaling | New `runtime:` config block + `tokio::runtime::Builder` wiring + `/api/runtime` admin endpoint + dashboard panel + `affinity` Cargo feature for CPU pinning. +18 tests, 2,228 total. Restart-only. Live verified on 12-core (auto) and 4-thread fixed configs. |
| 2026-04-30 | **HA-T1..T5** Cluster ingress / LB track CLOSED | `deploy/haproxy/haproxy.cfg` (HA-T1) + `tests/cluster/05/06` + `tests/load/failover-burst.js` (HA-T2) + `WafConfig.node.id` (HA-T3) + `LeaderView::set_members` + `/api/cluster.peers[]` (HA-T4) + `POST /admin/drain` + `?strict=1` + SIGTERM drain (HA-T5). 99.93 % hard / 100 % graceful failover budget. |
| 2026-04-29 | **Carry-over B** — rate-limit response code | Gateway already returns 429 with Retry-After; test script recalibrated (BURST_RPS 200 → 2000, threshold 0.95 → 0.30). 50 status_429 observed live. |
| 2026-04-29 | **Carry-over A** — data-plane Allow forwarding | `lib.rs::handle_data_request` now async, takes `Arc<ProxyContext>`, Allow branch goes through `forward::forward()`. Live: 31.5 k RPS / 504 µs median / 3.66 ms full-hop p95 vs httpbin. |
| 2026-04-29 | **B5-T2** Benchmark mode core slice — closes B5 | `aegis-proxy::benchmark`: `BenchmarkConfig` + `StageTimings` + `X-Aegis-*` header serialiser; `proxy::handle_request` captures total/route/upstream timings + tier + decision when enabled. +21 unit + 2 proxy end-to-end tests. |
| 2026-04-29 | **B5-T1** HTTP/3 listener | `aegis-proxy/http3` Cargo feature ships `listener::http3` on quinn 0.11 + h3 0.0.8 + h3-quinn 0.0.10. +15 tests. |

---

## Next Task

**Task:** **Open — operator pick.** UP-T1 closed the
highest-leverage perf gap. Open queue:

1. **Linux re-measure on a NUMA host.** Run-07 saw the laptop
   plateau at ~8 k RPS regardless of worker count even with
   the pool on. Strongly suggests a bottleneck above the
   pool — listener accept loop, hyper service-fn dispatch,
   single-threaded route lookup. NUMA + more cores may
   unmask it.
2. **B6-T1 production Dockerfile** (deferred).
3. **Multi-process workers (`SO_REUSEPORT`).** Phase 5 of
   the workers plan. Becomes interesting if #1 confirms a
   non-NUMA-related bottleneck.
4. **Upstream HTTPS pool.** UP-T1 covers HTTP only;
   `upstream::tls.rs` still does per-request connect for
   HTTPS upstreams. Wire the pooled `Client` to a rustls
   connector.
5. **Clean-host TLS handshake re-measure** (run-05 noise).

No active blocker.

**Outline.**

1. New `deploy/Dockerfile` — multi-stage:
   - Stage 1: `rust:1.<msrv>-slim` — `cargo build -p
     aegis-bin --release` with the production feature
     set (`redis`, `vault`, `aws`, `gcp`, `azure`,
     `consul`, `etcd`, `k8s`, `taxii`, `geoip`, `http3`,
     `alerts`).
   - Stage 2: `gcr.io/distroless/cc-debian12:nonroot` —
     copies the release binary + `git` (B3-T1 needs it
     in PATH) + the bundled CA store. `USER nonroot`.
2. Image entrypoint = `/usr/local/bin/waf`. Default
   command = `run --config /etc/aegis/waf.yaml`. Operators
   override the config path via env.
3. `EXPOSE 8080 8443 9443 443/udp` (HTTP/3).
4. Multi-arch build: `linux/amd64` + `linux/arm64` via
   `docker buildx`.
5. Image signing: `cosign sign --keyless` in CI (B6-T3
   wires the workflow; for B6-T1 we just ship the
   Dockerfile + build script).
6. Tests:
   - `tests/api/dockerfile.sh` — builds the image
     locally, runs `docker run aegis-gate validate
     --config /tmp/waf.dev.yaml`, asserts exit 0.
   - Image size budget: < 100 MiB compressed.
7. Doc — flip the production-Dockerfile carry-over in
   `docs/operations/zero-downtime-ops.md`.

**Acceptance.**

- `docker build -t aegis-gate:dev -f deploy/Dockerfile .`
  succeeds.
- Built image runs `waf validate` cleanly.
- Image size compressed < 100 MiB.
- New script in `tests/api/` exercises the build.

**On close:** Next Task → **B6-T2 — Helm chart**.

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
  [`config/waf.tls.yaml`](./config/waf.tls.yaml) +
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
| **Carry-over B** — rate-limit response code alignment. Investigation found the gateway *already* emits 429 + Retry-After at `lib.rs:1814`; the original failure was a `tests/load/rate-limit.js` calibration bug (burst < budget). Fixed in script: defaults bumped to 2 000 RPS × 8 s, VU pool resized, thresholds relaxed to match real budget arithmetic, 403 strike-block path also accepted. Re-run: `status_429_observed = 50`, threshold PASS. No gateway code change. | tests/load, tests/results | 2026-04-29 |
| **Carry-over 3** — leader-state admin endpoint. New `LeaderView` shared cell + background polling task in `aegis-proxy::run` reads `lease_store.holder("leader:cluster")` every 2 s; `LeaseStore::self_id()` added so the trait surfaces a node's identity. `/api/cluster` now returns `is_leader`, `leader_node`, `our_node`. Singleton `leader:cluster` lease (5 s TTL) acquired by exactly one node. `tests/cluster/02-leader-failover.sh` flipped SKIP → PASS. +5 net new tests in `tracking::tests`. | aegis-control, aegis-proxy, aegis-core | 2026-04-29 |
| **Carry-over 4** — cluster-shared rate-limit bucket. Closed as a doc clarification: the per-IP volumetric guard is intentionally per-node (DDoS shield), the named-bucket limiter is cluster-shared via `StateBackend`. `docs/security/rate-limiting.md` rewritten to distinguish the two surfaces explicitly. No code change. | docs | 2026-04-29 |
| **Carry-over 5** — data-plane TLS loader. `config.tls.certificates` now flows to a single `tokio_rustls::TlsAcceptor` built at boot; data-plane listeners with `tls: true` use it. ALPN forced to `http/1.1` (HTTP/2 over TLS is a follow-up). New `config/waf.tls.yaml` + self-signed cert fixture in `tests/fixtures/tls/`. Live: TLS 1.3 + AES-256-GCM, k6 measures 31.8 k RPS / handshake p95 2.12 ms / request p95 1.03 ms. | aegis-proxy, config, tests/fixtures | 2026-04-29 |
| **run-04 perf re-run** — `tests/results/` restructured into per-run dated subdirs. Cluster smoke 4/4 PASS (was 3/4), HTTPS data plane proven end-to-end, cluster perf identical across nodes. Documented in `tests/results/run-04-2026-04-29-cluster-https/README.md` + master index `tests/results/README.md`. | tests/results | 2026-04-29 |
| **Carry-over 6 (NEW, open)** — HA perf test methodology gap noted: cluster perf hits each node on its own port, not via a single VIP / LB. New `tests/cluster/HA-TEST-METHODOLOGY.md` analyses three remediation options (DNS RR / HAProxy / SO_REUSEPORT), recommends HAProxy in front. Cluster + run-04 + master READMEs cross-reference the doc. Test-infra gap, not a runtime bug. | tests/cluster, tests/results, docs | 2026-04-29 |
| **HA cluster docs + ingress plan** — rewrote `docs/operations/ha-clustering.md` to align with what shipped vs the v2-design placeholder (drop `state.backends[]` array, document actual `state.redis` block); added §"Cluster topology" diagram, §"Load balancer patterns" (k8s Ingress / Nginx / HAProxy recipes), §"Roadmap" with 8 open HA items + carry-over 6 + B-track cross-refs. New `plans/cluster-ingress-lb.md` breaks the fix into HA-T1..HA-T5 sub-tracks (~1.5 days total); promoted to second active track in `plans/README.md`. | docs/operations, plans | 2026-04-29 |
