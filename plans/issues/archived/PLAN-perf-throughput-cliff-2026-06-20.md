# Throughput cliff at high RPS — diagnosis correction + perf hardening plan

**Status:** Open — diagnosis revised, fixes scoped
**Filed:** 2026-06-20
**Reporter:** operator (big-traffic test, `aiagent.waf-exams.info`) + s-tester report
**Severity:** 🟡 Medium (perf hardening; not a correctness/security defect)
**Source report:** [`tests/s-tester/reports/20260620_redis_throughput_bottleneck_report.md`](../../tests/s-tester/reports/20260620_redis_throughput_bottleneck_report.md)

## TL;DR

The s-tester report is a **good, file:line-accurate review** of the Redis backend, and
every code claim in it checks out. **But its headline root cause does not apply to the
config that was actually under test.** Both per-request gates — DDoS and rate-limit —
were refactored to a **fully in-process** decision; **no `StateBackend`/Redis round-trip
sits on the synchronous hot path** in dev/cluster/prod configs. The dashboard confirms
this directly: **Redis shows 165 keys, P50 109 µs / P95 365 µs / P99 1.4 ms, circuit
closed, no replica lag** — i.e. Redis is **idle and healthy**, not a 660 k-member hot
ZSET being hammered.

The report says exactly this in its own §6 ("⚠️ phải đọc trước khi fix") and §8 row 7
("Bắt buộc: xác nhận Redis có thật sự trên hot path trước khi tối ưu"). This plan
**promotes that caveat to the headline** and re-points the work:

- The `~3,000 rps` cliff under an `~11,000 rps` offered load is **mostly a single-source-IP
  test artifact** (§6.b) hitting **one in-process hot key → one `DashMap` shard write-lock**
  serialized on one core — *not* Redis.
- That same hot-key contention is **also a real concern** for our actual threat model
  (volumetric DoS from a *few* attacker IPs — exactly what the dashboard's top-attacker
  list shows: one IP at 140 k hits), so it is worth fixing regardless of the test method.
- At ~8 k rps the box is **CPU-bound in the detector pipeline** (AI detector dominates the
  attack distribution: 119 457 of 310 008 detections), and there is **no load-shedding** —
  so once latency rises past the knee, the queue saturates and throughput collapses (the
  classic cliff), independent of Redis.

**Do the measurement gate (P0) first.** Then fix the in-process hot-key contention (P1) and
add backpressure/load-shedding (P2); the Redis-path hardening the report lists (P3) is real
and worth doing as defense-in-depth, but it is **not** what caps this test.

---

## ✅ P0 RESULTS — executed locally 2026-06-20 (root cause found)

Ran the measurement gate on this machine: release build, dev.yaml, **ddos off**
(`WAF_DDOS__ENABLED=false`), k6 closed-loop flood single source IP (127.0.0.1),
`/usr/bin/sample` CPU profiles, Redis `commandstats`/`slowlog`/`INFO clients` deltas.

**1. Redis is exonerated — not on the per-request hot path (definitive).**
While serving **1.14 M requests in 40 s (28.6 k rps benign / 29.9 k rps attack)**, Redis
saw **9 `evalsha` calls total**, `blocked_clients: 0`, 10/16 pool conns used. The only
slowlog entry was a cluster-lease heartbeat (`g:lease:members:*`). The pre-prod dashboard's
**44.9 ms Redis P50 under load is a CPU-starvation *symptom*** (the tokio runtime is too busy
to service the periodic health/lease ops), not a cause. The s-tester report's ZSET/pool
headline does not apply.

**2. The in-process rate-limiter hot key is NOT the wall.** Single source IP sustained
**~30 k rps with no cliff**; `check_local`/`RiskKey` were a rounding error in the profile
(4 / 13 samples). Single-hot-key contention (report §6.b, original P1) is **not** the
dominant cost at these rates. → **P1 downgraded.**

**3. ROOT CAUSE — the always-on interop audit sink serializes the whole data plane.**
The heaviest WAF subtree in *both* benign and attack profiles is
`aegis_control::interop::audit::MinimalJsonlSink` (1464 samples; audit-related frames
~2.4 k in both runs). It is a **single process-wide `Mutex<BufWriter<File>>` that
`flush()`es to disk on every write** (`crates/aegis-control/src/interop/audit.rs:86-95`)
and is stamped **on every request** by the *always-on* `stamp_interop_response`
(`crates/aegis-proxy/src/admin_dispatch.rs:1289, 1429`). Every worker thread serializes on
one mutex, each holding it across a blocking `flush()` syscall.

**This explains the operator's "1–2 IPs fast, 4 machines → ~1/3 throughput" report exactly:**
the wall is **aggregate offered load** (4 machines ≫ 2 machines of RPS) plus, under attack,
**one always-on audit line per request** funnelled through a single flushing mutex. As RPS
rises past the point where the mutex critical-section (write + disk `flush`) saturates, all
workers queue behind it and throughput collapses super-linearly. It is **not** distinct-IP
contention (RiskTracker + rate-limiter are `DashMap`-sharded; geo is cached) — IP count is a
proxy for aggregate load + per-request block volume.

**Why it didn't cliff locally:** macOS local-SSD `flush()` is ~µs, so the mutex section stays
short even at 30 k. Pre-prod adds (a) a slower-flushing disk, (b) **TLS** crypto, and (c)
**AI/ONNX inference** (`ai.enabled: false` locally — `aegis_ai_inference_duration` all-zero;
pre-prod runs it on an AI-dominated attack mix) — all of which lengthen how long each worker
holds resources, so the same mutex saturates at a far lower RPS (the ~11 k knee).

**Revised fix priority (supersedes the P1–P4 table below):**

| New # | Fix | Why |
|---|---|---|
| **A (Critical)** ✅ **DONE** | **Take `flush()` off the per-request path in `MinimalJsonlSink`** — bounded MPSC → dedicated writer thread, batched flush (256 lines / 25 ms / `sync()` / drop). Request workers never touch the file mutex or block on disk; OC correlation window preserved (≤25 ms). Shipped on `perf/audit-sink-async-writer` (TDD: 2 new + 7 contract tests green; `aegis-control` lib 1133/0). | Removes the single global serialization point that caps the whole data plane. Highest ROI by far. |
| **B (High)** | **Measure the AI/ONNX + TLS cost *on pre-prod*** (where they're live) with the same flood + `perf`/`sample`. Prime suspect for the residual cliff once A lands. | The expensive ingredients are absent locally; must be profiled where enabled. |
| **C (Med)** | Verify the **Gradient2 load-shedder** (`shed.rs`, dev.yaml:358) actually engages at the knee; tune so it sheds before collapse instead of after. | Backpressure should bound the cliff; reframed old P2. |
| **D (Low)** | Redis hygiene (fast-fail already `100ms` in dev, breaker, drop latency `Mutex`) **only** for the async `auto_block` storm path. | Defense-in-depth; not this bottleneck. Old P3, downgraded. |
| **E (Low)** | In-process O(1) window swap (old P1). | Real for extreme single-key floods, but not the wall. Downgraded. |

Raw artifacts: `/tmp/p0/{flood,attack}.log`, `/tmp/p0/waf_{flood,attack}_sample.txt`,
`/tmp/p0/k6.log`. Reproduce: boot with `WAF_DDOS__ENABLED=false`, `k6 run /tmp/p0/flood.js`,
`docker exec aegis-cluster-redis redis-cli INFO commandstats`.

**Fix A landed — local before/after (same box, 200 VUs, single-IP closed-loop flood):**
throughput **28.6k → 54.2k rps (~1.9×)**, p95 **21.3 ms → 8.4 ms**, audit fully preserved
(1,084,467 lines written for 1,084,493 requests — no loss, no back-pressure stalls). The
per-write `flush()`-under-mutex was costly even on macOS local SSD; on pre-prod's slower disk
the relative win should be larger. Confirms the root cause: decoupling the audit flush lifts
throughput. (`perf/audit-sink-async-writer`.)

---

## Cross-check — l-tester report (`tests/l-tester/reports/perf-bottleneck-analysis-en.md`)

This second report (7k→3k, static analysis) is **much stronger than the s-tester one and
complements P0**: it correctly identifies the **LoadShedder cascade as the cliff *mechanism***
and adds concrete file:line for the **AI + TLS** CPU causes P0 flagged but couldn't measure
locally. It **misses the one thing P0 found** (the synchronous interop audit `flush()` — it
flagged the *async* AuditBus clone instead). Each claim verified against code:

| # (their) | Claim | Verdict | Notes |
|---|---|---|---|
| 1 | LoadShedder Gradient2 cascade | ✅ **mechanism confirmed**, ⚠️ **config stale** | The cascade *shape* is real and explains why the drop is a cliff not a slope. BUT the "limits too low (1000/100)" is stale — `config/dev.yaml:368-371` already sets `initial_limit: 20000, min_limit: 2000` (raised 2026-05-22). The `LoadShedder::new(100,1)` they cite is a **unit test** (`shed.rs:244`). The `rtt_min` "pins low forever" concern was **already mitigated** by the upward decay at `shed.rs:79` (`current_min/512`, with a comment naming exactly that bug). → The shedder converts CPU saturation into the cliff; fix the *cause* (A/B), then verify pre-prod's actual shed limits. |
| 2 | Missing `SO_REUSEPORT` / backlog | ✅ confirmed | `acceptor.rs:20` is a plain `TcpListener::bind`, no reuseport, no explicit backlog. Real for new-connection/TLS churn (less under keep-alive). **Adopt** — see Fix F. |
| 3 | DDoS `format!` key + DashMap write-lock/req | ⚠️ overstated | Real micro-cost, but ddos is **off** in the test and `check_local` was 4 samples in the P0 profile. Shard-count↑ doesn't help single-IP (one shard). Low-value micro-opt; folds into old Fix E. |
| 4 | StatsAggregator `std::Mutex` contended across workers | ❌ **incorrect** | `record()` has **no per-worker caller** — it runs on the single bus-subscriber task (`run.rs:885` `rx.recv().await` loop). Single-writer `std::Mutex` is fine; not a hot-path contention point. Dismiss. |
| 5 | AI `block_in_place` parks worker | ✅ confirmed | `detectors/ai/batch_detector.rs` — inline `block_in_place` on the tokio worker. Matches P0 Fix B (AI is the prime pre-prod cliff cause). **Measure on pre-prod**, then move inference to a dedicated pool. |
| 6 | AuditBus clones event × subscribers | ✅ confirmed | `audit.rs:322` `broadcast::send(ev)` by value → one clone per receiver (subscriber task + every open SSE dashboard tab). `Arc<AuditEvent>` is a cheap win. **Adopt** — Fix G. |
| 7 | `max_idle_per_host = 32` default | ✅ confirmed | `config.rs:2805`. Raise per-upstream for high-RPS keep-alive reuse. Cheap config — Fix H. |
| 8 | TLS handshake inline per new conn | ✅ confirmed | Real for connection churn; keep-alive + session resumption mitigate. Part of Fix B (TLS cost, pre-prod). |
| 9 | `maybe_sweep` try_lock/req | ✅ low/negligible | One amortised atomic try-lock; not worth chasing. |

### Unified causal chain (both reports + P0)

```
(A) interop audit flush()-under-mutex/req   ┐
(B) AI block_in_place + TLS handshake (pp)  ├─► CPU → 95% early ─► WAF self-RTT ↑
    [P0 found A; l-tester found B]          ┘                        │
                                                                     ▼
                              Gradient2 shedder sees RTT↑ ─► shrinks concurrency limit
                              [l-tester #1 = the cliff MECHANISM]  ─► sheds Med/Low
                                                                     ▼
                                            visible throughput collapses to ~3k  = CLIFF
                              (Redis 44.9ms P50 = parallel symptom of the same starvation)
```

So: **l-tester explains the cliff trigger/shape (shedder); P0 explains a primary cause it
missed (audit flush); l-tester adds the other big causes (AI/TLS, SO_REUSEPORT) with
file:line.** No real conflict — they stack.

## Cross-check — s-tester "load-shedder placement" report (`20260620_load_shedder_placement_report.md`) + pre-prod result

**Operator observed: Fix A did NOT improve pre-prod much.** That is consistent and important —
it reframes the root cause. Verified against code:

- **Why Fix A underperformed on pre-prod.** P0 was run locally with **AI off** (`ai.enabled:false`,
  zero inference), **plain HTTP** (no TLS), and **tiny bodies** — so the audit sink was the
  heaviest *local* subtree and removing it ~doubled local throughput. On pre-prod the dominant
  costs are **AI/ONNX inference + TLS crypto + full-body buffering**, none of which the local
  repro exercised. Fix A removed a real cost, but a smaller share of the *pre-prod* budget.
- **The pre-prod cliff is a congestion collapse / metastable failure** (11k stable → 14k →
  ~2–3k), not a simple per-stage cost. The shed gate is correctly *before* detectors but still
  **too late** in three ways, all verified:
  1. ✅ **Shed runs after full-body buffering.** `Limited::new(body,cap).collect().await`
     (`data_plane.rs:887`) reads + heap-allocs the whole body; `should_admit` is at
     `data_plane.rs:972`. A request that gets shed has already paid network-read + alloc + memcpy
     for its body — allocator/bandwidth pressure exactly when CPU is at 95% (death-spiral fuel).
     `route_tier` is already resolved at `data_plane.rs:432`, so the gate **can move up** to
     before `into_parts()`/collect without re-architecting tier resolution.
  2. ✅ **No admission at accept/TLS.** `accept.rs` has no `should_admit`/semaphore before the
     TLS handshake — under a connection flood every (expensive) handshake completes before any
     shed decision.
  3. ✅ **Shed signal lags the real constraint.** Gradient2 keys on RTT (`shed.rs`), fed by
     `record_rtt(request_start.elapsed())` at the *end* of inspection (`data_plane.rs:1755`) — so
     it reacts only after queues have already built, and request N+1's admit uses request N's
     latency. Industry practice (Google SRE / AWS / DAGOR) sheds on **CPU / in-flight concurrency**
     as the primary signal, RTT as secondary.
  - §3.4 (Critical bypass + still counts inflight) — by design; the report's §5.4 (reserve
    capacity for Critical instead of letting it self-saturate) is the safe way to keep "Critical
    never shed" without it dragging the node down.

The report's fixes are sound and standard. **They are a different, higher-priority track than
Fix A for pre-prod**, folded into the list below as **F-shed/J/K**.

### ⚠️ Hard dependency: does this help a *Critical-tier* benchmark?

The shed-placement track only ever sheds **non-Critical** traffic (Critical bypasses by policy,
verified `shed.rs:121`). So:
- **Mixed-tier load:** early-shedding non-Critical frees CPU/RAM that lets the Critical route hold
  its plateau → the whole track pays off (directly for low tiers, indirectly for Critical).
- **Pure-Critical load:** *no shed-placement change moves the number* — Critical is admitted
  regardless, still buffers body + runs detectors. The only levers are **per-request cost**
  (Fix B: AI off the worker, TLS resumption; and moving body-buffering after a cheap gate) or
  horizontal scale. This is an honest design limit: a 100%-Critical flood has no admission valve.

→ **Confirm the failing benchmark's tier mix before investing in the shed track.**

### Resolution (2026-06-20) — shed-before-body shipped; session closed

Operator confirmed the failing pre-prod load is **mostly/all Critical-tier**, and
**"Critical never apply shedder" is a hard contract** (not to be softened). Decision: implement
the report's headline fix (P1, shed-before-body-buffer) as resilience hardening for the
non-Critical fraction, keep the Critical contract intact, and close the perf-tuning session.

**Shipped** (`perf/shed-before-body-buffer`): the adaptive-shedder gate + `admit_guard` moved
from after body buffering (was `data_plane.rs:972`, post-`collect()`) to **before**
`into_parts()`/`collect()`, keyed on the already-resolved `route_tier`. A shed (non-Critical)
request now returns `503 load_shed` without reading or allocating its body. **Critical is
untouched** — `should_admit(Critical)` still returns `true`, so Critical falls through and
buffers + inspects exactly as before (contract preserved). The §5.5 reject stays cheap (small
fixed 503). Validated: `aegis-proxy` lib **933/0**; smoke with `initial_limit=0` →
non-Critical POST gets `503 {"error":"load_shed","tier":"high"}`, normal limit passes.

**Honest limitation (stated to operator):** because the contract exempts Critical, this does
**not** move the mostly-Critical pre-prod number — it only relieves the non-Critical fraction
of the flood (freeing some CPU for Critical). The only remaining levers for a Critical-tier
ceiling are **per-request cost reduction** (Fix B — AI/ONNX off the tokio worker via a
dedicated pool + TLS session resumption) or horizontal scale; a 100%-Critical flood has no
admission valve by contract. **Fix B is deferred** (needs on-pre-prod AI/TLS profiling).

Remaining open items from the s-tester/l-tester cross-checks (F/G/H/J/K — accept-layer
`SO_REUSEPORT`/admission, `Arc<AuditEvent>`, pool idle, CPU-signal shedding) are catalogued
above but **not** scheduled — reopen if a future non-Critical-heavy load needs them.

### Net additions to the fix list (verified, folded in)

| New # | Fix | From | Severity |
|---|---|---|---|
| **F** | `SO_REUSEPORT` + explicit `listen(4096)` backlog on the data listener (`acceptor.rs:20`); also check OS `somaxconn`/`ulimit -n` | l-tester #2 + infra checklist | High (conn churn / TLS) |
| **G** | `Arc<AuditEvent>` in `AuditBus::emit` (`audit.rs:322`) — one Arc vs N struct clones | l-tester #6 | Med (cheap) |
| **H** | Raise upstream `max_idle_per_host` (32→256) for keep-alive reuse | l-tester #7 | Low (config) |
| (C↑) | **Promote shedder work**: don't just retune — confirm pre-prod's live `initial_limit/min_limit` and whether it sheds *before* vs *after* collapse. Dev is already 20000/2000. | l-tester #1 (corrected) | Med |

**Caution on the l-tester "Step 1 config-only" block:** its `load_shedder: initial_limit:
5000` would *lower* dev's existing 20000 ceiling — don't apply blindly. Verify the live
profile first.

### ⚠️ Critical-tier routes: the shedder does NOT apply (operator question, 2026-06-20)

The shedder runs **after** tier classification and `should_admit(Tier::Critical)` returns
`true` unconditionally (`shed.rs:121`; call site `data_plane.rs:962-991`, comment "Critical
traffic is never shed"). Consequences for a **Critical-tier benchmark route**:

- **The l-tester #1 cascade does NOT explain its drop.** Critical requests are always
  admitted + fully processed — never 503'd. So for Critical traffic the cliff is **pure CPU
  saturation / serialization** (Fix A audit-flush mutex + Fix B AI/TLS), not shedding. Each
  request just gets slower; completed req/s collapses without rejections.
- **Critical gets no backpressure.** It still `admit_guard()`s (counts toward inflight + feeds
  RTT into the estimator), so a Critical-heavy load self-saturates the WAF with **no relief
  valve** — it shrinks the limit for *lower* tiers (which get shed) while Critical floods
  through slowly. → a Critical-only run shows the full uncapped collapse.
- **Therefore, for a Critical route, shedder tuning (C) is irrelevant — prioritise A + B.**
  (If the run is *mixed*-tier, the lower-tier portion IS shed, so the visible number is
  shed-lower-tiers + slow-Critical combined.)

---

## Evidence — verified against code (2026-06-20)

### The per-request hot path is in-process; Redis is not on it

- **DDoS:** `data_plane.rs:579` calls `ddos.check_with_tier(peer_ip, tier).await`, which runs
  `detector.check_local(...)` entirely in memory (`ddos.rs:298-352`). The only Redis touch is
  a **fire-and-forget `tokio::spawn(state.auto_block(...))` on a *fresh* block**
  (`ddos.rs:327`) — off the request's critical path. The perf note at `ddos.rs:288-297`
  states it plainly: *"NO `StateBackend` round-trip on the hot path (was 2)."*
- **Rate-limit:** `data_plane.rs:754-757` calls `ip_rate_limiter.consume_with_key(...)`, a
  synchronous in-process `DashMap<RiskKey, VecDeque<Instant>>` operation
  (`rate_limit/ip_limiter.rs:118, 187-237`). No `.await`, no Redis.
- **`incr_window` (the `SLIDING_WINDOW_LUA` ZSET-log the report flags as the root cause) is
  not called anywhere in `data_plane.rs`.** `grep` for it on the data path returns nothing.
- **Dashboard corroborates:** L3 shared-state panel — `DBSIZE 165`, P99 `1.4 ms`, circuit
  `closed`, replica lag `—`. A saturated 660 k-member hot ZSET would show neither 165 keys
  nor sub-ms latency.

**Conclusion:** the report's §4.1/§4.2 mechanism (hot ZSET + tiny pool) is real code but
**dormant in the tested config**. The cliff is produced elsewhere.

### Where the cliff actually comes from

1. **Single hot key → single shard lock (the dominant test-method effect).** One source IP
   collapses to ~one `RiskKey`, so every request takes a **write lock on the same `DashMap`
   shard** (`ip_limiter.rs:223` `get_mut`) *and* on the ddos `windows` map (`ddos.rs:452`).
   `DashMap` shards by key hash; one hot key = one shard = serialized on one core. Each
   request also does an O(window) front-trim of the `VecDeque` (`ip_limiter.rs:191-196`,
   `ddos.rs:453-459`). Under ~11 k rps to one key this is a per-core serialization point.
   Production traffic spread across thousands of IPs hits many shards and **does not cliff
   like this** (report §6.b).
2. **CPU-bound detector pipeline + no load-shedding (the real-traffic effect).** At ~8 k rps
   CPU is already ~90% (report §2) — that is the regex/AI detector cost, not Redis. With no
   backpressure, crossing the knee makes per-request latency climb, in-flight count balloons,
   and throughput falls off a cliff. This is independent of the source-IP count.

### The report's Redis findings are accurate but currently off-path

All verified true in code — they matter **only** for configs/paths where Redis *is*
synchronous (and for the async `auto_block` storm under mass-blocking):

| Finding | Verified at | On the tested hot path? |
|---|---|---|
| `pool_size` default 16 (8 cluster / 32 prod) | `redis.rs:56`, `config/dev.yaml:127` | No |
| per-op `timeout` 5 s, no fast-fail / breaker | `redis.rs:57, 315` | No (but see async path) |
| `std::Mutex` latency-ring lock per successful op | `redis.rs:319` | No |
| `SLIDING_WINDOW_LUA` stores 1 ZSET member/req | `redis.rs:69-85`, `incr_window` `redis.rs:475` | Not called on data path |
| ddos Redis variant = 3 serial RTT | `ddos.rs:549-588` | Not used (in-process path is live) |

---

## Plan — phased, measurement-gated

### P0 — Confirm before optimizing (MANDATORY, ~half a day) 🔴 blocking

Per the report's §7 and our own "verify against code/measurement" discipline. Do **not**
write perf code until P0 says where the time goes.

1. **Prove Redis is idle under load.** During a load run:
   `redis-cli SLOWLOG RESET` → load → `SLOWLOG GET 20`, `INFO commandstats`, `--bigkeys`,
   `INFO clients` (`blocked_clients`, `connected_clients` vs `pool_size`). Expectation given
   the dashboard: ZADD/ZREMRANGEBYSCORE near-zero, no big ZSET, `blocked_clients ≈ 0`.
2. **Profile the WAF process** at ~11 k rps single-IP: `cargo flamegraph` (or `perf record`)
   on the proxy. Expectation: time dominated by `DashMap` shard lock / `VecDeque` ops in
   `consume_with_key` + `check_local`, and the detector pipeline — **not** redis client code.
3. **Re-run with many source IPs** (or rotating, *trusted* XFF) to separate measurement
   artifact from design defect. Expectation: cliff softens substantially (load spreads across
   shards), isolating the residual real cost (detector CPU).
4. **Decision gate:** record which of {hot-key contention, detector CPU, Redis} actually
   dominates. Branch into P1/P2/P3 by the evidence; drop any phase the data doesn't support.

**Acceptance:** a short measurement note appended here with SLOWLOG/commandstats output, a
flamegraph, and the single-IP vs multi-IP throughput numbers.

### P1 — Kill the in-process hot-key contention 🟡 (gated on P0.2 confirming it)

Target: a single hot key must not serialize the whole node on one shard/core.

- **Replace the per-key sliding-window-*log* (`VecDeque<Instant>`) with an O(1) counter.**
  Both `IpRateLimiter` (`ip_limiter.rs`) and the ddos `windows` map (`ddos.rs`) currently
  keep a growing deque and trim it every request. Switch to a **fixed-window or
  two-counter sliding-window** cell: store `(window_start, AtomicU32 count)` (or a small
  bucketed ring) per key. This removes the per-request O(window) trim and shrinks the
  critical section to a couple of atomic ops.
- **Shorten / remove the lock hold on the hot key.** With an atomic-counter cell, the hot
  path can use `DashMap::get` + atomic `fetch_add` instead of a `get_mut` write guard held
  across a deque trim — turning the per-shard write-lock into a read-guard + atomic.
- **Keep behavior + tests green.** Preserve the existing semantics the tests assert
  (`ip_limiter.rs:538, 632` — exact-100 denial, per-session isolation on same IP); add cases
  for the new counter rollover. This is a measurable, in-process win that also benefits the
  real few-IP volumetric threat, not just the test.

**Acceptance:** single-IP `consume_with_key` throughput (micro-bench) up materially; the
end-to-end single-IP cliff rises toward the multi-IP number from P0.3; all existing
rate-limit/ddos unit tests still pass.

### P2 — Backpressure / load-shedding so saturation degrades, not collapses 🟡

The cliff is a queueing collapse: once past the knee there is no shed valve. Add one so the
node sheds the cheapest-to-reject load first and holds a floor instead of falling to 3 k.

- **Fast-reject under in-flight pressure.** Bound concurrent in-flight requests (semaphore /
  connection cap) and return `503 + Retry-After` immediately past the cap, *before* the
  detector pipeline — same spirit as the existing "rate guard fires before detectors so a
  flood can't burn CPU on regex" comment (`data_plane.rs:742-748`).
- **Cap detector CPU spend.** The AI detector is the dominant cost; confirm there is a budget
  / short-circuit so a flood of obviously-blockable traffic (already rate-limited IP) skips
  the expensive matchers. (P0.2 flamegraph tells us if this is needed.)

**Acceptance:** at offered load past the knee, sustained throughput holds a floor (no
free-fall to ~3 k) and p99 latency is bounded rather than unbounded.

### P3 — Redis-path hardening (defense-in-depth; the report's §8 list) 🟢

These do **not** cap the tested config, but they are correct and protect (a) any future/edge
config that puts Redis on the sync path, and (b) the **async `auto_block` propagation under a
mass-blocking storm** (many fresh blocks → many `tokio::spawn`ed Redis writes; a 5 s timeout
there piles up tasks/connections). Do these as a low-risk batch:

1. **Fast-fail timeout + circuit breaker, fail-open** on the data-plane Redis calls: drop the
   per-op `timeout` from 5 s → ~50–100 ms (`redis.rs:57, 315`); the circuit-state plumbing
   (`last_error_at`, health snapshot) already exists — wire an open-circuit short-circuit.
2. **Right-size the pool** for the async/auxiliary load (`pool_size` 16/8/32 →
   evaluate 32–64); pair with the fast-fail so a slow Redis can't hold connections 5 s.
3. **Remove the `std::Mutex` latency-ring from the per-op path** (`redis.rs:319`) → atomic /
   sharded histogram, so telemetry never contends cross-core if Redis returns to the hot path.
4. **(Optional) Collapse the ddos Redis variant to 1 Lua RTT** (`ddos.rs:549-588`) and prefer
   the existing `TOKEN_BUCKET_LUA` (O(1), `redis.rs:89`) over `SLIDING_WINDOW_LUA` **if** any
   config ever re-enables the Redis rate-limit path. Pure cleanup until then.

**Acceptance:** under an induced slow-Redis fault, the data plane fails open within ~100 ms
(no 5 s stalls), in-flight/RAM stay bounded, and a mass-block storm doesn't exhaust the pool.

### P4 — Fix the load-test methodology 🟡 (process, not code)

- Re-run the throughput test with **many source IPs** (the report's §6.b ask) so the headline
  number reflects production fan-out, not a single-shard artifact. Capture 8 k / 11 k / cliff
  numbers for both single-IP and multi-IP so future regressions are comparable.
- Add a short note to `tests/s-tester/` on running the multi-IP profile + the P0 redis-cli
  confirmation commands, so the next "Redis is slow" report starts from measurement.

---

## Risks & notes

- **Don't "fix" a non-problem.** Re-pointing the ZSET as the headline would burn effort on a
  path that isn't loaded (dashboard proves it). P0 exists to prevent that.
- **Behavior preservation (P1).** The window data-structure swap must keep the exact
  rate-limit/ddos semantics the suite asserts (per-(tier,ip)/per-session keying, exact-N
  denial). TDD it: add the rollover tests first, keep the existing ones green.
- **Immutability/Rust style:** P1/P3 touch hot concurrent code — prefer atomics over wider
  locks, keep critical sections minimal, `cargo clippy -D warnings` + `cargo fmt` per the
  repo's per-file style (this repo is not whole-crate rustfmt-clean — only format files we
  fully author).
- **Scope discipline:** this is perf hardening, not a security change. The in-process refactor
  already removed the dependency that the report feared; we are tightening the in-process path
  and adding a shed valve, plus opportunistic Redis hygiene.

## File/line map (verified)

| Thing | File:line |
|---|---|
| DDoS hot path = in-process `check_local` | `crates/aegis-security/src/ddos.rs:298-352` |
| DDoS async fire-and-forget `auto_block` | `crates/aegis-security/src/ddos.rs:327` |
| DDoS in-process window `DashMap`+`VecDeque` | `crates/aegis-security/src/ddos.rs:430-477` |
| Rate-limit hot path = in-process consume | `crates/aegis-proxy/src/data_plane.rs:754-757` |
| `IpRateLimiter` `DashMap<RiskKey, VecDeque>` | `crates/aegis-security/src/rate_limit/ip_limiter.rs:98-127, 187-237` |
| DDoS check call site | `crates/aegis-proxy/src/data_plane.rs:579` |
| Redis defaults (pool 16, timeout 5 s) | `crates/aegis-proxy/src/state/redis.rs:52-58` |
| `with_timeout` + latency `std::Mutex` | `crates/aegis-proxy/src/state/redis.rs:310-340` |
| `SLIDING_WINDOW_LUA` (off data path) | `crates/aegis-proxy/src/state/redis.rs:69-85` |
| `TOKEN_BUCKET_LUA` (already present) | `crates/aegis-proxy/src/state/redis.rs:89` |
| `incr_window` (no data-plane caller) | `crates/aegis-proxy/src/state/redis.rs:475` |

---

*Diagnosis revised from the s-tester report after code + dashboard verification: Redis is
healthy and off the hot path; the cliff is in-process single-hot-key contention (largely a
single-IP test artifact, partly a real few-IP volumetric concern) plus an unshed CPU-bound
detector pipeline. Measurement gate P0 confirms before any optimization lands.*
