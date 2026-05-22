# Adaptive Load Shedding (v2, enterprise)

> **Status:** Implemented — `aegis-proxy/src/shed.rs` + `aegis-core/src/load_mode.rs` (P7).
>
> See [`../../plans/plan.md`](../../plans/plan.md#1-doc-by-doc-implementation-status) for the full matrix.

> **Enterprise addendum.** Under saturation, the WAF sheds lowest-tier
> traffic first so CRITICAL routes keep serving. Uses the **Gradient2**
> algorithm (adaptive concurrency) to find the stable concurrency
> ceiling without operator tuning.

## Purpose

Keep the WAF responsive and CRITICAL routes available under traffic
spikes, degraded backends, or CPU starvation — without a static
concurrency limit that's wrong 99% of the time.

## Gradient2

Adaptive concurrency limit inspired by Netflix `concurrency-limits`:

- Measures the minimum *recent* latency (`RTT_min`) as a baseline
- Measures the short-window latency (`RTT_now`, EMA, α = 0.2) continuously
- Gradient `g = RTT_min / RTT_now ∈ (0, 1]`
- **AIMD** update (2026-05-17 lifecycle fix — the pre-fix rule was
  multiplicative-decrease only, so the limit could only ever shrink
  and never recovered after a transient spike):
  - `g ≥ 0.9` → system healthy → `L += 1` (additive grow, clamped to
    `initial_limit` so a long healthy run can't push concurrency past
    the operator's configured ceiling)
  - `g < 0.9` → system stressed → `L *= g` (multiplicative shrink,
    floored at `min_limit`)

### RTT is WAF-inspection latency only (2026-05-22)

The single most important property: the gradient is fed the **WAF's own
processing time** (parse + detectors + gates), measured at the
upstream-forward boundary — **not** the upstream round-trip. Mixing in
upstream latency made a slow or jittery backend look like WAF overload,
so a healthy WAF would shed traffic it could comfortably serve. That was
the failure mode observed around 7k RPS. The data plane records
`request_start.elapsed()` right before connecting upstream, so zero
backend time is in the sample.

`RTT_min` also **decays upward** (~0.2 %/sample, capped below `RTT_now`)
rather than latching the all-time minimum forever. Without decay, a
single ultra-fast sample (e.g. a 0.3 ms cache hit) pinned the gradient
near zero, which pegged the limit at `min_limit` and shed healthy
traffic indefinitely.

## Shedding priority

When in-flight concurrency exceeds the current limit, requests are shed
in **reverse priority order** by risk tier (see Detectors & Tiers in the
dashboard, which documents this gate inline):

1. **Low** (catch-all) traffic shed first
2. **Medium** next
3. **High** next (gets ~10 % headroom over Medium/Low)
4. **Critical** is **never** shed by the adaptive layer; it can only be
   blocked by a real security decision

## Early 503

Shed requests get an immediate `503 Service Unavailable` with
`Retry-After` — no pipeline cost, no upstream contact. This is the
single most important lever for stability under overload.

## Coordination with DDoS mode *(design intent — not implemented)*

When global DDoS mode is active (see [`ddos-protection.md`](../security/ddos-protection.md)),
the shedder would tighten more aggressively:

- CATCH-ALL dropped at 50% of normal limit
- MEDIUM dropped at 70%
- HIGH dropped at 90%

## CPU-aware backstop *(design intent — not implemented)*

A kernel-reported CPU saturation signal (`/proc/stat` load or cgroups
`cpu.stat`) would feed a global backstop. When CPU > 90%, shedding kicks
in independent of Gradient2.

## Per-tenant concurrency *(design intent — not implemented)*

Each tenant would have `concurrency_soft` and `concurrency_hard`:

- Soft: tenant shares cluster pool as long as unused capacity exists
- Hard: tenant cannot exceed, even if cluster pool is idle

This prevents a burst from tenant A starving tenant B.

## Metrics

- `waf_shed_total{tier,tenant,reason}`
- `waf_concurrency_limit{pool}` (gauge)
- `waf_concurrency_inflight{pool}` (gauge)
- `waf_rtt_seconds_bucket{pool}`

## Configuration

The implemented knobs (`aegis-core::config::LoadShedderConfig`). The key
is `load_shedder:` (singular noun) — three fields, all optional:

```yaml
load_shedder:
  enabled: true          # master toggle (default true)
  initial_limit: 20000   # adaptive ceiling = max concurrent in WAF
  min_limit: 2000        # floor — never shed below this concurrency
```

`initial_limit` doubles as the **grow ceiling** (`max_limit` internally):
the AIMD grow path never pushes concurrency past it.

### Sizing for throughput (>=10k RPS)

By Little's law, required concurrency ≈ `RPS × WAF-inspection-latency`.
With sub-millisecond inspection, a few hundred concurrent slots covers
10k RPS — so the shipped defaults leave generous headroom:

| Profile | `initial_limit` | `min_limit` |
|---|---|---|
| `dev` / `prod-balanced` / `prod-strict` | 20000 | 2000 |
| `prod-high-throughput` | 40000 | 4000 |

The high floor matters as much as the ceiling: it guarantees a transient
RTT blip can't shrink the limit far enough to shed healthy load before
the gradient recovers.

> **Not yet implemented.** Earlier revisions of this doc described
> `algorithm`, `gradient2.*`, `cpu_backstop`, `ddos_mode_tightening`, and
> per-tenant `concurrency_soft`/`hard` knobs. Those remain design intent
> — the live `LoadShedderConfig` exposes only the three fields above. The
> sections below marked *(design intent)* are not wired up.

## P7 — `LoadMode` discrete-state companion

Adaptive shedding makes per-request *concurrency* decisions; P7
adds a coarser, longer-lived *operational mode* signal. Both
mechanisms run alongside each other.

```yaml
load_mode:
  elevated_rps:    2000      # auto Normal → Elevated boundary
  critical_rps:    8000      # auto Elevated → Critical boundary
  sample_interval: 1s        # >= 100ms
  hysteresis:      0.10      # 10 %; stops borderline oscillation
```

State transitions are computed by `next_mode(prev, rps, cfg)` —
a pure function with hysteresis floors at
`elevated_rps × (1 - hysteresis)` and
`critical_rps × (1 - hysteresis)`. A workload at exactly the
elevated boundary doesn't oscillate every second.

The hot path bumps the request counter once per request (one
`Relaxed` `fetch_add`) and reads the live mode via
`LoadGauge::current()` (one `ArcSwap` load).

| Mode | Behaviour change |
|---|---|
| Normal | Full audit detail, full SSE broadcast capacity |
| Elevated | (reserved — P7 surface; future degradations land here) |
| Critical | Audit `fields` payload drops to `null`; chain writes shrink ~50 % at 5 000 RPS |

`PUT /api/loadmode { "override": "critical"|"unset" }` lets an
operator pin a mode through the `AuditedMutate` pipeline.

## Implementation

- `crates/aegis-proxy/src/shed.rs` — the whole shedder: `LoadShedder`
  (Gradient2 AIMD limit + `record_rtt`), tier-priority `should_admit`,
  and the RAII `ShedGuard` that tracks in-flight concurrency
- `crates/aegis-proxy/src/data_plane.rs` — call sites: the
  `should_admit` gate (503 + `circuit_breaker("load_shed")`) and the
  WAF-inspection-only `record_rtt` at the upstream-forward boundary
- `aegis-core::config::LoadShedderConfig` — the `load_shedder:` knobs
- `aegis-core::load_mode` — **P7** `LoadMode` enum +
  `LoadGauge` (Arc<ArcSwap<…>>) + `next_mode` pure transition
- `aegis-control::api::load_mode` — `/api/loadmode` HTTP surface

## Performance notes

- Limit check is one atomic `fetch_add` + compare — wait-free
- Shed decision is O(1) per request
- Gradient2 updates run on a tick, not per request
