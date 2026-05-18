# DDoS Protection

> **Status:** ✅ **Implemented (v1 single-node)** as of 2026-05-09.
> Wired in `aegis-proxy/src/data_plane.rs` via `DdosRuntime`,
> instantiated at boot from `cfg.ddos`. Defaults to **enforce mode**
> (`observe_only: false`) — secure-by-default, matching every other
> security primitive in the data plane. Per-IP burst-exceed → HTTP
> 403 with `X-WAF-Action: block` per
> [`Hackathon_Doc/EN_waf_interop_contract_v2.3.md`](../../Hackathon_Doc/EN_waf_interop_contract_v2.3.md)
> §3.1 (volumetric abuse from a single source). Cluster-wide
> spike-mode broadcast across nodes stays deferred behind the
> ha-clustering work — single-node nodes coordinate via the shared
> `StateBackend::auto_block` keyspace.
>
> Audit trail: original stub-finding [`BUG-DDOS-STUB`](../../reports/findings/2026-05-09-internal-audit-ddos/BUG-DDOS-STUB.md);
> wire-up plan [`internal-audit-2026-05-09-ddos/`](../../plans/issue-fix/internal-audit-2026-05-09-ddos/).

> **Operator surface:** the dashboard's **Traffic Gates** page
> (Policy menu) shows the live DDoS telemetry — `current_rps`,
> `baseline_rps`, `spike_active`, mode (enforce / observe-only),
> alongside summary cards for the other three request-flow gates.
> Operator workflow + tuning guide:
> [`docs/operator/traffic-gates.md`](../operator/traffic-gates.md).

## What DDoS is — and isn't

DDoS is a **request-flow gate**, not a `Detector` trait
implementation. It does not produce risk-score signals via the
detector chain in `aegis-security/src/detectors/`; it sits in the
same architectural tier as access-list, strike-block, and
rate-limit:

| Tier | Module | Returns | When it fires |
|---|---|---|---|
| Access list | `aegis-control/src/api/blacklist.rs` | 403 + `X-WAF-Action: block` | IP/CIDR/country on the operator blacklist |
| Strike-block | `aegis-security/src/risk/tracker.rs` | 403 + `X-WAF-Action: block` | Per-IP lifetime strike count ≥ `risk.strikes.block_at` |
| **DDoS** | `aegis-security/src/ddos.rs` | 403 + `X-WAF-Action: block` | Per-IP burst-exceed in a sliding window OR previously auto-blocked |
| Rate-limit | `aegis-security/src/rate_limit/` | 429 + `X-WAF-Action: rate_limit` | Token-bucket exceeded for this request |

All four read shared state (the `StateBackend` cluster-wide
keyspace) and decide block-or-pass *before* the detector chain
runs. They don't emit `Signal { score, tag, field }` rows; they
short-circuit the request directly. This is why the legacy struct
name `DdosDetector` is misleading and the runtime wrapper is
called `DdosRuntime`.

## Purpose

Mitigate sudden volumetric pressure from single abusers — an IP
sustaining > `per_ip_limit` requests in a `per_ip_window_s` window
earns an auto-block for `block_ttl_s` seconds. The block is written
to `StateBackend::auto_block`, so subsequent requests from the same
IP — on this node OR any other node sharing the same backend — are
short-circuited at the next call to
`StateBackend::is_auto_blocked` without burning detector-chain
cycles.

Where [`rate-limiting.md`](./rate-limiting.md) enforces **steady
per-request budgets** with token-bucket leaky-bucket semantics,
DDoS handles **sustained burst → temporary block** with sliding-
window auto-block.

## Detection strategies

### Per-IP burst gate

Each client IP is tracked in a sliding window via
`StateBackend::incr_window`. Exceeding `per_ip_limit` within
`per_ip_window_s` writes a `block_ttl_s`-second auto-block entry
via `StateBackend::auto_block(ip, ttl)`. Counters live in the
state backend (`in_memory` or `redis`), so a burst spread across
nodes still trips the gate cluster-wide.

### EWMA spike-mode ticker

Every node maintains a rolling RPS estimate (`current_rps` for the
just-elapsed second, `baseline_rps` as an EWMA). A `tick_rps()`
ticker spawned in `aegis-proxy/src/run.rs` advances this once per
second so the EWMA progresses regardless of traffic load.

When `current_rps > spike_multiplier × baseline_rps` AND
`baseline_rps > 10`, the per-process `spike_active` flag flips to
`true`. The flag is currently per-process (single-node) — cluster-
wide spike-mode broadcast across nodes is deferred behind the
ha-clustering work. The `tightened_per_ip_rps` knob is wired into
the config so the Phase-2 cluster-broadcast follow-up can clamp
each offender without further data-plane changes.

### Cluster-wide auto-block list

Triggered blocks are written to the state backend keyspace under
the `auto_block` primitive. Every node consults the same keyspace
on every request, so a block written from one node takes effect
across the whole cluster within the replication latency bound.

- **in_memory** backend: single-node only, `DashMap` fallback.
- **redis** backend: `SET` with `EX` TTL, read on the hot path
  with pipelining.

The redis backend's TTL primitive purges expired entries
automatically. The in-memory backend's `auto_block` map is
sweeper-tracked by the existing risk-tracker GC (no separate
DDoS sweeper needed).

## Response behaviour

| Outcome | HTTP status | `X-WAF-Action` | `X-WAF-Mode` | Audit tag |
|---|---|---|---|---|
| Per-IP burst auto-block (`enforce`) | **403** | `block` | `enforce` | `ddos_blocked` |
| Already in cluster auto-block list (`enforce`) | **403** | `block` | `enforce` | `ddos_blocked` |
| Burst-exceed in observe-only mode | upstream HTTP status (typically 200) | upstream-derived | `enforce` | `ddos_observed` |
| Backend error during check | upstream HTTP status (fail-open) | upstream-derived | `enforce` | (none — debug log only) |

Per-contract mapping ([§3.1](../../Hackathon_Doc/EN_waf_interop_contract_v2.3.md#31-threat-category-to-action-semantics)
"Volumetric abuse from single source"):

- **Acceptable** actions: `rate_limit`, `block`. ✅ This gate emits `block`.
- **Unacceptable** actions: `circuit_breaker`. ✅ This gate never emits `circuit_breaker` — that action is reserved for upstream protection (the upstream pool's circuit breaker, not the source rate management).

Per [§4](../../Hackathon_Doc/EN_waf_interop_contract_v2.3.md#4-detection-via-http-response-primary)
recommended HTTP behaviour: `block` → typically `403`. ✅ Matches.

The token-bucket [`rate-limiting.md`](./rate-limiting.md) (`F-T2`)
covers the `rate_limit` + 429 path independently. The two gates
are complementary — operators can configure both.

## Integration with risk scoring

The DDoS gate does NOT push to the risk score; it short-circuits
before the detector chain runs. A subsequent strike-block (which
*is* risk-driven) provides the risk-score linkage for any IP that
has earned multiple offences. The
[`docs/operator/risk-tuning.md`](../operator/risk-tuning.md) guide
documents how the four gates interact.

## Configuration

```yaml
ddos:
  enabled: true            # default — secure by default
  observe_only: false      # default — enforce by default
  per_ip_limit: 1000       # max requests per IP within the window
  per_ip_window_s: 10      # sliding window length, seconds
  block_ttl_s: 300         # auto-block duration on burst-exceed
  spike_multiplier: 3.0    # current_rps > 3 × baseline → spike mode
  tightened_per_ip_rps: 20 # per-IP cap during spike mode (Phase-2 wire)
```

| Knob | Default | When to tune |
|---|---:|---|
| `enabled` | `true` | Set `false` for benchmark / synthetic-load runs that need raw throughput without the gate. |
| `observe_only` | `false` (enforce) | Set `true` for shadow-mode validation (CDN-fronted traffic where high RPS-per-IP is normal; you want to see the audit signal before flipping enforce on). |
| `per_ip_limit` / `per_ip_window_s` | 1000 / 10 s | Defaults are deliberately generous (≈100 req/s sustained). Drop to 100 / 60 s for stricter posture; raise for high-volume internal APIs. |
| `block_ttl_s` | 300 (5 min) | Lower for a more forgiving block; raise for stricter quarantine. |
| `spike_multiplier` | 3.0 | Lower (2.0) for earlier spike trigger; raise (5.0) for noisier baselines. |
| `tightened_per_ip_rps` | 20 | Cap each IP receives during spike mode (cluster-broadcast wiring deferred — see "Future work" below). |

### Per-profile posture

The shipped profiles diverge on DDoS posture the same way they
diverge on `rate_limit`, `risk.thresholds`, and the `detectors`
mask. Reading the profile's YAML is the source of truth; this table
exists so you can pick the right profile without diffing them by
hand.

| Profile | `enabled` | `per_ip_limit` | `per_ip_window_s` | `block_ttl_s` | `spike_multiplier` | `tightened_per_ip_rps` |
|---|---|---:|---:|---:|---:|---:|
| `config/dev.yaml` | `true` | 1000 | 10 | 300 | 3.0 | 20 |
| `config/prod.yaml` | `true` | 1000 | 10 | 300 | 3.0 | 20 |
| `config/profiles/prod-balanced.yaml` | `true` | 1000 | 10 | 300 | 3.0 | 20 |
| `config/profiles/prod-strict.yaml` | `true` | **200** | 10 | **600** | **2.0** | **10** |
| `config/profiles/prod-high-throughput.yaml` | `true` | **5000** | 10 | **180** | **4.0** | **100** |
| `tests/hackathon/configs/prod-balanced-5k.yaml` | **`false`** | — | — | — | — | — |

The 5k benchmark profile disables the gate for the same reason it
disables `brute_force` and relaxes `rate_limit`: a single source IP
(127.0.0.1) driving the k6 harness cannot honour any per-IP gate.
Production profiles never want `enabled: false`.

## Operator action map (when something fires)

| Symptom | First check | Then |
|---|---|---|
| Legit user blocked with `ddos_blocked` audit | Their burst was > `per_ip_limit` in `per_ip_window_s`. Raise `per_ip_limit`, or set `observe_only: true` to validate the signal first. | If they're behind a CDN, the WAF sees the CDN's IP — verify XFF resolution at `data_plane.rs:192` is enabled; if not, the per-IP gate is keying off the CDN edge IP and one mis-tuned limit will block thousands of users. |
| Spike-mode flag stuck on | `tick_rps()` ticker stopped; check `aegis-proxy/src/run.rs` log line `ddos: runtime installed` was emitted at boot. | If the ticker is alive but `baseline_rps` is climbing forever, the EWMA isn't decaying because `current_rps` keeps swapping. Investigate the auto-block sweeper. |
| Cluster has 5 nodes but only 1 sees the block | The state backend is `in_memory` (single-node only). Configure `state.backend: redis` to share the auto-block keyspace cluster-wide. | Verify `redis` reachability with `redis-cli -h <host> ping`. |

## Future work (deferred)

These pieces stay deferred behind their own platform dependencies:

- **Cluster-wide spike-mode broadcast.** Currently `spike_active`
  is per-process. A node-cluster needs to converge on the spike
  state via the shared backend (e.g. a `waf:ddos:spike_active`
  TTL'd key). Depends on the ha-clustering plan.
- **Adaptive-load-shedder integration.** The load-shedder
  (`aegis-proxy/src/shed.rs`) already sheds lowest-tier traffic
  first; integrating spike-mode as a shed-trigger is a one-line
  hook deferred until the cluster-broadcast lands.
- **Dashboard panel.** The Health & SLOs page would surface
  `current_rps`, `baseline_rps`, `spike_active`, and the rolling
  block-rate; queued as a follow-up to the Phase-1 wire-up. The
  metrics are already reachable on `Arc<DdosRuntime>` —
  `current_rps()`, `baseline_rps()`, `is_spike_active()`.

## Implementation

- `crates/aegis-security/src/ddos.rs` — `DdosDetector` (legacy
  name), `DdosRuntime` wrapper, `DdosCheckOutcome` decision
  shape.
- `crates/aegis-proxy/src/proxy.rs::ProxyContext::ddos` —
  `OnceLock<Arc<DdosRuntime>>` install slot.
- `crates/aegis-proxy/src/run.rs` — boot wiring (config plumb,
  runtime instantiate, ticker spawn).
- `crates/aegis-proxy/src/data_plane.rs` — request-flow call site
  between strike-block and rate-limit; emits `ddos_blocked` or
  `ddos_observed` audit event; returns 403 + `X-WAF-Action: block`
  on enforce.

## Performance notes

- Hot-path check is one `StateBackend::is_auto_blocked` lookup
  (microseconds with `in_memory`; one redis round-trip with
  `redis`).
- Burst-exceed write path is one `StateBackend::auto_block` SET
  with TTL — fire-and-forget, doesn't block the response.
- Backend errors fail-open: a transient redis hiccup logs at
  debug level and lets the request through. The strike-block and
  rate-limit gates downstream still apply.
