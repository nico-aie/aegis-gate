# Runtime tuning — Layer-1 scaling

Layer-1 of Aegis-Gate's three-layer scaling model is the in-node
runtime: how many tokio worker threads serve traffic, how big the
blocking-thread pool is, whether worker threads are pinned to
specific CPU cores. This document is the operator's guide to
sizing those knobs.

> Layer 2 (cross-node HA cluster) is documented in
> [`ha-clustering.md`](./ha-clustering.md). Layer 3 (Redis state) is
> §12 of [`../../Architecture.md`](../../Architecture.md).

## TL;DR

```yaml
runtime:
  workers: auto             # default; resolves to num_cpus
  blocking_threads: 512     # tokio default
  cpu_affinity: false       # Linux-first, advisory elsewhere
  stack_size_kb: 2048       # 2 MiB per thread
```

Restart-only — changes here require a full process restart.
The admin surface exposes the *current* values at
`GET /api/runtime` so operators can confirm the boot pulled the
right config.

## Knobs

### `runtime.workers`

Number of async worker threads in the tokio multi-thread runtime.

| Value | Meaning |
|---|---|
| `"auto"` (default) | `num_cpus::get()` resolved at boot; lifted to a minimum of 2 |
| Integer in `[2, 512]` | Explicit thread count |

**Why ≥ 2.** The cluster heartbeat + roster poller (HA-T4) and
the lease-renewal task each schedule periodically. A single-thread
runtime starves them under traffic and causes false LB flapping.
Validation rejects `workers: 1`.

**Why ≤ 512.** Beyond a small multiple of physical cores you stop
gaining throughput and start paying for context switches. The
ceiling is a guard against typo'd config (e.g. `workers: 5120`
instead of `512`).

**When to override `auto`.** Three common cases:

1. **Container quota smaller than host CPUs.** When your k8s
   pod has `cpu: "2"` on a 32-core node, `num_cpus` returns 32 but
   you only get 2 cores' worth of CPU time. Pin `workers: 2` (or
   slightly above) explicitly.
2. **Sidecar / shared host.** Other heavy processes on the same
   host — pin `workers` to leave headroom.
3. **Diagnostics.** Pinning to `workers: 1` (after temporarily
   disabling the floor for debugging) reproduces single-thread
   behaviour for chasing scheduling races.

### `runtime.blocking_threads`

Maximum size of tokio's blocking-thread pool. Tasks queued via
`tokio::task::spawn_blocking` (sync I/O, CPU-bound work the async
runtime can't await) borrow from this pool. Tokio default is 512;
the same default applies here.

Lower it on memory-constrained hosts. Raise it only if profiling
shows blocking-task starvation.

### `runtime.cpu_affinity`

Pin each worker thread to a distinct CPU core round-robin.

| OS | Mechanism | Strength |
|---|---|---|
| Linux | `sched_setaffinity` | hard pin |
| macOS | thread policy hint | advisory (kernel may move) |
| Windows | `SetThreadAffinityMask` | hard pin |

Honoured **only** when the binary is built with the `affinity`
Cargo feature:

```sh
cargo build -p aegis-bin --release --features "redis affinity"
```

Without that feature, the request is logged and ignored — the
binary boots with the default scheduling. The dashboard
"Settings → Runtime (Layer-1)" panel surfaces both the requested
flag *and* whether it was honoured.

### `runtime.stack_size_kb`

Per-thread stack size in KiB. Tokio default is 2048 (2 MiB). Most
workloads don't touch this. Raise it if you have deep recursive
rule evaluators or large stack-allocated buffers; lower it on
hosts where memory matters more than headroom.

Validation enforces a 64-KiB floor.

## Sizing recipes

Pick the row that matches your deployment shape. Numbers are
starting points, not absolutes — measure under real traffic.

| Deployment | `workers` | `blocking_threads` | `cpu_affinity` |
|---|---|---|---|
| 2-core dev VM, single node | `auto` | `128` | `false` |
| 4-core production node, single tenant | `auto` | `512` | `false` |
| 32-core bare-metal in front of a hot path | `auto` (= 32) | `512` | `true` |
| k8s pod with `cpu: "4"` quota on a 64-core node | `4` | `256` | `false` (k8s scheduler owns affinity) |
| HAProxy / Nginx-fronted multi-node cluster | `auto` per node | `512` | `false` |

## Verifying boot-time pickup

Three signals confirm your `runtime:` block was honoured:

1. **Log line at startup**:
   ```
   tokio runtime workers=12 blocking_threads=512 stack_size_kb=2048 cpu_affinity=false
   ```
2. **Admin endpoint**:
   ```sh
   curl http://localhost:9443/api/runtime
   ```
   ```json
   {
     "workers": 12,
     "workers_mode": "auto",
     "blocking_threads": 512,
     "stack_size_kb": 2048,
     "cpu_affinity_requested": false,
     "cpu_affinity_active": false,
     "host_logical_cpus": 12
   }
   ```
3. **Dashboard panel**: `Settings → Runtime (Layer-1)` shows the
   same JSON fields rendered as a key/value list.

If `workers_mode` says `auto` but `workers` doesn't match
`host_logical_cpus`, the host is reporting CPU quota (k8s,
cgroups) rather than physical cores — `num_cpus::get()` honours
that.

## Hot-reload posture

The `runtime:` block is **restart-only** by design. Tokio doesn't
expose a runtime resize API; building a new runtime mid-flight
would orphan in-flight tasks. The existing hot-reload pipeline
(`figment` → `WafConfig` → `ArcSwap`) does honour every other
config block; runtime sizing is the one explicit exception, and
the admin surface returns 4xx if you try to PUT it.

In practice: deploy the new YAML, then restart the process. Use
the standard graceful pattern:

1. `POST /admin/drain` on this node — readiness flips to 503.
2. Wait for the LB to pull this node out (≤ HAProxy `inter × fall`).
3. SIGTERM — process drains for `AEGIS_DRAIN_GRACE_MS` (default 5 s)
   then aborts listeners.
4. Restart with the new config. The new runtime picks up the
   updated `runtime:` block.

## Cross-references

- [`Architecture.md` §1](../../Architecture.md#three-layer-scaling-model)
  — three-layer scaling model overview.
- [`ha-clustering.md`](./ha-clustering.md) — Layer-2 cross-node
  scaling.
- [`zero-downtime-ops.md`](./zero-downtime-ops.md) — drain pattern,
  SIGTERM grace period.
- [`config/waf.yaml`](../../config/waf.yaml) — example YAML with
  the `runtime:` block commented out.
