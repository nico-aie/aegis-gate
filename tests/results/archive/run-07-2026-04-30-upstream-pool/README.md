# Run 07 — 2026-04-30 — Upstream Connection Pool (UP-T1)

First perf run after the upstream connection pool feature
(UP-T1) landed. Validates that pooled HTTP/1.1 keep-alive
connections lift the throughput ceiling that run-05 + run-06
attributed to "new TCP per request."

## What's being measured

Two-axis sweep, single-node, release binary built with
`--features redis`:

- **Axis 1 — pool mode**:
  - `pooled` (UP-T1 default): `max_idle_per_host: 32`,
    `idle_timeout: 30s`, `keep_alive: true`.
  - `unpooled` (pre-UP-T1 baseline): `max_idle_per_host: 0`,
    `keep_alive: false`. Reproduces the per-request `connect +
    handshake` shape so we can measure the delta directly.
- **Axis 2 — workers**: `runtime.workers ∈ {2, 4, 8, 12, auto}`.

Each iteration runs 30 s of `failover-burst.js` at constant
arrival rate against the WAF data plane (port 18080), which
forwards to `aegis-httpbin` (port 8081). 20-s cooldown between
iterations to drain `TIME_WAIT` ports.

## Run context

| Field | Value |
|---|---|
| Date (UTC) | 2026-04-30T07:30Z |
| Host | Darwin 23.1.0 arm64, 12 logical CPUs |
| Gateway binary | `target/release/waf` built with `--features redis` |
| Upstream | `aegis-httpbin` on `127.0.0.1:8081` |
| Load driver | `aegis-k6` (k6 0.51.0) |
| Scenario | `failover-burst.js` constant-arrival-rate, 30 s |

## Headline — UP-T1 nearly **doubles sustainable RPS** at 1 k offered, **lifts the ceiling ~15×** as offered RPS grows

| Offered RPS | Pooled achieved | Unpooled achieved | Pooled p95 | Unpooled p95 | Pooled success | Unpooled success |
|---|---|---|---|---|---|---|
| 1 000 | **1 000.0** | 525.8 | 0.94 ms | 2.97 ms | **100.00 %** | 96.31 % |
| 2 000 | **1 999.8** | 496.3 | 0.70 ms | **3.83 s** ⚠️ | **100.00 %** | 94.81 % |
| 4 000 | **3 979.5** | 510.0 | 0.74 ms | **4.99 s** ⚠️ | **100.00 %** | 93.6 % |
| 8 000 | **7 963.9** | n/a | 1.56 ms | n/a | **100.00 %** | n/a |
| 15 000 | 7 057.2 | n/a | 55.75 ms | n/a | 64.09 % | n/a |

The ⚠️ p95s on the unpooled column are k6 timing out at the
client side (5-s timeout) — those requests didn't fail with
5xx, they failed with the WAF returning 502 because the
upstream connect ran out of ephemeral ports.

Headline numbers:

- **At 1 k RPS offered**: pooled = 1 000 RPS / 100 % / sub-1 ms
  p95. Unpooled = 525 RPS / 96 % / 3 ms p95.
- **At 4 k RPS offered**: pooled = 4 000 RPS / 100 % / 0.74 ms
  p95. Unpooled flatlines at ~510 RPS regardless of offered
  load — that's the laptop's per-IP TCP TIME_WAIT ceiling.
- **At 8 k RPS offered**: pooled = 7 964 RPS / 100 % / 1.56 ms
  p95. Approaching the new pooled ceiling.
- **At 15 k RPS offered**: pooled drops to 7 057 RPS at 64 %
  success. The pool is saturated; latency tail explodes to
  55 ms p95.

So the laptop's **practical RPS ceiling moved from ~525 RPS to
~8 000 RPS** — a **15× lift**.

## Worker scaling — does Layer-1 matter now?

[`summary.txt`](./summary.txt) (RPS=1000) shows worker count
across both modes:

| `runtime.workers` | Pooled RPS | Pooled p95 | Unpooled RPS | Unpooled p95 |
|---|---|---|---|---|
| `2` | 999.86 | 1.36 ms | 525.84 | 2.65 ms |
| `4` | 999.94 | 0.98 ms | 525.62 | 3.61 ms |
| `8` | 999.95 | 0.99 ms | 525.72 | 3.79 ms |
| `12` | 999.96 | 0.94 ms | 526.05 | 4.22 ms |
| `auto` (=12) | 999.92 | 1.00 ms | 525.80 | 2.97 ms |

At 1 k RPS, all worker counts hit the same RPS — neither column
is saturated. The 4 k RPS [`summary-ceiling-4k.txt`](./summary-ceiling-4k.txt)
sweep gives the same answer: `workers ∈ {2, 4, 12}` all deliver
~3 980 RPS / 100 % / sub-1 ms p95. **Worker count above 2 still
doesn't move the needle on this code base / this host** — but
now it's because we're not yet hitting the next bottleneck, not
because the upstream pool is masking it.

Interpretation: the pool removed the upstream-side ceiling.
The next bottleneck (hyper service-fn dispatch, listener accept
loop, single-threaded route lookup, etc.) sits *above* what 2
worker threads can sustain on this 12-core laptop. NUMA hosts
or much higher offered RPS may shift this — re-measure on
production hardware.

## Files in this run

- [`summary.txt`](./summary.txt) — pooled vs unpooled at 1 k RPS, 5 worker counts each.
- [`summary-ceiling-2k.txt`](./summary-ceiling-2k.txt) — 2 k RPS, `workers=auto`, both modes.
- [`summary-ceiling-4k.txt`](./summary-ceiling-4k.txt) — 4 k RPS, `workers ∈ {2,4,12}`, both modes.
- [`summary-ceiling-8k.txt`](./summary-ceiling-8k.txt) — 8 k RPS, `workers=auto`, pooled only.
- [`summary-ceiling-15k.txt`](./summary-ceiling-15k.txt) — 15 k RPS, `workers=auto`, pooled only (saturated).
- `k6-{pooled,unpooled}-workers-{2,4,8,12,auto}.log` — raw k6 output per iteration.
- [`run-perf.sh`](./run-perf.sh) — reproducer.

## What got better since run-06

- ✅ Proxied-traffic ceiling lifted from ~525 RPS (run-06) to
  ~8 000 RPS (run-07). 15× improvement on the same host.
- ✅ p95 dropped from 3.85 ms (run-06 at 200 RPS) to **0.94 ms
  at 1 000 RPS** (5× the load, 4× lower p95).
- ✅ Connection-reuse asserted via two new `forward.rs` tests:
  `pooled_keep_alive_reuses_tcp_connection` (5 reqs / 1 TCP)
  and `keep_alive_disabled_opens_a_connection_per_request`
  (3 reqs / 3 TCPs).
- ✅ `keep_alive: false` + `max_idle_per_host: 0` cleanly
  reproduces pre-UP-T1 behaviour — operators can flip it for
  diagnostics without rebuilding.

## What's left after run-07

- **Linux re-measure on a NUMA host.** The laptop tops out at
  ~8 000 RPS regardless of worker count — strongly suggests a
  bottleneck above the upstream pool that NUMA + more cores
  may unmask. Run on a bare-metal Linux host to confirm.
- **B6-T1 production Dockerfile** (still deferred).
- **Multi-process workers (`SO_REUSEPORT`)** (still deferred,
  Phase 5 of the workers plan).
- **Upstream HTTPS pool.** The new pool is HTTP only.
  TLS upstream connections still go through the older code
  path in `upstream/tls.rs`. Wiring them through the same
  `Client` (with a custom rustls connector) is the next pool
  expansion.

## Reproducing

```sh
# Build the release binary.
cargo build -p aegis-bin --release --features redis

# Aegis-k6 + aegis-httpbin must be running.
docker compose -f deploy/docker-compose.dev.yml up -d aegis-k6 aegis-httpbin

# Default sweep — 1k RPS, 5 worker counts, both pool modes.
bash tests/results/run-07-2026-04-30-upstream-pool/run-perf.sh

# Override sweeps:
RPS=4000 WORKER_COUNTS="2 12" bash run-perf.sh   # ceiling probe
RPS=200  bash run-perf.sh                         # below-saturation
```
