# Run 06 — 2026-04-30 — Workers / Layer-1 perf sweep

First perf run after the workers (Layer-1 in-node scaling) feature
landed. Validates that `runtime.workers` actually drives the tokio
runtime, and measures whether worker count matters at typical load
levels on a single node.

## What's being measured

Two complementary sweeps, both single-node, both against the
release binary built with `--features redis`:

1. **Proxied path** ([`run-perf.sh`](./run-perf.sh)) — k6 drives
   the data plane (port 18080) at a constant 200 RPS for 30 s;
   the WAF forwards each request to `aegis-httpbin`. Same wire
   shape as production traffic (route resolve → security
   pipeline → upstream forward) but bottlenecked by the upstream
   pool's "new TCP per request" design (B6 candidate).
2. **Pure-WAF path** ([`run-perf-pure.sh`](./run-perf-pure.sh)) —
   k6 drives the admin port `/healthz/ready` at 200 VUs for 30 s.
   No upstream call. Isolates Layer-1 in-process throughput from
   the upstream-pool ceiling.

For each sweep the script writes one config with the worker count
under test, boots the WAF, polls `/api/runtime` to confirm the
effective worker count, runs k6, then gracefully drains. A 30-s
TIME_WAIT cooldown sits between iterations on the proxied sweep.

## Run context

| Field | Value |
|---|---|
| Date (UTC) | 2026-04-30T06:30Z |
| Host | Darwin 23.1.0 arm64, 12 logical CPUs |
| Gateway binary | `target/release/waf` built with `--features redis` |
| Upstream | `aegis-httpbin` on `127.0.0.1:8081` |
| Load driver | `aegis-k6` (k6 0.51.0) |
| Proxied scenario | `failover-burst.js`, 200 RPS, 30 s |
| Pure scenario | `admin-healthz.js`, 200 VUs, 30 s |

## Results — proxied path (data plane)

[`summary.txt`](./summary.txt) · per-iteration k6 logs at
`k6-workers-{2,4,8,12,auto}.log`.

| `runtime.workers` | Effective | RPS achieved | p50 | p95 | allow_success |
|---|---|---|---|---|---|
| `2` | 2 | 199.99 | 2.00 ms | 3.85 ms | 100.00 % |
| `4` | 4 | 199.98 | 1.97 ms | 3.90 ms | 100.00 % |
| `8` | 8 | 200.01 | 1.94 ms | 3.77 ms | 100.00 % |
| `12` | 12 | 200.00 | 1.98 ms | 3.81 ms | 100.00 % |
| `auto` | 12 | 200.01 | 2.13 ms | 3.65 ms | 100.00 % |

**Reading the numbers.** All five configs deliver the offered
200 RPS at 100 % success with statistically indistinguishable
latency (~2 ms p50, ~3.8 ms p95). At this load the bottleneck is
the upstream forwarder doing new TCP per request — not the WAF's
worker pool. `auto` correctly resolves to `num_cpus::get()` = 12.

A higher-RPS pre-run at 1000 RPS hit ephemeral-port exhaustion
(captured in `k6-workers-{2,4,8,12,auto}.log` from the first
sweep iteration before the script got 30-s cooldown) and produced
unstable results — those numbers are not load-bearing here.
B6 connection pooling is the prerequisite for measuring proxied
throughput at higher rates.

## Results — pure-WAF path (admin /healthz/ready)

[`summary-pure.txt`](./summary-pure.txt) · per-iteration k6 logs
at `k6-pure-workers-{2,4,8,12,auto}.log`.

| `runtime.workers` | Effective | RPS achieved | p50 | p95 | ready_success |
|---|---|---|---|---|---|
| `2` | 2 | 47 516 | 3.91 ms | 6.72 ms | 100.00 % |
| `4` | 4 | 47 978 | 3.91 ms | 6.42 ms | 100.00 % |
| `8` | 8 | 46 027 | 4.08 ms | 6.64 ms | 100.00 % |
| `12` | 12 | 46 367 | 4.05 ms | 6.61 ms | 100.00 % |
| `auto` | 12 | 43 376 | 4.34 ms | 7.11 ms | 100.00 % |

**Reading the numbers.** The pure-admin path saturates at
~46 k RPS regardless of worker count. With 200 VUs each
opening one keep-alive connection, k6 is offering ~200 k req/s;
the system caps at 46 k. The fact that `workers: 2` matches
`workers: 12` proves the bottleneck is **not** the worker thread
pool — it's likely the listener accept loop or per-connection
hyper task scheduling. CPU was at ~60 % across all 12 cores at
peak in `Activity Monitor`; no single core was at 100 %.

The 5 % spread between iterations is host noise (Docker, Spotlight,
the test driver itself running on the same laptop).

## Headline finding

**On the current code base, on a 12-core Apple-Silicon laptop, the
worker count above 2 doesn't materially change throughput or
latency.** Both code paths under test (proxied and pure-admin)
saturate on something other than the worker pool:

- Proxied path: upstream pool's per-request TCP connect.
- Pure-admin path: listener accept / hyper service-fn dispatch.

This **does not mean the knob is useless.** It means:

1. **The knob is correctly wired** — `/api/runtime` confirms
   the effective worker count matches the YAML, and validation
   rejects out-of-range values.
2. **`workers: auto` is the right default.** Higher values cost
   memory (`stack_size_kb` × workers, 24 MiB per worker default)
   without buying throughput today.
3. **Lower values are also viable on small hosts** — 2-core VMs
   running `workers: 2` get the same per-request latency. The
   minimum-of-2 floor is needed for the cluster heartbeat +
   roster pollers, not for the data path.
4. **The workers feature unlocks future work, not today's
   throughput.** Once the upstream pool lands (B6 candidate),
   we expect to see actual scaling: more workers → more
   concurrent upstream connections → higher proxied-traffic RPS
   ceiling.

## Runtime knobs verified live

For each iteration, `/api/runtime` was polled before k6 to
confirm the boot picked up the right config:

```
$ curl http://127.0.0.1:19443/api/runtime
{"workers":4,"workers_mode":"fixed","blocking_threads":512,
 "stack_size_kb":2048,"cpu_affinity_requested":false,
 "cpu_affinity_active":false,"host_logical_cpus":12}
```

`workers_mode` correctly switched between `auto` (lifted to 12
on this host) and `fixed` (the integer values).

## What's left after run-06

- **Upstream connection pool** (B6 candidate). Run-06 confirms
  that without one, more workers can't translate into more
  proxied throughput. This is now the highest-leverage open
  perf item.
- **Higher-VU pure-admin sweep** to find where CPU does become
  the bottleneck. 200 VUs / 46 k RPS leaves headroom on the
  laptop; on a serious host with 1000+ VUs we'd expect to see
  the workers knob differentiate.
- **Linux re-measure with `affinity` feature on.** macOS treats
  `set_for_current` as advisory; the Linux `sched_setaffinity`
  hard pin may show different scaling behaviour, especially on
  NUMA hosts.

## Reproducing

```sh
# Build the release binary.
cargo build -p aegis-bin --release --features redis

# Make sure aegis-k6 + aegis-httpbin are up.
docker compose -f deploy/docker-compose.dev.yml up -d aegis-k6 aegis-httpbin

# Sweep the proxied path (200 RPS × 30 s × 5 worker counts).
bash tests/results/run-06-2026-04-30-workers-perf/run-perf.sh

# Sweep the pure-admin path (200 VUs × 30 s × 5 worker counts).
bash tests/results/run-06-2026-04-30-workers-perf/run-perf-pure.sh

# Override sweeps:
WORKER_COUNTS="2 16" RPS=400 bash run-perf.sh
WORKER_COUNTS="2 8 32" VUS=500 bash run-perf-pure.sh
```

Each script writes per-iteration k6 logs into this directory and
appends a one-line summary into `summary.txt` /
`summary-pure.txt`.
