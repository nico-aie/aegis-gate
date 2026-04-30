# Cluster (HA) smoke tests

Live two-node integration tests that exercise the Phase B
milestone B1 contract: shared Redis state backend, cross-node
leader lease, rehydrate-readiness gate, and partition-safe
merge on heal.

These are **not** unit tests — they boot real `waf` processes,
real Redis, and assert behaviour over admin / data-plane HTTP.
Run them after `cargo test --workspace` clears the per-crate
gate.

## Layout

```
tests/cluster/
├── README.md                   this file
├── _common.sh                  helpers (redis up/down, node start/stop, wait_ready)
├── 01-shared-counter.sh        per-IP counter shared across A + B
├── 02-leader-failover.sh       killing the leader hands off the lease
├── 03-rehydrate-readiness.sh   /healthz/ready honours the warm-up window
├── 04-partition-fallback.sh    Redis partition → fallback → heal → union
└── run-all.sh                  drive everything in order
```

The two test configs live alongside the existing dev/test
configs:

```
config/
├── waf.cluster-a.yaml   data :8080  admin :9443  redis://127.0.0.1:6379
└── waf.cluster-b.yaml   data :8090  admin :9543  redis://127.0.0.1:6379
```

Both nodes are the **same** binary — distinguished only by bind
ports. Both point at the *same* Redis primary, which is how
they form a cluster on a single host.

## What each script proves

| # | Script | Phase B contract | Pass criterion |
|---|---|---|---|
| 01 | shared-counter | **B1-T1 + B1-T2** | After requests to both nodes, node B's RiskTracker view of `127.0.0.1` shows recent activity (`idle_seconds < 60`). Without shared state, node B would show no activity from node A's traffic. |
| 02 | leader-failover | **B1-T3** | Exactly one node reports `is_leader: true` from `/api/cluster/leader`. After killing the leader, the survivor flips to `is_leader: true` within 10 s. |
| 03 | rehydrate-readiness | **B1-T5** | While Redis is unreachable on boot, `/healthz/ready` returns 503 for at least 200 ms. After Redis comes back, readiness flips to 200 within `state.reconcile.readiness_warm_ms` + slack. |
| 04 | partition-fallback | **B1-T6** | Stopping Redis must not stop the data plane on either node — both keep answering `GET /` with non-zero status. After Redis returns, both nodes converge to ready=200. |

## Prerequisites

| Tool | Why |
|---|---|
| `docker` | start the `aegis-cluster-redis` container |
| `curl` | probe data + admin endpoints |
| `jq` | parse the admin JSON responses |
| `target/release/waf` | the gateway under test (`cargo build -p aegis-bin --release`) |

If any are missing, every script bails with a clear `SKIP:` line
rather than producing false negatives.

## Bring-up

```sh
# 1. Build the release binary.
cargo build -p aegis-bin --release

# 2. Run the whole track.
tests/cluster/run-all.sh

# 3. Or run scripts individually.
tests/cluster/01-shared-counter.sh
tests/cluster/02-leader-failover.sh
tests/cluster/03-rehydrate-readiness.sh
tests/cluster/04-partition-fallback.sh
```

Each script cleans up after itself via a `trap EXIT` that stops
the nodes (and the Redis container, where relevant). On a failed
run, look at the per-node logs the helpers leave behind:

```
/tmp/waf-cluster-a.log
/tmp/waf-cluster-b.log
```

## Manual cleanup

If a script crashed mid-run and left state on disk:

```sh
pkill -f 'waf run --config config/waf.cluster-' || true
docker rm -f aegis-cluster-redis 2>/dev/null || true
```

## Known limitations

- **No load balancer in front of the cluster.** The current
  perf harness drives k6 at `:8080` (node A) and `:8090`
  (node B) sequentially. That proves per-node throughput
  + correctness but does **not** measure the HA properties
  operators actually buy when they deploy a fleet — single-
  endpoint throughput, mid-burst failover, sticky sessions,
  upstream pool sharing. Three concrete options for closing
  the gap (HAProxy / DNS round-robin / `SO_REUSEPORT`) are
  in
  [`HA-TEST-METHODOLOGY.md`](./HA-TEST-METHODOLOGY.md). The
  recommended next step is option 2 (HAProxy in front) —
  see `Implement-Progress.md`'s carry-over list.
- These scripts run **two nodes on one host**. That's enough to
  prove the state-backend + lease + readiness contracts, but it
  doesn't exercise real network partitions (use `tc qdisc` or a
  netem container for that). `04-partition-fallback.sh` simulates
  the partition by stopping the Redis container, which the
  gateway sees as `WafError::State` — same code path, smaller
  blast radius.
- `01-shared-counter.sh` uses idle-seconds as a proxy for
  shared-counter visibility. A future refinement is the
  per-bucket count via the metrics endpoint once
  `waf_rate_limit_bucket_value` lands.
- `02-leader-failover.sh` and `04-partition-fallback.sh` both
  depend on admin endpoints (`/api/cluster`,
  `/api/blocks`). The leader-state surface landed in
  carry-over 3 (run-04); `/api/blocks` remains a follow-up.

## Sister tracks

- **HTTPS**: `tests/api/tls.sh` (admin), `tests/api/tls-data.sh`
  (data plane), `tests/api/tls-ciphers.sh` (negotiation),
  `tests/load/tls-baseline.js` (k6 over HTTPS).
- **Plaintext load**: `tests/load/baseline.js`,
  `tests/load/ddos-burst.js`, `tests/load/rate-limit.js`,
  `tests/load/mixed-tiers.js`, …

## Reference

- [`docs/operations/ha-clustering.md`](../../docs/operations/ha-clustering.md)
- [`plans/phase-b/README.md` § B1](../../plans/phase-b/README.md#b1--ha--multi-node-unblocks-everything-else)
- [`Implement-Progress.md`](../../Implement-Progress.md) — current
  Phase B status board.
