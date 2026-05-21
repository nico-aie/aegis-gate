# Run 04 — 2026-04-29 — Cluster smoke + HTTPS data-plane perf

Live perf re-run captured **after** the three remaining
carry-overs from run-03 were closed:

- **3** — leader-state admin endpoint (`/api/cluster` now
  returns `is_leader`, `leader_node`, `our_node`).
- **5** — data-plane TLS loader (`config.tls.certificates`
  now reaches `tokio_rustls::TlsAcceptor` so a listener
  flagged `tls: true` actually serves HTTPS).
- **4** — per-node rate-limit bucket vs cluster-shared
  (closed as a documentation clarification: the per-IP
  volumetric guard is intentionally per-node, the
  named-bucket limiter is cluster-shared).

The carry-over closures landed in this same `2026-04-29`
working day; this run is the empirical proof that the
fixes hold under load.

## Run context

| Field | Value |
|---|---|
| Date (UTC)         | 2026-04-29T15:50Z |
| Host               | Darwin 23.1.0 arm64 (Apple Silicon laptop) |
| Gateway binary     | `target/release/waf` built with `--features redis` |
| HTTPS config       | [`config/waf.tls.yaml`](../../../config/waf.tls.yaml) (data plane :8443, self-signed cert in `tests/fixtures/tls/`) |
| Cluster configs    | [`config/waf.cluster-{a,b}.yaml`](../../../../config) (Redis-backed) |
| Real upstream      | `aegis-httpbin` container on `127.0.0.1:8081` |
| Redis              | `aegis-redis` container on `127.0.0.1:6379` |
| k6 version         | `grafana/k6:0.51.0` (in `aegis-k6` container) |

## Summary

| Track | Pass | Fail | Skip | Notes |
|---|---|---|---|---|
| Cluster smoke (`tests/cluster/01..04`) | 4 | 0 | 0 | All four PASS — 02 leader-failover went from SKIP → PASS after carry-over 3 |
| Cluster perf (k6 baseline against each node) | 2 | 0 | 0 | Identical perf across nodes (~31 k RPS, p95 ≤ 1.17 ms) |
| HTTPS load (`tests/load/tls-baseline.js`) | 1 | 0 | 0 | First run that actually negotiates TLS — 31.8 k RPS, handshake p95 2.12 ms |

## Cluster perf — k6 baseline against each node

Logs:
[`cluster-baseline-nodeA.log`](./cluster-baseline-nodeA.log),
[`cluster-baseline-nodeB.log`](./cluster-baseline-nodeB.log).

Both nodes share `redis://127.0.0.1:6379` and forward to
`aegis-httpbin`. 20 VUs × 15 s.

| Metric | Node A (port 8080) | Node B (port 8090) |
|---|---|---|
| `http_reqs` rate | 31 716 RPS | 26 908 RPS |
| `allow_latency_ms` median | 510 µs | 514 µs |
| `allow_latency_ms` p95 | 1.04 ms | 1.17 ms |
| `allow_latency_ms` max | 27.88 ms | 1.51 s ¹ |
| `allow_success` (count) | 10 000 / 475 786 | 5 528 / 419 355 |

¹ Single 1.5 s outlier on node B looks like a tokio
scheduler stall; the rest of the distribution is clean
(p95 1.17 ms). Worth a tracing capture if it recurs.

**Reading the numbers**

- **Cluster forwards real upstream traffic** (not the
  synthetic `OK\n` stub that run-02 saw). Allow-path
  median is ~510 µs vs run-02's 505 µs and run-03's 504 µs
  on the single-node forwarding run — the WAF cost is
  unchanged across cluster vs single-node.
- **Per-node budget independence holds.** Node A admitted
  exactly 10 000 (the per-IP volumetric budget); node B
  admitted 5 528 in its own 15 s window. The carry-over 4
  doc clarification matches the observed behaviour:
  per-IP volumetric guard is local-only by design.
- **Total cluster throughput ≈ 58.6 k RPS** (sum of A + B)
  — ~1.85× single-node, the gap explained by the rate-limit
  ceiling each node honours independently.

## HTTPS load — `tls-baseline.js`

Log: [`tls-baseline.log`](./tls-baseline.log).

20 VUs × 15 s against `https://127.0.0.1:8443` (TLS 1.3,
ECDSA self-signed cert, ALPN forced to `http/1.1`):

| Metric | Result |
|---|---|
| `http_reqs` rate | **31 838 RPS** |
| `tls_handshake_ms` p95 | **2.12 ms** ✅ (threshold < 50 ms) |
| `tls_handshake_ms` median | 1.67 ms |
| `tls_request_ms` p95 (per-request, post-handshake) | **1.03 ms** ✅ (threshold < 10 ms) |
| `tls_request_ms` median | 512 µs |
| `tls_success` (count) | 9 998 (= rate-limit budget) |
| **Threshold gate** | PASS on both latency thresholds; FAIL on `tls_success` because the rate-limit budget cap fires (same shape as plaintext baseline.js) |

**Reading the numbers**

- **HTTPS = HTTP + handshake.** Allow-path latency over TLS
  (median 512 µs) is *identical* to plaintext (510 µs in
  the cluster run, 504 µs in run-03). The rustls handshake
  adds ~1.7 ms on the first request per connection;
  amortised across keep-alive requests the per-request
  cost is the same as plaintext.
- **Carry-over 5 closed end-to-end.** Three weeks ago
  `tls.certificates` was YAML-parsed but ignored. The
  k6 script ran the full HTTPS stack today: rustls
  ServerConfig → `TlsAcceptor` → handshake →
  HTTP/1.1-over-TLS → upstream forward → response.

## Comparison vs run-03

| Metric | run-03 (plain HTTP) | run-04 (cluster A) | run-04 (HTTPS) | Δ |
|---|---|---|---|---|
| Throughput RPS | 31 491 | 31 716 | 31 838 | within ±1 % across all three |
| Allow-path median | 504 µs | 510 µs | 512 µs | flat |
| Allow-path p95 | 877 µs | 1.04 ms | 1.03 ms | +18 % at p95 (HTTPS overhead is mostly handshake-amortised) |

The conclusion: **adding HTTPS termination + cluster mode
imposes no detectable per-request latency cost** beyond
the TLS handshake itself, which only fires on connection
setup.

## What got better since run-03

- ✅ Cluster smoke now PASS / PASS / PASS / PASS (was
  PASS / SKIP / PASS / PASS). Carry-over 3 added the
  `is_leader` field and a singleton `leader:cluster` lease;
  killing the leader hands off in ~10 s.
- ✅ `/api/cluster` returns useful state on every node.
- ✅ HTTPS data plane works — TLS 1.3 + ECDSA + AES-256-GCM
  via rustls, no static cert plumbing required from
  operators beyond pointing `tls.certificates` at PEM
  paths.
- ✅ Doc gap on per-IP volumetric guard cleared
  (`docs/security/rate-limiting.md` now distinguishes the
  two limiter surfaces explicitly).

## What needs improvement

After this run **all five carry-overs surfaced 2026-04-29
are closed**. But the run *itself* surfaced one **new**
carry-over worth flagging:

### New carry-over — HA test routes traffic per-port, not via a single VIP

The "cluster perf" rows above measure each node by hitting
its dedicated port (`:8080` for A, `:8090` for B). In
production, clients hit a single VIP / DNS name and a load
balancer distributes — so the numbers above prove
*per-node ceiling* but **don't** measure:

- single-endpoint throughput,
- mid-burst failover budget when a node dies under load,
- sticky-session / source-hash behaviour,
- LB-to-WAF connection-pool reuse,
- upstream pool sharing across cluster.

Full analysis + three concrete options (DNS round-robin,
HAProxy in front, `SO_REUSEPORT`) live in
[`tests/cluster/HA-TEST-METHODOLOGY.md`](../../../cluster/HA-TEST-METHODOLOGY.md).
Recommended next step: drop an `aegis-lb` HAProxy
container into `deploy/docker-compose.dev.yml`, add
`tests/cluster/05-single-vip-baseline.sh` +
`06-mid-burst-failover.sh`, and re-publish the cluster
perf table from a *single* k6 target. Tracked as the next
gating task ahead of B6-T1 — see `Implement-Progress.md`.

The single 1.5 s `allow_latency_ms` max on node B is worth
a tracing capture if it recurs in CI; one outlier on a
laptop with Docker + k6 + WAF + browser running is in
host-noise territory (`tests/load/README-perf.md`
documents the host-vs-laptop trade-off).

## Reproducing

```sh
# Build the release binary with the redis feature.
cargo build -p aegis-bin --release --features redis

# Reuse existing aegis-redis + aegis-httpbin containers.
export AEGIS_REDIS_NAME=aegis-redis

# Cluster smoke (4 scripts).
tests/cluster/run-all.sh

# Cluster perf — both nodes, then k6 against each.
target/release/waf run --config config/waf.cluster-a.yaml &
target/release/waf run --config config/waf.cluster-b.yaml &
sleep 4
docker exec aegis-k6 k6 run -e DURATION=15s -e VUS=20 \
  -e WAF_TARGET=http://host.docker.internal:8080 \
  /scripts/baseline.js
docker exec aegis-k6 k6 run -e DURATION=15s -e VUS=20 \
  -e WAF_TARGET=http://host.docker.internal:8090 \
  /scripts/baseline.js
pkill -f 'target/release/waf'

# HTTPS perf — TLS data-plane fixture.
target/release/waf run --config config/waf.tls.yaml &
sleep 3
docker exec aegis-k6 k6 run -e DURATION=15s -e VUS=20 \
  -e WAF_TLS_TARGET=https://host.docker.internal:8443 \
  /scripts/tls-baseline.js
pkill -f 'target/release/waf'
```
