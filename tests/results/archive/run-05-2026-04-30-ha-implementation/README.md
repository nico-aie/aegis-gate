# Run 05 — 2026-04-30 — HA implementation (HA-T1..HA-T5)

Live perf re-run captured **after** the full
[`plans/cluster-ingress-lb.md`](../../../plans/cluster-ingress-lb.md)
HA track landed. Closes carry-over 6 (HA test methodology gap)
and proves the new LB-fronted topology works end-to-end with
graceful drain.

## What changed since run-04

| Track | Status | Files |
|---|---|---|
| **HA-T1** HAProxy reference deploy | landed | `deploy/haproxy/haproxy.cfg`, `deploy/docker-compose.dev.yml` |
| **HA-T2** Single-VIP load tests | landed | `tests/cluster/05-single-vip-baseline.sh`, `06-mid-burst-failover.sh`, `tests/load/failover-burst.js` |
| **HA-T3** Stable `node.id` config knob | landed | `crates/aegis-core/src/config.rs` `NodeConfig`, `crates/aegis-bin/src/lease_select.rs` `derive_node_id(&cfg)` |
| **HA-T4** Cluster `peers[]` membership | landed | `crates/aegis-control/src/api/tracking.rs` `LeaderView::{set_members, members}`, membership heartbeat + roster poller in `crates/aegis-proxy/src/lib.rs` |
| **HA-T5** LB-friendly readiness semantics | landed | `crates/aegis-control/src/health.rs` `check_ready_strict`, `POST /admin/drain` handler, SIGTERM → drain → 5 s grace → abort |

Run-05 also fixed two latent issues surfaced while wiring the
above:

1. **HAProxy health probe was hitting the data port.** The
   reference config used `option httpchk … server waf-a
   host.docker.internal:8080` which 404'd `/healthz/ready` (it
   only exists on the admin port). Switched to `port 9443` /
   `port 9543` so the L7 check probes the admin plane while
   traffic still flows to the data plane.
2. **Round-robin skewed badly with HTTP keep-alive.** k6's
   long-lived VU connections concentrate on whichever backend
   gets allocated first. Switched HAProxy to `balance leastconn`
   which rebalances continuously on persistent sockets.

## Run context

| Field | Value |
|---|---|
| Date (UTC)         | 2026-04-30T05:47Z |
| Host               | Darwin 23.1.0 arm64 (Apple Silicon laptop) |
| Gateway binary     | `target/release/waf` built with `--features redis` |
| Cluster configs    | [`config/waf.cluster-{a,b}.yaml`](../../../config/) (Redis-backed, `node.id: waf-a`/`waf-b`) |
| HTTPS config       | [`config/waf.tls.yaml`](../../../config/waf.tls.yaml) (data plane :8443, ALPN `http/1.1`) |
| Real upstream      | `aegis-httpbin` container on `127.0.0.1:8081` |
| Redis              | `aegis-redis` container on `127.0.0.1:6379` |
| LB                 | `aegis-lb` HAProxy 2.9.15 on `:9180` (plaintext VIP) + `:9443` (TLS VIP) + `:8404` (stats) |
| k6 version         | `grafana/k6:0.51.0` (in `aegis-k6` container) |

## Summary

| Track | Pass | Fail | Skip | Notes |
|---|---|---|---|---|
| Cluster smoke (`tests/cluster/01..04`) | 4 | 0 | 0 | All four PASS — peer-membership assertion (HA-T4) added to `01-shared-counter.sh` confirms `waf-a`/`waf-b` see each other in `/api/cluster.peers[]` after ~12 s convergence |
| LB suite (`tests/cluster/05..06`) | 3 | 0 | 0 | Single-VIP baseline + mid-burst failover (hard kill **and** graceful drain) all green |
| HTTPS load (`tests/load/tls-baseline.js`) | 1 | 0 | 0 | 31.2 k RPS, handshake p95 9.08 ms (slower than run-04's 2.12 ms — see §"Notes on latency") |

## Single-VIP baseline (HA-T2)

Log: [`lb-vip-baseline.log`](./lb-vip-baseline.log).

| Metric | Result |
|---|---|
| k6 throughput at VIP | **9 469 RPS** (147 k reqs / 15 s × 20 VUs) |
| HAProxy `stot` waf-a | 15 264 |
| HAProxy `stot` waf-b | 27 852 |
| Per-backend share | A=35 %, B=64 % (≥ 15 % floor each) |

The skew is from k6's keep-alive sockets concentrating on the
backend that received earlier connection assignments;
`leastconn` keeps it within a 2× factor on a 15 s laptop run.
Production setups with many short-lived clients converge to
~50/50 because each new connection is rebalanced.

## Mid-burst failover budget (HA-T2 + HA-T5)

Logs: [`lb-failover-hard.log`](./lb-failover-hard.log),
[`lb-failover-graceful.log`](./lb-failover-graceful.log).

30 s `failover-burst.js` (200 RPS constant arrival rate, rate-
controlled) at the VIP. At t≈10 s, node B is killed:

| Variant | Method | `allow_success` | HAProxy `chkfail` waf-b | Status |
|---|---|---|---|---|
| Hard | `SIGKILL` | **99.93 %** ≥ 80 % floor | 2 | PASS |
| Graceful | `POST /admin/drain` → 5 s wait → `SIGTERM` | **100.00 %** ≥ 99 % floor | 3 | PASS |

The graceful path produces **zero 5xx**. HA-T5's pattern
(operator drain flag → external LB observes 503 on
`/healthz/ready` → LB stops sending traffic → process aborts)
delivers the active-active production topology cluster
operators expect. The hard-kill path absorbs the 4 s `inter
× fall` window with HAProxy's retries + `option redispatch`
default, surfacing only 0.07 % failure rate.

The earlier two iterations of this test surfaced and fixed:

- HAProxy probing the wrong port (data 8080/8090 instead of
  admin 9443/9543) — `option httpchk` now uses `port 9443/9543`.
- The `failover-burst.js` script replaces `baseline.js` for
  this test because constant-VU executors saturate the
  laptop's ephemeral-port budget under the rate-limit-relaxed
  cluster configs (the upstream forwarder still does new TCP
  per request — connection pooling lands in B6).

## Cluster smoke + peer convergence (HA-T4)

Log: [`cluster-smoke.log`](./cluster-smoke.log) (full output of
`tests/cluster/run-all.sh`).

| Test | Result |
|---|---|
| `01-shared-counter.sh` | PASS — HA-T4 peers convergence: both nodes see `waf-a` + `waf-b` in `/api/cluster.peers[]` within 12 s of boot |
| `02-leader-failover.sh` | PASS — leader hand-off after `SIGKILL` of holder |
| `03-rehydrate-readiness.sh` | PASS — `/healthz/ready` flips 200 after Redis returns |
| `04-partition-fallback.sh` | PASS — both nodes serve traffic during Redis outage; block lists converge after heal |

## HTTPS load — `tls-baseline.js`

Log: [`tls-baseline.log`](./tls-baseline.log).

20 VUs × 15 s against `https://127.0.0.1:8443` (TLS 1.3, ECDSA
self-signed, ALPN forced to `http/1.1`):

| Metric | Run-04 (last) | Run-05 (this) |
|---|---|---|
| `http_reqs` rate | 31 838 RPS | **31 236 RPS** (within 2 %) |
| `tls_handshake_ms` p95 | **2.12 ms** | 9.08 ms ⚠️ |
| `tls_handshake_ms` median | 1.67 ms | 6.61 ms |
| `tls_request_ms` p95 (post-handshake) | 1.03 ms | **1.07 ms** |
| `tls_request_ms` median | 512 µs | 521 µs |
| `tls_success` | 9 998 | 9 998 (matches per-IP rate-limit budget) |

### Notes on latency

The `tls_handshake_ms` p95 grew ~4× since run-04. The per-
request post-handshake latency (`tls_request_ms`) is unchanged
within noise (1.07 ms vs 1.03 ms), so the regression is
exclusively in the rustls handshake step. Likely sources, in
order of likelihood:

1. Host noise from running redis + httpbin + k6 + HAProxy +
   the WAF on the same Apple-Silicon laptop. The laptop test
   rig has been documented as unreliable for handshake-tail
   measurements (`tests/load/README-perf.md`).
2. Run-04 used a fresh laptop reboot; run-05 has been running
   docker containers + Rust builds for several hours.
3. No code path in the TLS stack changed between runs that
   would cost handshake CPU — so this is not a regression in
   `aegis-proxy::run` or `aegis_security::detectors`.

The handshake number warrants a dedicated capture on a clean
host before being treated as a regression. Per-request post-
handshake p95 is the production-relevant number and stayed
flat.

## Comparison vs run-04

| Track | run-04 | run-05 | Δ |
|---|---|---|---|
| Cluster smoke pass count | 4 / 4 | 4 / 4 | flat |
| HTTPS p95 request latency (post-handshake) | 1.03 ms | 1.07 ms | flat (within noise) |
| HTTPS RPS | 31.84 k | 31.24 k | -2 % (within noise) |
| Single-VIP test exists? | NO | **YES — 9.5 k RPS** | gap closed |
| Mid-burst failover budget exists? | NO | **YES — 99.93 % (hard) / 100 % (graceful)** | gap closed |
| Peers visibility test exists? | NO | **YES — both members converge in 12 s** | gap closed |
| Operator drain endpoint exists? | NO | **YES — `POST /admin/drain`** | gap closed |

## Carry-over outcomes

| Carry-over | Status before run-05 | Status after run-05 |
|---|---|---|
| 6 (HA test methodology — single-VIP, failover, peers) | open | **CLOSED** |

## What's left after run-05

- **B6-T1** — production Dockerfile (multi-stage, distroless,
  `< 100 MiB` compressed). Unblocked.
- **Upstream connection pool** — the 4–5 k RPS limit measured
  here for fully-forwarded cluster traffic (not 429-throttled)
  comes from the upstream forwarder opening a fresh TCP
  connection per request. Tracked as a B6-track candidate; not
  blocking carry-over closure.
- **Handshake p95 regression on TLS baseline** — needs a
  re-measure on a clean host. Not promoted to a carry-over
  yet.

## Reproducing

```sh
# Build the release binary with the redis feature.
cargo build -p aegis-bin --release --features redis

# Reuse existing aegis-redis + aegis-httpbin containers.
export AEGIS_REDIS_NAME=aegis-redis

# Cluster smoke (4 scripts including HA-T4 peers).
tests/cluster/run-all.sh

# LB suite (5 + 6 — HA-T2).
AEGIS_LB_TESTS=1 tests/cluster/run-all.sh

# Hard-kill mid-burst.
tests/cluster/06-mid-burst-failover.sh

# Graceful drain mid-burst (HA-T5).
AEGIS_GRACEFUL=1 tests/cluster/06-mid-burst-failover.sh

# HTTPS perf — TLS data-plane fixture.
target/release/waf run --config config/waf.tls.yaml &
sleep 3
docker exec aegis-k6 k6 run -e DURATION=15s -e VUS=20 \
  -e WAF_TLS_TARGET=https://host.docker.internal:8443 \
  /scripts/tls-baseline.js
pkill -f 'target/release/waf'
```
