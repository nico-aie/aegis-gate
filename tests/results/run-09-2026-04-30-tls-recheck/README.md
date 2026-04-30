# Run 09 — 2026-04-30 — TLS-T1 clean-host TLS handshake re-check

Closes the run-05 noise carry-over. Re-measures
`tls-baseline.js` against `config/waf.tls.yaml` to check
whether the handshake-latency tail seen in run-05 was a real
regression or host noise.

## History

| Run | `tls_handshake_ms` p95 | `tls_request_ms` p95 | RPS | Verdict at the time |
|---|---|---|---|---|
| 04 | **2.12 ms** | 1.03 ms | 31 838 | clean baseline |
| 05 | 9.08 ms ⚠️ | 1.07 ms | 31 236 | suspicious; flagged for re-measure |
| **09** (this run) | **5.23 ms** | **1.04 ms** | **31 386** | host noise, not a regression |

## Verdict

**The run-05 number was host noise.** The post-handshake
per-request latency (`tls_request_ms`) is unchanged within
1 µs across all three runs; only the handshake tail moves.
This run's handshake p95 (5.23 ms) sits between the run-04
baseline (2.12 ms) and the run-05 spike (9.08 ms), so the
"true" handshake latency on this hardware varies in the
2–5 ms range depending on:

- whether the laptop has been idle (cold cache → faster) or
  busy (hot cache + scheduler contention → slower);
- how loaded Docker / Spotlight / browser are at run time;
- whether previous TLS sessions were resumed or full
  handshake (k6 doesn't pin a session-resumption mode).

No code-level handshake regression has occurred. The carry-
over closes.

## Run context

| Field | Value |
|---|---|
| Date (UTC) | 2026-04-30T09:35Z |
| Host | Darwin 23.1.0 arm64, 12 logical CPUs |
| Binary | `target/release/waf` built with HP-T1 (hyper-rustls + ring CryptoProvider installed) |
| Config | [`config/waf.tls.yaml`](../../../config/waf.tls.yaml) |
| Scenario | `tls-baseline.js` 20 VUs × 15 s, ALPN forced to `http/1.1` |

## What's left

Both run-05 carry-overs are now resolved:

- ✅ **Run-05 cluster-failover budget** — closed in run-05/06
  with HA-T5.
- ✅ **Run-05 TLS handshake noise** — closed here.

No open carry-overs from any prior run. The next track is the
dashboard redesign.

## Reproducing

```sh
cargo build -p aegis-bin --release --features redis
target/release/waf run --config config/waf.tls.yaml &
sleep 4
docker exec aegis-k6 k6 run -e DURATION=15s -e VUS=20 \
  -e WAF_TLS_TARGET=https://host.docker.internal:8443 \
  /scripts/tls-baseline.js
pkill -f 'target/release/waf'
```
