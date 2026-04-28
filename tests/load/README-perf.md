# `tests/load/` — performance SLOs and host expectations

The k6 thresholds in `baseline.js` are written for a **dedicated
load-test host**, not a developer laptop. Running them on a
laptop with k6 + Docker + the WAF + a browser + an IDE all on
the same CPU consistently fails the latency SLO even though the
WAF itself is healthy. This document captures the trade-off so
nobody chases a phantom regression.

## The two performance contracts

There are two layers of "performance":

1. **In-WAF** — the time the gateway spends classifying a
   request, running detectors, taking a rate-limit decision,
   and emitting the audit event. This is what
   `aegis-proxy::handle_data_request` controls.
2. **End-to-end RTT** — what k6 sees: TCP connect, request
   write, server read+process, response write, TCP read, k6
   parse. Everything except `(server read+process)` is host
   noise that the WAF can't fix.

`baseline.js` measures **end-to-end RTT** because that's what k6
exposes via `http_req_duration`. F-T10 splits the WAF-internal
time into a per-stage histogram so we can subtract the host
overhead from a measurement; until that lands, treat
`http_req_duration` as `(host noise) + (WAF time)`.

## Host targets

| Host class | k6 location | `p99` (allow path) | `RPS` per node | `allow_success` |
|---|---|---|---|---|
| **Dedicated** — bare metal or single-tenant VM, no other tenants, k6 on a separate machine | external | `≤ 5 ms` | `≥ 5 000` | `≥ 99.9 %` |
| **CI runner** — GitHub Actions / GitLab Runner standard tier, k6 + WAF on the same node, Docker overhead included | local | `≤ 25 ms` | `≥ 2 000` | `≥ 99.9 %` |
| **Developer laptop** — k6 + Docker + WAF + browser + IDE | local | `≤ 100 ms` | `≥ 1 000` | `≥ 99.5 %` |

The single hardcoded threshold in `baseline.js` —
`p(99)<5ms` — is the **dedicated** target. CI and laptop runs
will fail it; that failure is *informational*, not a release
gate.

## How to read a baseline run

| Output line | What it tells you |
|---|---|
| `http_reqs.../s` | Sustained throughput. Above 5 000 RPS even on a laptop = WAF is healthy; below 1 000 RPS = something is wrong, investigate. |
| `allow_success` | Hit rate of 200 OK on the catch-all route. Anything below 99 % = real regression, regardless of host. |
| `allow_latency_ms p(99)` | End-to-end RTT. Compare against the table above for the host you're on. |
| `http_req_failed` | Should always be 0 % on a healthy run. Non-zero = TCP / connection / shedder issue. |

## Reproducing dedicated numbers

If you need to confirm the SLO holds, run from a host that
matches the "dedicated" row:

```sh
# On a fresh single-tenant VM with the binary already built
target/release/waf run --config config/waf.test.yaml &
WAF_PID=$!
until curl -sf http://127.0.0.1:9443/healthz/ready >/dev/null; do
  sleep 0.5
done

# Run k6 from a *different* machine pointed at this host's :8080
docker run --rm \
  -e WAF_TARGET=http://<this-host-ip>:8080 \
  -v "$(pwd)/tests/load":/scripts:ro \
  grafana/k6:0.51.0 run /scripts/baseline.js

kill $WAF_PID
```

Anything else (k6 on the same host, Docker layer in between,
laptop) will not hit the 5 ms p99.

## CI-vs-laptop table for the rest of the suite

The latency SLO is the only one that's hardware-sensitive.
Every other threshold in `tests/load/*.js` works on any host:

| Script | Threshold | Host-sensitive? |
|---|---|---|
| `baseline.js` | `p99 < 5 ms` | **Yes** — dedicated only |
| `baseline.js` | `RPS > 5 000`, `allow_success > 99.9 %` | No |
| `mixed-tiers.js` | `critical_fail_open == 0` | No |
| `ddos-burst.js` | `auto_block_count > 0`, `p95 autoblock_latency < 2 s` | No |
| `loadmode-degradation.js` | `auto_elevated`, `auto_critical observed` | Sensitive to RPS ceiling — laptop must use `config/waf.test.yaml` |
| `security-toggle-flips.js` | mask flip rates | No |
| `risk-strikes.js` | strike-block reaches | No |
| `verbosity-pin.js` | audit silent count | No |
| `audit-since.js` (F-T9) | replay-shape contract | No |
| `cold-tier.js` (F-T9) | inventory shape | No |

## When the SLO actually slips

If a dedicated-host run starts failing `p99 < 5 ms`:

1. Run with F-T10's per-stage histogram enabled (when it
   lands) and check which stage's contribution grew.
2. Attach `tracing` at `level=info` and look for slow request
   IDs.
3. Compare against the previous green run's WAF binary;
   `cargo bench` (when added) will help bisect.
4. Common culprits: a detector regex that backtracks, a hot
   `Mutex` contention point, a new audit-sink that blocks on
   write. None of these are host-sensitive; they show up as
   p99 slips on **every** host class proportionally.
