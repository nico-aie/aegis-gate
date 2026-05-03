# Performance checklist

Goals on a `make run-dev` profile (laptop, 4-8 cores, no SIMD
tuning):

| Metric | Target | Source |
|---|---|---|
| Throughput sustained | ≥ 1 000 req/s | `make mock-load-mix` 30 s |
| Latency p99 (data plane) | ≤ 5 ms | `/metrics` `waf_request_duration_ms` |
| Latency p50 | ≤ 1 ms | same |
| Memory after 60 s | stable, no growth trend | `ps -o rss` on the WAF |
| Audit batch flush | < 200 ms p99 | inferred from `/api/audit/since` poll |

For comparison, the prod-balanced 5 k+ RPS run on a beefier
machine sustained 4 891 RPS k6 / 6 392 RPS WAF-internal at
p99 1.03 ms — see
`tests/results/run-perf-5krps-prod-balanced-2026-05-02-v3/REPORT.md`.

## P1 — Throughput baseline

```bash
make mock-load-mix DURATION=30s
```

In another shell, scrape `/metrics` once before, once after.
Compute `delta(waf_requests_total) / 30`. File a finding if it's
under the floor.

## P2 — Latency distribution

```bash
curl -s http://127.0.0.1:9443/metrics | \
  grep -E 'waf_request_duration_ms_bucket|_sum|_count' | head -30
```

Compute p50 / p95 / p99 from the histogram. Compare to last
known good baseline in `tests/results/`. >2x regression is a
HIGH finding.

## P3 — Memory under load

Find the WAF PID, sample RSS:

```bash
PID=$(pgrep -f "target/release/waf" | head -1)
for i in 1 2 3 4 5 6; do
  ps -o rss= -p "$PID"
  sleep 5
done
```

Steady-state should plateau within 30 s. Continuous growth →
HIGH finding (memory leak suspect).

## P4 — Audit batch shape

The audit chain batches to disk every 1 s by default. Write an
event, immediately fetch:

```bash
# Drive one request, then poll /api/audit/since at 1 Hz for 5 s.
curl -s http://127.0.0.1:8080/api/foo -o /dev/null
for i in 1 2 3 4 5; do
  curl -s "http://127.0.0.1:9443/api/audit/since?limit=1" \
    | jq -r '.events[0].event.ts'
  sleep 1
done
```

The first event timestamp should appear within 1 s of the
request. Lag > 2 s is a finding.

## P5 — SSE backpressure

Open `/dashboard/sse` with `curl -N`, drive `make mock-load-mix`,
observe whether SSE keeps up or drops the connection. The stream
should emit `:lagged` markers if the consumer is slow, never
disconnect silently.

## P6 — Hot-reload latency

Edit `config/dev.yaml` (e.g. flip a detector). Time from save to
the WAF logging `config_reload`. Target: <500 ms (file watcher
inotify delay is ~100 ms; everything else is config-validate +
ArcSwap). >2 s is a finding.

## P7 — Cold-start time

Restart `make run-dev`. Time from `cargo run` exec to first
successful `/healthz/ready`. Target: <3 s on a laptop (debug
build is slower; use `make build && ./target/release/waf` for
the apples-to-apples comparison).

## P8 — Clipping / saturation

Run a real saturation drive:

```bash
DURATION=60s make mock-load-mix
```

Watch the WAF stdout for:
- `loadmode degraded → critical` log lines (expected at >2k RPS
  on `make run-dev` defaults).
- Any `lagged` warnings on the audit bus.
- Any `connection refused` / `accept error` storms.

Document the actual RPS where the dashboard p99 first crosses
5 ms. That's your "knee" on this hardware.

## Reporting shape

For perf findings, always include:

- The commit SHA tested (`git rev-parse HEAD`)
- The hardware (uname -a + CPU model)
- The build features (`cargo build` flags / `FEATURES=`)
- The baseline measurement
- The observed measurement
- The delta + significance (e.g. "2.3x regression on p99")
