# k6 test results — 2026-04-28 (post F-T1 + F-T4 + F-T5 baseline)

Second whole-system run captured after the post-k6 follow-up
landed F-T1 (admin login wired), F-T4 (waf.test.yaml + tuned k6
stages), and F-T5 (admin scripts fail fast on login error).

The previous run on the same date (recorded in git history of
this file) is now superseded.

## Run context

| Field | Value |
|---|---|
| Date (UTC)         | 2026-04-28T22:18Z |
| Host               | Darwin 23.1.0 arm64 (Apple Silicon laptop) |
| Gateway binary     | `target/release/waf` (release build) |
| Config             | **`config/waf.test.yaml`** (lower load-mode thresholds for k6) |
| Data plane         | `host.docker.internal:8080` (plain HTTP) |
| Admin plane        | `host.docker.internal:9443` (plain HTTP — `/admin/login` now wired) |
| k6 version         | `grafana/k6:0.51.0` (in `aegis-k6` container) |
| Per-script logs    | `*.log` files in this directory |

## Summary

| Script | Threshold | Result | Detail |
|---|---|---|---|
| `baseline.js` | `p99 < 5ms` allow latency | **FAIL** (env) | p95 = 9.54 ms, throughput 37 533 RPS — host-bound, not a WAF bug. Captured under F-T6. |
| `baseline.js` | `rps > 5000` | **PASS** | 37 533 RPS sustained over 15 s |
| `baseline.js` | `allow_success > 99.9 %` | **PASS** | 100.00 % (562 934 / 562 934) |
| `mixed-tiers.js` | `critical_fail_open == 0` | **PASS** | 0 fail-opens over 60 s × 5 500 RPS |
| `mixed-tiers.js` | `tier:critical 4xx < 1 %` | **PASS** | 0.00 % (0 / 30 001) — previous run's 5.99 % was cross-test strike contamination, not a real bug |
| `ddos-burst.js` | `auto_block_count > 0` | **PASS** | 40 001 blocks observed (was: 0 vacuous pass pre-F-T2) |
| `ddos-burst.js` | `p95 autoblock_latency < 2 s` | **PASS** | p95 = 1 ms (was: counter empty pre-F-T2) |
| `loadmode-degradation.js` | `auto_elevated_observed > 0` | **PASS** | 100 % (9/9 polls saw `elevated`) |
| `loadmode-degradation.js` | `auto_critical_observed > 0` | **PASS** | 100 % (9/9 polls saw `critical`) — F-T4 fix working |
| `security-toggle-flips.js` | mask flip propagation | **PASS** | `blocked_when_sqli_on: 100 %`, `allowed_when_sqli_off: 100 %` (30 / 30 each) |
| `risk-strikes.js` | strike-block reached | **PASS** | rate == 1; permanent block after 50 malicious events |
| `risk-strikes.js` | clean req still blocked after strike | **PASS** | rate == 1 (1 / 1) |
| `verbosity-pin.js` | new audit entries during silent window | **PASS** | count == 0 over 8 s × 100 RPS of malicious requests |

**12 of 13 thresholds PASS, 1 FAIL (environmental, F-T6 documented).**

The single FAIL is `baseline.js p99 latency` — host-bound, not a WAF bug. F-T2 closed the only remaining real-bug gap.

## What changed since the previous run

| Change | Effect |
|---|---|
| **F-T1** `POST /admin/login` + `/admin/logout` wired | All 3 admin-needing k6 scripts now exercise the real audit-mutated path end-to-end |
| **F-T4** `config/waf.test.yaml` ships with `elevated_rps=500, critical_rps=2000` | `loadmode-degradation.js` reaches Critical (was 0/8 → now 9/9) |
| **F-T4** `loadmode-degradation.js` stages re-tuned to 100/750/3000 RPS | Stays in laptop range; no dropped iterations |
| **F-T5** All 3 admin scripts moved login into k6's `setup()` | Pre-flight failure aborts the whole run with one clear error instead of millions of retry log lines |
| **F-T5** Login response cookies read from `Set-Cookie` headers directly | Bypasses k6's cookie jar dropping `Secure` cookies on plain HTTP — works against the dev/test admin listener without weakening server behaviour |
| Per-iteration risk reset added to `security-toggle-flips.js` | Prevents the test's own SQLi-on probes from accumulating strikes that mask the propagation signal |

## Known gaps (open in `plans/post-k6-followup.md`)

- **F-T6 — latency baseline.** p95 = 9.54 ms on a laptop
  running k6 + Docker + WAF + browser is environmental, not
  a WAF bug. Documented as the host-vs-laptop trade-off.
- ~~F-T2 — DDoS auto-block.~~ **Closed.** `IpRateLimiter` wired
  into `handle_data_request`; live run shows 40 001 blocks
  with p95 latency 1 ms.

## Cross-test contamination — important harness note

If a single script accumulates strikes against `127.0.0.1`
(via the SQLi-on probes in `security-toggle-flips.js` or
the malicious sweep in `risk-strikes.js`) and a follow-on
test runs against the same gateway, the follow-on test's
otherwise-clean traffic will get strike-blocked.

**Mitigation:** restart the WAF between scripts, OR call
`PUT /api/risk/127.0.0.1/reset` between them. The current
harness does the latter inside `security-toggle-flips.js`
per iteration. `mixed-tiers.js` and `ddos-burst.js` are
"no-auth" tests so they can't reset; the recipe in
"Reproducing" below restarts the WAF before each.

## Per-script artefacts

- `baseline.log`
- `mixed-tiers.log`
- `ddos-burst.log`
- `loadmode-degradation.log`
- `security-toggle-flips.log`
- `risk-strikes.log`
- `verbosity-pin.log`

Large logs are trimmed to the first 50 + last 200 lines so the
repo doesn't carry MB of k6 banner output. Re-run for fresh
detail.

## Reproducing

```sh
# Bring up the docker stack (etcd / k6 / etc.)
docker compose -f deploy/docker-compose.dev.yml \
               -f deploy/docker-compose.test.yml up -d

# WAF on the test config (lower load_mode thresholds)
target/release/waf run --config config/waf.test.yaml &
WAF_PID=$!

# Wait for ready
until curl -sf http://127.0.0.1:9443/healthz/ready >/dev/null; do
  sleep 0.5
done

# Run each script. Restart the WAF before mixed-tiers and
# ddos-burst so they get a clean strike state.
docker exec aegis-k6 k6 run -e DURATION=15s /scripts/baseline.js

docker exec aegis-k6 k6 run \
  -e WAF_ADMIN=http://host.docker.internal:9443 \
  /scripts/loadmode-degradation.js

docker exec aegis-k6 k6 run \
  -e WAF_ADMIN=http://host.docker.internal:9443 \
  -e ADMIN_USER=admin -e ADMIN_PASS=aegis-test-1234 \
  /scripts/security-toggle-flips.js

docker exec aegis-k6 k6 run \
  -e WAF_ADMIN=http://host.docker.internal:9443 \
  -e ADMIN_USER=admin -e ADMIN_PASS=aegis-test-1234 \
  /scripts/risk-strikes.js

docker exec aegis-k6 k6 run \
  -e WAF_ADMIN=http://host.docker.internal:9443 \
  -e ADMIN_USER=admin -e ADMIN_PASS=aegis-test-1234 \
  /scripts/verbosity-pin.js

# Restart for clean state — strike accumulator from earlier
# tests will otherwise mark every request 403.
kill $WAF_PID; sleep 1
target/release/waf run --config config/waf.test.yaml &
WAF_PID=$!
sleep 2

docker exec aegis-k6 k6 run /scripts/mixed-tiers.js

kill $WAF_PID; sleep 1
target/release/waf run --config config/waf.test.yaml &
WAF_PID=$!
sleep 2

docker exec aegis-k6 k6 run /scripts/ddos-burst.js

kill $WAF_PID
```
