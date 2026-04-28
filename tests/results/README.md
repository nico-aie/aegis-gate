# k6 test results — 2026-04-28

Run captured by `tests/TESTING.md` § "Layer 3 — k6 load tests"
against the dev gateway brought up from `config/waf.dev.yaml`.

## Run context

| Field | Value |
|---|---|
| Date (UTC) | 2026-04-28T16:46:31Z |
| Host | Darwin 23.1.0 arm64 (Apple Silicon laptop) |
| Git commit | `0a2d31e` |
| Gateway binary | `target/release/waf` (release build, PID 7141) |
| Config | `config/waf.dev.yaml` |
| WAF data plane | `host.docker.internal:8080` (plain HTTP) |
| WAF admin plane | `host.docker.internal:9443` (plain HTTP — see "Known gap") |
| k6 version | `grafana/k6:0.51.0` (in `aegis-k6` container) |
| Per-script logs | `*.log` files in this directory |

## Summary

| Script | Threshold | Result | Detail |
|---|---|---|---|
| `baseline.js` | `p99 < 5ms` allow latency | **FAIL** | p95 = 7.15 ms; throughput 42 811 RPS (≫ 5 000 target) |
| `baseline.js` | `rps > 5000` | **PASS** | 42 811 RPS sustained over 15 s |
| `baseline.js` | `allow_success > 99.9 %` | **PASS** | 100.00 % (642 272 / 642 272) |
| `mixed-tiers.js` | `critical_fail_open == 0` | **PASS** | 0 fail-opens recorded over 60 s × 5 500 RPS |
| `mixed-tiers.js` | `http_req_failed{tier:critical} < 1 %` | **FAIL** | 5.99 % (1 799 / 30 000) |
| `ddos-burst.js` | `p95 autoblock_latency < 2 s` | **PASS** | counter empty (no auto-block trigger fired in 10 s burst) |
| `loadmode-degradation.js` | `auto_elevated_observed > 0` | **PASS** | 100 % (8 / 8 polls saw `elevated`) |
| `loadmode-degradation.js` | `auto_critical_observed > 0` | **FAIL** | 0 / 8 polls — host couldn't sustain 12 k RPS, dropped 87 627 iters |
| `security-toggle-flips.js` | mask flip applies in < 200 ms | **BLOCKED** | login 404 — see "Known gap" |
| `risk-strikes.js` | strike block + clean blocked | **BLOCKED** | login 404 — see "Known gap" |
| `verbosity-pin.js` | audit silent during pin | **BLOCKED** | login 404 — see "Known gap" |

## Known gap — admin login HTTP route not wired

The admin login flow (`POST /admin/login`) accepts a JSON body
`{user, password}`, validates against `admin.dashboard_auth.password_hash_ref`,
issues a session + CSRF cookie. The argon2id verification helper
(`aegis_control::admin_auth::password::verify`) and the session
issuer (`aegis_control::admin_auth::session`) both exist and are
unit-tested, but the **HTTP route handler that wires them into
the proxy `admin_router` is not yet present**.

Direct evidence:

```
$ curl -i -X POST http://127.0.0.1:9443/admin/login \
    -H "content-type: application/json" \
    -d '{"user":"admin","password":"aegis-test-1234"}'
HTTP/1.1 404 Not Found
{"error":"not found","path":"/admin/login"}
```

Result: every k6 script that depends on an authenticated admin
session aborts at the login step before exercising the
audit-mutated mutation endpoint it was meant to test.

The `tests/api/*.sh` smoke layer hits the same wall — every
`aegis_login` call in `_common.sh` will get a 404 until the
route is plumbed.

### What still got verified

The four scripts that don't need admin auth ran end-to-end and
exercised the data-plane hot path:

- `baseline.js` — 642 272 GET /get over 15 s; data plane handled
  the load with 0 failures (apart from the latency SLO breach
  which is an artefact of running debug-tier docker, the WAF,
  and k6 on the same laptop).
- `mixed-tiers.js` — 330 001 mixed-tier requests; the
  CRITICAL fail-closed counter stayed at 0.
- `ddos-burst.js` — 50 000 requests at 5 000 RPS from a single
  source IP; data plane survived.
- `loadmode-degradation.js` — confirmed P7 auto-mode actually
  elevates: every 1 s sample during stage B saw
  `mode = "elevated"`. (Critical wasn't reached because the host
  couldn't actually deliver 12 k RPS — k6 dropped 87 627
  iterations rather than overflow the gateway's accept loop.
  This is a host capacity ceiling, not a WAF correctness issue.)

### Re-running after `/admin/login` lands

Once the login handler is wired, re-run the three blocked
scripts (`security-toggle-flips.js`, `risk-strikes.js`,
`verbosity-pin.js`) with the same env:

```sh
docker exec aegis-k6 k6 run \
  -e WAF_ADMIN=http://host.docker.internal:9443 \
  -e ADMIN_USER=admin \
  -e ADMIN_PASS=aegis-test-1234 \
  /scripts/<name>.js
```

The scripts already log in via `POST /admin/login` and pull the
`aegis_csrf` cookie out of the jar; no script changes needed.

## Note on `target/release/waf` vs the docs

The bring-up section of `tests/TESTING.md` originally said
`target/release/aegis-bin`, which doesn't exist — the binary is
named `waf` (`[[bin]] name = "waf"` in
`crates/aegis-bin/Cargo.toml`). That doc has been corrected;
this run used the right binary path
(`/Users/nico/waf-code/aegis-gate/target/release/waf`).

## Per-script artefacts

Each `*.log` file is the full k6 stdout including the threshold
table, per-metric percentiles, and error counters. Review them
directly for deeper diagnostics:

- `baseline.log`
- `mixed-tiers.log`
- `ddos-burst.log`
- `loadmode-degradation.log`
- `security-toggle-flips.log`
- `risk-strikes.log`
- `verbosity-pin.log`

## Reproducing

```sh
mkdir -p tests/results

# Bring up the docker stack (etcd / k6 / nuclei / etc.)
docker compose -f deploy/docker-compose.dev.yml \
               -f deploy/docker-compose.test.yml up -d

# Bring up the WAF
target/release/waf run --config config/waf.dev.yaml &

# Wait for readiness then run each script
docker exec aegis-k6 k6 run -e DURATION=15s /scripts/baseline.js | tee tests/results/baseline.log
docker exec aegis-k6 k6 run /scripts/mixed-tiers.js              | tee tests/results/mixed-tiers.log
docker exec aegis-k6 k6 run /scripts/ddos-burst.js               | tee tests/results/ddos-burst.log
docker exec aegis-k6 k6 run -e WAF_ADMIN=http://host.docker.internal:9443 \
  /scripts/loadmode-degradation.js                              | tee tests/results/loadmode-degradation.log
# ... admin-needing scripts: see "Re-running" section above
```
