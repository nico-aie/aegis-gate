# Post-k6 Follow-up Plan

> **Status:** Closed — P1..P8 + F-T1..F-T10 shipped. Reference only.
>
> See [`README.md`](../README.md) for the track status board.

> **Source.** Findings from the 2026-04-28 k6 + tests/api smoke
> run captured under [`tests/results/`](../../tests/results). This
> plan converts each test failure / blocked test / harness
> rough-edge into a concrete task with an effort estimate and an
> ordered recommendation.

---

## Tiering

Tasks are grouped by criticality, not by chronology:

- **Tier 1 — Critical.** A single missing piece that blocks 8
  other tests from running at all. Must land first.
- **Tier 2 — Real gaps.** Bugs the load tests revealed in the
  data plane itself.
- **Tier 3 — Test-harness polish.** The tests work but the
  ergonomics or laptop-vs-host capacity assumption needs
  fixing.
- **Tier 4 — Follow-on.** Nice-to-have observability + ACME
  integration.

Each task carries a stable ID (`F-T1` … `F-T10`) so future
progress entries can reference them.

---

## Tier 1 — Critical

### F-T1 — Wire `POST /admin/login` (and `/admin/logout`)

**Effort:** ~1 day &nbsp;·&nbsp; **Impact:** unblocks 3 k6 scripts + 5 API smoke scripts (8 tests)

#### Evidence

```
$ curl -i -X POST http://127.0.0.1:9443/admin/login \
    -H "content-type: application/json" \
    -d '{"user":"admin","password":"aegis-test-1234"}'
HTTP/1.1 404 Not Found
{"error":"not found","path":"/admin/login"}
```

`tests/results/risk-strikes.log` line 4:

```
Error: admin login: 404
  at loginAdmin (file:///scripts/risk-strikes.js:54:31(43))
```

#### Why it's critical

Every P2–P8 feature flows through `AuditedMutate`, which
validates `aegis_csrf` cookie + `X-CSRF-Token` header. With no
HTTP login route, **no operator-facing feature added by P1–P8
can be exercised end-to-end** — not from the dashboard SPA, not
from k6, not from curl, not from the Settings UI.

#### What's already in place (and what isn't)

| Piece | Status |
|---|---|
| Argon2id verify (`admin_auth::password::verify`) | done + unit tested |
| Session issuer (`admin_auth::session::SessionStore`) | done + unit tested |
| CSRF token generator (`admin_auth::csrf::generate_token`) | done + unit tested |
| Login rate limiter (`admin_auth::rate_limit`) | done + unit tested |
| Lockout policy (`admin_auth::rate_limit::Lockout`) | done + unit tested |
| **HTTP route handler `POST /admin/login`** | **missing** |
| **HTTP route handler `POST /admin/logout`** | **missing** |

#### Implementation outline

1. Add `handle_admin_login(req, cfg, services).await` in
   `aegis-proxy/src/lib.rs` next to `handle_logging_put`,
   `handle_loadmode_put`, etc.
2. Branch into the new handlers from `handle_admin_request`:
   ```rust
   if method == hyper::Method::POST && path == "/admin/login" {
       return handle_admin_login(req, cfg, services).await;
   }
   if method == hyper::Method::POST && path == "/admin/logout" {
       return handle_admin_logout(req, services).await;
   }
   ```
3. The login handler:
   - Reads JSON body `{user, password}`.
   - Honours `cfg.admin.dashboard_auth.login_rate_limit` and
     `lockout` (already configured in `config/dev.yaml`).
   - Validates against
     `cfg.admin.dashboard_auth.password_hash_ref` via
     `password::verify`.
   - On success: issues an `aegis_session` cookie (HttpOnly,
     Secure, SameSite=Strict, Max-Age = `session_ttl_idle`)
     and an `aegis_csrf` cookie (NOT HttpOnly so the JS reads
     it, Secure, SameSite=Strict).
   - Returns `200 {"ok": true, "expires_at": "..."}`.
   - On failure: returns 401 with the documented error envelope
     and a single `tracing::warn!` for SOC visibility.
4. The logout handler revokes the session via `SessionStore`
   and returns 204.
5. The IP allowlist check (already implemented in
   `admin_auth::session`) wraps every admin-listener request,
   so login is rejected from anything outside
   `cfg.admin.dashboard_auth.ip_allowlist`.

#### Tests

- aegis-proxy: integration test that POSTs valid creds, asserts
  200 + both cookies + cookie attributes.
- aegis-proxy: rate-limit + lockout regression test.
- After this lands, `tests/api/run-all.sh` and the 3 blocked k6
  scripts must pass on a re-run.

---

## Tier 2 — Real gaps

### F-T2 — Wire per-IP rate limiting into the data-plane hot path

**Effort:** ~2-3 days &nbsp;·&nbsp; **Triggered by:** `ddos-burst.js`

#### Evidence

`tests/results/ddos-burst.log` summary:

```
✓ autoblock_latency_ms: avg=0s ... p(95)=0s
http_req_failed: 7.42% ✓ 3710 ✗ 46290
```

The threshold passes vacuously — the latency counter records
only when a 403 is observed, and across 50 000 requests at
5 000 RPS from one source IP **no 403 ever came back**. The
7.42% failures are i/o timeouts (host overload), not
WAF-issued 403s.

#### Diagnosis

`aegis-security::rate_limit::buckets` is fully implemented and
unit tested, and `cfg.rate_limit.buckets` parses cleanly. But
`handle_data_request` (in `aegis-proxy/src/lib.rs`) **never
consults the rate limiter**. The hot path goes:

```
tick → strike-block check → tier classify → run_all_filtered
                                                ↓
                                        record_malicious or
                                        record_clean  →  level()
```

The bucket lookup is missing between `tier classify` and
`run_all_filtered`.

#### Implementation outline

1. Construct an `Arc<RateLimiter>` at boot from
   `cfg.rate_limit.buckets`.
2. Pass it through the same plumbing as `mask` and `risk` (one
   more parameter on `accept_loop` + `handle_data_request`).
3. Inside `handle_data_request`, after tier classification:
   ```rust
   if let Some(verdict) = limiter.consume(peer.ip(), tier).await {
       if !verdict.allowed {
           risk.record_malicious(peer.ip(), 30);
           return rate_limited_response(verdict.retry_after, …);
       }
   }
   ```
4. `record_malicious` here ensures repeat floods accumulate
   strikes — that's how a flooding IP eventually crosses
   `risk.strikes.block_at` and gets the permanent 403.
5. Update `ddos-burst.js` to record an `auto_block_count`
   counter so a missing block is a real test failure (not a
   silently-passing threshold):
   ```javascript
   thresholds: {
     "auto_block_count": ["count>0"],
     "autoblock_latency_ms": ["p(95)<2000"],
   }
   ```

#### Tests

- aegis-security: existing bucket tests already cover the
  algorithm; extend `tests/api/risk.sh` to run a small flood
  and assert the IP shows up in `/api/risk` afterwards.
- After this lands, re-run `ddos-burst.js`; expect 403s within
  ~2 s of crossing the bucket limit.

---

### F-T3 — Investigate 5.99% failure rate on `tier:critical` paths

**Effort:** ~half day &nbsp;·&nbsp; **Triggered by:** `mixed-tiers.js`

#### Evidence

`tests/results/mixed-tiers.log`:

```
http_req_failed{tier:critical} = 5.99%   (1 799 / 30 000)
http_req_failed{overall}       = 0.54%
```

CRITICAL paths (`/login`, `/payments`, `/checkout`) are 10×
more likely to error than the others.

#### Hypothesis

Two suspects:

- The `recon` detector matches `/login` heuristics aggressively
  and might be tripping on benign POST bodies during the burst.
- The `body_abuse` detector scans more bytes on POST payloads,
  contesting CPU under contention.

Both are testable by toggling each off via `PUT /api/detectors`
during a re-run (which depends on F-T1 landing first).

#### Investigation steps

1. Once F-T1 is in: re-run `mixed-tiers.js` with
   `recon: false` via the toggle; if the failure rate drops to
   match other tiers, that's the offender.
2. Else turn `body_abuse: false` and re-run.
3. If neither flip helps, capture a `tracing` log at
   `level=debug` for one critical-tier request and look for
   pipeline-stage timeouts in the per-stage spans.

---

## Tier 3 — Test-harness polish

### F-T4 — Make `loadmode-degradation.js` reach `Critical` on a laptop

**Effort:** ~half day

#### Evidence

`tests/results/loadmode-degradation.log`:

```
auto_critical_observed: 0 / 8 polls
dropped_iterations:    87 627
```

The host capped at ~7 k RPS but the script needs 8 k+ to push
the gauge into Critical.

#### Fix direction

Two complementary changes:

1. Ship a separate `config/dev.yaml` (sibling to
   `dev.yaml`) with lower thresholds:
   ```yaml
   load_mode:
     elevated_rps: 500
     critical_rps: 2000
   ```
   `dev.yaml` keeps realistic numbers so dev work isn't
   misled.
2. Have `loadmode-degradation.js` read its own thresholds from
   `/api/loadmode` at startup and target 1.5× whatever it sees,
   so the script stays correct regardless of which config is
   loaded.

---

### F-T5 — Make admin-needing k6 scripts fail fast on login error

**Effort:** ~2 hours

#### Evidence

The pre-trim `security-toggle-flips.log` was 179 MB / 691 026
lines — every iteration retried the login, every retry failed,
every failure logged a line.

#### Fix

Move login into k6's `setup()` so it runs once at startup; if
it fails, the whole run aborts with a clean error message
before any VU spins up.

```javascript
export function setup() {
  return loginAdmin();   // throws → run aborts with clear msg
}
export default function (data) {
  // use data.jar / data.csrf
}
```

Apply to `security-toggle-flips.js`, `risk-strikes.js`,
`verbosity-pin.js`.

---

### F-T6 — Document the latency-SLO host requirement

**Effort:** ~half day

#### Evidence

`tests/results/baseline.log`:

```
allow_latency_ms: avg=4.55ms p(95)=7.15ms p(99)=…
http_reqs:        642 272   42 811 RPS
```

Throughput is ~8.5× the 5 000 RPS target — hardware isn't the
limiter. p95 = 7.15 ms means p99 is well above the 5 ms SLO.
Almost certainly an artefact of running k6 + Docker + WAF
+ a browser + an IDE on one M-series laptop.

#### Fix

Add `tests/load/README-perf.md`:

- Document that the 5 ms p99 SLO requires a dedicated host (no
  Docker overhead, no other tenants).
- Document the laptop-acceptable target (e.g. p99 < 25 ms).
- Optionally add a `tests/load/baseline-host.js` variant that
  doesn't go through `host.docker.internal` so it can run from
  a CI runner directly against the binary.

This is documentation, not code — but it stops the SLO from
being treated as a hard gate during dev iteration.

---

## Tier 4 — Follow-on, nice-to-have

### F-T7 — Add Pebble (local ACME CA) container

**Effort:** ~1 day &nbsp;·&nbsp; **From:** P5 deferred items

`InstantAcmeProvider` is unit tested against a `MockProvider`,
but the real network adapter has no integration coverage.
Pebble is the standard local ACME CA. Add it to
`docker-compose.test.yml`, point `InstantAcmeProvider` at it
in a new `tests/api/acme.sh`.

### F-T8 — Wire `AcmeManager` + `InstantAcmeProvider` into `run()`

**Effort:** ~1 day &nbsp;·&nbsp; **From:** P5 deferred items

The renewal scheduler is built but not spawned from `run()`.
Plumb it alongside the existing `force_https_loop`. Requires
the cert writer to swap into the existing
`Arc<ArcSwap<CertStore>>`, which touches the listener TLS
path.

### F-T9 — k6 scripts for `/api/cold-tier` and `/api/audit/since`

**Effort:** ~2 hours

Coverage gap surfaced by the test pyramid review — these
endpoints have unit tests but no live-traffic exercise.

### F-T10 — Capture WAF-internal latency histograms

**Effort:** ~half day &nbsp;·&nbsp; **Follow-on to F-T6**

Add `waf_request_duration_ms` histogram split into
`{stage="accept", "detect", "rate_limit", "risk", "respond"}`
so `baseline.js` can attribute the 7.15 ms p95 to specific
pipeline stages instead of one opaque RTT.

---

## Recommended execution order

| # | Task | Why this position |
|---|---|---|
| 1 | **F-T1** | Single highest-leverage change. Unblocks 8 tests. |
| 2 | **F-T5** + **F-T4** in parallel | Test-harness fixes, ~one day combined. |
| 3 | *(re-run full k6 + API smoke suite)* | Captures fresh evidence with admin endpoints reachable. |
| 4 | **F-T2** | Concrete bug. Re-run from step 3 makes diagnosis easy. |
| 5 | **F-T3** | Depends on F-T1 (toggle endpoints) for diagnosis. |
| 6 | **F-T7** + **F-T8** together | Closes the P5 deferred items. |
| 7 | **F-T6, F-T9, F-T10** | Polish + observability. Schedulable any time. |

---

## Definition of done for the whole follow-up

- `tests/api/run-all.sh` exits 0 against a fresh dev gateway.
- All 7 k6 scripts under `tests/load/` exit 0 or document a
  hardware-bound failure under F-T6.
- `tests/results/README.md` is regenerated from the new run.
- A new `Implement-Progress.md` "Last Completed" entry
  references each closed F-T task.
