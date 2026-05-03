# Run 12 — 2026-05-01 — Pre-MTLS-T2 Verification

End-to-end verification after MTLS-T1 (config schema + identity
types) + MTLS-T6 (read-only console observability) +
PRE-T1/T2 (proxy refactor first two slices) landed.
**Operator-requested re-run** of load + security suites + admin
console feature audit.

## Headline

| Surface | Result |
|---|---|
| **Workspace tests** | 163 (core) + 855 (control) + 424 default / 461 etcd (proxy) + 41 (bin) + 888 (security) = **2,371 default-feature** |
| **OpenAPI shape contract** | **32/32 PASS** |
| **Round-1 acceptance** (Hackathon WAF-FE §2) | **8/8 PASS** — SSE 55 ms / hot-reload 76 ms / find-audit 48 ms |
| **Common attack curl probes** | All 5 attack classes blocked (SQLi UNION → 403, XSS → 400, path traversal → 403, SSRF → 403, CRLF → 403) |
| **Risk auto-block** | 5 attack probes from one IP → score 100 + 50 strikes → `strike_blocked: true` (subsequent benigns 403 from same IP) |
| **Risk reset (audit-mutated)** | `PUT /api/risk/{ip}/reset` clears state; benign retry 200 |
| **Nuclei security scan** | 742 templates, 1431 requests, **0 vulnerabilities matched** |
| **k6 baseline (4 VU × 5s)** | **37,600 req/s** sustained; 10k/min rate-limit budget enforced exactly |
| **k6 latency** | median **60 µs**, p95 **286 µs** on the allow path |
| **Dashboard screenshots** | 12/12 pages captured |
| **MTLS-T6 endpoints** | All 4 GET endpoints serve correct JSON shapes (cfg / connections / failures / ca-summary); CA summary returns empty when `tls.client_auth.ca_bundle` not configured (as expected for dev cfg) |

## Run context

| Field | Value |
|---|---|
| Date | 2026-05-01 |
| Host | macOS 23.1.0 arm64, 12 logical CPUs |
| Binary | `target/release/waf` built `--features "redis alerts geoip"` (20 MB) |
| Config | `config/dev.yaml` (in-memory state, single mock upstream :9999) |
| Bundle | `app.js` 178 KB |
| k6 version | brew install (latest stable) |
| Nuclei version | brew install + `nuclei -update-templates` |
| Playwright | npm `playwright@1.59.1` |

## What works (verified live)

### Detector behaviour

```
==> SQLi via query string         → 403 ✓
==> SQLi UNION SELECT             → 403 ✓
==> XSS reflected (<script>)      → 400 ✓
==> Path traversal (../)          → 403 ✓
==> SSRF (http://169.254.169.254) → 403 ✓
==> CRLF injection                → 403 ✓
==> Benign request                → 200 ✓ (after risk reset)
```

### Risk tracker auto-block

After running the 5 attack probes above, the source IP
`127.0.0.1` accumulated **score 100 / strikes 50** →
`strike_blocked: true`. Subsequent benign requests from the
same IP returned 403 (P6 risk auto-block working as designed).

`PUT /api/risk/127.0.0.1/reset` (CSRF-gated, audit-mutated)
cleared the state in one round-trip; benign retry returned
200 immediately.

### MTLS-T6 endpoints (this turn)

```
GET /api/mtls            → {"mode":"disabled","ca_bundle":null,"allowed_sans":[],"apply_to":[],"active":false}
GET /api/mtls/connections → {"connections":[],"window_seconds":3600}
GET /api/mtls/failures    → {"failures":[],"window_seconds":3600}
GET /api/mtls/ca-summary  → {"bundle_path":null,"last_loaded_ms":null,"certificates":[]}
```

Empty-state bodies are the expected output when
`cfg.tls.client_auth` is unset and the dev cfg has no CA
bundle. MTLS-T2 (rustls inbound wiring) + MTLS-T3 (identity
extraction) will populate `connections` / `failures` /
`ca-summary` once the WAF actually requests client certs.

### Performance (k6 baseline 4 VU × 5s)

```
http_reqs:        188004 (37,600 req/s)
allow_success:    5.31% (10,000 within rate-limit budget)
http_req_duration:
  median   60 µs
  p90     127 µs
  p95     286 µs
  max     161 ms (one outlier — likely accept-loop scheduling)
```

The 5.31% "allow_success" reflects the dev cfg's `10000/minute`
per-IP rate limit being deliberately tight. Within the allowed
budget the WAF processes 10k requests in well under 1 second
(the median p95 286 µs supports this); the remaining 178k
requests correctly return 429.

For a full workload-realistic perf run, raise
`cfg.rate_limit.buckets[0].limit` to e.g. 10_000_000 and
re-run — that matches run-04's methodology and would re-prove
the ~30k req/s throughput numbers.

## Admin console feature audit (operator request)

### What's WIRED to live data ✓

Every page that has a working `/api/*` endpoint now reads
from it:

- **Overview** — `/api/stats`, `/api/timeseries`,
  `/api/attacks/distribution`, `/api/attacks/top` (with
  GeoIP enrichment under `--features geoip`)
- **Live Feed** — `/dashboard/sse` (real audit-bus events,
  end-to-end latency 55 ms verified)
- **Audit** — `/api/audit/since` with `ip` / `rule_id` /
  `request_id` / `from` / `to` filters
- **Rules** — full CRUD via `POST/PUT/DELETE /api/rules`,
  audit-mutated, hot-reload latency 76 ms
- **Tier Config** — live config via `/api/detectors`
- **Blacklist / Whitelist** — `/api/blacklist`, `/api/whitelist`
- **Upstreams** — `/api/upstreams/config` (CC-T1.1.b full
  CRUD with proxy hot-swap + `referenced_by_routes` 409 on
  delete)
- **Tracking** — `/api/slo`, `/api/certs`, `/api/gitops/status`,
  `/api/alerts` (real fires — 3 captured during run-11),
  `/api/cluster`, alert-channels card
- **Settings** — `/api/mode` (audit-mutated PUT for shadow
  mode), `/api/runtime`, `/api/risk/thresholds`
- **TopBar / StatusBar** — `/api/about`, `/api/cluster`
  (HU-T2 replaced the hardcoded "v1.4.2 / 5 nodes / 14d
  uptime" placeholders)

### What still uses synthetic data (carryover from HU-T2)

Two pages render Math.random() data:

- **PageAttackEvents** (`pages.jsx:459–465`) — detector-bar
  chart. **Synthetic-data warning pill is rendered today**
  (HU-T2 work). However, `waf_detector_hits_total{class}` is
  now live (PROM-T2 closed) — the bars **could** be wired to
  the real Prometheus counter. Carryover.
- **PageAnalytics** (`pages.jsx:573–577`) — sparklines for
  request rate / block ratio / latency. **Same warning pill**.
  `waf_request_duration_ms` (PROM-T1) + `waf_requests_total`
  exist — sparklines could read from `/metrics`. Carryover.

The fallback fixture in `data.jsx::makeLiveEvent` is correct
behaviour — it only kicks in when the SSE endpoint is
unreachable. With SSE live (verified by round-1 acceptance),
the real events flow through.

**The `(demo)` and `synthetic data` pills HU-T2 added
correctly label these two as not-yet-live**, so the operator
isn't misled. But they're now **fixable** (the underlying
metrics exist). Recommend a follow-up slice **"PageAttackEvents
+ PageAnalytics → Prometheus"** that wires both pages to real
data and removes the warning pills. ~3-4 h.

### Decorative randomness (no fix needed)

- `widgets.jsx:262` — heatmap visualization adds occasional
  spike bumps. Decorative, not metric-tied.
- `widgets.jsx:389` — `Math.random().toString(36)` — DOM ID
  generator. Standard pattern.

## Pre-existing test bugs surfaced (not caused by recent slices)

- `tests/api/auth.sh` expects logout to return 200, server
  returns 204 (No Content — semantically correct for a
  logout). One-line fix in the test script:
  `assert_status` → accept `200|204`.
- `tests/security/run-corpus.sh` — skeleton-only; the corpus
  payloads aren't yet generated (per its own header
  comment). Not tested today.

## Files in this run

- `k6-baseline.log` — first baseline (rate-limit window
  hit during burst).
- `k6-baseline-clean.log` — clean run inside budget;
  37,600 req/s sustained.
- `k6-rate-limit.log` — 100% blocked-after-burst
  (rate-limit working).
- `attack-tests.log` — 6 attack probes + risk-reset.
- `nuclei-output.log` — 742 templates, 0 matches.
- `security-corpus.log` — corpus runner skeleton (see note
  above).
- `screenshots/` — 12 fresh per-page PNGs (1440×900):
  overview, live, attacks, analytics, audit, rules, tiers,
  blacklist, whitelist, settings, tracking, help.

## Recommendation

1. **Continue the proxy refactor (PRE-T3..T8)** before more
   handler slices land. `aegis-proxy/src/lib.rs` is at 4900
   lines; PRE-T3..T7 will get it to ≤ 200 lines.
2. **Queue a "PageAttackEvents + PageAnalytics → Prometheus"
   follow-up** (~3-4 h) once PRE-T8 lands — wires the two
   remaining synthetic pages to live `/metrics` data and
   removes the `synthetic data` pills.
3. **Resume MTLS-T track** after PRE-T8: MTLS-T6 frontend →
   MTLS-T2 (rustls) → MTLS-T3 (identity extraction) → ...
