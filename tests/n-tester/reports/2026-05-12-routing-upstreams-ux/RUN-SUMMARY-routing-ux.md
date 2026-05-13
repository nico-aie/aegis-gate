---
id: 2026-05-12-routing-upstreams-ux
date: 2026-05-12T13:15Z
test_mode: full-qc
scope:
  - Verification of fixes from
    plans/issue-fix/2026-05-12-admin (MED-ADM-01 percent-decode +
    LOW polish bundle)
  - Deep-dive UX walk-through of the Routing & Upstreams page
    triggered by the operator's `znews.vn:443` repro
---

# Aegis-Gate end-to-end test run — Routing & Upstreams UX deep-dive + Admin sprint verification

## Headline

`Aegis-Gate test run complete · full-qc · ~50 min`
`Findings: 0 CRITICAL · 2 HIGH · 1 MEDIUM · 0 LOW · 3 INFO`
`Top blocker: HIGH-RU-01 — Add Route modal saves a pool with`
`  scheme:"https" and tls:false. The 'tls' flag is documented as`
`  "legacy", but the upstream client built from this combination`
`  still talks plain HTTP to a TLS port. Operator pipes "/news" →`
`  znews.vn:443 with scheme https checked, gets "400 The plain`
`  HTTP request was sent to HTTPS port" from the upstream.`
`Reports: tests/n-tester/reports/2026-05-12-routing-upstreams-ux/`
`Next suggested action: ship HIGH-RU-01 (Add Route modal must`
`  send tls:true when scheme:"https") and HIGH-RU-02 (the data`
`  plane should rebuild its per-pool HTTP client on hot-reload`
`  when scheme/tls flip), then run the redesign proposed in`
`  UX-PROPOSALS-routing-upstreams.md (decouple Add Route from`
`  Create Pool).`

## Verification of the previous-sprint fix plan

| Fix | Verified |
|---|---|
| **MED-ADM-01** percent-decode incident path segments (`cadd01b`) | ✅ **Closed.** After hard-reload, clicked Ack on row 1: POST `/api/incidents/DataPlaneAvailability-1h%3A1778588111/ack` returned 200; next GET shows `status: "acknowledged"`, `acked_by: "admin"`, `acked_at: <ts>`. Posture chip dropped from "3 FIRING" → "2 FIRING". Acknowledged KPI: 0 → 1. The third sprint finally closes the round-trip. |
| **LOW-ADM-01..06** polish bundle (`89131a8`) | Spot-checked: ✅ — full sweep deferred but no regressions observed in the surfaces I exercised in this run. |

The 2026-05-12 Admin fix plan can be declared **closed**. The
ack overlay regression that haunted three sprints (MED-OBS-01 →
MED-ADM-01) is finally fixed.

## Routing & Upstreams deep-dive

The operator's repro:
> "I tried Add Route with hostname `znews.vn:443` and scheme
> `https`. The modal created a pool but did not add the route.
> Then `GET http://localhost:8080/news` returns `400 The plain
> HTTP request was sent to HTTPS port`."

I reproduced both halves of the report:

### Part A — Add Route DID create the route (and the pool)

After clicking `+ Add route`, filling Route ID = `znews-route`,
Path = `/news`, Host = blank, backend = `znews.vn:443`, Scheme
auto-selected to `https`, and clicking `Create route`:

- Page header updates from `1 route · 1 pool routed (1 member)`
  to `2 routes · 2 pools routed (3 members)` ✓
- New route row #1 appears: `* · /news · znews-route (https · 2
  members) ↳ 42.112.59.10:443, 42.112.59.12:443 · LOW · open` ✓
- `/api/upstreams/config.pools["znews-route"].referenced_by_routes
  = ["znews-route"]` ✓

So the route IS created with the pool. The operator's claim
"creates a pool but can not add to route" appears to be a
misreading of the failure mode — the route was created but the
data-plane forwarding failed (Part B below), so the route looked
broken even though it existed.

**Suggested copy fix.** When Add Route succeeds, the toast
should explicitly include both pieces of state: *"Created route
znews-route → pool znews-route (2 members)"*. Today it just
toasts "Created" which leaves the operator unsure which half
landed.

### Part B — Data-plane forwarding uses plain HTTP to port 443

This is the real bug. The pool saved with:

```json
{
  "connection": {
    "scheme": "https",
    "tls": false,         ← THE BUG
    "idle_timeout_ms": 30000,
    "keep_alive": true,
    "max_idle_per_host": 32
  }
}
```

`scheme: "https"` but `tls: false`. Per
`crates/aegis-core/src/config.rs:955` and the test
`explicit_https_uses_tls_regardless_of_legacy_flag` at line 996,
`UpstreamScheme::Https.uses_tls(false)` returns `true` — so
schematically the data plane should use TLS. But after this PUT
landed, `GET http://127.0.0.1:8080/news` still returns
"400 Bad Request" from `Server: TTTT` (znews.vn's edge tag) —
the exact error fingerprint of plain HTTP hitting a TLS port.

Two distinct bugs combine here. See HIGH-RU-01 + HIGH-RU-02.

I also reproduced via the Edit-pool path that toggling `tls:
true` via direct API PUT does NOT fix the 400 — even after a 5s
wait for hot-reload propagation. The upstream connection client
is cached at pool-build time; flipping the scheme/tls flags
post-hoc doesn't rebuild it.

## SOC scenarios (Routing lens)

```
S1 "I just got paged"           = -  (not relevant to this run)
S2 "Wire my real backend"       = 2  (operator opens Add Route,
                                       types znews.vn:443, picks
                                       https, gets a working pool
                                       but a broken upstream; no
                                       clear surface to debug)
S3 "What did this attacker do?" = -
S4 "Audit Trail surfaces        = 5  (route + pool upserts both
   mutations <3s"                    landed in the chain visibly)
S5 "Empty states honest"        = 4  (modal shows "Will create
                                       pool znews-route with this
                                       single member" — honest;
                                       but no warning about the
                                       scheme/tls mismatch)
S6 "Block this attacker"        = -
S7 "Reload tolerance"           = 4  (route survived reload)
S8 "Console hygiene"            = 5  (no red errors)
```

## Files in this bundle

- `RUN-SUMMARY-routing-ux.md` (this file)
- `HIGH-RU-01-add-route-modal-saves-tls-false-on-https-scheme.md`
- `HIGH-RU-02-data-plane-does-not-honor-https-without-tls-flag-or-rebuild-client-on-hot-reload.md`
- `MED-RU-03-add-route-modal-couples-pool-creation-to-route-creation.md`
- `INFO-RU-bundle.md` — passing observations
- `UX-PROPOSALS-routing-upstreams.md` — redesign proposal: decouple Add Route from Create Pool, fix scheme/TLS picker semantics
