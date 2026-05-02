# CQA — Live verification (closes the gaps the source-only sweep left open)

Run by hitting the live WAF (`http://127.0.0.1:9443`) booted on
`config/dev.yaml` while the e2e-runner agent did its
source-grep sweep in parallel.

## Read-endpoint sweep — all green

41 dashboard read endpoints + health/metrics. **41 / 41
return HTTP 200**, content-type `application/json` (or
`text/plain` for `/metrics`), JSON-parseable where applicable.
Full table in `read-endpoints.md`. No backend gap.

Endpoints exercised:

```
/api/about          /api/stats            /api/runtime
/api/cluster        /api/slo              /api/certs
/api/alerts         /api/gitops/status    /api/state
/api/mode           /api/risk/thresholds  /api/risk
/api/rules          /api/blacklist        /api/whitelist
/api/routes         /api/tiers            /api/upstreams
/api/upstreams/config                     /api/alert-receivers
/api/mtls/sans      /api/mtls             /api/mtls/connections
/api/mtls/failures  /api/mtls/ca-summary  /api/detectors
/api/loadmode       /api/logging          /api/cold-tier
/api/config/version /api/config/versions  /api/stats/timeseries
/api/attacks/distribution                 /api/attacks/top
/api/attacks/by-detector                  /api/bots/mix
/api/threat-intel/hits                    /api/audit/since
/healthz/ready      /healthz/live         /metrics
```

## §2.5 — CSRF gate enforcement

| Test | Result |
|---|---|
| `PUT /api/mode {"mode":"log_only"}` **without** `x-csrf-token` | **403** — `{"reason":"csrf_missing_header"}` ✅ |
| Same `PUT /api/mode` **with** valid CSRF | **200** — `{"ok":true,"mode":"log_only"}` ✅ |

## §2.6 — `/api/config/version` increments after mutation

| Snapshot | Value |
|---|---|
| Before `PUT /api/mode log_only` | `0` |
| After (1 s sleep) | `1` |
| Delta | **+1 ✅** |

## §2.4 — Audit chain captures the mutation

`GET /api/config/versions?limit=5` (after a round-trip toggle):

```json
[
  { "seq": 3, "action": "mode_set", "actor": "admin" },
  { "seq": 2, "action": "mode_set", "actor": "admin" }
]
```

Both mutations land in the chain with `actor=admin`. ✅

## Coverage summary

The source-only audit (run by the e2e-runner agent) flagged
the following acceptance criteria as unverifiable. This live
sweep closes them:

| Criterion | Source-only verdict | Live verdict |
|---|---|---|
| §2.1 read APIs return 200 | unverified | ✅ 41/41 |
| §2.4 audit chain entries visible within 2 s | unverified | ✅ visible immediately |
| §2.5 CSRF gate | unverified | ✅ 403 without, 200 with |
| §2.6 /api/config/version increments | unverified | ✅ +1 per mutation |
| §2.8 no unintentional 4xx/5xx | unverified | ✅ no rogue 4xx/5xx in the read sweep |

## What this **doesn't** verify

- §2.2 honest empty states (UI render — needs a browser)
- §2.3 every button produces visible feedback (UI render —
  but the source audit already shows several buttons have
  `onClick` missing entirely; those won't surface feedback
  even if the API exists)
- §2.7 no browser console errors (UI render — needs a
  browser)

These gaps are not blockers for the sprint plan — the
source audit identified the missing onClick handlers and
hardcoded JSX values directly, which is what the next
sprint fixes.
