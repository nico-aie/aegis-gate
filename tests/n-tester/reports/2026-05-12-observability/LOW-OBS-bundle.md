---
id: 2026-05-12-observability-low-findings-bundle
date: 2026-05-12T07:28Z
severity: LOW
area: dashboard
component: various
status: open
test_mode: full-qc
---

# LOW-severity findings (Observability polish)

## LOW-OBS-01 — Performance "Latency p50/p95/p99 by route" empty state contradicts the "Error rate by route" data right above it

On the Performance page, **Error rate by route** (right column,
above the Latency-by-route card) lists 7 routes with per-route
TOTAL / BLOCKED / 5XX / ERROR % filled in. Below it, **Latency
p50/p95/p99 by route** card says:

```
no per-route samples yet
Drive traffic with `make mock-load`; per-route series populate as routes resolve.
```

Both cards read from the same audit ring. If "Error rate by
route" can surface counts for `/`, `/files`, `/fetch`,
`/wp-admin`, `/api`, `/.env`, `/login`, the latency card should
have the same coverage. Operators read the contradictory pair
and either think the page is broken or that "samples" mean
something different than "blocked requests" (it doesn't —
latency is collected on every request including blocks).

**Fix.** Either:
- Point the Latency-by-route card at the same source as the
  Error-rate-by-route card. ~5 LoC if it's a Map keyed by
  route_id with `Vec<latency_sample>`.
- Or update the empty-state copy to clarify: *"Per-route
  latency requires resolved routes; blocked requests don't
  resolve and aren't sampled here."* — operator can then read
  the page coherently.

## LOW-OBS-02 — Health & SLOs route is `#/health` but sidebar label is "Health & SLOs"

Navigating to `#/health-slos` returns a "Page not found" card.
The actual route is `#/health`. Same pattern as the previous
sprint's LOW-SO-02 (Live Feed sidebar vs `#/live` route).

**Fix.** Add `#/health-slos` as an alias for `#/health` in the
router. ~3 LoC. While we're there, audit the rest of the
sidebar for "compact route name vs. sidebar long name" pairs:

| Sidebar | Route | Alias? |
|---|---|---|
| Health & SLOs | `#/health` | Add `#/health-slos` |
| (others appear consistent) |  |  |

## LOW-OBS-03 — Test alert button surfaces "Test failed: unknown error" instead of the actual error

On Health & SLOs, the alert channel row for `default-viptalk`
shows a red pill **"FAILED 3× · VIPTALK RETURNED 401
UNAUTHORIZE"** — that's the actual error the channel sees on
real delivery attempts. Click the row's **Test** button: a
red toast appears reading just **"Test failed: unknown error"**.

The test handler clearly hit the same 401 from VipTalk (since
the credentials are wrong); the error is known. Surfacing it as
"unknown error" is misleading.

**Fix.** In the test-alert handler, the upstream error result
already carries the HTTP status + body. Pass it through to the
toast message so the operator sees the same "VIPTALK RETURNED
401 UNAUTHORIZE" they see in the channel row. ~5 LoC server or
~5 LoC dashboard (whichever swallows the error today).

## LOW-OBS-04 — Audit Trail RULE column renders `—` on detection rows

On the Audit Trail page with class filter set to `all`, every
DETECTION row has CLIENT IP populated and REASON populated with
the detector breakdown (`blocked by detectors: recon_path (score:
100)`) — but the RULE column shows `—` even when the same data
exists in `fields.detectors[]`.

This mirrors the previous sprint's MED-SO-06 fix for the
Investigation Audit timeline. The Audit Trail page is a separate
code path and needs the same `extractResourceId(event)` /
`event.fields.detectors?.join(',')` fallback applied to its
RULE column renderer.

**Fix.** ~5 LoC in the Audit Trail row renderer — apply the same
fallback pattern that lit up Investigation's RULE_ID column.

## LOW-OBS-05 — Performance time-window subtitle update is good — minor: the chart's "Block ratio" peak time format mixes 12h + AM/PM

After clicking the 1h pill on the Performance page, the Block
ratio card subtitle updated to `"avg 96.6% · peak 100.0% at
11:17 AM"`. The 12-hour format is fine for laptops but
operators in 24-hour shops parse "11:17" twice (is that AM or
PM?). Mixed-format times can also be ambiguous on log timelines.

**Fix.** Standardize on either 24-hour HH:MM (consistent with
the rest of the dashboard) or always show AM/PM. ~5 LoC.

