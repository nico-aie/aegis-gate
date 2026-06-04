# SigNoz dashboards for Aegis-Gate

Importable [SigNoz](https://signoz.io) dashboards built from the WAF's
own OTLP traces (`service.name = aegis-gate`). Requires the WAF built
with `--features otel` and exporting to a SigNoz collector (see
[`../README.md`](../README.md)).

## `waf-overview.json` — WAF Overview

Schema `v4` (SigNoz v0.126+). Ten panels, all **trace-based** (no
metrics/logs pipeline required), grounded in the spans the WAF actually
emits:

| Panel | Span / attribute |
|---|---|
| Total requests / Blocked / Challenged (stat) | `waf.handle_data_request`, `action` |
| Request rate by action (time series) | `action` (allow/block/challenge/circuit_breaker/risk_reset) |
| Request latency (end-to-end · incl. upstream) p50/p95/p99 | `waf.handle_data_request` span duration |
| WAF decision latency (excl. upstream) p50/p95/p99 | `waf.handle_data_request` span duration, filtered `action != allow` |
| Requests by tier | `tier` |
| Top targeted paths (table) | `path` |
| Top clients / peer (table) | `peer` |
| Upstream forward outcome | `waf.forward_upstream`, `outcome` |
| Upstream forward latency p95 | `waf.forward_upstream` span duration, `upstream` |

> **⚠ Latency semantics.** `waf.handle_data_request` span duration is
> **end-to-end** — it wraps the upstream forward (`waf.forward_upstream`),
> so for *allowed* requests it's dominated by upstream RTT, **not** the
> WAF's decision cost. The **"WAF decision latency (excl. upstream)"**
> panel filters to `action != allow` (block/challenge/circuit_breaker —
> requests that never forward), giving the true sub-millisecond WAF
> overhead (matches the `waf_overhead` Prometheus stage). The full
> per-stage WAF overhead lives in the `waf_request_duration_ms`
> histogram; surface it here once the metrics pipeline (Collector
> `prometheus` receiver → SigNoz) is live.

> The detector / `rule_id` breakdown is **not** in traces (it lives in
> the audit ring + the copilot snapshot) — same metrics-pipeline follow-up.

> **Regenerate:** the JSON is built by
> [`gen-waf-dashboard.py`](./gen-waf-dashboard.py) —
> `python3 gen-waf-dashboard.py > waf-overview.json`. Edit panels there
> (or freely in the SigNoz UI after import).

### Import — UI (recommended)

1. SigNoz → **Dashboards** → **+ New Dashboard** → **Import JSON**.
2. Upload `deploy/signoz/dashboards/waf-overview.json` (or paste its
   contents) → **Import and next**.
3. Drive some traffic; panels fill on the next refresh. Widen the time
   range (top-right) to cover when the WAF was running.

### Import — API (one-liner)

Run this yourself so your SigNoz credentials stay local (adjust host/port
— the UI is `:8090` in the dev compose remap):

```bash
EMAIL='you@example.com'; PASS='your-signoz-password'
JWT=$(curl -s -X POST http://localhost:8090/api/v1/login \
  -H content-type:application/json \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["accessJwt"])')

curl -s -X POST http://localhost:8090/api/v1/dashboards \
  -H "Authorization: Bearer $JWT" -H content-type:application/json \
  --data @deploy/signoz/dashboards/waf-overview.json | python3 -m json.tool
```

### Notes

- Latency panels use `durationNano` (y-axis unit `ns`).
- If a panel shows "no data", confirm the time range covers a WAF run
  and that spans exist: SigNoz → **Traces** → filter `service.name =
  aegis-gate`. The panels are plain query-builder queries, so any
  attribute/grouping can be tweaked in-place after import.
