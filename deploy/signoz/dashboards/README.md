# SigNoz dashboards for Aegis-Gate

Importable [SigNoz](https://signoz.io) dashboards built from the WAF's
own OTLP traces (`service.name = aegis-gate`). Requires the WAF built
with `--features otel` and exporting to a SigNoz collector (see
[`../README.md`](../README.md)).

## `waf-overview.json` — WAF Overview

Schema `v4` (SigNoz v0.126+). 16 panels — the core set is **trace-based**
(no metrics/logs pipeline required), plus a **per-node** section, grounded
in the spans the WAF actually emits:

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

### Per-node section (multi-node clusters)

Traffic panels group by the `host.name` **resource** attribute the WAF
stamps on every span (`service.instance.id` is also available — see
`crates/aegis-bin/src/otel.rs`). System panels read the otel
**hostmetrics** receiver and join to traffic on the same `host.name`.

| Panel | Source |
|---|---|
| Request rate by node | traces, group by resource `host.name` |
| Blocked by node | traces, `action=block`, group by `host.name` |
| Traffic share by node (table) | traces, group by `host.name` |
| CPU load (1m) by node | metric `system.cpu.load_average.1m`, group by `host.name` |
| Memory used by node | metric `system.memory.usage` (`state=used`), group by `host.name` |

> **⚠ System panels need a per-node hostmetrics agent.** CPU/memory are
> empty until an otel collector with the `hostmetrics` receiver runs **on
> each node** (one agent per VM) — see
> [`../../otel/collector.yaml`](../../otel/collector.yaml). A single
> central collector reports only its own host. The trace-based traffic
> panels work as soon as nodes export with the per-node resource attrs.
> Single-node clusters render one series per panel.
>
> The metric queries (`system.cpu.load_average.1m` Gauge,
> `system.memory.usage` Sum) are best-effort for the hostmetrics naming;
> if a series doesn't resolve, confirm the metric name/type in SigNoz
> *Metrics Explorer* and adjust the panel (or `mdata(...)` in the
> generator) — the trace panels are unaffected.

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
