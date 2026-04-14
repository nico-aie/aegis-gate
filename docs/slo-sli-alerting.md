# SLO / SLI / Alerting (v2, enterprise)

> **Enterprise addendum.** Defines SLIs, SLOs, burn-rate alerts,
> and paging routes for the WAF itself. Drives the dashboard Alerts
> view and the Prometheus alertmanager wiring.

## Purpose

Tell operators when the WAF is broken, before customers do, with
enough signal to distinguish "backend is slow" from "WAF is slow"
and enough discipline to avoid alert fatigue.

## SLIs

| SLI | Definition | Source |
|---|---|---|
| `availability` | `requests_not_5xx / requests_total` | `waf_requests_total` |
| `latency_p99` | p99 of `waf_request_duration_seconds` (data-plane overhead only) | histogram |
| `upstream_availability` | `upstream_2xx / upstream_total` | `waf_upstream_requests_total` |
| `admin_api_availability` | 2xx/total on control plane | `waf_admin_requests_total` |
| `audit_delivery` | `1 - drops / emitted` | `waf_audit_events_total`, `waf_audit_drops_total` |
| `config_freshness` | seconds since last successful reload | `waf_config_reloads_total` |
| `cert_freshness` | min remaining validity across certs | gauge |

Latency SLIs measure **WAF overhead** (pipeline time), not end-to-end,
so a slow backend doesn't poison the WAF SLO.

## SLOs

| Service | SLI | Target | Window |
|---|---|---|---|
| Data plane | availability | 99.99% | 30 days |
| Data plane | latency_p99 overhead ≤ 5 ms | 99% of 1-min windows | 30 days |
| Control plane | admin availability | 99.9% | 30 days |
| Audit | delivery | 99.999% | 30 days |
| Certs | freshness ≥ 7 days remaining | 100% | continuous |

## Burn-rate alerts

Multi-window, multi-burn-rate alerts (Google SRE pattern):

- **Fast burn**: 2% of 30-day budget in 1 hour → page
- **Slow burn**: 5% of 30-day budget in 6 hours → page
- **Trickle burn**: 10% of 30-day budget in 3 days → ticket

Each alert carries a runbook link, suspected subsystem, and the
dashboard deep-link filtered to the relevant tenant/route.

## Sample PromQL

```promql
# 1h fast burn
(
  sum(rate(waf_requests_total{status=~"5.."}[1h]))
  / sum(rate(waf_requests_total[1h]))
) > (14.4 * (1 - 0.9999))
```

## Dashboards

The Alerts view shows:

- Error budget remaining (per SLO)
- Burn-rate gauges (1h / 6h / 3d)
- Active incidents with actor + runbook
- Recent config reloads + their outcome
- Circuit-breaker state per pool
- Audit sink lag + drops
- Cert expiry timeline

See [`dashboard.md`](./dashboard.md).

## Alert routing

```yaml
alerting:
  routes:
    - match: { severity: page }
      receiver: pagerduty_primary
    - match: { severity: ticket }
      receiver: jira_ops
    - match: { severity: info }
      receiver: slack_ops
  receivers:
    pagerduty_primary:
      type: pagerduty
      routing_key: "${secret:env:PD_KEY}"
    jira_ops:
      type: jira
      project: OPS
      endpoint: "https://jira.example.com"
      auth: { type: bearer, token: "${secret:env:JIRA_TOKEN}" }
    slack_ops:
      type: slack
      webhook: "${secret:env:SLACK_WEBHOOK}"
```

## Runbooks

Each alert references a runbook under `docs/runbooks/<name>.md` with:

- Symptom
- Immediate mitigations (drain, config rollback, rate-limit tighten)
- Root-cause probes (which metric, which log)
- Escalation path

## Configuration

```yaml
slo:
  availability_target: 0.9999
  latency_p99_overhead_ms: 5
  audit_delivery_target: 0.99999
  cert_min_days: 7
  burn_rate:
    fast: { window: 1h,  budget_pct: 2 }
    slow: { window: 6h,  budget_pct: 5 }
    trickle: { window: 72h, budget_pct: 10 }
```

## Implementation

- `src/slo/sli.rs` — SLI derivation from metrics
- `src/slo/burn_rate.rs` — multi-window burn-rate calculator
- `src/alerting/router.rs` — match + receiver dispatch
- `src/alerting/receivers/{pagerduty,jira,slack,webhook}.rs`

## Performance notes

- SLI calculation runs on a scheduled Prometheus recording rule, not
  on the request path
- Burn-rate queries are cheap aggregations on recording rules
- Receivers are async with bounded retries; failure to page is itself
  an alert
