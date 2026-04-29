# SLO / SLI / Alerting (v2, enterprise)

> **Status:** Implemented — `slo.rs` — 5 SLI kinds, multi-burn windows, 6 receiver kinds (PagerDuty / Slack / Alertmanager-Webhook / ServiceNow / Jira / **VipTalk**). VipTalk is the project's default chat receiver and is the only kind with in-process HTTP delivery (`slo::dispatch::send_alert`, behind `aegis-control/alerts`); the other five are descriptive metadata that an operator-side dispatcher (typically Alertmanager) reads and routes off-box.
>
> See [`../../plans/plan.md`](../../plans/plan.md#1-doc-by-doc-implementation-status) for the full matrix.

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

See [`dashboard.md`](../control-plane/dashboard.md).

## Alert routing

Six receiver kinds. **VipTalk is the project's default** — a
fresh deployment that calls
[`aegis_control::slo::default_receivers()`](../../crates/aegis-control/src/slo.rs)
gets one VipTalk receiver pre-wired against the dev/UAT bot.
For every other receiver kind the SLO engine emits the
metadata; an operator-side dispatcher (Alertmanager, a
sidecar, a CronJob — whatever the deployment standardised on)
reads it and delivers off-box.

| Receiver | Delivery |
|---|---|
| **VipTalk** | In-process HTTP POST via `slo::dispatch::send_alert` (behind the `aegis-control/alerts` Cargo feature). |
| PagerDuty / Slack / Alertmanager-Webhook / ServiceNow / Jira | Operator-side. The SLO engine emits the receiver definition; a sidecar dispatcher delivers. |

### VipTalk default receiver

The chat receiver wraps the VipTalk Bot API:

```text
POST https://api.viptalk.org/v1/bot/<bot-token>/sendMessage
Content-Type: application/x-www-form-urlencoded

text=<formatted-alert>&roomIds=<room>[&roomIds=<room>...]
```

Operators override the default bot + room via two env vars at
boot:

| Env | Purpose | Default |
|---|---|---|
| `AEGIS_VIPTALK_BOT_TOKEN` | Bot identity slug from the `/v1/bot/<token>/...` URL | `QGJvdF8yYXB0b2h4Ymdq_…` (project dev/UAT bot — replace in prod) |
| `AEGIS_VIPTALK_ROOM_IDS` | Comma-separated Matrix-style room IDs the bot posts to | `!QNxJHzVzJBrLWIOLPo:matrix-uat.viptalk.org` |
| `AEGIS_VIPTALK_API_BASE` | API root (override for sovereign / private VipTalk deployments) | `https://api.viptalk.org` |

To **disable** VipTalk routing entirely, build your own
`Vec<AlertReceiver>` in your config builder instead of calling
`default_receivers()`.

### Message format

Each alert renders as a multi-line chat message. The exact
shape comes from `slo::dispatch::format_alert_text`; tests
assert on it so the format is stable:

```text
[Page] SLO breach: DataPlaneAvailability
Burn rate: 14.00× over 1h window
Budget consumed: 2.0%
Fired at: 2026-04-29T07:31:14.123Z
Runbook: https://runbooks.example.com/slo/data-plane
```

When an alert resolves the engine fires a follow-up message
with `Resolved at: <timestamp>` appended.

### Routing config (operator-side dispatcher)

The other five receiver kinds remain plain config the
operator's dispatcher consumes:

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

The `aegis-control/alerts` feature is **independent** of this
config: enabling the feature flips on real VipTalk delivery,
the others remain operator-side regardless. Operators who don't
want any in-process HTTP from the gateway just leave the feature
off.

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

- [`crates/aegis-control/src/slo.rs`](../../crates/aegis-control/src/slo.rs) —
  `SloEngine` + `SliKind` + `AlertReceiver` + `default_receivers()`
- [`crates/aegis-control/src/slo/dispatch.rs`](../../crates/aegis-control/src/slo/dispatch.rs) —
  `send_alert(alert, &receivers) -> DispatchSummary`. VipTalk
  receivers get real HTTP delivery (gated by
  `aegis-control/alerts`); other kinds count as `external` in
  the summary so the operator's dispatcher takes over.
- The `format_alert_text` helper is the wire-format
  source-of-truth — change one place, change every receiver
  that reads it.

## Performance notes

- SLI calculation runs on a scheduled Prometheus recording rule, not
  on the request path
- Burn-rate queries are cheap aggregations on recording rules
- Receivers are async with bounded retries; failure to page is itself
  an alert
