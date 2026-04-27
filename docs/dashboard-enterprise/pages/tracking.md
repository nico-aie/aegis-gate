# Page — Tracking

> The "Tracking" sidebar consolidates the live-state widgets that
> aren't a fit for the operator or config buckets: SLO burn,
> upstream pool health, cluster peer state, certificate freshness,
> GitOps sync. Think of it as "the bits that page you in the
> middle of the night".

## Route

`GET /dashboard/tracking`

## Data sources

| Widget | Source |
|--------|--------|
| SLO burn rate | `GET /api/slo` |
| Upstream pools | `GET /api/upstreams` |
| Cluster peers | `GET /api/cluster` |
| Cert freshness | `GET /api/certs` |
| GitOps sync | `GET /api/gitops/status` |
| Active alerts | `GET /api/alerts` |

Most of these endpoints already exist in `aegis-control` (audit,
SLO module, GitOps loader). The few new ones (`/api/upstreams`,
`/api/cluster`, `/api/certs`, `/api/alerts`) are read-only
projections of existing in-memory state — see
[`../api.md`](../api.md).

## Layout

```
┌──────────────────────────────────────────────────────────────┐
│ Tracking — operational state                                  │
├──────────────────────────────────────────────────────────────┤
│ ┌─SLO burn ─────────────┐  ┌─Active alerts ────────────────┐ │
│ │ availability  [99.95%]│  │ 0 firing, 1 pending, 0 resolved│ │
│ │ overhead p95  [12ms]  │  │ list…                          │ │
│ │ … per SLI rows         │  │                                │ │
│ └────────────────────────┘  └────────────────────────────────┘ │
├──────────────────────────────────────────────────────────────┤
│ ┌─Upstream pools ───────────────────────────────────────────┐ │
│ │ pool · members · healthy/total · LB · CB · p99            │ │
│ └────────────────────────────────────────────────────────────┘ │
├──────────────────────────────────────────────────────────────┤
│ ┌─Cluster peers ────────────┐  ┌─Cert freshness ───────────┐ │
│ │ id · addr · version · last │  │ host · expires · status   │ │
│ │ heartbeat                  │  │                            │ │
│ └────────────────────────────┘  └────────────────────────────┘ │
├──────────────────────────────────────────────────────────────┤
│ ┌─GitOps sync ──────────────────────────────────────────────┐ │
│ │ repo · branch · last sync · drift · break-glass status    │ │
│ └────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

## SLO burn

- One row per SLI from `slo.rs` (availability, p50/p95/p99
  overhead, per-pool availability, audit delivery, cert
  freshness).
- Each row: name, current value, target, budget remaining,
  burn-rate sparkline (1h / 6h / 3d).
- Colour: ok / warn / err thresholds inherited from the SLO
  config.

## Active alerts

- List of alerts currently firing or pending (from the alert
  state machine in `slo.rs`).
- Each row: severity pill, alert name, since, runbook link.
- Click → drawer with the full alert payload (would-be
  Alertmanager body) and the receiver delivery status (Slack,
  PagerDuty, ServiceNow, Jira webhook responses).

## Upstream pools

- One row per pool.
- Columns: pool id, member count, healthy / total, LB strategy,
  circuit-breaker state (per member, mini grid), p99 latency.
- Click pool row → drawer listing each member with last health
  check, last error, in-flight requests.

## Cluster peers

- Table of peers from the cluster membership module
  (`aegis-proxy::cluster`).
- Columns: id, address, version (with skew warning if mismatched),
  role (leader/follower for witness/state-snapshot leases), last
  heartbeat (relative time), lease holdings.

## Cert freshness

- One row per certificate in the cert store.
- Columns: host, issuer, days to expiry (red `< 7`, amber
  `< 30`, ok otherwise), source (acme / static / mtls).
- Action: "Renew now" if ACME-managed (calls `POST
  /api/certs/{host}/renew`).

## GitOps sync

- Single panel showing repo, branch, last sync timestamp, head
  commit + signature status, drift indicator (red if local
  config differs from repo head), break-glass banner if
  break-glass override is active.
- Action: "Force resync" (admin-only, audit-logged).

## Refresh

- The whole page polls `/api/tracking/snapshot` every 5s (a
  single aggregated read that fans out internally) — keeps the
  UI cheap. Individual widgets can also poll their own endpoint
  on focus.

## Empty state

- Never empty: there's always at least one SLI, one cert, one
  pool. If a section is genuinely empty (no GitOps configured),
  show a static "Not configured" tile with a link to
  `/dashboard/settings#integrations`.
