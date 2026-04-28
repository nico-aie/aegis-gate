# Milestone D-M5 — Tracking Page

**Goal.** Single Tracking page surfacing the live operational state
that doesn't fit the operator or config buckets: SLO burn rate,
upstream pool detail, cluster peers, certificate freshness, GitOps
sync status, active alerts.

**Crate touched.** `aegis-control`.
**Verification.** `cargo test -p aegis-control && cargo clippy -p aegis-control -- -D warnings`.

**Reference.** [`docs/control-plane/enterprise/pages/tracking.md`](../../docs/control-plane/enterprise/pages/tracking.md).

---

## New endpoints

| Method | Path |
|--------|------|
| GET | `/api/slo` |
| GET | `/api/upstreams` |
| GET | `/api/cluster` |
| GET | `/api/certs` |
| POST | `/api/certs/{host}/renew` |
| GET | `/api/gitops/status` |
| GET | `/api/alerts` |
| GET | `/api/tracking/snapshot` |

All read-only except `/api/certs/{host}/renew`.

## Tasks

### D-M5-T5.1 SLO endpoint

- File: `src/api/slo.rs`
- Wraps the existing `slo.rs` engine. Returns per-SLI rows
  with current value, target, budget remaining, burn-rate
  series for 1h / 6h / 3d.
- Test: with seeded SLI history, assert the response shape.

### D-M5-T5.2 Upstream pools endpoint

- File: `src/api/upstreams.rs` (extend the M2 `summary`)
- Full pool detail: members with last health check, last
  error, in-flight requests, p99 latency, circuit-breaker state.
- Reads from the existing `aegis-proxy` pool registry.

### D-M5-T5.3 Cluster peers endpoint

- File: `src/api/cluster.rs`
- Reads from the cluster-membership module. Returns peer id,
  address, version, last heartbeat, lease holdings.

### D-M5-T5.4 Cert freshness endpoint

- File: `src/api/certs.rs`
- Reads the cert store; returns host, issuer, expiry,
  source (`acme | static | mtls`), days-to-expiry.
- `POST /api/certs/{host}/renew` triggers ACME renewal for
  ACME-managed certs; 405 for static. Audit-logged.

### D-M5-T5.5 GitOps status endpoint

- File: `src/api/gitops.rs`
- Returns repo, branch, last sync, head commit + signature
  status, drift indicator (compare in-memory config head with
  repo head), break-glass marker.

### D-M5-T5.6 Alerts endpoint

- File: `src/api/alerts.rs`
- Returns active alerts from the `slo.rs` state machine. Each
  alert: name, severity, since, runbook URL, last receiver
  delivery status (Slack / PagerDuty / Alertmanager / Jira /
  ServiceNow).

### D-M5-T5.7 Tracking snapshot aggregate

- File: `src/api/tracking.rs`
- Composes all six reads into one response with a 2s cache.
- Test: snapshot includes all six sections and stays under
  ~5KB JSON for a typical deployment.

### D-M5-T5.8 Tracking page UI

- File: `assets/dashboard/pages/tracking.js`
- Six-section layout from [`pages/tracking.md`](../../docs/control-plane/enterprise/pages/tracking.md).
- Polls `/api/tracking/snapshot` every 5s; per-section
  drill-ins fetch the dedicated endpoint on demand.
- Drawers for upstream pools, cluster peers, alerts.

### D-M5-T5.9 Cert renew confirmation

- File: `assets/dashboard/pages/tracking.js`
- Renew button opens a confirm modal with the host name typed
  back. Toast on success / failure.

## Exit gate

- Tracking page renders all six sections with real data.
- Cert renew action audited and reflected in `/api/certs`.
- `/api/tracking/snapshot` returns < 50ms p99 on a 50-route
  config (load test with k6 in `tests/load/`).
- 22+ new tests added; full workspace test suite green.

## Implement-Progress.md update

```
## Last Completed
- Task: D-M5 Tracking page
- Crate: aegis-control
- Status: DONE

## Next Task
- Task: D-M6-T6.1 Accessibility audit
- Plan: plans/dashboard-enterprise/milestone-6-polish.md
```
