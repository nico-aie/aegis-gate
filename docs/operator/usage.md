# Aegis-Gate Usage & Operations Guide

> **Status:** Implemented — Operator runbook current; references real `waf` subcommands.
>
> See [`../../plans/plan.md`](../../plans/plan.md#1-doc-by-doc-implementation-status) for the full matrix.

Complete guide to operating Aegis-Gate in development and production.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Running the Gateway](#2-running-the-gateway)
3. [Configuration](#3-configuration)
4. [Admin Dashboard](#4-admin-dashboard)
5. [Security Pipeline](#5-security-pipeline)
6. [Audit & Compliance](#6-audit--compliance)
7. [Observability](#7-observability)
8. [GitOps](#8-gitops)
9. [SLO & Alerting](#9-slo--alerting)
10. [CLI Reference](#10-cli-reference)
11. [Operational Runbooks](#11-operational-runbooks)

---

## 1. Architecture Overview

Aegis-Gate is composed of three planes:

```
Client → [Data Plane] → [Security Pipeline] → Upstream
              ↕                  ↕
         [Control Plane: dashboard, audit, metrics, compliance]
```

- **Data Plane** (`aegis-proxy`): TLS termination, routing, upstream pools, load balancing, caching, retries
- **Security Pipeline** (`aegis-security`): rule engine, OWASP detectors, risk scoring, DLP, API security
- **Control Plane** (`aegis-control`): 11-page enterprise SPA dashboard, 24 read-only `/api/*` endpoints, authentication, audit chain, SIEM sinks, SLO alerts

All three are compiled into a single `waf` binary via `aegis-bin`.

---

## 2. Running the Gateway

### Start

```sh
# With a local config file
waf run --config /etc/aegis/waf.yaml

# With defaults (looks for config/prod.yaml)
waf run
```

### Validate Config Without Starting

```sh
waf validate --config config/prod.yaml
```

This parses, resolves secrets, and reports errors — without binding any listeners.

### Graceful Operations

| Signal | Action |
|--------|--------|
| `SIGTERM` | Graceful shutdown — drain active connections, then exit |
| `SIGUSR2` | Hot binary reload — start new process, drain old |
| `SIGHUP` | Config reload (if hot-reload enabled) |

---

## 3. Configuration

### Minimal Config

```yaml
listeners:
  data:
    - bind: "0.0.0.0:8443"
  admin:
    bind: "127.0.0.1:9443"

routes:
  - id: api
    path: "/api/*"
    upstream: backend

upstreams:
  backend:
    members:
      - addr: "10.0.0.1:8080"

state:
  backend: in_memory
```

### Routing

Routes are matched in order: most-specific path first (trie-based).

```yaml
routes:
  - id: api-v2
    host: "api.example.com"
    path: "/v2/*"
    upstream: api-v2-pool
    rate_limit:
      requests_per_second: 100
      burst: 50

  - id: static
    path: "/static/*"
    upstream: cdn
    cache:
      enabled: true
      ttl: 3600

  - id: catch-all
    path: "/"
    upstream: default
```

### Upstream Pools

```yaml
upstreams:
  api-pool:
    members:
      - addr: "10.0.1.10:8080"
        weight: 3
      - addr: "10.0.1.11:8080"
        weight: 1
    lb: weighted_round_robin    # round_robin | random | least_conn | ip_hash | weighted_round_robin
    health_check:
      interval: 10s
      timeout: 3s
      path: /healthz
      expected_status: 200
    circuit_breaker:
      threshold: 5
      timeout: 30s
```

### TLS

```yaml
listeners:
  data:
    - bind: "0.0.0.0:8443"
      tls:
        cert: /etc/aegis/tls/server.crt
        key: /etc/aegis/tls/server.key
        min_version: "1.2"
        # ACME (auto-cert)
        acme:
          enabled: true
          email: admin@example.com
          directory: https://acme-v02.api.letsencrypt.org/directory
```

---

## 4. Admin Dashboard

### Access

The admin dashboard is served on the admin listener (default `:9443`).
The root path redirects to the SPA shell, which then routes
client-side to `/dashboard/overview`.

```
https://localhost:9443/                    →  serves the SPA shell
https://localhost:9443/dashboard/          →  redirects to /dashboard/overview
https://localhost:9443/dashboard/<page>    →  deep-link to any of 11 pages
https://localhost:9443/dashboard/sse       →  Server-Sent Events stream
https://localhost:9443/dashboard/assets/*  →  embedded JS / CSS / icons
https://localhost:9443/api/*               →  27 read-only JSON endpoints
https://localhost:9443/healthz/{live,ready,startup}
https://localhost:9443/metrics             →  Prometheus exposition
```

### Authentication Flow

1. **IP Allowlist check** (pre-TCP)
2. **mTLS** (optional — valid client cert bypasses password)
3. **Password** (argon2id)
4. **TOTP** (6-digit, 30s step)
5. **Session issued** (HMAC cookie: `HttpOnly; Secure; SameSite=Strict`)
6. **CSRF token** set (double-submit cookie)

### Setup Admin Credentials

```sh
# Hash a password
waf admin set-password
# Paste/pipe password → receive PHC hash string

# Enroll TOTP
waf admin enroll-totp --issuer "Aegis" --account "admin@corp.com"
# Receive: base32 secret, provisioning URI, recovery codes
```

### Dashboard Features

The dashboard is a multi-page operator console (D-M1..D-M6 — see
[`docs/control-plane/enterprise/`](../control-plane/enterprise/) for the full
design spec) served as a vanilla-JS SPA on the admin listener.

**Sidebar pages (11)**:

| Section | Page | Purpose |
|---------|------|---------|
| Operator | Overview | 4 KPI tiles + 15 m traffic chart + attack-distribution donut + top-attackers table |
| Operator | Live Feed | SSE-driven row stream + class/action filter chips + row-detail drawer |
| Operator | Attack Events | Detector breakdown donut, top attackers, threat-intel hits, bot mix |
| Operator | Analytics | 6 allow-listed PromQL chart cards with 1h / 6h / 24h / 7d / 30d range selector |
| Operator | Audit Log | Cursor-paginated table, witness lag pill, chain status pill, NDJSON export |
| Configuration | Rule Manager | Rule list + drawer (mutation gated on M3 audit-mutation pipeline) |
| Configuration | Tier Config | Four canonical tiers (`critical`/`high`/`medium`/`low`) with pipelines + thresholds |
| Configuration | Blacklist / Whitelist | IP / CIDR / ASN entry list + bulk import (read-only v1) |
| Configuration | Settings | Account info, integrations, danger-zone (break-glass status) |
| Tracking | Tracking | SLO burn, upstreams, cluster peers, certs, alerts |

**API surface** (24 read-only endpoints, all under `/api/*` —
detailed shapes in
[`docs/control-plane/enterprise/api.md`](../control-plane/enterprise/api.md)):

```
/api/about               /api/stats              /api/stats/timeseries
/api/upstreams           /api/upstreams/summary  /api/attacks/distribution
/api/attacks/top         /api/attacks/by-detector /api/threat-intel/hits
/api/bots/mix            /api/audit/since        /api/filters
/api/analytics/query     /api/rules              /api/rules/top
/api/tiers               /api/blacklist          /api/whitelist
/api/admin/sessions      /api/admin/break-glass  /api/integrations
/api/slo                 /api/cluster            /api/certs
/api/alerts              /api/tracking/snapshot
```

> Removed 2026-07-04 (PE-1): `/api/audit/witness`,
> `/api/gitops/status`, `/api/threat-intel/feeds` — placeholder
> endpoints that never served real data.

**Real-time surfaces**:
- `/dashboard/sse` — Server-Sent Events stream consumed by Live
  Feed (with optional `?class=&action=&route=` server-side filter)
  and the status-bar connection pill (Connected / Reconnecting /
  Disconnected).
- Per-page polling cadence aligned with the per-endpoint
  `Cache-Control: max-age=…` (1 s for stats, 10 s for analytics,
  etc.). All pages pause polling on `document.visibilityState !==
  "visible"`.

**Theme + i18n**: Light / dark / system theme toggle persisted in
`localStorage`; theme bootstrap runs synchronously in `<head>` to
avoid flash-of-wrong-theme. All UI strings live in
`/dashboard/assets/i18n/en.json` (no hardcoded English in HTML/JS).

**Read-only in v1**: mutating endpoints (rule save, tier put,
blacklist/whitelist add, password change, etc.) are gated on the
M3 audit-mutation pipeline being wired so writes go through CSRF
+ audit chain. The page UI surfaces this with a status banner.

### Session Management

- Idle timeout: 30 minutes
- Absolute timeout: 8 hours
- Revocation: immediate (server-side session store)
- TOTP required for full access

### Rate Limiting

- Per-IP: 5 attempts / 1 minute
- Per-user: 10 attempts / 15 minutes
- Lockout: 15 minutes after threshold exceeded
- Exponential backoff: 2s → 5s → 15s between failed attempts

---

## 5. Security Pipeline

### OWASP Detectors

| Detector | Protects Against |
|----------|-----------------|
| SQLi | SQL injection in query strings, headers, body |
| XSS | Cross-site scripting (reflected, stored) |
| Path Traversal | `../` directory traversal attempts |
| SSRF | Server-side request forgery (internal IP, metadata endpoints) |
| Header Injection | CRLF injection, response splitting |
| Body Abuse | Oversized bodies, deep JSON nesting |
| Recon | Scanner signatures, admin path probing |

### Rule Engine

Custom rules use a declarative syntax:

```yaml
rules:
  - id: block-tor-exit
    condition: "ip.geoip.is_tor == true"
    action: block
    reason: "Tor exit node"

  - id: rate-limit-api
    condition: "path.starts_with('/api') && req.rate > 100"
    action: challenge
    reason: "API rate exceeded"
```

### Risk Scoring

Each request accumulates a risk score from multiple signals:
- OWASP detector matches
- IP reputation (threat intel feeds)
- Bot classification score
- Behavioral anomaly score
- TLS fingerprint mismatch

The **challenge ladder** escalates based on score:
1. **Allow** (score < 40, default)
2. **Challenge** (40 ≤ score < 80, 429 + `Retry-After`)
3. **Block** (score ≥ 80)

Thresholds are tunable via `risk.thresholds.{challenge_at, block_at}`.

#### P6 — strikes + trust recovery

Beyond the legacy half-life decay, the WAF maintains a per-IP
strike counter that **never decays**:

```yaml
risk:
  trust_recovery:
    per_hour: 30        # max points the score can claw back per hour of clean traffic
  strikes:
    block_at: 50        # permanent block after this many malicious events
```

Each malicious detection bumps the strike counter; once
`block_at` is reached, the IP is blocked at the data plane
*regardless of how much its score has decayed* — until an
operator runs `PUT /api/risk/{ip}/reset` (audit-mutated).

```sh
# Inspect risky clients
curl -s -b cookies.txt https://127.0.0.1:9443/api/risk?limit=20 | jq

# Reset one client (assumes you've logged in and have aegis_csrf in cookies.txt)
CSRF=$(grep aegis_csrf cookies.txt | awk '{print $7}')
curl -s -X PUT -b cookies.txt -H "x-csrf-token: $CSRF" \
  https://127.0.0.1:9443/api/risk/203.0.113.7/reset | jq
```

---

### Security Toggles (P1–P8)

The WAF ships an audit-mutated control plane for runtime
configuration of every security knob. Every PUT below requires
an authenticated session + matching `aegis_csrf` cookie/header
pair, and every applied change lands an admin chain entry.

#### Detection-class toggles

```sh
# Inspect the live mask + per-tier overrides + declared compliance modes
curl -s -b cookies.txt https://127.0.0.1:9443/api/detectors | jq

# Disable the recon detector globally
curl -s -X PUT -b cookies.txt -H "x-csrf-token: $CSRF" \
  -H "content-type: application/json" \
  -d '{"mask":{"sqli":true,"xss":true,"path_traversal":true,
                "ssrf":true,"header_injection":true,
                "body_abuse":true,"recon":false,"brute_force":true}}' \
  https://127.0.0.1:9443/api/detectors | jq

# Override just the High tier (keep base mask intact)
curl -s -X PUT -b cookies.txt -H "x-csrf-token: $CSRF" \
  -H "content-type: application/json" \
  -d '{"overrides":{"high":{"sqli":true,"xss":true,"path_traversal":true,
                            "ssrf":true,"header_injection":true,
                            "body_abuse":true,"recon":true,"brute_force":false}}}' \
  https://127.0.0.1:9443/api/detectors | jq
```

> Compliance lock-by-mode (auto-pinning detector classes when a
> mode is active) is **deferred for now** — operators may freely
> enable or disable any class regardless of `compliance.modes`.
> See [`plans/future/compliance-profiles.md`](../../plans/archive/compliance-profiles.md)
> for the restoration plan.

#### Load-mode override

```sh
curl -s -b cookies.txt https://127.0.0.1:9443/api/loadmode | jq

# Pin to elevated for a maintenance window
curl -s -X PUT -b cookies.txt -H "x-csrf-token: $CSRF" \
  -H "content-type: application/json" \
  -d '{"override":"elevated"}' \
  https://127.0.0.1:9443/api/loadmode | jq

# Clear the pin (back to auto-detection)
curl -s -X PUT -b cookies.txt -H "x-csrf-token: $CSRF" \
  -H "content-type: application/json" \
  -d '{"override":"unset"}' \
  https://127.0.0.1:9443/api/loadmode | jq
```

#### Audit verbosity

```sh
curl -s -b cookies.txt https://127.0.0.1:9443/api/logging | jq

# Drop verbose `fields` payloads in audit events
curl -s -X PUT -b cookies.txt -H "x-csrf-token: $CSRF" \
  -H "content-type: application/json" \
  -d '{"level":"warn"}' https://127.0.0.1:9443/api/logging

# Full silence (only block-action 403s, no chain writes)
curl -s -X PUT -b cookies.txt -H "x-csrf-token: $CSRF" \
  -H "content-type: application/json" \
  -d '{"level":"silent"}' https://127.0.0.1:9443/api/logging
```

#### Cold-tier sink inventory

```sh
curl -s -b cookies.txt https://127.0.0.1:9443/api/cold-tier | jq
```

Returns the list of configured `audit.sinks` (jsonl / syslog /
splunk / kafka) with destination + delivery state. Splunk HEC
tokens are redacted before the response is built.

See `docs/control-plane/enterprise/api.md` for the full request /
response shapes and `docs/observability/audit-logging.md` for the
`AuditedMutate` invariants.

### DLP (Data Loss Prevention)

```yaml
dlp:
  patterns:
    - name: credit-card
      regex: '\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
      action: mask          # mask | block | alert
    - name: ssn
      regex: '\b\d{3}-\d{2}-\d{4}\b'
      action: fpe           # Format-Preserving Encryption (AES-FF1)
```

### API Security

- **OpenAPI enforcement**: validate requests against a schema
- **GraphQL guard**: depth limit, complexity limit, introspection control
- **JWT validation**: RS256/ES256, issuer/audience checks
- **HMAC request signing**: verify `X-Signature` headers

---

## 6. Audit & Compliance

### Audit Hash Chain

Every significant event is recorded in a tamper-evident SHA-256 hash chain:

```
Event₀ → hash(genesis || Event₀) = H₀
Event₁ → hash(H₀ || Event₁) = H₁
...
```

### Verify Integrity

```sh
waf audit verify --from /var/log/aegis/audit.ndjson
# OK: chain is clean (1234 entries)
# — or —
# TAMPERED at line 567: expected hash abc..., got def...
```

### SIEM Sinks

| Sink | Format | Transport |
|------|--------|-----------|
| JSONL | Newline-delimited JSON | File / stdout |
| Syslog | RFC 5424 | UDP / TCP / TLS |
| CEF | Common Event Format | Syslog |
| LEEF | Log Event Extended Format | Syslog |
| OCSF | Open Cybersecurity Schema | HTTP |
| Splunk HEC | Splunk HTTP Event Collector | HTTPS |
| ECS | Elastic Common Schema | HTTP |
| Kafka | JSON | Kafka producer |

Only the JSONL persist task and the Syslog forwarder run as live
sink tasks today; the other formats are available to them (and to
export tooling) but have no dedicated forwarder — `/api/cold-tier`
reports those sinks as `unwired`.

### Auth & Control-Plane Events (AU-1, 2026-07-04)

Admin authentication leaves an `Access`-class trail: `login_success`,
`login_failure` (reason bucketed — `invalid_credentials` /
`locked_out` / `rate_limited` / `store_unavailable`; submitted
credentials are never recorded), and `logout` (real revocations
only). Repeated failures from one IP aggregate: first event
immediately, then a roll-up carrying `fields.count` when the IP is
next seen after the 30 s window — a credential-stuffing flood cannot
melt the audit bus. The control-plane `reset_state` wipe emits an
`Admin`-class `reset_state` event **before** the wipe runs, so the
wipe cannot erase its own record.

### Durability Model (honest version)

- Events flow over a bounded in-process broadcast bus
  (`audit.bus_capacity`, default 100 000). A consumer that falls
  behind loses events *from its own view only*; those drops are
  counted on `waf_audit_events_dropped_total{consumer}` and logged.
  Delivery is **best-effort by design** — the data plane never
  blocks on audit I/O.
- The JSONL chain sink `flush`es + `fsync`s (`sync_data`) **per
  batch** (F-CRITICAL-013), so the crash-loss window is bounded by
  one batch: up to `max_batch` events (default 100) or
  `flush_interval` (default 1 s), whichever fills first — plus
  whatever was still in the broadcast buffer.
- Per-sink delivery state (delivered / errors / last success) is
  live at `GET /api/cold-tier`.

### Compliance Profiles (deferred)

`cfg.compliance.modes` accepts five tag values:

```yaml
compliance:
  modes: [fips, pci, soc2, gdpr, hipaa]
```

The dashboard's Compliance page surfaces the declared modes as
documentation tags. **Per-regime enforcement (PAN masking, FIPS
primitive allow-list, residency pinning, PHI log mode, automatic
detector pinning, retention floors) is deferred for now** —
declaring a mode does not change WAF behavior today. Operators
may freely enable or disable any detector class regardless of
which modes are set.

The full per-regime restoration plan (including the historical
detector pin baseline `sqli, xss, path_traversal, ssrf`) lives at
[`plans/future/compliance-profiles.md`](../../plans/archive/compliance-profiles.md).

### Data Residency & Erasure

```sh
# GDPR right-to-erasure (via admin API)
POST /api/gdpr/erase
{
  "subject_id": "user-12345",
  "reason": "Data subject request"
}

# Export subject data
GET /api/gdpr/export?subject=user-12345
```

Erasure pseudonymizes PII in audit events without breaking the hash chain.

---

## 7. Observability

### Prometheus Metrics

Scraped from `:9100/metrics`. Key metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `aegis_requests_total` | Counter | Total requests by route, status |
| `aegis_request_duration_seconds` | Histogram | Request latency |
| `aegis_upstream_health` | Gauge | Upstream pool health (0/1) |
| `aegis_security_detections_total` | Counter | Security detections by detector |
| `aegis_audit_events_total` | Counter | Audit events emitted |
| `aegis_slo_budget_remaining_pct` | Gauge | SLO error budget remaining |

### Health Probes

| Endpoint | Use Case |
|----------|----------|
| `/healthz/live` | Kubernetes liveness probe |
| `/healthz/ready` | Kubernetes readiness probe (config + upstreams) |
| `/healthz/startup` | Kubernetes startup probe |

### Distributed Tracing

W3C Trace Context (`traceparent` header) is propagated through the proxy. Export to Jaeger via OTLP.

### Access Logs

Three formats available:

```yaml
access_log:
  format: combined    # combined | json | template
  # template: '$remote_addr - $request_method $path $status $duration_ms'
```

---

## 8. GitOps

**Not shipped.** The gitops module was removed 2026-05-17
(F-CRITICAL-005: it had zero production callers), and the placeholder
`/api/gitops/status` endpoint plus its dashboard card were removed
2026-07-04 (PE-1). There is no `gitops:` config section — configure
the WAF via the dashboard/API (audit-chained) or by deploying
`waf.yaml` through your own pipeline (atomic-rename hot-reload is
supported and drilled). Re-introduction is tracked as a Round-3 §5.9
bonus candidate.

---

## 9. SLO & Alerting

### SLIs Tracked

| SLI | Description |
|-----|-------------|
| Data-plane availability | `1 - error_rate` |
| WAF overhead p50/p95/p99 | Latency added by security processing |
| Upstream availability | Per-pool health |
| Audit delivery rate | Events emitted vs acknowledged by sinks |
| Cert freshness | Days to certificate expiry |

### Multi-Burn-Rate Alerting

| Window | Budget Threshold | Severity |
|--------|-----------------|----------|
| 1 hour | 2% consumed | **Page** (PagerDuty) |
| 6 hours | 5% consumed | Ticket (Jira/ServiceNow) |
| 3 days | 10% consumed | Ticket |

### Alert Receivers

```yaml
slo:
  receivers:
    - name: pagerduty
      type: pagerduty
      routing_key: "R0..."
    - name: slack-sre
      type: slack
      webhook_url: "https://hooks.slack.com/services/..."
    - name: jira
      type: jira
      base_url: "https://jira.corp.com"
      project: SRE
```

Every alert includes a `runbook_url` pointing to the relevant operational runbook.

---

## 10. CLI Reference

```
waf run       [--config PATH] [--workers N]    Start the gateway
waf validate  [--config PATH] [--strict]       Validate config (parser + lint)
waf audit     verify --from PATH               Verify audit chain integrity
waf audit     export --since T --until T       Export audit events
waf admin     set-password                     Hash admin password (argon2id)
waf admin     enroll-totp [--issuer] [--account]  Generate TOTP secret
waf config    export [--format yaml|json]      Export compiled config
waf config    diff --left P --right P          Structural config diff
waf rules     lint --path DIR                  Lint rule files
waf rules     test --path DIR --corpus DIR     Test rules against corpus
waf cert      list                             List TLS certificates
waf cert      renew --name NAME                Force ACME renewal
waf cluster   peers                            Show cluster members
waf snapshot  create --out PATH                DR snapshot
waf snapshot  restore --from PATH              DR restore
waf version   [--json]                         Build info
waf help                                       Help
```

See [`docs/operator/cli.md`](./cli.md) for the full authoritative reference.

---

## 11. Operational Runbooks

### WAF Not Starting

1. Check config: `waf validate --config ...`
2. Check port conflicts: `ss -tlnp | grep 8443`
3. Check TLS certs exist and are readable
4. Check etcd connectivity (if using etcd backend)

### High Latency

1. Check upstream health: dashboard or `/healthz/ready`
2. Check circuit breaker state in metrics
3. Review `aegis_request_duration_seconds` histogram
4. Check if load shedder is active

### Security Alert Spike

1. Check `aegis_security_detections_total` by detector type
2. Review audit log for patterns (IP, path, user agent)
3. Check if it's a false positive (benign corpus)
4. Adjust rule thresholds or add to allowlist if FP

### Audit Chain Broken

1. Run `waf audit verify --from <path>`
2. Note the exact line number reported
3. Check filesystem integrity (disk errors, unauthorized access)
4. Restore from last known-good witness export

### SLO Budget Exhausted

1. Check which SLI is burning (dashboard or metrics)
2. For availability: check upstream pool health
3. For latency: check if security pipeline has new expensive rules
4. For audit delivery: check SIEM sink connectivity
5. Acknowledge alert in PagerDuty/Jira once mitigated
