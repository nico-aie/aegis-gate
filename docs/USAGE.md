# Aegis-Gate Usage & Operations Guide

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
- **Control Plane** (`aegis-control`): admin dashboard, authentication, audit chain, SIEM sinks, compliance, GitOps, SLO alerts

All three are compiled into a single `waf` binary via `aegis-bin`.

---

## 2. Running the Gateway

### Start

```sh
# With a local config file
waf run --config /etc/aegis/waf.yaml

# With defaults (looks for config/waf.yaml)
waf run
```

### Validate Config Without Starting

```sh
waf validate --config config/waf.yaml
```

This parses, resolves secrets, applies compliance profiles, and reports errors — without binding any listeners.

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

```
https://localhost:9443/
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

- **Overview**: live request rate, error rate, active connections (SSE real-time)
- **Config viewer**: current running config (read-only)
- **Health status**: live/ready/startup probes
- **Audit log**: recent audit events (SSE stream)
- **Metrics**: embedded Prometheus metrics link

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
1. **Allow** (score < 30)
2. **JS Challenge** (30-60)
3. **CAPTCHA** (60-80)
4. **Block** (80+)

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

### Compliance Profiles

Apply in config:

```yaml
compliance:
  modes: [fips, pci, soc2, gdpr, hipaa]
```

| Profile | Key Enforcement |
|---------|----------------|
| **FIPS** | aws-lc-rs TLS provider; reject RC4/DES/3DES/MD5; TLS ≥ 1.2 |
| **PCI-DSS** | TLS ≥ 1.2; PAN masking; audit retention ≥ 90 days |
| **SOC 2** | Audit hash chain enabled; admin trail; SLO alerts |
| **GDPR** | PII pseudonymization; data residency pin; right-to-erasure endpoint |
| **HIPAA** | PHI-safe log mode (PHI fields masked before sink write) |

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

### How It Works

1. Aegis polls a configured Git repository
2. New commits are verified (GPG/SSH signature against `allowed_signers`)
3. Config is dry-run validated
4. If valid, atomically swapped via `ConfigBroadcast`

### Break-Glass

Direct API config edits auto-create a branch + PR. The dashboard shows a banner until the PR is merged, maintaining GitOps as the source of truth.

### Config

```yaml
gitops:
  repo_url: "https://git.corp.com/infra/waf-config"
  branch: main
  poll_interval_secs: 60
  config_path: waf.yaml
  require_signed_commits: true
  allowed_signers:
    - "ops@corp.com"
    - "sre@corp.com"
```

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
waf validate  [--config PATH] [--strict]       Validate config + compliance
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

See [`docs/cli.md`](cli.md) for the full authoritative reference.

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
