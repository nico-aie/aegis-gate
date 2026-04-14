# Audit Logging (v2)

> **v1 → v2:** audit events are now **tamper-evident** via a hash chain,
> **forwarded to SIEM** in standard formats (syslog RFC 5424, CEF, LEEF, OCSF,
> Kafka), and a separate **admin change log** tracks every control-plane
> mutation for SOC 2 evidence. See [`siem-log-forwarding.md`](./siem-log-forwarding.md)
> and [`rbac-sso.md`](./rbac-sso.md).

## Purpose

Provide an authoritative, queryable, **compliance-grade** record of
everything the WAF did: security decisions, admin changes, operational
events. Fuels dashboards, SIEM pipelines, incident response, and audits.

## Event classes

| Class | Produced by | Sensitivity |
|-------|-------------|-------------|
| `request`   | Data-plane handler | medium |
| `detection` | Detectors, rule engine | high |
| `decision`  | Risk engine, challenge | high |
| `auto_block`| DDoS, brute force | high |
| `admin`     | Control-plane mutations | critical |
| `operational` | Config reload, cert reload, health transitions | medium |

## Event schema (v2, stable)

```json
{
  "schema_version": 2,
  "ts": "2026-04-12T10:15:30.123Z",
  "class": "detection",
  "tenant_id": "acme",
  "request_id": "c0ffee…",
  "trace_id": "00-4bf92f…-e2...-01",
  "client_ip": "203.0.113.4",
  "asn": 15169,
  "method": "POST",
  "host": "api.example.com",
  "path": "/v1/login",
  "route_id": "api_v1_login",
  "tier": "critical",
  "decision": "block",
  "risk_score": 85,
  "detectors": ["sqli"],
  "rule_ids": ["block_sqlmap_ua"],
  "bot_class": "likely",
  "user_agent": "sqlmap/1.7.0",
  "jwt_sub": null,
  "feed_id": null,
  "elapsed_ms": 3.1,
  "status": 403,
  "prev_hash": "sha256:…",
  "hash": "sha256:…"
}
```

Breaking changes to field names require a `schema_version` bump.

## Tamper-evident hash chain

Every event in the admin and detection classes carries:

```
hash = SHA-256(prev_hash || canonical_json_of_fields)
```

The chain root is periodically:

1. Signed with the cluster key
2. Exported to an external **witness** (S3 with Object Lock, an append-only
   log service, or a blockchain anchor — configurable)

A CLI (`waf audit verify`) walks a local file or sink export and reports
the first break, if any.

## Sinks

Audit events flow through a bounded `EventBus` channel to one or more
sinks. Each sink is a dedicated tokio task with backpressure.

| Sink | Format | Transport |
|------|--------|-----------|
| `stdout` | JSON Lines | stdout |
| `file`   | JSON / CEF / combined | Rotating file via `tracing-appender` |
| `syslog` | RFC 5424  | TCP + TLS |
| `cef`    | CEF       | Syslog or file |
| `leef`   | LEEF      | Syslog or file |
| `ocsf`   | OCSF JSON | HTTP POST batch |
| `kafka`  | JSON / OCSF | `rdkafka` with SASL + TLS |
| `http`   | JSON      | HTTPS POST (generic collector) |

On bounded-channel full, sinks **spool to disk** (bounded). On overflow,
**drop lowest-severity first** and emit `waf_audit_drops_total`.

## Retention

- Security events: default 365 days (90 days minimum in PCI mode)
- Admin change events: retained for the lifetime of the deployment +
  exported periodically
- Request access logs: default 30 days

Retention is enforced per sink by the sink implementation (e.g. S3
lifecycle policies) plus a local spool purger.

## Redaction

All events run through the DLP pipeline before emission, masking:

- Authorization / Cookie headers by default
- Any header / JSON field the DLP patterns classify as secret
- Request bodies on PHI-flagged routes (HIPAA mode)

The dashboard live feed presents the already-redacted form.

## Admin change log

Every mutation through the admin API produces a separate high-severity
record capturing:

- Actor (OIDC `sub` + IdP)
- Target (what resource, what change)
- Full diff (added / removed / modified fields)
- Reason (free text, required)
- Approver (when change-approval is on)

This feed has a dedicated sink group so auditors can consume it without
wading through data-plane events. Tamper chain is separate.

## Access-log compatibility

A lightweight "access log" variant in nginx `combined` format is produced
alongside structured events for compatibility with existing log analysis
tooling. Configurable template string with `%{var}` placeholders.

## Configuration

```yaml
observability:
  audit:
    retention_days: 365
    hash_chain: true
    witness:
      type: s3
      bucket: "audit-witness"
      kms_key_id: "${secret:env:AUDIT_KMS_KEY}"
    sinks:
      - { name: local, type: file, format: json, path: /var/log/waf/audit.jsonl }
      - { name: siem,  type: syslog, format: cef, endpoint: "siem.internal:6514", tls: true }
      - { name: kafka, type: kafka, format: ocsf, brokers: [...], topic: waf-events }
```

## Implementation

- `src/audit/event.rs` — `AuditEvent` struct, canonical JSON
- `src/audit/chain.rs` — hash chain + verifier CLI
- `src/audit/bus.rs` — `EventBus` (tokio broadcast + bounded per-sink queues)
- `src/audit/sinks/*` — one module per sink
- `src/audit/spool.rs` — disk spool with bounded size + drop policy
- `src/audit/formatter/{json,combined,cef,leef,ocsf}.rs`

## Performance notes

- Emit is lock-free: push into a bounded channel; sinks drain in background
- JSON canonicalization (sorted keys for hashing) is done once per event
- Hash chain uses `Sha256` from `sha2` (hardware accelerated on x86-64)
