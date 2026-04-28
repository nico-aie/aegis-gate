# Data Residency & Retention (v2, enterprise)

> **Enterprise addendum.** Pin tenant data to a region, enforce
> per-class retention ceilings, and support GDPR right-to-erasure
> workflows.

## Purpose

Meet regulatory requirements (GDPR, UK DPA, CCPA, Canada PIPEDA,
Brazil LGPD, and sector-specific rules) by restricting *where* data
lives, *how long*, and *who* can retrieve it.

## Data classes and defaults

| Class | Default retention | Min (compliance) | Max |
|---|---|---|---|
| Request access log | 30 days | 30 days (PCI) | 90 days |
| Security detection event | 365 days | 90 days (PCI) | 7 years |
| Admin change log | 7 years | lifetime (SOC 2) | indefinite |
| Challenge state | 1 hour | — | 24 hours |
| Rate-limit counters | sliding | — | sliding |
| Device fingerprint | 24 hours | — | 30 days |
| Risk score | 24 hours | — | 30 days |
| Session / OIDC | 8 hours | — | 8 hours |

Retention is enforced per sink (S3 lifecycle), per state keyspace
(TTL), and per index (dashboard queries honor the ceiling).

## Region pinning

Tenants can pin data to a single region or a named set:

```yaml
tenants:
  acme_eu:
    data_residency:
      regions: [eu-west-1, eu-central-1]
      enforce: strict    # strict | preferred
```

Under `strict`:

- Audit sinks must be in an allowed region (rejected otherwise)
- State-backend writes go to a region-local shard
- Metrics are kept in a regional Prometheus
- Dashboard queries for this tenant only hit regional endpoints

Under `preferred`, non-compliant sinks emit a warning but are allowed
for operational data (not for audit).

## Right-to-erasure (GDPR Art. 17)

Process:

1. Subject request received via admin API (`POST /api/privacy/erasure`)
2. Identify all records linked to subject (IP hash, device id, user id,
   tenant scoping)
3. Produce an erasure ticket, audit-logged with actor + reason
4. Delete / tombstone records in state backend and operational logs
5. Audit-log entries are **not** deleted (they are required evidence);
   instead, subject identifiers are pseudonymized in place — the hash
   chain stays valid because redaction replaces fields deterministically
6. Issue completion certificate

Dual control required: a second admin must approve erasure tickets.

## Pseudonymization

After `pseudonymize_after_days` (default 30):

- Client IPs stored as salted hash
- User agents truncated + hashed
- JWT `sub` stored as hashed form
- Raw values moved to a short-retention bucket

## Export

GDPR Art. 20 (data portability) and SOC 2 evidence exports:

- `GET /api/privacy/export/{subject}` streams JSONL of all records
- Export is authenticated, rate-limited, and audit-logged

## Configuration

```yaml
retention:
  access_log_days: 30
  detection_days: 365
  admin_days: 2555
  challenge_state_hours: 1
  fingerprint_hours: 24
  risk_hours: 24
  pseudonymize_after_days: 30
  erasure:
    dual_control: true
```

## Implementation

- `src/retention/policy.rs` — per-class ceilings + enforcement
- `src/retention/pseudonymize.rs` — salted-hash rewriter
- `src/privacy/erasure.rs` — erasure workflow
- `src/privacy/export.rs` — subject data export
- `src/residency/region.rs` — region pin validator

## Performance notes

- Retention enforcement runs on a daily sweeper; hot path untouched
- Pseudonymization runs in batch on the state-backend leader
- Region pinning is a single check at sink configuration load time
