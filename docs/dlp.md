# Data Loss Prevention (DLP) (v2, enterprise)

> **Enterprise addendum.** Scans requests **and** responses for sensitive
> data (PII, credentials, card numbers, health identifiers) and redacts,
> masks, tokenizes, or blocks based on policy. Shared with
> [`response-filtering.md`](./response-filtering.md) and
> [`audit-logging.md`](./audit-logging.md).

## Purpose

Prevent credential leakage in request bodies, PII exfiltration in
responses, and sensitive data in audit logs. One canonical pipeline
applied in three places: ingress, egress, log redaction.

## Patterns

Shipped set (all Luhn-validated where applicable):

- Credit card numbers (16/15/14-digit issuers, Luhn checked)
- US SSN (`XXX-XX-XXXX`, `XXXXXXXXX`)
- IBAN (per-country length + mod-97 check)
- US phone, email, DOB
- AWS (`AKIA...`, `ASIA...`), GCP keys, Azure SAS, Slack (`xoxb-`, `xoxp-`),
  Stripe (`sk_live_`, `pk_live_`), GitHub (`ghp_`, `gho_`, `ghu_`),
  Atlassian, Twilio
- Private keys (PEM headers)
- JWTs (`eyJ...` with structure check)
- Password-like fields by key name
- HIPAA: MRN patterns, ICD-10 code patterns (opt-in)

Custom patterns via regex with a named capture group `value`.

## Actions

Per match:

- **redact** — replace with `[REDACTED]`
- **mask** — shape-preserving mask (`****-****-****-1234`)
- **fpe** — format-preserving encryption via AES-FF1; downstream still
  gets a valid-looking token that can later be detokenized with the key
- **hash** — `HMAC-SHA256` with a per-deployment salt
- **block** — reject the whole request with 4xx; audit event

## Pipeline placement

1. **Inbound** — scan request bodies on configured routes; apply
   action before the security pipeline sees the body. FPE-encoded
   tokens are opaque to downstream.
2. **Outbound** — scan response bodies via the streaming frame
   processor in [`response-filtering.md`](./response-filtering.md).
3. **Audit redaction** — every audit event runs through DLP before
   emission so sensitive data is never persisted even in logs.

Aho-Corasick is used for the fixed-literal patterns; regex is used
for structural patterns; both feed the same match aggregator.

## Key management

FPE and hash actions use keys from [`secrets-management.md`](./secrets-management.md):

```yaml
dlp:
  fpe_key: "${secret:vault:kv/data/waf#fpe_key}"
  hash_salt: "${secret:vault:kv/data/waf#dlp_salt}"
```

Key rotation re-generates tokens going forward; existing FPE tokens
remain decryptable via a versioned keyring until retired.

## Policy scoping

Policies are per-tenant and per-route:

```yaml
dlp:
  policies:
    pci_strict:
      patterns: [credit_card, cvv, track_data]
      inbound_action: block
      outbound_action: mask
      audit_action: redact
    hipaa:
      patterns: [mrn, icd10, us_dob]
      inbound_action: redact
      outbound_action: redact
      audit_action: redact
    default:
      patterns: [email, api_key_any, jwt]
      outbound_action: redact
      audit_action: redact

routes:
  - id: payments
    path: /payments/
    match: prefix
    dlp_policy: pci_strict
```

## Confidence + false-positive control

Each pattern carries a confidence score. Low-confidence matches can
be configured to **only** mask in responses without blocking inbound.
Double-validation (Luhn, IBAN mod-97, JWT structure) eliminates most
false positives on numeric patterns.

## Metrics + audit

- `waf_dlp_matches_total{pattern,direction,action,policy}`
- Every match produces a `detection` audit event (itself redacted)

## Implementation

- `src/dlp/patterns.rs` — pattern registry + compile
- `src/dlp/match.rs` — Aho-Corasick + regex orchestrator
- `src/dlp/action.rs` — redact/mask/fpe/hash/block
- `src/dlp/fpe.rs` — AES-FF1
- `src/dlp/policy.rs` — per-tenant/per-route policy resolver

## Performance notes

- Aho-Corasick is O(n) over the body
- Regex runs only on candidate windows (literal preselection)
- FPE cost is microseconds per token; hash is nanoseconds
- Streaming match uses a bounded trailing window for cross-frame
  patterns
