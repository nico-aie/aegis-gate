# Content Scanning (ICAP / AV) (v2, enterprise)

> **Enterprise addendum.** Route request bodies and response payloads
> to an **ICAP (RFC 3507)** antivirus server (ClamAV or commercial
> scanners) for malware / exploit checks.

## Purpose

Block known-bad file uploads before they reach the backend, and block
malicious downloads before they reach the client — without embedding
a scanner in the WAF process.

## ICAP mode

- **REQMOD** — inbound request body scan
- **RESPMOD** — outbound response body scan

The WAF acts as an ICAP client. A scanner (ClamAV, Symantec, Trend,
Sophos) listens on an ICAP port and returns either:

- `204 No Content` — clean, forward
- `200 OK` with modified body — cleaned, forward the cleaned form
- `403 Forbidden` — block, audit as `content_block`

## Eligibility

Only routes that explicitly opt in get scanned, because ICAP adds
latency. Typical targets: `/upload`, `/import`, download routes
serving user-supplied content.

```yaml
routes:
  - id: upload
    path: /v1/upload
    match: prefix
    upstream_ref: upload_pool
    content_scan:
      reqmod: clamav
      timeout_ms: 500
      max_bytes: 50Mi
      on_timeout: fail_close
      on_error: fail_close

  - id: downloads
    path: /files/
    match: prefix
    upstream_ref: files_pool
    content_scan:
      respmod: clamav
      timeout_ms: 1000
      max_bytes: 200Mi
```

## Failure modes

- **fail_close** — block on timeout/error (default for CRITICAL routes)
- **fail_open** — forward on timeout/error (default for CATCH-ALL)
- **cache_clean** — only clean hashes bypass the scanner for TTL window

## Hash cache

The first N bytes of the payload are hashed; if the hash is in the
clean cache (TTL default 1h), skip the scan. This cuts latency for
repeated legitimate downloads.

## Response rewrite

When the ICAP server returns cleaned bytes (e.g., stripped macro from
a document), the WAF forwards the cleaned form and audit-logs the
cleanup with the scanner's verdict.

## Backpressure

ICAP calls are awaited on a per-route connection pool to the scanner.
Pool exhaustion applies the route's failure mode. Metrics:

- `waf_icap_requests_total{scanner,verdict}`
- `waf_icap_duration_seconds_bucket{scanner}`
- `waf_icap_errors_total{scanner,reason}`

## Configuration

```yaml
content_scanning:
  scanners:
    clamav:
      endpoint: "icap://clamav.internal:1344"
      service: "srv_clamav"
      pool_size: 32
      tls: false
    trend:
      endpoint: "icaps://trend.internal:11344"
      service: "avscan"
      pool_size: 16
      tls: true
      ca_bundle: "/etc/waf/certs/trend-ca.pem"
  clean_cache:
    ttl_s: 3600
    max_entries: 100000
```

## Implementation

- `src/scan/icap.rs` — ICAP client (REQMOD + RESPMOD)
- `src/scan/pool.rs` — connection pool per scanner
- `src/scan/cache.rs` — clean-hash cache
- `src/scan/gate.rs` — per-route gate + failure mode

## Performance notes

- ICAP connections are kept alive and pooled
- Only payloads under `max_bytes` are sent; oversized payloads are
  rejected outright (`413`)
- Hash cache is `moka`-backed, TTL-evicted
- Latency is **always** charged to the request budget — CRITICAL
  routes should generally not use RESPMOD
