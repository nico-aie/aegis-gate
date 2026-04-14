# Per-Route Quotas & Buffering (v2, new)

> **New in v2.** Body size, header size, and I/O timeout limits are
> now declarative **per route**, with tier defaults and tenant overrides.

## Purpose

Prevent resource exhaustion from oversized or slow requests, and apply
targeted limits to routes that carry large uploads vs chat endpoints
vs static assets — without a one-size-fits-all global cap.

## Quotas

| Quota | Default | Notes |
|---|---|---|
| `client_max_body_size` | 1 MiB | Overridable for upload routes |
| `client_max_header_bytes` | 64 KiB | hyper-level cap |
| `max_uri_length` | 8 KiB | Rejects abusive URIs |
| `read_timeout_ms` | 30 000 | Body read (slowloris guard) |
| `write_timeout_ms` | 30 000 | Response write |
| `upstream_connect_ms` | 2 000 | See graceful-degradation |
| `upstream_request_ms` | 10 000 | Backend SLA bound |
| `max_request_duration_ms` | 30 000 | Absolute ceiling |
| `buffer_request_body` | true | False = stream to upstream |
| `buffer_response_body` | true | False = stream to client |

## Tier defaults

| Tier | body | read_to | upstream_req |
|---|---|---|---|
| CRITICAL | 256 KiB | 10 s | 5 s |
| HIGH | 1 MiB | 30 s | 10 s |
| MEDIUM | 10 MiB | 60 s | 30 s |
| CATCH-ALL | 1 MiB | 30 s | 10 s |

Per-route overrides take precedence. Per-tenant overrides come next.

## Buffering vs streaming

Buffered bodies run the security pipeline on the full payload before
any byte is forwarded upstream. Streaming forwards incrementally but
disables body-dependent detectors (SQLi in body, DLP inbound).

A route can opt into streaming for large uploads:

```yaml
routes:
  - id: upload
    path: /v1/upload
    quotas:
      client_max_body_size: 500Mi
      buffer_request_body: false
      read_timeout_ms: 600000
```

Streaming uploads still get:

- Rate limiting
- IP reputation
- Header + method filters
- Rule-engine header conditions
- Outbound response filtering

## Exceeded quota responses

- Body too large → `413 Payload Too Large`
- Header too big → `431 Request Header Fields Too Large`
- Read timeout → `408 Request Timeout`
- Upstream timeout → `504 Gateway Timeout`
- Duration ceiling → `503 Service Unavailable`

Each emits an audit event with the specific quota name.

## Configuration

```yaml
quota_defaults:
  tier:
    critical: { client_max_body_size: 256Ki, upstream_request_ms: 5000 }
    high:     { client_max_body_size: 1Mi,   upstream_request_ms: 10000 }
    medium:   { client_max_body_size: 10Mi,  upstream_request_ms: 30000 }
    catchall: { client_max_body_size: 1Mi }

routes:
  - id: api_upload
    path: /v1/upload
    quotas:
      client_max_body_size: 500Mi
      buffer_request_body: false
```

## Implementation

- `src/quota/schema.rs` — size parsing (`1Mi`, `500Mi`, `1Gi`)
- `src/quota/enforce.rs` — limit middleware
- `src/quota/resolve.rs` — tier → tenant → route merge

## Performance notes

- Enforcement is a single comparison per request; zero allocation
- Streaming mode avoids buffering cost for large uploads
- Header caps are enforced at hyper's parser level — oversized requests
  are rejected before the pipeline allocates
