# Smart Caching

## Purpose

Reduce backend load and tail latency by serving repeated requests from an in-process cache. The cache is **tier-aware**: different routes get different caching policies that balance freshness, safety, and throughput.

## Backend

Built on `moka::future::Cache`, an async in-memory cache with TTL and size-based eviction.

- **Lock-free reads:** moka uses sharded internal structures
- **Bounded memory:** configurable max entries / max bytes
- **TTL + TTI:** time-to-live and time-to-idle
- **Async-friendly:** never blocks the tokio runtime

## Per-tier policies

| Tier | TTL | Vary by | Methods | Notes |
|---|---|---|---|---|
| **CRITICAL** | disabled | — | — | Never cache — content is dynamic and user-specific |
| **HIGH** | 30s | session | GET | Short TTL, session-scoped |
| **MEDIUM** | 300s | — | GET, HEAD | Aggressive — static assets |
| **CATCH-ALL** | 60s | — | GET | Conservative baseline |

## Cache key

```
(method, path, vary_headers_hash)
```

`vary_headers_hash` is a hash of the headers listed in the tier's `vary_by` config — typically `session`, `accept-encoding`, and `user-agent` buckets.

For aggressive caching (MEDIUM tier), query parameters can be ignored via `ignore_query: true` to collapse cache entries for static assets that use cache-busting query strings.

## Cache bypass rules

A response is **not cached** if any of these are true:

- The request method is not in the tier's allowed list
- The response status is not 200, 301, or 304
- The response has `Cache-Control: no-store` or `private`
- The response has `Set-Cookie` headers
- The request triggered any detection or block (see [attack detection](./detection-sqli.md))
- The route is in CRITICAL tier

## Configuration

```yaml
tiers:
  - name: high
    cache:
      ttl_s: 30
      vary_by: [session]
      methods: [GET]
      max_body_bytes: 1048576

  - name: medium
    cache:
      ttl_s: 300
      aggressive: true         # ignore query strings
      methods: [GET, HEAD]
      max_body_bytes: 10485760

cache:
  max_entries: 100000
  max_memory_mb: 512
```

## Cache invalidation

- **TTL expiry:** handled automatically by moka
- **Hot-reload:** clearing the cache on config reload is **opt-in** via `cache.clear_on_reload: true`
- **API:** `DELETE /api/cache` on the dashboard flushes the cache
- **Pattern-based:** `DELETE /api/cache?path=/api/user/*` invalidates matching entries

## Integration with request pipeline

The cache lookup runs **early** in the pipeline (after IP reputation and tier classification, before attack detection). On a hit:

1. Serve the cached response directly
2. Skip backend forwarding and response filtering (the cached response was already filtered)
3. Still emit an audit log and update metrics
4. Skip most detection stages (the hit means we've already vetted this request pattern)

This makes cached requests nearly free: `O(1)` lookup, microsecond latency.

## Implementation

- `src/cache/smart_cache.rs` — moka wrapper, per-tier policy lookup, key generation

## Design notes

- The cache is an **in-process** cache per WAF instance — no Redis or memcached required
- For multi-node deployments, each node has its own cache; this is a deliberate trade-off for simplicity and latency over a perfect hit rate
- Response bodies larger than `max_body_bytes` are passed through uncached
- The cache stores the **post-filter** response, so sensitive data redaction runs once per entry, not once per hit
