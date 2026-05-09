# Rate Limiting (v2)

> **Status:** Implemented — `rate_limit/{bucket,sliding,ip_limiter,mod}.rs`.
>
> See [`../../plans/plan.md`](../../plans/plan.md#1-doc-by-doc-implementation-status) for the full matrix.

> **Two limiter surfaces, two contracts** (clarified after
> the 2026-04-29 cluster smoke surfaced the distinction):
>
> - **Per-IP volumetric guard** —
>   `rate_limit::ip_limiter::IpRateLimiter` is the very-first
>   thing the hot path calls in `handle_data_request`. It's a
>   **per-node** sliding-window log keyed on `peer.ip()` with a
>   local `DashMap`. It does **not** share state across
>   cluster nodes — by design, because under DDoS each node
>   should drop a flooding source independently rather than
>   hop the cluster for every counter read. With N nodes
>   and a budget B, the cluster admits up to N × B
>   per-IP-per-window in the worst case; that's the contract.
> - **Named-bucket limiter** —
>   `rate_limit::sliding::check` is what `rate_limit.buckets[*]`
>   blocks in YAML wire to. It takes a `&dyn StateBackend`,
>   so when the cluster runs on Redis
>   (`state.backend: redis`) every node reads + writes
>   through the **shared** Redis primary — one counter per
>   `(key, bucket)` for the whole fleet. This is the
>   "clusterable" surface the v1 → v2 redesign promised.
>
> The two are distinct on purpose. If you want strictly
> clustered per-IP enforcement, declare a route-level bucket
> with `key: ip` and let the named-bucket limiter gate it;
> the volumetric guard then acts as a fast local DDoS shield
> in front of it.

## Purpose

Prevent clients from hitting any endpoint too frequently. First line of
defense against brute force, credential stuffing, scraping, and resource-
exhaustion attacks.

## Algorithms

Selected per tier (or per route) in config.

### Sliding window (default)

Tracks request timestamps per key; allowed if count in the last N seconds is
under the limit.

- **Accurate**, never permits burst above limit
- **Memory**: O(requests_in_window) per key
- **Use case**: CRITICAL and HIGH tiers

### Token bucket

Fixed-rate refill, O(1) memory, allows short bursts.

- **Use case**: MEDIUM tier (static assets)

## Scoping

Limits can be keyed by any combination:

- `ip` — post-XFF true client
- `session` — session cookie
- `device` — fingerprint hash
- `user` — authenticated user id
- `api_key` — consumer API key (v2, see [`api-security.md`](./api-security.md))

Multiple scopes are ANDed: a request must pass **all** configured limits.

Key format: `{tier}:{scope}:{identifier_hash}`.

## Storage backends

v2 introduces a `StateBackend` abstraction. A single config line chooses
the backend; the algorithm and key layout are identical across backends.

| Backend | Use case | Latency | Consistency |
|---------|----------|---------|-------------|
| `in_memory` | Single-node dev | ~µs | Strong (local only) |
| `redis`     | Clustered prod  | ~sub-ms LAN | max-of-replicas on reconcile |
| `raft`      | Air-gapped      | low ms | Strong, linearizable (bonus) |

Redis implementation uses Lua for atomic sliding-window ops:

```lua
-- sliding_window.lua: evict expired, count, optionally add
local key, window, now, limit = KEYS[1], tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local count = redis.call('ZCARD', key)
if count >= limit then return 0 end
redis.call('ZADD', key, now, now..':'..ARGV[4])
redis.call('PEXPIRE', key, window)
return 1
```

## Configuration

```yaml
state:
  backend: redis
  redis:
    url: "redis://cluster.internal:6379"
    pool_size: 32

tiers:
  - name: critical
    rate_limit:
      algorithm: sliding_window
      requests: 10
      window_s: 60
      scope: [ip, session, device]

  - name: medium
    rate_limit:
      algorithm: token_bucket
      requests: 500
      window_s: 60
      burst: 100
      scope: [ip]
```

Route-level overrides (`routes[*].policies.rate_limit`) win over tier defaults.

## Behavior on limit exceeded

- Return **HTTP 429**
- `Retry-After` header with seconds until next allowed
- Add `+10` risk to the offender (repeat offenders graduate to challenge/block)
- Emit audit + metric (`waf_rate_limit_rejections_total{tier, scope}`)

## Integration with DDoS

Rate limiting and [`ddos-protection.md`](./ddos-protection.md) share the state
backend but have different thresholds:

- Rate limit: per-tier policy (e.g., 100/min per IP)
- DDoS burst: extreme spikes (e.g., 100/sec per IP) → auto-block

## Implementation

- `src/rate_limit/sliding_window.rs` — in-memory backend
- `src/rate_limit/token_bucket.rs` — governor wrapper
- `src/rate_limit/redis_backend.rs` — Lua + deadpool-redis
- `src/rate_limit/store.rs` — `RateLimitStore` dispatches per backend + tier

## Performance notes

- In-memory: sharded `DashMap`, lock-free hot path
- Redis: connection pool via `deadpool-redis`, pipelined Lua EVALSHA, p99 ≤ 1 ms
- Ahash keys; no per-request allocations for the key string (pre-formatted into a `SmallString`)
