# Rate Limiting (v2)

> **Status:** Implemented — `rate_limit/{bucket,sliding,ip_limiter,mod}.rs`.
>
> See [`../../plans/plan.md`](../../plans/plan.md#1-doc-by-doc-implementation-status) for the full matrix.

> **2026-05-18 Phase E (F-CRITICAL-002):** the per-IP volumetric
> guard's storage upgraded from `DashMap<IpAddr, …>` to
> `DashMap<RiskKey, …>` (composite of IP + device_fp + session).
> The IP-only API (`consume(ip)`, `reset(ip)`) keeps working by
> internally constructing `RiskKey::from_ip(ip)`. New
> `consume_with_key` / `consume_at_with_key` / `reset_with_key`
> methods take the full composite — two sessions on the same NAT'd
> IP get independent rate-limit buckets. Mirrors the `RiskTracker`
> migration in commit 01c053c.
>
> **2026-05-19:** `tenant_id` axis removed from `RiskKey` (the
> multi-tenant feature was deprecated upstream). The composite key
> is now exactly `{ip, device_fp, session}`.
>
> **2026-05-19 (data-plane completion):** the per-IP volumetric
> guard call site in `data_plane.rs` switched from
> `consume(peer_ip)` to `consume_with_key(build_risk_key(...))`,
> so two TLS sessions on the same NAT'd IP with different JA4 /
> User-Agent / session-cookie shapes now get **independent**
> token buckets in production. The legacy `consume(ip)` API
> stays alive for IP-only callers (operator-driven resets etc.)
> and the IP-only bucket becomes the floor for anonymous /
> plain-HTTP traffic where the composite axes are `None`.

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

### Division of labor — which gate throttles a single-IP flood (LT-P3)

The two per-IP gates are evaluated in this order on the data-plane hot path
(the ddos gate sits between strike-block and the rate limiter — see the
comment at `data_plane.rs` "DDoS ... sits between the strike-block gate and the
per-IP rate-limit token bucket"):

```
blacklist → strike-block → ddos gate → per-IP rate limiter → detectors
```

They are deliberately tuned for **different jobs**:

| Gate | Code | Default | Role |
|---|---|---|---|
| **DDoS per-IP flood** | `src/ddos.rs` (`DdosDetector`) | **1000 req / 10 s** per `(tier, ip)` (~100 rps/IP), enabled by default | The **effective single-source volumetric defense**. Fires first under a flood; breach → local auto-block for `block_ttl_s` (default 300 s). |
| **Per-IP rate limiter** | `src/rate_limit/ip_limiter.rs` (`IpRateLimiter`) | **1_000_000 req / 60 s** per composite key | A deliberately **loose backstop** + the hook for an operator-set strict per-IP cap (`PUT /api/rate-limit` / the `global-ip` bucket). Not the volumetric gate. |

So under a single-IP L7 flood the **ddos gate fires ~167× sooner** than the
rate-limiter backstop (pinned by the `ddos_gate_fires_far_sooner_than_ip_limiter_backstop`
test in `ddos.rs`).

**Why the rate-limiter default is left loose:** at a tight default it would
throttle legitimate high-RPS traffic arriving from a *small set* of source IPs
(a CDN/NAT front, or the benchmark's own load generator), producing false 429s —
without adding any volumetric coverage `ddos.rs` doesn't already provide. Set a
strict per-IP cap explicitly only when you know the client-IP cardinality is high.

**L3/L4 packet floods** (SYN/UDP volumetric) are out of scope for both L7 gates —
they belong to the kernel / load balancer / anycast tier upstream of the WAF
(see the L4 posture note, AC-P3-d). These gates defend the L7 request path only.

**Runbook — confirm which gate fired:** a single-source flood that stops at
`~1000 requests / 10 s` with `403` + audit `rule_id: ddos` (not `429`) is the
ddos gate doing its job. A `429` with `X-WAF-Rule-Id` from the rate limiter means
an operator-configured strict bucket fired, not the default backstop (the default
1M/60s effectively never trips first).

## Implementation

- `src/rate_limit/sliding_window.rs` — in-memory backend
- `src/rate_limit/token_bucket.rs` — governor wrapper
- `src/rate_limit/redis_backend.rs` — Lua + deadpool-redis
- `src/rate_limit/store.rs` — `RateLimitStore` dispatches per backend + tier

## Performance notes

- In-memory: sharded `DashMap`, lock-free hot path
- Redis: connection pool via `deadpool-redis`, pipelined Lua EVALSHA, p99 ≤ 1 ms
- Ahash keys; no per-request allocations for the key string (pre-formatted into a `SmallString`)
