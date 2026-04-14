# Session Affinity (v2, new)

> **New in v2.** Sticky routing via cookie injection or consistent-hash
> over a chosen request attribute.

## Purpose

Route repeat requests from the same client to the same upstream member
so that local backend state (per-session cache, WebSocket, stateful
game session) stays valid. Must survive member churn gracefully.

## Modes

### Consistent-hash

Uses the pool's `consistent_hash` LB strategy with a configurable key:

```yaml
upstreams:
  game_pool:
    lb: consistent_hash
    hash_key:
      source: cookie       # header | cookie | query | client_ip | jwt_claim
      name:   "game_id"
    ring_replicas: 160     # virtual nodes per member
    fallback_on_miss: round_robin
```

Member churn reshuffles at most `1/N` of keys (standard consistent-hash
property). Suitable when the backend can tolerate occasional session
migration.

### Cookie injection

The WAF mints a `waf_aff=<member_id>` cookie on first response; on
subsequent requests it routes to that member if it exists and is
healthy, else falls through to the pool's primary LB.

```yaml
upstreams:
  app_pool:
    lb: round_robin
    affinity:
      cookie:
        name: waf_aff
        ttl_s: 3600
        path: "/"
        secure: true
        http_only: true
        same_site: lax
        hmac_secret: "${secret:vault:kv/data/waf#aff_key}"
```

`member_id` is HMAC-signed so clients can't pin themselves to a member
they shouldn't reach.

## Failure handling

- Pinned member ejected → fall through to the LB strategy
- Pinned member draining → route elsewhere; cookie re-issued
- Signature mismatch → treat as no cookie present

## Interaction with rate limiting

Session affinity is independent of the rate limiter's identity —
limits still scope on IP/session/device as configured.

## Configuration (summary)

Defined on the pool, consumed transparently by routing. No route-level
config needed beyond pointing at the pool.

## Implementation

- `src/upstream/affinity/cookie.rs` — mint + verify + lookup
- `src/upstream/affinity/consistent_hash.rs` — ring + key extraction
- `src/upstream/affinity/hmac.rs` — shared signer

## Performance notes

- Cookie path: HMAC verify is one SHA-256 over ~16 bytes
- Consistent-hash: binary search on the ring (log n); rings are rebuilt
  off-hot-path whenever the member set changes
