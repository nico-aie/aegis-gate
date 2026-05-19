# Smart Caching — future plan

> **Status (2026-05-19): Designed, not started.** The
> `X-WAF-Cache` response header already exists (always `BYPASS`
> today) and the contract reserves the wire slot. This plan
> captures the operator-facing UX, key derivation, eviction
> policy, and integration points so the build phase is mechanical.

## Why

1. **Contract slot already paid for.** Every response stamps
   `X-WAF-Cache: BYPASS|HIT|MISS`. Today it's BYPASS unconditional
   — the operator has paid the per-request stamp cost but gets no
   value from it.
2. **Real upstream relief.** Sustained 4–6 kRPS benchmarks on
   `prod-balanced` spend the bulk of their time in the upstream
   round-trip; even a 30% HIT ratio on common public-asset paths
   (`/`, `/favicon.ico`, `/static/*`, common OpenAPI GETs) frees
   meaningful headroom for security work.
3. **Dashboard already has the surface.** `X-WAF-Cache` is
   surfaced in Live Feed + Audit Trail + per-route latency
   histograms; flipping a cache on instantly lights up the UI.

## Why deferred

- The hackathon scoring rubric does not measure cache hit rate
  directly; performance-axis points come from sustained RPS +
  p99 latency, not from cache hits in isolation. Shipping
  detector recall + composite-key risk has higher marginal score
  per LoC.
- A buggy cache is worse than no cache (stale auth, leaked
  per-user content). The minimum-viable shape needs careful
  surrogate-key design + a deny list — both worth a focused
  sprint rather than a side-quest.
- The current `X-WAF-Cache` stamping path is correct; turning it
  on later is purely additive.

## Code anchor

- `crates/aegis-control/src/interop/headers.rs` — `CacheState::{Hit,Miss,Bypass}` enum + `Decision::stamp()` writes `X-WAF-Cache`.
- `crates/aegis-proxy/src/data_plane.rs` — `Decision::allow()` defaults `CacheState::Bypass`; this is where a cache lookup would intercept.
- `crates/aegis-proxy/src/proxy/` — upstream forwarder; cache writes happen on the response path here.
- `crates/aegis-control/src/api/` — would need a `GET /api/cache/stats` for the dashboard.

## Future plan

### Phase 1 — In-memory LRU, GET-only, allow-list

**Scope:** route-scoped GET cache for explicitly allow-listed
path prefixes. Coarse `(method, host, path, query)` key. TTL
from config, ignore upstream `Cache-Control`. No vary-by.
Bounded by a per-pool entry count + total byte budget.

**Config shape (`cfg.cache`):**
```yaml
cache:
  enabled: true
  backend: in_memory          # only option in Phase 1
  max_entries: 4096
  max_total_bytes: 67_108_864 # 64 MiB
  default_ttl: "30s"
  routes:
    - prefix: "/static/"
      ttl: "5m"
    - prefix: "/favicon.ico"
      ttl: "24h"
    - prefix: "/"
      methods: [GET]
      ttl: "10s"
      deny_query_keys: ["token", "session", "auth"]
```

**Code shape:**
- New crate-internal `cache::` module under `aegis-proxy`:
  `CacheKey`, `CacheEntry { body, headers, status, expires_at }`,
  `LruCache` (single `parking_lot::Mutex<lru::LruCache<...>>` is
  enough for the first cut).
- Hook point in `handle_data_request` after the security gate
  passes: if the request is allow-listed, probe cache. HIT →
  return cached `Response<Full<Bytes>>` + stamp `X-WAF-Cache: HIT`
  via `Decision::allow().with_cache(CacheState::Hit)`. MISS →
  proceed to upstream, then on a 200 OK with cacheable headers
  + body ≤ `max_entry_bytes`, store and stamp `MISS`.

**Defaults:** off. Operator opts in per-route.

**Acceptance:**
- `X-WAF-Cache: HIT` appears on the second of two identical
  benign GET `/favicon.ico` requests.
- HIT response carries the cached upstream body bit-for-bit
  except for the WAF observability headers (re-stamped per
  request).
- `GET /api/cache/stats` returns
  `{entries, bytes, hit_count, miss_count, hit_ratio}` — wired
  into the Performance page card.
- Audit log includes a `cache_decision` field on cached
  responses (operator can grep).

### Phase 2 — Surrogate keys + invalidation

- Config: `vary_by: [host, accept-encoding]` so the cache keys
  on negotiated encoding (avoids serving gzip to a non-gzip
  client). One synthetic entry per `Vary` combination.
- Admin endpoint `POST /__waf_control/flush_cache` already
  exists — wire it to actually drop entries instead of the
  current `supported: false` no-op. Optional body
  `{prefix: "/static/"}` for surgical purges.
- Dashboard: per-route HIT ratio sparkline on Routing &
  Upstreams.

### Phase 3 — Distributed (Redis-backed)

- Backend swap: `cfg.cache.backend: redis`. Same `cache::` trait
  with a Redis impl behind `state.redis.urls`.
- TTL → Redis EX; LRU eviction → Redis allkeys-lru.
- Bytes counter via `INCRBY` on writes / decrements on evictions
  (best-effort).
- Per-pool key prefix so multiple WAFs sharing a Redis don't
  collide. Useful for the multi-node deploy path that's already
  in `archive/multi-node-deployment/`.

### Phase 4 — Bypass intelligence

- Auto-bypass when:
  - Response carries `Set-Cookie` (per-user content).
  - `Authorization` header present on the request.
  - Upstream sets `Cache-Control: no-store` (configurable to
    honour or ignore).
- Stamp `X-WAF-Cache: BYPASS` with a `Vary`-aware reason
  surfaced in audit (`cache_bypass_reason: "set_cookie" | ...`).

## Restoration checklist

When this plan is picked up:

1. **Spec the allow-list semantics.** Confirm operators want
   per-prefix `methods: [GET]` opt-in vs. blanket GET-all. The
   safer default is opt-in.
2. **Confirm benchmark target.** If the OC is measuring p99
   latency on a public-asset path, ship Phase 1 with `/static/*`
   + `/favicon.ico` defaults so the hit ratio shows up without
   operator config.
3. **Audit the cache key for PII.** A `query` key segment can
   leak — Phase 1 strips `token` / `session` / `auth` by default
   per `deny_query_keys`. Verify against the openapi.public.yaml
   surface before turning on by default.
4. **Wire `flush_cache` to do work.** Today
   `POST /__waf_control/flush_cache` returns `supported: false`.
   The contract treats it as graceful — but once a cache ships,
   the same endpoint must actually evict.
5. **Update `Implement-Progress.md` + dashboard help.** The
   `X-WAF-Cache` glossary entry currently says "always BYPASS
   until smart cache lands". Flip the line.

## Effort estimate

| Phase | Est. LoC | Est. days |
|---|---|---|
| 1 — in-memory LRU + GET allow-list | ~600 | 3 |
| 2 — surrogate keys + flush_cache wiring | ~250 | 1.5 |
| 3 — Redis backend | ~400 | 2 |
| 4 — bypass intelligence + audit reasons | ~200 | 1 |
| Tests + dashboard wiring | ~400 | 2 |
| **Total** | **~1850** | **~10 days** |

## Related work / cross-references

- `archive/multi-node-deployment/` — shared cache in Redis
  becomes load-bearing once the WAF runs > 1 node.
- `future/audit-cold-tier-export.md` — once cache stats land,
  the cold-tier export can include hit ratio for SLO reports.
- `archive/interop-contract.md` — `X-WAF-Cache` wire-shape was
  finalised here; do not change the enum.

## Out of scope

- HTTP/3 push cache.
- Conditional revalidation (`If-None-Match` / ETag).
- Edge cache (we are the edge; revisiting requires a tier
  between us and the upstream).
- Cache poisoning protection beyond the deny-list — relying on
  upstream-controlled `Vary` headers is a Phase 5 conversation.
