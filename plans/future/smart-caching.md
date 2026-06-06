# Smart Caching — per-upstream response cache (future plan)

> **Status (2026-06-06): Researched + designed, not started.** Supersedes
> the per-tier design in
> [`../archive/smart-caching.md`](../archive/smart-caching.md) (kept for the
> still-valid pieces: the `X-WAF-Cache` wire slot, eviction sketch, phasing).
> This revision changes the **configuration axis** from *risk tier* to
> *per-upstream + path*, and makes "never cache CRITICAL" a hard,
> non-configurable invariant.

## Goal

Let an operator declare, **per upstream**, which paths are cacheable
(`/static/*`, `/assets/*`, `/favicon.ico`, …). On a repeat of an identical,
safe request the WAF serves the stored response and skips the upstream
round-trip — freeing backend + WAF headroom for security work. **CRITICAL-tier
requests are never cached, regardless of config.**

This is intentionally a *reverse-proxy response cache* (we are the edge), not a
browser cache and not a CDN tier in front of us.

---

## 1. How the world does it (2025–2026 scan)

| Product | Config axis | Cacheability decision | Notable safety defaults |
|---|---|---|---|
| **Cloudflare Cache Rules** | Per-zone **rules matched by URL/expression** (path, extension, host) | "Cache eligibility: Eligible / Bypass" per rule; customizable cache key (query/header/cookie); **Bypass Cache on Cookie** | **Cache Deception Armor** — only cache when response `Content-Type` matches the URL extension |
| **AWS CloudFront** | **Cache behaviors per path pattern** (most-specific first), one per origin | Cache *policy* defines the key (headers/cookies/query); honors origin `Cache-Control` | Path-pattern behaviors → different origins/paths get different policies |
| **nginx `proxy_cache`** | Per **`location`** (path) block | `proxy_cache_valid` per status/TTL; key `$scheme$proxy_host$request_uri` | **Does NOT cache responses with `Set-Cookie` by default**; `proxy_no_cache`/`proxy_cache_bypass` on session cookies |
| **Fastly / Varnish** | VCL per service; **surrogate keys** for tag-based purge | `beresp` TTL, `Surrogate-Control`; recv/fetch/deliver states | **grace / stale-while-revalidate / stale-if-error** — serve stale while/​after revalidating |
| **RFC 9111** (the spec) | n/a — per-response | `Cache-Control` (`no-store`/`private`/`no-cache`/`max-age`/`s-maxage`), `Vary`, conditional revalidation (ETag / Last-Modified) | `private`/`no-store` ⇒ a shared cache must not store |

**Cross-product consensus — the safe baseline every serious cache shares:**

1. **Explicit, path-scoped opt-in per origin.** Nobody safe caches "everything"
   blindly — CloudFront *behaviors* and Cloudflare *rules* are matched by path
   pattern; nginx by `location`. Per-origin/path is the universal axis.
2. **GET/HEAD only.**
3. **Never cache authenticated / per-user content.** Request `Authorization`
   present, or response `Set-Cookie` → bypass (nginx makes this the *default*).
4. **Honor origin intent.** `Cache-Control: no-store / private / no-cache` ⇒
   don't store (overridable only for known-static asset rules).
5. **A normalized, fully-specified cache key.** Key on every user-controllable
   input that changes the response; normalize case/encoding/path; key on `Vary`
   (at least `Accept-Encoding`). Under-keying = cache poisoning; over-trusting
   path suffix = cache deception.
6. **Resilience: serve stale on error** (`stale-if-error` / Varnish grace).
7. **Targeted purge** (surrogate keys / prefix / by-origin), not just full flush.

### Why a WAF's cache must be *more* defensive than a CDN's

We're a security product, so two attack classes are first-class design inputs,
not afterthoughts ([PortSwigger Web Security Academy], [F5 DevCentral]):

- **Web cache *deception*** — attacker lures the cache into storing a victim's
  private page by dressing a dynamic URL as static
  (`/account/profile.css`, `/api/me/foo.jpg`). Mitigation: **Cache Deception
  Armor** — only store when the response `Content-Type` matches the rule's
  expected static type, *and* prefer explicit static-prefix allow-lists over
  suffix matching. Never cache a response carrying `Set-Cookie`.
- **Web cache *poisoning*** — attacker gets a malicious response stored under a
  victim's key via **unkeyed inputs** (e.g. `X-Forwarded-Host`, weird
  `Accept-Encoding`). Mitigation: **normalize the key**, key only on a vetted
  input set, and refuse to cache responses whose `Vary` lists a header we don't
  key on.

> A buggy WAF cache is worse than no cache: it can *leak* private data
> (deception) or *serve attacker content to every user* (poisoning). The design
> below defaults to closed and opts in narrowly.

---

## 2. The decision: per-tier vs per-upstream

**Recommendation — configure caching *per-upstream + path*, and use *tier* as a
hard guardrail, not the configuration axis.**

### Why not per-tier as the config axis

`Tier` (Critical/High/Medium/Low) is a **security/risk** classification — "how
sensitive/dangerous is this route" — *not* a **cacheability** classification.
They don't line up:

- A `Medium` route can still serve per-user dynamic JSON (must not cache); a
  `Low` route can serve static assets (great to cache). Tier doesn't tell you.
- Cacheability is a property of the **resource/path on a specific backend**
  (`/static/*` on the assets pool), which is exactly what every product above
  keys on. Tier is too coarse and the wrong dimension.
- Operators reason about caching as "this service / these paths are static",
  not "this is medium-risk."

### Why per-upstream + path fits us specifically

- Our data model already supports it cleanly: a request resolves
  route → `upstream` name → `PoolConfig` (config.rs `upstreams: HashMap<String,
  PoolConfig>`), and `PoolConfig` *already* nests per-upstream sub-configs
  (`health`, `circuit_breaker`, `connection`). A `cache:` block slots in with
  zero new top-level plumbing.
- It matches the mental model + the industry (CloudFront behaviors, Cloudflare
  rules, nginx locations): **per backend, per path.**
- Different backends genuinely have different cacheability — an assets pool vs.
  an API pool — and per-upstream config expresses that directly.

### Where tier still earns its keep — as a guardrail

Tier is **already on `route_ctx.tier` at the forward point**
(`forward_allow_to_upstream`, data_plane.rs ~1457), so layering it as a safety
gate is free and load-bearing:

1. **Hard invariant: `Tier::Critical` is never cached** — non-configurable.
   Even if an operator allow-lists a path that resolves to a Critical route,
   the cache refuses (defense-in-depth; Critical is `FailClose` everywhere
   else too).
2. **Optional TTL ceilings by tier** (nice-to-have, Phase 2+): `High` caps the
   effective TTL low (e.g. ≤ 30 s) even if a rule asks for more; `Medium`/`Low`
   take the rule's TTL. This keeps a misconfigured aggressive rule from
   over-caching a sensitive-ish route without blocking it outright.

**Net:** per-upstream/path is the *operator surface*; tier is the *security
clamp*. Best of both — operators configure where it's meaningful, the security
model enforces the invariants.

---

## 3. Proposed design

### 3.1 Config (per-upstream `cache:` block)

```yaml
upstreams:
  assets-pool:
    members: [ ... ]
    cache:                      # NEW — absent ⇒ caching off for this pool
      enabled: true
      max_entries: 4096
      max_total_bytes: 67108864   # 64 MiB budget for THIS pool
      default_ttl: "60s"
      respect_origin_cache_control: true   # honor no-store/private/max-age
      rules:
        - prefix: "/static/"
          ttl: "5m"
          content_types: ["text/css", "application/javascript", "image/*"]  # deception armor
        - prefix: "/assets/"
          ttl: "1h"
        - prefix: "/favicon.ico"
          ttl: "24h"
      # safety knobs (all default to the safe value)
      methods: [GET, HEAD]
      deny_query_keys: ["token", "session", "auth", "sig"]
      vary_by: ["accept-encoding"]
      bypass_on_cookie: true       # request Cookie / response Set-Cookie ⇒ bypass
      bypass_on_authorization: true
      stale_if_error: "30s"        # serve stale when upstream is down (pairs with circuit breaker)
```

- **Opt-in, allow-list, per pool.** No rule match ⇒ `BYPASS`. Mirrors
  CloudFront behaviors / nginx locations.
- `content_types` per rule = our **Cache Deception Armor**: store only if the
  upstream response type matches.

### 3.2 The decision pipeline (order matters — fail closed)

At `forward_allow_to_upstream`, *before* dialing upstream:

```
1.  tier == Critical?                         → BYPASS (hard, non-configurable)
2.  method ∉ {GET, HEAD}?                      → BYPASS
3.  pool has no cache / no rule matches path?  → BYPASS
4.  request has Authorization / Cookie (and bypass_on_* )? → BYPASS
5.  cache key = normalize(method, host, path, kept-query, vary headers)
6.  HIT and fresh?     → serve stored body+headers, stamp X-WAF-Cache: HIT
7.  HIT but stale?     → stale-if-error window? revalidate (ETag/If-None-Match);
                          serve stale on upstream error
8.  MISS → forward upstream, then store IFF:
      • status cacheable (200/203/300/301/404/410 — start with 200 only)
      • no Set-Cookie
      • Cache-Control not no-store/private (unless rule overrides)
      • Content-Type matches rule.content_types (deception armor)
      • body ≤ per-entry cap
    → stamp X-WAF-Cache: MISS
```

The WAF's own observability headers (`X-WAF-*`) are **re-stamped per request**,
never served from the cached copy.

### 3.3 Cache key + normalization (anti-poisoning)

`key = sha256( lower(method) ⏐ lower(host) ⏐ normalize_path(path) ⏐
sorted(kept_query) ⏐ vary_values )`

- `normalize_path`: percent-decode once, collapse `//`, resolve `.`/`..`,
  lowercase only if the pool opts in. Reject ambiguous/over-encoded paths
  (don't cache — they're a deception signal).
- `kept_query`: drop `deny_query_keys`; optionally `ignore_query` for pure
  static rules.
- `vary_values`: only headers in `vary_by`. If the **response** `Vary` lists a
  header not in `vary_by` ⇒ **don't store** (we'd be under-keyed → poisonable).

### 3.4 Backends & multi-node topology

**Tiered, behind one `CacheBackend` trait** (`get` / `put` / `invalidate`) so the
deployment picks the layer without touching call sites.

**L1 — in-process per node (Phase 1, the default).** `moka::future::Cache`
(async, sharded, byte-weighted eviction). Microsecond lookups, zero-copy
`Bytes` serving, **no network on the hot path** — preserves the WAF's
sub-millisecond decision latency. Each node warms its own cache independently:

- Behind the LB (DNS-RR / HAProxy) a hot path is fetched once *per node* before
  all are warm (**N× cold-fetch**); steady-state hit ratio on hot paths stays
  high.
- Same object is stored on each node (N× fleet memory, each node bounded by its
  own byte budget — safe).
- **Staleness is bounded by TTL.** Fine for the primary use case (immutable,
  versioned static assets); mutable content relies on the purge fan-out below.

**Cross-node invalidation — Redis pub/sub purge fan-out (Phase 1, reuses the
existing cluster Redis).** The one real multi-node gotcha is that a local
`flush_cache` evicts only the node that received it. Fix it *without* putting
Redis on the hot path: publish purges (`{}` / `{upstream}` / `{prefix}`) to a
cluster channel; every node subscribes and evicts its L1. We already run Redis
for the cluster lease + config plane, so this is a few lines — and the cache
itself stays in-memory and fast. → **fleet-wide purge from day one.**

**L2 — shared Redis *behind* L1 (Phase 3, scale-triggered, NOT a replacement).**
The standard CDN shape (local cache + shield / tiered cache): a node misses L1 →
checks L2 (shared) → misses → origin, then populates both. Flip it on when:

- objects are **expensive to regenerate and shared across users** (not just
  static files), so cross-node hit ratio matters;
- N× origin cold-fetch starts hurting upstreams at many nodes;
- you want cache to survive rolling restarts.

Design notes: **a dedicated cache Redis, separate from the control/config
Redis** — cached bodies (100s KB) + eviction churn must not pressure the small
control-plane instance. TTL→`EX`, `maxmemory` + `allkeys-lru` (Redis enforces
the L2 ceiling), per-pool key prefix.

**Redis Cluster (cluster mode) — a deliberate scale-only L2 option.** Worth
deploying once the L2 cache dataset or throughput **outgrows a single Redis**
(tens of GB of cached bodies, or ops beyond one instance / one core). Implications,
designed-for now so it's a *client swap*, not a re-architecture:

- Keys (cache-key hashes) spread across the 16384 hash slots → natural memory +
  throughput **sharding** and per-master failover with replicas. Our `get`/`put`
  are **single-key**, so they're Cluster-safe by construction.
- **Prefix purge is harder in Cluster**: a pool's keys scatter across masters, so
  a `{prefix}` purge must `SCAN`+`DEL` per master (or maintain surrogate-key
  index sets). Simplest and recommended: rely on the **L1 pub/sub fan-out for
  instant invalidation** and let L2 fall back to **TTL** — don't make correctness
  depend on L2 prefix purge.
- **Pub/sub**: keep the purge fan-out on *regular* (non-sharded) pub/sub so every
  WAF node receives it. Redis 7 sharded pub/sub (`SSUBSCRIBE`) is slot-scoped —
  the wrong tool for a fleet broadcast.
- Needs a **cluster-aware client** (`redis::cluster`) that handles MOVED/ASK + the
  slot map. Availability/failover is a *bonus* here, not a requirement — a cache
  miss simply falls through to origin, so the cache is never on the critical
  availability path.
- **Hash-tag caution:** co-locating a pool's keys with a `{pool}` hash-tag makes
  prefix purge easy but defeats sharding (one hot pool → one node). Prefer spread
  keys + pub/sub purge over hash-tag co-location.

**Recommendation:** ship **L1 in-memory + Redis pub/sub purge** now; add **L2
single (dedicated) Redis** when a shared tier is justified; adopt **Redis
Cluster only** when that L2 outgrows one instance. All three are the same
`CacheBackend` trait — a config choice, not a rewrite.

### 3.5 Memory budgeting & size control (must never impact the WAF)

The cache must be *unconditionally bounded* — a cache that OOMs the WAF is a
self-inflicted DoS. Seven independent layers, each bounding on its own:

1. **Capacity is measured in *bytes*, not entry count.** moka's `max_capacity`
   with a **weigher** = `entry.body.len() + headers_len`; eviction keeps
   **total bytes ≤ budget**. Count-only bounding would let large objects blow
   past RAM. `max_entries` stays as a cheap secondary cap.
2. **Per-entry cap — reject big objects.** `max_entry_bytes` (default 1 MiB):
   a larger response is streamed straight through and stamped `BYPASS`, never
   stored. Caps the worst-case single allocation (a multi-GB download can't
   enter).
3. **Per-upstream budget + a global ceiling.** Each pool's `max_total_bytes`
   is its own bound; the sum is capped by top-level `cache.global_max_bytes`.
   One noisy backend can't starve the others or the WAF's working set.
4. **Eviction = TinyLFU + TTL + TTI (this is the under-attack protection).**
   TTL (freshness) + TTI (time-to-idle) drop stale/cold entries automatically.
   moka's **TinyLFU admission is scan-resistant**: a cache-busting flood of
   one-hit-wonder URLs is **rejected at admission** rather than evicting hot
   `/static/*` entries — a naive LRU would let an attacker flush the useful
   cache; TinyLFU won't.
5. **Key-cardinality control.** `deny_query_keys` + optional `ignore_query`
   collapse cache-buster variants (`?v=12345`) into one entry; normalized keys
   prevent duplicates. Without this the key space (and entry count) is
   unbounded.
6. **Zero-copy serving.** The body is `bytes::Bytes` (refcounted) — a HIT is an
   O(1) refcount bump, **no per-request body copy**. Serving from cache adds no
   allocation and *reduces* CPU/latency + upstream load.
7. **Defaults off + kill switch.** Opt-in per pool; a runtime toggle +
   `flush_cache` drops the whole cache instantly if memory ever spikes — no
   restart.

Combined with the admission filter (GET/HEAD only, never Critical, never
`Set-Cookie`/`Authorization`, 200-only initially), the dynamic/sensitive/large
responses that would bloat memory never get in.

**Size knobs:**
```yaml
cache:
  global_max_bytes: 268435456      # 256 MiB hard ceiling across ALL pools
upstreams:
  assets-pool:
    cache:
      max_total_bytes: 67108864    # 64 MiB for THIS pool (weigher-enforced)
      max_entries: 4096            # secondary count cap
      max_entry_bytes: 1048576     # 1 MiB — bigger responses bypass
      default_ttl: "60s"           # freshness
      time_to_idle: "300s"         # evict cold entries
```

**Sizing guideline:** budget against *headroom*, not total RAM —
`global_max_bytes` ≤ ~25–30 % of the container's memory limit, leaving the rest
for the per-request working set + connection pools. moka's accounting is
proactive and bounded, so RSS stays near the budget plus small index overhead.
Start at 64–256 MiB, watch the stats, raise only if hit-ratio is good and
headroom exists.

**Redis backend (Phase 3)** moves the ceiling into Redis: `maxmemory` +
`maxmemory-policy allkeys-lru`, per-pool key prefix, TTL via `EX`. The WAF
keeps an approximate byte counter for stats; Redis is the real bound.

### 3.6 Purge / invalidation

Wire the **already-reserved** `POST /__waf_control/flush_cache` (today a
`supported: false` no-op) to actually evict. Body selects scope:
`{}` = all, `{upstream: "assets-pool"}`, `{prefix: "/static/"}` — surrogate-key
-style targeted purge rather than only a global flush.

### 3.7 Observability (surface already exists)

- `X-WAF-Cache: HIT|MISS|BYPASS` (+ audit `cache_bypass_reason`:
  `critical_tier|set_cookie|authorization|no_match|content_type|origin_no_store`).
  The header is already stamped on every response and shown in Live Feed +
  Audit + per-route latency.
- `GET /api/cache/stats` → `{per_pool: {entries, bytes, budget_utilization_pct,
  hit, miss, hit_ratio, evictions}}`, rendered as a card on the Performance page
  and a per-upstream HIT-ratio sparkline on Routing & Upstreams. **Watch
  signal:** high `evictions` + low `hit_ratio` = churn (narrow the rules or
  raise the budget); high `hit_ratio` near 100 % utilization = raise the budget
  if RAM allows.

---

## 4. Phasing

| Phase | Scope | Est. |
|---|---|---|
| **1** | Per-upstream **L1 in-mem** cache, GET/HEAD allow-list by prefix, hard Critical guard, key normalization + deny-query, Set-Cookie/Authorization bypass, byte-budgeted eviction, `X-WAF-Cache` HIT/MISS, `/api/cache/stats`, **Redis pub/sub purge fan-out** (fleet-wide invalidation, reuses cluster Redis) | ~750 LoC · ~4.5 d |
| **2** | Cache Deception Armor (`content_types`), `Vary`/`Accept-Encoding` keying, origin `Cache-Control` honoring, tier TTL ceilings, wire `flush_cache` (by upstream/prefix) | ~350 LoC · ~2 d |
| **3** | **L2 shared Redis behind L1** (tiered; dedicated cache instance, per-pool prefix, `allkeys-lru`). **Redis Cluster** as a scale-only option behind the same `CacheBackend` trait | ~450 LoC · ~2.5 d |
| **4** | `stale-if-error` / serve-stale (pairs with circuit breaker + graceful degradation), conditional revalidation (ETag) | ~300 LoC · ~2 d |
| — | Tests (incl. **deception + poisoning** abuse tests) + dashboard wiring | ~450 LoC · ~2.5 d |

Defaults **off**; operator opts in per pool. Phase 1 is shippable on its own.

---

## 5. Code anchors (verified 2026-06-06)

- `crates/aegis-core/src/config.rs` — `PoolConfig` (~1212) gains
  `cache: Option<PoolCacheConfig>`; `upstreams: HashMap<String, PoolConfig>`
  (~72) is the per-upstream home; route→pool via `RouteConfig.upstream` (~1062),
  tier via `RouteConfig.tier_override` (~1064) / `route_ctx.tier`.
- `crates/aegis-proxy/src/data_plane.rs` — `forward_allow_to_upstream` (~1457)
  is the lookup-before / store-after hook; `route_ctx.tier` is in scope here, so
  the Critical guard is one branch.
- `crates/aegis-control/src/interop/headers.rs` — `CacheState::{Hit,Miss,Bypass}`
  (~83) + `x-waf-cache` (~19) already exist; do **not** change the wire enum
  (`archive/interop-contract.md`).
- `crates/aegis-proxy/src/lib.rs` (~24) — `/__waf_control/flush_cache` contract
  stub to wire up.
- `crates/aegis-core/src/tier.rs` — `Tier::Critical` ⇒ `FailClose` (the guard's
  rationale).

---

## 6. Security review checklist (WAF-specific — gate before enabling by default)

- [ ] **Critical tier never cached** — covered by a test that allow-lists a
      Critical route's path and asserts `BYPASS` + `cache_bypass_reason=critical_tier`.
- [ ] **Deception**: a dynamic `/account/profile.css` returning `text/html` is
      NOT stored under a `content_types: [text/css]` rule.
- [ ] **Poisoning**: unkeyed `X-Forwarded-Host` / `Accept-Encoding` variations
      can't cross-pollute keys; response `Vary` outside `vary_by` ⇒ not stored.
- [ ] `Set-Cookie` response / `Authorization` request ⇒ `BYPASS`.
- [ ] `Cache-Control: no-store/private` honored (unless explicit rule override).
- [ ] `deny_query_keys` strips `token/session/auth/sig` from the key; verify
      against `openapi.public.yaml`.
- [ ] Per-pool byte budget enforced; eviction under memory pressure.
- [ ] Audit carries the decision + reason; purge actually evicts.

---

## 7. Roadmap slot + cross-refs

Belongs under the roadmap's **Operational / correctness backlog** (perf +
upstream-relief), interleaved by capacity — not a security-capability tier.
Pairs with:

- `archive/multi-node-deployment/` — multi-node runs fine on L1 + Redis pub/sub
  purge; the L2 shared Redis (single, then Cluster at scale) is the cross-node
  hit-ratio upgrade, not a requirement.
- `docs/data-plane/graceful-degradation.md` — `stale-if-error` complements the
  circuit breaker (serve last-good while upstream is down).
- `archive/smart-caching.md` — the per-tier predecessor (reuse: phasing,
  eviction sketch, the "contract slot already paid for" rationale).

## 8. Out of scope

- HTTP/3 server push; full RFC 9111 conditional revalidation matrix (ETag
  arrives in Phase 4, `Last-Modified` later); request collapsing / coalescing
  (a Phase 5 perf item); caching of non-200 statuses beyond a small allow-list.

---

### Sources (2025–2026 scan)

- Cloudflare Cache Rules — settings, cache keys, Bypass-Cache-on-Cookie, Cache
  Deception Armor: <https://developers.cloudflare.com/cache/how-to/cache-rules/>
- AWS CloudFront cache behaviors + cache policies:
  <https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cache-key-understand-cache-policy.html>
- nginx `ngx_http_proxy_module` (`proxy_cache*`, Set-Cookie default):
  <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
- Fastly serving stale / surrogate keys / purging:
  <https://www.fastly.com/documentation/guides/full-site-delivery/performance/serving-stale-content/>
- RFC 9111 HTTP Caching: <https://www.rfc-editor.org/rfc/rfc9111.html>
- Web cache deception — PortSwigger Web Security Academy:
  <https://portswigger.net/web-security/web-cache-deception>
- PortSwigger Research, "Gotta cache 'em all" (2024 cache-key exploitation):
  <https://portswigger.net/research/gotta-cache-em-all>
