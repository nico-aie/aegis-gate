//! SC-1 — per-upstream smart response cache (Phase 1, L1 in-process).
//!
//! A `ResponseCache` holds one independent, byte-budgeted `moka` cache per
//! upstream pool that opts in via `cfg.upstreams.<pool>.cache`. The data plane
//! ([`crate::data_plane::forward_allow_to_upstream`]) calls [`PoolCache::lookup`]
//! after the route's auth gate and *before* dialing upstream; on a HIT it serves
//! the stored response, on a MISS it forwards and then [`PoolCache::store`]s.
//!
//! **Security invariants enforced here** (the CRITICAL-tier guard lives in the
//! data plane, which is tier-aware): GET/HEAD only · path-prefix allow-list ·
//! bypass on request `Cookie`/`Authorization` and response `Set-Cookie` ·
//! deny-query stripping · normalized key · per-entry size cap · byte budget.
//! See `plans/future/smart-caching.md`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use dashmap::DashMap;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use moka::future::Cache;
use moka::Expiry;

// SC-1 — Redis pub/sub purge fan-out (multi-node). Only with `--features redis`.
#[cfg(feature = "redis")]
pub mod purge;

// SC-1 Phase 3 — shared L2 (Redis) cache tier. Only with `--features redis`.
#[cfg(feature = "redis")]
pub mod l2;

use aegis_core::config::{CacheRuleConfig, PoolCacheConfig, PoolConfig};

/// 256-bit normalized cache key. 32 bytes makes accidental collisions (which
/// would serve the wrong body — a security bug) negligible vs a 64-bit hash.
pub type CacheKey = [u8; 32];

/// A stored upstream response. Body is `Bytes` (refcounted) so serving a HIT is
/// an O(1) clone — no per-request copy.
#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub status: u16,
    /// Cacheable header subset (hop-by-hop + WAF `X-WAF-*` already stripped).
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub body: Bytes,
    /// Per-entry TTL (from the matched rule or the pool default).
    pub ttl: Duration,
    /// Weigher units = body + header bytes; bounds the byte budget.
    pub weight: u32,
    /// SC-1 Phase 4 — `stored_at + ttl`: the instant this entry stops being
    /// *fresh*. Past it, the entry is retained for the pool's `stale_if_error`
    /// window (see [`classify_freshness`]) so it can be served on an upstream
    /// error or revalidated. Runtime-only (monotonic `Instant`) — **not** in the
    /// L2 wire format; an L2 hit is reconstructed as freshly-stored (Redis `EX`
    /// already bounds it to its TTL).
    pub fresh_until: std::time::Instant,
}

impl CacheEntry {
    /// Serialize for the L2 (Redis) store. Compact framing:
    /// `magic(4) | status(u16) | ttl_secs(u32) | nheaders(u16) |
    ///  [name_len(u16) name val_len(u16) val]* | body`. All big-endian.
    pub fn encode_for_l2(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body.len() + 64);
        out.extend_from_slice(b"AC1\0");
        out.extend_from_slice(&self.status.to_be_bytes());
        out.extend_from_slice(&(self.ttl.as_secs().min(u32::MAX as u64) as u32).to_be_bytes());
        let n = self.headers.len().min(u16::MAX as usize) as u16;
        out.extend_from_slice(&n.to_be_bytes());
        for (name, val) in self.headers.iter().take(n as usize) {
            let nb = name.as_str().as_bytes();
            let vb = val.as_bytes();
            out.extend_from_slice(&(nb.len().min(u16::MAX as usize) as u16).to_be_bytes());
            out.extend_from_slice(&nb[..nb.len().min(u16::MAX as usize)]);
            out.extend_from_slice(&(vb.len().min(u16::MAX as usize) as u16).to_be_bytes());
            out.extend_from_slice(&vb[..vb.len().min(u16::MAX as usize)]);
        }
        out.extend_from_slice(&self.body);
        out
    }

    /// Inverse of [`Self::encode_for_l2`]. Returns `None` on any malformed
    /// or truncated buffer (treated as an L2 miss — never panics on untrusted
    /// Redis bytes).
    pub fn decode_from_l2(buf: &[u8]) -> Option<CacheEntry> {
        let mut p = 0usize;
        let take = |p: &mut usize, n: usize| -> Option<&[u8]> {
            let s = buf.get(*p..p.checked_add(n)?)?;
            *p += n;
            Some(s)
        };
        let u16be = |p: &mut usize| -> Option<u16> {
            Some(u16::from_be_bytes(take(p, 2)?.try_into().ok()?))
        };
        if take(&mut p, 4)? != b"AC1\0" {
            return None;
        }
        let status = u16be(&mut p)?;
        let ttl_secs = u32::from_be_bytes(take(&mut p, 4)?.try_into().ok()?);
        let nheaders = u16be(&mut p)?;
        let mut headers = Vec::with_capacity(nheaders as usize);
        for _ in 0..nheaders {
            let nl = u16be(&mut p)? as usize;
            let name = HeaderName::from_bytes(take(&mut p, nl)?).ok()?;
            let vl = u16be(&mut p)? as usize;
            let val = HeaderValue::from_bytes(take(&mut p, vl)?).ok()?;
            headers.push((name, val));
        }
        let body = Bytes::copy_from_slice(&buf[p..]);
        let header_bytes: usize = headers
            .iter()
            .map(|(n, v)| n.as_str().len() + v.as_bytes().len())
            .sum();
        let weight = (body.len() + header_bytes).min(u32::MAX as usize) as u32;
        let ttl = Duration::from_secs(ttl_secs as u64);
        Some(CacheEntry {
            status,
            headers,
            body,
            ttl,
            weight,
            // L2 entries are bounded by Redis `EX ttl`, so a retrieved L2 hit is
            // within its TTL → treat it as freshly stored for L1 freshness.
            fresh_until: std::time::Instant::now() + ttl,
        })
    }
}

/// Outcome of a request-side cache decision.
pub enum CacheLookup {
    /// Not cacheable — forward normally, stamp BYPASS with this reason.
    Bypass(&'static str),
    /// Cacheable but not stored — forward, then `store(key, rule_idx, …)`.
    Miss { key: CacheKey, rule_idx: usize },
    /// Stored + fresh — serve this, stamp HIT.
    Hit(Arc<CacheEntry>),
    /// SC-1 Phase 4 — stored but past TTL, retained within the `stale_if_error`
    /// window. Forward (revalidating with `If-None-Match` if the entry has an
    /// `ETag`); on a 304 refresh + serve the stored body, on an upstream error
    /// serve this stale copy, otherwise store the fresh response. Carries the
    /// `key`/`rule_idx` so a fresh response can be re-stored.
    Stale {
        entry: Arc<CacheEntry>,
        key: CacheKey,
        rule_idx: usize,
    },
}

/// Per-pool cache + resolved policy + counters.
pub struct PoolCache {
    cache: Cache<CacheKey, Arc<CacheEntry>>,
    cfg: PoolCacheConfig,
    /// Rules sorted longest-prefix-first so the most specific wins.
    rules: Vec<CacheRuleConfig>,
    hits: AtomicU64,
    misses: AtomicU64,
    stores: AtomicU64,
    evictions: Arc<AtomicU64>,
    /// Phase 3 — shared L2 (Redis) tier behind L1. `None` ⇒ L1-only.
    #[cfg(feature = "redis")]
    l2: Option<l2::L2Cache>,
}

/// SC-1 Phase 4 — freshness of a retained entry relative to `now`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Freshness {
    /// Within TTL — serve directly (a normal `Hit`).
    Fresh,
    /// Past TTL but within the `stale_if_error` window — retained so it can be
    /// served on an upstream error or revalidated (ETag).
    Stale,
    /// Past TTL + stale window — no longer usable (treat as a miss). The cache
    /// backend should have evicted it; this is the defensive classification for
    /// the lazy-eviction window.
    Expired,
}

/// Classify a retained entry. `fresh_until` is `stored_at + ttl`; an entry is
/// `Stale` for `stale_window` after that, then `Expired`. A zero `stale_window`
/// means no stale band (Fresh → Expired, today's behavior).
pub(crate) fn classify_freshness(
    fresh_until: std::time::Instant,
    now: std::time::Instant,
    stale_window: Duration,
) -> Freshness {
    if now < fresh_until {
        Freshness::Fresh
    } else if now < fresh_until + stale_window {
        Freshness::Stale
    } else {
        Freshness::Expired
    }
}

/// Per-entry expiry so each rule's TTL is honored (moka's `time_to_live` is
/// global; this returns the entry's own TTL at insert time). SC-1 Phase 4 —
/// retention is extended to `ttl + stale_window` so an expired-but-recent entry
/// survives for stale-if-error / revalidation; freshness is then decided
/// logically via [`classify_freshness`].
struct EntryExpiry {
    stale_window: Duration,
}
impl Expiry<CacheKey, Arc<CacheEntry>> for EntryExpiry {
    fn expire_after_create(
        &self,
        _key: &CacheKey,
        value: &Arc<CacheEntry>,
        _now: std::time::Instant,
    ) -> Option<Duration> {
        // Retain past TTL for the stale window so stale-if-error / revalidation
        // can still find the entry; freshness is decided by `classify_freshness`.
        Some(value.ttl + self.stale_window)
    }
}

impl PoolCache {
    fn new(name: &str, cfg: PoolCacheConfig) -> Self {
        let _ = name; // used only by the L2 builder (feature = "redis")
        // Longest-prefix-first so `/static/img/` beats `/static/`.
        let mut rules = cfg.rules.clone();
        rules.sort_by(|a, b| b.prefix.len().cmp(&a.prefix.len()));

        // Build the L2 (Redis) tier before `cfg` is moved into the struct.
        #[cfg(feature = "redis")]
        let l2 = cfg
            .l2
            .as_ref()
            .and_then(|l2cfg| l2::L2Cache::connect(name, l2cfg));

        let evictions = Arc::new(AtomicU64::new(0));
        let ev = evictions.clone();
        let cache = Cache::builder()
            .max_capacity(cfg.max_total_bytes)
            // Weight in bytes → eviction keeps stored bytes ≤ max_total_bytes.
            .weigher(|_k: &CacheKey, v: &Arc<CacheEntry>| v.weight)
            .time_to_idle(cfg.time_to_idle)
            .expire_after(EntryExpiry {
                stale_window: cfg.stale_if_error.unwrap_or(Duration::ZERO),
            })
            .eviction_listener(move |_k, _v, _cause| {
                ev.fetch_add(1, Ordering::Relaxed);
            })
            .build();

        Self {
            cache,
            cfg,
            rules,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            stores: AtomicU64::new(0),
            evictions,
            #[cfg(feature = "redis")]
            l2,
        }
    }

    /// The normalized config this pool was built with. Used by the reload
    /// reconcile ([`ResponseCache::apply`]) to detect an unchanged policy and
    /// preserve the existing cache entries.
    pub(crate) fn cfg(&self) -> &PoolCacheConfig {
        &self.cfg
    }

    /// First (longest) prefix rule matching `path`, with its index.
    fn match_rule(&self, path: &str) -> Option<(usize, &CacheRuleConfig)> {
        self.rules
            .iter()
            .enumerate()
            .find(|(_, r)| path.starts_with(&r.prefix))
    }

    fn method_allowed(&self, method: &Method) -> bool {
        let m = method.as_str();
        self.cfg.methods.iter().any(|x| x.eq_ignore_ascii_case(m))
    }

    /// Request-side decision: returns Bypass / Hit / Miss. Pure + cheap except
    /// the moka `get` on the eligible path. Reasons are stable strings surfaced
    /// in the audit `cache_bypass_reason` field.
    pub async fn lookup(
        &self,
        method: &Method,
        path: &str,
        query: Option<&str>,
        req_headers: &HeaderMap,
    ) -> CacheLookup {
        if !self.cfg.enabled {
            return CacheLookup::Bypass("disabled");
        }
        if !self.method_allowed(method) {
            return CacheLookup::Bypass("method");
        }
        if self.cfg.bypass_on_authorization && req_headers.contains_key(http::header::AUTHORIZATION)
        {
            return CacheLookup::Bypass("authorization");
        }
        if self.cfg.bypass_on_cookie && req_headers.contains_key(http::header::COOKIE) {
            return CacheLookup::Bypass("cookie");
        }
        let (rule_idx, rule) = match self.match_rule(path) {
            Some((i, r)) => (i, r),
            None => return CacheLookup::Bypass("no_match"),
        };
        // Key on the negotiated content-encoding bucket so a gzip/br body is
        // never served to a client that didn't accept that encoding. All
        // clients sharing a key accept the same encoding set, so any encoding
        // the cached entry carries is acceptable to every one of them.
        let ae = normalize_accept_encoding(req_headers);
        let key = compute_key(method, host_of(req_headers), path, query, &ae, rule, &self.cfg);
        let stale_window = self.cfg.stale_if_error.unwrap_or(Duration::ZERO);
        // L1 (in-process) first.
        if let Some(entry) = self.cache.get(&key).await {
            match classify_freshness(entry.fresh_until, std::time::Instant::now(), stale_window) {
                Freshness::Fresh => {
                    self.hits.fetch_add(1, Ordering::Relaxed);
                    return CacheLookup::Hit(entry);
                }
                // Past TTL but retained — revalidate / serve-on-error upstream.
                Freshness::Stale => {
                    return CacheLookup::Stale { entry, key, rule_idx };
                }
                // Past the stale window (lazy-eviction lingerer) — treat as miss.
                Freshness::Expired => {
                    self.misses.fetch_add(1, Ordering::Relaxed);
                    return CacheLookup::Miss { key, rule_idx };
                }
            }
        }
        // L2 (shared Redis) behind L1: on a hit, promote into L1 so subsequent
        // requests on this node are microsecond-fast.
        #[cfg(feature = "redis")]
        if let Some(l2) = &self.l2 {
            if let Some(entry) = l2.get(&key).await {
                let entry = Arc::new(entry);
                self.cache.insert(key, entry.clone()).await;
                self.hits.fetch_add(1, Ordering::Relaxed);
                return CacheLookup::Hit(entry);
            }
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        CacheLookup::Miss { key, rule_idx }
    }

    /// Decide whether an upstream response is storable, and if so store it.
    /// Returns true when stored (caller stamps MISS) — false means the response
    /// was served through but not cached (still a MISS on the wire).
    pub async fn store(
        &self,
        key: CacheKey,
        rule_idx: usize,
        status: u16,
        resp_headers: &HeaderMap,
        body: &Bytes,
    ) -> bool {
        // Phase 1: only 200 OK is cacheable.
        if status != 200 {
            return false;
        }
        // Never cache per-user content.
        if self.cfg.bypass_on_cookie && resp_headers.contains_key(http::header::SET_COOKIE) {
            return false;
        }
        // Honor origin intent.
        if header_blocks_caching(resp_headers) {
            return false;
        }
        // Vary safety (anti-poisoning): we key on method/host/path/query +
        // Accept-Encoding. If the response varies on anything else (or `*`),
        // storing it under our key would be under-keyed and poisonable — so
        // refuse. `Vary: Accept-Encoding` is fine (we key on it).
        if response_varies_on_unkeyed_header(resp_headers) {
            return false;
        }
        let rule = match self.rules.get(rule_idx) {
            Some(r) => r,
            None => return false,
        };
        // Cache-Deception-Armor: if the rule constrains content types, the
        // upstream type must match — stops a dynamic page dressed as static.
        if !rule.content_types.is_empty()
            && !content_type_matches(resp_headers, &rule.content_types)
        {
            return false;
        }
        // Per-entry size cap — big objects stream through, never stored.
        if body.len() as u64 > self.cfg.max_entry_bytes {
            return false;
        }
        let headers = cacheable_headers(resp_headers);
        let header_bytes: usize = headers
            .iter()
            .map(|(n, v)| n.as_str().len() + v.as_bytes().len())
            .sum();
        let weight = (body.len() + header_bytes).min(u32::MAX as usize) as u32;
        let ttl = rule.ttl.unwrap_or(self.cfg.default_ttl);
        let entry = Arc::new(CacheEntry {
            status,
            headers,
            body: body.clone(),
            ttl,
            weight,
            fresh_until: std::time::Instant::now() + ttl,
        });
        // Write L2 (shared) before L1 so a racing peer that misses L1 can still
        // find it in L2. Best-effort — an L2 failure never blocks the L1 store.
        #[cfg(feature = "redis")]
        if let Some(l2) = &self.l2 {
            l2.put(&key, &entry).await;
        }
        self.cache.insert(key, entry).await;
        self.stores.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// SC-1 Phase 4 — refresh a stale entry's freshness after a `304 Not
    /// Modified` revalidation (re-insert with `fresh_until = now + ttl`), so the
    /// next request is a fresh `Hit` again without re-fetching the body.
    pub async fn refresh(&self, key: CacheKey, entry: &Arc<CacheEntry>) {
        let refreshed = Arc::new(CacheEntry {
            fresh_until: std::time::Instant::now() + entry.ttl,
            ..(**entry).clone()
        });
        #[cfg(feature = "redis")]
        if let Some(l2) = &self.l2 {
            l2.put(&key, &refreshed).await;
        }
        self.cache.insert(key, refreshed).await;
    }

    /// Drop all entries in this pool's L1 cache (sync; moka reclaims lazily).
    /// L2 is cleared separately via [`Self::invalidate_l2`] so the pub/sub
    /// subscriber can flush every node's L1 without each node also hammering
    /// the shared L2.
    pub fn invalidate_all(&self) {
        self.cache.invalidate_all();
    }

    /// Clear this pool's shared L2 (Redis) entries. Called once by the node
    /// that handled `flush_cache`; other nodes only clear their L1.
    #[cfg(feature = "redis")]
    pub async fn invalidate_l2(&self) {
        if let Some(l2) = &self.l2 {
            l2.invalidate_prefix().await;
        }
    }

    /// True when a shared L2 (Redis) tier is wired for this pool.
    #[cfg(feature = "redis")]
    pub fn has_l2(&self) -> bool {
        self.l2.is_some()
    }

    pub fn stats(&self, pool: &str) -> PoolStats {
        let entries = self.cache.entry_count();
        let bytes = self.cache.weighted_size();
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        // Tier label: L1-only ("in_memory") vs L1 + shared L2 Redis
        // ("in_memory+redis"). The dashboard badge keys off this.
        #[cfg(feature = "redis")]
        let backend = if self.l2.is_some() {
            "in_memory+redis"
        } else {
            "in_memory"
        };
        #[cfg(not(feature = "redis"))]
        let backend = "in_memory";
        PoolStats {
            pool: pool.to_string(),
            backend,
            enabled: self.cfg.enabled,
            entries,
            bytes,
            budget_bytes: self.cfg.max_total_bytes,
            budget_utilization_pct: if self.cfg.max_total_bytes == 0 {
                0.0
            } else {
                (bytes as f64 / self.cfg.max_total_bytes as f64) * 100.0
            },
            hit: hits,
            miss: misses,
            hit_ratio: if total == 0 {
                0.0
            } else {
                hits as f64 / total as f64
            },
            stores: self.stores.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
        }
    }
}

/// Top-level cache: one [`PoolCache`] per opted-in upstream.
pub struct ResponseCache {
    /// `DashMap` (not a plain map) so the config-plane reload helper
    /// (`apply`) can add / replace / remove pools at runtime while the data
    /// plane reads concurrently — the `Arc<ResponseCache>` identity stays
    /// stable, so background flush/reset tasks holding a clone keep seeing
    /// live pools instead of a detached snapshot.
    pools: DashMap<String, Arc<PoolCache>>,
}

/// Normalize a raw `cache:` block: keep only the safe-to-cache verbs
/// (GET/HEAD), defaulting to `[GET]` if the operator listed none. Shared by
/// boot (`from_upstreams`) and the hot-reload reconcile (`apply`) so the two
/// derive identical configs — and so the unchanged-config comparison in
/// `apply` (which preserves cached entries) is exact.
fn normalize_cache_cfg(cache_cfg: &PoolCacheConfig) -> PoolCacheConfig {
    let mut cfg = cache_cfg.clone();
    cfg.methods
        .retain(|m| m.eq_ignore_ascii_case("GET") || m.eq_ignore_ascii_case("HEAD"));
    if cfg.methods.is_empty() {
        cfg.methods = vec!["GET".into()];
    }
    cfg
}

impl ResponseCache {
    /// Build from the boot config's `upstreams` map. Only pools with a
    /// `cache:` block (regardless of `enabled`) get a `PoolCache`; the
    /// `enabled` flag is re-checked per request so a hot toggle is cheap.
    pub fn from_upstreams(upstreams: &HashMap<String, PoolConfig>) -> Self {
        let pools = DashMap::new();
        for (name, pool) in upstreams {
            if let Some(cache_cfg) = &pool.cache {
                let cfg = normalize_cache_cfg(cache_cfg);
                pools.insert(name.clone(), Arc::new(PoolCache::new(name, cfg)));
            }
        }
        Self { pools }
    }

    /// 2026-06-21 — config-plane hot-reload. Reconcile the live pools against
    /// `upstreams` from a freshly-activated config WITHOUT a restart:
    /// - a pool that gained a `cache:` block (or is new) gets a `PoolCache`;
    /// - a pool whose normalized cache config is UNCHANGED keeps its existing
    ///   `PoolCache` (cached entries + counters + L2 connection preserved);
    /// - a pool whose cache config changed is rebuilt (cold);
    /// - a pool that lost its `cache:` block is dropped.
    /// Mirrors the risk/ddos "preserve state, swap config" reload pattern.
    pub fn apply(&self, upstreams: &HashMap<String, PoolConfig>) {
        // Desired set + (re)build where needed.
        let mut desired: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (name, pool) in upstreams {
            let Some(cache_cfg) = &pool.cache else { continue };
            desired.insert(name.clone());
            let cfg = normalize_cache_cfg(cache_cfg);
            let unchanged = self
                .pools
                .get(name)
                .map(|existing| existing.cfg() == &cfg)
                .unwrap_or(false);
            if !unchanged {
                self.pools
                    .insert(name.clone(), Arc::new(PoolCache::new(name, cfg)));
            }
        }
        // Drop pools whose `cache:` block was removed.
        self.pools.retain(|name, _| desired.contains(name));
    }

    pub fn is_empty(&self) -> bool {
        self.pools.is_empty()
    }

    pub fn pool(&self, name: &str) -> Option<Arc<PoolCache>> {
        self.pools.get(name).map(|p| p.clone())
    }

    pub fn stats(&self) -> Vec<PoolStats> {
        let mut out: Vec<PoolStats> = self
            .pools
            .iter()
            .map(|kv| kv.value().stats(kv.key()))
            .collect();
        out.sort_by(|a, b| a.pool.cmp(&b.pool));
        out
    }

    /// Purge L1 scope: a specific pool, or all pools. (L2 is cleared via
    /// [`Self::invalidate_l2_all`] by the node that handled the flush.)
    pub fn invalidate(&self, pool: Option<&str>) {
        match pool {
            Some(name) => {
                if let Some(pc) = self.pools.get(name) {
                    pc.invalidate_all();
                }
            }
            None => {
                for kv in self.pools.iter() {
                    kv.value().invalidate_all();
                }
            }
        }
    }

    /// Clear every pool's shared L2 (Redis) entries. Called once by the node
    /// that handled `flush_cache`; other nodes clear only their L1 (via the
    /// pub/sub fan-out). No-op when no pool has an L2.
    #[cfg(feature = "redis")]
    pub async fn invalidate_l2_all(&self) {
        // Collect Arcs first — never hold a DashMap guard across `.await`.
        let pcs: Vec<Arc<PoolCache>> = self.pools.iter().map(|kv| kv.value().clone()).collect();
        for pc in pcs {
            pc.invalidate_l2().await;
        }
    }

    /// True when any pool has a shared L2 (Redis) tier wired.
    #[cfg(feature = "redis")]
    pub fn any_l2(&self) -> bool {
        self.pools.iter().any(|kv| kv.value().has_l2())
    }
}

/// Stats row surfaced by `GET /api/cache/stats`.
#[derive(Clone, Debug, serde::Serialize)]
pub struct PoolStats {
    pub pool: String,
    /// Which cache tier these numbers describe: `in_memory` (L1, per node)
    /// today; `redis` / `in_memory+redis` once the L2 tier ships.
    pub backend: &'static str,
    /// Whether this pool's cache is currently enabled (vs configured-but-off).
    pub enabled: bool,
    pub entries: u64,
    pub bytes: u64,
    pub budget_bytes: u64,
    pub budget_utilization_pct: f64,
    pub hit: u64,
    pub miss: u64,
    pub hit_ratio: f64,
    pub stores: u64,
    pub evictions: u64,
}

// ----------------------------- helpers --------------------------------------

fn host_of(headers: &HeaderMap) -> &str {
    headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

/// Normalized 256-bit key over the inputs that legitimately change the
/// response. Normalization (lowercase host, collapsed `//`, sorted kept-query)
/// defeats key-confusion poisoning; deny-query + `ignore_query` bound key
/// cardinality.
fn compute_key(
    method: &Method,
    host: &str,
    path: &str,
    query: Option<&str>,
    accept_encoding: &str,
    rule: &CacheRuleConfig,
    cfg: &PoolCacheConfig,
) -> CacheKey {
    let mut h = blake3::Hasher::new();
    h.update(b"aegis-cache-v2\0");
    h.update(method.as_str().to_ascii_uppercase().as_bytes());
    h.update(b"\0");
    h.update(host.to_ascii_lowercase().as_bytes());
    h.update(b"\0");
    h.update(normalize_path(path).as_bytes());
    h.update(b"\0");
    if !rule.ignore_query {
        let kept = kept_query(query, &cfg.deny_query_keys);
        h.update(kept.as_bytes());
    }
    h.update(b"\0ae\0");
    h.update(accept_encoding.as_bytes());
    *h.finalize().as_bytes()
}

/// Canonical bucket of the recognized content-codings the client accepts —
/// sorted + deduped, or `identity` when none. Two requests with the same
/// acceptable set share a key, and any encoding the cached entry carries was
/// acceptable to the request that stored it, so it's acceptable to all of
/// them. Bounds key cardinality to a handful of real-world buckets.
fn normalize_accept_encoding(headers: &HeaderMap) -> String {
    let raw = headers
        .get(http::header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let mut toks: Vec<&str> = raw
        .split(',')
        .map(|t| t.split(';').next().unwrap_or("").trim())
        .filter(|t| matches!(*t, "gzip" | "br" | "deflate" | "zstd"))
        .collect();
    toks.sort_unstable();
    toks.dedup();
    if toks.is_empty() {
        "identity".to_string()
    } else {
        toks.join(",")
    }
}

/// True when the response's `Vary` requires keying on an input we don't key on
/// (anything other than `accept-encoding`, or `*`) — storing it would be
/// poisonable, so the caller must refuse.
fn response_varies_on_unkeyed_header(headers: &HeaderMap) -> bool {
    // A response can carry multiple `Vary` headers; check them all.
    for v in headers.get_all(http::header::VARY).iter() {
        let Ok(s) = v.to_str() else {
            return true; // unparseable Vary → be safe, don't store
        };
        for token in s.split(',') {
            let token = token.trim().to_ascii_lowercase();
            if token.is_empty() {
                continue;
            }
            if token == "*" || token != "accept-encoding" {
                return true;
            }
        }
    }
    false
}

/// Collapse duplicate slashes; we do not lowercase the path (case can be
/// significant upstream). Leaves percent-encoding as-is but rejects nothing —
/// the allow-list prefix already bounds what's cacheable.
fn normalize_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut prev_slash = false;
    for c in path.chars() {
        if c == '/' {
            if !prev_slash {
                out.push(c);
            }
            prev_slash = true;
        } else {
            out.push(c);
            prev_slash = false;
        }
    }
    out
}

/// Keep only non-denied query keys, sorted, as a stable `k=v&…` string.
fn kept_query(query: Option<&str>, deny: &[String]) -> String {
    let q = match query {
        Some(q) if !q.is_empty() => q,
        _ => return String::new(),
    };
    let mut pairs: Vec<(&str, &str)> = q
        .split('&')
        .filter_map(|kv| {
            let mut it = kv.splitn(2, '=');
            let k = it.next()?;
            let v = it.next().unwrap_or("");
            if deny.iter().any(|d| d.eq_ignore_ascii_case(k)) {
                None
            } else {
                Some((k, v))
            }
        })
        .collect();
    pairs.sort_unstable();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// True when the response's `Cache-Control` forbids a shared cache from
/// storing it (`no-store`, `private`, `no-cache`).
fn header_blocks_caching(headers: &HeaderMap) -> bool {
    if let Some(cc) = headers
        .get(http::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
    {
        let cc = cc.to_ascii_lowercase();
        return cc.contains("no-store") || cc.contains("private") || cc.contains("no-cache");
    }
    false
}

fn content_type_matches(headers: &HeaderMap, allow: &[String]) -> bool {
    let ct = match headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    {
        Some(c) => c
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase(),
        None => return false,
    };
    allow.iter().any(|a| {
        let a = a.to_ascii_lowercase();
        if let Some(prefix) = a.strip_suffix("/*") {
            ct.starts_with(prefix) && ct[prefix.len()..].starts_with('/')
        } else {
            ct == a
        }
    })
}

/// Headers safe to store + replay. Drops hop-by-hop framing headers (hyper
/// re-derives them for the `Full<Bytes>` body) and the WAF's own `X-WAF-*`
/// observability headers (re-stamped per request, never served from cache).
fn cacheable_headers(headers: &HeaderMap) -> Vec<(HeaderName, HeaderValue)> {
    headers
        .iter()
        .filter(|(n, _)| {
            let s = n.as_str();
            !s.eq_ignore_ascii_case("connection")
                && !s.eq_ignore_ascii_case("keep-alive")
                && !s.eq_ignore_ascii_case("proxy-authenticate")
                && !s.eq_ignore_ascii_case("proxy-authorization")
                && !s.eq_ignore_ascii_case("te")
                && !s.eq_ignore_ascii_case("trailer")
                && !s.eq_ignore_ascii_case("transfer-encoding")
                && !s.eq_ignore_ascii_case("upgrade")
                && !s.eq_ignore_ascii_case("content-length")
                && !s.to_ascii_lowercase().starts_with("x-waf-")
        })
        .map(|(n, v)| (n.clone(), v.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(prefix: &str) -> CacheRuleConfig {
        CacheRuleConfig {
            prefix: prefix.into(),
            ttl: None,
            content_types: vec![],
            ignore_query: false,
        }
    }

    fn cfg(rules: Vec<CacheRuleConfig>) -> PoolCacheConfig {
        PoolCacheConfig {
            enabled: true,
            max_total_bytes: 1024 * 1024,
            max_entries: 100,
            max_entry_bytes: 4096,
            default_ttl: Duration::from_secs(60),
            time_to_idle: Duration::from_secs(300),
            rules,
            methods: vec!["GET".into(), "HEAD".into()],
            deny_query_keys: vec!["token".into(), "session".into()],
            bypass_on_cookie: true,
            bypass_on_authorization: true,
            l2: None,
            stale_if_error: None,
        }
    }

    // SC-1 Phase 4 — stale-if-error: freshness classification. An entry past
    // its TTL but within the stale window is `Stale` (servable on upstream
    // error / revalidatable); past TTL+stale it's `Expired` (a miss).
    #[test]
    fn freshness_classifies_fresh_stale_expired() {
        let base = std::time::Instant::now();
        let fresh_until = base + Duration::from_secs(10);
        let stale = Duration::from_secs(30);
        assert_eq!(classify_freshness(fresh_until, base, stale), Freshness::Fresh);
        assert_eq!(
            classify_freshness(fresh_until, base + Duration::from_secs(20), stale),
            Freshness::Stale,
        );
        assert_eq!(
            classify_freshness(fresh_until, base + Duration::from_secs(45), stale),
            Freshness::Expired,
        );
        // No stale window ⇒ no stale band: Expired the instant it's not Fresh.
        assert_eq!(
            classify_freshness(fresh_until, base + Duration::from_secs(11), Duration::ZERO),
            Freshness::Expired,
        );
        // Exactly at the freshness boundary is no longer Fresh.
        assert_eq!(classify_freshness(fresh_until, fresh_until, stale), Freshness::Stale);
    }

    #[test]
    fn l2_codec_round_trips() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_TYPE, HeaderValue::from_static("text/css"));
        headers.insert(http::header::ETAG, HeaderValue::from_static("\"abc123\""));
        let entry = CacheEntry {
            status: 200,
            headers: cacheable_headers(&headers),
            body: Bytes::from_static(b"body-bytes-\x00\xff-binary"),
            ttl: Duration::from_secs(300),
            weight: 99,
            fresh_until: std::time::Instant::now() + Duration::from_secs(300),
        };
        let buf = entry.encode_for_l2();
        let back = CacheEntry::decode_from_l2(&buf).expect("decodes");
        assert_eq!(back.status, 200);
        assert_eq!(&back.body[..], &entry.body[..]);
        assert_eq!(back.ttl, Duration::from_secs(300));
        let names: Vec<String> = back.headers.iter().map(|(n, _)| n.as_str().to_string()).collect();
        assert!(names.contains(&"content-type".to_string()));
        assert!(names.contains(&"etag".to_string()));
        // truncated / garbage ⇒ None, never panics
        assert!(CacheEntry::decode_from_l2(b"AC1\0\x00").is_none());
        assert!(CacheEntry::decode_from_l2(b"nope").is_none());
        assert!(CacheEntry::decode_from_l2(&[]).is_none());
    }

    #[tokio::test]
    async fn miss_then_hit_on_identical_get() {
        let pc = PoolCache::new("test", cfg(vec![rule("/static/")]));
        let h = HeaderMap::new();
        let key = match pc.lookup(&Method::GET, "/static/app.css", None, &h).await {
            CacheLookup::Miss { key, rule_idx } => {
                assert_eq!(rule_idx, 0);
                key
            }
            _ => panic!("expected miss"),
        };
        let mut rh = HeaderMap::new();
        rh.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/css"),
        );
        assert!(
            pc.store(key, 0, 200, &rh, &Bytes::from_static(b"body"))
                .await
        );
        match pc.lookup(&Method::GET, "/static/app.css", None, &h).await {
            CacheLookup::Hit(e) => assert_eq!(&e.body[..], b"body"),
            _ => panic!("expected hit"),
        }
    }

    #[tokio::test]
    async fn bypass_rules() {
        let pc = PoolCache::new("test", cfg(vec![rule("/static/")]));
        // unmatched path
        assert!(matches!(
            pc.lookup(&Method::GET, "/api/x", None, &HeaderMap::new())
                .await,
            CacheLookup::Bypass("no_match")
        ));
        // POST
        assert!(matches!(
            pc.lookup(&Method::POST, "/static/x", None, &HeaderMap::new())
                .await,
            CacheLookup::Bypass("method")
        ));
        // Authorization present
        let mut h = HeaderMap::new();
        h.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer x"),
        );
        assert!(matches!(
            pc.lookup(&Method::GET, "/static/x", None, &h).await,
            CacheLookup::Bypass("authorization")
        ));
        // Cookie present
        let mut h = HeaderMap::new();
        h.insert(http::header::COOKIE, HeaderValue::from_static("s=1"));
        assert!(matches!(
            pc.lookup(&Method::GET, "/static/x", None, &h).await,
            CacheLookup::Bypass("cookie")
        ));
    }

    #[tokio::test]
    async fn store_refuses_set_cookie_and_no_store_and_big_and_bad_type() {
        let mut c = cfg(vec![CacheRuleConfig {
            prefix: "/static/".into(),
            ttl: None,
            content_types: vec!["text/css".into(), "image/*".into()],
            ignore_query: false,
        }]);
        c.max_entry_bytes = 8;
        let pc = PoolCache::new("test", c);
        let key = [9u8; 32];
        // Set-Cookie ⇒ refuse
        let mut rh = HeaderMap::new();
        rh.insert(http::header::SET_COOKIE, HeaderValue::from_static("a=1"));
        rh.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/css"),
        );
        assert!(!pc.store(key, 0, 200, &rh, &Bytes::from_static(b"x")).await);
        // no-store ⇒ refuse
        let mut rh = HeaderMap::new();
        rh.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        );
        rh.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/css"),
        );
        assert!(!pc.store(key, 0, 200, &rh, &Bytes::from_static(b"x")).await);
        // wrong content-type ⇒ refuse (deception armor)
        let mut rh = HeaderMap::new();
        rh.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/html"),
        );
        assert!(!pc.store(key, 0, 200, &rh, &Bytes::from_static(b"x")).await);
        // image/* wildcard ⇒ ok, but body too big ⇒ refuse
        let mut rh = HeaderMap::new();
        rh.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("image/png"),
        );
        assert!(
            !pc.store(key, 0, 200, &rh, &Bytes::from_static(b"123456789"))
                .await
        );
        // small image ⇒ stored
        assert!(
            pc.store(key, 0, 200, &rh, &Bytes::from_static(b"img"))
                .await
        );
        // non-200 ⇒ refuse
        let mut rh = HeaderMap::new();
        rh.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/css"),
        );
        assert!(
            !pc.store([1u8; 32], 0, 404, &rh, &Bytes::from_static(b"x"))
                .await
        );
    }

    #[test]
    fn key_normalization_and_deny_query() {
        let c = cfg(vec![rule("/static/")]);
        let r = rule("/static/");
        let ae = "identity";
        // collapsed slashes + denied query stripped ⇒ same key
        let k1 = compute_key(
            &Method::GET,
            "h",
            "/static//a.css",
            Some("token=abc&v=1"),
            ae,
            &r,
            &c,
        );
        let k2 = compute_key(
            &Method::GET,
            "h",
            "/static/a.css",
            Some("v=1&token=zzz"),
            ae,
            &r,
            &c,
        );
        assert_eq!(k1, k2, "denied query + slash normalization should collapse");
        // different kept-query ⇒ different key
        let k3 = compute_key(&Method::GET, "h", "/static/a.css", Some("v=2"), ae, &r, &c);
        assert_ne!(k1, k3);
        // ignore_query ⇒ query irrelevant
        let mut ri = rule("/static/");
        ri.ignore_query = true;
        let a = compute_key(&Method::GET, "h", "/static/a.css", Some("v=1"), ae, &ri, &c);
        let b = compute_key(&Method::GET, "h", "/static/a.css", Some("v=2"), ae, &ri, &c);
        assert_eq!(a, b);
    }

    #[test]
    fn accept_encoding_buckets_the_key() {
        let c = cfg(vec![rule("/static/")]);
        let r = rule("/static/");
        let q = Some("v=1");
        // gzip vs identity ⇒ different keys (won't serve gzip to a non-gzip client)
        let gzip = compute_key(&Method::GET, "h", "/static/a.css", q, "gzip", &r, &c);
        let ident = compute_key(&Method::GET, "h", "/static/a.css", q, "identity", &r, &c);
        assert_ne!(gzip, ident);
        // same acceptable SET in a different order ⇒ same key (normalized)
        let h1 = {
            let mut h = HeaderMap::new();
            h.insert(http::header::ACCEPT_ENCODING, HeaderValue::from_static("gzip, br"));
            normalize_accept_encoding(&h)
        };
        let h2 = {
            let mut h = HeaderMap::new();
            h.insert(http::header::ACCEPT_ENCODING, HeaderValue::from_static("br;q=1.0, gzip"));
            normalize_accept_encoding(&h)
        };
        assert_eq!(h1, "br,gzip");
        assert_eq!(h1, h2);
        // no/empty Accept-Encoding ⇒ identity bucket
        assert_eq!(normalize_accept_encoding(&HeaderMap::new()), "identity");
    }

    #[tokio::test]
    async fn store_refuses_vary_on_unkeyed_header_but_allows_accept_encoding() {
        let pc = PoolCache::new("test", cfg(vec![rule("/static/")]));
        // Vary: Cookie ⇒ refuse (we don't key on Cookie → poisonable)
        let mut rh = HeaderMap::new();
        rh.insert(http::header::CONTENT_TYPE, HeaderValue::from_static("text/css"));
        rh.insert(http::header::VARY, HeaderValue::from_static("Cookie"));
        assert!(!pc.store([2u8; 32], 0, 200, &rh, &Bytes::from_static(b"x")).await);
        // Vary: * ⇒ refuse
        let mut rh = HeaderMap::new();
        rh.insert(http::header::CONTENT_TYPE, HeaderValue::from_static("text/css"));
        rh.insert(http::header::VARY, HeaderValue::from_static("*"));
        assert!(!pc.store([3u8; 32], 0, 200, &rh, &Bytes::from_static(b"x")).await);
        // Vary: Accept-Encoding ⇒ OK (we key on it)
        let mut rh = HeaderMap::new();
        rh.insert(http::header::CONTENT_TYPE, HeaderValue::from_static("text/css"));
        rh.insert(http::header::VARY, HeaderValue::from_static("Accept-Encoding"));
        assert!(pc.store([4u8; 32], 0, 200, &rh, &Bytes::from_static(b"x")).await);
    }

    #[tokio::test]
    async fn disabled_pool_bypasses() {
        let mut c = cfg(vec![rule("/static/")]);
        c.enabled = false;
        let pc = PoolCache::new("test", c);
        assert!(matches!(
            pc.lookup(&Method::GET, "/static/x", None, &HeaderMap::new())
                .await,
            CacheLookup::Bypass("disabled")
        ));
    }

    #[tokio::test]
    async fn invalidate_clears_and_stats_count() {
        let pc = PoolCache::new("test", cfg(vec![rule("/static/")]));
        let h = HeaderMap::new();
        let key = match pc.lookup(&Method::GET, "/static/a", None, &h).await {
            CacheLookup::Miss { key, .. } => key,
            _ => panic!("miss"),
        };
        let mut rh = HeaderMap::new();
        rh.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/css"),
        );
        assert!(pc.store(key, 0, 200, &rh, &Bytes::from_static(b"x")).await);
        // a hit bumps the counter
        assert!(matches!(
            pc.lookup(&Method::GET, "/static/a", None, &h).await,
            CacheLookup::Hit(_)
        ));
        let s = pc.stats("p");
        assert_eq!(s.hit, 1);
        assert!(s.miss >= 1);
        assert_eq!(s.stores, 1);
        assert!(s.hit_ratio > 0.0);
        // after invalidate, the same key misses
        pc.invalidate_all();
        // moka reclaims lazily; run_pending isn't exposed, but get() honors
        // the invalidation timestamp immediately.
        assert!(matches!(
            pc.lookup(&Method::GET, "/static/a", None, &h).await,
            CacheLookup::Miss { .. }
        ));
    }

    #[test]
    fn from_upstreams_builds_only_opted_in_pools_and_filters_methods() {
        let yaml = r#"
assets:
  members:
    - addr: "127.0.0.1:9000"
      weight: 1
  cache:
    enabled: true
    methods: [GET, HEAD, POST, PUT]
    rules:
      - prefix: "/static/"
api:
  members:
    - addr: "127.0.0.1:9001"
      weight: 1
"#;
        let upstreams: std::collections::HashMap<String, PoolConfig> =
            serde_yaml::from_str(yaml).unwrap();
        let rc = ResponseCache::from_upstreams(&upstreams);
        assert!(rc.pool("assets").is_some(), "opted-in pool present");
        assert!(rc.pool("api").is_none(), "pool without cache: absent");
        // unsafe verbs dropped — only GET/HEAD survive
        let pc = rc.pool("assets").unwrap();
        assert!(pc.method_allowed(&Method::GET));
        assert!(pc.method_allowed(&Method::HEAD));
        assert!(!pc.method_allowed(&Method::POST));
        assert!(!pc.method_allowed(&Method::PUT));
    }

    // 2026-06-21 — config-plane hot-reload. A pool that gains a `cache:` block
    // at runtime (dashboard "Response cache" toggle) must get a live cache
    // without a restart — the bug the user hit (BYPASS forever).
    #[test]
    fn apply_enables_pool_added_at_runtime() {
        let boot: std::collections::HashMap<String, PoolConfig> =
            serde_yaml::from_str("app:\n  members:\n    - addr: \"127.0.0.1:9000\"\n").unwrap();
        let rc = ResponseCache::from_upstreams(&boot);
        assert!(rc.pool("app").is_none(), "precondition: no cache block at boot");

        let next: std::collections::HashMap<String, PoolConfig> = serde_yaml::from_str(
            "app:\n  members:\n    - addr: \"127.0.0.1:9000\"\n  cache:\n    enabled: true\n    rules:\n      - prefix: \"/static/css\"\n",
        )
        .unwrap();
        rc.apply(&next);
        let pc = rc.pool("app").expect("cache live after apply, no restart");
        assert!(pc.cfg().enabled);
    }

    #[test]
    fn apply_preserves_pool_when_cfg_unchanged() {
        let yaml = "app:\n  members:\n    - addr: \"127.0.0.1:9000\"\n  cache:\n    enabled: true\n    rules:\n      - prefix: \"/static/\"\n";
        let up: std::collections::HashMap<String, PoolConfig> = serde_yaml::from_str(yaml).unwrap();
        let rc = ResponseCache::from_upstreams(&up);
        let before = rc.pool("app").unwrap();
        rc.apply(&up); // identical config
        let after = rc.pool("app").unwrap();
        assert!(
            Arc::ptr_eq(&before, &after),
            "unchanged cfg must preserve the live cache instance (entries kept)",
        );
    }

    #[test]
    fn apply_rebuilds_pool_when_cfg_changed() {
        let up1: std::collections::HashMap<String, PoolConfig> = serde_yaml::from_str(
            "app:\n  members:\n    - addr: \"127.0.0.1:9000\"\n  cache:\n    enabled: true\n    rules:\n      - prefix: \"/static/\"\n",
        )
        .unwrap();
        let rc = ResponseCache::from_upstreams(&up1);
        let before = rc.pool("app").unwrap();
        let up2: std::collections::HashMap<String, PoolConfig> = serde_yaml::from_str(
            "app:\n  members:\n    - addr: \"127.0.0.1:9000\"\n  cache:\n    enabled: true\n    rules:\n      - prefix: \"/assets/\"\n",
        )
        .unwrap();
        rc.apply(&up2);
        let after = rc.pool("app").unwrap();
        assert!(!Arc::ptr_eq(&before, &after), "changed cfg must rebuild the pool");
    }

    #[test]
    fn apply_removes_pool_when_cache_block_dropped() {
        let up1: std::collections::HashMap<String, PoolConfig> = serde_yaml::from_str(
            "app:\n  members:\n    - addr: \"127.0.0.1:9000\"\n  cache:\n    enabled: true\n    rules:\n      - prefix: \"/static/\"\n",
        )
        .unwrap();
        let rc = ResponseCache::from_upstreams(&up1);
        assert!(rc.pool("app").is_some());
        let up2: std::collections::HashMap<String, PoolConfig> =
            serde_yaml::from_str("app:\n  members:\n    - addr: \"127.0.0.1:9000\"\n").unwrap();
        rc.apply(&up2);
        assert!(rc.pool("app").is_none(), "dropping the cache block removes the pool");
    }

    #[test]
    fn cacheable_headers_strips_hop_and_waf() {
        let mut h = HeaderMap::new();
        h.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/css"),
        );
        h.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("keep-alive"),
        );
        h.insert("x-waf-cache", HeaderValue::from_static("MISS"));
        h.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("3"));
        let kept = cacheable_headers(&h);
        let names: Vec<String> = kept.iter().map(|(n, _)| n.as_str().to_string()).collect();
        assert!(names.contains(&"content-type".to_string()));
        assert!(!names.iter().any(|n| n == "connection"));
        assert!(!names.iter().any(|n| n.starts_with("x-waf-")));
        assert!(!names.iter().any(|n| n == "content-length"));
    }
}
