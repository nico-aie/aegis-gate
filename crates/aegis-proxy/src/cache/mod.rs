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
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use moka::future::Cache;
use moka::Expiry;

// SC-1 — Redis pub/sub purge fan-out (multi-node). Only with `--features redis`.
#[cfg(feature = "redis")]
pub mod purge;

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
}

/// Outcome of a request-side cache decision.
pub enum CacheLookup {
    /// Not cacheable — forward normally, stamp BYPASS with this reason.
    Bypass(&'static str),
    /// Cacheable but not stored — forward, then `store(key, rule_idx, …)`.
    Miss { key: CacheKey, rule_idx: usize },
    /// Stored + fresh — serve this, stamp HIT.
    Hit(Arc<CacheEntry>),
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
}

/// Per-entry expiry so each rule's TTL is honored (moka's `time_to_live` is
/// global; this returns the entry's own TTL at insert time).
struct EntryExpiry;
impl Expiry<CacheKey, Arc<CacheEntry>> for EntryExpiry {
    fn expire_after_create(
        &self,
        _key: &CacheKey,
        value: &Arc<CacheEntry>,
        _now: std::time::Instant,
    ) -> Option<Duration> {
        Some(value.ttl)
    }
}

impl PoolCache {
    fn new(cfg: PoolCacheConfig) -> Self {
        // Longest-prefix-first so `/static/img/` beats `/static/`.
        let mut rules = cfg.rules.clone();
        rules.sort_by(|a, b| b.prefix.len().cmp(&a.prefix.len()));

        let evictions = Arc::new(AtomicU64::new(0));
        let ev = evictions.clone();
        let cache = Cache::builder()
            .max_capacity(cfg.max_total_bytes)
            // Weight in bytes → eviction keeps stored bytes ≤ max_total_bytes.
            .weigher(|_k: &CacheKey, v: &Arc<CacheEntry>| v.weight)
            .time_to_idle(cfg.time_to_idle)
            .expire_after(EntryExpiry)
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
        }
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
        match self.cache.get(&key).await {
            Some(entry) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                CacheLookup::Hit(entry)
            }
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                CacheLookup::Miss { key, rule_idx }
            }
        }
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
        });
        self.cache.insert(key, entry).await;
        self.stores.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Drop all entries in this pool's cache. moka's `invalidate_all` is sync
    /// (entries are reclaimed lazily); a prefix purge isn't possible without a
    /// scan, so Phase 1 purges the whole pool — coarse but correct.
    pub fn invalidate_all(&self) {
        self.cache.invalidate_all();
    }

    pub fn stats(&self, pool: &str) -> PoolStats {
        let entries = self.cache.entry_count();
        let bytes = self.cache.weighted_size();
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        PoolStats {
            pool: pool.to_string(),
            // Phase 1 is L1 in-process only; when the L2 Redis tier lands this
            // becomes per-pool ("in_memory" / "redis" / "in_memory+redis") so
            // the dashboard can show which tier the numbers come from.
            backend: "in_memory",
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
    pools: HashMap<String, Arc<PoolCache>>,
}

impl ResponseCache {
    /// Build from the boot config's `upstreams` map. Only pools with a
    /// `cache:` block (regardless of `enabled`) get a `PoolCache`; the
    /// `enabled` flag is re-checked per request so a hot toggle is cheap.
    pub fn from_upstreams(upstreams: &HashMap<String, PoolConfig>) -> Self {
        let mut pools = HashMap::new();
        for (name, pool) in upstreams {
            if let Some(cache_cfg) = &pool.cache {
                // Keep only GET/HEAD methods (the only safe-to-cache verbs).
                let mut cfg = cache_cfg.clone();
                cfg.methods
                    .retain(|m| m.eq_ignore_ascii_case("GET") || m.eq_ignore_ascii_case("HEAD"));
                if cfg.methods.is_empty() {
                    cfg.methods = vec!["GET".into()];
                }
                pools.insert(name.clone(), Arc::new(PoolCache::new(cfg)));
            }
        }
        Self { pools }
    }

    pub fn is_empty(&self) -> bool {
        self.pools.is_empty()
    }

    pub fn pool(&self, name: &str) -> Option<&Arc<PoolCache>> {
        self.pools.get(name)
    }

    pub fn stats(&self) -> Vec<PoolStats> {
        let mut out: Vec<PoolStats> = self.pools.iter().map(|(name, pc)| pc.stats(name)).collect();
        out.sort_by(|a, b| a.pool.cmp(&b.pool));
        out
    }

    /// Purge scope: a specific pool, or all pools.
    pub fn invalidate(&self, pool: Option<&str>) {
        match pool {
            Some(name) => {
                if let Some(pc) = self.pools.get(name) {
                    pc.invalidate_all();
                }
            }
            None => {
                for pc in self.pools.values() {
                    pc.invalidate_all();
                }
            }
        }
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
        }
    }

    #[tokio::test]
    async fn miss_then_hit_on_identical_get() {
        let pc = PoolCache::new(cfg(vec![rule("/static/")]));
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
        let pc = PoolCache::new(cfg(vec![rule("/static/")]));
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
        let pc = PoolCache::new(c);
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
        let pc = PoolCache::new(cfg(vec![rule("/static/")]));
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
        let pc = PoolCache::new(c);
        assert!(matches!(
            pc.lookup(&Method::GET, "/static/x", None, &HeaderMap::new())
                .await,
            CacheLookup::Bypass("disabled")
        ));
    }

    #[tokio::test]
    async fn invalidate_clears_and_stats_count() {
        let pc = PoolCache::new(cfg(vec![rule("/static/")]));
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
