//! SC-1 Phase 3 — L2 (shared Redis) cache tier integration test.
//!
//! Proves the L2 tier shares cache entries across "nodes": store via one
//! `ResponseCache` instance, then a *fresh* instance (cold L1) finds the entry
//! in L2 and serves a HIT; an L2 purge then makes it a MISS again.
//!
//! Live-Redis test — set `AEGIS_REDIS_URL` to run it, e.g.:
//!   AEGIS_REDIS_URL=redis://127.0.0.1:6379 \
//!     cargo test -p aegis-proxy --features redis --test smart_cache_l2
//! Without the env var every test prints "skipped" and passes.
#![cfg(feature = "redis")]

use std::collections::HashMap;

use aegis_core::config::PoolConfig;
use aegis_proxy::cache::{CacheLookup, ResponseCache};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method};

fn redis_url() -> Option<String> {
    std::env::var("AEGIS_REDIS_URL").ok()
}

/// Build a one-pool `ResponseCache` whose pool has an L2 pointing at `url`,
/// namespaced by `prefix` (unique per test so runs don't collide).
fn build_cache(url: &str, prefix: &str) -> ResponseCache {
    let yaml = format!(
        r#"
p:
  members: [{{ addr: "127.0.0.1:9" }}]
  cache:
    enabled: true
    default_ttl: "60s"
    rules:
      - prefix: "/static/"
    l2:
      urls: ["{url}"]
      key_prefix: "{prefix}"
"#
    );
    let upstreams: HashMap<String, PoolConfig> = serde_yaml::from_str(&yaml).unwrap();
    ResponseCache::from_upstreams(&upstreams)
}

fn resp_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(http::header::CONTENT_TYPE, HeaderValue::from_static("text/css"));
    h
}

#[tokio::test]
async fn l2_shares_entries_across_nodes_then_purges() {
    let Some(url) = redis_url() else {
        eprintln!("skipped: set AEGIS_REDIS_URL to run the L2 integration test");
        return;
    };
    let prefix = format!("aegistest:{}", uuid::Uuid::new_v4());
    let path = "/static/shared.css";
    let body = Bytes::from_static(b"l2-shared-body");

    // Node A: store (writes L1 + L2).
    let node_a = build_cache(&url, &prefix);
    let pc_a = node_a.pool("p").expect("pool p");
    let key = match pc_a.lookup(&Method::GET, path, None, &HeaderMap::new()).await {
        CacheLookup::Miss { key, rule_idx } => {
            assert!(
                pc_a
                    .store(key, rule_idx, 200, &resp_headers(), &body)
                    .await,
                "store should accept a 200 text/css under /static/",
            );
            key
        }
        other => panic!("node A first lookup should MISS, got {:?}", cache_kind(&other)),
    };
    let _ = key;

    // Node B: a FRESH cache (cold L1) must find it in the shared L2 → HIT.
    let node_b = build_cache(&url, &prefix);
    let pc_b = node_b.pool("p").expect("pool p");
    match pc_b.lookup(&Method::GET, path, None, &HeaderMap::new()).await {
        CacheLookup::Hit(entry) => assert_eq!(&entry.body[..], &body[..], "L2 body round-trips"),
        other => panic!(
            "node B should HIT from shared L2, got {:?} (is AEGIS_REDIS_URL reachable?)",
            cache_kind(&other)
        ),
    }

    // Purge the shared L2 → node C (fresh) misses again.
    node_b.invalidate_l2_all().await;
    let node_c = build_cache(&url, &prefix);
    let pc_c = node_c.pool("p").expect("pool p");
    assert!(
        matches!(
            pc_c.lookup(&Method::GET, path, None, &HeaderMap::new()).await,
            CacheLookup::Miss { .. }
        ),
        "after L2 purge a fresh node must MISS",
    );
}

fn cache_kind(l: &CacheLookup) -> &'static str {
    match l {
        CacheLookup::Bypass(_) => "BYPASS",
        CacheLookup::Miss { .. } => "MISS",
        CacheLookup::Hit(_) => "HIT",
    }
}
