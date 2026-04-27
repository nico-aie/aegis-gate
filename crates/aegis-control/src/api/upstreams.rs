//! `/api/upstreams/summary` data layer (D-M2-T2.3).
//!
//! Pure-logic side of the upstream-pool summary endpoint. The Tracking
//! page (and the Overview-page upstream tile fed by `/api/stats`)
//! consume this output. Architecture mirrors `api::stats`:
//!
//! - This module owns the JSON wire shape and the rollup rules.
//! - The data source (live cluster pool state) lives in `aegis-proxy`.
//!   The handler accepts a `Box<dyn Fn() -> PoolHealthSnapshot>`
//!   closure so the proxy plugs in its reader without forcing
//!   `aegis-control` to depend on `aegis-proxy`.
//!
//! Spec: `docs/dashboard-enterprise/api.md` §"Tracking page" and
//! `docs/dashboard-enterprise/pages/overview.md` §"Upstream pools".

#![allow(dead_code)]

use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;

/// Default response cache TTL. The Tracking page polls
/// `/api/tracking/snapshot` at 5 s but pages can override; 2 s
/// matches `docs/dashboard-enterprise/api.md` §"Caching" for the
/// tracking-snapshot family.
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(2);

/// Snapshot of one upstream pool. Cheap value type so the `aegis-proxy`
/// side can build it from `Pool::members.iter().map(|m| m.is_healthy())`
/// without exposing its internal types upward.
#[derive(Clone, Debug, Default, Serialize)]
pub struct PoolHealthEntry {
    pub name: String,
    pub healthy: u32,
    pub total: u32,
}

/// Input to [`compute_summary`]. A list of `PoolHealthEntry`. The
/// proxy re-builds this on every read from the cluster state.
#[derive(Clone, Debug, Default, Serialize)]
pub struct PoolHealthSnapshot {
    pub pools: Vec<PoolHealthEntry>,
}

/// JSON shape returned by `GET /api/upstreams/summary`. Matches
/// `docs/dashboard-enterprise/api.md`. State is one of
/// `Healthy | Degraded | Down` — the spec is explicit there are
/// only 3 states (no `Unknown`).
#[derive(Clone, Debug, Serialize)]
pub struct UpstreamSummaryResponse {
    pub state: &'static str,
    pub healthy_members: u32,
    pub total_members: u32,
    pub pools: Vec<PoolHealthEntry>,
}

/// Roll up a [`PoolHealthSnapshot`] into the summary response.
///
/// State semantics (spec §"Upstream pools"):
/// - **`Healthy`**: every member of every pool is up.
/// - **`Degraded`**: at least one member is down, but every pool
///   has at least one healthy member (traffic still routable).
/// - **`Down`**: at least one pool has zero healthy members, OR
///   no pools are configured at all (no upstream to serve).
pub fn compute_summary(snap: &PoolHealthSnapshot) -> UpstreamSummaryResponse {
    let mut healthy_members = 0u32;
    let mut total_members = 0u32;
    let mut any_dead_pool = false;
    let mut any_unhealthy_member = false;

    for pool in &snap.pools {
        healthy_members = healthy_members.saturating_add(pool.healthy);
        total_members = total_members.saturating_add(pool.total);
        if pool.healthy < pool.total {
            any_unhealthy_member = true;
        }
        // A pool is "dead" if it has no routable members — either
        // because every member is down OR because it has no members
        // at all (misconfiguration).
        if pool.total == 0 || pool.healthy == 0 {
            any_dead_pool = true;
        }
    }

    let state = if snap.pools.is_empty() || any_dead_pool {
        "Down"
    } else if any_unhealthy_member {
        "Degraded"
    } else {
        "Healthy"
    };

    UpstreamSummaryResponse {
        state,
        healthy_members,
        total_members,
        pools: snap.pools.clone(),
    }
}

/// HTTP-side wrapper. Holds a snapshot-provider closure plugged in
/// by the proxy and caches the rendered JSON for `cache_ttl`.
pub struct UpstreamHandler {
    provider: Box<dyn Fn() -> PoolHealthSnapshot + Send + Sync>,
    cache: Mutex<Option<(Instant, UpstreamSummaryResponse)>>,
    cache_ttl: Duration,
}

impl UpstreamHandler {
    pub fn new<F>(provider: F) -> Self
    where
        F: Fn() -> PoolHealthSnapshot + Send + Sync + 'static,
    {
        Self::with_ttl(provider, DEFAULT_CACHE_TTL)
    }

    pub fn with_ttl<F>(provider: F, cache_ttl: Duration) -> Self
    where
        F: Fn() -> PoolHealthSnapshot + Send + Sync + 'static,
    {
        Self {
            provider: Box::new(provider),
            cache: Mutex::new(None),
            cache_ttl,
        }
    }

    /// Return the JSON body for `GET /api/upstreams/summary`. Cached
    /// for `cache_ttl` so consecutive Tracking-page polls don't
    /// re-walk the cluster member list.
    pub fn render(&self) -> String {
        let now = Instant::now();
        {
            let cache = self.cache.lock().expect("upstreams cache poisoned");
            if let Some((stamped_at, response)) = cache.as_ref() {
                if now.duration_since(*stamped_at) < self.cache_ttl {
                    return serde_json::to_string(response)
                        .unwrap_or_else(|_| String::from("{}"));
                }
            }
        }

        // Cache miss: pull a fresh snapshot from the provider closure
        // and render it.
        let snap = (self.provider)();
        let response = compute_summary(&snap);
        let body = serde_json::to_string(&response).unwrap_or_else(|_| String::from("{}"));
        let mut cache = self.cache.lock().expect("upstreams cache poisoned");
        *cache = Some((now, response));
        body
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(name: &str, healthy: u32, total: u32) -> PoolHealthEntry {
        PoolHealthEntry {
            name: name.into(),
            healthy,
            total,
        }
    }

    fn snap(pools: Vec<PoolHealthEntry>) -> PoolHealthSnapshot {
        PoolHealthSnapshot { pools }
    }

    #[test]
    fn empty_snapshot_is_down() {
        // Zero pools = nothing to serve. Down per spec.
        let s = compute_summary(&snap(vec![]));
        assert_eq!(s.state, "Down");
        assert_eq!(s.healthy_members, 0);
        assert_eq!(s.total_members, 0);
        assert!(s.pools.is_empty());
    }

    #[test]
    fn all_pools_fully_healthy_is_healthy() {
        let s = compute_summary(&snap(vec![
            pool("api-pool", 3, 3),
            pool("static-pool", 2, 2),
        ]));
        assert_eq!(s.state, "Healthy");
        assert_eq!(s.healthy_members, 5);
        assert_eq!(s.total_members, 5);
        assert_eq!(s.pools.len(), 2);
    }

    #[test]
    fn partially_healthy_pool_is_degraded() {
        let s = compute_summary(&snap(vec![
            pool("api-pool", 2, 3),         // 1 down
            pool("static-pool", 2, 2),
        ]));
        assert_eq!(s.state, "Degraded");
        assert_eq!(s.healthy_members, 4);
        assert_eq!(s.total_members, 5);
    }

    #[test]
    fn pool_with_zero_healthy_is_down() {
        // Even if other pools are healthy, an entirely-down pool means
        // some upstream is unroutable -> Down per spec.
        let s = compute_summary(&snap(vec![
            pool("api-pool", 0, 3),         // entirely down
            pool("static-pool", 2, 2),
        ]));
        assert_eq!(s.state, "Down");
        assert_eq!(s.healthy_members, 2);
        assert_eq!(s.total_members, 5);
    }

    #[test]
    fn single_pool_zero_healthy_is_down() {
        let s = compute_summary(&snap(vec![pool("only", 0, 4)]));
        assert_eq!(s.state, "Down");
        assert_eq!(s.healthy_members, 0);
        assert_eq!(s.total_members, 4);
    }

    #[test]
    fn pool_with_zero_total_is_down() {
        // An empty pool (no members) can't serve traffic.
        let s = compute_summary(&snap(vec![pool("empty", 0, 0)]));
        assert_eq!(s.state, "Down");
        assert_eq!(s.total_members, 0);
    }

    #[test]
    fn pool_entries_preserved_in_response() {
        // The page renders per-pool rows, so the entries in the
        // snapshot must round-trip into the response unchanged.
        let s = compute_summary(&snap(vec![
            pool("a", 1, 1),
            pool("b", 1, 2),
            pool("c", 0, 1),
        ]));
        assert_eq!(s.pools.len(), 3);
        assert_eq!(s.pools[0].name, "a");
        assert_eq!(s.pools[1].healthy, 1);
        assert_eq!(s.pools[1].total, 2);
        assert_eq!(s.pools[2].healthy, 0);
    }

    #[test]
    fn response_serializes_to_documented_shape() {
        let s = compute_summary(&snap(vec![pool("api", 2, 3)]));
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        let obj = json.as_object().expect("top-level object");
        for key in ["state", "healthy_members", "total_members", "pools"] {
            assert!(obj.contains_key(key), "response missing {key}");
        }
        let pools = obj["pools"].as_array().expect("pools array");
        let first = pools[0].as_object().expect("pool object");
        for key in ["name", "healthy", "total"] {
            assert!(first.contains_key(key), "pool entry missing {key}");
        }
    }

    #[test]
    fn handler_caches_response_within_ttl() {
        // Provider invocations are tracked via a counter; a second
        // render() within TTL must NOT call the provider again.
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let calls_clone = std::sync::Arc::clone(&calls);
        let h = UpstreamHandler::with_ttl(
            move || {
                calls_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                snap(vec![pool("a", 1, 1)])
            },
            Duration::from_secs(1),
        );
        let _ = h.render();
        let _ = h.render();
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn handler_invalidates_after_ttl() {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let calls_clone = std::sync::Arc::clone(&calls);
        let h = UpstreamHandler::with_ttl(
            move || {
                calls_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                snap(vec![pool("a", 1, 1)])
            },
            Duration::from_millis(20),
        );
        let _ = h.render();
        std::thread::sleep(Duration::from_millis(40));
        let _ = h.render();
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    #[test]
    fn handler_render_emits_valid_json() {
        let h = UpstreamHandler::new(|| snap(vec![pool("a", 1, 1)]));
        let json = h.render();
        let v: serde_json::Value =
            serde_json::from_str(&json).expect("render must emit valid JSON");
        // The cached state propagates to the rendered body.
        assert_eq!(v["state"].as_str(), Some("Healthy"));
    }
}
