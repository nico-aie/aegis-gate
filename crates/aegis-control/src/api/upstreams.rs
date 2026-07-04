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
//! Spec: `docs/control-plane/enterprise/api.md` §"Tracking page" and
//! `docs/control-plane/enterprise/pages/overview.md` §"Upstream pools".


use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Default response cache TTL. The Tracking page polls
/// `/api/tracking/snapshot` at 5 s but pages can override; 2 s
/// matches `docs/control-plane/enterprise/api.md` §"Caching" for the
/// tracking-snapshot family.
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(2);

/// Observed liveness of a single upstream member.
///
/// 2026-06-18 (upstream "up" badge report): members are born optimistically
/// `healthy = true` and only an *active* health check ever flips them. Pools
/// without a `health:` block were therefore reported `up` unconditionally —
/// the badge meant "configured", not "verified reachable". `Unknown`
/// distinguishes "no health signal yet" (grey) from a verified `Up`/`Down`,
/// so the dashboard never claims a backend is up that nothing ever checked.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MemberStatus {
    /// No health signal yet (no probe has run, or none is configured).
    #[default]
    Unknown,
    /// Verified reachable by an active HTTP health check or a TCP probe.
    Up,
    /// Verified unreachable / failing.
    Down,
}

/// Per-member health line. Additive detail for the Routing & Upstreams
/// page so operators see *which* backend is down, not just a count.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemberHealth {
    pub addr: String,
    /// Legacy boolean retained for the rollup counts + older clients. For a
    /// member with a real signal it equals `status == Up`; before any probe
    /// runs it falls back to the optimistic routing flag so counts don't
    /// regress at boot. Prefer [`Self::status`] for display.
    pub healthy: bool,
    /// Tri-state observed liveness. `#[serde(default)]` ⇒ `Unknown` so older
    /// snapshots (no `status` key) still deserialize.
    #[serde(default)]
    pub status: MemberStatus,
    /// Zone-aware LB P3 — this member's availability zone (`MemberConfig.zone`),
    /// or `None` if unlabeled. Additive; omitted from JSON when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    /// Zone-aware LB P3 — `true` when this member's zone matches the node's
    /// own zone (the dashboard tints local members). Convenience flag so the
    /// frontend doesn't re-derive it per member.
    #[serde(default)]
    pub is_local: bool,
}

/// Zone-aware LB P3 — per-zone health rollup for one pool's member set. Lets
/// the dashboard card show "az-a: 2/3 healthy · serving local" so spillover
/// state is legible.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZoneHealth {
    pub zone: String,
    pub healthy: u32,
    pub total: u32,
    /// `true` when this zone is the node's own.
    pub local: bool,
}

/// Roll a pool's members up by zone (zone-aware LB P3). Unlabeled members are
/// grouped under the empty-string zone and are never `local`. Output is sorted
/// by zone name for stable rendering.
pub fn zone_rollup(members: &[MemberHealth], self_zone: Option<&str>) -> Vec<ZoneHealth> {
    use std::collections::BTreeMap;
    let mut by_zone: BTreeMap<&str, (u32, u32)> = BTreeMap::new();
    for m in members {
        let z = m.zone.as_deref().unwrap_or("");
        let entry = by_zone.entry(z).or_insert((0, 0));
        entry.1 += 1; // total
        if m.healthy {
            entry.0 += 1; // healthy
        }
    }
    by_zone
        .into_iter()
        .map(|(zone, (healthy, total))| ZoneHealth {
            zone: zone.to_string(),
            healthy,
            total,
            local: self_zone.is_some_and(|sz| !zone.is_empty() && zone == sz),
        })
        .collect()
}

/// Snapshot of one upstream pool. Cheap value type so the `aegis-proxy`
/// side can build it from `Pool::members.iter().map(|m| m.is_healthy())`
/// without exposing its internal types upward.
///
/// `members` + `circuit` are additive (2026-06-04, routing-upstream #1):
/// per-member health + the pool's circuit-breaker state
/// (`closed`/`open`/`half_open`, absent when no breaker is configured).
/// Both `#[serde(default)]` so older snapshots still deserialize.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PoolHealthEntry {
    pub name: String,
    pub healthy: u32,
    pub total: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<MemberHealth>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circuit: Option<String>,
    /// Zone-aware LB P3 — per-zone health rollup (derived in `compute_summary`
    /// from `members`). Empty when members carry no zone labels.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub zones: Vec<ZoneHealth>,
}

/// Input to [`compute_summary`]. A list of `PoolHealthEntry`. The
/// proxy re-builds this on every read from the cluster state.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PoolHealthSnapshot {
    pub pools: Vec<PoolHealthEntry>,
    /// Zone-aware LB P3 — the node's own availability zone, so the dashboard
    /// can render "this node: az-a" and tint local members. `None` ⇒ no zone
    /// identity. Set proxy-side from `ProxyContext.self_zone`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_zone: Option<String>,
}

/// JSON shape returned by `GET /api/upstreams/summary`. Matches
/// `docs/control-plane/enterprise/api.md`. State is one of
/// `Healthy | Degraded | Down` — the spec is explicit there are
/// only 3 states (no `Unknown`).
#[derive(Clone, Debug, Serialize)]
pub struct UpstreamSummaryResponse {
    pub state: &'static str,
    pub healthy_members: u32,
    pub total_members: u32,
    pub pools: Vec<PoolHealthEntry>,
    /// Zone-aware LB P3 — the node's own zone (echoed from the snapshot) for
    /// the "this node: az-a" readout. Omitted when no zone identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_zone: Option<String>,
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

    // Zone-aware LB P3 — attach the per-zone rollup to each pool (derived from
    // its members + the node's self-zone) so the dashboard card can show
    // per-zone healthy counts and which zone is local.
    let self_zone = snap.self_zone.as_deref();
    let pools = snap
        .pools
        .iter()
        .map(|p| {
            let mut p = p.clone();
            p.zones = zone_rollup(&p.members, self_zone);
            p
        })
        .collect();

    UpstreamSummaryResponse {
        state,
        healthy_members,
        total_members,
        pools,
        self_zone: snap.self_zone.clone(),
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

    /// Typed snapshot for callers that need the response directly
    /// (e.g., `tracking::TrackingHandler::render_snapshot` composes
    /// the upstream summary into the aggregate without round-tripping
    /// through JSON).
    pub fn snapshot(&self) -> UpstreamSummaryResponse {
        compute_summary(&(self.provider)())
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
            ..Default::default()
        }
    }

    fn snap(pools: Vec<PoolHealthEntry>) -> PoolHealthSnapshot {
        PoolHealthSnapshot { pools, ..Default::default() }
    }

    #[test]
    fn per_member_health_and_circuit_round_trip_through_summary() {
        // routing-upstream #1 — the additive members[] + circuit fields
        // survive compute_summary (which clones pools into the response).
        let entry = PoolHealthEntry {
            name: "api".into(),
            healthy: 1,
            total: 2,
            members: vec![
                MemberHealth { addr: "10.0.0.1:80".into(), healthy: true, status: MemberStatus::Up, ..Default::default() },
                MemberHealth { addr: "10.0.0.2:80".into(), healthy: false, status: MemberStatus::Down, ..Default::default() },
            ],
            circuit: Some("open".into()),
            ..Default::default()
        };
        let resp = compute_summary(&snap(vec![entry]));
        assert_eq!(resp.state, "Degraded"); // 1 of 2 healthy
        let p = &resp.pools[0];
        assert_eq!(p.members.len(), 2);
        assert!(p.members[0].healthy && !p.members[1].healthy);
        assert_eq!(p.circuit.as_deref(), Some("open"));
        // The fields serialize for the dashboard.
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"10.0.0.2:80\"") && json.contains("\"circuit\":\"open\""));
    }

    // Zone-aware LB P3 — per-zone observability.

    fn zmember(addr: &str, healthy: bool, zone: Option<&str>) -> MemberHealth {
        MemberHealth {
            addr: addr.into(),
            healthy,
            status: if healthy { MemberStatus::Up } else { MemberStatus::Down },
            zone: zone.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn zone_rollup_groups_counts_and_marks_local() {
        let members = vec![
            zmember("10.0.0.1:80", true, Some("az-a")),
            zmember("10.0.0.2:80", false, Some("az-a")),
            zmember("10.0.0.3:80", true, Some("az-b")),
        ];
        let zones = zone_rollup(&members, Some("az-a"));
        // Sorted by zone name for stable rendering.
        assert_eq!(zones.len(), 2);
        let az_a = zones.iter().find(|z| z.zone == "az-a").unwrap();
        assert_eq!((az_a.healthy, az_a.total), (1, 2));
        assert!(az_a.local, "az-a matches the node's zone");
        let az_b = zones.iter().find(|z| z.zone == "az-b").unwrap();
        assert_eq!((az_b.healthy, az_b.total), (1, 1));
        assert!(!az_b.local);
    }

    #[test]
    fn zone_rollup_unlabeled_members_are_not_local() {
        let members = vec![zmember("10.0.0.1:80", true, None)];
        let zones = zone_rollup(&members, Some("az-a"));
        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].zone, "");
        assert!(!zones[0].local);
    }

    #[test]
    fn self_zone_and_per_zone_summary_flow_through_compute_summary() {
        let entry = PoolHealthEntry {
            name: "api".into(),
            healthy: 1,
            total: 2,
            members: vec![
                zmember("10.0.0.1:80", true, Some("az-a")),
                zmember("10.0.0.2:80", false, Some("az-b")),
            ],
            ..Default::default()
        };
        let snapshot = PoolHealthSnapshot {
            pools: vec![entry],
            self_zone: Some("az-a".into()),
        };
        let resp = compute_summary(&snapshot);
        assert_eq!(resp.self_zone.as_deref(), Some("az-a"));
        // The per-zone rollup is attached to the pool for the dashboard card.
        let zones = &resp.pools[0].zones;
        assert_eq!(zones.len(), 2);
        assert!(zones.iter().any(|z| z.zone == "az-a" && z.local));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"self_zone\":\"az-a\""));
    }

    #[test]
    fn member_status_serializes_lowercase() {
        // The dashboard matches on these exact strings.
        assert_eq!(serde_json::to_string(&MemberStatus::Up).unwrap(), "\"up\"");
        assert_eq!(serde_json::to_string(&MemberStatus::Down).unwrap(), "\"down\"");
        assert_eq!(
            serde_json::to_string(&MemberStatus::Unknown).unwrap(),
            "\"unknown\""
        );
    }

    #[test]
    fn member_health_defaults_status_to_unknown_when_absent() {
        // 2026-06-18 — a snapshot from before the tri-state landed (no
        // `status` key) deserializes as Unknown, not a false "up".
        let m: MemberHealth =
            serde_json::from_str(r#"{"addr":"10.0.0.1:80","healthy":true}"#).unwrap();
        assert_eq!(m.status, MemberStatus::Unknown);
        assert!(m.healthy);
    }

    #[test]
    fn member_health_status_round_trips() {
        let m = MemberHealth {
            addr: "1.2.3.4:80".into(),
            healthy: false,
            status: MemberStatus::Down,
            ..Default::default()
        };
        let back: MemberHealth =
            serde_json::from_str(&serde_json::to_string(&m).unwrap()).unwrap();
        assert_eq!(back.status, MemberStatus::Down);
    }

    #[test]
    fn legacy_snapshot_without_members_still_deserializes() {
        // Old snapshots (no members/circuit keys) must still parse —
        // both fields are #[serde(default)].
        let e: PoolHealthEntry =
            serde_json::from_str(r#"{"name":"p","healthy":2,"total":2}"#).unwrap();
        assert_eq!(e.total, 2);
        assert!(e.members.is_empty());
        assert!(e.circuit.is_none());
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
