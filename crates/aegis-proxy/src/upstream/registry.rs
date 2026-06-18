//! CC-T1.1.b — hot-swappable pool registry.
//!
//! Replaces the previous `HashMap<String, Pool>` field on
//! `ProxyContext` with an `Arc<ArcSwap<…>>` so the audit-mutated
//! `PUT /api/upstreams/config`, `PUT /api/upstreams/pool/{id}`,
//! and `DELETE /api/upstreams/pool/{id}` handlers can replace
//! the live pool table without bouncing the proxy.
//!
//! ## Hot-path cost
//!
//! `get` / `breaker` cost one `ArcSwap::load` (~ns) plus one
//! `HashMap::get`. The returned `Arc<Pool>` keeps the previous
//! map alive for any in-flight request that already grabbed it,
//! so a swap mid-request never invalidates the borrow chain
//! (`pool.strategy`, `pool.members`, `pool.connection`).
//!
//! ## Apply semantics
//!
//! `apply(new_pools)` rebuilds `Pool` + `CircuitBreaker` from the
//! supplied `PoolConfig` map and swaps both stores atomically.
//! Validation runs *first* — if any pool fails [`validate_pool`]
//! the swap is skipped and the registry is untouched. The
//! audit-mutated handler converts the validation failure into a
//! `MutationError::Validation` so the dashboard sees a stable
//! `reason_code`.

use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use arc_swap::ArcSwap;

use aegis_core::config::PoolConfig;
use aegis_control::api::upstreams_config::{
    validate_pool, PoolValidationError,
};

use crate::upstream::circuit::CircuitBreaker;
use crate::upstream::lb::LbStrategy;
use crate::upstream::{Member, Pool};

/// `(pools, breakers)` map pair returned by [`PoolRegistry::build_pools`].
pub type BuiltPools = (
    HashMap<String, Arc<Pool>>,
    HashMap<String, Arc<CircuitBreaker>>,
);

/// Hot-swappable pool + circuit-breaker store.
///
/// Cheap to clone — internals are `Arc`. Both inner maps are
/// updated together by [`Self::apply`] so the breaker store
/// never references a pool that no longer exists.
#[derive(Clone)]
pub struct PoolRegistry {
    pools: Arc<ArcSwap<HashMap<String, Arc<Pool>>>>,
    breakers: Arc<ArcSwap<HashMap<String, Arc<CircuitBreaker>>>>,
    /// FIX 2026-05-04 — admin-side `/api/upstreams/config` GET +
    /// the route handler's pool-existence check both want the
    /// *config* shape (`PoolConfig` with full members,
    /// connection settings, host_header overrides). The compiled
    /// `Pool` map throws that detail away — it's stored as
    /// `Arc<Member>` etc. We shadow the raw config alongside so
    /// readers can get the post-runtime-mutation truth without
    /// having to reconstruct it from the compiled Pool.
    raw: Arc<ArcSwap<HashMap<String, PoolConfig>>>,
    /// P2 — the shared fleet upstream-mTLS identity, seeded at boot
    /// (`seed_upstream_identity`). `apply` reuses it so a runtime
    /// pool re-apply re-resolves each pool's client cert against the
    /// same identity. `None` ⇒ no pool can have upstream mTLS.
    upstream_identity: Arc<ArcSwap<Option<aegis_core::config::UpstreamIdentityConfig>>>,
}

impl PoolRegistry {
    /// Build an empty registry. Useful for tests; production paths
    /// use [`Self::from_pools`].
    pub fn empty() -> Self {
        Self {
            pools: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            breakers: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            raw: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            upstream_identity: Arc::new(ArcSwap::from_pointee(None)),
        }
    }

    /// Construct directly from already-built `Pool` + breaker
    /// maps. Used by `ProxyContext::build` (boot path) so the
    /// existing config-derivation logic isn't duplicated here.
    pub fn from_pools(
        pools: HashMap<String, Arc<Pool>>,
        breakers: HashMap<String, Arc<CircuitBreaker>>,
    ) -> Self {
        Self {
            pools: Arc::new(ArcSwap::from_pointee(pools)),
            breakers: Arc::new(ArcSwap::from_pointee(breakers)),
            // Boot path also calls `seed_raw` after this — until
            // it does, the GET endpoint will see an empty map
            // and fall back to the cfg snapshot.
            raw: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            upstream_identity: Arc::new(ArcSwap::from_pointee(None)),
        }
    }

    /// Boot path uses this to seed the raw config shadow with
    /// the boot snapshot. After boot, `apply` keeps it in sync.
    pub fn seed_raw(&self, raw: HashMap<String, PoolConfig>) {
        self.raw.store(Arc::new(raw));
    }

    /// P2 — seed the shared upstream-mTLS identity at boot so
    /// `apply` can re-resolve pool client certs against it on a
    /// runtime pool re-apply.
    pub fn seed_upstream_identity(
        &self,
        identity: Option<aegis_core::config::UpstreamIdentityConfig>,
    ) {
        self.upstream_identity.store(Arc::new(identity));
    }

    /// Snapshot of the live raw pool configs — used by the
    /// admin GET endpoint and the route handler so they see
    /// runtime-added pools with their full member detail (not
    /// the empty placeholder we used to insert).
    pub fn current_pools(&self) -> HashMap<String, PoolConfig> {
        (**self.raw.load()).clone()
    }

    /// Build a new registry from a config map. Pure: doesn't read
    /// or modify any registry state. Returns the typed validation
    /// error on failure so the caller can surface a stable
    /// `reason_code` to the dashboard.
    pub fn build_pools(
        upstreams: &HashMap<String, PoolConfig>,
        upstream_identity: Option<&aegis_core::config::UpstreamIdentityConfig>,
    ) -> Result<BuiltPools, PoolValidationError> {
        for cfg in upstreams.values() {
            validate_pool(cfg)?;
        }
        let mut pools: HashMap<String, Arc<Pool>> = HashMap::with_capacity(upstreams.len());
        let mut breakers: HashMap<String, Arc<CircuitBreaker>> =
            HashMap::with_capacity(upstreams.len());
        for (name, cfg) in upstreams {
            let members: Vec<Arc<Member>> = cfg
                .members
                .iter()
                .map(|mc| {
                    // 2026-05-11 (PR-DNS-1) — hostnames must have
                    // been resolved into IP literals before this
                    // point. The boot path runs
                    // `aegis_proxy::upstream::dns_resolve::
                    // expand_hostname_members` first; if anyone
                    // builds a registry from a hostname-shaped
                    // config we fail loudly with a stable
                    // `PoolValidationError` instead of silently
                    // dropping the member.
                    let sa = match &mc.addr {
                        aegis_core::config::MemberAddrSpec::Ip(sa) => *sa,
                        aegis_core::config::MemberAddrSpec::Hostname {
                            host,
                            port,
                            ..
                        } => {
                            return Err(PoolValidationError::UnresolvedHostname {
                                host: host.clone(),
                                port: *port,
                            });
                        }
                    };
                    // 2026-05-03 PM — when the operator pinned a
                    // Host header on this member, register the
                    // hostname → addr mapping with the global
                    // pinned resolver so the HTTPS forwarder can
                    // build URLs using the hostname (correct SNI +
                    // cert validation) while still connecting to
                    // the configured IP.  Idempotent — re-running
                    // boot or reloading cfg simply re-installs.
                    if let Some(host) = mc.host_header.as_deref() {
                        crate::upstream::pinned_resolver::global()
                            .register(host.to_string(), sa);
                    }
                    Ok(Arc::new(Member::with_host_override(
                        sa,
                        mc.weight,
                        mc.zone.clone(),
                        mc.host_header.clone(),
                    )))
                })
                .collect::<Result<Vec<_>, PoolValidationError>>()?;
            let strategy = match cfg.lb {
                aegis_core::config::LbStrategy::RoundRobin => {
                    LbStrategy::RoundRobin(AtomicUsize::new(0))
                }
                aegis_core::config::LbStrategy::WeightedRoundRobin => {
                    LbStrategy::WeightedRoundRobin(AtomicUsize::new(0))
                }
                aegis_core::config::LbStrategy::LeastConn => LbStrategy::LeastConn,
                aegis_core::config::LbStrategy::P2c => LbStrategy::P2c,
                aegis_core::config::LbStrategy::ConsistentHash => LbStrategy::ConsistentHash,
            };
            if let Some(cb_cfg) = &cfg.circuit_breaker {
                breakers.insert(
                    name.clone(),
                    Arc::new(CircuitBreaker::new(
                        cb_cfg.error_rate_threshold,
                        10, // min_requests default
                        cb_cfg.open_duration,
                    )),
                );
            }
            // P2 — resolve this pool's upstream-mTLS material from
            // its `upstream_mtls` block + the shared fleet identity,
            // and attach it to the cloned connection config so
            // `forward::build_client` presents the client cert and
            // `PoolKey` includes the cert fingerprint.
            let mut connection = cfg.connection.clone();
            connection.upstream_mtls =
                aegis_core::config::resolve_upstream_mtls(cfg, upstream_identity);
            pools.insert(
                name.clone(),
                Arc::new(Pool {
                    name: name.clone(),
                    members,
                    strategy,
                    connection,
                }),
            );
        }
        Ok((pools, breakers))
    }

    /// Hot-path read. Returns an owning `Arc<Pool>` so the
    /// caller's borrow survives any concurrent swap.
    pub fn get(&self, name: &str) -> Option<Arc<Pool>> {
        self.pools.load().get(name).cloned()
    }

    /// Hot-path read for the matching circuit breaker (if any).
    pub fn breaker(&self, name: &str) -> Option<Arc<CircuitBreaker>> {
        self.breakers.load().get(name).cloned()
    }

    /// Snapshot the current pool map. Used by the dashboard
    /// renderer so consecutive reads see a consistent view.
    pub fn snapshot(&self) -> Arc<HashMap<String, Arc<Pool>>> {
        self.pools.load_full()
    }

    /// Per-pool health counts. Derived from the live
    /// `Member::is_healthy()` flag — boot-time pools are all
    /// healthy until a probe flips them; real numbers track
    /// the active health-check loop. Used by the
    /// `waf_upstream_members_*` Prometheus gauges.
    pub fn health_counts(
        &self,
    ) -> Vec<aegis_control::metrics::upstream_pools::PoolHealthCounts> {
        let snap = self.snapshot();
        let mut out: Vec<_> = snap
            .iter()
            .map(|(name, pool)| {
                let total = pool.members.len() as u32;
                let healthy = pool
                    .members
                    .iter()
                    .filter(|m| m.is_healthy())
                    .count() as u32;
                aegis_control::metrics::upstream_pools::PoolHealthCounts {
                    name: name.clone(),
                    healthy,
                    total,
                }
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// Replace the entire pool table atomically. Validates first;
    /// on failure the registry is untouched. New connections after
    /// the swap use the new pools; in-flight requests that already
    /// grabbed an `Arc<Pool>` finish on the old one.
    ///
    /// Connection-pool stats (per-host idle keep-alive pools) are
    /// **rebuilt from scratch** for any pool whose `connection`
    /// config changed; for pools that retained their previous
    /// connection signature, hyper-util's pool keys still match.
    pub fn apply(
        &self,
        new_pools: &HashMap<String, PoolConfig>,
    ) -> Result<(), PoolValidationError> {
        let identity = self.upstream_identity.load();
        let (pools, breakers) = Self::build_pools(new_pools, (**identity).as_ref())?;
        self.pools.store(Arc::new(pools));
        self.breakers.store(Arc::new(breakers));
        // Keep the raw shadow in lock-step so admin reads see
        // the latest runtime-applied pool config.
        self.raw.store(Arc::new(new_pools.clone()));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// UpstreamWriter trait impl — bridge to aegis-control handlers
// ---------------------------------------------------------------------------

impl aegis_control::api::upstreams_config::UpstreamWriter for PoolRegistry {
    fn apply(
        &self,
        new_pools: &HashMap<String, PoolConfig>,
    ) -> Result<(), PoolValidationError> {
        Self::apply(self, new_pools)
    }

    fn current_pools(&self) -> HashMap<String, PoolConfig> {
        PoolRegistry::current_pools(self)
    }

    fn live_snapshot(
        &self,
    ) -> aegis_control::api::upstreams::PoolHealthSnapshot {
        use crate::upstream::circuit::State;
        let snap = self.snapshot();
        let breakers = self.breakers.load();
        let pools = snap
            .iter()
            .map(|(name, pool)| {
                use aegis_control::api::upstreams::MemberStatus;
                let total = pool.members.len() as u32;
                let members: Vec<_> = pool
                    .members
                    .iter()
                    .map(|m| {
                        // 2026-06-18 (upstream "up" badge report): report the
                        // *verified* observed status for display. The legacy
                        // `healthy` bool (used for rollup counts) follows the
                        // observed result once we have one, and falls back to
                        // the optimistic LB flag while still `Unknown` so the
                        // pre-probe boot window doesn't regress the counts.
                        let status = m.observed_status();
                        let healthy = match status {
                            MemberStatus::Up => true,
                            MemberStatus::Down => false,
                            MemberStatus::Unknown => m.is_healthy(),
                        };
                        aegis_control::api::upstreams::MemberHealth {
                            addr: m.addr.to_string(),
                            healthy,
                            status,
                        }
                    })
                    .collect();
                let healthy = members.iter().filter(|m| m.healthy).count() as u32;
                // Circuit state is per-pool (the registry keys breakers
                // by pool name). Absent when no breaker is configured.
                let circuit = breakers.get(name).map(|cb| {
                    match cb.state() {
                        State::Closed => "closed",
                        State::Open => "open",
                        State::HalfOpen => "half_open",
                    }
                    .to_string()
                });
                aegis_control::api::upstreams::PoolHealthEntry {
                    name: name.clone(),
                    healthy,
                    total,
                    members,
                    circuit,
                }
            })
            .collect();
        aegis_control::api::upstreams::PoolHealthSnapshot { pools }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn pool_cfg(addr: &str) -> PoolConfig {
        let yaml = format!(
            r#"
members:
  - addr: "{addr}"
    weight: 1
lb: round_robin
"#
        );
        serde_yaml::from_str(&yaml).expect("test yaml")
    }

    fn pool_cfg_with_cb(addr: &str) -> PoolConfig {
        let yaml = format!(
            r#"
members:
  - addr: "{addr}"
    weight: 1
lb: round_robin
circuit_breaker:
  error_rate_threshold: 0.5
  open_duration: "30s"
"#
        );
        serde_yaml::from_str(&yaml).expect("test yaml")
    }

    fn cfg_map(entries: &[(&str, PoolConfig)]) -> HashMap<String, PoolConfig> {
        entries
            .iter()
            .map(|(n, c)| ((*n).to_string(), c.clone()))
            .collect()
    }

    // ----- build_pools ----------------------------------------------------

    #[test]
    fn build_pools_constructs_arc_pool_per_entry() {
        let cfg = cfg_map(&[
            ("a", pool_cfg("127.0.0.1:3001")),
            ("b", pool_cfg("127.0.0.1:3002")),
        ]);
        let (pools, breakers) = PoolRegistry::build_pools(&cfg, None).unwrap();
        assert_eq!(pools.len(), 2);
        assert!(pools.contains_key("a"));
        assert!(pools.contains_key("b"));
        // No circuit_breaker block → no breaker entries.
        assert!(breakers.is_empty());
    }

    #[test]
    fn build_pools_creates_breaker_only_when_config_present() {
        let cfg = cfg_map(&[
            ("a", pool_cfg("127.0.0.1:3001")),
            ("b", pool_cfg_with_cb("127.0.0.1:3002")),
        ]);
        let (_pools, breakers) = PoolRegistry::build_pools(&cfg, None).unwrap();
        assert_eq!(breakers.len(), 1);
        assert!(breakers.contains_key("b"));
        assert!(!breakers.contains_key("a"));
    }

    #[test]
    fn build_pools_rejects_invalid_pool() {
        // Empty members → validator rejects.
        let mut bad = pool_cfg("127.0.0.1:3001");
        bad.members.clear();
        let cfg = cfg_map(&[("bad", bad)]);
        let err = PoolRegistry::build_pools(&cfg, None).unwrap_err();
        assert_eq!(err, PoolValidationError::EmptyMembers);
    }

    #[test]
    fn build_pools_rejects_zero_weight_member() {
        let mut bad = pool_cfg("127.0.0.1:3001");
        bad.members[0].weight = 0;
        let cfg = cfg_map(&[("bad", bad)]);
        let err = PoolRegistry::build_pools(&cfg, None).unwrap_err();
        assert!(matches!(err, PoolValidationError::ZeroWeight { .. }));
    }

    // ----- get / breaker --------------------------------------------------

    #[test]
    fn get_returns_arc_pool() {
        let cfg = cfg_map(&[("a", pool_cfg("127.0.0.1:3001"))]);
        let (pools, breakers) = PoolRegistry::build_pools(&cfg, None).unwrap();
        let registry = PoolRegistry::from_pools(pools, breakers);
        let p = registry.get("a").expect("present");
        assert_eq!(p.name, "a");
        assert!(registry.get("ghost").is_none());
    }

    #[test]
    fn breaker_returns_only_when_configured() {
        let cfg = cfg_map(&[
            ("a", pool_cfg("127.0.0.1:3001")),
            ("b", pool_cfg_with_cb("127.0.0.1:3002")),
        ]);
        let (pools, breakers) = PoolRegistry::build_pools(&cfg, None).unwrap();
        let registry = PoolRegistry::from_pools(pools, breakers);
        assert!(registry.breaker("a").is_none());
        assert!(registry.breaker("b").is_some());
    }

    #[test]
    fn snapshot_keeps_old_arc_alive_after_swap() {
        // Hot-path safety: a request that grabbed Arc<Pool> before
        // a swap still has a valid pool reference after the swap.
        let cfg_v1 = cfg_map(&[("a", pool_cfg("127.0.0.1:3001"))]);
        let (pools, breakers) = PoolRegistry::build_pools(&cfg_v1, None).unwrap();
        let registry = PoolRegistry::from_pools(pools, breakers);
        let in_flight = registry.get("a").expect("v1 pool");

        // Swap to v2: removes "a", adds "b".
        let cfg_v2 = cfg_map(&[("b", pool_cfg("127.0.0.1:3002"))]);
        registry.apply(&cfg_v2).unwrap();

        // New reads see only "b".
        assert!(registry.get("a").is_none());
        assert!(registry.get("b").is_some());

        // The in-flight Arc still works — name + members intact.
        assert_eq!(in_flight.name, "a");
        assert!(!in_flight.members.is_empty());
    }

    // ----- apply ---------------------------------------------------------

    #[test]
    fn apply_replaces_pools_atomically() {
        let cfg_v1 = cfg_map(&[("a", pool_cfg("127.0.0.1:3001"))]);
        let (pools, breakers) = PoolRegistry::build_pools(&cfg_v1, None).unwrap();
        let registry = PoolRegistry::from_pools(pools, breakers);

        let cfg_v2 = cfg_map(&[
            ("b", pool_cfg("127.0.0.1:3002")),
            ("c", pool_cfg("127.0.0.1:3003")),
        ]);
        registry.apply(&cfg_v2).unwrap();
        assert!(registry.get("a").is_none());
        assert!(registry.get("b").is_some());
        assert!(registry.get("c").is_some());
    }

    #[test]
    fn apply_leaves_registry_untouched_on_validation_error() {
        let cfg_v1 = cfg_map(&[("a", pool_cfg("127.0.0.1:3001"))]);
        let (pools, breakers) = PoolRegistry::build_pools(&cfg_v1, None).unwrap();
        let registry = PoolRegistry::from_pools(pools, breakers);

        // Apply a config with one invalid pool.
        let mut bad = pool_cfg("127.0.0.1:3002");
        bad.members.clear();
        let cfg_bad = cfg_map(&[("a", pool_cfg("127.0.0.1:3001")), ("bad", bad)]);
        let err = registry.apply(&cfg_bad).unwrap_err();
        assert_eq!(err, PoolValidationError::EmptyMembers);

        // Original "a" is still there.
        assert!(registry.get("a").is_some());
        assert!(registry.get("bad").is_none());
    }

    #[test]
    fn apply_swaps_breakers_in_lockstep_with_pools() {
        let cfg_v1 = cfg_map(&[("a", pool_cfg("127.0.0.1:3001"))]);
        let (pools, breakers) = PoolRegistry::build_pools(&cfg_v1, None).unwrap();
        let registry = PoolRegistry::from_pools(pools, breakers);
        assert!(registry.breaker("a").is_none());

        let cfg_v2 = cfg_map(&[("a", pool_cfg_with_cb("127.0.0.1:3001"))]);
        registry.apply(&cfg_v2).unwrap();
        assert!(registry.breaker("a").is_some(), "breaker added on swap");

        // Swap back — breaker disappears.
        let cfg_v3 = cfg_map(&[("a", pool_cfg("127.0.0.1:3001"))]);
        registry.apply(&cfg_v3).unwrap();
        assert!(registry.breaker("a").is_none(), "breaker removed on swap");
    }

    #[test]
    fn apply_to_empty_registry() {
        let registry = PoolRegistry::empty();
        let cfg = cfg_map(&[("a", pool_cfg("127.0.0.1:3001"))]);
        registry.apply(&cfg).unwrap();
        assert!(registry.get("a").is_some());
    }

    #[test]
    fn snapshot_returns_arc_of_full_map() {
        let cfg = cfg_map(&[
            ("a", pool_cfg("127.0.0.1:3001")),
            ("b", pool_cfg("127.0.0.1:3002")),
        ]);
        let (pools, breakers) = PoolRegistry::build_pools(&cfg, None).unwrap();
        let registry = PoolRegistry::from_pools(pools, breakers);
        let snap = registry.snapshot();
        assert_eq!(snap.len(), 2);
        assert!(snap.contains_key("a"));
        assert!(snap.contains_key("b"));
    }

    #[test]
    fn cheap_clone_shares_inner_storage() {
        let cfg = cfg_map(&[("a", pool_cfg("127.0.0.1:3001"))]);
        let (pools, breakers) = PoolRegistry::build_pools(&cfg, None).unwrap();
        let r1 = PoolRegistry::from_pools(pools, breakers);
        let r2 = r1.clone();

        let cfg_v2 = cfg_map(&[("b", pool_cfg("127.0.0.1:3002"))]);
        r1.apply(&cfg_v2).unwrap();
        // r2 sees the swap because they share Arc<ArcSwap>.
        assert!(r2.get("b").is_some());
    }

    #[test]
    fn live_snapshot_starts_with_all_members_healthy() {
        use aegis_control::api::upstreams_config::UpstreamWriter;
        let cfg = cfg_map(&[
            ("a", pool_cfg("127.0.0.1:3001")),
            ("b", pool_cfg("127.0.0.1:3002")),
        ]);
        let (pools, breakers) = PoolRegistry::build_pools(&cfg, None).unwrap();
        let registry = PoolRegistry::from_pools(pools, breakers);
        let snap = registry.live_snapshot();
        assert_eq!(snap.pools.len(), 2);
        for pool in &snap.pools {
            assert_eq!(pool.healthy, pool.total, "{} should be all-healthy at boot", pool.name);
            assert_eq!(pool.total, 1);
        }
    }

    #[test]
    fn live_snapshot_reflects_member_health_flip() {
        use aegis_control::api::upstreams_config::UpstreamWriter;
        use std::sync::atomic::Ordering;
        let cfg = cfg_map(&[("api", pool_cfg("127.0.0.1:3001"))]);
        let (pools, breakers) = PoolRegistry::build_pools(&cfg, None).unwrap();
        let registry = PoolRegistry::from_pools(pools, breakers);

        // Walk the live pool, flip the member's healthy AtomicBool
        // (same flag the health-checker writes), and confirm the
        // snapshot reflects it without rebuilding the registry.
        let live = registry.snapshot();
        let pool = live.get("api").expect("pool present");
        pool.members[0].healthy.store(false, Ordering::Relaxed);

        let snap = registry.live_snapshot();
        let api = snap.pools.iter().find(|p| p.name == "api").unwrap();
        assert_eq!(api.healthy, 0);
        assert_eq!(api.total, 1);
    }

    #[test]
    fn live_snapshot_counts_partial_pool_health() {
        use aegis_control::api::upstreams_config::UpstreamWriter;
        use std::sync::atomic::Ordering;
        // Two members in one pool — flip only the first.
        let yaml = r#"
members:
  - addr: "127.0.0.1:3001"
    weight: 1
  - addr: "127.0.0.1:3002"
    weight: 1
lb: round_robin
"#;
        let pool_cfg: PoolConfig = serde_yaml::from_str(yaml).unwrap();
        let cfg = cfg_map(&[("mixed", pool_cfg)]);
        let (pools, breakers) = PoolRegistry::build_pools(&cfg, None).unwrap();
        let registry = PoolRegistry::from_pools(pools, breakers);

        let live = registry.snapshot();
        let pool = live.get("mixed").unwrap();
        pool.members[0].healthy.store(false, Ordering::Relaxed);

        let snap = registry.live_snapshot();
        let m = snap.pools.iter().find(|p| p.name == "mixed").unwrap();
        assert_eq!(m.healthy, 1);
        assert_eq!(m.total, 2);
    }

    // 2026-06-18 (upstream "up" badge report) — the snapshot reports the
    // verified observed status, and a down observation drops the member
    // from the displayed `healthy` count without touching the LB flag.
    #[test]
    fn live_snapshot_reports_observed_status() {
        use aegis_control::api::upstreams::MemberStatus;
        use aegis_control::api::upstreams_config::UpstreamWriter;
        let cfg = cfg_map(&[("api", pool_cfg("127.0.0.1:3001"))]);
        let (pools, breakers) = PoolRegistry::build_pools(&cfg, None).unwrap();
        let registry = PoolRegistry::from_pools(pools, breakers);

        let live = registry.snapshot();
        let member = &live.get("api").unwrap().members[0];

        // Before any probe: Unknown, but counts fall back to the optimistic
        // LB flag (no boot regression).
        let snap = registry.live_snapshot();
        let api = snap.pools.iter().find(|p| p.name == "api").unwrap();
        assert_eq!(api.members[0].status, MemberStatus::Unknown);
        assert_eq!(api.healthy, 1);

        // A verified-down observation: status Down, dropped from the count,
        // but the LB routing flag is untouched.
        member.set_observed(false);
        let snap = registry.live_snapshot();
        let api = snap.pools.iter().find(|p| p.name == "api").unwrap();
        assert_eq!(api.members[0].status, MemberStatus::Down);
        assert!(!api.members[0].healthy);
        assert_eq!(api.healthy, 0);
        assert!(member.is_healthy(), "LB flag must stay optimistic");

        // Verified-up.
        member.set_observed(true);
        let snap = registry.live_snapshot();
        let api = snap.pools.iter().find(|p| p.name == "api").unwrap();
        assert_eq!(api.members[0].status, MemberStatus::Up);
        assert_eq!(api.healthy, 1);
    }

    // Suppress unused-import warning when no test uses `Duration`.
    #[allow(dead_code)]
    fn _unused() -> Duration {
        Duration::from_secs(1)
    }
}
