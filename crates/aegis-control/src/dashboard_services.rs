//! Dashboard service bundle (D-M2-T2.7).
//!
//! One struct that owns every aggregator, handler, and provider
//! closure the new `/api/*` endpoints need. The proxy admin
//! listener constructs this once at boot and shares it with every
//! request via `Arc`.
//!
//! The bundle also spawns a single audit-bus drain task that feeds
//! both the stats and the attacks aggregators from the same
//! subscriber — one channel reader, two recipients, no extra
//! hot-path cost on the data plane.

#![allow(dead_code)]

use std::sync::Arc;

use aegis_core::audit::AuditEvent;
use aegis_core::{AuditBus, LoadGauge, LoadModeConfig, SharedVerbosity};
use aegis_security::detectors::SharedDetectorMask;
use aegis_security::rate_limit::IpRateLimiter;
use aegis_security::risk::RiskTracker;

use crate::admin_auth::rate_limit::LoginRateLimiter;
use crate::admin_auth::session::SessionStore as AuthSessionStore;
use crate::api::{
    admin::{BreakGlass, SessionStore},
    attacks::{AttacksAggregator, AttacksHandler},
    audit::{AuditHandler, AuditRing, WitnessHandler, WitnessState},
    blacklist::AccessListStore,
    filters::{FilterCatalogue, FiltersHandler},
    login::AdminIdentity,
    mutation::AuditedMutate,
    routes::RoutesHandler,
    rules::{RuleStats, RuleStore},
    stats::{StatsAggregator, StatsHandler, UpstreamSummary},
    tiers::TierStore,
    tracking::TrackingHandler,
    upstreams::{compute_summary, PoolHealthEntry, PoolHealthSnapshot, UpstreamHandler},
};

/// Closure type for "give me the current cluster pool state" —
/// plugged in by the proxy at construction time. For now the proxy
/// builds a config-derived snapshot (pool names + 0/0 health)
/// because per-member health requires the cluster runtime which
/// is itself stubbed; T2.7's commitment is the wire-up, not the
/// data-source quality.
pub type PoolSnapshotProvider =
    Arc<dyn Fn() -> PoolHealthSnapshot + Send + Sync + 'static>;

/// Bundle of every dashboard handler. Cheap to clone (everything
/// is `Arc`).
#[derive(Clone)]
pub struct DashboardServices {
    pub stats: Arc<StatsHandler>,
    pub stats_agg: Arc<StatsAggregator>,
    pub attacks: Arc<AttacksHandler>,
    pub attacks_agg: Arc<AttacksAggregator>,
    pub upstreams: Arc<UpstreamHandler>,
    pub audit_ring: Arc<AuditRing>,
    pub audit: Arc<AuditHandler>,
    pub witness_state: Arc<WitnessState>,
    pub witness: Arc<WitnessHandler>,
    pub filter_catalogue: Arc<FilterCatalogue>,
    pub filters: Arc<FiltersHandler>,
    pub rules: Arc<RuleStore>,
    pub rule_stats: Arc<RuleStats>,
    pub tiers: Arc<TierStore>,
    pub routes: Arc<RoutesHandler>,
    pub blacklist: Arc<AccessListStore>,
    pub whitelist: Arc<AccessListStore>,
    pub sessions: Arc<SessionStore>,
    pub break_glass: Arc<BreakGlass>,
    pub tracking: Arc<TrackingHandler>,
    pub mutate: Arc<AuditedMutate>,
    pub detector_mask: SharedDetectorMask,
    pub risk: RiskTracker,
    /// Per-IP volumetric guard. F-T2 — fires before any
    /// detector runs so a single source IP can't flood the
    /// pipeline. Strikes are accrued on the same key when the
    /// limiter fires, so repeat offenders eventually cross
    /// `risk.strikes.block_at` and get the permanent 403.
    pub ip_rate_limiter: Arc<IpRateLimiter>,
    pub load_gauge: LoadGauge,
    pub verbosity: SharedVerbosity,
    /// Auth-layer session store (HMAC-signed cookies). Distinct
    /// from [`SessionStore`] which is the dashboard's view-side
    /// list. F-T1 wires both: login creates an entry in each.
    pub auth_sessions: Arc<AuthSessionStore>,
    pub login_rate_limiter: Arc<LoginRateLimiter>,
    /// Single configured admin identity (until RBAC lands). The
    /// proxy reads `cfg.admin.dashboard_auth.password_hash_ref`
    /// and builds this once at boot.
    pub admin_identity: Arc<AdminIdentity>,
    /// Idle TTL the login handler stamps on the session cookie.
    pub session_idle_seconds: u64,
    pub environment: Option<String>,
    /// Live audit bus — a clone of the broadcast handle the
    /// drain task subscribes to. Used by `/dashboard/sse` (B4-T4)
    /// and any future streaming surface that needs live events.
    pub bus: AuditBus,
    /// Live cluster-leader view. `None` for single-node /
    /// test builds; `Some` when `aegis-proxy::run` wires the
    /// leader-poll background task. See
    /// [`crate::api::tracking::LeaderView`] (carry-over 3,
    /// post 2026-04-29 cluster smoke).
    pub leader_view: Option<Arc<crate::api::tracking::LeaderView>>,
    /// External interop surface — `/__waf_control/*` dispatch,
    /// `X-WAF-*` response stamping, minimal-schema audit log.
    /// See [`plans/interop-contract.md`].
    pub interop: Option<Arc<crate::interop::InteropRuntime>>,
    /// Alert-channel management surface (CC-T2.1). `None` until
    /// `aegis-proxy::run` plumbs a receiver provider closure +
    /// the dispatch outcome ring shared with the SLO dispatch
    /// task. The GET `/api/alert-receivers` endpoint returns
    /// `{"receivers": []}` while this is `None` so the
    /// dashboard renders an empty-state card without erroring.
    pub alert_receivers:
        Option<Arc<crate::api::alert_receivers::AlertReceiversHandler>>,
    /// Live receiver list — the ArcSwap'd store the SLO dispatch
    /// task and the GET handler share. Exposed so the audit-mutated
    /// PUT / DELETE handlers (CC-T2.1.b) can `.store(Arc::new(new))`
    /// to hot-swap the list. Wired by the proxy boot path alongside
    /// [`Self::alert_receivers`]; both either present or absent
    /// together.
    pub alert_receivers_store:
        Option<Arc<arc_swap::ArcSwap<Vec<crate::slo::AlertReceiver>>>>,
    /// Dispatch outcome ring — the writeable handle the
    /// PUT / DELETE / POST-test handlers update. Same instance
    /// the SLO dispatch task feeds and the GET handler reads;
    /// duplicating the handle here keeps the audit-mutated
    /// handlers from having to reach through
    /// [`Self::alert_receivers`].
    pub alert_receivers_ring:
        Option<crate::api::alert_receivers::DispatchOutcomeRing>,
    /// CC-T1.1.b — writer handle for the live upstream pool
    /// registry. The proxy boot path stashes an
    /// `Arc<PoolRegistry>` here (via the `UpstreamWriter` trait)
    /// so the audit-mutated `/api/upstreams/config` PUT/DELETE
    /// handlers can hot-swap the pool table without bouncing
    /// the proxy. `None` for test bundles that boot
    /// `DashboardServices` standalone — handlers return Internal
    /// in that case.
    pub upstream_writer:
        Option<std::sync::Arc<dyn crate::api::upstreams_config::UpstreamWriter>>,
    /// MTLS-T6 — live per-identity sliding-window tracker. The
    /// `/api/mtls/connections` and `/api/mtls/failures`
    /// endpoints read snapshots from this. `None` for test
    /// bundles that don't need mTLS observability — the
    /// handlers serve empty-state bodies in that case.
    /// Wired by the proxy boot path; `record_request` /
    /// `record_failure` callers light up once MTLS-T2 / T3
    /// land the rustls + identity-extraction stages.
    pub identity_tracker:
        Option<std::sync::Arc<crate::identity_tracker::IdentityTracker>>,
    /// SC-T1 — handle to the live `StateBackend` so the
    /// `/api/state` endpoint can call `health()` without a
    /// separate provider closure. `None` for test bundles that
    /// boot `DashboardServices` standalone — the GET handler
    /// returns `BackendHealth::unknown()` in that case so the
    /// dashboard renders a "no backend wired" pill instead of
    /// 404'ing. Wired by `aegis-proxy::run` from whatever
    /// `state_select` produced.
    pub state_backend:
        Option<std::sync::Arc<dyn aegis_core::state::StateBackend>>,
    /// Per-stage request-duration histogram. `Some` once
    /// `aegis-proxy::run` has registered it; `None` for tests
    /// that don't drive real requests. The
    /// `GET /api/analytics/latency` endpoint reads percentiles
    /// from this when present, otherwise returns an empty
    /// `{stages: {}}` body.
    pub request_stage_hist:
        Option<std::sync::Arc<crate::metrics::request_duration::RequestStageHistogram>>,
    /// Per-route latency histogram. `Some` once
    /// `aegis-proxy::run` has registered it; `None` for tests.
    /// Populated by the data plane on every request once the
    /// route resolves. Read by
    /// `GET /api/analytics/latency/routes`.
    pub route_latency_hist:
        Option<std::sync::Arc<crate::metrics::route_latency::RouteLatencyHistogram>>,
    /// Phase-3 incident overlay — operator ack/snooze/resolve
    /// state on top of the SLO engine's firing alerts. Always
    /// present; the tracker starts empty and grows as operators
    /// interact with the Incidents page.
    pub incidents: std::sync::Arc<crate::api::incidents::IncidentTracker>,
    /// MTLS-T8 — runtime override of `cfg.tls.client_auth.mode`.
    /// Always present; starts at "no override" (resolves to the
    /// configured value). PUT /api/mtls/mode swaps the override
    /// in-process.
    pub mtls_mode_store: std::sync::Arc<crate::api::mtls_mode::ClientAuthModeStore>,
    /// MTLS-T10 — operator opt-in for the dashboard's CA bundle
    /// upload card. Mirrors `cfg.admin.dashboard_auth.allow_ca_upload`.
    /// Default `false` so trust anchors stay GitOps-managed
    /// unless the operator explicitly flips it on.
    pub allow_ca_upload: bool,
    /// HACK-T3 — shared detector list for the `/api/rules/simulate`
    /// preview endpoint (Tier-A bonus). Same `Vec<Box<dyn Detector>>`
    /// the data-plane `accept_loop` runs, so the simulator and live
    /// proxy can't drift. `None` for test bundles → simulator
    /// returns 404.
    pub detectors:
        Option<std::sync::Arc<Vec<Box<dyn aegis_security::detectors::Detector>>>>,
    /// MTLS-T7 — live, mutable allowed-SAN list. The boot path
    /// seeds it from `cfg.tls.client_auth.allowed_sans`; the
    /// audit-mutated `PUT/DELETE /api/mtls/sans` handlers update
    /// it in place. The data-plane identity-extraction call
    /// reads through this store on every TLS handshake to gate
    /// admission. `None` for test bundles → identity extraction
    /// behaves as before (no allowlist gate).
    pub allowed_sans:
        Option<crate::api::mtls::AllowedSansStore>,
}

impl DashboardServices {
    /// Construct the bundle and spawn the audit-bus drain task.
    /// Returns the bundle plus the join handle of the drain task —
    /// the caller can detach it (typical for the admin listener)
    /// or hold it for graceful shutdown.
    pub fn spawn(
        bus: AuditBus,
        pool_snapshot: PoolSnapshotProvider,
        environment: Option<String>,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        // Default auth runtime: empty admin (every login fails),
        // default rate limiter, blake3-of-empty-string session
        // key. Tests that need real auth call `spawn_with_mask`
        // directly with the runtime they want.
        let auth_sessions = Arc::new(AuthSessionStore::new([0u8; 32]));
        let login_rate_limiter =
            Arc::new(LoginRateLimiter::new(Default::default()));
        let admin_identity = Arc::new(AdminIdentity {
            user: String::new(),
            password_hash: String::new(),
        });
        Self::spawn_with_mask(
            bus,
            pool_snapshot,
            environment,
            SharedDetectorMask::default(),
            RiskTracker::new(&aegis_core::config::RiskConfig::default()),
            Arc::new(IpRateLimiter::new(Default::default())),
            LoadGauge::new(LoadModeConfig::default()),
            SharedVerbosity::default(),
            auth_sessions,
            login_rate_limiter,
            admin_identity,
            1800,
        )
    }

    /// Same as [`spawn`] but lets the caller share an existing
    /// [`SharedDetectorMask`], [`RiskTracker`], [`LoadGauge`], and
    /// [`SharedVerbosity`] with the data plane so every operator
    /// knob propagates uniformly across the proxy and dashboard.
    #[allow(clippy::too_many_arguments)]
    pub fn spawn_with_mask(
        bus: AuditBus,
        pool_snapshot: PoolSnapshotProvider,
        environment: Option<String>,
        detector_mask: SharedDetectorMask,
        risk: RiskTracker,
        ip_rate_limiter: Arc<IpRateLimiter>,
        load_gauge: LoadGauge,
        verbosity: SharedVerbosity,
        auth_sessions: Arc<AuthSessionStore>,
        login_rate_limiter: Arc<LoginRateLimiter>,
        admin_identity: Arc<AdminIdentity>,
        session_idle_seconds: u64,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        Self::spawn_with_mask_and_leader(
            bus,
            pool_snapshot,
            environment,
            detector_mask,
            risk,
            ip_rate_limiter,
            load_gauge,
            verbosity,
            auth_sessions,
            login_rate_limiter,
            admin_identity,
            session_idle_seconds,
            None,
        )
    }

    /// Same as [`spawn_with_mask`] but accepts a live
    /// [`crate::api::tracking::LeaderView`]. The proxy's
    /// `run()` builds one of these and threads it in so
    /// `/api/cluster` reports `is_leader` + `leader_node`
    /// correctly. Older call sites (tests, single-node
    /// builds) keep using `spawn_with_mask` and get the
    /// `None` placeholder behaviour.
    #[allow(clippy::too_many_arguments)]
    pub fn spawn_with_mask_and_leader(
        bus: AuditBus,
        pool_snapshot: PoolSnapshotProvider,
        environment: Option<String>,
        detector_mask: SharedDetectorMask,
        risk: RiskTracker,
        ip_rate_limiter: Arc<IpRateLimiter>,
        load_gauge: LoadGauge,
        verbosity: SharedVerbosity,
        auth_sessions: Arc<AuthSessionStore>,
        login_rate_limiter: Arc<LoginRateLimiter>,
        admin_identity: Arc<AdminIdentity>,
        session_idle_seconds: u64,
        leader_view: Option<Arc<crate::api::tracking::LeaderView>>,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let stats_agg = Arc::new(StatsAggregator::new());
        let attacks_agg = Arc::new(AttacksAggregator::new());
        let audit_ring = Arc::new(AuditRing::new());
        let witness_state = Arc::new(WitnessState::new());
        let filter_catalogue = Arc::new(FilterCatalogue::new());
        let rules = Arc::new(RuleStore::new());
        let rule_stats = Arc::new(RuleStats::new());
        let tiers = Arc::new(TierStore::new());
        let routes = Arc::new(RoutesHandler::new());
        let blacklist = Arc::new(AccessListStore::new());
        let whitelist = Arc::new(AccessListStore::new());
        let sessions = Arc::new(SessionStore::new());
        let break_glass = Arc::new(BreakGlass::new());
        let mutate = Arc::new(AuditedMutate::new(bus.clone()));
        let bus_handle = bus.clone();

        // Stats handler reduces the full pool snapshot to the
        // embedded `UpstreamSummary` (no per-pool list — that's
        // what /api/upstreams/summary is for).
        let stats_pool_provider = Arc::clone(&pool_snapshot);
        let stats = Arc::new(StatsHandler::with_upstream(
            Arc::clone(&stats_agg),
            move || {
                let snap = stats_pool_provider();
                let summary = compute_summary(&snap);
                UpstreamSummary {
                    state: summary.state.to_string(),
                    healthy_members: summary.healthy_members,
                    total_members: summary.total_members,
                }
            },
        ));

        let upstreams_pool_provider = Arc::clone(&pool_snapshot);
        let upstreams = Arc::new(UpstreamHandler::new(move || {
            upstreams_pool_provider()
        }));
        let tracking = Arc::new(match leader_view.as_ref() {
            Some(lv) => TrackingHandler::with_leader_view(
                Arc::clone(&upstreams),
                Arc::clone(lv),
            ),
            None => TrackingHandler::new(Arc::clone(&upstreams)),
        });

        let attacks = Arc::new(AttacksHandler::new(Arc::clone(&attacks_agg)));

        let audit_handler = Arc::new(AuditHandler::new(Arc::clone(&audit_ring)));
        let witness_handler = Arc::new(WitnessHandler::new(Arc::clone(&witness_state)));
        let filters_handler = Arc::new(FiltersHandler::new(Arc::clone(&filter_catalogue)));

        // Subscribe SYNCHRONOUSLY before spawning so events emitted
        // between `spawn` returning and the task being scheduled
        // aren't dropped (broadcast::Receiver only sees post-subscribe
        // messages).
        let mut rx = bus.subscribe();
        let stats_clone = Arc::clone(&stats_agg);
        let attacks_clone = Arc::clone(&attacks_agg);
        let audit_clone = Arc::clone(&audit_ring);
        let filter_clone = Arc::clone(&filter_catalogue);
        let rule_stats_clone = Arc::clone(&rule_stats);
        let drain = tokio::spawn(async move {
            while let Ok(ev) = rx.recv().await {
                Self::dispatch_event(
                    &stats_clone,
                    &attacks_clone,
                    &audit_clone,
                    &filter_clone,
                    &rule_stats_clone,
                    &ev,
                );
            }
        });

        (
            Self {
                stats,
                stats_agg,
                attacks,
                attacks_agg,
                upstreams,
                audit_ring,
                audit: audit_handler,
                witness_state,
                witness: witness_handler,
                filter_catalogue,
                filters: filters_handler,
                rules,
                rule_stats,
                tiers,
                routes,
                blacklist,
                whitelist,
                sessions,
                break_glass,
                tracking,
                mutate,
                detector_mask,
                risk,
                ip_rate_limiter,
                load_gauge,
                verbosity,
                auth_sessions,
                login_rate_limiter,
                admin_identity,
                session_idle_seconds,
                environment,
                bus: bus_handle,
                leader_view,
                // Interop contract is opted in by the bin
                // crate after construction (see
                // `aegis-bin/src/main.rs`).
                interop: None,
                // Alert-receivers handler + writeable handles are
                // opted in by the proxy boot path once it has
                // constructed the shared receiver ArcSwap +
                // dispatch ring.
                alert_receivers: None,
                alert_receivers_store: None,
                alert_receivers_ring: None,
                // CC-T1.1.b — wired by the proxy boot path once
                // `ProxyContext.pools` (PoolRegistry) is built.
                upstream_writer: None,
                // MTLS-T6 — wired by the proxy boot path. Until
                // then `/api/mtls/connections` + `/api/mtls/failures`
                // serve empty-state bodies.
                identity_tracker: None,
                // SC-T1 — wired by the proxy boot path. Until then
                // `/api/state` reports `BackendHealth::unknown()`.
                state_backend: None,
                // Wired by `aegis-proxy::run` after the
                // `RequestStageHistogram` is registered. Tests
                // don't drive real requests so this stays None.
                request_stage_hist: None,
                route_latency_hist: None,
                // Phase-3 incident overlay — empty at boot, fills
                // as operators ack/snooze/resolve via the dashboard.
                incidents: std::sync::Arc::new(
                    crate::api::incidents::IncidentTracker::new(),
                ),
                // MTLS-T8 — empty override at boot. The proxy may
                // seed it from a persisted file or YAML if needed.
                mtls_mode_store: std::sync::Arc::new(
                    crate::api::mtls_mode::ClientAuthModeStore::new(),
                ),
                // MTLS-T10 — default off; proxy boot path overrides
                // from cfg.admin.dashboard_auth.allow_ca_upload.
                allow_ca_upload: false,
                // HACK-T3 — wired by the proxy boot path. Until then
                // `/api/rules/simulate` returns 503.
                detectors: None,
                // MTLS-T7 — wired by the proxy boot path. Until then
                // identity extraction skips the allowlist gate.
                allowed_sans: None,
            },
            drain,
        )
    }

    /// Dispatch one audit event to every aggregator that cares.
    /// Pulled out for direct invocation in tests where spawning
    /// a tokio task would race the assertions.
    pub fn dispatch_event(
        stats: &StatsAggregator,
        attacks: &AttacksAggregator,
        audit: &AuditRing,
        filters: &FilterCatalogue,
        rule_stats: &RuleStats,
        ev: &AuditEvent,
    ) {
        stats.record(ev);
        attacks.record(ev);
        audit.record(ev.clone());
        filters.record(ev);
        rule_stats.record(ev);
    }
}

/// Build a snapshot provider from a `WafConfig`. Reads pool names and
/// member counts at *construction time* (closures clone the
/// already-snapshot values) so changes to the live config aren't
/// reflected — call `pool_snapshot_provider` again on hot reload.
///
/// All pools report `healthy = total` (every member assumed up)
/// until the cluster runtime lands real per-member health probes.
/// This matches the in-process `Member::new()` default of
/// `healthy: AtomicBool::new(true)` — the data plane *will* route
/// to those members, so reporting "Down" in the dashboard while
/// the proxy actually serves traffic was misleading.
///
/// When a pool config carries a `health:` block, the live probe
/// flips the member flag in `PoolRegistry`; this provider does
/// not yet read those flags (carry-over noted in
/// `Implement-Progress.md` — depends on membership-driven
/// cluster runtime). Once that lands, replace the closure body
/// with a live registry read.
pub fn pool_snapshot_provider(cfg: &aegis_core::config::WafConfig) -> PoolSnapshotProvider {
    let pools: Vec<PoolHealthEntry> = cfg
        .upstreams
        .iter()
        .map(|(name, pool)| {
            let total = pool.members.len() as u32;
            PoolHealthEntry {
                name: name.clone(),
                healthy: total,
                total,
            }
        })
        .collect();
    Arc::new(move || PoolHealthSnapshot {
        pools: pools.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::audit::AuditClass;

    fn det_event(detector: &str, ip: &str) -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "test".into(),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: None,
            action: "block".into(),
            reason: "test".into(),
            client_ip: ip.into(),
            route_id: None,
            rule_id: None,
            risk_score: Some(80),
            fields: serde_json::json!({"detector": detector}),
        }
    }

    fn empty_pool_provider() -> PoolSnapshotProvider {
        Arc::new(|| PoolHealthSnapshot { pools: Vec::new() })
    }

    fn fake_pool_provider() -> PoolSnapshotProvider {
        Arc::new(|| PoolHealthSnapshot {
            pools: vec![PoolHealthEntry {
                name: "api-pool".into(),
                healthy: 3,
                total: 4,
            }],
        })
    }

    #[tokio::test]
    async fn drain_task_feeds_both_aggregators() {
        let bus = AuditBus::new(64);
        let (services, _drain) =
            DashboardServices::spawn(bus.clone(), empty_pool_provider(), None);

        bus.emit(det_event("sqli", "8.8.8.8"));
        bus.emit(det_event("xss", "1.1.1.1"));
        // Give the drain task time to consume.
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            let dist = services.attacks_agg.distribution(900);
            if dist.categories.len() == 2 {
                break;
            }
        }

        let dist = services.attacks_agg.distribution(900);
        assert_eq!(dist.categories.len(), 2);
        // Stats aggregator also saw the events (block_rate_pct = 100).
        let stats = services.stats_agg.snapshot();
        assert_eq!(stats.blocks_total, 2);
    }

    #[tokio::test]
    async fn dispatch_event_runs_synchronously() {
        // The exposed dispatch_event helper sidesteps the tokio
        // runtime — useful in tests that need deterministic order.
        let bus = AuditBus::new(8);
        let (services, _) = DashboardServices::spawn(bus, empty_pool_provider(), None);
        DashboardServices::dispatch_event(
            &services.stats_agg,
            &services.attacks_agg,
            &services.audit_ring,
            &services.filter_catalogue,
            &services.rule_stats,
            &det_event("sqli", "8.8.8.8"),
        );
        let dist = services.attacks_agg.distribution(900);
        assert_eq!(dist.categories.len(), 1);
        assert_eq!(dist.categories[0].name, "sqli");
        // Audit ring also captured the event.
        assert_eq!(services.audit_ring.high_water(), 1);
        // Filter catalogue saw the actor + class.
        let cat = services.filter_catalogue.snapshot();
        assert!(cat.classes.contains(&"detection".to_string()));
        assert!(cat.actors.contains(&"8.8.8.8".to_string()));
    }

    #[tokio::test]
    async fn audit_ring_captures_drained_events() {
        let bus = AuditBus::new(64);
        let (services, _drain) =
            DashboardServices::spawn(bus.clone(), empty_pool_provider(), None);
        bus.emit(det_event("sqli", "8.8.8.8"));
        bus.emit(det_event("xss", "1.1.1.1"));
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            if services.audit_ring.high_water() >= 2 {
                break;
            }
        }
        assert_eq!(services.audit_ring.high_water(), 2);
        let body = services.audit.render_since(0, 100);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["events"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn stats_handler_reflects_pool_provider() {
        // /api/stats embeds the upstream summary derived from the
        // pool snapshot provider.
        let bus = AuditBus::new(8);
        let (services, _) = DashboardServices::spawn(bus, fake_pool_provider(), None);
        let body = services.stats.render();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["upstream"]["healthy_members"].as_u64(), Some(3));
        assert_eq!(v["upstream"]["total_members"].as_u64(), Some(4));
        // 3 of 4 healthy, no fully-dead pool → Degraded.
        assert_eq!(v["upstream"]["state"].as_str(), Some("Degraded"));
    }

    #[tokio::test]
    async fn upstreams_handler_reports_pools_with_state() {
        let bus = AuditBus::new(8);
        let (services, _) = DashboardServices::spawn(bus, fake_pool_provider(), None);
        let body = services.upstreams.render();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["state"].as_str(), Some("Degraded"));
        assert_eq!(v["pools"].as_array().unwrap().len(), 1);
        assert_eq!(v["pools"][0]["name"].as_str(), Some("api-pool"));
    }

    #[tokio::test]
    async fn mutate_wraps_rule_upsert_and_appends_admin_audit() {
        // P1 wiring smoke: a successful rule upsert flows through
        // AuditedMutate, which appends one chain entry, emits one
        // bus event, which the drain task records into AuditRing.
        let bus = AuditBus::new(64);
        let (services, _drain) =
            DashboardServices::spawn(bus.clone(), empty_pool_provider(), None);

        let req = crate::api::mutation::MutationRequest {
            method: "PUT",
            csrf_cookie: Some("tok"),
            csrf_header: Some("tok"),
            actor: "admin",
            request_id: "req-rule-1",
            resource: "/api/rules/sqli-1",
            action: "create",
            reason: "wire-up smoke",
        };
        let rules = Arc::clone(&services.rules);
        let outcome = services
            .mutate
            .apply(
                &req,
                serde_json::Value::Null,
                serde_json::json!({"id": "sqli-1", "enabled": true}),
                || {
                    let v = rules.upsert("sqli-1", "rule sqli-1 { allow }", true);
                    if v.ok {
                        Ok::<(), String>(())
                    } else {
                        Err(format!("validator failed: {:?}", v.errors))
                    }
                },
            )
            .expect("mutation should succeed");
        assert_eq!(outcome.value, ());
        assert_eq!(services.mutate.chain_len(), 1);

        // Wait for the drain task to feed the audit ring.
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            if services.audit_ring.high_water() >= 1 {
                break;
            }
        }
        assert_eq!(services.audit_ring.high_water(), 1);
        let body = services.audit.render_since(0, 100);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let events = v["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["class"], "admin");
        assert_eq!(events[0]["action"], "create");
        assert_eq!(events[0]["request_id"], "req-rule-1");
    }

    #[tokio::test]
    async fn mutate_rejects_csrf_and_does_not_mutate_store() {
        let bus = AuditBus::new(8);
        let (services, _drain) =
            DashboardServices::spawn(bus, empty_pool_provider(), None);

        let req = crate::api::mutation::MutationRequest {
            method: "PUT",
            csrf_cookie: Some("aaa"),
            csrf_header: Some("bbb"),
            actor: "attacker",
            request_id: "req-bad",
            resource: "/api/rules/x",
            action: "create",
            reason: "csrf attempt",
        };
        let rules = Arc::clone(&services.rules);
        let result: Result<_, _> = services.mutate.apply(
            &req,
            serde_json::Value::Null,
            serde_json::Value::Null,
            || {
                rules.upsert("x", "rule x { allow }", true);
                Ok::<(), String>(())
            },
        );
        assert!(result.is_err());
        assert_eq!(services.mutate.chain_len(), 0);
        assert!(services.rules.get("x").is_none(), "store mutated despite CSRF rejection");
    }

    #[tokio::test]
    async fn detector_mask_flips_via_mutate_pipeline() {
        // P2 wiring smoke: a successful PUT /api/detectors flows
        // through AuditedMutate, swaps the SharedDetectorMask, and
        // appends one admin chain entry whose diff records the
        // before/after toggle.
        let bus = AuditBus::new(64);
        let initial_mask = aegis_security::detectors::SharedDetectorMask::default();
        let (services, _drain) = DashboardServices::spawn_with_mask(
            bus.clone(),
            empty_pool_provider(),
            None,
            initial_mask.clone(),
            RiskTracker::new(&aegis_core::config::RiskConfig::default()),
            Arc::new(IpRateLimiter::new(Default::default())),
            LoadGauge::new(LoadModeConfig::default()),
            SharedVerbosity::default(),
            Arc::new(AuthSessionStore::new([0u8; 32])),
            Arc::new(LoginRateLimiter::new(Default::default())),
            Arc::new(AdminIdentity {
                user: String::new(),
                password_hash: String::new(),
            }),
            1800,
        );

        // Sanity: starts all-on.
        assert!(initial_mask
            .load()
            .is_enabled(aegis_security::detectors::DetectorClass::Recon));

        let proposed = initial_mask
            .load()
            .with(aegis_security::detectors::DetectorClass::Recon, false);

        let req = crate::api::mutation::MutationRequest {
            method: "PUT",
            csrf_cookie: Some("tok"),
            csrf_header: Some("tok"),
            actor: "admin",
            request_id: "req-detectors-1",
            resource: "/api/detectors",
            action: "update",
            reason: "disable recon",
        };
        let mask_handle = initial_mask.clone();
        let outcome = services
            .mutate
            .apply(
                &req,
                serde_json::to_value(aegis_security::detectors::DetectorMaskBody::from(
                    initial_mask.load(),
                ))
                .unwrap(),
                serde_json::to_value(aegis_security::detectors::DetectorMaskBody::from(
                    proposed,
                ))
                .unwrap(),
                || {
                    if let Err(violations) =
                        crate::api::detectors::enforce_compliance_clamp(proposed, &[])
                    {
                        return Err(format!("locked: {}", violations.join(",")));
                    }
                    mask_handle.store(proposed);
                    Ok::<(), String>(())
                },
            )
            .expect("mutation should succeed");

        // Mask flipped.
        assert!(!initial_mask
            .load()
            .is_enabled(aegis_security::detectors::DetectorClass::Recon));
        // Single chain entry recorded with before/after diff.
        assert_eq!(services.mutate.chain_len(), 1);
        let fields = outcome.chain_entry.event.fields.as_object().unwrap();
        assert_eq!(fields["resource"], "/api/detectors");
        assert!(fields["diff"]["before"]["recon"].as_bool().unwrap());
        assert!(!fields["diff"]["after"]["recon"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn detector_mask_compliance_clamp_blocks_disable() {
        let bus = AuditBus::new(8);
        let initial_mask = aegis_security::detectors::SharedDetectorMask::default();
        let (services, _drain) = DashboardServices::spawn_with_mask(
            bus,
            empty_pool_provider(),
            None,
            initial_mask.clone(),
            RiskTracker::new(&aegis_core::config::RiskConfig::default()),
            Arc::new(IpRateLimiter::new(Default::default())),
            LoadGauge::new(LoadModeConfig::default()),
            SharedVerbosity::default(),
            Arc::new(AuthSessionStore::new([0u8; 32])),
            Arc::new(LoginRateLimiter::new(Default::default())),
            Arc::new(AdminIdentity {
                user: String::new(),
                password_hash: String::new(),
            }),
            1800,
        );

        let proposed = aegis_security::detectors::DetectorMask::all_enabled()
            .with(aegis_security::detectors::DetectorClass::Sqli, false);

        let req = crate::api::mutation::MutationRequest {
            method: "PUT",
            csrf_cookie: Some("tok"),
            csrf_header: Some("tok"),
            actor: "admin",
            request_id: "req-detectors-2",
            resource: "/api/detectors",
            action: "update",
            reason: "try to drop sqli",
        };
        let modes = vec![aegis_core::config::ComplianceMode::Pci];
        let mask_handle = initial_mask.clone();
        let result: Result<_, _> = services.mutate.apply(
            &req,
            serde_json::Value::Null,
            serde_json::Value::Null,
            || {
                if let Err(violations) =
                    crate::api::detectors::enforce_compliance_clamp(proposed, &modes)
                {
                    return Err(format!("compliance: {}", violations.join(",")));
                }
                mask_handle.store(proposed);
                Ok::<(), String>(())
            },
        );

        assert!(result.is_err());
        // Mask unchanged — sqli still on.
        assert!(initial_mask
            .load()
            .is_enabled(aegis_security::detectors::DetectorClass::Sqli));
        // No chain entry on validation failure.
        assert_eq!(services.mutate.chain_len(), 0);
    }

    #[test]
    fn pool_snapshot_provider_reads_config() {
        let yaml = r#"
listeners:
  data:
    - bind: "0.0.0.0:8080"
  admin:
    bind: "127.0.0.1:9443"
routes:
  - id: catch-all
    path: "/"
    upstream: api-pool
upstreams:
  api-pool:
    members:
      - addr: "127.0.0.1:9001"
      - addr: "127.0.0.1:9002"
state:
  backend: in_memory
"#;
        let cfg: aegis_core::config::WafConfig = serde_yaml::from_str(yaml).unwrap();
        let provider = pool_snapshot_provider(&cfg);
        let snap = provider();
        assert_eq!(snap.pools.len(), 1);
        let p = &snap.pools[0];
        assert_eq!(p.name, "api-pool");
        assert_eq!(p.total, 2);
        // Members default to healthy=true at construction; with no
        // live `health:` probe configured, `healthy == total`.
        // Replace this assertion with a live registry read once the
        // cluster runtime lands real per-member health probes.
        assert_eq!(p.healthy, 2);
    }
}
