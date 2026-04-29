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
        let stats_agg = Arc::new(StatsAggregator::new());
        let attacks_agg = Arc::new(AttacksAggregator::new());
        let audit_ring = Arc::new(AuditRing::new());
        let witness_state = Arc::new(WitnessState::new());
        let filter_catalogue = Arc::new(FilterCatalogue::new());
        let rules = Arc::new(RuleStore::new());
        let rule_stats = Arc::new(RuleStats::new());
        let tiers = Arc::new(TierStore::new());
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
        let tracking = Arc::new(TrackingHandler::new(Arc::clone(&upstreams)));

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
/// All pools report `healthy = 0` until the cluster runtime lands
/// real per-member health. The names + total counts surface
/// correctly so the dashboard table is populated; state is "Down"
/// per the [`compute_summary`] rules.
pub fn pool_snapshot_provider(cfg: &aegis_core::config::WafConfig) -> PoolSnapshotProvider {
    let pools: Vec<PoolHealthEntry> = cfg
        .upstreams
        .iter()
        .map(|(name, pool)| PoolHealthEntry {
            name: name.clone(),
            healthy: 0,
            total: pool.members.len() as u32,
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
        assert_eq!(p.healthy, 0); // No live cluster — placeholder.
    }
}
