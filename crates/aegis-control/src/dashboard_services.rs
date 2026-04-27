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
use aegis_core::AuditBus;

use crate::api::{
    attacks::{AttacksAggregator, AttacksHandler},
    audit::{AuditHandler, AuditRing},
    stats::{StatsAggregator, StatsHandler, UpstreamSummary},
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
    pub environment: Option<String>,
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
        let stats_agg = Arc::new(StatsAggregator::new());
        let attacks_agg = Arc::new(AttacksAggregator::new());
        let audit_ring = Arc::new(AuditRing::new());

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

        let attacks = Arc::new(AttacksHandler::new(Arc::clone(&attacks_agg)));

        let audit_handler = Arc::new(AuditHandler::new(Arc::clone(&audit_ring)));

        // Subscribe SYNCHRONOUSLY before spawning so events emitted
        // between `spawn` returning and the task being scheduled
        // aren't dropped (broadcast::Receiver only sees post-subscribe
        // messages).
        let mut rx = bus.subscribe();
        let stats_clone = Arc::clone(&stats_agg);
        let attacks_clone = Arc::clone(&attacks_agg);
        let audit_clone = Arc::clone(&audit_ring);
        let drain = tokio::spawn(async move {
            while let Ok(ev) = rx.recv().await {
                Self::dispatch_event(&stats_clone, &attacks_clone, &audit_clone, &ev);
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
                environment,
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
        ev: &AuditEvent,
    ) {
        stats.record(ev);
        attacks.record(ev);
        audit.record(ev.clone());
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
            &det_event("sqli", "8.8.8.8"),
        );
        let dist = services.attacks_agg.distribution(900);
        assert_eq!(dist.categories.len(), 1);
        assert_eq!(dist.categories[0].name, "sqli");
        // Audit ring also captured the event.
        assert_eq!(services.audit_ring.high_water(), 1);
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
