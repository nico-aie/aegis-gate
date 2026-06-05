//! D-M2-T2.7 integration smoke test.
//!
//! Boots a `DashboardServices` bundle, seeds the audit bus with a
//! fixed event sequence, then exercises every new dashboard
//! endpoint via its handler. Asserts the JSON shapes match
//! `docs/control-plane/enterprise/api.md` and that the
//! `attacks/distribution` percentages sum to ~100.
//!
//! The test runs against the in-process handler — no TCP listener
//! — because the proxy admin router is a thin wrapper around the
//! same handlers. The wrapper is exercised by `aegis-proxy`'s own
//! test suite; this file covers the data-layer end-to-end.

use std::sync::Arc;
use std::time::Duration;

use aegis_control::api::upstreams::{PoolHealthEntry, PoolHealthSnapshot};
use aegis_control::dashboard_services::{DashboardServices, PoolSnapshotProvider};
use aegis_core::audit::{AuditClass, AuditEvent};
use aegis_core::AuditBus;

fn det_event(detector: &str, action: &str, ip: &str, risk: u32) -> AuditEvent {
    AuditEvent {
        schema_version: 1,
        ts: chrono::Utc::now(),
        request_id: format!("req-{ip}"),
        class: AuditClass::Detection,
        tenant_id: None,
        tier: None,
        action: action.into(),
        reason: "smoke".into(),
        client_ip: ip.into(),
        route_id: None,
        rule_id: None,
        risk_score: Some(risk),
        method: None,
        path: None,
        mode: None,
        fields: serde_json::json!({"detector": detector}),
    }
}

fn fake_pools() -> PoolSnapshotProvider {
    Arc::new(|| PoolHealthSnapshot {
        pools: vec![
            PoolHealthEntry {
                name: "api-pool".into(),
                healthy: 4,
                total: 4,
                members: Vec::new(),
                circuit: None,
            },
            PoolHealthEntry {
                name: "static-pool".into(),
                healthy: 2,
                total: 2,
                members: Vec::new(),
                circuit: None,
            },
        ],
    })
}

async fn wait_for_distribution(services: &DashboardServices, min_categories: usize) {
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(5)).await;
        let dist = services.attacks_agg.distribution(900);
        if dist.categories.len() >= min_categories {
            return;
        }
    }
}

#[tokio::test]
async fn api_about_shape() {
    let body = aegis_control::api::about::render(Some("staging".into()));
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["name"].as_str(), Some("Aegis WAF"));
    assert!(v["version"].as_str().is_some());
    assert_eq!(v["environment"].as_str(), Some("staging"));
}

#[tokio::test]
async fn api_stats_shape_with_real_aggregator() {
    let bus = AuditBus::new(64);
    let (services, _drain) = DashboardServices::spawn(bus.clone(), fake_pools(), None);
    bus.emit(det_event("sqli", "block", "8.8.8.8", 80));
    bus.emit(det_event("xss", "block", "1.1.1.1", 60));
    wait_for_distribution(&services, 2).await;

    let body = services.stats.render();
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    for key in ["request_rate", "blocks_total", "block_rate_pct", "active_threats", "upstream", "ts"] {
        assert!(v.get(key).is_some(), "/api/stats missing {key}");
    }
    // Upstream summary derived from the configured pools.
    assert_eq!(v["upstream"]["state"].as_str(), Some("Healthy"));
    assert_eq!(v["upstream"]["healthy_members"].as_u64(), Some(6));
    assert_eq!(v["upstream"]["total_members"].as_u64(), Some(6));
    // Block accounting: 2 blocks recorded.
    assert_eq!(v["blocks_total"].as_u64(), Some(2));
}

#[tokio::test]
async fn api_stats_timeseries_shape() {
    let bus = AuditBus::new(64);
    let (services, _drain) = DashboardServices::spawn(bus.clone(), fake_pools(), None);
    for _ in 0..5 {
        bus.emit(det_event("sqli", "block", "8.8.8.8", 80));
    }
    wait_for_distribution(&services, 1).await;

    let resp = services.stats_agg.timeseries(60, 5);
    let v: serde_json::Value = serde_json::to_value(&resp).unwrap();
    assert_eq!(v["window_seconds"].as_u64(), Some(60));
    assert_eq!(v["step_seconds"].as_u64(), Some(5));
    let points = v["points"].as_array().unwrap();
    assert_eq!(points.len(), 12);
    let total: u64 = points.iter().map(|p| p["total"].as_u64().unwrap_or(0)).sum();
    assert_eq!(total, 5);
}

#[tokio::test]
async fn api_attacks_distribution_percentages_sum_to_100() {
    // Per the milestone: "feed mixed-detector events, assert percentages."
    let bus = AuditBus::new(64);
    let (services, _drain) = DashboardServices::spawn(bus.clone(), fake_pools(), None);
    for name in ["sqli", "xss", "ssrf", "path", "cmdi", "lfi"] {
        for _ in 0..4 {
            bus.emit(det_event(name, "block", "8.8.8.8", 80));
        }
    }
    wait_for_distribution(&services, 6).await;

    let body = services.attacks.render(900);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let cats = v["categories"].as_array().expect("categories array");
    assert_eq!(cats.len(), 6);
    let total_pct: f64 = cats.iter().map(|c| c["pct"].as_f64().unwrap_or(0.0)).sum();
    assert!(
        (total_pct - 100.0).abs() < 0.5,
        "percentages should sum to ~100, got {total_pct}"
    );
}

#[tokio::test]
async fn api_attacks_top_groups_by_attacker() {
    let bus = AuditBus::new(64);
    let (services, _drain) = DashboardServices::spawn(bus.clone(), fake_pools(), None);
    for _ in 0..7 {
        bus.emit(det_event("sqli", "block", "1.1.1.1", 70));
    }
    for _ in 0..3 {
        bus.emit(det_event("xss", "block", "8.8.8.8", 60));
    }
    wait_for_distribution(&services, 2).await;

    let body = services.attacks.render_top(900, 5);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let attackers = v["attackers"].as_array().expect("attackers array");
    assert_eq!(attackers.len(), 2);
    // Sorted by hits desc — 1.1.1.1 (7 hits) ahead of 8.8.8.8 (3 hits).
    assert_eq!(attackers[0]["identifier"].as_str(), Some("1.1.1.1"));
    assert_eq!(attackers[0]["hits"].as_u64(), Some(7));
}

// ---------- SC-T1 — `/api/state` round-trip via DashboardServices ----------

/// Stub backend that lets us inject a fixed `BackendHealth`
/// without depending on a concrete impl. Only `health()` is
/// non-trivial; every other method is a stub the test never
/// calls (the API smoke harness never drives traffic through
/// it).
struct StubBackend {
    health: aegis_core::state::BackendHealth,
}

#[async_trait::async_trait]
impl aegis_core::state::StateBackend for StubBackend {
    async fn get(&self, _: &str) -> aegis_core::Result<Option<Vec<u8>>> {
        Ok(None)
    }
    async fn set(
        &self,
        _: &str,
        _: &[u8],
        _: std::time::Duration,
    ) -> aegis_core::Result<()> {
        Ok(())
    }
    async fn del(&self, _: &str) -> aegis_core::Result<()> {
        Ok(())
    }
    async fn incr_window(
        &self,
        _: &str,
        _: std::time::Duration,
        _: u64,
    ) -> aegis_core::Result<aegis_core::state::SlidingWindowResult> {
        Ok(aegis_core::state::SlidingWindowResult {
            count: 0,
            allowed: true,
            retry_after: None,
        })
    }
    async fn token_bucket(
        &self,
        _: &str,
        _: u32,
        _: u32,
    ) -> aegis_core::Result<bool> {
        Ok(true)
    }
    async fn get_risk(
        &self,
        _: &aegis_core::risk::RiskKey,
    ) -> aegis_core::Result<u32> {
        Ok(0)
    }
    async fn add_risk(
        &self,
        _: &aegis_core::risk::RiskKey,
        _: i32,
        _: u32,
    ) -> aegis_core::Result<u32> {
        Ok(0)
    }
    async fn auto_block(
        &self,
        _: std::net::IpAddr,
        _: std::time::Duration,
    ) -> aegis_core::Result<()> {
        Ok(())
    }
    async fn is_auto_blocked(
        &self,
        _: std::net::IpAddr,
    ) -> aegis_core::Result<bool> {
        Ok(false)
    }
    async fn put_nonce(
        &self,
        _: &str,
        _: std::time::Duration,
    ) -> aegis_core::Result<bool> {
        Ok(true)
    }
    async fn consume_nonce(&self, _: &str) -> aegis_core::Result<bool> {
        Ok(true)
    }
    async fn health(&self) -> aegis_core::state::BackendHealth {
        self.health.clone()
    }
}

#[tokio::test]
async fn api_state_unwired_returns_unknown_backend() {
    // Boot a bundle without a state backend — the spawn helper
    // doesn't touch `state_backend`, leaving it `None`. The proxy
    // dispatch path should still produce a parseable response so
    // the dashboard renders an empty-state pill instead of 404.
    let bus = AuditBus::new(8);
    let (services, _drain) = DashboardServices::spawn(bus, fake_pools(), None);
    assert!(services.state_backend.is_none());

    // Drive the same render path the proxy's `/api/state` handler
    // uses. With no backend wired, fall through to
    // `BackendHealth::unknown()`.
    //
    // 2026-05-11 CORE-06 fix — `connected: true` now (was false).
    // The default unknown shape signals "status unknown but
    // assumed up" so the dashboard doesn't red-flag test stubs
    // and third-party backends that haven't overridden health().
    let h = aegis_core::state::BackendHealth::unknown();
    let view = aegis_control::api::state::StateView::render(h);
    let body = serde_json::to_value(&view).unwrap();
    assert_eq!(body["backend"], "unknown");
    assert_eq!(body["connected"], true);
    assert_eq!(body["circuit"]["state"], "closed");
}

#[tokio::test]
async fn api_state_wired_returns_backend_health() {
    use aegis_core::state::StateBackend;

    // Build a stub backend reporting healthy redis.
    let stub_health = aegis_core::state::BackendHealth {
        backend: "redis",
        connected: true,
        latency: aegis_core::state::LatencyP::from_samples(&[100, 200, 300]),
        key_count: Some(42),
        replica_lag_ms: Some(50),
        server_version: Some("7.2.4".to_string()),
        circuit: aegis_core::state::CircuitState::Closed,
    };
    let stub: std::sync::Arc<dyn StateBackend> = std::sync::Arc::new(StubBackend {
        health: stub_health,
    });

    // Wire it into a fresh services bundle.
    let bus = AuditBus::new(8);
    let (mut services, _drain) =
        DashboardServices::spawn(bus, fake_pools(), None);
    services.state_backend = Some(stub);

    // Drive the same path the proxy dispatch handler runs.
    let h = services.state_backend.as_ref().unwrap().health().await;
    let view = aegis_control::api::state::StateView::render(h);
    let body = serde_json::to_value(&view).unwrap();
    assert_eq!(body["backend"], "redis");
    assert_eq!(body["connected"], true);
    assert_eq!(body["key_count"], 42);
    assert_eq!(body["replica_lag_ms"], 50);
    assert_eq!(body["server_version"], "7.2.4");
    assert_eq!(body["circuit"]["state"], "closed");
    assert!(body["latency"].is_object());
}

#[tokio::test]
async fn api_upstreams_summary_reflects_pool_provider() {
    let bus = AuditBus::new(8);
    let (services, _drain) = DashboardServices::spawn(bus, fake_pools(), None);
    let body = services.upstreams.render();
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["state"].as_str(), Some("Healthy"));
    assert_eq!(v["healthy_members"].as_u64(), Some(6));
    assert_eq!(v["total_members"].as_u64(), Some(6));
    assert_eq!(v["pools"].as_array().unwrap().len(), 2);
}
