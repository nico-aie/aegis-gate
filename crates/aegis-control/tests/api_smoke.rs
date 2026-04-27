//! D-M2-T2.7 integration smoke test.
//!
//! Boots a `DashboardServices` bundle, seeds the audit bus with a
//! fixed event sequence, then exercises every new dashboard
//! endpoint via its handler. Asserts the JSON shapes match
//! `docs/dashboard-enterprise/api.md` and that the
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
            },
            PoolHealthEntry {
                name: "static-pool".into(),
                healthy: 2,
                total: 2,
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
