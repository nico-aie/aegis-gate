//! `/api/risk*` endpoints (P6 of the security-toggle plan).
//!
//! Three surfaces:
//! - `GET /api/risk` — top-N high-risk IPs (default 50), sorted
//!   by `(strikes desc, score desc)`. The dashboard polls this
//!   every 5 s on the Tracking page.
//! - `GET /api/risk/{ip}` — full snapshot for a single client.
//!   404 when the tracker hasn't seen the IP.
//! - `PUT /api/risk/{ip}/reset` — operator override that flows
//!   through `AuditedMutate` to clear strikes + score.
//!
//! All read paths sit on top of [`RiskTracker`] which is shared
//! between the data plane (the producer) and the control plane
//! (the consumer).

#![allow(dead_code)]

use std::net::IpAddr;

use aegis_security::risk::{RiskSnapshot, RiskTracker};
use serde::Serialize;

/// JSON shape returned by `GET /api/risk`.
#[derive(Clone, Debug, Serialize)]
pub struct RiskListResponse {
    pub total_tracked: usize,
    pub returned: usize,
    pub clients: Vec<RiskSnapshot>,
}

/// JSON shape returned by `GET /api/risk/{ip}`.
#[derive(Clone, Debug, Serialize)]
pub struct RiskDetailResponse {
    pub client: RiskSnapshot,
}

/// Render the list endpoint. `limit` is clamped to [1, 500] —
/// the dashboard never asks for more than a screenful but
/// scripted callers can paginate by IP-prefix later.
pub fn render_list(tracker: &RiskTracker, limit: u32) -> String {
    let limit = limit.clamp(1, 500) as usize;
    let body = RiskListResponse {
        total_tracked: tracker.len(),
        returned: 0, // re-set after the take below
        clients: tracker.top(limit),
    };
    let body = RiskListResponse {
        returned: body.clients.len(),
        ..body
    };
    serde_json::to_string(&body).unwrap_or_else(|_| String::from("{}"))
}

/// Render the detail endpoint. Returns `(status, body)` so the
/// caller can wire 200/404 without re-parsing the JSON.
pub fn render_detail(tracker: &RiskTracker, ip: IpAddr) -> (u16, String) {
    match tracker.snapshot_wire(ip) {
        Some(client) => (
            200,
            serde_json::to_string(&RiskDetailResponse { client })
                .unwrap_or_else(|_| String::from("{}")),
        ),
        None => (
            404,
            serde_json::json!({
                "error": "not_found",
                "ip": ip.to_string(),
            })
            .to_string(),
        ),
    }
}

/// Parse an IP from the URL trailing segment. `None` for malformed
/// addresses lets the caller emit a 400 instead of a 404.
pub fn parse_ip_segment(segment: &str) -> Option<IpAddr> {
    segment.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::config::{RiskConfig, StrikeConfig, TrustRecoveryConfig};

    fn cfg() -> RiskConfig {
        let mut c = RiskConfig::default();
        c.strikes = Some(StrikeConfig { block_at: 5 });
        c.trust_recovery = Some(TrustRecoveryConfig { per_hour: 30 });
        c
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn render_list_returns_documented_envelope_when_empty() {
        let tracker = RiskTracker::new(&cfg());
        let body = render_list(&tracker, 10);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["total_tracked"].as_u64(), Some(0));
        assert_eq!(v["returned"].as_u64(), Some(0));
        assert!(v["clients"].as_array().unwrap().is_empty());
    }

    #[test]
    fn render_list_reflects_strike_block_pill() {
        let tracker = RiskTracker::new(&cfg());
        for _ in 0..5 {
            tracker.record_malicious(ip("10.0.0.1"), 1);
        }
        let body = render_list(&tracker, 10);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["total_tracked"].as_u64(), Some(1));
        let client = &v["clients"][0];
        assert_eq!(client["ip"].as_str(), Some("10.0.0.1"));
        assert_eq!(client["strike_blocked"].as_bool(), Some(true));
        assert_eq!(client["level"].as_str(), Some("block"));
    }

    #[test]
    fn render_list_clamps_limit() {
        let tracker = RiskTracker::new(&cfg());
        for i in 0..10u8 {
            tracker.record_malicious(ip(&format!("10.0.0.{i}")), 10);
        }
        // Caller asked for 0 → clamped to 1.
        let body = render_list(&tracker, 0);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["clients"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn render_detail_returns_200_with_client_block_when_known() {
        let tracker = RiskTracker::new(&cfg());
        tracker.record_malicious(ip("10.0.0.1"), 90);
        let (status, body) = render_detail(&tracker, ip("10.0.0.1"));
        assert_eq!(status, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["client"]["ip"].as_str(), Some("10.0.0.1"));
        assert_eq!(v["client"]["score"].as_u64(), Some(90));
    }

    #[test]
    fn render_detail_returns_404_when_unknown() {
        let tracker = RiskTracker::new(&cfg());
        let (status, body) = render_detail(&tracker, ip("8.8.8.8"));
        assert_eq!(status, 404);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["error"].as_str(), Some("not_found"));
        assert_eq!(v["ip"].as_str(), Some("8.8.8.8"));
    }

    #[test]
    fn parse_ip_segment_handles_v4_and_v6() {
        assert!(parse_ip_segment("10.0.0.1").is_some());
        assert!(parse_ip_segment("::1").is_some());
        assert!(parse_ip_segment("not-an-ip").is_none());
        assert!(parse_ip_segment("").is_none());
    }
}
