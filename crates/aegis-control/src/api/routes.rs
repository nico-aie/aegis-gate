//! `/api/routes` (CI-T5).
//!
//! Read-only view of the routing trie consumed by the Tier Config
//! page. Backed by an `ArcSwap`-style [`Mutex<Vec<RouteSummary>>`]
//! so the data-plane bootstrap can swap the table on hot-reload
//! without serialising every read.
//!
//! Source of truth is `WafConfig::routes` in `aegis-core`. The proxy
//! seeds the handler at boot with an adapted snapshot; mutations land
//! through the audit-mutation pipeline (out of scope for CI-T5).
//!
//! Stable JSON shape:
//!
//! ```json
//! {
//!   "routes": [
//!     {
//!       "id": "login",
//!       "host": "api.example.com",
//!       "path": "/login",
//!       "match_type": "exact",
//!       "methods": ["POST"],
//!       "upstream": "auth-pool",
//!       "tier_override": "critical"
//!     }
//!   ]
//! }
//! ```

#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use serde::Serialize;

/// One row of the `/api/routes` response. Mirrors
/// [`aegis_core::config::RouteConfig`] but with every field
/// owned + serialisable (no enum types, just strings) so the
/// dashboard can render without an enum table.
#[derive(Clone, Debug, Serialize)]
pub struct RouteSummary {
    pub id: String,
    /// `None` is rendered as JSON `null` — catch-all routes set this.
    pub host: Option<String>,
    pub path: String,
    /// `"exact"`, `"prefix"`, or `"regex"` — matches the YAML schema.
    pub match_type: String,
    /// Empty when the route accepts every HTTP method.
    pub methods: Vec<String>,
    pub upstream: String,
    /// `None` when the route inherits its tier from the global default.
    pub tier_override: Option<String>,
    /// PR1 — effective evaluation priority computed from the
    /// route's host / path / method / position. Compact tuple
    /// rendered as `<host>.<path-kind>.<segs>.<method>.<declared>.<yaml-pos>`.
    /// Empty string `""` for legacy callers that don't compute it.
    /// Higher matches first; the dashboard sorts by this string
    /// descending. **Additive**: existing clients that ignore the
    /// field still work.
    #[serde(default)]
    pub priority: String,
    /// PR2 — `true` when this route is the default fallback for
    /// its host scope. The dashboard renders a "default" pill.
    #[serde(default)]
    pub default: bool,
    /// PR2 — `false` when the route is admin-disabled (still in
    /// config, skipped from trie). The dashboard dims the row.
    #[serde(default = "default_route_summary_enabled")]
    pub enabled: bool,
    /// `true` when the matched route prefix is stripped from the
    /// forwarded path. Mirrors [`aegis_core::config::RouteConfig::strip_prefix`]
    /// and is emitted so the console can round-trip an explicit
    /// `false` — without it the dashboard reads `undefined !== false`
    /// and re-checks the box on every edit. Defaults to `true` on
    /// deserialize to match `default_strip_prefix` for legacy clients.
    #[serde(default = "default_strip_prefix_summary")]
    pub strip_prefix: bool,
    /// MEDIUM-2 (2026-06-19) — per-route enforcement mode: `"enforce"`
    /// (default) or `"log_only"` (monitor). Emitted so the console can
    /// render the `monitor` badge and the editor checkbox can reflect
    /// saved state. Defaults to `"enforce"` on deserialize for legacy
    /// clients / routes saved before the field existed.
    #[serde(default = "default_route_summary_mode")]
    pub mode: String,
}

fn default_route_summary_enabled() -> bool {
    true
}

fn default_strip_prefix_summary() -> bool {
    true
}

fn default_route_summary_mode() -> String {
    "enforce".to_string()
}

#[derive(Clone, Debug, Serialize)]
pub struct RoutesResponse {
    pub routes: Vec<RouteSummary>,
}

#[derive(Clone)]
pub struct RoutesHandler {
    inner: Arc<Mutex<Vec<RouteSummary>>>,
}

impl Default for RoutesHandler {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl RoutesHandler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the snapshot — called by the proxy at boot and on
    /// every successful hot-reload.
    pub fn set(&self, routes: Vec<RouteSummary>) {
        let mut guard = self.inner.lock().expect("routes handler poisoned");
        *guard = routes;
    }

    pub fn list(&self) -> Vec<RouteSummary> {
        self.inner
            .lock()
            .expect("routes handler poisoned")
            .clone()
    }

    /// Render the `GET /api/routes` body.
    pub fn render(&self) -> String {
        let body = RoutesResponse { routes: self.list() };
        serde_json::to_string(&body).unwrap_or_else(|_| "{\"routes\":[]}".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<RouteSummary> {
        vec![
            RouteSummary {
                id: "login".into(),
                host: Some("api.example.com".into()),
                path: "/login".into(),
                match_type: "exact".into(),
                methods: vec!["POST".into()],
                upstream: "auth-pool".into(),
                tier_override: Some("critical".into()),
                priority: "3.4.1.1.0.0".into(),
                default: false,
                enabled: true,
                strip_prefix: true,
                mode: "enforce".into(),
            },
            RouteSummary {
                id: "catch-all".into(),
                host: None,
                path: "/".into(),
                match_type: "prefix".into(),
                methods: vec![],
                upstream: "backend-pool".into(),
                tier_override: None,
                priority: "0.0.0.0.0.1".into(),
                default: true,
                enabled: true,
                strip_prefix: false,
                mode: "log_only".into(),
            },
        ]
    }

    #[test]
    fn render_empty_returns_routes_field() {
        let h = RoutesHandler::new();
        let body = h.render();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v["routes"].is_array());
        assert_eq!(v["routes"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn render_round_trip_preserves_fields() {
        let h = RoutesHandler::new();
        h.set(sample());
        let v: serde_json::Value = serde_json::from_str(&h.render()).unwrap();
        let routes = v["routes"].as_array().unwrap();
        assert_eq!(routes.len(), 2);

        let login = &routes[0];
        assert_eq!(login["id"], "login");
        assert_eq!(login["host"], "api.example.com");
        assert_eq!(login["match_type"], "exact");
        assert_eq!(login["methods"], serde_json::json!(["POST"]));
        assert_eq!(login["tier_override"], "critical");

        // strip_prefix must serialize so the console can round-trip
        // an explicit false (BUG-route-strip-prefix-toggle-not-roundtripped).
        assert_eq!(login["strip_prefix"], true);

        let catch_all = &routes[1];
        assert!(catch_all["host"].is_null());
        assert!(catch_all["tier_override"].is_null());
        assert!(catch_all["methods"].as_array().unwrap().is_empty());
        assert_eq!(catch_all["strip_prefix"], false);
    }

    #[test]
    fn set_replaces_existing_snapshot() {
        let h = RoutesHandler::new();
        h.set(sample());
        assert_eq!(h.list().len(), 2);
        h.set(vec![]);
        assert_eq!(h.list().len(), 0);
    }
}
