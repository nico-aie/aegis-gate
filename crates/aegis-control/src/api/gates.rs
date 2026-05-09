//! `/api/gates/*` — operator-facing read surface for the four
//! request-flow gates (access list, strike-block, rate-limit, DDoS)
//! that fire BEFORE the detector chain.
//!
//! 2026-05-09 — built alongside the new "Traffic Gates" dashboard
//! page so operators have one place to see (a) which gates are
//! protecting them and (b) live telemetry from each.
//!
//! Today this module ships the **DDoS** read surface only. The
//! other three gates already have dedicated endpoints
//! (`/api/blacklist`, `/api/whitelist`, `/api/risk`,
//! `/api/rate-limit/*`); the SPA aggregates them on the Traffic
//! Gates page client-side. A future `/api/gates/summary`
//! endpoint can collapse those into one server-side response if
//! the page-load cost ever matters.
//!
//! ## Why a dedicated module
//!
//! DDoS is **not a `Detector` trait impl** — it doesn't fit on
//! the Detectors page or under `/api/detectors`. It's a request-
//! flow gate (sliding-window per-IP burst counter + EWMA spike-
//! mode ticker, both reading from the shared `StateBackend`).
//! See [`docs/security/ddos-protection.md`](../../../../docs/security/ddos-protection.md).

use serde::Serialize;
use std::sync::Arc;

use aegis_security::ddos::DdosRuntime;

/// Read shape returned by `GET /api/gates/ddos`.
///
/// `runtime` is `None` when the gate is disabled at boot
/// (`cfg.ddos.enabled = false`) — the SPA renders an empty-state
/// card with a "DDoS gate disabled" message in that case.
#[derive(Debug, Serialize)]
pub struct DdosView {
    /// `true` if a `DdosRuntime` is installed in `DashboardServices`.
    pub enabled: bool,
    /// `false` for enforce mode (default), `true` for shadow mode.
    /// Read-only on the wire — operators flip it via YAML +
    /// reload. Hot-reload of DDoS thresholds is queued as a
    /// follow-up.
    pub observe_only: bool,
    /// EWMA spike-detection telemetry. `current_rps` and
    /// `baseline_rps` are reachable on `Arc<DdosRuntime>` and
    /// updated by the once-per-second `tick_rps()` ticker spawned
    /// in `aegis-proxy::run`.
    pub current_rps: u64,
    pub baseline_rps: u64,
    pub spike_active: bool,
}

impl DdosView {
    pub fn from_runtime(runtime: Option<&Arc<DdosRuntime>>) -> Self {
        match runtime {
            Some(r) => Self {
                enabled: true,
                observe_only: r.observe_only(),
                current_rps: r.current_rps(),
                baseline_rps: r.baseline_rps(),
                spike_active: r.is_spike_active(),
            },
            None => Self {
                enabled: false,
                observe_only: false,
                current_rps: 0,
                baseline_rps: 0,
                spike_active: false,
            },
        }
    }
}

/// Render the GET payload. Stable across calls; cheap (one
/// atomic load per telemetry field). Caller plumbs the response
/// into the standard `json_body_response(200, ..., "private,
/// max-age=2")` shape.
pub fn render_get(runtime: Option<&Arc<DdosRuntime>>) -> String {
    let view = DdosView::from_runtime(runtime);
    serde_json::to_string(&view).unwrap_or_else(|_| String::from("{}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_returns_disabled_shape_when_runtime_absent() {
        let body = render_get(None);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["enabled"], false);
        assert_eq!(v["observe_only"], false);
        assert_eq!(v["current_rps"], 0);
        assert_eq!(v["baseline_rps"], 0);
        assert_eq!(v["spike_active"], false);
    }

    #[test]
    fn render_returns_runtime_shape_when_present() {
        // MockState lives in the ddos test module; we can't reach
        // it from here. Build a real DdosRuntime against a
        // `noop` state backend for the smoke test.
        use aegis_security::ddos::DdosConfig;
        use std::time::Duration;

        struct DummyState;

        #[async_trait::async_trait]
        impl aegis_core::state::StateBackend for DummyState {
            async fn get(&self, _: &str) -> aegis_core::Result<Option<Vec<u8>>> {
                Ok(None)
            }
            async fn set(&self, _: &str, _: &[u8], _: Duration) -> aegis_core::Result<()> {
                Ok(())
            }
            async fn del(&self, _: &str) -> aegis_core::Result<()> {
                Ok(())
            }
            async fn incr_window(
                &self,
                _: &str,
                _: Duration,
                _: u64,
            ) -> aegis_core::Result<aegis_core::SlidingWindowResult> {
                Ok(aegis_core::SlidingWindowResult {
                    count: 1,
                    allowed: true,
                    retry_after: None,
                })
            }
            async fn token_bucket(&self, _: &str, _: u32, _: u32) -> aegis_core::Result<bool> {
                Ok(true)
            }
            async fn get_risk(&self, _: &aegis_core::RiskKey) -> aegis_core::Result<u32> {
                Ok(0)
            }
            async fn add_risk(
                &self,
                _: &aegis_core::RiskKey,
                _: i32,
                _: u32,
            ) -> aegis_core::Result<u32> {
                Ok(0)
            }
            async fn auto_block(
                &self,
                _: std::net::IpAddr,
                _: Duration,
            ) -> aegis_core::Result<()> {
                Ok(())
            }
            async fn is_auto_blocked(
                &self,
                _: std::net::IpAddr,
            ) -> aegis_core::Result<bool> {
                Ok(false)
            }
            async fn put_nonce(&self, _: &str, _: Duration) -> aegis_core::Result<bool> {
                Ok(true)
            }
            async fn consume_nonce(&self, _: &str) -> aegis_core::Result<bool> {
                Ok(true)
            }
        }

        let runtime = Arc::new(DdosRuntime::new(
            DdosConfig {
                enabled: true,
                observe_only: false,
                per_ip_limit: 100,
                per_ip_window_s: 10,
                block_ttl_s: 60,
                spike_multiplier: 3.0,
                tightened_per_ip_rps: 20,
            },
            Arc::new(DummyState),
        ));
        let body = render_get(Some(&runtime));
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["enabled"], true);
        assert_eq!(v["observe_only"], false);
        assert!(v.get("current_rps").is_some());
        assert!(v.get("baseline_rps").is_some());
        assert_eq!(v["spike_active"], false);
    }
}
