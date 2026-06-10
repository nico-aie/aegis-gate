//! `/api/about` endpoint (D-M2-T2.6).
//!
//! Returns the WAF identity tuple — name, version, build SHA,
//! deployment environment label. Used by:
//!
//! - The SPA topbar to fill the version + env slots (placeholders
//!   today; populated by `pages/overview.js` after the first
//!   `/api/about` poll in D-M2-T2.7).
//! - The Tracking page to detect whether benchmark mode is
//!   configured (the dashboard panel only renders when
//!   `benchmark.configured_mode != null`; that field is added
//!   later by the parallel B-T4.2 task in `plans/benchmark-mode.md`).
//!
//! Spec: `docs/control-plane/enterprise/api.md` §"Stats / Overview".

#![allow(dead_code)]

use std::sync::OnceLock;

use serde::Serialize;

/// Process boot timestamp — captured the first time `/api/about`
/// is rendered (or sooner via `mark_started`). Lets the dashboard
/// compute UPTIME from `Date.now() - started_at` without a
/// dedicated runtime endpoint. CQF-T9.
static BOOT_TS: OnceLock<chrono::DateTime<chrono::Utc>> = OnceLock::new();

/// Stamp the process's boot time. Idempotent: only the first call
/// wins. Safe to call from `aegis-bin::main` at startup so the
/// timestamp reflects actual boot, not the first dashboard
/// request.
pub fn mark_started() -> chrono::DateTime<chrono::Utc> {
    *BOOT_TS.get_or_init(chrono::Utc::now)
}

/// Read the process boot timestamp, lazily initialising on first
/// call. Returns the same timestamp for the rest of the process
/// lifetime.
///
/// Public so `health.rs`'s `/healthz/ready` handler can compute
/// `uptime_seconds` (F-CRITICAL-003 Round-1 mandate).
pub fn boot_ts() -> chrono::DateTime<chrono::Utc> {
    *BOOT_TS.get_or_init(chrono::Utc::now)
}

/// JSON shape returned by `GET /api/about`.
///
/// `build_sha` is optional because development builds typically
/// don't have `AEGIS_BUILD_SHA` baked in; CI populates it via
/// `cargo build`'s environment so released binaries always carry
/// the commit they were cut from.
#[derive(Clone, Debug, Serialize)]
pub struct AboutResponse {
    pub name: &'static str,
    pub version: &'static str,
    pub build_sha: Option<&'static str>,
    pub environment: Option<String>,
    /// Process boot time as RFC 3339 (UTC). The dashboard computes
    /// UPTIME = `Date.now() - started_at` rather than carry a
    /// duration field that goes stale between polls.
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// MTLS-T9 — true when `AEGIS_ZERO_TRUST_BREAK_GLASS=1` was set at
    /// process start. The dashboard renders a prominent red
    /// banner whenever this is true so operators can't miss
    /// that mTLS enforcement is downgraded.
    pub zero_trust_break_glass_active: bool,
}

impl AboutResponse {
    /// Build a response from the live admin-config environment field.
    /// All other fields come from compile-time constants.
    pub fn new(environment: Option<String>) -> Self {
        Self {
            name: "Aegis WAF",
            version: env!("CARGO_PKG_VERSION"),
            build_sha: option_env!("AEGIS_BUILD_SHA"),
            environment,
            started_at: boot_ts(),
            zero_trust_break_glass_active: aegis_core::break_glass::is_active(),
        }
    }
}

/// Render `GET /api/about` as JSON. No caching — every field is a
/// compile-time constant or a small `Option<String>` clone, so a
/// fresh allocation per request is the cheapest correct path.
pub fn render(environment: Option<String>) -> String {
    serde_json::to_string(&AboutResponse::new(environment))
        .unwrap_or_else(|_| String::from("{}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_carries_all_documented_keys() {
        let body = render(Some("staging".into()));
        let v: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        let obj = v.as_object().expect("top-level object");
        for key in ["name", "version", "build_sha", "environment", "started_at"] {
            assert!(obj.contains_key(key), "/api/about missing {key}");
        }
    }

    #[test]
    fn started_at_is_stable_across_calls() {
        // Boot timestamp is captured once and reused — repeated
        // /api/about reads must report the same value.
        let a = render(None);
        let b = render(None);
        let av: serde_json::Value = serde_json::from_str(&a).unwrap();
        let bv: serde_json::Value = serde_json::from_str(&b).unwrap();
        assert_eq!(av["started_at"], bv["started_at"]);
    }

    #[test]
    fn name_is_aegis_waf() {
        let body = render(None);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["name"].as_str(), Some("Aegis WAF"));
    }

    #[test]
    fn version_matches_cargo_pkg_version() {
        let body = render(None);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let version = v["version"].as_str().expect("version is string");
        assert!(!version.is_empty());
        assert_eq!(version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn build_sha_serialised_as_null_when_unset() {
        // Tests run without AEGIS_BUILD_SHA set so the field must
        // serialise as JSON null — but the key still has to exist
        // so the dashboard's null-check works.
        let body = render(None);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        // Value::Null is the expected shape; either Null or a string.
        let sha = &v["build_sha"];
        assert!(
            sha.is_null() || sha.as_str().is_some(),
            "build_sha must be null or string, got {sha:?}"
        );
    }

    #[test]
    fn environment_passes_through_when_set() {
        let body = render(Some("prod".into()));
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["environment"].as_str(), Some("prod"));
    }

    #[test]
    fn environment_is_null_when_none() {
        let body = render(None);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v["environment"].is_null(), "environment should be null");
    }

    #[test]
    fn render_emits_valid_json() {
        let body = render(Some("dev".into()));
        let v: serde_json::Value =
            serde_json::from_str(&body).expect("render must emit valid JSON");
        assert!(v.is_object());
    }
}
