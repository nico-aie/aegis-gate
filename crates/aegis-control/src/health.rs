use aegis_core::health::ReadinessSignal;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Health check responses.
///
/// 2026-05-17 F-CRITICAL-003 (control audit): `uptime_seconds` +
/// `mode` + `active_rule_count` added so the dashboard surfaces
/// the three fields Round-1 explicitly requires from
/// `/healthz/ready`. All three are `Option` so callers that don't
/// have the info available (test fixtures, single-node builds
/// without interop) skip the fields rather than emit defaults.
#[derive(Clone, Debug, serde::Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub checks: HealthChecks,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_rule_count: Option<u64>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct HealthChecks {
    pub config_loaded: bool,
    pub state_backend_up: bool,
    pub certs_loaded: bool,
    pub pool_has_healthy: bool,
    pub draining: bool,
}

/// Startup probe tracker.
#[derive(Clone)]
pub struct StartupProbe {
    started: Arc<AtomicBool>,
}

impl Default for StartupProbe {
    fn default() -> Self {
        Self {
            started: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl StartupProbe {
    pub fn mark_started(&self) {
        self.started.store(true, Ordering::Relaxed);
    }

    pub fn is_started(&self) -> bool {
        self.started.load(Ordering::Relaxed)
    }
}

/// Liveness check: 200 if process is running and not draining.
pub fn check_live(signal: &ReadinessSignal) -> (u16, &'static str) {
    if signal.is_live() {
        (200, "ok")
    } else {
        (503, "draining")
    }
}

/// Readiness check: 200 only when all signals pass.
pub fn check_ready(signal: &ReadinessSignal) -> (u16, HealthResponse) {
    let checks = HealthChecks {
        config_loaded: signal.config_loaded.load(Ordering::Relaxed),
        state_backend_up: signal.state_backend_up.load(Ordering::Relaxed),
        certs_loaded: signal.certs_loaded.load(Ordering::Relaxed),
        pool_has_healthy: signal.pool_has_healthy.load(Ordering::Relaxed),
        draining: signal.draining.load(Ordering::Relaxed),
    };
    let status = if signal.is_ready() { 200 } else { 503 };
    let label = if status == 200 { "ok" } else { "not_ready" };
    (
        status,
        HealthResponse {
            status: label,
            checks,
            uptime_seconds: None,
            mode: None,
            active_rule_count: None,
        },
    )
}

/// Strict readiness check: 200 only when [`check_ready`] passes
/// AND `is_leader` is true. Used by `/healthz/ready?strict=1`,
/// the LB-side variant that lets only the lease-holding node
/// receive the singleton-style traffic (e.g. cluster-wide
/// reconciler ingress in active/standby topologies).
///
/// `is_leader` is provided by the caller — typically
/// `services.leader_view.as_ref().map(|lv| lv.is_leader())`.
/// `None` means "no cluster wired" (single-node build) — strict
/// mode degrades to plain `check_ready`.
pub fn check_ready_strict(
    signal: &ReadinessSignal,
    is_leader: Option<bool>,
) -> (u16, HealthResponse) {
    let (mut status, mut resp) = check_ready(signal);
    if status == 200 {
        if let Some(false) = is_leader {
            status = 503;
            resp.status = "not_leader";
        }
    }
    (status, resp)
}

/// Startup check: 200 after first config load completes.
pub fn check_startup(probe: &StartupProbe) -> (u16, &'static str) {
    if probe.is_started() {
        (200, "started")
    } else {
        (503, "starting")
    }
}

impl HealthResponse {
    /// F-CRITICAL-003 (2026-05-17 control audit): builder that
    /// populates the Round-1 mandated `uptime_seconds` + `mode` +
    /// `active_rule_count` fields. Caller computes uptime from
    /// `aegis_control::api::about::boot_ts`, reads mode from the
    /// interop runtime, and rule count from the live `RuleStore`.
    pub fn with_runtime_info(
        mut self,
        uptime_seconds: u64,
        mode: &'static str,
        active_rule_count: u64,
    ) -> Self {
        self.uptime_seconds = Some(uptime_seconds);
        self.mode = Some(mode);
        self.active_rule_count = Some(active_rule_count);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_ready() -> ReadinessSignal {
        let s = ReadinessSignal::default();
        s.config_loaded.store(true, Ordering::Relaxed);
        s.state_backend_up.store(true, Ordering::Relaxed);
        s.certs_loaded.store(true, Ordering::Relaxed);
        s.pool_has_healthy.store(true, Ordering::Relaxed);
        s
    }

    // Live checks.
    #[test]
    fn live_200_when_not_draining() {
        let s = ReadinessSignal::default();
        let (code, _) = check_live(&s);
        assert_eq!(code, 200);
    }

    #[test]
    fn live_503_when_draining() {
        let s = ReadinessSignal::default();
        s.draining.store(true, Ordering::Relaxed);
        let (code, _) = check_live(&s);
        assert_eq!(code, 503);
    }

    // Ready checks.
    #[test]
    fn ready_200_when_all_signals() {
        let s = all_ready();
        let (code, _) = check_ready(&s);
        assert_eq!(code, 200);
    }

    #[test]
    fn ready_503_when_config_not_loaded() {
        let s = all_ready();
        s.config_loaded.store(false, Ordering::Relaxed);
        let (code, resp) = check_ready(&s);
        assert_eq!(code, 503);
        assert!(!resp.checks.config_loaded);
    }

    #[test]
    fn ready_503_when_state_backend_down() {
        let s = all_ready();
        s.state_backend_up.store(false, Ordering::Relaxed);
        let (code, _) = check_ready(&s);
        assert_eq!(code, 503);
    }

    #[test]
    fn ready_503_when_certs_not_loaded() {
        let s = all_ready();
        s.certs_loaded.store(false, Ordering::Relaxed);
        let (code, _) = check_ready(&s);
        assert_eq!(code, 503);
    }

    #[test]
    fn ready_503_when_no_healthy_pool() {
        let s = all_ready();
        s.pool_has_healthy.store(false, Ordering::Relaxed);
        let (code, _) = check_ready(&s);
        assert_eq!(code, 503);
    }

    #[test]
    fn ready_503_when_draining() {
        let s = all_ready();
        s.draining.store(true, Ordering::Relaxed);
        let (code, _) = check_ready(&s);
        assert_eq!(code, 503);
    }

    #[test]
    fn ready_response_serializes() {
        let s = all_ready();
        let (_, resp) = check_ready(&s);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
        assert!(json.contains("\"config_loaded\":true"));
        // F-CRITICAL-003: the three new fields are `Option` with
        // `skip_serializing_if = Option::is_none`, so callers that
        // don't populate them get the legacy shape (no rotation
        // of existing clients).
        assert!(!json.contains("uptime_seconds"));
        assert!(!json.contains("active_rule_count"));
    }

    #[test]
    fn ready_response_with_runtime_info_carries_round1_fields() {
        // F-CRITICAL-003 regression: builder populates the three
        // Round-1 mandated fields. The dashboard's Health/Status
        // view reads them from this exact JSON shape.
        let s = all_ready();
        let (_, resp) = check_ready(&s);
        let resp = resp.with_runtime_info(123, "enforce", 7);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"uptime_seconds\":123"));
        assert!(json.contains("\"mode\":\"enforce\""));
        assert!(json.contains("\"active_rule_count\":7"));
    }

    // Startup checks.
    #[test]
    fn startup_503_initially() {
        let probe = StartupProbe::default();
        let (code, _) = check_startup(&probe);
        assert_eq!(code, 503);
    }

    #[test]
    fn startup_200_after_started() {
        let probe = StartupProbe::default();
        probe.mark_started();
        let (code, _) = check_startup(&probe);
        assert_eq!(code, 200);
    }

    #[test]
    fn startup_probe_clone_shares_state() {
        let p1 = StartupProbe::default();
        let p2 = p1.clone();
        p1.mark_started();
        assert!(p2.is_started());
    }

    // Strict-mode (HA-T5).
    #[test]
    fn strict_503_when_not_leader() {
        let s = all_ready();
        let (code, resp) = check_ready_strict(&s, Some(false));
        assert_eq!(code, 503);
        assert_eq!(resp.status, "not_leader");
    }

    #[test]
    fn strict_200_when_leader() {
        let s = all_ready();
        let (code, resp) = check_ready_strict(&s, Some(true));
        assert_eq!(code, 200);
        assert_eq!(resp.status, "ok");
    }

    #[test]
    fn strict_200_when_no_cluster_wired() {
        // Single-node builds pass `None` — degrades to plain ready.
        let s = all_ready();
        let (code, _) = check_ready_strict(&s, None);
        assert_eq!(code, 200);
    }

    #[test]
    fn strict_503_when_underlying_not_ready() {
        // Even if we're "the leader", failing pre-conditions
        // keep us out of rotation.
        let s = ReadinessSignal::default();
        let (code, _) = check_ready_strict(&s, Some(true));
        assert_eq!(code, 503);
    }

    // Transition tests.
    #[test]
    fn ready_transitions_503_to_200() {
        let s = ReadinessSignal::default();
        assert_eq!(check_ready(&s).0, 503);
        s.config_loaded.store(true, Ordering::Relaxed);
        s.state_backend_up.store(true, Ordering::Relaxed);
        s.certs_loaded.store(true, Ordering::Relaxed);
        s.pool_has_healthy.store(true, Ordering::Relaxed);
        assert_eq!(check_ready(&s).0, 200);
    }

    #[test]
    fn ready_transitions_200_to_503() {
        let s = all_ready();
        assert_eq!(check_ready(&s).0, 200);
        s.draining.store(true, Ordering::Relaxed);
        assert_eq!(check_ready(&s).0, 503);
    }
}
