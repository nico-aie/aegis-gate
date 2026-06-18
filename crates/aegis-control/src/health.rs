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

/// Readiness check.
///
/// 2026-06-18 (healthz-ready-misreports-redis-down report):
/// `checks.state_backend_up` now reflects **live** backend connectivity
/// (`ReadinessSignal::state_backend_connected`, refreshed by the proxy's
/// health poller) instead of the boot warm-up gate — so a real Redis
/// outage is visible on the wire. The overall status is three-valued:
/// - `503 not_ready` — a readiness gate is unsatisfied (warm-up not done,
///   config/certs/pool missing, or draining). Pull from rotation.
/// - `200 degraded` — warm and serving, but the state backend is currently
///   unreachable. The data plane runs on in-memory fallback, so the node
///   stays in rotation; the field flags the degradation for monitors.
/// - `200 ok` — everything healthy.
pub fn check_ready(signal: &ReadinessSignal) -> (u16, HealthResponse) {
    let backend_connected = signal.state_backend_connected.load(Ordering::Relaxed);
    let checks = HealthChecks {
        config_loaded: signal.config_loaded.load(Ordering::Relaxed),
        state_backend_up: backend_connected,
        certs_loaded: signal.certs_loaded.load(Ordering::Relaxed),
        pool_has_healthy: signal.pool_has_healthy.load(Ordering::Relaxed),
        draining: signal.draining.load(Ordering::Relaxed),
    };
    let (status, label) = if !signal.is_ready() {
        (503, "not_ready")
    } else if !backend_connected {
        (200, "degraded")
    } else {
        (200, "ok")
    };
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

// Phase 1 (leaderless): `check_ready_strict` + the
// `/healthz/ready?strict=1` "not_leader 503" mode were removed.
// The cluster has no leader, so readiness is purely node-local
// (`check_ready` — state rehydrated + listeners bound + not
// draining). Singleton side-tasks coordinate via per-task leases,
// not LB-gated leader ingress.

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
        s.state_warmup_done.store(true, Ordering::Relaxed);
        s.state_backend_connected.store(true, Ordering::Relaxed);
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
    fn ready_503_until_warmup_done() {
        // The boot warm-up gate (not live connectivity) gates readiness.
        let s = all_ready();
        s.state_warmup_done.store(false, Ordering::Relaxed);
        let (code, resp) = check_ready(&s);
        assert_eq!(code, 503);
        assert_eq!(resp.status, "not_ready");
    }

    // 2026-06-18 (healthz-ready-misreports-redis-down report) — when the
    // node is warm + serving but the state backend is unreachable, the
    // readiness probe must report the outage truthfully (state_backend_up
    // false, status "degraded") WITHOUT 503-ing the node out of rotation,
    // and /healthz/live must stay 200.
    #[test]
    fn degraded_200_when_warm_but_backend_disconnected() {
        let s = all_ready();
        s.state_backend_connected.store(false, Ordering::Relaxed);
        let (code, resp) = check_ready(&s);
        assert_eq!(code, 200);
        assert_eq!(resp.status, "degraded");
        assert!(
            !resp.checks.state_backend_up,
            "state_backend_up must reflect the live outage"
        );
        // Liveness is unaffected — the process is alive and not draining.
        assert_eq!(check_live(&s).0, 200);
    }

    #[test]
    fn ok_200_when_backend_connected() {
        let s = all_ready();
        let (code, resp) = check_ready(&s);
        assert_eq!(code, 200);
        assert_eq!(resp.status, "ok");
        assert!(resp.checks.state_backend_up);
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

    // Phase 1 (leaderless): the HA-T5 strict-mode tests were
    // removed alongside `check_ready_strict` / `?strict=1`.
    // Readiness is node-local only — covered by the plain
    // `check_ready` transition tests below.

    // Transition tests.
    #[test]
    fn ready_transitions_503_to_200() {
        let s = ReadinessSignal::default();
        assert_eq!(check_ready(&s).0, 503);
        s.config_loaded.store(true, Ordering::Relaxed);
        s.state_warmup_done.store(true, Ordering::Relaxed);
        s.state_backend_connected.store(true, Ordering::Relaxed);
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
