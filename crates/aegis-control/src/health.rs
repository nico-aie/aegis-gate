use aegis_core::health::ReadinessSignal;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Health check responses.
#[derive(Clone, Debug, serde::Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub checks: HealthChecks,
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
        },
    )
}

/// Startup check: 200 after first config load completes.
pub fn check_startup(probe: &StartupProbe) -> (u16, &'static str) {
    if probe.is_started() {
        (200, "started")
    } else {
        (503, "starting")
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
