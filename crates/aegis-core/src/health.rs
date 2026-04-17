use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Clone)]
pub struct ReadinessSignal {
    pub config_loaded: Arc<AtomicBool>,
    pub state_backend_up: Arc<AtomicBool>,
    pub certs_loaded: Arc<AtomicBool>,
    pub pool_has_healthy: Arc<AtomicBool>,
    pub draining: Arc<AtomicBool>,
}

impl Default for ReadinessSignal {
    fn default() -> Self {
        Self {
            config_loaded: Arc::new(AtomicBool::new(false)),
            state_backend_up: Arc::new(AtomicBool::new(false)),
            certs_loaded: Arc::new(AtomicBool::new(false)),
            pool_has_healthy: Arc::new(AtomicBool::new(false)),
            draining: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl ReadinessSignal {
    pub fn is_ready(&self) -> bool {
        self.config_loaded.load(Ordering::Relaxed)
            && self.state_backend_up.load(Ordering::Relaxed)
            && self.certs_loaded.load(Ordering::Relaxed)
            && self.pool_has_healthy.load(Ordering::Relaxed)
            && !self.draining.load(Ordering::Relaxed)
    }

    pub fn is_live(&self) -> bool {
        !self.draining.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_readiness_is_not_ready() {
        let r = ReadinessSignal::default();
        assert!(!r.is_ready());
    }

    #[test]
    fn ready_when_all_signals_true() {
        let r = ReadinessSignal::default();
        r.config_loaded.store(true, Ordering::Relaxed);
        r.state_backend_up.store(true, Ordering::Relaxed);
        r.certs_loaded.store(true, Ordering::Relaxed);
        r.pool_has_healthy.store(true, Ordering::Relaxed);
        assert!(r.is_ready());
    }

    #[test]
    fn not_ready_when_draining() {
        let r = ReadinessSignal::default();
        r.config_loaded.store(true, Ordering::Relaxed);
        r.state_backend_up.store(true, Ordering::Relaxed);
        r.certs_loaded.store(true, Ordering::Relaxed);
        r.pool_has_healthy.store(true, Ordering::Relaxed);
        r.draining.store(true, Ordering::Relaxed);
        assert!(!r.is_ready());
    }

    #[test]
    fn not_ready_when_missing_pool() {
        let r = ReadinessSignal::default();
        r.config_loaded.store(true, Ordering::Relaxed);
        r.state_backend_up.store(true, Ordering::Relaxed);
        r.certs_loaded.store(true, Ordering::Relaxed);
        // pool_has_healthy left false
        assert!(!r.is_ready());
    }

    #[test]
    fn live_unless_draining() {
        let r = ReadinessSignal::default();
        assert!(r.is_live());
        r.draining.store(true, Ordering::Relaxed);
        assert!(!r.is_live());
    }

    #[test]
    fn readiness_is_clone() {
        let r1 = ReadinessSignal::default();
        r1.config_loaded.store(true, Ordering::Relaxed);
        let r2 = r1.clone();
        assert!(r2.config_loaded.load(Ordering::Relaxed));
    }
}
