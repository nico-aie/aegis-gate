use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Clone)]
pub struct ReadinessSignal {
    pub config_loaded: Arc<AtomicBool>,
    /// Boot warm-up gate. Held `false` until the state-backend rehydrate
    /// probe round-trips (or the warm-up deadline elapses), which is what
    /// keeps a fresh node at `/healthz/ready` 503 until its state is warm.
    /// Once `true` it stays `true`: a *later* backend outage must NOT pull
    /// the node out of rotation, because the data plane keeps serving via
    /// in-memory fallback. Live connectivity is tracked separately by
    /// [`Self::state_backend_connected`].
    ///
    /// 2026-06-18 (healthz-ready-misreports-redis-down report): this field
    /// used to be the single `state_backend_up` atomic that both gated
    /// readiness and was reported on the wire — set once at boot and never
    /// updated, so `/healthz/ready` reported `state_backend_up: true` for
    /// the entire duration of a Redis outage. Split into a boot gate (this
    /// field) + a live signal (below).
    pub state_warmup_done: Arc<AtomicBool>,
    /// Live state-backend connectivity, refreshed by a periodic poller in
    /// the proxy. Reported on `/healthz/ready` as `checks.state_backend_up`
    /// so monitors observe a real outage, but intentionally NOT part of
    /// [`Self::is_ready`]: a transient backend blip surfaces as `degraded`
    /// (HTTP 200, still serving) rather than 503 (pulled from the LB).
    pub state_backend_connected: Arc<AtomicBool>,
    /// R-1b (2026-06-19): live state-backend **writability**, refreshed by the
    /// same proxy poller via a tiny set/del probe. A read-only Redis replica
    /// (the `REPLICAOF`-hijack scenario) still answers PING — so
    /// [`Self::state_backend_connected`] stays `true` — but rejects writes,
    /// which silently broke admin-session persistence. Reported on
    /// `/healthz/ready` as `checks.state_backend_writable` (surfaces as
    /// `degraded`, HTTP 200); like the connectivity signal it is NOT a gate —
    /// the data plane keeps serving on in-memory fallback. Defaults `true` so
    /// a node isn't falsely degraded before the first probe tick.
    pub state_backend_writable: Arc<AtomicBool>,
    pub certs_loaded: Arc<AtomicBool>,
    pub pool_has_healthy: Arc<AtomicBool>,
    pub draining: Arc<AtomicBool>,
    /// 2026-06-18 (runtime-config-lost-on-redis-data-loss report): set by the
    /// shared-store config watcher when it detects the store came back empty
    /// after a version had been applied (e.g. Redis restarted without
    /// persistence) and the node fell back to the on-disk file baseline —
    /// silently dropping operator-authored pools/routes. Reported on
    /// `/healthz/ready` (surfaces as `degraded`, HTTP 200) but, like
    /// [`Self::state_backend_connected`], NOT a gate: the node keeps serving
    /// the baseline. Cleared when a shared config doc is present again.
    pub config_store_degraded: Arc<AtomicBool>,
}

impl Default for ReadinessSignal {
    fn default() -> Self {
        Self {
            config_loaded: Arc::new(AtomicBool::new(false)),
            state_warmup_done: Arc::new(AtomicBool::new(false)),
            state_backend_connected: Arc::new(AtomicBool::new(false)),
            // Default true (report-only): avoid a spurious "degraded" before
            // the first write-probe tick; the poller corrects within ~3 s.
            state_backend_writable: Arc::new(AtomicBool::new(true)),
            certs_loaded: Arc::new(AtomicBool::new(false)),
            pool_has_healthy: Arc::new(AtomicBool::new(false)),
            draining: Arc::new(AtomicBool::new(false)),
            config_store_degraded: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl ReadinessSignal {
    pub fn is_ready(&self) -> bool {
        self.config_loaded.load(Ordering::Relaxed)
            && self.state_warmup_done.load(Ordering::Relaxed)
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
        r.state_warmup_done.store(true, Ordering::Relaxed);
        r.certs_loaded.store(true, Ordering::Relaxed);
        r.pool_has_healthy.store(true, Ordering::Relaxed);
        assert!(r.is_ready());
    }

    #[test]
    fn not_ready_when_draining() {
        let r = ReadinessSignal::default();
        r.config_loaded.store(true, Ordering::Relaxed);
        r.state_warmup_done.store(true, Ordering::Relaxed);
        r.certs_loaded.store(true, Ordering::Relaxed);
        r.pool_has_healthy.store(true, Ordering::Relaxed);
        r.draining.store(true, Ordering::Relaxed);
        assert!(!r.is_ready());
    }

    #[test]
    fn undrain_restores_readiness() {
        // Drain flips readiness off; undrain (clearing the flag) restores it
        // without touching the other gates — the basis of the console's
        // reversible Drain/Resume toggle.
        let r = ReadinessSignal::default();
        r.config_loaded.store(true, Ordering::Relaxed);
        r.state_warmup_done.store(true, Ordering::Relaxed);
        r.certs_loaded.store(true, Ordering::Relaxed);
        r.pool_has_healthy.store(true, Ordering::Relaxed);

        r.draining.store(true, Ordering::Relaxed);
        assert!(!r.is_ready(), "draining → not ready");
        assert!(!r.is_live(), "draining → not live");

        r.draining.store(false, Ordering::Relaxed);
        assert!(r.is_ready(), "undrain → ready again");
        assert!(r.is_live(), "undrain → live again");
    }

    #[test]
    fn not_ready_when_missing_pool() {
        let r = ReadinessSignal::default();
        r.config_loaded.store(true, Ordering::Relaxed);
        r.state_warmup_done.store(true, Ordering::Relaxed);
        r.certs_loaded.store(true, Ordering::Relaxed);
        // pool_has_healthy left false
        assert!(!r.is_ready());
    }

    #[test]
    fn ready_independent_of_live_backend_connectivity() {
        // 2026-06-18 regression: once warmed, a backend disconnect must not
        // flip is_ready() — the node stays in rotation on in-memory fallback.
        let r = ReadinessSignal::default();
        r.config_loaded.store(true, Ordering::Relaxed);
        r.state_warmup_done.store(true, Ordering::Relaxed);
        r.certs_loaded.store(true, Ordering::Relaxed);
        r.pool_has_healthy.store(true, Ordering::Relaxed);
        // Backend reported disconnected — readiness must still hold.
        r.state_backend_connected.store(false, Ordering::Relaxed);
        assert!(r.is_ready());
    }

    #[test]
    fn not_ready_until_warmup_done() {
        let r = ReadinessSignal::default();
        r.config_loaded.store(true, Ordering::Relaxed);
        r.certs_loaded.store(true, Ordering::Relaxed);
        r.pool_has_healthy.store(true, Ordering::Relaxed);
        // Warm-up gate still false → not ready (fresh-node 503-until-warm).
        assert!(!r.is_ready());
        r.state_warmup_done.store(true, Ordering::Relaxed);
        assert!(r.is_ready());
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
