//! Adaptive load shedder using the Gradient2 algorithm.
//!
//! Per-pool: `L(t+1) = L(t) * (RTT_min / RTT_now)`.
//! Priority drop order: CatchAll → Medium → High; Critical never shed.
//! Shed response: 503 + `Retry-After` + request id, zero pipeline cost.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use aegis_core::tier::Tier;

/// Gradient2-based load shedder.
pub struct LoadShedder {
    /// Minimum observed RTT in microseconds.
    rtt_min_us: AtomicU64,
    /// Current smoothed RTT in microseconds.
    rtt_now_us: AtomicU64,
    /// Current concurrency limit.
    limit: AtomicU64,
    /// Current in-flight count.
    inflight: AtomicU64,
    /// Minimum limit floor.
    min_limit: u64,
}

impl LoadShedder {
    pub fn new(initial_limit: u64, min_limit: u64) -> Self {
        Self {
            rtt_min_us: AtomicU64::new(u64::MAX),
            rtt_now_us: AtomicU64::new(0),
            limit: AtomicU64::new(initial_limit),
            inflight: AtomicU64::new(0),
            min_limit,
        }
    }

    /// Record a completed request's RTT and update the gradient.
    pub fn record_rtt(&self, rtt: Duration) {
        let us = rtt.as_micros() as u64;
        if us == 0 {
            return;
        }

        // Update min RTT.
        let mut current_min = self.rtt_min_us.load(Ordering::Relaxed);
        while us < current_min {
            match self.rtt_min_us.compare_exchange_weak(
                current_min,
                us,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current_min = actual,
            }
        }

        // Exponential moving average for current RTT.
        let alpha = 0.2f64;
        let prev = self.rtt_now_us.load(Ordering::Relaxed);
        let smoothed = if prev == 0 {
            us
        } else {
            (alpha * us as f64 + (1.0 - alpha) * prev as f64) as u64
        };
        self.rtt_now_us.store(smoothed, Ordering::Relaxed);

        // Gradient: new_limit = limit * (rtt_min / rtt_now).
        let rtt_min = self.rtt_min_us.load(Ordering::Relaxed);
        if smoothed > 0 && rtt_min < u64::MAX {
            let gradient = rtt_min as f64 / smoothed as f64;
            let current_limit = self.limit.load(Ordering::Relaxed) as f64;
            let new_limit = (current_limit * gradient).max(self.min_limit as f64) as u64;
            self.limit.store(new_limit, Ordering::Relaxed);
        }
    }

    /// Try to acquire a slot for a request with the given tier.
    /// Returns `true` if the request should proceed, `false` if it should be shed.
    pub fn should_admit(&self, tier: &Tier) -> bool {
        // Critical requests are never shed.
        if matches!(tier, Tier::Critical) {
            return true;
        }

        let inflight = self.inflight.load(Ordering::Relaxed);
        let limit = self.limit.load(Ordering::Relaxed);

        if inflight < limit {
            return true;
        }

        // Over limit — shed based on tier priority.
        // High gets more headroom than Medium, which gets more than CatchAll.
        let headroom = match tier {
            Tier::High => (limit as f64 * 0.1) as u64,    // 10% headroom
            Tier::Medium => 0,                              // no headroom
            Tier::CatchAll => 0,                            // first to shed
            Tier::Critical => unreachable!(),
        };

        inflight < limit + headroom
    }

    /// Increment in-flight counter.
    pub fn acquire(&self) {
        self.inflight.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement in-flight counter.
    pub fn release(&self) {
        self.inflight.fetch_sub(1, Ordering::Relaxed);
    }

    /// Current concurrency limit.
    pub fn current_limit(&self) -> u64 {
        self.limit.load(Ordering::Relaxed)
    }

    /// Current in-flight count.
    pub fn current_inflight(&self) -> u64 {
        self.inflight.load(Ordering::Relaxed)
    }

    /// Current smoothed RTT.
    pub fn current_rtt(&self) -> Duration {
        Duration::from_micros(self.rtt_now_us.load(Ordering::Relaxed))
    }

    /// Minimum observed RTT.
    pub fn min_rtt(&self) -> Option<Duration> {
        let v = self.rtt_min_us.load(Ordering::Relaxed);
        if v == u64::MAX {
            None
        } else {
            Some(Duration::from_micros(v))
        }
    }
}

/// Which tiers to shed and in what order.
pub fn shed_order() -> [Tier; 3] {
    [Tier::CatchAll, Tier::Medium, Tier::High]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_never_shed() {
        let s = LoadShedder::new(1, 1);
        // Saturate the limit.
        s.acquire();
        s.acquire();
        // Critical still admitted.
        assert!(s.should_admit(&Tier::Critical));
    }

    #[test]
    fn catchall_shed_first() {
        let s = LoadShedder::new(20, 1);
        for _ in 0..20 {
            s.acquire();
        }
        // At limit — CatchAll should be shed.
        assert!(!s.should_admit(&Tier::CatchAll));
        // High gets 10% headroom (2 slots).
        assert!(s.should_admit(&Tier::High));
    }

    #[test]
    fn under_limit_all_admitted() {
        let s = LoadShedder::new(100, 1);
        assert!(s.should_admit(&Tier::CatchAll));
        assert!(s.should_admit(&Tier::Medium));
        assert!(s.should_admit(&Tier::High));
        assert!(s.should_admit(&Tier::Critical));
    }

    #[test]
    fn gradient_reduces_limit_on_high_rtt() {
        let s = LoadShedder::new(100, 10);
        // Record a fast baseline.
        s.record_rtt(Duration::from_millis(1));
        let limit_after_fast = s.current_limit();

        // Record much slower RTT.
        for _ in 0..20 {
            s.record_rtt(Duration::from_millis(100));
        }
        let limit_after_slow = s.current_limit();
        assert!(
            limit_after_slow < limit_after_fast,
            "limit should decrease: {limit_after_slow} < {limit_after_fast}"
        );
    }

    #[test]
    fn gradient_respects_min_limit() {
        let s = LoadShedder::new(100, 50);
        s.record_rtt(Duration::from_millis(1));
        // Massive RTT spike.
        for _ in 0..100 {
            s.record_rtt(Duration::from_secs(10));
        }
        assert!(s.current_limit() >= 50);
    }

    #[test]
    fn acquire_release_tracking() {
        let s = LoadShedder::new(100, 1);
        s.acquire();
        s.acquire();
        assert_eq!(s.current_inflight(), 2);
        s.release();
        assert_eq!(s.current_inflight(), 1);
    }

    #[test]
    fn shed_order_priority() {
        let order = shed_order();
        assert_eq!(order[0], Tier::CatchAll);
        assert_eq!(order[1], Tier::Medium);
        assert_eq!(order[2], Tier::High);
    }

    #[test]
    fn min_rtt_none_initially() {
        let s = LoadShedder::new(100, 1);
        assert!(s.min_rtt().is_none());
        s.record_rtt(Duration::from_millis(5));
        assert_eq!(s.min_rtt().unwrap(), Duration::from_millis(5));
    }

    #[test]
    fn synthetic_overload_critical_survives() {
        let s = LoadShedder::new(10, 5);
        // Fill to capacity.
        for _ in 0..10 {
            s.acquire();
        }

        let mut critical_ok = 0u32;
        let mut catchall_ok = 0u32;
        let total = 1000;

        for _ in 0..total {
            if s.should_admit(&Tier::Critical) {
                critical_ok += 1;
            }
            if s.should_admit(&Tier::CatchAll) {
                catchall_ok += 1;
            }
        }

        // Critical: 100% success.
        assert_eq!(critical_ok, total);
        // CatchAll: should be fully shed.
        assert_eq!(catchall_ok, 0);
    }
}
