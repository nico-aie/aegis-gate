//! Adaptive load shedder using the Gradient2 algorithm.
//!
//! Per-pool: `L(t+1) = L(t) * (RTT_min / RTT_now)`.
//! Priority drop order: CatchAll → Medium → High; Critical never shed.
//! Shed response: 503 + `Retry-After` + request id, zero pipeline cost.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
    /// Maximum limit ceiling. Caps the grow path so a long
    /// healthy run can't push the limit to unbounded values.
    /// Set to the constructor's `initial_limit` so the operator-
    /// configured value is the steady-state target.
    max_limit: u64,
}

impl LoadShedder {
    pub fn new(initial_limit: u64, min_limit: u64) -> Self {
        Self {
            rtt_min_us: AtomicU64::new(u64::MAX),
            rtt_now_us: AtomicU64::new(0),
            limit: AtomicU64::new(initial_limit),
            inflight: AtomicU64::new(0),
            min_limit,
            max_limit: initial_limit,
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

        // Gradient: gradient = rtt_min / rtt_now ∈ (0, 1].
        //
        // F-HIGH-lifecycle (2026-05-17 s-tester audit): pre-fix the
        // update was unconditionally `new = old * gradient` —
        // multiplicative decrease only. Since gradient ≤ 1.0 by
        // construction (rtt_min is the minimum), the limit could
        // ONLY shrink. After any transient RTT spike that lowered
        // the limit, no recovery path existed even when the system
        // returned to healthy operation. The shedder slowly bled
        // down to `min_limit` and stayed there.
        //
        // Now AIMD-shaped:
        //   gradient >= 0.9   → system healthy → +1 (additive grow)
        //   gradient <  0.9   → system stressed → *= gradient
        //                       (multiplicative shrink, clamped to
        //                       `min_limit`)
        // Grow path is clamped to `max_limit` (the configured
        // `initial_limit`) so a long healthy run doesn't push the
        // concurrency past the operator's bias.
        let rtt_min = self.rtt_min_us.load(Ordering::Relaxed);
        if smoothed > 0 && rtt_min < u64::MAX {
            let gradient = rtt_min as f64 / smoothed as f64;
            let current_limit = self.limit.load(Ordering::Relaxed);
            let new_limit = if gradient >= 0.9 {
                (current_limit + 1).min(self.max_limit)
            } else {
                let shrunk = (current_limit as f64 * gradient) as u64;
                shrunk.max(self.min_limit)
            };
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
            Tier::Low => 0,                            // first to shed
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

    /// RAII admit: `acquire`s a slot, captures `Instant::now()`, and
    /// returns a guard whose `Drop` calls `release` + `record_rtt`
    /// with the elapsed time. Use in the data plane so a request
    /// cancelled mid-flight still releases its slot and feeds RTT
    /// signal to the Gradient2 adapter — `acquire` + `release`
    /// without RAII would leak the counter on any future that
    /// drops between the two calls (same class of bug as
    /// F-CRITICAL-008's inflight counter).
    pub fn admit_guard(self: &Arc<Self>) -> ShedGuard {
        self.acquire();
        ShedGuard {
            shedder: Arc::clone(self),
            start: Instant::now(),
        }
    }
}

/// RAII guard issued by [`LoadShedder::admit_guard`]. Drop releases
/// the in-flight slot and records the request's RTT into the
/// Gradient2 estimator.
pub struct ShedGuard {
    shedder: Arc<LoadShedder>,
    start: Instant,
}

impl Drop for ShedGuard {
    fn drop(&mut self) {
        self.shedder.release();
        self.shedder.record_rtt(self.start.elapsed());
    }
}

/// Which tiers to shed and in what order.
pub fn shed_order() -> [Tier; 3] {
    [Tier::Low, Tier::Medium, Tier::High]
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
        assert!(!s.should_admit(&Tier::Low));
        // High gets 10% headroom (2 slots).
        assert!(s.should_admit(&Tier::High));
    }

    #[test]
    fn under_limit_all_admitted() {
        let s = LoadShedder::new(100, 1);
        assert!(s.should_admit(&Tier::Low));
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
    fn gradient_recovers_after_transient_rtt_spike() {
        // F-HIGH-lifecycle regression. Pre-fix the gradient update
        // was multiplicative-only (`limit *= gradient`), and
        // `gradient ≤ 1.0` by construction. After any transient
        // spike the limit shrank to `min_limit` and stayed there
        // forever, defeating the whole point of an adaptive
        // shedder. Now AIMD: grow +1 when gradient >= 0.9, shrink
        // multiplicatively otherwise.
        let s = LoadShedder::new(1000, 100);
        // Establish a fast baseline (sets rtt_min low).
        for _ in 0..10 {
            s.record_rtt(Duration::from_millis(1));
        }
        // Transient stress — push the limit down toward min_limit.
        for _ in 0..50 {
            s.record_rtt(Duration::from_secs(1));
        }
        let limit_after_spike = s.current_limit();
        assert!(
            limit_after_spike <= 200,
            "spike must have shrunk limit: {limit_after_spike}",
        );
        // System recovers — RTT comes back close to rtt_min. Many
        // healthy samples must grow the limit back up (it should
        // recover noticeably; we don't require full restoration to
        // initial because the EMA decays gradually).
        for _ in 0..500 {
            s.record_rtt(Duration::from_millis(1));
        }
        let limit_after_recovery = s.current_limit();
        assert!(
            limit_after_recovery > limit_after_spike,
            "limit must recover: {limit_after_recovery} > {limit_after_spike}",
        );
    }

    #[test]
    fn gradient_grow_clamped_to_max_limit() {
        // Companion to the recovery test — sustained healthy
        // operation must not push limit past `max_limit` (the
        // constructor's `initial_limit`).
        let s = LoadShedder::new(50, 10);
        for _ in 0..10_000 {
            s.record_rtt(Duration::from_millis(1));
        }
        assert!(
            s.current_limit() <= 50,
            "grow must clamp to max_limit (initial_limit): got {}",
            s.current_limit(),
        );
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
        assert_eq!(order[0], Tier::Low);
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
    fn admit_guard_releases_on_drop() {
        // Pre-RAII the data plane manually paired acquire +
        // release; a cancellation between the two leaked the
        // counter. ShedGuard's Drop closes that gap.
        let s = Arc::new(LoadShedder::new(100, 1));
        assert_eq!(s.current_inflight(), 0);
        {
            let _g = s.admit_guard();
            assert_eq!(s.current_inflight(), 1);
        }
        assert_eq!(s.current_inflight(), 0);
    }

    #[test]
    fn admit_guard_releases_on_panic_unwind() {
        // Sister regression: a panic inside the guarded scope must
        // still release. Drop runs during unwind, so this works
        // by construction — pin it with a catch_unwind so a
        // future refactor that disables unwinding can't silently
        // regress.
        let s = Arc::new(LoadShedder::new(100, 1));
        let s_clone = Arc::clone(&s);
        let result = std::panic::catch_unwind(move || {
            let _g = s_clone.admit_guard();
            assert_eq!(s_clone.current_inflight(), 1);
            panic!("simulated downstream panic");
        });
        assert!(result.is_err());
        assert_eq!(s.current_inflight(), 0);
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
            if s.should_admit(&Tier::Low) {
                catchall_ok += 1;
            }
        }

        // Critical: 100% success.
        assert_eq!(critical_ok, total);
        // CatchAll: should be fully shed.
        assert_eq!(catchall_ok, 0);
    }
}
