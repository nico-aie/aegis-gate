use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Circuit breaker state machine: `Closed → Open → HalfOpen → Closed`.
///
/// While `Closed`, requests flow normally.  If the error rate exceeds
/// `error_threshold_pct` after at least `min_requests`, the breaker trips to
/// `Open`.  After `open_duration`, it transitions to `HalfOpen` and allows a
/// single probe request.  A success resets to `Closed`; a failure re-opens.
#[derive(Debug)]
pub struct CircuitBreaker {
    inner: Mutex<Inner>,
    error_threshold_pct: f64,
    min_requests: u64,
    open_duration: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug)]
struct Inner {
    state: State,
    total: u64,
    failures: u64,
    opened_at: Option<Instant>,
}

impl CircuitBreaker {
    pub fn new(error_threshold_pct: f64, min_requests: u64, open_duration: Duration) -> Self {
        Self {
            inner: Mutex::new(Inner {
                state: State::Closed,
                total: 0,
                failures: 0,
                opened_at: None,
            }),
            error_threshold_pct,
            min_requests,
            open_duration,
        }
    }

    /// Check whether a request is allowed.
    ///
    /// - `Closed` → always allowed.
    /// - `Open` → denied unless `open_duration` has elapsed, in which case the
    ///   breaker transitions to `HalfOpen` and allows exactly one probe.
    /// - `HalfOpen` → denied (only one probe at a time).
    pub fn allow_request(&self) -> bool {
        let mut inner = self.inner.lock().unwrap();
        match inner.state {
            State::Closed => true,
            State::Open => {
                if let Some(opened_at) = inner.opened_at {
                    if opened_at.elapsed() >= self.open_duration {
                        inner.state = State::HalfOpen;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            State::HalfOpen => false,
        }
    }

    /// Record a successful outcome.
    pub fn record_success(&self) {
        let mut inner = self.inner.lock().unwrap();
        match inner.state {
            State::Closed => {
                inner.total += 1;
            }
            State::HalfOpen => {
                // Probe succeeded — reset to Closed.
                inner.state = State::Closed;
                inner.total = 0;
                inner.failures = 0;
                inner.opened_at = None;
            }
            State::Open => {}
        }
    }

    /// Record a failure outcome.
    pub fn record_failure(&self) {
        let mut inner = self.inner.lock().unwrap();
        match inner.state {
            State::Closed => {
                inner.total += 1;
                inner.failures += 1;
                if inner.total >= self.min_requests {
                    let rate = inner.failures as f64 / inner.total as f64;
                    if rate >= self.error_threshold_pct {
                        inner.state = State::Open;
                        inner.opened_at = Some(Instant::now());
                    }
                }
            }
            State::HalfOpen => {
                // Probe failed — re-open.
                inner.state = State::Open;
                inner.opened_at = Some(Instant::now());
            }
            State::Open => {}
        }
    }

    /// Current state (for observability).
    pub fn state(&self) -> State {
        self.inner.lock().unwrap().state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_closed() {
        let cb = CircuitBreaker::new(0.5, 5, Duration::from_millis(100));
        assert_eq!(cb.state(), State::Closed);
        assert!(cb.allow_request());
    }

    #[test]
    fn trips_to_open_after_threshold() {
        let cb = CircuitBreaker::new(0.5, 4, Duration::from_millis(100));

        // 4 failures out of 4 = 100% > 50%
        for _ in 0..4 {
            assert!(cb.allow_request());
            cb.record_failure();
        }

        assert_eq!(cb.state(), State::Open);
        assert!(!cb.allow_request());
    }

    #[test]
    fn does_not_trip_below_min_requests() {
        let cb = CircuitBreaker::new(0.5, 10, Duration::from_millis(100));

        // 5 failures, but min_requests is 10
        for _ in 0..5 {
            cb.record_failure();
        }
        assert_eq!(cb.state(), State::Closed);
    }

    #[test]
    fn open_to_half_open_after_duration() {
        let cb = CircuitBreaker::new(0.5, 2, Duration::from_millis(50));

        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), State::Open);

        // Wait for open_duration.
        std::thread::sleep(Duration::from_millis(60));

        // Next allow_request should transition to HalfOpen.
        assert!(cb.allow_request());
        assert_eq!(cb.state(), State::HalfOpen);
    }

    #[test]
    fn half_open_success_closes() {
        let cb = CircuitBreaker::new(0.5, 2, Duration::from_millis(50));

        cb.record_failure();
        cb.record_failure();
        std::thread::sleep(Duration::from_millis(60));
        assert!(cb.allow_request()); // → HalfOpen

        cb.record_success(); // probe succeeded
        assert_eq!(cb.state(), State::Closed);
        assert!(cb.allow_request());
    }

    #[test]
    fn half_open_failure_reopens() {
        let cb = CircuitBreaker::new(0.5, 2, Duration::from_millis(50));

        cb.record_failure();
        cb.record_failure();
        std::thread::sleep(Duration::from_millis(60));
        assert!(cb.allow_request()); // → HalfOpen

        cb.record_failure(); // probe failed
        assert_eq!(cb.state(), State::Open);
        assert!(!cb.allow_request());
    }

    #[test]
    fn full_lifecycle_inject_20_failures() {
        let cb = CircuitBreaker::new(0.5, 10, Duration::from_millis(50));

        // Inject 20 failures → Open
        for _ in 0..20 {
            if cb.allow_request() {
                cb.record_failure();
            }
        }
        assert_eq!(cb.state(), State::Open);

        // Wait → HalfOpen
        std::thread::sleep(Duration::from_millis(60));
        assert!(cb.allow_request());
        assert_eq!(cb.state(), State::HalfOpen);

        // One success → Closed
        cb.record_success();
        assert_eq!(cb.state(), State::Closed);
    }
}
