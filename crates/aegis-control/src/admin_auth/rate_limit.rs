/// Login rate limiter + lockout.
///
/// Per-IP: 5 attempts/1min. Per-user: 10 attempts/15min.
/// Exponential backoff at attempts 6/7/8. Lockout 15min after threshold.
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Login attempt outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoginOutcome {
    Allowed,
    RateLimited { retry_after: Duration },
    LockedOut { remaining: Duration },
}

/// Rate limiter configuration.
#[derive(Clone, Debug)]
pub struct LoginRateLimitConfig {
    pub ip_max_attempts: u32,
    pub ip_window: Duration,
    pub user_max_attempts: u32,
    pub user_window: Duration,
    pub lockout_threshold: u32,
    pub lockout_duration: Duration,
}

impl Default for LoginRateLimitConfig {
    fn default() -> Self {
        Self {
            ip_max_attempts: 5,
            ip_window: Duration::from_secs(60),
            user_max_attempts: 10,
            user_window: Duration::from_secs(900),
            lockout_threshold: 10,
            lockout_duration: Duration::from_secs(900),
        }
    }
}

struct AttemptTracker {
    attempts: Vec<Instant>,
    locked_until: Option<Instant>,
}

impl AttemptTracker {
    fn new() -> Self {
        Self {
            attempts: Vec::new(),
            locked_until: None,
        }
    }

    fn prune(&mut self, window: Duration) {
        let cutoff = Instant::now() - window;
        self.attempts.retain(|t| *t > cutoff);
    }

    fn count_in_window(&mut self, window: Duration) -> u32 {
        self.prune(window);
        self.attempts.len() as u32
    }

    fn record(&mut self) {
        self.attempts.push(Instant::now());
    }

    fn is_locked(&self) -> Option<Duration> {
        if let Some(until) = self.locked_until {
            let now = Instant::now();
            if now < until {
                return Some(until - now);
            }
        }
        None
    }

    fn lock(&mut self, duration: Duration) {
        self.locked_until = Some(Instant::now() + duration);
    }
}

/// Login rate limiter.
pub struct LoginRateLimiter {
    config: LoginRateLimitConfig,
    ip_trackers: Mutex<HashMap<String, AttemptTracker>>,
    user_trackers: Mutex<HashMap<String, AttemptTracker>>,
}

impl LoginRateLimiter {
    pub fn new(config: LoginRateLimitConfig) -> Self {
        Self {
            config,
            ip_trackers: Mutex::new(HashMap::new()),
            user_trackers: Mutex::new(HashMap::new()),
        }
    }

    /// Check if a login attempt is allowed.
    pub fn check(&self, ip: &str, username: &str) -> LoginOutcome {
        // Check user lockout first.
        {
            let trackers = self.user_trackers.lock().unwrap();
            if let Some(tracker) = trackers.get(username) {
                if let Some(remaining) = tracker.is_locked() {
                    return LoginOutcome::LockedOut { remaining };
                }
            }
        }

        // Check IP rate limit.
        {
            let mut trackers = self.ip_trackers.lock().unwrap();
            let tracker = trackers.entry(ip.to_string()).or_insert_with(AttemptTracker::new);
            let count = tracker.count_in_window(self.config.ip_window);
            if count >= self.config.ip_max_attempts {
                let backoff = backoff_duration(count - self.config.ip_max_attempts + 1);
                return LoginOutcome::RateLimited { retry_after: backoff };
            }
        }

        // Check user rate limit.
        {
            let mut trackers = self.user_trackers.lock().unwrap();
            let tracker = trackers.entry(username.to_string()).or_insert_with(AttemptTracker::new);
            let count = tracker.count_in_window(self.config.user_window);
            if count >= self.config.user_max_attempts {
                return LoginOutcome::RateLimited {
                    retry_after: Duration::from_secs(15),
                };
            }
        }

        LoginOutcome::Allowed
    }

    /// Record a failed login attempt.
    pub fn record_failure(&self, ip: &str, username: &str) {
        {
            let mut trackers = self.ip_trackers.lock().unwrap();
            let tracker = trackers.entry(ip.to_string()).or_insert_with(AttemptTracker::new);
            tracker.record();
        }
        {
            let mut trackers = self.user_trackers.lock().unwrap();
            let tracker = trackers.entry(username.to_string()).or_insert_with(AttemptTracker::new);
            tracker.record();
            let count = tracker.count_in_window(self.config.user_window);
            if count >= self.config.lockout_threshold {
                tracker.lock(self.config.lockout_duration);
            }
        }
    }

    /// Record a successful login (clears attempts for that user and IP).
    pub fn record_success(&self, ip: &str, username: &str) {
        {
            let mut trackers = self.ip_trackers.lock().unwrap();
            trackers.remove(ip);
        }
        {
            let mut trackers = self.user_trackers.lock().unwrap();
            trackers.remove(username);
        }
    }
}

fn backoff_duration(over: u32) -> Duration {
    match over {
        1 => Duration::from_secs(2),
        2 => Duration::from_secs(5),
        _ => Duration::from_secs(15),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter() -> LoginRateLimiter {
        LoginRateLimiter::new(LoginRateLimitConfig {
            ip_max_attempts: 3,
            ip_window: Duration::from_secs(60),
            user_max_attempts: 5,
            user_window: Duration::from_secs(60),
            lockout_threshold: 5,
            lockout_duration: Duration::from_secs(10),
        })
    }

    #[test]
    fn first_attempt_allowed() {
        let rl = limiter();
        assert_eq!(rl.check("1.2.3.4", "admin"), LoginOutcome::Allowed);
    }

    #[test]
    fn ip_rate_limit_after_threshold() {
        let rl = limiter();
        for _ in 0..3 {
            rl.record_failure("1.2.3.4", "admin");
        }
        let result = rl.check("1.2.3.4", "admin");
        assert!(matches!(result, LoginOutcome::RateLimited { .. }));
    }

    #[test]
    fn different_ip_not_limited() {
        let rl = limiter();
        for _ in 0..3 {
            rl.record_failure("1.2.3.4", "admin");
        }
        assert_eq!(rl.check("5.6.7.8", "admin"), LoginOutcome::Allowed);
    }

    #[test]
    fn user_lockout_after_threshold() {
        let rl = limiter();
        for _ in 0..5 {
            rl.record_failure("1.2.3.4", "admin");
        }
        let result = rl.check("5.6.7.8", "admin"); // Different IP, same user.
        assert!(matches!(result, LoginOutcome::LockedOut { .. }));
    }

    #[test]
    fn success_clears_user_attempts() {
        let rl = limiter();
        for _ in 0..4 {
            rl.record_failure("1.2.3.4", "admin");
        }
        rl.record_success("1.2.3.4", "admin");
        assert_eq!(rl.check("1.2.3.4", "admin"), LoginOutcome::Allowed);
    }

    #[test]
    fn backoff_escalates() {
        assert_eq!(backoff_duration(1), Duration::from_secs(2));
        assert_eq!(backoff_duration(2), Duration::from_secs(5));
        assert_eq!(backoff_duration(3), Duration::from_secs(15));
        assert_eq!(backoff_duration(10), Duration::from_secs(15));
    }

    #[test]
    fn locked_out_remaining_positive() {
        let rl = limiter();
        for _ in 0..5 {
            rl.record_failure("1.2.3.4", "admin");
        }
        if let LoginOutcome::LockedOut { remaining } = rl.check("5.6.7.8", "admin") {
            assert!(remaining.as_secs() > 0);
        } else {
            panic!("expected lockout");
        }
    }

    #[test]
    fn default_config() {
        let c = LoginRateLimitConfig::default();
        assert_eq!(c.ip_max_attempts, 5);
        assert_eq!(c.user_max_attempts, 10);
        assert_eq!(c.lockout_duration, Duration::from_secs(900));
    }
}
