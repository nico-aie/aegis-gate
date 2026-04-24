//! Hot binary reload via SIGUSR2.
//!
//! On SIGUSR2: `fork+exec` a new binary with listening socket FDs passed via
//! environment variables. The old process enters the drain path. If the new
//! process fails its readiness probe, the old process resumes accepting.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// State of the hot-reload process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadState {
    /// Normal operation.
    Idle,
    /// New binary spawned, waiting for readiness.
    Pending,
    /// Reload succeeded, old process draining.
    Draining,
    /// Reload failed, old process resumed.
    RolledBack,
}

/// Manages the hot binary reload lifecycle.
pub struct HotReloader {
    state: std::sync::Mutex<ReloadState>,
    signal_received: AtomicBool,
    readiness_timeout: Duration,
}

impl HotReloader {
    pub fn new(readiness_timeout: Duration) -> Self {
        Self {
            state: std::sync::Mutex::new(ReloadState::Idle),
            signal_received: AtomicBool::new(false),
            readiness_timeout,
        }
    }

    /// Mark that SIGUSR2 was received.
    pub fn signal(&self) {
        self.signal_received.store(true, Ordering::Release);
    }

    /// Check if a signal was received and reset the flag.
    pub fn take_signal(&self) -> bool {
        self.signal_received.swap(false, Ordering::AcqRel)
    }

    /// Transition to a new state.
    pub fn transition(&self, new_state: ReloadState) {
        let mut state = self.state.lock().unwrap();
        *state = new_state;
    }

    /// Current state.
    pub fn state(&self) -> ReloadState {
        *self.state.lock().unwrap()
    }

    pub fn readiness_timeout(&self) -> Duration {
        self.readiness_timeout
    }
}

/// Describes how FDs are passed to the new binary.
#[derive(Debug, Clone)]
pub struct FdPassConfig {
    /// Environment variable name for passing the number of listener FDs.
    pub env_fd_count: String,
    /// Base FD number (usually 3, after stdin/stdout/stderr).
    pub base_fd: i32,
}

impl Default for FdPassConfig {
    fn default() -> Self {
        Self {
            env_fd_count: "AEGIS_LISTEN_FDS".into(),
            base_fd: 3,
        }
    }
}

/// Parse the FD count from the environment (used by the new binary on startup).
pub fn inherited_fd_count() -> Option<usize> {
    std::env::var("AEGIS_LISTEN_FDS")
        .ok()
        .and_then(|v| v.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state_is_idle() {
        let r = HotReloader::new(Duration::from_secs(10));
        assert_eq!(r.state(), ReloadState::Idle);
    }

    #[test]
    fn signal_and_take() {
        let r = HotReloader::new(Duration::from_secs(10));
        assert!(!r.take_signal());
        r.signal();
        assert!(r.take_signal());
        assert!(!r.take_signal()); // consumed
    }

    #[test]
    fn state_transitions() {
        let r = HotReloader::new(Duration::from_secs(10));
        r.transition(ReloadState::Pending);
        assert_eq!(r.state(), ReloadState::Pending);
        r.transition(ReloadState::Draining);
        assert_eq!(r.state(), ReloadState::Draining);
    }

    #[test]
    fn rollback_on_failure() {
        let r = HotReloader::new(Duration::from_secs(10));
        r.transition(ReloadState::Pending);
        // Simulate readiness failure → rollback.
        r.transition(ReloadState::RolledBack);
        assert_eq!(r.state(), ReloadState::RolledBack);
    }

    #[test]
    fn fd_pass_config_default() {
        let cfg = FdPassConfig::default();
        assert_eq!(cfg.env_fd_count, "AEGIS_LISTEN_FDS");
        assert_eq!(cfg.base_fd, 3);
    }

    #[test]
    fn inherited_fd_count_missing() {
        // In test environment, this env var should not be set.
        assert!(inherited_fd_count().is_none());
    }
}
