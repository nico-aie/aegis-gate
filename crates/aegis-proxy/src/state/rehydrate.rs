//! State-backend warm-up (B1-T5 — Phase B).
//!
//! On boot, [`rehydrate`] confirms the configured `StateBackend`
//! is reachable and round-trips a write/read/delete probe before
//! `/healthz/ready` flips to 200. The aim: stop a fresh node
//! from accepting traffic against an unreachable Redis (where
//! every rate-limit decision would silently fall through), and
//! stop a node from serving for the first ~second before its
//! cluster-shared counters have caught up.
//!
//! Behaviour:
//!
//! - **In-memory backend.** Probe finishes in microseconds —
//!   `completed = true` returns essentially instantly. The
//!   readiness gate is a no-op here in practice.
//! - **Redis backend.** Probe pays one connect + three round
//!   trips (set, get, del). On a healthy LAN this is < 5 ms; on
//!   an unreachable host it hits the per-call timeout and
//!   returns `completed = false`.
//!
//! Either way the caller flips `/healthz/ready` to 200 once
//! `rehydrate` returns. We deliberately **never** leave a node
//! permanently 503'd — a misconfigured Redis URL must not keep
//! the gateway down indefinitely. The result includes the
//! elapsed time + an error message so the operator can spot the
//! failure in the boot logs.

use std::sync::Arc;
use std::time::{Duration, Instant};

use aegis_core::state::StateBackend;

/// Outcome of a [`rehydrate`] call.
///
/// Hold this for telemetry — current B1-T5 callers only inspect
/// `completed` for the boot-log line, but the timing + error
/// fields will feed a future Prometheus gauge once SLOs around
/// "time-to-ready" land.
#[derive(Debug, Clone)]
pub struct RehydrateResult {
    /// `true` if the probe write/read/delete cycle completed
    /// within the deadline. `false` means the deadline elapsed
    /// or the backend errored.
    pub completed: bool,
    /// How long the probe took. Capped at the deadline.
    pub elapsed: Duration,
    /// Detail string when `completed = false`. None on success.
    pub error: Option<String>,
}

impl RehydrateResult {
    pub fn is_ok(&self) -> bool {
        self.completed
    }
}

/// Canary key written + read + deleted as the warm-up probe.
/// Namespace prefix matches the rest of the state backend.
const PROBE_KEY: &str = "g:__aegis_warmup__";

/// Warm-up probe.
///
/// Writes a small value with TTL = `deadline`, reads it back,
/// asserts it round-trips, then deletes it. Returns
/// `RehydrateResult { completed: true, .. }` if every step
/// succeeds within `deadline`; otherwise `completed: false` with
/// elapsed time and the first error encountered.
///
/// **Never panics, never blocks past `deadline`.** Suitable to
/// run in a `tokio::spawn` from boot.
pub async fn rehydrate(
    store: Arc<dyn StateBackend>,
    deadline: Duration,
) -> RehydrateResult {
    let started = Instant::now();
    let probe = async {
        let value = b"ok";

        // Set with the deadline as TTL — even if our delete
        // fails, the key self-cleans within the boot window.
        store
            .set(PROBE_KEY, value, deadline)
            .await
            .map_err(|e| format!("set: {e}"))?;

        match store.get(PROBE_KEY).await {
            Ok(Some(v)) if v == value => {}
            Ok(Some(other)) => {
                return Err(format!(
                    "probe round-trip mismatch: wrote {value:?} got {other:?}"
                ));
            }
            Ok(None) => return Err("probe key missing on read".to_string()),
            Err(e) => return Err(format!("get: {e}")),
        }

        store
            .del(PROBE_KEY)
            .await
            .map_err(|e| format!("del: {e}"))?;

        Ok::<(), String>(())
    };

    match tokio::time::timeout(deadline, probe).await {
        Ok(Ok(())) => RehydrateResult {
            completed: true,
            elapsed: started.elapsed(),
            error: None,
        },
        Ok(Err(e)) => RehydrateResult {
            completed: false,
            elapsed: started.elapsed(),
            error: Some(e),
        },
        Err(_) => RehydrateResult {
            completed: false,
            elapsed: deadline,
            error: Some(format!(
                "rehydrate deadline {deadline:?} elapsed before backend round-trip completed"
            )),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::InMemoryBackend;

    #[tokio::test]
    async fn in_memory_completes_quickly() {
        let store: Arc<dyn StateBackend> = Arc::new(InMemoryBackend::new());
        let r = rehydrate(store, Duration::from_secs(5)).await;
        assert!(r.completed, "in-memory probe should complete: {:?}", r.error);
        assert!(r.error.is_none());
        // Should be wildly under the deadline.
        assert!(
            r.elapsed < Duration::from_millis(500),
            "elapsed should be tiny, got {:?}",
            r.elapsed,
        );
    }

    /// Test-only [`StateBackend`] that never returns from any
    /// op. Used to exercise the deadline path.
    struct StallingBackend;

    #[async_trait::async_trait]
    impl StateBackend for StallingBackend {
        async fn get(
            &self,
            _key: &str,
        ) -> aegis_core::Result<Option<Vec<u8>>> {
            std::future::pending().await
        }
        async fn set(
            &self,
            _key: &str,
            _val: &[u8],
            _ttl: Duration,
        ) -> aegis_core::Result<()> {
            std::future::pending().await
        }
        async fn del(&self, _key: &str) -> aegis_core::Result<()> {
            std::future::pending().await
        }
        async fn incr_window(
            &self,
            _key: &str,
            _window: Duration,
            _limit: u64,
        ) -> aegis_core::Result<aegis_core::SlidingWindowResult> {
            std::future::pending().await
        }
        async fn token_bucket(
            &self,
            _key: &str,
            _rate_per_s: u32,
            _burst: u32,
        ) -> aegis_core::Result<bool> {
            std::future::pending().await
        }
        async fn get_risk(
            &self,
            _key: &aegis_core::risk::RiskKey,
        ) -> aegis_core::Result<u32> {
            std::future::pending().await
        }
        async fn add_risk(
            &self,
            _key: &aegis_core::risk::RiskKey,
            _delta: i32,
            _max: u32,
        ) -> aegis_core::Result<u32> {
            std::future::pending().await
        }
        async fn auto_block(
            &self,
            _ip: std::net::IpAddr,
            _ttl: Duration,
        ) -> aegis_core::Result<()> {
            std::future::pending().await
        }
        async fn is_auto_blocked(
            &self,
            _ip: std::net::IpAddr,
        ) -> aegis_core::Result<bool> {
            std::future::pending().await
        }
        async fn put_nonce(
            &self,
            _nonce: &str,
            _ttl: Duration,
        ) -> aegis_core::Result<bool> {
            std::future::pending().await
        }
        async fn consume_nonce(
            &self,
            _nonce: &str,
        ) -> aegis_core::Result<bool> {
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn deadline_returns_with_error() {
        let store: Arc<dyn StateBackend> = Arc::new(StallingBackend);
        let deadline = Duration::from_millis(150);
        let r = rehydrate(store, deadline).await;
        assert!(!r.completed);
        let err = r.error.expect("error should be set on deadline");
        assert!(err.contains("deadline"), "got: {err}");
        // Elapsed should be ~deadline.
        assert!(r.elapsed >= deadline);
        assert!(
            r.elapsed < deadline + Duration::from_millis(500),
            "should not run wildly past deadline, got {:?}",
            r.elapsed,
        );
    }

    /// Test-only backend whose `set` always errors.
    struct AlwaysErrSet;

    #[async_trait::async_trait]
    impl StateBackend for AlwaysErrSet {
        async fn get(&self, _: &str) -> aegis_core::Result<Option<Vec<u8>>> {
            Ok(None)
        }
        async fn set(
            &self,
            _: &str,
            _: &[u8],
            _: Duration,
        ) -> aegis_core::Result<()> {
            Err(aegis_core::WafError::State("simulated set failure".into()))
        }
        async fn del(&self, _: &str) -> aegis_core::Result<()> {
            Ok(())
        }
        async fn incr_window(
            &self,
            _: &str,
            _: Duration,
            _: u64,
        ) -> aegis_core::Result<aegis_core::SlidingWindowResult> {
            unreachable!()
        }
        async fn token_bucket(
            &self,
            _: &str,
            _: u32,
            _: u32,
        ) -> aegis_core::Result<bool> {
            unreachable!()
        }
        async fn get_risk(
            &self,
            _: &aegis_core::risk::RiskKey,
        ) -> aegis_core::Result<u32> {
            unreachable!()
        }
        async fn add_risk(
            &self,
            _: &aegis_core::risk::RiskKey,
            _: i32,
            _: u32,
        ) -> aegis_core::Result<u32> {
            unreachable!()
        }
        async fn auto_block(
            &self,
            _: std::net::IpAddr,
            _: Duration,
        ) -> aegis_core::Result<()> {
            unreachable!()
        }
        async fn is_auto_blocked(
            &self,
            _: std::net::IpAddr,
        ) -> aegis_core::Result<bool> {
            unreachable!()
        }
        async fn put_nonce(
            &self,
            _: &str,
            _: Duration,
        ) -> aegis_core::Result<bool> {
            unreachable!()
        }
        async fn consume_nonce(&self, _: &str) -> aegis_core::Result<bool> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn set_error_surfaces_in_result() {
        let store: Arc<dyn StateBackend> = Arc::new(AlwaysErrSet);
        let r = rehydrate(store, Duration::from_secs(5)).await;
        assert!(!r.completed);
        let err = r.error.expect("error should be set");
        assert!(err.contains("set:"), "got: {err}");
        assert!(err.contains("simulated"), "got: {err}");
    }

    #[test]
    fn is_ok_mirrors_completed() {
        let r = RehydrateResult {
            completed: true,
            elapsed: Duration::from_millis(1),
            error: None,
        };
        assert!(r.is_ok());
        let r = RehydrateResult {
            completed: false,
            elapsed: Duration::from_secs(5),
            error: Some("boom".into()),
        };
        assert!(!r.is_ok());
    }
}
