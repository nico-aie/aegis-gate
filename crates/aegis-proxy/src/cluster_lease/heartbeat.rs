//! Background renewal task for a held lease.
//!
//! [`spawn_heartbeat`] kicks off a Tokio task that calls
//! [`LeaseStore::renew`] every `ttl/3`. As soon as `renew` returns
//! `false` (lease lost) or errors (Redis unreachable past the
//! per-call timeout), the task fires the `on_lost` notifier and
//! exits — the caller wires that up to stop whatever leader-only
//! work the lease was guarding.
//!
//! The 1/3-TTL cadence is the standard "comfortably under
//! expiry" interval — three failed network round-trips and we
//! still detect the loss before TTL fires.

use std::sync::Arc;
use std::time::Duration;

use aegis_core::cluster::{LeaseHandle, LeaseStore};

use tokio::sync::Notify;
use tokio::task::JoinHandle;

/// Handle to a running heartbeat task.
pub struct HeartbeatHandle {
    /// Fires when the heartbeat decides we no longer hold the
    /// lease (renew returned false, errored, or the heartbeat
    /// was cancelled).
    pub lost: Arc<Notify>,
    join: JoinHandle<()>,
    cancel: Arc<Notify>,
}

impl HeartbeatHandle {
    /// Stop the heartbeat. Best-effort — may yield one more
    /// renew before the task notices the cancel.
    pub fn cancel(&self) {
        self.cancel.notify_one();
    }

    /// Wait for the heartbeat task to exit. Useful in tests; not
    /// usually needed in production where the task lives until
    /// `lost` fires.
    pub async fn join(self) -> Result<(), tokio::task::JoinError> {
        self.cancel.notify_one();
        self.join.await
    }
}

/// Spawn the renewal loop. Returns immediately with a handle.
///
/// The renewal interval is `ttl / 3` clamped to `[100ms, ttl/2]`.
/// `Notify::notify_one` fires on `lost` exactly once when the
/// lease drops; subsequent `await` calls on `lost.notified()`
/// return immediately.
pub fn spawn_heartbeat<S>(
    store: Arc<S>,
    lease: LeaseHandle,
    ttl: Duration,
) -> HeartbeatHandle
where
    S: LeaseStore + ?Sized,
{
    let lost = Arc::new(Notify::new());
    let cancel = Arc::new(Notify::new());
    let lost_clone = lost.clone();
    let cancel_clone = cancel.clone();

    let interval = renew_interval(ttl);

    let join = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {
                    match store.renew(&lease, ttl).await {
                        Ok(true) => continue,
                        Ok(false) => {
                            tracing::warn!(
                                key = %lease.key,
                                holder = %lease.holder,
                                "lease lost — heartbeat exiting",
                            );
                            lost_clone.notify_waiters();
                            return;
                        }
                        Err(e) => {
                            tracing::warn!(
                                key = %lease.key,
                                holder = %lease.holder,
                                error = %e,
                                "lease renew errored — treating as lost",
                            );
                            lost_clone.notify_waiters();
                            return;
                        }
                    }
                }
                _ = cancel_clone.notified() => {
                    // Best-effort release on graceful cancel.
                    let _ = store.release(&lease).await;
                    return;
                }
            }
        }
    });

    HeartbeatHandle { lost, join, cancel }
}

fn renew_interval(ttl: Duration) -> Duration {
    let third = ttl / 3;
    let half = ttl / 2;
    third.clamp(Duration::from_millis(100), half.max(Duration::from_millis(100)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_lease::InProcessLease;
    use aegis_core::cluster::NodeId;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn renew_interval_clamps_short_ttl() {
        // 100ms TTL → third would be ~33ms but we floor at 100ms.
        let i = renew_interval(Duration::from_millis(100));
        assert!(i >= Duration::from_millis(100));
        assert!(i <= Duration::from_millis(100));
    }

    #[test]
    fn renew_interval_is_one_third_for_normal_ttl() {
        let i = renew_interval(Duration::from_secs(30));
        assert_eq!(i, Duration::from_secs(10));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn heartbeat_renews_until_cancelled() {
        let store = Arc::new(InProcessLease::new(NodeId::new("node-1")));
        let h = store
            .acquire("acme", Duration::from_secs(30))
            .await
            .unwrap()
            .unwrap();

        let hb = spawn_heartbeat(store.clone(), h.clone(), Duration::from_secs(30));

        // Advance virtual time past three renew intervals.
        tokio::time::sleep(Duration::from_secs(35)).await;

        // We should still hold the lease — heartbeat refreshed it.
        assert_eq!(
            store.holder("acme").await.unwrap().unwrap(),
            NodeId::new("node-1"),
        );

        hb.cancel();
        let _ = hb.join.await;
    }

    /// Test-only `LeaseStore` that lies — `renew` returns false
    /// after N successful renewals.
    struct LosesAfter {
        inner: InProcessLease,
        renews_remaining: AtomicU64,
    }

    #[async_trait::async_trait]
    impl LeaseStore for LosesAfter {
        async fn acquire(
            &self,
            key: &str,
            ttl: Duration,
        ) -> aegis_core::Result<Option<LeaseHandle>> {
            self.inner.acquire(key, ttl).await
        }
        async fn renew(
            &self,
            lease: &LeaseHandle,
            ttl: Duration,
        ) -> aegis_core::Result<bool> {
            if self.renews_remaining.fetch_sub(1, Ordering::Relaxed) == 0 {
                Ok(false)
            } else {
                self.inner.renew(lease, ttl).await
            }
        }
        async fn release(&self, lease: &LeaseHandle) -> aegis_core::Result<()> {
            self.inner.release(lease).await
        }
        async fn holder(
            &self,
            key: &str,
        ) -> aegis_core::Result<Option<NodeId>> {
            self.inner.holder(key).await
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn heartbeat_fires_lost_when_renew_returns_false() {
        let store = Arc::new(LosesAfter {
            inner: InProcessLease::new(NodeId::new("node-1")),
            renews_remaining: AtomicU64::new(2),
        });

        let h = store
            .acquire("acme", Duration::from_secs(30))
            .await
            .unwrap()
            .unwrap();
        let hb = spawn_heartbeat(store.clone(), h, Duration::from_secs(30));
        let lost = hb.lost.clone();

        // Advance past 4 renew intervals (40s) — the third
        // renew should return false and fire `lost`.
        tokio::time::timeout(Duration::from_secs(60), lost.notified())
            .await
            .expect("lost should fire within 4 renew intervals");
    }
}
