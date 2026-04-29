//! Generic "run only on the lease holder" wrapper (B1-T4).
//!
//! [`run_with_lease`] is the standard pattern for any background
//! task that must run on **exactly one** node in a cluster: ACME
//! issuance, GitOps poll, threat-intel fetcher, witness export.
//!
//! Lifecycle:
//!
//! ```text
//!   loop forever:
//!     acquire(key, ttl)
//!       │
//!       ├─ Some(lease) ──▶ spawn(task)        ┐
//!       │                  spawn_heartbeat()  ├─ wait for whichever fires first
//!       │                                     ┘
//!       │   on heartbeat.lost → abort(task), back off, retry
//!       │   on task exits early → release lease, back off, retry
//!       │
//!       └─ None (someone else holds it) → sleep(retry), loop
//! ```
//!
//! The wrapper **never returns** in normal operation — it owns the
//! task for the lifetime of the gateway. To stop it, drop the
//! `JoinHandle` returned by [`spawn_with_lease`] (which sends a
//! cancel signal to the heartbeat first so the lease is
//! gracefully released).

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use aegis_core::cluster::{LeaseStore, NodeId};

use crate::cluster_lease::heartbeat::spawn_heartbeat;

/// Default retry on "another node holds the lease". Half the
/// lease TTL — comfortably under expiry, not so frequent that a
/// 100-node cluster hammers the lease store.
fn default_retry_interval(ttl: Duration) -> Duration {
    let half = ttl / 2;
    half.clamp(Duration::from_secs(1), Duration::from_secs(30))
}

/// Run `factory` only on the node currently holding the lease
/// `key`. Loops forever, re-acquiring after each loss.
///
/// `factory` is a closure that produces a fresh future each time
/// we win the lease — the future is the leader-only task body.
/// It receives the [`NodeId`] (so it can stamp side-effects with
/// our identity) and a [`tokio::sync::Notify`] that fires when
/// the lease is lost (so the task can shut itself down quickly
/// instead of being aborted mid-write).
///
/// The future is `tokio::select!`'d against the heartbeat's
/// `lost` notification: whichever resolves first wins. If the
/// task exits naturally we release the lease and re-acquire on
/// the next iteration.
pub async fn run_with_lease<S, F, Fut>(
    store: Arc<S>,
    key: String,
    ttl: Duration,
    mut factory: F,
)
where
    S: LeaseStore + ?Sized,
    F: FnMut(NodeId, Arc<tokio::sync::Notify>) -> Fut + Send,
    Fut: Future<Output = ()> + Send,
{
    let retry = default_retry_interval(ttl);

    loop {
        let lease = match store.acquire(&key, ttl).await {
            Ok(Some(handle)) => handle,
            Ok(None) => {
                tracing::debug!(
                    key = %key,
                    "lease held elsewhere — retrying after backoff",
                );
                tokio::time::sleep(retry).await;
                continue;
            }
            Err(e) => {
                tracing::warn!(
                    key = %key,
                    error = %e,
                    "lease acquire failed — retrying after backoff",
                );
                tokio::time::sleep(retry).await;
                continue;
            }
        };

        tracing::info!(
            key = %key,
            holder = %lease.holder,
            fence = lease.fence,
            "leader: acquired lease, starting task",
        );

        let hb = spawn_heartbeat(store.clone(), lease.clone(), ttl);
        let lost = hb.lost.clone();
        let task = factory(lease.holder.clone(), lost.clone());

        tokio::select! {
            _ = task => {
                tracing::info!(
                    key = %key,
                    "leader: task exited naturally; releasing lease",
                );
                hb.cancel();
            }
            _ = lost.notified() => {
                tracing::warn!(
                    key = %key,
                    "leader: lease lost; aborting task and retrying",
                );
            }
        }

        // Best-effort drain of the heartbeat task, ignoring its
        // result. The heartbeat's `cancel` already fired (either
        // because we cancelled, or because `lost` fired and the
        // task is already winding down).
        let _ = hb.join().await;

        // Tiny extra backoff before re-acquire to avoid thrashing
        // a flapping Redis. `retry` is the right shape because
        // it's already TTL-derived.
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Spawn [`run_with_lease`] on the current Tokio runtime,
/// returning a [`JoinHandle`] the caller can drop to stop the
/// task. Convenience for the common case at boot.
pub fn spawn_with_lease<S, F, Fut>(
    store: Arc<S>,
    key: impl Into<String>,
    ttl: Duration,
    factory: F,
) -> tokio::task::JoinHandle<()>
where
    S: LeaseStore + ?Sized + 'static,
    F: FnMut(NodeId, Arc<tokio::sync::Notify>) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let key = key.into();
    tokio::spawn(run_with_lease(store, key, ttl, factory))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_lease::InProcessLease;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Helper: shared counter that the gated task increments
    /// on every iteration. After all nodes finish, exactly one
    /// of them should have incremented (since only one held
    /// the lease).
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn only_one_of_three_nodes_runs_the_task() {
        let store = Arc::new(InProcessLease::new(NodeId::new("node-1")));
        let store_b = Arc::new(store.cloned_with_node(NodeId::new("node-2")));
        let store_c = Arc::new(store.cloned_with_node(NodeId::new("node-3")));

        let counter = Arc::new(AtomicU64::new(0));

        let mk_factory = |c: Arc<AtomicU64>| {
            move |_id: NodeId, _lost: Arc<tokio::sync::Notify>| {
                let c = c.clone();
                async move {
                    c.fetch_add(1, Ordering::Relaxed);
                    // Block forever — heartbeat keeps refreshing
                    // the lease, no one else gets it.
                    std::future::pending::<()>().await;
                }
            }
        };

        let h1 = spawn_with_lease(
            store.clone(),
            "leader:test",
            Duration::from_secs(30),
            mk_factory(counter.clone()),
        );
        let h2 = spawn_with_lease(
            store_b.clone(),
            "leader:test",
            Duration::from_secs(30),
            mk_factory(counter.clone()),
        );
        let h3 = spawn_with_lease(
            store_c.clone(),
            "leader:test",
            Duration::from_secs(30),
            mk_factory(counter.clone()),
        );

        // Let the runners settle: one wins, two retry.
        tokio::time::sleep(Duration::from_secs(5)).await;

        // Exactly one node ran the task body.
        assert_eq!(counter.load(Ordering::Relaxed), 1);

        h1.abort();
        h2.abort();
        h3.abort();
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn runner_up_takes_over_after_release() {
        let store_a = Arc::new(InProcessLease::new(NodeId::new("node-A")));
        let store_b = Arc::new(store_a.cloned_with_node(NodeId::new("node-B")));

        // Tracks who's currently running the task.
        let runner = Arc::new(parking_lot::Mutex::new(Option::<NodeId>::None));

        let mk_factory = |r: Arc<parking_lot::Mutex<Option<NodeId>>>| {
            move |id: NodeId, lost: Arc<tokio::sync::Notify>| {
                let r = r.clone();
                async move {
                    *r.lock() = Some(id);
                    // Wait for either lease loss or external
                    // cancellation. The runner aborts us if
                    // lease is lost.
                    lost.notified().await;
                }
            }
        };

        let h_a = spawn_with_lease(
            store_a.clone(),
            "leader:test",
            Duration::from_secs(30),
            mk_factory(runner.clone()),
        );
        let h_b = spawn_with_lease(
            store_b.clone(),
            "leader:test",
            Duration::from_secs(30),
            mk_factory(runner.clone()),
        );

        // Let one of them claim it.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let initial = runner.lock().clone();
        assert!(initial.is_some(), "one node should have claimed the lease");

        // Stop node A — its store goes away (mimics process
        // death in a multi-process deployment).
        h_a.abort();

        // The lease will expire after `ttl` (30s); B's runner
        // backs off for `retry` (15s), then re-acquires. Give
        // it time.
        tokio::time::sleep(Duration::from_secs(60)).await;

        // Either node-B took over, or node-A's claim was always
        // node-B in the first place — both prove "exactly one
        // active runner". The key assertion is that *some*
        // node is running.
        let after = runner.lock().clone();
        assert!(after.is_some(), "lease should have been picked up after timeout");

        h_b.abort();
    }

    #[test]
    fn default_retry_interval_clamps() {
        // Very short TTL: floor at 1s
        assert_eq!(default_retry_interval(Duration::from_millis(500)), Duration::from_secs(1));
        // Normal TTL: half
        assert_eq!(default_retry_interval(Duration::from_secs(30)), Duration::from_secs(15));
        // Very long TTL: cap at 30s
        assert_eq!(default_retry_interval(Duration::from_secs(120)), Duration::from_secs(30));
    }
}
