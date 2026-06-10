//! Fleet event bus — leaderless Redis pub/sub fanout for the
//! cross-node live event feed (cluster plan Phase 2, §2b).
//!
//! This is a **sibling** of [`crate::state::StateBackend`], not part
//! of it: pub/sub messaging is a different capability from key/value
//! state, only the Redis backend implements it for real, and keeping
//! it off `StateBackend` avoids touching that trait's 9+ implementors.
//!
//! ## Lossy-by-design
//!
//! The feed is an **append-only, at-most-once monitor**. A dropped
//! message means one row is missing from a *remote* dashboard — never
//! a divergence of enforcement state. SigNoz + per-node
//! `waf_audit.log` remain the source of truth (cluster plan §10). So
//! every call site treats the bus as best-effort: a Redis outage costs
//! monitoring completeness for the outage window, never protection.
//!
//! ## Hot-path safety
//!
//! Nothing here is called on the request→upstream path. `publish` runs
//! from a background task that drains the local `AuditBus`; `subscribe`
//! owns a dedicated connection so a slow consumer can never stall the
//! state-backend command pool.

use async_trait::async_trait;
use tokio::sync::mpsc;

/// Pub/sub transport for the cross-node event feed. Best-effort by
/// contract — `publish` is infallible at the call site (the impl logs
/// and swallows transport errors) so a slow or failed publish can
/// never propagate onto a caller that must not block.
#[async_trait]
pub trait FleetBus: Send + Sync + 'static {
    /// Best-effort publish of `payload` to `channel`. Fire-and-forget:
    /// transport errors are logged at debug inside the impl and
    /// swallowed — the monitor feed tolerates loss.
    async fn publish(&self, channel: &str, payload: Vec<u8>);

    /// Subscribe to `channel`. Returns a receiver of raw payloads; the
    /// implementation owns the connection + forwarding task and ends it
    /// when the receiver is dropped. `bound` caps in-flight buffered
    /// messages — on overflow the **oldest** is dropped (the feed is
    /// lossy, so a flood can't turn into unbounded memory growth).
    fn subscribe(&self, channel: &str, bound: usize) -> mpsc::Receiver<Vec<u8>>;
}

/// No-op fleet bus for single-node / `in_memory` deployments.
/// `publish` discards; `subscribe` returns an immediately-closed
/// receiver so the subscriber task parks with zero cost. This is what
/// keeps Phase 2 free on a single node — the wiring exists but moves
/// no bytes.
pub struct NoopFleetBus;

#[async_trait]
impl FleetBus for NoopFleetBus {
    async fn publish(&self, _channel: &str, _payload: Vec<u8>) {}

    fn subscribe(&self, _channel: &str, _bound: usize) -> mpsc::Receiver<Vec<u8>> {
        // Drop the sender immediately → the receiver is closed → the
        // subscriber loop sees `None` on its first `recv()` and idles.
        let (_tx, rx) = mpsc::channel(1);
        rx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_publish_is_a_no_op() {
        // Must not panic / block.
        NoopFleetBus.publish("fleet:events", b"x".to_vec()).await;
    }

    #[tokio::test]
    async fn noop_subscribe_yields_nothing() {
        let mut rx = NoopFleetBus.subscribe("fleet:events", 8);
        // Sender was dropped → closed channel → immediate None.
        assert!(rx.recv().await.is_none());
    }
}
