//! Cluster Phase 2 — cross-node fleet **event fanout** (cluster plan
//! §2b, the ≤ 5 s logs/events SLA path).
//!
//! Two background tasks, spawned only when a Redis state backend is
//! present AND `cluster.fleet_events.enabled` (single-node pays
//! nothing — see [`crate::run`] wiring):
//!
//! - [`spawn_fleet_publisher`] drains the **local** `AuditBus` and
//!   best-effort-`PUBLISH`es each event (origin-tagged, rate-capped)
//!   to the shared Redis channel.
//! - [`spawn_fleet_subscriber`] receives peers' events off that
//!   channel and re-emits them onto a **separate** fleet-event bus
//!   that only the dashboard SSE feed merges in — never the local
//!   `AuditBus`, so the durable sinks + the hash-linked audit chain
//!   stay "this node's decisions" (cluster plan §10).
//!
//! ## Loop / echo guard (structural, no per-event flag)
//!
//! The publisher reads the *local* bus; remote events land on the
//! *fleet* bus, which the publisher never reads — so a remote event
//! can never be re-published. Redis pub/sub additionally **echoes a
//! PUBLISH back to the publishing connection**, so the subscriber
//! drops any event whose `origin_node` is *us*. Together these need no
//! `remote: bool` field on `AuditEvent` (which has 128 construction
//! sites).
//!
//! ## Lossy by design
//!
//! Best-effort throughout: a Redis outage stops cross-node events
//! (each dashboard falls back to its own local feed) but never touches
//! the request path. The local bus + SigNoz remain the complete record.

use std::sync::Arc;

use aegis_core::audit::{AuditBus, AuditEvent};
use aegis_core::fleet::FleetBus;

/// `fields` key under which the publisher stamps the originating node
/// id. Lets the subscriber drop Redis's echo of our own events and the
/// dashboard label which node a row came from. Lives in the event's
/// free-form `fields: serde_json::Value` so no `AuditEvent` field is
/// added.
const ORIGIN_NODE_KEY: &str = "origin_node";

/// Bound on the subscriber's in-flight buffer. Overflow drops the
/// oldest (monitor feed is lossy).
const SUBSCRIBE_CHANNEL_BOUND: usize = 1024;

/// Spawn the publisher task: drain the local `AuditBus`, origin-tag a
/// copy, and best-effort publish to `channel`, capped at
/// `max_publish_rate_per_s` events/s (bounded-loss guard).
pub fn spawn_fleet_publisher(
    local_bus: AuditBus,
    fleet: Arc<dyn FleetBus>,
    channel: String,
    our_node: String,
    max_publish_rate_per_s: u32,
) {
    let mut rx = local_bus.subscribe();
    tokio::spawn(async move {
        let mut limiter = RateLimiter::new(max_publish_rate_per_s);
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    if !limiter.allow() {
                        // Flood guard: sample/drop above the cap.
                        continue;
                    }
                    let mut tagged = ev;
                    stamp_origin(&mut tagged, &our_node);
                    match serde_json::to_vec(&tagged) {
                        Ok(bytes) => fleet.publish(&channel, bytes).await,
                        Err(e) => {
                            tracing::debug!(error = %e, "fleet event serialize failed");
                        }
                    }
                }
                // Lagged: the local bus outran us. Skip the gap and
                // keep going — the monitor feed tolerates loss.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::debug!(skipped = n, "fleet publisher lagged local bus");
                }
                // Sender dropped → shutdown.
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}

/// Spawn the subscriber task: receive peers' events off `channel` and
/// re-emit them onto `fleet_event_bus` (the SSE-only fleet feed).
/// Drops Redis's echo of our **own** events (`origin_node == our_node`).
pub fn spawn_fleet_subscriber(
    fleet: Arc<dyn FleetBus>,
    channel: String,
    fleet_event_bus: AuditBus,
    our_node: String,
) {
    let mut rx = fleet.subscribe(&channel, SUBSCRIBE_CHANNEL_BOUND);
    tokio::spawn(async move {
        while let Some(payload) = rx.recv().await {
            let ev: AuditEvent = match serde_json::from_slice(&payload) {
                Ok(ev) => ev,
                Err(e) => {
                    tracing::debug!(error = %e, "fleet event deserialize failed");
                    continue;
                }
            };
            // Drop Redis's echo of our own PUBLISH — those events are
            // already on the local bus + SSE feed.
            if origin_of(&ev).as_deref() == Some(our_node.as_str()) {
                continue;
            }
            fleet_event_bus.emit(ev);
        }
    });
}

/// Write the originating node id into `ev.fields["origin_node"]`,
/// preserving any existing object fields.
fn stamp_origin(ev: &mut AuditEvent, node: &str) {
    match ev.fields.as_object_mut() {
        Some(map) => {
            map.insert(
                ORIGIN_NODE_KEY.to_string(),
                serde_json::Value::String(node.to_string()),
            );
        }
        None => {
            // `fields` was null / non-object — replace with a fresh
            // object carrying just the origin (don't clobber a
            // meaningful value: only null/absent reaches here in
            // practice for system events).
            ev.fields = serde_json::json!({ ORIGIN_NODE_KEY: node });
        }
    }
}

/// Read `ev.fields["origin_node"]` if present.
fn origin_of(ev: &AuditEvent) -> Option<String> {
    ev.fields
        .get(ORIGIN_NODE_KEY)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Simple per-second token cap. Not exact (resets on a 1 s wall-clock
/// boundary) but cheap and good enough for a flood guard on a monitor
/// feed.
struct RateLimiter {
    max_per_s: u32,
    window_start: std::time::Instant,
    count: u32,
}

impl RateLimiter {
    fn new(max_per_s: u32) -> Self {
        Self {
            max_per_s,
            window_start: std::time::Instant::now(),
            count: 0,
        }
    }

    /// `true` if a publish is allowed now; `false` if the per-second
    /// cap is hit. `max_per_s == 0` means "unlimited".
    fn allow(&mut self) -> bool {
        if self.max_per_s == 0 {
            return true;
        }
        let now = std::time::Instant::now();
        if now.duration_since(self.window_start).as_secs() >= 1 {
            self.window_start = now;
            self.count = 0;
        }
        if self.count < self.max_per_s {
            self.count += 1;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::audit::{AuditClass, AuditEvent};

    fn ev() -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "req-1".into(),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: None,
            action: "block".into(),
            reason: "test".into(),
            client_ip: "1.2.3.4".into(),
            route_id: None,
            rule_id: None,
            risk_score: Some(80),
            method: None,
            path: None,
            mode: None,
            fields: serde_json::json!({ "existing": true }),
        }
    }

    #[test]
    fn stamp_and_read_origin_round_trips() {
        let mut e = ev();
        stamp_origin(&mut e, "node-A");
        assert_eq!(origin_of(&e).as_deref(), Some("node-A"));
        // Existing fields preserved.
        assert_eq!(e.fields.get("existing"), Some(&serde_json::json!(true)));
    }

    #[test]
    fn stamp_origin_handles_null_fields() {
        let mut e = ev();
        e.fields = serde_json::Value::Null;
        stamp_origin(&mut e, "node-B");
        assert_eq!(origin_of(&e).as_deref(), Some("node-B"));
    }

    #[test]
    fn rate_limiter_caps_within_a_second() {
        let mut rl = RateLimiter::new(3);
        assert!(rl.allow());
        assert!(rl.allow());
        assert!(rl.allow());
        assert!(!rl.allow(), "4th in the same second is dropped");
    }

    #[test]
    fn rate_limiter_zero_means_unlimited() {
        let mut rl = RateLimiter::new(0);
        for _ in 0..10_000 {
            assert!(rl.allow());
        }
    }

    /// In-process [`FleetBus`] mimicking Redis pub/sub — including the
    /// key property that a `publish` is **echoed back to every
    /// subscriber, the publisher included**. Lets the publisher +
    /// subscriber tasks be tested end-to-end without a Redis server.
    struct InProcessFleetBus {
        tx: tokio::sync::broadcast::Sender<(String, Vec<u8>)>,
    }

    impl InProcessFleetBus {
        fn new() -> Self {
            let (tx, _) = tokio::sync::broadcast::channel(256);
            Self { tx }
        }
    }

    #[async_trait::async_trait]
    impl FleetBus for InProcessFleetBus {
        async fn publish(&self, channel: &str, payload: Vec<u8>) {
            let _ = self.tx.send((channel.to_string(), payload));
        }
        fn subscribe(
            &self,
            channel: &str,
            bound: usize,
        ) -> tokio::sync::mpsc::Receiver<Vec<u8>> {
            let (out_tx, out_rx) = tokio::sync::mpsc::channel(bound);
            let mut rx = self.tx.subscribe();
            let want = channel.to_string();
            tokio::spawn(async move {
                while let Ok((ch, payload)) = rx.recv().await {
                    if ch == want && out_tx.send(payload).await.is_err() {
                        break;
                    }
                }
            });
            out_rx
        }
    }

    #[tokio::test]
    async fn end_to_end_peer_event_reaches_other_node_not_self() {
        // Shared "Redis": node A and node B both publish/subscribe.
        let fleet: Arc<InProcessFleetBus> = Arc::new(InProcessFleetBus::new());
        let fleet_dyn: Arc<dyn FleetBus> = fleet.clone();
        let channel = "fleet:events".to_string();

        // Node A: local bus → publisher; and a subscriber feeding A's
        // own fleet bus (which should NOT see A's own events).
        let a_local = AuditBus::new(64);
        let a_fleet = AuditBus::new(64);
        let mut a_fleet_rx = a_fleet.subscribe();
        spawn_fleet_publisher(
            a_local.clone(),
            fleet_dyn.clone(),
            channel.clone(),
            "node-A".into(),
            0,
        );
        spawn_fleet_subscriber(fleet_dyn.clone(), channel.clone(), a_fleet, "node-A".into());

        // Node B: just a subscriber feeding B's fleet bus.
        let b_fleet = AuditBus::new(64);
        let mut b_fleet_rx = b_fleet.subscribe();
        spawn_fleet_subscriber(fleet_dyn.clone(), channel.clone(), b_fleet, "node-B".into());

        // Give the subscriber tasks a moment to wire up.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Node A processes a request → emits locally.
        let mut e = ev();
        e.request_id = "from-A".into();
        a_local.emit(e);

        // Node B's dashboard sees A's event within the SLA budget.
        let got = tokio::time::timeout(std::time::Duration::from_secs(2), b_fleet_rx.recv())
            .await
            .expect("B should receive A's event well under 5s")
            .expect("event");
        assert_eq!(got.request_id, "from-A");
        assert_eq!(origin_of(&got).as_deref(), Some("node-A"));

        // Node A must NOT re-render its own event off the fleet feed
        // (Redis echoed it back; the subscriber dropped it).
        assert!(
            a_fleet_rx.try_recv().is_err(),
            "A's own event must not loop back onto its fleet feed"
        );
        drop(fleet);
    }

    #[tokio::test]
    async fn subscriber_drops_self_origin_echo() {
        // Redis echoes our own PUBLISH back; the subscriber must drop
        // events whose origin is us, and forward peers' events.
        let fleet: Arc<dyn FleetBus> = Arc::new(aegis_core::fleet::NoopFleetBus);
        let fleet_event_bus = AuditBus::new(16);
        let mut sse_rx = fleet_event_bus.subscribe();

        // Drive the dedup logic directly (the Noop bus yields nothing,
        // so we exercise the filter via the helper it uses).
        let mut mine = ev();
        stamp_origin(&mut mine, "node-A");
        assert_eq!(origin_of(&mine).as_deref(), Some("node-A"));

        let mut theirs = ev();
        stamp_origin(&mut theirs, "node-B");

        // Mirror the subscriber's filter:
        let our_node = "node-A";
        for e in [mine, theirs.clone()] {
            if origin_of(&e).as_deref() == Some(our_node) {
                continue;
            }
            fleet_event_bus.emit(e);
        }
        let got = sse_rx.try_recv().expect("peer event forwarded");
        assert_eq!(origin_of(&got).as_deref(), Some("node-B"));
        assert!(sse_rx.try_recv().is_err(), "only the peer event, not our echo");
        drop(fleet);
    }
}
