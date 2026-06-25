//! CONFIG-PLANE seam (H2b P1, 2026-06-24) — the narrow durable-config
//! traits the config plane talks to, extracted out of [`StateBackend`] /
//! [`FleetBus`] so a second implementor (etcd) can back the config doc
//! without dragging in the hot-path ephemeral keyspace.
//!
//! See `plans/future/config-etcd-source-of-truth.md`. The split is the
//! key constraint of that plan: the durable config plane (`config:waf:*`)
//! is low-write fleet-wide-consensus data — a perfect etcd workload — while
//! the same `StateBackend` also carries rate-limit counters, nonces, risk,
//! and leases, which must NEVER move off Redis. Porting all of
//! `StateBackend` to etcd would be a correctness and performance disaster;
//! porting this narrow seam is exactly right.
//!
//! ## What P1 ships (pure refactor, zero behaviour change)
//!
//! - [`ConfigBackend`] — the durable KV + compare-and-set surface the
//!   versioned config doc uses ([`crate::state::StateBackend`] is a strict
//!   superset of it).
//! - [`ConfigWatch`] — the change-notification surface the config-plane
//!   nudge uses (a narrow slice of [`FleetBus`]).
//! - [`SharedStateConfigBackend`] / [`FleetBusConfigWatch`] — adapters that
//!   make `config_plane.store: shared_state` (the default) ride the existing
//!   data-plane `StateBackend` / config nudge `FleetBus`, forwarding 1:1.
//!
//! The traits are siblings of `StateBackend` / `FleetBus`, NOT supertraits:
//! making them supertraits would force every one of the ~30 `StateBackend`
//! test stubs + wrappers to also implement them, exactly the churn the
//! `FleetBus` sibling design already avoids. The adapters cost one pointer
//! hop and are the only `shared_state` implementor; the future `EtcdBackend`
//! (P2) implements [`ConfigBackend`] / [`ConfigWatch`] directly.
//!
//! ## Mapping to etcd primitives (P2)
//!
//! Each method has a first-class etcd v3 equivalent, replacing a bolted-on
//! Redis emulation:
//!
//! | [`ConfigBackend`] method | Redis today | etcd (P2) |
//! |---|---|---|
//! | [`ConfigBackend::get`] | `GET` | KV `Get` |
//! | [`ConfigBackend::cas_set`] | hand-written Lua CAS | `Txn` w/ `Compare` |
//! | [`ConfigBackend::put_ttl`] (per-node ACK) | `PSETEX` TTL | lease-attached `Put` |
//! | [`ConfigBackend::scan_prefix`] | `SCAN MATCH` | `Get` w/ `WithPrefix` |
//!
//! The reset-epoch **counter** ops (`incrby` / `get_counter`) are NOT in
//! this trait: the plan defers whether they stay on Redis to P3, and a
//! consensus store is a poor counter — so the control plane keeps talking to
//! `StateBackend` for now (out of scope for P1, see the plan's P1 note).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::error::Result;
use crate::fleet::FleetBus;
use crate::state::StateBackend;

/// The durable config plane's view of a key/value store: read, durable
/// write, atomic compare-and-set, and prefix scan. This is the narrow seam
/// the versioned config document (`config:waf:doc`, its per-version
/// snapshots, and the per-node applied-version ACKs) is written and read
/// through.
///
/// [`StateBackend`] is a strict superset, so every shipped data-plane
/// backend already satisfies this surface; [`SharedStateConfigBackend`]
/// forwards to it for the default `config_plane.store: shared_state`. A
/// dedicated etcd backend (P2) implements this trait directly without being
/// a full `StateBackend`.
///
/// All methods are **required** (no inert defaults): unlike `StateBackend`'s
/// optional extensions — which default so the many test stubs keep compiling
/// — a `ConfigBackend` has only a handful of implementors, and a config
/// write that silently no-ops would be a correctness hole, not a
/// convenience.
#[async_trait]
pub trait ConfigBackend: Send + Sync + 'static {
    /// Read the value at `key`, or `None` when absent.
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Write `val` at `key` with an expiry. Used only for the per-node
    /// applied-version ACK (`config:waf:applied:<node>`), which ages a dead
    /// node out of the drift roster — etcd expresses this natively as a
    /// lease-attached put (P2). Durable config values are written via
    /// [`Self::cas_set`] with `ttl = None`, never here.
    async fn put_ttl(&self, key: &str, val: &[u8], ttl: Duration) -> Result<()>;

    /// Atomic compare-and-set: write `new` iff the current value equals
    /// `expected` (`None` ⇒ key must be absent). `ttl = None` persists the
    /// key (config must not expire). Returns `true` on a successful swap,
    /// `false` on an optimistic-concurrency conflict (value mismatch). This
    /// is the sole arbiter of a config-version activation.
    async fn cas_set(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        new: &[u8],
        ttl: Option<Duration>,
    ) -> Result<bool>;

    /// Return every key matching `prefix` (the per-node applied-version
    /// roster for the console drift view).
    async fn scan_prefix(&self, prefix: &str) -> Result<Vec<String>>;
}

/// The config plane's change-notification seam: a best-effort "config
/// changed" nudge so a watcher re-reads the doc in ~ms instead of waiting
/// for its next poll tick. A narrow slice of [`FleetBus`] (publish one
/// fixed channel, subscribe to it).
///
/// For `shared_state` this is Redis pub/sub + the watcher's poll backstop
/// ([`FleetBusConfigWatch`]); for etcd (P2) it becomes a native `Watch`
/// with no missed events and the poll demoted to a slow heartbeat.
#[async_trait]
pub trait ConfigWatch: Send + Sync + 'static {
    /// Fire a best-effort change notification. Loss-tolerant: a dropped
    /// notification just falls back to the watcher's poll, so this never
    /// blocks or errors at the call site.
    async fn notify_change(&self);

    /// Subscribe to change notifications. `bound` caps in-flight buffered
    /// events; the payload carries no meaning (the signal is "re-read now",
    /// correctness lives in the polled doc). The implementation owns the
    /// connection/forwarding task and ends it when the receiver drops.
    fn watch(&self, bound: usize) -> mpsc::Receiver<Vec<u8>>;
}

/// `shared_state` adapter — exposes any data-plane [`StateBackend`] as a
/// [`ConfigBackend`]. This is what makes `config_plane.store: shared_state`
/// (the default) ride the existing Redis / in-memory state backend with
/// zero behaviour change: every method forwards 1:1. The etcd backend (P2)
/// implements [`ConfigBackend`] directly instead of going through this.
pub struct SharedStateConfigBackend {
    inner: Arc<dyn StateBackend>,
}

impl SharedStateConfigBackend {
    /// Wrap a data-plane state backend as the config plane's store.
    pub fn new(inner: Arc<dyn StateBackend>) -> Self {
        Self { inner }
    }

    /// Convenience: wrap and erase to `Arc<dyn ConfigBackend>` in one step.
    pub fn arc(inner: Arc<dyn StateBackend>) -> Arc<dyn ConfigBackend> {
        Arc::new(Self::new(inner))
    }
}

#[async_trait]
impl ConfigBackend for SharedStateConfigBackend {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.inner.get(key).await
    }

    async fn put_ttl(&self, key: &str, val: &[u8], ttl: Duration) -> Result<()> {
        self.inner.set(key, val, ttl).await
    }

    async fn cas_set(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        new: &[u8],
        ttl: Option<Duration>,
    ) -> Result<bool> {
        self.inner.cas_set(key, expected, new, ttl).await
    }

    async fn scan_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        self.inner.scan_prefix(prefix).await
    }
}

/// `shared_state` adapter — exposes a [`FleetBus`] as a [`ConfigWatch`]
/// bound to a single config-bump channel. The channel name is baked in at
/// construction so the watcher just calls [`ConfigWatch::watch`] without
/// knowing the wire detail. Forwards 1:1 (subscribe returns the bus'
/// receiver directly — no extra task or hop).
pub struct FleetBusConfigWatch {
    bus: Arc<dyn FleetBus>,
    channel: String,
}

impl FleetBusConfigWatch {
    /// Bind `bus` to `channel` (the config-bump channel) as a config watch.
    pub fn new(bus: Arc<dyn FleetBus>, channel: impl Into<String>) -> Self {
        Self {
            bus,
            channel: channel.into(),
        }
    }

    /// Convenience: wrap and erase to `Arc<dyn ConfigWatch>` in one step.
    pub fn arc(bus: Arc<dyn FleetBus>, channel: impl Into<String>) -> Arc<dyn ConfigWatch> {
        Arc::new(Self::new(bus, channel))
    }
}

#[async_trait]
impl ConfigWatch for FleetBusConfigWatch {
    async fn notify_change(&self) {
        // 1-byte payload mirrors the prior nudge; its content is ignored.
        self.bus.publish(&self.channel, vec![1]).await;
    }

    fn watch(&self, bound: usize) -> mpsc::Receiver<Vec<u8>> {
        self.bus.subscribe(&self.channel, bound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Mutex;

    use crate::risk::RiskKey;
    use crate::state::SlidingWindowResult;

    /// Minimal in-memory [`StateBackend`] for adapter forwarding tests — a
    /// map for `get`/`set`/`cas_set` plus prefix scan. Only the methods the
    /// config plane uses are meaningfully implemented; the hot-path ones are
    /// inert stubs (this is a test double, not a shipping backend).
    #[derive(Default)]
    struct MapBackend {
        map: Mutex<HashMap<String, Vec<u8>>>,
    }

    #[async_trait]
    impl StateBackend for MapBackend {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.map.lock().unwrap().get(key).cloned())
        }
        async fn set(&self, key: &str, val: &[u8], _ttl: Duration) -> Result<()> {
            self.map.lock().unwrap().insert(key.to_string(), val.to_vec());
            Ok(())
        }
        async fn del(&self, key: &str) -> Result<()> {
            self.map.lock().unwrap().remove(key);
            Ok(())
        }
        async fn incr_window(
            &self,
            _: &str,
            _: Duration,
            _: u64,
        ) -> Result<SlidingWindowResult> {
            Ok(SlidingWindowResult {
                count: 0,
                allowed: true,
                retry_after: None,
            })
        }
        async fn token_bucket(&self, _: &str, _: u32, _: u32) -> Result<bool> {
            Ok(true)
        }
        async fn get_risk(&self, _: &RiskKey) -> Result<u32> {
            Ok(0)
        }
        async fn add_risk(&self, _: &RiskKey, _: i32, _: u32) -> Result<u32> {
            Ok(0)
        }
        async fn auto_block(&self, _: IpAddr, _: Duration) -> Result<()> {
            Ok(())
        }
        async fn is_auto_blocked(&self, _: IpAddr) -> Result<bool> {
            Ok(false)
        }
        async fn put_nonce(&self, _: &str, _: Duration) -> Result<bool> {
            Ok(true)
        }
        async fn consume_nonce(&self, _: &str) -> Result<bool> {
            Ok(true)
        }
        async fn cas_set(
            &self,
            key: &str,
            expected: Option<&[u8]>,
            new: &[u8],
            _ttl: Option<Duration>,
        ) -> Result<bool> {
            let mut map = self.map.lock().unwrap();
            let cur = map.get(key).map(|v| v.as_slice());
            if cur == expected {
                map.insert(key.to_string(), new.to_vec());
                Ok(true)
            } else {
                Ok(false)
            }
        }
        async fn scan_prefix(&self, prefix: &str) -> Result<Vec<String>> {
            Ok(self
                .map
                .lock()
                .unwrap()
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
    }

    #[tokio::test]
    async fn shared_state_adapter_forwards_get_and_cas_set() {
        let cfg: Arc<dyn ConfigBackend> =
            SharedStateConfigBackend::arc(Arc::new(MapBackend::default()));

        // Absent key.
        assert!(cfg.get("config:waf:doc").await.unwrap().is_none());

        // First CAS (expected absent) writes; reading it back round-trips.
        assert!(cfg
            .cas_set("config:waf:doc", None, b"v1", None)
            .await
            .unwrap());
        assert_eq!(cfg.get("config:waf:doc").await.unwrap().unwrap(), b"v1");

        // Stale expected ⇒ conflict (no write).
        assert!(!cfg
            .cas_set("config:waf:doc", None, b"v2", None)
            .await
            .unwrap());
        assert_eq!(cfg.get("config:waf:doc").await.unwrap().unwrap(), b"v1");

        // Correct expected ⇒ swap.
        assert!(cfg
            .cas_set("config:waf:doc", Some(b"v1"), b"v2", None)
            .await
            .unwrap());
        assert_eq!(cfg.get("config:waf:doc").await.unwrap().unwrap(), b"v2");
    }

    #[tokio::test]
    async fn shared_state_adapter_forwards_put_ttl_and_scan_prefix() {
        let cfg: Arc<dyn ConfigBackend> =
            SharedStateConfigBackend::arc(Arc::new(MapBackend::default()));

        cfg.put_ttl("config:waf:applied:node-a", b"5", Duration::from_secs(30))
            .await
            .unwrap();
        cfg.put_ttl("config:waf:applied:node-b", b"4", Duration::from_secs(30))
            .await
            .unwrap();
        cfg.put_ttl("config:waf:doc", b"x", Duration::from_secs(30))
            .await
            .unwrap();

        let mut roster = cfg.scan_prefix("config:waf:applied:").await.unwrap();
        roster.sort();
        assert_eq!(
            roster,
            vec![
                "config:waf:applied:node-a".to_string(),
                "config:waf:applied:node-b".to_string(),
            ],
        );
    }

    /// Recording [`FleetBus`] — captures publishes so the watch adapter test
    /// can assert `notify_change` published to the bound channel.
    #[derive(Default)]
    struct RecordingBus {
        published: Mutex<Vec<(String, Vec<u8>)>>,
    }

    #[async_trait]
    impl FleetBus for RecordingBus {
        async fn publish(&self, channel: &str, payload: Vec<u8>) {
            self.published
                .lock()
                .unwrap()
                .push((channel.to_string(), payload));
        }
        fn subscribe(&self, _channel: &str, bound: usize) -> mpsc::Receiver<Vec<u8>> {
            let (_tx, rx) = mpsc::channel(bound.max(1));
            rx
        }
    }

    #[tokio::test]
    async fn fleet_watch_adapter_publishes_change_on_bound_channel() {
        let bus = Arc::new(RecordingBus::default());
        let watch = FleetBusConfigWatch::new(bus.clone(), "config:waf:bump");
        watch.notify_change().await;
        let pubs = bus.published.lock().unwrap();
        assert_eq!(pubs.len(), 1, "exactly one bump per notify_change");
        assert_eq!(pubs[0].0, "config:waf:bump");
    }
}
