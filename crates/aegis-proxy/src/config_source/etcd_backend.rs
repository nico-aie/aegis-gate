//! CONFIG-PLANE etcd backend (H2b P2, 2026-06-25) — the durable config doc
//! on a real consensus KV/watch store.
//!
//! Implements the narrow [`aegis_core::config_backend::ConfigBackend`] +
//! [`aegis_core::config_backend::ConfigWatch`] seam (extracted in P1) over
//! native etcd v3 gRPC ([`etcd_client`]: KV / Txn / Watch / Lease), so a
//! deployment can set `config_plane.store: etcd` and keep the SAME versioned
//! config doc (`config:waf:doc`, its `config:waf:v:{n}` snapshots, and the
//! per-node `config:waf:applied:*` ACKs) on a store built for exactly this
//! workload. The ephemeral hot-path keyspace never moves — Redis stays
//! mandatory for the data plane (see the plan's key constraint).
//!
//! Behind the default-off `etcd_config` cargo feature: the shipped binary
//! pulls no etcd-client / gRPC dependency.
//!
//! ## Why each method maps cleanly onto an etcd primitive
//!
//! | Seam method | etcd primitive | Replaces (shared_state) |
//! |---|---|---|
//! | [`ConfigBackend::get`] | KV `Get` | Redis `GET` |
//! | [`ConfigBackend::cas_set`] | `Txn` with a `Compare` | hand-written Lua CAS |
//! | [`ConfigBackend::put_ttl`] | lease-attached `Put` | `PSETEX` TTL ACK |
//! | [`ConfigBackend::scan_prefix`] | `Get` `WithPrefix` (keys-only) | `SCAN MATCH` |
//! | [`ConfigWatch::watch`] | native `Watch` on `config:waf:doc` | pub/sub bump + 3 s poll |
//!
//! The `cas_set` Txn is the single biggest cleanup: optimistic concurrency
//! becomes a first-class primitive instead of a bolted-on Lua script. The
//! native Watch means [`ConfigWatch::notify_change`] is a **no-op** — the KV
//! write itself wakes every node's watcher (the writer's own included), with
//! no missed events and no poll fallback needed.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use etcd_client::{Client, Compare, CompareOp, GetOptions, PutOptions, Txn, TxnOp};
use tokio::sync::mpsc;

use aegis_core::config_backend::{ConfigBackend, ConfigWatch};
use aegis_core::error::{Result, WafError};

use super::config_store::DOC_KEY;

/// Map an [`etcd_client::Error`] onto the crate's state-error variant —
/// the same variant the Redis backend uses, so callers (`ConfigStore`)
/// treat a transport failure identically regardless of store.
fn etcd_err(context: &str, e: etcd_client::Error) -> WafError {
    WafError::State(format!("etcd config plane: {context}: {e}"))
}

/// Durable config-plane backend over native etcd v3 gRPC.
///
/// [`Client`] is a cheap, cloneable handle over one multiplexed gRPC
/// channel; the trait methods clone it per call so the impl is `&self`
/// (and thus `Send + Sync`) without interior mutability.
#[derive(Clone)]
pub struct EtcdConfigBackend {
    client: Client,
}

impl EtcdConfigBackend {
    /// Connect to the etcd cluster at `endpoints` (etcd v3 gRPC, e.g.
    /// `["http://127.0.0.1:2379"]`). Fails loudly if no endpoint is
    /// reachable — the boot path treats this like any other config-store
    /// connect failure.
    pub async fn connect(endpoints: &[String]) -> Result<Self> {
        if endpoints.is_empty() {
            return Err(WafError::Config(
                "config_plane.etcd.endpoints is empty".into(),
            ));
        }
        let client = Client::connect(endpoints, None)
            .await
            .map_err(|e| etcd_err("connect", e))?;
        Ok(Self { client })
    }

    /// Erase to `Arc<dyn ConfigBackend>` for the config-store wiring.
    pub fn into_backend(self) -> Arc<dyn ConfigBackend> {
        Arc::new(self)
    }

    /// A [`ConfigWatch`] handle sharing this backend's connection. Watches
    /// the active-doc key so an activation anywhere in the fleet wakes the
    /// local watcher natively (no poll). Erased to `Arc<dyn ConfigWatch>`
    /// for the watcher wiring.
    pub fn config_watch(&self) -> Arc<dyn ConfigWatch> {
        Arc::new(EtcdConfigWatch {
            client: self.client.clone(),
            key: DOC_KEY.to_string(),
        })
    }
}

#[async_trait]
impl ConfigBackend for EtcdConfigBackend {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let mut client = self.client.clone();
        let resp = client
            .get(key, None)
            .await
            .map_err(|e| etcd_err("get", e))?;
        Ok(resp.kvs().first().map(|kv| kv.value().to_vec()))
    }

    async fn put_ttl(&self, key: &str, val: &[u8], ttl: Duration) -> Result<()> {
        // Native lease: grant a fresh lease for this ACK and attach it to the
        // put. The key auto-expires when the lease lapses — the per-node ACK
        // TTL we emulate with PSETEX under Redis, expressed first-class. The
        // watcher re-stamps every poll (granting a new lease each time, like
        // a fresh PSETEX), so leases turn over rather than accumulate.
        let mut client = self.client.clone();
        // etcd lease TTL is whole seconds; round up so a sub-second TTL never
        // truncates to 0 (which would mean "no expiry").
        let ttl_secs = ttl.as_secs().max(1) as i64;
        let lease = client
            .lease_grant(ttl_secs, None)
            .await
            .map_err(|e| etcd_err("lease_grant", e))?;
        let opts = PutOptions::new().with_lease(lease.id());
        client
            .put(key, val, Some(opts))
            .await
            .map_err(|e| etcd_err("put_ttl", e))?;
        Ok(())
    }

    async fn cas_set(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        new: &[u8],
        ttl: Option<Duration>,
    ) -> Result<bool> {
        let mut client = self.client.clone();

        // Build the PutOptions (durable by default; lease-attached when a TTL
        // is requested — only the snapshot/doc paths pass ttl=None).
        let put_opts = match ttl {
            None => None,
            Some(d) => {
                let lease = client
                    .lease_grant(d.as_secs().max(1) as i64, None)
                    .await
                    .map_err(|e| etcd_err("lease_grant", e))?;
                Some(PutOptions::new().with_lease(lease.id()))
            }
        };
        let put_op = TxnOp::put(key, new, put_opts);

        // The Compare guard expresses the optimistic-concurrency precondition:
        //  - expected None  → key must be ABSENT (create_revision == 0).
        //  - expected Some  → key must EXIST with exactly that value. We AND
        //    create_revision > 0 with value == expected so an absent key (whose
        //    value compares as empty) can never spuriously satisfy a non-empty
        //    expected. A satisfied guard runs the put (succeeded == true); an
        //    unsatisfied one runs nothing (succeeded == false → Conflict).
        let txn = match expected {
            None => Txn::new()
                .when(vec![Compare::create_revision(key, CompareOp::Equal, 0)])
                .and_then(vec![put_op]),
            Some(exp) => Txn::new()
                .when(vec![
                    Compare::create_revision(key, CompareOp::Greater, 0),
                    Compare::value(key, CompareOp::Equal, exp),
                ])
                .and_then(vec![put_op]),
        };

        let resp = client.txn(txn).await.map_err(|e| etcd_err("cas_set txn", e))?;
        Ok(resp.succeeded())
    }

    async fn scan_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        let mut client = self.client.clone();
        // Keys-only range over the prefix — we only need the key names (the
        // per-node ACK roster); skipping values keeps the response small.
        let opts = GetOptions::new().with_prefix().with_keys_only();
        let resp = client
            .get(prefix, Some(opts))
            .await
            .map_err(|e| etcd_err("scan_prefix", e))?;
        let mut out = Vec::with_capacity(resp.kvs().len());
        for kv in resp.kvs() {
            // Keys are UTF-8 by construction (we only ever write `config:waf:*`
            // ASCII keys); skip any non-UTF-8 key rather than failing the scan.
            if let Ok(k) = kv.key_str() {
                out.push(k.to_string());
            }
        }
        Ok(out)
    }
}

/// Native-watch [`ConfigWatch`] over etcd. Subscribes to the active-doc key
/// ([`DOC_KEY`]); every put to it (a new activated version) delivers a watch
/// event that wakes the local config watcher in ~ms.
///
/// [`ConfigWatch::notify_change`] is intentionally a **no-op**: under etcd
/// the KV write IS the notification (every node, including the writer,
/// observes its own put via the watch), so there is nothing extra to
/// publish — the missed-nudge / poll-fallback seam that `shared_state`
/// needs simply doesn't exist here.
#[derive(Clone)]
pub struct EtcdConfigWatch {
    client: Client,
    key: String,
}

/// How long the watch-forwarder backs off before re-establishing a dropped
/// etcd watch stream. The config watcher's interval poll is the correctness
/// backstop during any gap, so this only bounds reconnect churn.
const WATCH_RECONNECT_BACKOFF: Duration = Duration::from_secs(1);

#[async_trait]
impl ConfigWatch for EtcdConfigWatch {
    async fn notify_change(&self) {
        // No-op — see the type doc. The etcd Put already woke every watcher.
    }

    fn watch(&self, bound: usize) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(bound.max(1));
        let mut client = self.client.clone();
        let key = self.key.clone();
        tokio::spawn(async move {
            // Reconnect loop: a watch stream can end on a transport blip; the
            // config watcher's poll covers any window, so we just re-establish.
            loop {
                let watched = client.watch(key.as_str(), None).await;
                let (_watcher, mut stream) = match watched {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::debug!(
                            error = %e,
                            "etcd config watch: establish failed; \
                             relying on poll backstop and retrying",
                        );
                        tokio::time::sleep(WATCH_RECONNECT_BACKOFF).await;
                        // Receiver gone while we were backing off → stop.
                        if tx.is_closed() {
                            return;
                        }
                        continue;
                    }
                };
                loop {
                    match stream.message().await {
                        Ok(Some(_resp)) => {
                            // Coalesced "re-read now" signal; payload is
                            // meaningless (correctness lives in the polled
                            // DOC_KEY). Drop on a full/closed channel — the
                            // watcher only needs to know "something changed".
                            if tx.try_send(vec![1]).is_err() && tx.is_closed() {
                                return; // receiver dropped → end the task
                            }
                        }
                        Ok(None) => break,   // stream ended → reconnect
                        Err(e) => {
                            tracing::debug!(
                                error = %e,
                                "etcd config watch: stream error; reconnecting",
                            );
                            break;
                        }
                    }
                }
                if tx.is_closed() {
                    return;
                }
                tokio::time::sleep(WATCH_RECONNECT_BACKOFF).await;
            }
        });
        rx
    }
}

// ---------------------------------------------------------------------------
// Integration tests — require a real etcd. Gated on AEGIS_ETCD_TEST_ENDPOINTS
// so a normal `cargo test --features etcd_config` (no etcd running) skips them
// instead of failing. Run against a local etcd with, e.g.:
//   docker run -d -p 2379:2379 quay.io/coreos/etcd:v3.5.16 /usr/local/bin/etcd \
//     --advertise-client-urls http://0.0.0.0:2379 \
//     --listen-client-urls http://0.0.0.0:2379
//   AEGIS_ETCD_TEST_ENDPOINTS=http://127.0.0.1:2379 \
//     cargo test -p aegis-proxy --features etcd_config etcd_backend
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// Endpoints from the env, or `None` to skip (no etcd available).
    fn test_endpoints() -> Option<Vec<String>> {
        std::env::var("AEGIS_ETCD_TEST_ENDPOINTS")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.split(',').map(|e| e.trim().to_string()).collect())
    }

    /// A unique key prefix per test run so concurrent / repeated runs against
    /// the same etcd never collide. Varies by the supplied tag + a nanosecond
    /// clock read (std::time, allowed outside the workflow sandbox).
    fn unique_prefix(tag: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("config:waf:test:{tag}:{nanos}:")
    }

    async fn backend() -> Option<EtcdConfigBackend> {
        let eps = test_endpoints()?;
        Some(
            EtcdConfigBackend::connect(&eps)
                .await
                .expect("connect to test etcd"),
        )
    }

    #[tokio::test]
    async fn get_absent_key_is_none() {
        let Some(b) = backend().await else { return };
        let key = format!("{}doc", unique_prefix("absent"));
        assert!(b.get(&key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn cas_set_first_write_then_roundtrips() {
        let Some(b) = backend().await else { return };
        let key = format!("{}doc", unique_prefix("cas-first"));

        // expected=None on an absent key → writes.
        assert!(b.cas_set(&key, None, b"v1", None).await.unwrap());
        assert_eq!(b.get(&key).await.unwrap().unwrap(), b"v1");
    }

    #[tokio::test]
    async fn cas_set_absent_guard_conflicts_when_key_exists() {
        let Some(b) = backend().await else { return };
        let key = format!("{}doc", unique_prefix("cas-absent-guard"));

        assert!(b.cas_set(&key, None, b"v1", None).await.unwrap());
        // A second expected=None must lose — key now exists (parity with the
        // Lua-CAS 409 path).
        assert!(!b.cas_set(&key, None, b"v2", None).await.unwrap());
        assert_eq!(b.get(&key).await.unwrap().unwrap(), b"v1");
    }

    #[tokio::test]
    async fn cas_set_value_guard_swaps_then_conflicts_on_stale() {
        let Some(b) = backend().await else { return };
        let key = format!("{}doc", unique_prefix("cas-value-guard"));

        assert!(b.cas_set(&key, None, b"v1", None).await.unwrap());
        // Correct expected → swaps.
        assert!(b.cas_set(&key, Some(b"v1"), b"v2", None).await.unwrap());
        assert_eq!(b.get(&key).await.unwrap().unwrap(), b"v2");
        // Stale expected → Conflict, value unchanged.
        assert!(!b.cas_set(&key, Some(b"v1"), b"v3", None).await.unwrap());
        assert_eq!(b.get(&key).await.unwrap().unwrap(), b"v2");
    }

    #[tokio::test]
    async fn scan_prefix_lists_only_matching_keys() {
        let Some(b) = backend().await else { return };
        let pfx = unique_prefix("scan");
        let applied = format!("{pfx}applied:");

        b.cas_set(&format!("{applied}node-a"), None, b"5", None)
            .await
            .unwrap();
        b.cas_set(&format!("{applied}node-b"), None, b"4", None)
            .await
            .unwrap();
        // A sibling key under the run prefix but NOT the applied: sub-prefix.
        b.cas_set(&format!("{pfx}doc"), None, b"x", None)
            .await
            .unwrap();

        let mut got = b.scan_prefix(&applied).await.unwrap();
        got.sort();
        assert_eq!(
            got,
            vec![format!("{applied}node-a"), format!("{applied}node-b")],
        );
    }

    #[tokio::test]
    async fn put_ttl_value_is_readable_then_expires() {
        let Some(b) = backend().await else { return };
        let key = format!("{}applied:node-a", unique_prefix("ttl"));

        // 1 s lease (the floor) — written and immediately readable.
        b.put_ttl(&key, b"7", Duration::from_millis(500))
            .await
            .unwrap();
        assert_eq!(b.get(&key).await.unwrap().unwrap(), b"7");

        // After the lease lapses the key is gone — native TTL, no manual del.
        // (etcd lease floor is 1 s; allow margin for revocation.)
        tokio::time::sleep(Duration::from_millis(2500)).await;
        assert!(
            b.get(&key).await.unwrap().is_none(),
            "lease-attached key must auto-expire",
        );
    }

    #[tokio::test]
    async fn watch_delivers_a_change_event_without_polling() {
        let Some(b) = backend().await else { return };
        // The watch is hard-wired to DOC_KEY, so this test writes the real
        // active-doc key. Use cas_set so we don't depend on another node's
        // state; a fresh etcd has DOC_KEY absent (expected=None writes).
        // NOTE: shares the global DOC_KEY — fine for a dedicated test etcd.
        let watch = b.config_watch();
        let mut rx = watch.watch(8);

        // Give the watch stream a beat to establish before the write.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Activate a new value on DOC_KEY (value-guarded so re-runs work
        // regardless of the current value).
        let cur = b.get(DOC_KEY).await.unwrap();
        let wrote = b
            .cas_set(DOC_KEY, cur.as_deref(), b"watch-probe", None)
            .await
            .unwrap();
        assert!(wrote, "probe write should win the CAS on a quiet test etcd");

        // The native watch must deliver an event well inside the would-be
        // poll interval (3 s) — prove convergence isn't poll-bound.
        let got = tokio::time::timeout(Duration::from_millis(1500), rx.recv()).await;
        assert!(
            matches!(got, Ok(Some(_))),
            "etcd watch must deliver a change event without the poll fallback",
        );
    }

    #[tokio::test]
    async fn notify_change_is_a_noop() {
        let Some(b) = backend().await else { return };
        // Must not panic / error — the etcd Put is the notification.
        b.config_watch().notify_change().await;
    }
}
