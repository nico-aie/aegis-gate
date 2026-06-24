//! CONFIG-PLANE (2026-05-27) — shared, versioned config document in
//! the `StateBackend` so every node converges on the same config and a
//! console edit survives leader failover.
//!
//! See `plans/future/cluster-config-sync-and-scaling.md`. The design
//! invariants (from Cloudflare Quicksilver / Envoy xDS / Fastly):
//!
//! - **Control plane authoritative; nodes are read replicas.** Edits go
//!   through [`ConfigStore::activate`], never mutate a node directly.
//! - **Immutable, versioned, atomically-activated snapshot.** The active
//!   document lives under a single key ([`DOC_KEY`]) so activation is one
//!   atomic compare-and-set ([`StateBackend::cas_set`]); each version's
//!   YAML is also written write-once to [`snapshot_key`] for rollback.
//! - **Monotonic version + per-node ACK.** Each node records the version
//!   it applied under [`applied_key`]; the console reads
//!   [`ConfigStore::applied_map`] to show drift.
//! - **Fail-static** is the watcher's job (keep last-good `ArcSwap` if the
//!   backend is unreachable) — see `redis_source`.
//!
//! The store is backend-agnostic: it works against `in_memory` (single
//! node / dev / tests) and `redis` (multi-node) identically.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use aegis_core::config_backend::{ConfigBackend, ConfigWatch, SharedStateConfigBackend};
use aegis_core::error::{Result, WafError};
use aegis_core::state::StateBackend;

/// The single key holding the active config document (JSON-encoded
/// [`ConfigDoc`]). Activation is a compare-and-set on this key.
pub const DOC_KEY: &str = "config:waf:doc";

/// N2 (2026-06-11) — pub/sub bump channel for the config plane. A 1-byte
/// message is published here on a successful [`ConfigStore::activate`] so
/// every node's config watcher (including the writer's own) re-polls
/// [`DOC_KEY`] immediately instead of waiting for its next poll tick.
/// Loss-tolerant: the watcher's poll interval is the backstop. Mirrors the
/// control plane's `CONTROL_BUMP_CHANNEL`.
pub const CONFIG_BUMP_CHANNEL: &str = "config:waf:bump";

/// Per-node applied-version keys live under this prefix; the value is
/// the decimal version string. TTL'd so a dead node ages out of the
/// drift view.
pub const APPLIED_PREFIX: &str = "config:waf:applied:";

/// How long a node's applied-version ACK lives without a refresh. The
/// watcher re-stamps it every poll, so a node that stops polling
/// disappears from the roster within this window.
pub const APPLIED_TTL: Duration = Duration::from_secs(30);

/// Immutable per-version YAML snapshot key (for rollback).
pub fn snapshot_key(version: u64) -> String {
    format!("config:waf:v:{version}")
}

/// Per-node applied-version key.
pub fn applied_key(node_id: &str) -> String {
    format!("{APPLIED_PREFIX}{node_id}")
}

/// The active config document. `blob` is the same YAML the file / etcd
/// loaders accept — single validation surface.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigDoc {
    /// Monotonic version, bumped on every accepted activation.
    pub version: u64,
    /// The DYNAMIC config as YAML (H2a — bootstrap keys are stripped at
    /// `activate`; the bootstrap half lives in the file/env, never the doc).
    pub blob: String,
    /// Who wrote this version (audit attribution).
    #[serde(default)]
    pub actor: String,
    /// RFC-3339 activation timestamp.
    #[serde(default)]
    pub ts: String,
    /// Short human summary of the change.
    #[serde(default)]
    pub summary: String,
}

/// Outcome of an activation attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Activate {
    /// Swap succeeded; the new active version.
    Applied { version: u64 },
    /// Optimistic-concurrency conflict — someone else activated since
    /// the editor loaded. Carries the version that is now current so the
    /// caller can reload-and-retry (→ HTTP 409).
    Conflict { current: u64 },
}

/// Versioned config store over a [`ConfigBackend`].
///
/// H2b (2026-06-24) — the store talks to the narrow [`ConfigBackend`] /
/// [`ConfigWatch`] seam, not [`StateBackend`] / `FleetBus` directly, so the
/// durable config plane can be backed by etcd (P2) without dragging in the
/// hot-path ephemeral keyspace. [`Self::new`] is the `shared_state` path: it
/// wraps the data-plane state backend in [`SharedStateConfigBackend`], the
/// default behaviour where the config doc rides `state.backend`.
#[derive(Clone)]
pub struct ConfigStore {
    backend: Arc<dyn ConfigBackend>,
    /// Optional config-plane change-notification seam. When set, a
    /// successful [`Self::activate`] fires [`ConfigWatch::notify_change`] so
    /// every node's config watcher (incl. the writer's own) re-reads
    /// immediately rather than waiting for its next poll tick. Best-effort +
    /// non-load-bearing: a dropped notification just falls back to the poll.
    /// `None` on the watcher's read-only store and on single-node /
    /// in-memory deployments.
    nudge: Option<Arc<dyn ConfigWatch>>,
}

impl ConfigStore {
    /// `shared_state` constructor — the config doc rides the data-plane
    /// [`StateBackend`] (today's default). Wraps `backend` in
    /// [`SharedStateConfigBackend`]; the etcd path (P2) will construct the
    /// store from an [`Arc<dyn ConfigBackend>`] directly.
    pub fn new(backend: Arc<dyn StateBackend>) -> Self {
        Self {
            backend: SharedStateConfigBackend::arc(backend),
            nudge: None,
        }
    }

    /// Attach a config-plane change-notification seam (see the `nudge`
    /// field). Builder so the per-request write-path stores opt in while the
    /// watcher's read-only store stays nudge-free. A `None` argument is a
    /// no-op.
    pub fn with_nudge(mut self, nudge: Option<Arc<dyn ConfigWatch>>) -> Self {
        self.nudge = nudge;
        self
    }

    /// Best-effort config-plane change notification. No-op when no watch is
    /// wired. The signal carries no meaning — it is a pure "re-read now"
    /// nudge; correctness lives in the polled [`DOC_KEY`].
    async fn fire_nudge(&self) {
        if let Some(watch) = &self.nudge {
            watch.notify_change().await;
        }
    }

    /// Load the active document, or `None` when no config has been
    /// activated yet (fresh cluster).
    pub async fn load(&self) -> Result<Option<ConfigDoc>> {
        match self.backend.get(DOC_KEY).await? {
            Some(bytes) => {
                let doc = serde_json::from_slice(&bytes)
                    .map_err(|e| WafError::State(format!("config doc decode: {e}")))?;
                Ok(Some(doc))
            }
            None => Ok(None),
        }
    }

    /// The current active version (0 when none activated yet).
    pub async fn current_version(&self) -> Result<u64> {
        Ok(self.load().await?.map(|d| d.version).unwrap_or(0))
    }

    /// Activate `blob` as the next version, but only if the current
    /// version still equals `expected_version` (optimistic concurrency).
    ///
    /// The caller is responsible for having `WafConfig::validate`d the
    /// blob first — the store does not parse it (single validation
    /// surface lives at the boundary). Writes an immutable snapshot, then
    /// CAS-flips the active document. A lost CAS (someone raced) returns
    /// [`Activate::Conflict`].
    pub async fn activate(
        &self,
        expected_version: u64,
        blob: String,
        actor: &str,
        summary: &str,
    ) -> Result<Activate> {
        // H2a — the config doc store holds the DYNAMIC config only. Strip any
        // bootstrap keys before persisting (idempotent — a doc that's already
        // dynamic-only passes through unchanged), so a bootstrap field can
        // never be STORED in the doc regardless of which caller wrote it
        // (handler patch, file publish, genesis seed, rollback). Both the doc
        // and its rollback snapshot are written from this stripped blob.
        let blob = aegis_core::strip_legacy_bootstrap_keys(&blob)
            .map_err(|e| WafError::State(format!("config doc strip: {e}")))?;
        let current = self.load().await?;
        let cur_version = current.as_ref().map(|d| d.version).unwrap_or(0);
        if cur_version != expected_version {
            return Ok(Activate::Conflict {
                current: cur_version,
            });
        }

        let next = cur_version + 1;
        let doc = ConfigDoc {
            version: next,
            blob: blob.clone(),
            actor: actor.to_string(),
            ts: chrono::Utc::now().to_rfc3339(),
            summary: summary.to_string(),
        };
        let new_bytes = serde_json::to_vec(&doc)
            .map_err(|e| WafError::State(format!("config doc encode: {e}")))?;

        // Compute the CAS expected-bytes (the exact doc we loaded) up
        // front so the two Redis writes below can overlap.
        let expected_bytes = match &current {
            Some(d) => Some(
                serde_json::to_vec(d)
                    .map_err(|e| WafError::State(format!("config doc encode: {e}")))?,
            ),
            None => None,
        };

        // 2026-06-12 (config-plane latency) — run the immutable rollback
        // snapshot write and the atomic activation CAS CONCURRENTLY. They
        // touch different keys and are independent, so overlapping them
        // shaves a Redis round-trip off the operator-visible mutation path
        // WITHOUT changing semantics: the snapshot is still durable before
        // this returns (rollback stays correct) and the doc CAS is still
        // the sole arbiter of the activation. The snapshot is best-effort —
        // a collision means a racing writer took the same version number;
        // the CAS decides the real winner.
        let snap_key = snapshot_key(next);
        let (snap_res, swap_res) = tokio::join!(
            self.backend
                .cas_set(&snap_key, None, blob.as_bytes(), None),
            self.backend
                .cas_set(DOC_KEY, expected_bytes.as_deref(), &new_bytes, None),
        );
        let _ = snap_res;
        let swapped = swap_res?;

        if swapped {
            // N2 — wake every node's watcher (incl. ours) so the new
            // version applies in ~ms instead of on the next poll tick.
            self.fire_nudge().await;
            Ok(Activate::Applied { version: next })
        } else {
            // Lost the race between load and CAS — report the version
            // that is current now so the caller retries against it.
            let now = self.current_version().await?;
            Ok(Activate::Conflict { current: now })
        }
    }

    /// Roll back to a previously-activated version by re-activating its
    /// (immutable) snapshot as a *new* version. No re-validation needed —
    /// the snapshot already passed validation when first activated.
    pub async fn rollback(&self, target_version: u64, actor: &str) -> Result<Activate> {
        let snap = self.backend.get(&snapshot_key(target_version)).await?;
        let Some(blob_bytes) = snap else {
            return Err(WafError::State(format!(
                "no config snapshot for version {target_version}"
            )));
        };
        let blob = String::from_utf8(blob_bytes)
            .map_err(|e| WafError::State(format!("snapshot not UTF-8: {e}")))?;
        let cur = self.current_version().await?;
        self.activate(cur, blob, actor, &format!("rollback to v{target_version}"))
            .await
    }

    /// H2a one-shot migration — if the active doc still carries bootstrap keys
    /// (a pre-H2a full-`WafConfig` doc), rewrite it IN PLACE as the dynamic
    /// projection. Same version (no spurious bump / fleet re-apply), CAS-
    /// guarded against a concurrent writer. Idempotent: a doc already
    /// dynamic-only is left untouched (returns `Ok(false)`). Snapshots are not
    /// rewritten eagerly — a rollback re-canonicalizes the target via
    /// [`Self::activate`]'s strip, and the watcher tolerates a legacy snapshot
    /// via `load_dynamic_str`. Returns `true` if a rewrite was applied.
    pub async fn canonicalize_active_doc(&self) -> Result<bool> {
        let Some(doc) = self.load().await? else {
            return Ok(false);
        };
        if !aegis_core::yaml_has_legacy_bootstrap_keys(&doc.blob) {
            return Ok(false);
        }
        let stripped = aegis_core::strip_legacy_bootstrap_keys(&doc.blob)
            .map_err(|e| WafError::State(format!("canonicalize strip: {e}")))?;
        let old_bytes = serde_json::to_vec(&doc)
            .map_err(|e| WafError::State(format!("config doc encode: {e}")))?;
        let new_doc = ConfigDoc {
            version: doc.version,
            blob: stripped,
            actor: doc.actor.clone(),
            ts: doc.ts.clone(),
            summary: doc.summary.clone(),
        };
        let new_bytes = serde_json::to_vec(&new_doc)
            .map_err(|e| WafError::State(format!("config doc encode: {e}")))?;
        self.backend
            .cas_set(DOC_KEY, Some(&old_bytes), &new_bytes, None)
            .await
    }

    /// Record (ACK) that this node has applied `version`. TTL'd so a
    /// node that stops polling drops out of the roster.
    pub async fn record_applied(&self, node_id: &str, version: u64) -> Result<()> {
        self.backend
            .put_ttl(
                &applied_key(node_id),
                version.to_string().as_bytes(),
                APPLIED_TTL,
            )
            .await
    }

    /// The version `node_id` last ACKed as applied, or 0 if the node
    /// has no ACK yet (fresh boot / no shared config activated). F7
    /// (2026-06-11): `GET /api/detectors` returns this as the
    /// `config_version` the client echoes in `If-Match` on its next
    /// `PUT /api/detectors`, so the detector CAS guards against the
    /// version the client actually *viewed* (the applied version that
    /// produced the in-process mask) rather than a fresh server read.
    pub async fn applied_version(&self, node_id: &str) -> Result<u64> {
        match self.backend.get(&applied_key(node_id)).await? {
            Some(v) => Ok(std::str::from_utf8(&v)
                .unwrap_or("")
                .trim()
                .parse::<u64>()
                .unwrap_or(0)),
            None => Ok(0),
        }
    }

    /// The applied-version of every live node, for the console drift
    /// view. `(node_id, version)` pairs.
    pub async fn applied_map(&self) -> Result<Vec<(String, u64)>> {
        let keys = self.backend.scan_prefix(APPLIED_PREFIX).await?;
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            if let Some(v) = self.backend.get(&k).await? {
                if let Ok(version) = std::str::from_utf8(&v)
                    .unwrap_or("")
                    .trim()
                    .parse::<u64>()
                {
                    let node = k.strip_prefix(APPLIED_PREFIX).unwrap_or(&k).to_string();
                    out.push((node, version));
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::in_memory::InMemoryBackend;

    fn store() -> ConfigStore {
        ConfigStore::new(Arc::new(InMemoryBackend::new()))
    }

    #[tokio::test]
    async fn fresh_store_has_no_doc_and_version_zero() {
        let s = store();
        assert!(s.load().await.unwrap().is_none());
        assert_eq!(s.current_version().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn first_activate_writes_version_one() {
        let s = store();
        let r = s.activate(0, "blob-a".into(), "alice", "init").await.unwrap();
        assert_eq!(r, Activate::Applied { version: 1 });
        let doc = s.load().await.unwrap().unwrap();
        assert_eq!(doc.version, 1);
        assert_eq!(doc.blob, "blob-a");
        assert_eq!(doc.actor, "alice");
    }

    // H2a — a realistic full-WafConfig blob (has bootstrap + dynamic keys).
    const FULL_YAML: &str = "listeners:\n  data:\n    - bind: \"127.0.0.1:8080\"\n  admin:\n    bind: \"127.0.0.1:9090\"\nstate:\n  backend: in_memory\nroutes:\n  - id: r\n    path: \"/\"\n    upstream: u\nupstreams:\n  u:\n    members:\n      - addr: \"127.0.0.1:3000\"\n";

    #[tokio::test]
    async fn activate_strips_bootstrap_keys_storing_dynamic_only() {
        let s = store();
        s.activate(0, FULL_YAML.into(), "u", "").await.unwrap();
        let doc = s.load().await.unwrap().unwrap();
        assert!(
            !aegis_core::yaml_has_legacy_bootstrap_keys(&doc.blob),
            "the stored doc must hold no bootstrap keys"
        );
        assert!(doc.blob.contains("upstream"), "dynamic content is preserved");
    }

    #[tokio::test]
    async fn canonicalize_migrates_a_pre_h2a_full_doc_in_place_idempotently() {
        let backend = Arc::new(InMemoryBackend::new());
        let s = ConfigStore::new(backend.clone());
        // Simulate a pre-H2a deployment: a FULL doc written directly, bypassing
        // the strip that `activate` now applies.
        let full = ConfigDoc {
            version: 4,
            blob: FULL_YAML.into(),
            actor: "legacy".into(),
            ts: "t".into(),
            summary: "s".into(),
        };
        let bytes = serde_json::to_vec(&full).unwrap();
        backend.cas_set(DOC_KEY, None, &bytes, None).await.unwrap();

        let changed = s.canonicalize_active_doc().await.unwrap();
        assert!(changed, "a legacy doc is migrated");
        let doc = s.load().await.unwrap().unwrap();
        assert_eq!(doc.version, 4, "migration is in place — no version bump");
        assert!(!aegis_core::yaml_has_legacy_bootstrap_keys(&doc.blob), "now dynamic-only");
        assert!(doc.blob.contains("upstream"), "dynamic content survives");
        // Idempotent: a second run is a no-op.
        assert!(!s.canonicalize_active_doc().await.unwrap());
    }

    #[tokio::test]
    async fn canonicalize_is_noop_on_a_fresh_or_dynamic_store() {
        let s = store();
        assert!(!s.canonicalize_active_doc().await.unwrap(), "no doc → no-op");
        s.activate(0, FULL_YAML.into(), "u", "").await.unwrap(); // stored dynamic
        assert!(!s.canonicalize_active_doc().await.unwrap(), "already dynamic → no-op");
    }

    #[tokio::test]
    async fn sequential_activations_bump_version() {
        let s = store();
        s.activate(0, "a".into(), "u", "").await.unwrap();
        let r = s.activate(1, "b".into(), "u", "").await.unwrap();
        assert_eq!(r, Activate::Applied { version: 2 });
        assert_eq!(s.current_version().await.unwrap(), 2);
        assert_eq!(s.load().await.unwrap().unwrap().blob, "b");
    }

    #[tokio::test]
    async fn stale_expected_version_conflicts() {
        let s = store();
        s.activate(0, "a".into(), "u", "").await.unwrap(); // -> v1
        // Editor that still thinks current is v0 tries to write.
        let r = s.activate(0, "stale".into(), "u", "").await.unwrap();
        assert_eq!(r, Activate::Conflict { current: 1 });
        // Active config is unchanged.
        assert_eq!(s.load().await.unwrap().unwrap().blob, "a");
    }

    #[tokio::test]
    async fn rollback_reactivates_old_snapshot_as_new_version() {
        let s = store();
        s.activate(0, "v1-blob".into(), "u", "").await.unwrap(); // v1
        s.activate(1, "v2-blob".into(), "u", "").await.unwrap(); // v2
        // Roll back to v1's content — becomes v3.
        let r = s.rollback(1, "operator").await.unwrap();
        assert_eq!(r, Activate::Applied { version: 3 });
        let doc = s.load().await.unwrap().unwrap();
        assert_eq!(doc.version, 3);
        assert_eq!(doc.blob, "v1-blob", "rollback restores the old content");
    }

    #[tokio::test]
    async fn rollback_to_missing_version_errors() {
        let s = store();
        assert!(s.rollback(99, "u").await.is_err());
    }

    #[tokio::test]
    async fn applied_map_tracks_per_node_versions() {
        let s = store();
        s.record_applied("node-a", 5).await.unwrap();
        s.record_applied("node-b", 4).await.unwrap();
        let mut got = s.applied_map().await.unwrap();
        got.sort();
        assert_eq!(
            got,
            vec![("node-a".to_string(), 5), ("node-b".to_string(), 4)]
        );
    }

    // F7 (2026-06-11) — single-node applied-version read used by
    // `GET /api/detectors` to stamp the `config_version` the client
    // echoes in `If-Match`.
    #[tokio::test]
    async fn applied_version_reads_per_node_ack() {
        let s = store();
        // No ACK yet → 0 (fresh boot / no shared config).
        assert_eq!(s.applied_version("node-a").await.unwrap(), 0);
        s.record_applied("node-a", 7).await.unwrap();
        assert_eq!(s.applied_version("node-a").await.unwrap(), 7);
        // Isolated per node.
        assert_eq!(s.applied_version("node-b").await.unwrap(), 0);
    }

    // N2 (2026-06-11) — config-plane nudge. H2b — the nudge is now the
    // narrow [`ConfigWatch`] seam; the channel detail lives in the adapter,
    // so the recorder just counts `notify_change` calls.

    /// Recording [`ConfigWatch`] — counts every `notify_change` so a test
    /// can assert a nudge fired exactly once per successful activate.
    #[derive(Default)]
    struct RecordingWatch {
        notified: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl ConfigWatch for RecordingWatch {
        async fn notify_change(&self) {
            self.notified
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        fn watch(&self, bound: usize) -> tokio::sync::mpsc::Receiver<Vec<u8>> {
            let (_tx, rx) = tokio::sync::mpsc::channel(bound.max(1));
            rx
        }
    }

    impl RecordingWatch {
        fn count(&self) -> usize {
            self.notified.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    #[tokio::test]
    async fn activate_fires_a_nudge_when_bus_wired() {
        let watch = Arc::new(RecordingWatch::default());
        let s = store().with_nudge(Some(watch.clone()));
        s.activate(0, "a".into(), "u", "").await.unwrap();
        assert_eq!(watch.count(), 1, "exactly one nudge per successful activate");
    }

    #[tokio::test]
    async fn conflict_does_not_nudge() {
        let watch = Arc::new(RecordingWatch::default());
        let s = store().with_nudge(Some(watch.clone()));
        s.activate(0, "a".into(), "u", "").await.unwrap(); // v1, fires once
        // Stale expected version → Conflict, must NOT fire a second nudge.
        let r = s.activate(0, "stale".into(), "u", "").await.unwrap();
        assert_eq!(r, Activate::Conflict { current: 1 });
        assert_eq!(watch.count(), 1);
    }

    #[tokio::test]
    async fn activate_without_nudge_is_fine() {
        // Default store has no bus — activate must still succeed.
        let s = store();
        assert_eq!(
            s.activate(0, "a".into(), "u", "").await.unwrap(),
            Activate::Applied { version: 1 }
        );
    }
}
