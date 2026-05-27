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

use aegis_core::error::{Result, WafError};
use aegis_core::state::StateBackend;

/// The single key holding the active config document (JSON-encoded
/// [`ConfigDoc`]). Activation is a compare-and-set on this key.
pub const DOC_KEY: &str = "config:waf:doc";

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
    /// The full `WafConfig` as YAML.
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

/// Versioned config store over a [`StateBackend`].
#[derive(Clone)]
pub struct ConfigStore {
    backend: Arc<dyn StateBackend>,
}

impl ConfigStore {
    pub fn new(backend: Arc<dyn StateBackend>) -> Self {
        Self { backend }
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

        // Immutable, write-once, persistent snapshot for rollback. A
        // collision here (snapshot already exists for this version) means
        // a racing writer beat us to the same number — harmless, the CAS
        // below decides the winner. Best-effort.
        let _ = self
            .backend
            .cas_set(&snapshot_key(next), None, blob.as_bytes(), None)
            .await;

        // Atomic activation: CAS the active document from the exact bytes
        // we loaded (or absent) to the new document. `None` ttl = persist.
        let expected_bytes = match &current {
            Some(d) => Some(
                serde_json::to_vec(d)
                    .map_err(|e| WafError::State(format!("config doc encode: {e}")))?,
            ),
            None => None,
        };
        let swapped = self
            .backend
            .cas_set(DOC_KEY, expected_bytes.as_deref(), &new_bytes, None)
            .await?;

        if swapped {
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

    /// Record (ACK) that this node has applied `version`. TTL'd so a
    /// node that stops polling drops out of the roster.
    pub async fn record_applied(&self, node_id: &str, version: u64) -> Result<()> {
        self.backend
            .set(
                &applied_key(node_id),
                version.to_string().as_bytes(),
                APPLIED_TTL,
            )
            .await
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
}
