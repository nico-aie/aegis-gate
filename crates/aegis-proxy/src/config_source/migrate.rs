//! CONFIG-PLANE migration (H2b P3, 2026-06-25) — one-shot copy of the live
//! config + control plane from one [`ConfigBackend`] to another.
//!
//! The cutover step from `plans/future/config-etcd-source-of-truth.md` P3:
//! copy the active config doc, every immutable version snapshot, and the
//! durable control-plane keys from the current store (shared_state / Redis)
//! into a fresh etcd cluster, then verify the active version round-trips.
//! The operator runs this once while still on `shared_state`, confirms the
//! report, then flips `config_plane.store: etcd`.
//!
//! The whole operation is expressed on the narrow [`ConfigBackend`] seam
//! (`get` / `scan_prefix` / `cas_set`), so it is backend-agnostic — Redis →
//! etcd is just one instantiation, and the logic is unit-testable with two
//! in-memory backends. The CLI wiring (Redis source + etcd dest) lives in
//! `aegis-bin` behind the `etcd_config` feature.
//!
//! ## What is and isn't copied
//!
//! Copied (durable, low-write consensus data — string-valued):
//! - `config:waf:doc` — the active versioned doc.
//! - `config:waf:v:*` — every immutable rollback snapshot.
//! - `control:waf:modes`, `control:waf:reset_epoch` — fleet mode map + the
//!   reset epoch.
//! - `control:waf:access_list:*` — operator block/allow lists.
//!
//! Deliberately NOT copied:
//! - `config:waf:applied:*` — ephemeral per-node ACKs (lease/TTL'd; each node
//!   re-stamps within seconds of boot).
//! - `control:waf:incidents` / `:risk` / `:stats:counters` — the
//!   redis-interim-durability HASH keys (a different keyspace + Redis HASH
//!   type; they stay on Redis, see `aegis_core::state`).
//! - pub/sub bump channels (`config:waf:bump`, `control:waf:bump`) — not keys.

use std::sync::Arc;

use aegis_core::config_backend::ConfigBackend;
use aegis_core::error::{Result, WafError};

use super::config_store::{ConfigDoc, DOC_KEY};

/// Snapshot-key prefix (`config:waf:v:{n}`); mirrors
/// [`super::config_store::snapshot_key`].
const SNAPSHOT_PREFIX: &str = "config:waf:v:";

/// Outcome of a migration run — surfaced to the operator so the cutover is a
/// verified step, not a blind copy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MigrationReport {
    /// The active config version found in the source doc (`None` ⇒ source had
    /// no doc — a fresh/never-activated config plane; nothing to migrate).
    pub source_version: Option<u64>,
    /// Whether the active `config:waf:doc` was copied.
    pub doc_copied: bool,
    /// Number of `config:waf:v:*` snapshots copied.
    pub snapshots_copied: usize,
    /// Number of `control:waf:*` keys copied (modes / reset_epoch /
    /// access-lists).
    pub control_keys_copied: usize,
    /// `true` when the destination `config:waf:doc` reads back at exactly
    /// `source_version` after the copy. The go/no-go signal for the cutover.
    pub verified: bool,
}

/// The explicit set of exact control-plane keys to migrate. Prefix-scanned
/// keys (snapshots, access-lists) are handled separately. Kept as a function
/// (not a const array) so the aegis-control key constants stay the single
/// source of truth.
fn control_exact_keys() -> [&'static str; 2] {
    [
        aegis_control::interop::cluster_sync::MODES_KEY,
        aegis_control::interop::cluster_sync::RESET_EPOCH_KEY,
    ]
}

/// Copy `key` from `source` to `dest` if present, overwriting any existing
/// destination value (idempotent re-runs). Returns `true` if a value was
/// copied, `false` if the source had no such key.
async fn copy_key(
    source: &Arc<dyn ConfigBackend>,
    dest: &Arc<dyn ConfigBackend>,
    key: &str,
) -> Result<bool> {
    let Some(value) = source.get(key).await? else {
        return Ok(false);
    };
    // Overwrite idempotently: CAS against the destination's current value so a
    // re-run replaces rather than fails on an existing key. One retry covers a
    // benign race; migration is a one-shot offline step so contention is nil.
    for _ in 0..2 {
        let current = dest.get(key).await?;
        if dest
            .cas_set(key, current.as_deref(), &value, None)
            .await?
        {
            return Ok(true);
        }
    }
    Err(WafError::State(format!(
        "migration: destination key {key} kept losing CAS (concurrent writer?)"
    )))
}

/// Copy every key under `prefix` from `source` to `dest`. Returns the count
/// copied.
async fn copy_prefix(
    source: &Arc<dyn ConfigBackend>,
    dest: &Arc<dyn ConfigBackend>,
    prefix: &str,
) -> Result<usize> {
    let keys = source.scan_prefix(prefix).await?;
    let mut copied = 0;
    for key in keys {
        if copy_key(source, dest, &key).await? {
            copied += 1;
        }
    }
    Ok(copied)
}

/// Migrate the durable config + control plane from `source` to `dest` and
/// verify the active version round-trips. See the module docs for exactly
/// which keys are (and are not) copied.
///
/// Idempotent: a second run overwrites the destination with the same data and
/// re-verifies. A source with no active doc returns an un-verified report with
/// `source_version: None` (nothing to migrate) rather than an error.
pub async fn migrate_config_plane(
    source: &Arc<dyn ConfigBackend>,
    dest: &Arc<dyn ConfigBackend>,
) -> Result<MigrationReport> {
    let mut report = MigrationReport::default();

    // 1. Active doc — also gives us the version we verify against.
    let source_doc = source.get(DOC_KEY).await?;
    let source_version = match &source_doc {
        Some(bytes) => {
            let doc: ConfigDoc = serde_json::from_slice(bytes)
                .map_err(|e| WafError::State(format!("migration: source doc decode: {e}")))?;
            Some(doc.version)
        }
        None => None,
    };
    report.source_version = source_version;
    report.doc_copied = copy_key(source, dest, DOC_KEY).await?;

    // 2. Immutable version snapshots.
    report.snapshots_copied = copy_prefix(source, dest, SNAPSHOT_PREFIX).await?;

    // 3. Control plane — exact keys + the access-list prefix.
    for key in control_exact_keys() {
        if copy_key(source, dest, key).await? {
            report.control_keys_copied += 1;
        }
    }
    report.control_keys_copied += copy_prefix(
        source,
        dest,
        aegis_control::interop::cluster_sync::ACCESS_LIST_KEY_PREFIX,
    )
    .await?;

    // 4. Verify: the destination doc must read back at the source version.
    report.verified = match source_version {
        Some(v) => {
            let dest_doc = dest.get(DOC_KEY).await?;
            match dest_doc {
                Some(bytes) => {
                    let doc: ConfigDoc = serde_json::from_slice(&bytes).map_err(|e| {
                        WafError::State(format!("migration: dest doc decode: {e}"))
                    })?;
                    doc.version == v
                }
                None => false,
            }
        }
        // Nothing to migrate ⇒ trivially "nothing to verify"; report stays
        // unverified so the operator sees an empty source explicitly.
        None => false,
    };

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_source::config_store::{snapshot_key, ConfigStore};
    use crate::state::in_memory::InMemoryBackend;
    use aegis_core::config_backend::SharedStateConfigBackend;
    use aegis_core::state::StateBackend;

    fn backend() -> Arc<dyn ConfigBackend> {
        SharedStateConfigBackend::arc(Arc::new(InMemoryBackend::new()))
    }

    /// Seed a source backend with an active doc (via ConfigStore so the JSON
    /// shape matches production) + a couple of control keys, then migrate.
    #[tokio::test]
    async fn migrates_doc_snapshots_and_control_keys_then_verifies() {
        let src_state: Arc<dyn StateBackend> = Arc::new(InMemoryBackend::new());
        let source: Arc<dyn ConfigBackend> = SharedStateConfigBackend::arc(src_state.clone());

        // Two activations → doc at v2 + snapshots v1, v2.
        let store = ConfigStore::new(src_state.clone());
        store.activate(0, "a: 1".into(), "op", "v1").await.unwrap();
        store.activate(1, "b: 2".into(), "op", "v2").await.unwrap();
        // Control-plane keys (raw string values, as cluster_sync writes them).
        source
            .cas_set(
                aegis_control::interop::cluster_sync::MODES_KEY,
                None,
                br#"{"generation":3,"default":"enforce","feature_overrides":[],"policy_overrides":[]}"#,
                None,
            )
            .await
            .unwrap();
        source
            .cas_set(
                aegis_control::interop::cluster_sync::RESET_EPOCH_KEY,
                None,
                b"5",
                None,
            )
            .await
            .unwrap();
        source
            .cas_set(
                &format!(
                    "{}blacklist",
                    aegis_control::interop::cluster_sync::ACCESS_LIST_KEY_PREFIX
                ),
                None,
                br#"{"generation":1,"entries":[]}"#,
                None,
            )
            .await
            .unwrap();

        let dest = backend();
        let report = migrate_config_plane(&source, &dest).await.unwrap();

        assert_eq!(report.source_version, Some(2));
        assert!(report.doc_copied);
        assert_eq!(report.snapshots_copied, 2, "v1 + v2 snapshots");
        assert_eq!(
            report.control_keys_copied, 3,
            "modes + reset_epoch + one access list",
        );
        assert!(report.verified, "dest doc reads back at the source version");

        // Spot-check the destination round-trips the real content.
        let dest_store = ConfigStore::with_config_backend(dest.clone());
        assert_eq!(dest_store.current_version().await.unwrap(), 2);
        assert_eq!(dest_store.load().await.unwrap().unwrap().blob, "b: 2");
        assert_eq!(
            dest.get(&snapshot_key(1)).await.unwrap().unwrap(),
            b"a: 1",
            "v1 snapshot content migrated",
        );
        assert_eq!(
            dest.get(aegis_control::interop::cluster_sync::RESET_EPOCH_KEY)
                .await
                .unwrap()
                .unwrap(),
            b"5",
        );
    }

    #[tokio::test]
    async fn is_idempotent_across_reruns() {
        let src_state: Arc<dyn StateBackend> = Arc::new(InMemoryBackend::new());
        let source: Arc<dyn ConfigBackend> = SharedStateConfigBackend::arc(src_state.clone());
        ConfigStore::new(src_state.clone())
            .activate(0, "x: 1".into(), "op", "v1")
            .await
            .unwrap();

        let dest = backend();
        let r1 = migrate_config_plane(&source, &dest).await.unwrap();
        let r2 = migrate_config_plane(&source, &dest).await.unwrap();
        assert_eq!(r1, r2, "a re-run produces an identical, verified report");
        assert!(r2.verified);
    }

    #[tokio::test]
    async fn empty_source_reports_nothing_to_migrate() {
        let source = backend();
        let dest = backend();
        let report = migrate_config_plane(&source, &dest).await.unwrap();
        assert_eq!(report.source_version, None);
        assert!(!report.doc_copied);
        assert_eq!(report.snapshots_copied, 0);
        assert_eq!(report.control_keys_copied, 0);
        assert!(!report.verified, "empty source is surfaced as un-verified");
    }
}
