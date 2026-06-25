//! C-1 (multi-node consistency) — cluster-native propagation of the
//! interop control plane.
//!
//! `POST /__waf_control/set_profile` and `/__waf_control/reset_state`
//! historically changed only the node that received the request: the
//! `ModeStore` is an in-process `ArcSwap`, and while `reset_state`
//! wipes the shared `StateBackend` fleet-wide, the *local* trackers on
//! the other N-1 nodes stayed warm. Behind a load balancer that breaks
//! the determinism contract (§2.4/§2.5).
//!
//! This module converges both through the durable [`ConfigBackend`] seam
//! (H2b — the same store the config doc rides: Redis under `shared_state`,
//! etcd under `config_plane.store: etcd`), with no new transport:
//!
//! - **Modes** ride a single versioned doc at [`MODES_KEY`]: a
//!   generation counter embedded in the JSON, written with `cas_set`
//!   (persistent — no TTL). A node that changes modes publishes the
//!   new snapshot; every node polls the key and applies the snapshot
//!   to its local `ModeStore` when the generation advances.
//! - **`reset_state`** bumps the [`RESET_EPOCH_KEY`] counter via a
//!   **CAS-counter** (read decimal → `cas_set` to +1, retry on conflict —
//!   so it works on the narrow seam without a backend `incrby`). Each node
//!   polls it and runs its *local* reset chain when the epoch advances — the
//!   shared-backend wipe already fanned out fleet-wide, so peers only need to
//!   flush in-process trackers.
//!
//! Best-effort by design: a backend hiccup logs and is swallowed so a
//! control call never turns into a 500. Single-node / in-memory
//! deployments don't wire this at all (see `aegis-proxy::run`), so the
//! local-only path is unchanged there.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use aegis_core::config_backend::ConfigBackend;

use super::headers::Mode;
use super::mode::ModeSnapshot;

/// Common key prefix for the durable control plane (modes / reset_epoch /
/// access-lists). H2b — the etcd config-plane watch subscribes to this prefix
/// so any control-plane key changing wakes the poller natively.
pub const CONTROL_KEY_PREFIX: &str = "control:waf:";

/// Persistent doc holding the fleet-wide interop mode map + its
/// monotonic generation.
pub const MODES_KEY: &str = "control:waf:modes";
/// Monotonic counter bumped once per cluster-scoped `reset_state`.
pub const RESET_EPOCH_KEY: &str = "control:waf:reset_epoch";
/// Phase 5 (§3) — pub/sub channel for the optional state *nudge*. A
/// 1-byte message published here on any config/control mutation tells
/// subscribing pollers to re-poll `MODES_KEY` / `RESET_EPOCH_KEY`
/// immediately. Loss-tolerant: polling is the backstop.
pub const CONTROL_BUMP_CHANNEL: &str = "control:waf:bump";

/// Wire form of [`ModeSnapshot`] + a generation. `Mode` has no serde
/// derive, so modes are carried as their `"enforce"` / `"log_only"`
/// strings (the same repr the contract uses) and the tuple-keyed
/// `policy_overrides` map is flattened to a `(feature, policy, mode)`
/// list — JSON has no tuple-key maps.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterModeDoc {
    /// Monotonic — readers apply a doc only when this exceeds the
    /// generation they last applied, so re-reads are idempotent.
    pub generation: u64,
    pub default: String,
    /// `(feature, mode)`.
    pub feature_overrides: Vec<(String, String)>,
    /// `(feature, policy, mode)`.
    pub policy_overrides: Vec<(String, String, String)>,
}

fn mode_str(m: Mode) -> String {
    m.as_str().to_string()
}

fn parse_mode(s: &str) -> Mode {
    // Anything that isn't an explicit `log_only` is `enforce` — the
    // fail-safe default (a malformed shared doc must never silently
    // drop enforcement).
    match s {
        "log_only" => Mode::LogOnly,
        _ => Mode::Enforce,
    }
}

impl ClusterModeDoc {
    /// Project a live snapshot into the wire form at `generation`.
    pub fn from_snapshot(snap: &ModeSnapshot, generation: u64) -> Self {
        let mut feature_overrides: Vec<(String, String)> = snap
            .feature_overrides
            .iter()
            .map(|(f, m)| (f.clone(), mode_str(*m)))
            .collect();
        feature_overrides.sort();
        let mut policy_overrides: Vec<(String, String, String)> = snap
            .policy_overrides
            .iter()
            .map(|((f, p), m)| (f.clone(), p.clone(), mode_str(*m)))
            .collect();
        policy_overrides.sort();
        Self {
            generation,
            default: mode_str(snap.default),
            feature_overrides,
            policy_overrides,
        }
    }

    /// Rebuild a [`ModeSnapshot`] from the wire form.
    pub fn to_snapshot(&self) -> ModeSnapshot {
        let mut snap = ModeSnapshot::empty(parse_mode(&self.default));
        for (f, m) in &self.feature_overrides {
            snap.feature_overrides.insert(f.clone(), parse_mode(m));
        }
        for (f, p, m) in &self.policy_overrides {
            snap.policy_overrides
                .insert((f.clone(), p.clone()), parse_mode(m));
        }
        snap
    }
}

/// Read the current published modes doc, if any. `None` when the key
/// is absent or unreadable/corrupt (the caller keeps its local view).
pub async fn read_modes(state: &Arc<dyn ConfigBackend>) -> Option<ClusterModeDoc> {
    match state.get(MODES_KEY).await {
        Ok(Some(bytes)) => match serde_json::from_slice::<ClusterModeDoc>(&bytes) {
            Ok(doc) => Some(doc),
            Err(e) => {
                tracing::warn!(error = %e, "cluster modes doc unparseable — ignoring");
                None
            }
        },
        Ok(None) => None,
        Err(e) => {
            tracing::debug!(error = %e, "cluster modes read failed");
            None
        }
    }
}

/// Publish `snap` as the next generation. Reads the current doc to
/// compute `generation + 1` and `cas_set`s it (one retry on a
/// concurrent-writer conflict). Best-effort: returns the published
/// generation on success, `None` on any backend error.
pub async fn publish_modes(state: &Arc<dyn ConfigBackend>, snap: &ModeSnapshot) -> Option<u64> {
    for _ in 0..2 {
        let current = state.get(MODES_KEY).await.ok().flatten();
        let cur_gen = current
            .as_deref()
            .and_then(|b| serde_json::from_slice::<ClusterModeDoc>(b).ok())
            .map(|d| d.generation)
            .unwrap_or(0);
        let doc = ClusterModeDoc::from_snapshot(snap, cur_gen + 1);
        let bytes = match serde_json::to_vec(&doc) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "cluster modes serialize failed");
                return None;
            }
        };
        match state
            .cas_set(MODES_KEY, current.as_deref(), &bytes, None)
            .await
        {
            Ok(true) => return Some(doc.generation),
            Ok(false) => continue, // lost the race — re-read and retry
            Err(e) => {
                tracing::debug!(error = %e, "cluster modes publish failed");
                return None;
            }
        }
    }
    None
}

/// Bump the cluster reset epoch. Returns the new epoch, or `None` on a
/// backend error. Peers run their local reset chain when they observe
/// the increase.
///
/// H2b — implemented as a **CAS-counter** on the narrow [`ConfigBackend`]
/// seam (read decimal → `cas_set` to +1, retry on conflict) rather than a
/// backend `incrby`, so the control plane needs no counter primitive and can
/// live in etcd as well as Redis. The epoch only needs to be *monotonic*
/// (peers act on any advance), and a CAS retry still advances on every reset,
/// so the semantics match the old `INCR`. The on-disk form is the same
/// decimal string `INCR` produced, so an existing Redis epoch is read/written
/// unchanged across the upgrade.
pub async fn publish_reset_epoch(state: &Arc<dyn ConfigBackend>) -> Option<u64> {
    for _ in 0..5 {
        let current = state.get(RESET_EPOCH_KEY).await.ok().flatten();
        let cur = decode_epoch(current.as_deref());
        let next = cur + 1;
        let bytes = next.to_string().into_bytes();
        match state
            .cas_set(RESET_EPOCH_KEY, current.as_deref(), &bytes, None)
            .await
        {
            Ok(true) => return Some(next),
            Ok(false) => continue, // lost the race — re-read and retry
            Err(e) => {
                tracing::debug!(error = %e, "cluster reset-epoch publish failed");
                return None;
            }
        }
    }
    None
}

/// Read the current reset epoch (absent/unparseable → 0).
pub async fn read_reset_epoch(state: &Arc<dyn ConfigBackend>) -> u64 {
    decode_epoch(state.get(RESET_EPOCH_KEY).await.ok().flatten().as_deref())
}

/// Decode the reset-epoch value: a decimal-string `u64` (the form both the
/// CAS-counter and the legacy Redis `INCR` write). Absent / non-UTF-8 /
/// unparseable ⇒ 0.
fn decode_epoch(bytes: Option<&[u8]>) -> u64 {
    bytes
        .and_then(|b| std::str::from_utf8(b).ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Access lists — HIGH-2 (operator blacklist/whitelist convergence)
// ---------------------------------------------------------------------------
//
// Before this, `POST /api/blacklist` mutated only the receiving node's
// in-process `AccessListStore`; behind the LB an IP blocked on one node
// was still served by the other N-1 (~1/3 enforcement). These functions
// converge each list through the same shared `StateBackend` as the modes
// doc: one persistent, generation-stamped doc per list label. Mutations
// read-modify-CAS the latest doc (delta on the published set, not a whole
// local snapshot) so concurrent add/remove on different nodes merge by
// entry id rather than clobbering each other. Pollers replace their local
// store when the generation advances.

use crate::api::blacklist::AccessListEntry;

/// Key prefix for the per-list converged doc; the list label
/// (`blacklist` / `whitelist`) is appended.
pub const ACCESS_LIST_KEY_PREFIX: &str = "control:waf:access_list:";

/// Build the shared-backend key for one access-list label.
pub fn access_list_key(label: &str) -> String {
    format!("{ACCESS_LIST_KEY_PREFIX}{label}")
}

/// Persistent doc holding the full converged entry set for one list +
/// its monotonic generation. Readers apply a doc only when `generation`
/// exceeds the one they last applied, so re-reads are idempotent.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ClusterAccessListDoc {
    pub generation: u64,
    pub entries: Vec<AccessListEntry>,
}

/// Read the published doc for `label`, or `None` when the key is absent
/// or unparseable (the caller keeps its local view).
pub async fn read_access_list(
    state: &Arc<dyn ConfigBackend>,
    label: &str,
) -> Option<ClusterAccessListDoc> {
    let key = access_list_key(label);
    match state.get(&key).await {
        Ok(Some(bytes)) => match serde_json::from_slice::<ClusterAccessListDoc>(&bytes) {
            Ok(doc) => Some(doc),
            Err(e) => {
                tracing::warn!(error = %e, label, "cluster access-list doc unparseable — ignoring");
                None
            }
        },
        Ok(None) => None,
        Err(e) => {
            tracing::debug!(error = %e, label, "cluster access-list read failed");
            None
        }
    }
}

/// Apply `mutate` to the latest published entry set and `cas_set` the
/// next generation. Read-modify-the-latest-doc (rather than publishing a
/// whole local snapshot) means concurrent add/remove on different nodes
/// merge by entry id instead of clobbering each other. Best-effort:
/// returns the new generation, or `None` on a backend error / lost race
/// after retries.
async fn publish_access_list_mutation<F>(
    state: &Arc<dyn ConfigBackend>,
    label: &str,
    mutate: F,
) -> Option<u64>
where
    F: Fn(&mut Vec<AccessListEntry>),
{
    let key = access_list_key(label);
    for _ in 0..4 {
        let current = state.get(&key).await.ok().flatten();
        let (cur_gen, mut entries) = current
            .as_deref()
            .and_then(|b| serde_json::from_slice::<ClusterAccessListDoc>(b).ok())
            .map(|d| (d.generation, d.entries))
            .unwrap_or((0, Vec::new()));
        mutate(&mut entries);
        let doc = ClusterAccessListDoc {
            generation: cur_gen + 1,
            entries,
        };
        let bytes = match serde_json::to_vec(&doc) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, label, "cluster access-list serialize failed");
                return None;
            }
        };
        match state.cas_set(&key, current.as_deref(), &bytes, None).await {
            Ok(true) => return Some(doc.generation),
            Ok(false) => continue, // lost the race — re-read and retry
            Err(e) => {
                tracing::debug!(error = %e, label, "cluster access-list publish failed");
                return None;
            }
        }
    }
    None
}

/// Publish an upsert of `entry` (insert, or replace the entry with the
/// same id) into the converged list.
pub async fn publish_access_list_upsert(
    state: &Arc<dyn ConfigBackend>,
    label: &str,
    entry: &AccessListEntry,
) -> Option<u64> {
    publish_access_list_mutation(state, label, |entries| {
        if let Some(slot) = entries.iter_mut().find(|e| e.id == entry.id) {
            *slot = entry.clone();
        } else {
            entries.push(entry.clone());
        }
    })
    .await
}

/// Publish a removal of the entry with `id` from the converged list.
pub async fn publish_access_list_remove(
    state: &Arc<dyn ConfigBackend>,
    label: &str,
    id: &str,
) -> Option<u64> {
    publish_access_list_mutation(state, label, |entries| {
        entries.retain(|e| e.id != id);
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doc_round_trips_through_snapshot() {
        let mut snap = ModeSnapshot::empty(Mode::LogOnly);
        snap.feature_overrides.insert("sqli".into(), Mode::Enforce);
        snap.policy_overrides
            .insert(("xss".into(), "reflected".into()), Mode::LogOnly);

        let doc = ClusterModeDoc::from_snapshot(&snap, 7);
        assert_eq!(doc.generation, 7);
        assert_eq!(doc.default, "log_only");

        let back = doc.to_snapshot();
        assert_eq!(back.default, Mode::LogOnly);
        assert_eq!(back.feature_overrides.get("sqli"), Some(&Mode::Enforce));
        assert_eq!(
            back.policy_overrides
                .get(&("xss".to_string(), "reflected".to_string())),
            Some(&Mode::LogOnly)
        );
    }

    #[test]
    fn doc_serializes_to_json() {
        let snap = ModeSnapshot::empty(Mode::Enforce);
        let doc = ClusterModeDoc::from_snapshot(&snap, 1);
        let json = serde_json::to_vec(&doc).unwrap();
        let back: ClusterModeDoc = serde_json::from_slice(&json).unwrap();
        assert_eq!(doc, back);
    }

    #[test]
    fn unknown_mode_string_fails_safe_to_enforce() {
        let doc = ClusterModeDoc {
            generation: 1,
            default: "garbage".into(),
            feature_overrides: vec![("f".into(), "also-garbage".into())],
            policy_overrides: vec![],
        };
        let snap = doc.to_snapshot();
        assert_eq!(snap.default, Mode::Enforce);
        assert_eq!(snap.feature_overrides.get("f"), Some(&Mode::Enforce));
    }
}
