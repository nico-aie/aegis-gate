//! Witness record — schema only.
//!
//! 2026-05-17 F-CRITICAL-006 (control audit): pre-fix this module
//! also shipped `sign_chain_head` and `verify_witness` HMAC functions
//! whose key argument had no production source (no boot path
//! generates or loads the cluster-witness HMAC key). The functions
//! had zero production callers — they were the on-disk record of an
//! unfinished feature.
//!
//! The struct itself IS load-bearing: `api::audit::WitnessState`
//! holds `Option<WitnessRecord>` so the `/api/audit/witness_lag`
//! endpoint can render a stable empty shape, and that endpoint is
//! reachable from the dashboard. Keeping the struct preserves the
//! HTTP wire format; the dead signing/verifying functions are
//! removed.
//!
//! When a real cluster-witness service lands, it would populate
//! these fields via `WitnessState::update`. The signing primitive
//! (HMAC over `{head_hash, node_id, entry_count}` with a key the
//! operator supplies via `cfg.cluster.witness_key_ref`) is sketched
//! at `plans/future/unwired-stubs-catalog.md` for whoever picks it
//! up.

use serde::{Deserialize, Serialize};

/// Witness record. Field shape mirrors what the deleted
/// `sign_chain_head` produced so a future re-introduction can
/// round-trip with the existing dashboard JSON parser.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessRecord {
    pub ts: chrono::DateTime<chrono::Utc>,
    pub chain_head_hash: String,
    pub signature: String,
    pub node_id: String,
    pub entry_count: u64,
}
