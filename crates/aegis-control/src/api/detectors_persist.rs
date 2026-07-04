//! DURABLE-T2 — file-backed persistence for the live detector mask.
//!
//! ## Why this exists
//!
//! `SharedDetectorMask` lives in an `ArcSwap<MaskState>` — fast hot
//! path, but **in-memory only**. A proxy restart resets every
//! operator toggle to the cfg-derived default, silently re-enabling
//! detector classes the operator had disabled. The storage audit
//! flagged this as the next durability gap to close after the audit
//! chain (DURABLE-T1).
//!
//! ## Design
//!
//! - **Snapshot file** — JSON document with the full base mask + the
//!   four optional per-tier overrides (P3 surface). One file,
//!   overwritten in place. No TTL needed (single state, not history).
//! - **Atomic write** — write to `<path>.tmp`, fsync, rename.
//!   POSIX `rename()` is atomic, so a crash mid-write leaves the
//!   previous snapshot intact.
//! - **Boot rehydrate** — if the file exists and parses, apply it
//!   to the live mask AFTER the cfg-derived initial state is
//!   constructed. Compliance clamps re-run: any class disabled by
//!   the snapshot but locked-on by compliance is forced back on
//!   (warn-logged). Operators who change compliance modes between
//!   restarts can't accidentally keep a non-compliant disable.
//! - **PUT-side write** — the audit-mutated detectors handler calls
//!   `save_snapshot` after the in-memory swap succeeds. Best-effort:
//!   if the disk write fails (full disk, EACCES), the change still
//!   takes effect in-memory and a warn is logged. Next successful
//!   PUT will retry persistence.
//! - **Hot-path safety** — writes happen once per PUT (audit-rate,
//!   not data-plane-rate). Reads happen once at boot. Neither
//!   touches the per-request hot path.


use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use aegis_core::config::ComplianceMode;
use aegis_security::detectors::{
    DetectorMask, DetectorMaskBody, MaskState, SharedDetectorMask, ALL_TIERS,
};
use aegis_core::tier::Tier;

use crate::api::detectors::enforce_compliance_clamp;

/// Schema version of the snapshot file. Bump when the on-disk
/// shape changes incompatibly so older binaries reject newer files
/// rather than silently misinterpret them.
pub const SNAPSHOT_SCHEMA_VERSION: u32 = 1;

/// On-disk shape. Forwards-compatible: unknown fields under the
/// schema_version are tolerated but not preserved.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetectorMaskSnapshot {
    pub schema_version: u32,
    /// ISO-8601 UTC timestamp of when the snapshot was written.
    /// Operator-visible; not consumed by the loader.
    pub saved_at: chrono::DateTime<chrono::Utc>,
    pub base: DetectorMaskBody,
    pub overrides: TierOverrides,
}

/// Per-tier override slot. `None` per tier means "fall through to
/// base". Field names match `tier_str()` so the JSON shape lines up
/// with `/api/detectors` GET.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TierOverrides {
    #[serde(default)]
    pub critical: Option<DetectorMaskBody>,
    #[serde(default)]
    pub high: Option<DetectorMaskBody>,
    #[serde(default)]
    pub medium: Option<DetectorMaskBody>,
    #[serde(default)]
    pub catch_all: Option<DetectorMaskBody>,
}

impl TierOverrides {
    fn for_tier(&self, tier: Tier) -> Option<DetectorMaskBody> {
        match tier {
            Tier::Critical => self.critical.clone(),
            Tier::High => self.high.clone(),
            Tier::Medium => self.medium.clone(),
            Tier::Low => self.catch_all.clone(),
        }
    }

    fn set_tier(&mut self, tier: Tier, body: Option<DetectorMaskBody>) {
        match tier {
            Tier::Critical => self.critical = body,
            Tier::High => self.high = body,
            Tier::Medium => self.medium = body,
            Tier::Low => self.catch_all = body,
        }
    }
}

impl DetectorMaskSnapshot {
    /// Build a snapshot from the current shared mask state.
    pub fn from_state(state: &MaskState) -> Self {
        let mut overrides = TierOverrides::default();
        for tier in ALL_TIERS {
            if let Some(m) = state.override_for(tier) {
                overrides.set_tier(tier, Some(m.into()));
            }
        }
        Self {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            saved_at: chrono::Utc::now(),
            base: state.base.into(),
            overrides,
        }
    }

    /// Convert the snapshot to a `MaskState` ready for
    /// `SharedDetectorMask::store_state`.
    pub fn into_state(self) -> MaskState {
        let mut state = MaskState::new(DetectorMask::from(self.base));
        for tier in ALL_TIERS {
            if let Some(body) = self.overrides.for_tier(tier) {
                state = state.with_override(tier, Some(DetectorMask::from(body)));
            }
        }
        state
    }
}

// ---------------------------------------------------------------------------
// Atomic save
// ---------------------------------------------------------------------------

/// Write `snapshot` to `path` atomically. Steps:
/// 1. ensure parent directory exists
/// 2. write JSON to `<path>.tmp`
/// 3. fsync the temp file
/// 4. rename `<path>.tmp` → `<path>` (POSIX-atomic)
///
/// On error the previous file (if any) is untouched.
pub async fn save_snapshot(
    path: &Path,
    snapshot: &DetectorMaskSnapshot,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }
    let body = serde_json::to_vec_pretty(snapshot)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let tmp = tmp_path_for(path);
    {
        let f = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)
            .await?;
        let mut writer = tokio::io::BufWriter::new(f);
        use tokio::io::AsyncWriteExt;
        writer.write_all(&body).await?;
        writer.flush().await?;
        // Sync inner file to disk before rename.
        writer.into_inner().sync_all().await?;
    }
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

/// Sibling temp-file path. `audit-mask.json` → `audit-mask.json.tmp`.
fn tmp_path_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

// ---------------------------------------------------------------------------
// Load
// ---------------------------------------------------------------------------

/// Why a snapshot couldn't be loaded. Distinct so the caller can
/// log the right level: `NotFound` is normal on first boot;
/// `Parse` and `SchemaMismatch` deserve a warn.
#[derive(Debug)]
pub enum LoadError {
    NotFound,
    Io(std::io::Error),
    Parse(serde_json::Error),
    SchemaMismatch { found: u32, expected: u32 },
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("snapshot file not found"),
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::Parse(e) => write!(f, "parse error: {e}"),
            Self::SchemaMismatch { found, expected } => {
                write!(f, "snapshot schema_version={found} but binary expects {expected}")
            }
        }
    }
}

impl std::error::Error for LoadError {}

/// Read and parse a snapshot. `Ok(None)` is reserved for callers
/// that want a "missing is fine" path; this function returns
/// `Err(LoadError::NotFound)` so the caller can decide.
pub async fn load_snapshot(path: &Path) -> Result<DetectorMaskSnapshot, LoadError> {
    let body = match tokio::fs::read(path).await {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(LoadError::NotFound),
        Err(e) => return Err(LoadError::Io(e)),
    };
    let snap: DetectorMaskSnapshot =
        serde_json::from_slice(&body).map_err(LoadError::Parse)?;
    if snap.schema_version != SNAPSHOT_SCHEMA_VERSION {
        return Err(LoadError::SchemaMismatch {
            found: snap.schema_version,
            expected: SNAPSHOT_SCHEMA_VERSION,
        });
    }
    Ok(snap)
}

// ---------------------------------------------------------------------------
// Boot-time rehydrate + compliance re-check
// ---------------------------------------------------------------------------

/// Outcome of [`apply_snapshot_with_compliance`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// Snapshot applied verbatim — no compliance violations.
    Applied,
    /// Snapshot applied but compliance forced some classes back on.
    /// `forced` lists the class names that were re-enabled (pre-clamp
    /// view of classes that the snapshot tried to disable).
    AppliedWithCompliance { forced: Vec<String> },
}

/// Apply a loaded snapshot to a live `SharedDetectorMask`, running
/// the compliance clamp on both the base mask AND every per-tier
/// override.
///
/// If the snapshot disables a class that the configured compliance
/// modes require ON (PCI / HIPAA / SOC2 / GDPR / FIPS), the clamp
/// flips that class back on in the affected mask and the forced
/// class names are returned via `AppliedWithCompliance { forced }`
/// so the caller can warn-log. `forced` carries entries of the form
/// `"sqli"` (base violation) or `"override[medium]:sqli"` (per-tier
/// violation) so operators can pinpoint the source. The snapshot
/// file is left unchanged — next save will overwrite it with the
/// clamped state.
pub fn apply_snapshot_with_compliance(
    snapshot: DetectorMaskSnapshot,
    mask: &SharedDetectorMask,
    modes: &[ComplianceMode],
) -> ApplyOutcome {
    use aegis_security::detectors::tier_str;

    let proposed = snapshot.into_state();
    let mut forced: Vec<String> = Vec::new();

    let clamped_base = clamp_mask_force_on(proposed.base, modes, &mut forced, "base");
    let mut clamped_overrides: [Option<DetectorMask>; 4] = [None; 4];
    for tier in ALL_TIERS {
        if let Some(m) = proposed.override_for(tier) {
            let scope = format!("override[{}]", tier_str(tier));
            let cm = clamp_mask_force_on(m, modes, &mut forced, &scope);
            let idx = aegis_security::detectors::tier_index(tier);
            clamped_overrides[idx] = Some(cm);
        }
    }

    let clamped = MaskState {
        base: clamped_base,
        overrides: clamped_overrides,
    };
    mask.store_state(clamped);

    if forced.is_empty() {
        ApplyOutcome::Applied
    } else {
        ApplyOutcome::AppliedWithCompliance { forced }
    }
}

/// Run the compliance clamp against the live state inside `mask`
/// and store the clamped result back if anything was forced. Used
/// on (a) boot when no persistence snapshot exists — without this
/// pass the cfg-derived initial mask would skip the clamp entirely
/// and a `cfg.detectors.sqli.enabled: false` would silently bypass
/// PCI / HIPAA / SOC2 / GDPR — and (b) hot-reload of waf.yaml,
/// where `cfg.detectors` may have flipped a compliance-locked
/// class off (the supervisor re-derives the cfg-initial mask and
/// passes it through here). Same `forced` shape as
/// [`apply_snapshot_with_compliance`] (`"sqli"` for base,
/// `"override[medium]:sqli"` for per-tier) so log messages stay
/// uniform across rehydrate / hot-reload / boot.
pub fn apply_live_mask_with_compliance(
    mask: &SharedDetectorMask,
    modes: &[ComplianceMode],
) -> ApplyOutcome {
    use aegis_security::detectors::tier_str;

    if modes.is_empty() {
        return ApplyOutcome::Applied;
    }

    let current = mask.load_state();
    let mut forced: Vec<String> = Vec::new();

    let clamped_base = clamp_mask_force_on(current.base, modes, &mut forced, "base");

    let mut clamped_overrides: [Option<DetectorMask>; 4] = [None; 4];
    for tier in ALL_TIERS {
        if let Some(m) = current.override_for(tier) {
            let scope = format!("override[{}]", tier_str(tier));
            let cm = clamp_mask_force_on(m, modes, &mut forced, &scope);
            let idx = aegis_security::detectors::tier_index(tier);
            clamped_overrides[idx] = Some(cm);
        }
    }

    if forced.is_empty() {
        // Common case — operator's mask already respects the
        // pinned classes; skip the store to keep the ArcSwap
        // hot read uncontended.
        return ApplyOutcome::Applied;
    }

    let clamped = MaskState {
        base: clamped_base,
        overrides: clamped_overrides,
    };
    mask.store_state(clamped);
    ApplyOutcome::AppliedWithCompliance { forced }
}

/// Run [`enforce_compliance_clamp`] against `proposed`; if it errors,
/// flip every flagged class back on and append the violation names
/// (prefixed by `scope`) to `forced`. Returns the clamped mask.
fn clamp_mask_force_on(
    proposed: DetectorMask,
    modes: &[ComplianceMode],
    forced: &mut Vec<String>,
    scope: &str,
) -> DetectorMask {
    match enforce_compliance_clamp(proposed, modes) {
        Ok(()) => proposed,
        Err(violations) => {
            let mut clamped = proposed;
            for class_name in &violations {
                if let Some(cls) = aegis_security::detectors::DetectorClass::ALL
                    .iter()
                    .copied()
                    .find(|c| c.as_str() == *class_name)
                {
                    clamped = clamped.with(cls, true);
                    if scope == "base" {
                        forced.push((*class_name).to_string());
                    } else {
                        forced.push(format!("{scope}:{class_name}"));
                    }
                }
            }
            clamped
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_security::detectors::{DetectorClass, DetectorMask};
    use tempfile::tempdir;

    fn full_state_disabling(class: DetectorClass) -> MaskState {
        let base = DetectorMask::all_enabled().with(class, false);
        MaskState::new(base)
    }

    fn snap_for(state: &MaskState) -> DetectorMaskSnapshot {
        DetectorMaskSnapshot::from_state(state)
    }

    // ----- snapshot ↔ state round-trip ------------------------------------

    #[test]
    fn snapshot_round_trips_base_mask() {
        let state = full_state_disabling(DetectorClass::Recon);
        let snap = DetectorMaskSnapshot::from_state(&state);
        let back: MaskState = snap.into_state();
        assert_eq!(back.base, state.base);
    }

    #[test]
    fn snapshot_preserves_per_tier_overrides() {
        let state = MaskState::new(DetectorMask::all_enabled())
            .with_override(
                Tier::Critical,
                Some(DetectorMask::all_enabled().with(DetectorClass::BruteForce, false)),
            )
            .with_override(
                Tier::Medium,
                Some(DetectorMask::none().with(DetectorClass::Sqli, true)),
            );
        let snap = DetectorMaskSnapshot::from_state(&state);
        let back = snap.into_state();
        assert_eq!(back.override_for(Tier::Critical), state.override_for(Tier::Critical));
        assert_eq!(back.override_for(Tier::Medium), state.override_for(Tier::Medium));
        assert!(back.override_for(Tier::High).is_none());
        assert!(back.override_for(Tier::Low).is_none());
    }

    #[test]
    fn snapshot_has_current_schema_version() {
        let snap = snap_for(&MaskState::default());
        assert_eq!(snap.schema_version, SNAPSHOT_SCHEMA_VERSION);
    }

    // ----- atomic save ----------------------------------------------------

    #[tokio::test]
    async fn save_creates_parent_dir_and_writes_pretty_json() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested/dir/mask.json");
        let snap = snap_for(&full_state_disabling(DetectorClass::Recon));
        save_snapshot(&path, &snap).await.unwrap();

        assert!(path.exists());
        let body = tokio::fs::read_to_string(&path).await.unwrap();
        // Pretty-printed: contains a newline.
        assert!(body.contains('\n'));
        // Sibling .tmp is gone after a successful rename.
        assert!(!tmp_path_for(&path).exists());
    }

    #[tokio::test]
    async fn save_overwrites_existing_snapshot_atomically() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mask.json");
        let s1 = snap_for(&full_state_disabling(DetectorClass::Recon));
        let s2 = snap_for(&full_state_disabling(DetectorClass::BruteForce));
        save_snapshot(&path, &s1).await.unwrap();
        save_snapshot(&path, &s2).await.unwrap();

        let loaded = load_snapshot(&path).await.unwrap();
        // Last write wins: brute_force should be off, recon on.
        assert!(!loaded.base.brute_force);
        assert!(loaded.base.recon);
    }

    #[test]
    fn tmp_path_appends_dot_tmp() {
        assert_eq!(
            tmp_path_for(Path::new("/var/lib/aegis/mask.json")),
            PathBuf::from("/var/lib/aegis/mask.json.tmp"),
        );
    }

    // ----- load ----------------------------------------------------------

    #[tokio::test]
    async fn load_missing_returns_not_found() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("never-written.json");
        match load_snapshot(&path).await {
            Err(LoadError::NotFound) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn load_garbage_returns_parse_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("garbage.json");
        tokio::fs::write(&path, b"not json").await.unwrap();
        match load_snapshot(&path).await {
            Err(LoadError::Parse(_)) => {}
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn load_rejects_unknown_schema_version() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("future.json");
        let payload = serde_json::json!({
            "schema_version": SNAPSHOT_SCHEMA_VERSION + 99,
            "saved_at": chrono::Utc::now(),
            "base": DetectorMaskBody::default(),
            "overrides": {},
        });
        tokio::fs::write(&path, serde_json::to_vec(&payload).unwrap()).await.unwrap();
        match load_snapshot(&path).await {
            Err(LoadError::SchemaMismatch { found, expected }) => {
                assert_eq!(found, SNAPSHOT_SCHEMA_VERSION + 99);
                assert_eq!(expected, SNAPSHOT_SCHEMA_VERSION);
            }
            other => panic!("expected SchemaMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn save_then_load_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mask.json");
        let original = full_state_disabling(DetectorClass::HeaderInjection);
        let snap = snap_for(&original);
        save_snapshot(&path, &snap).await.unwrap();
        let loaded = load_snapshot(&path).await.unwrap();
        let back: MaskState = loaded.into_state();
        assert_eq!(back.base, original.base);
    }

    // ----- apply_snapshot_with_compliance --------------------------------

    #[test]
    fn apply_runs_clean_when_no_compliance_modes() {
        let mask = SharedDetectorMask::default();
        let snap = snap_for(&full_state_disabling(DetectorClass::Recon));
        let outcome = apply_snapshot_with_compliance(snap, &mask, &[]);
        assert_eq!(outcome, ApplyOutcome::Applied);
        // Live mask reflects the snapshot.
        assert!(!mask.load().is_enabled(DetectorClass::Recon));
        assert!(mask.load().is_enabled(DetectorClass::Sqli));
    }

    #[test]
    fn apply_does_not_force_classes_back_on_while_lock_is_deferred() {
        // 2026-05-10 — compliance lock is deferred. PCI mode is
        // declared but the snapshot's per-class mask is applied
        // verbatim; sqli is NOT forced back on. Restore the
        // force-back behavior by repopulating COMPLIANCE_PINNED.
        let mask = SharedDetectorMask::default();
        let snap = snap_for(&full_state_disabling(DetectorClass::Sqli));
        let outcome = apply_snapshot_with_compliance(
            snap,
            &mask,
            &[ComplianceMode::Pci],
        );
        assert_eq!(outcome, ApplyOutcome::Applied);
        assert!(
            !mask.load().is_enabled(DetectorClass::Sqli),
            "lock is deferred — sqli stays off as requested by snapshot"
        );
    }

    #[test]
    fn apply_preserves_unrelated_disables() {
        // Snapshot disables sqli + recon. With the compliance lock
        // deferred, both stay off.
        let mask = SharedDetectorMask::default();
        let state = MaskState::new(
            DetectorMask::all_enabled()
                .with(DetectorClass::Sqli, false)
                .with(DetectorClass::Recon, false),
        );
        let snap = snap_for(&state);
        apply_snapshot_with_compliance(
            snap,
            &mask,
            &[ComplianceMode::Pci],
        );
        let live = mask.load();
        assert!(!live.is_enabled(DetectorClass::Sqli), "sqli stays off (deferred)");
        assert!(!live.is_enabled(DetectorClass::Recon), "recon stays off");
    }

    #[test]
    fn apply_preserves_per_tier_overrides_after_clamp() {
        let mask = SharedDetectorMask::default();
        let state = MaskState::new(DetectorMask::all_enabled())
            .with_override(
                Tier::Medium,
                Some(DetectorMask::all_enabled().with(DetectorClass::Recon, false)),
            );
        let snap = snap_for(&state);
        apply_snapshot_with_compliance(snap, &mask, &[ComplianceMode::Pci]);
        let live = mask.load_state();
        assert!(live.override_for(Tier::Medium).is_some(), "override preserved");
    }

    // ----- apply_live_mask_with_compliance ----------------------------------

    #[test]
    fn live_apply_no_op_when_modes_empty() {
        let mask = SharedDetectorMask::default();
        let initial = MaskState::new(DetectorMask::all_enabled().with(DetectorClass::Sqli, false));
        mask.store_state(initial);

        let outcome = apply_live_mask_with_compliance(&mask, &[]);
        assert_eq!(outcome, ApplyOutcome::Applied);
        // Mask unchanged — no clamp, no store.
        assert!(!mask.load().is_enabled(DetectorClass::Sqli));
    }

    #[test]
    fn live_apply_no_op_when_mask_already_compliant() {
        let mask = SharedDetectorMask::default();
        mask.store_state(MaskState::new(DetectorMask::all_enabled()));

        let outcome = apply_live_mask_with_compliance(&mask, &[ComplianceMode::Pci]);
        assert_eq!(outcome, ApplyOutcome::Applied);
        assert!(mask.load().is_enabled(DetectorClass::Sqli));
    }

    #[test]
    fn live_apply_does_not_force_classes_on_while_lock_is_deferred() {
        // 2026-05-10 — compliance lock is deferred. Operator-disabled
        // sqli + xss stay off even when PCI mode is active. Restore
        // the force-back behavior by repopulating COMPLIANCE_PINNED.
        let mask = SharedDetectorMask::default();
        mask.store_state(MaskState::new(
            DetectorMask::all_enabled()
                .with(DetectorClass::Sqli, false)
                .with(DetectorClass::Xss, false),
        ));

        let outcome = apply_live_mask_with_compliance(&mask, &[ComplianceMode::Pci]);
        assert_eq!(outcome, ApplyOutcome::Applied);
        let live = mask.load();
        assert!(!live.is_enabled(DetectorClass::Sqli), "sqli stays off (deferred)");
        assert!(!live.is_enabled(DetectorClass::Xss), "xss stays off (deferred)");
    }

    #[test]
    fn live_apply_preserves_all_disables_while_lock_is_deferred() {
        // 2026-05-10 — compliance lock is deferred. Both sqli (was
        // pinned) and recon (never pinned) stay off when PCI mode is
        // declared.
        let mask = SharedDetectorMask::default();
        mask.store_state(MaskState::new(
            DetectorMask::all_enabled()
                .with(DetectorClass::Sqli, false)
                .with(DetectorClass::Recon, false),
        ));

        apply_live_mask_with_compliance(&mask, &[ComplianceMode::Pci]);
        let live = mask.load();
        assert!(!live.is_enabled(DetectorClass::Sqli), "sqli stays off (deferred)");
        assert!(!live.is_enabled(DetectorClass::Recon), "recon stays off");
    }

    #[test]
    fn live_apply_does_not_clamp_per_tier_overrides_while_deferred() {
        // 2026-05-10 — compliance lock is deferred. Per-tier overrides
        // pass through verbatim; sqli stays off in the High override
        // even when PCI is active.
        let mask = SharedDetectorMask::default();
        mask.store_state(
            MaskState::new(DetectorMask::all_enabled()).with_override(
                Tier::High,
                Some(DetectorMask::all_enabled().with(DetectorClass::Sqli, false)),
            ),
        );

        let outcome = apply_live_mask_with_compliance(&mask, &[ComplianceMode::Pci]);
        assert_eq!(outcome, ApplyOutcome::Applied);
        let live = mask.load_state();
        let override_high = live.override_for(Tier::High).expect("override preserved");
        assert!(
            !override_high.is_enabled(DetectorClass::Sqli),
            "lock is deferred — per-tier sqli override stays off"
        );
    }

    #[test]
    fn live_apply_does_not_store_when_no_violations() {
        // The clamp should leave ArcSwap untouched on the no-op
        // path so hot reads stay uncontended. We assert this by
        // checking the in-memory pointer doesn't change.
        let mask = SharedDetectorMask::default();
        mask.store_state(MaskState::new(DetectorMask::all_enabled()));
        let before = mask.load_state();

        apply_live_mask_with_compliance(&mask, &[ComplianceMode::Pci]);
        let after = mask.load_state();
        assert_eq!(before.base.bits(), after.base.bits());
    }
}
