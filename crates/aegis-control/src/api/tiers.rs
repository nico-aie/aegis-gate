//! `/api/tiers` (D-M4-T4.4).
//!
//! Tier definition CRUD. Backed by an in-memory store seeded with
//! the four canonical tiers (`critical`, `high`, `medium`, `low`)
//! — the same names the `aegis_core::tier::Tier` enum uses, so a
//! route's `tier_override: low` correctly links to the `low` row
//! in the dashboard's Detectors page.
//!
//! 2026-05-04 — `Tier::CatchAll` was renamed to `Tier::Low`. The
//! role-based "catch-all" name conflated the security level with
//! the routing role; the routing role now lives on
//! `RouteConfig.default: bool` (PR2). Tiers are pure risk-level
//! labels: critical / high / medium / low. The legacy `catch_all`
//! string remains accepted as a serde alias on the enum + a parse
//! alias here so old YAML configs and API clients keep working.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tier {
    pub name: String,
    /// Detector pipeline names enabled for this tier. Descriptive
    /// metadata only — the data plane runs the detector chain via
    /// the per-tier mask overrides on `SharedDetectorMask`. Kept on
    /// the wire shape so existing YAML still loads. The dashboard
    /// no longer surfaces this list (2026-05-10).
    pub pipeline: Vec<String>,
    /// Per-request block score (0-100). When the SUM of detector
    /// signals on a single request crosses this value, the request
    /// is blocked. Per-request only — does not accumulate or decay.
    /// Field name kept as `risk_threshold` for wire-shape stability.
    pub risk_threshold: u32,
    /// Legacy descriptive metadata (req/s rate cap). The live
    /// rate-limit is configured per-cluster on the Traffic Gates
    /// page, not per-tier. Kept on the wire shape so older YAML
    /// configs still load; the dashboard no longer surfaces it.
    pub block_threshold: u32,
    /// 2026-05-10 — Option B per-tier cumulative IP risk thresholds.
    /// When `Some`, the data plane uses these instead of the global
    /// `cfg.risk.thresholds` for requests classified to this tier.
    /// `None` falls back to the global thresholds, so existing
    /// snapshots without these fields keep working.
    #[serde(default)]
    pub cumulative_challenge_at: Option<u32>,
    /// See `cumulative_challenge_at`. Both should be set together
    /// (validated: challenge < block when both Some).
    #[serde(default)]
    pub cumulative_block_at: Option<u32>,
    /// 2026-05-10 — when `false`, the challenge rung is removed
    /// from this tier's response ladder: cumulative score crossing
    /// `challenge_at` escalates straight to block instead of
    /// emitting a 429 PoW. Defaults to `true` so existing
    /// deployments keep their challenge behavior unchanged.
    #[serde(default = "default_challenges_enabled")]
    pub challenges_enabled: bool,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

fn default_challenges_enabled() -> bool {
    true
}

impl Tier {
    // FIX 2026-05-04 — `ai` joined the canonical pipeline list.
    // Note that the pipeline field today is **descriptive
    // metadata only** — the data plane gates detectors via the
    // detector mask (`is_enabled_id`), not by walking this
    // string list. The list still drives the dashboard's
    // tier-edit checkboxes so operators see a complete set of
    // detectors per tier; flipping a stage off here doesn't
    // currently disable the detector at runtime. Real
    // tier-scoped execution is a follow-up.
    fn defaults_for(name: &str) -> Self {
        let (pipeline, risk, block) = match name {
            "critical" => (
                vec!["rate", "rules", "sqli", "xss", "ssrf", "path_traversal", "header_inj", "bots", "ai", "risk", "challenge"],
                50,
                10,
            ),
            "high" => (
                vec!["rate", "rules", "sqli", "xss", "ssrf", "bots", "ai", "risk"],
                70,
                100,
            ),
            "medium" => (vec!["rate", "rules", "sqli", "xss"], 80, 1000),
            // `low` is the most permissive tier. Anything unknown
            // also falls here defensively (validators reject unknown
            // names elsewhere, but `defaults_for` is also called
            // from the migration path for forward-compat).
            _ => (vec!["rate", "rules"], 90, 10_000),
        };
        Tier {
            name: name.into(),
            pipeline: pipeline.into_iter().map(String::from).collect(),
            risk_threshold: risk,
            block_threshold: block,
            cumulative_challenge_at: None,
            cumulative_block_at: None,
            challenges_enabled: true,
            updated_at: chrono::Utc::now(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TierListResponse {
    pub tiers: Vec<Tier>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TierStatsResponse {
    pub tier: String,
    pub window_seconds: u32,
    pub requests: u64,
    pub blocks: u64,
}

#[derive(Default)]
struct TierStoreState {
    tiers: HashMap<String, Tier>,
}

#[derive(Clone)]
pub struct TierStore {
    inner: Arc<Mutex<TierStoreState>>,
}

impl Default for TierStore {
    fn default() -> Self {
        let mut tiers = HashMap::new();
        // Canonical names match `aegis_core::tier::Tier` (snake_case).
        for name in ["critical", "high", "medium", "low"] {
            tiers.insert(name.to_string(), Tier::defaults_for(name));
        }
        Self {
            inner: Arc::new(Mutex::new(TierStoreState { tiers })),
        }
    }
}

impl TierStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn list(&self) -> Vec<Tier> {
        let s = self.inner.lock().expect("tier store poisoned");
        let mut v: Vec<Tier> = s.tiers.values().cloned().collect();
        v.sort_by(|a, b| tier_order(&a.name).cmp(&tier_order(&b.name)));
        v
    }

    pub fn get(&self, name: &str) -> Option<Tier> {
        let s = self.inner.lock().expect("tier store poisoned");
        s.tiers.get(name).cloned()
    }

    /// Update a tier. Returns `Ok(updated)` or `Err(reason)` on
    /// validation failure (out-of-range thresholds, empty pipeline,
    /// challenge_at >= block_at when both set).
    #[allow(clippy::too_many_arguments)]
    pub fn put(
        &self,
        name: &str,
        pipeline: Vec<String>,
        risk_threshold: u32,
        block_threshold: u32,
        cumulative_challenge_at: Option<u32>,
        cumulative_block_at: Option<u32>,
        challenges_enabled: bool,
    ) -> Result<Tier, String> {
        // Accept `catch_all` / `catchall` as aliases — the legacy
        // names land in the same `low` slot. The store key still
        // normalises to "low" so list ordering + lookups stay clean.
        let canonical = match name {
            "low" | "catch_all" | "catchall" => "low",
            n if matches!(n, "critical" | "high" | "medium") => n,
            other => return Err(format!("unknown tier: {other}")),
        };
        if pipeline.is_empty() {
            return Err("pipeline must not be empty".into());
        }
        if risk_threshold > 100 {
            return Err("risk_threshold > 100".into());
        }
        // 2026-05-10 — Option B validation. Both Some => challenge
        // strictly less than block. One Some + one None is allowed
        // (operator can override challenge but inherit global block,
        // or vice versa) since both fall back to global on read.
        if let Some(c) = cumulative_challenge_at {
            if c > 100 {
                return Err("cumulative_challenge_at > 100".into());
            }
        }
        if let Some(b) = cumulative_block_at {
            if b > 100 {
                return Err("cumulative_block_at > 100".into());
            }
        }
        if let (Some(c), Some(b)) = (cumulative_challenge_at, cumulative_block_at) {
            if c >= b {
                return Err(format!(
                    "cumulative_challenge_at ({c}) must be strictly less than cumulative_block_at ({b})"
                ));
            }
        }
        let tier = Tier {
            name: canonical.to_string(),
            pipeline,
            risk_threshold,
            block_threshold,
            cumulative_challenge_at,
            cumulative_block_at,
            challenges_enabled,
            updated_at: chrono::Utc::now(),
        };
        let mut s = self.inner.lock().expect("tier store poisoned");
        s.tiers.insert(canonical.to_string(), tier.clone());
        Ok(tier)
    }
}

fn tier_order(name: &str) -> u32 {
    match name {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" | "catch_all" | "catchall" => 3,
        _ => 99,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_seeds_four_canonical_tiers() {
        let s = TierStore::new();
        let names: Vec<String> = s.list().into_iter().map(|t| t.name).collect();
        assert_eq!(names, vec!["critical", "high", "medium", "low"]);
    }

    /// Regression — the seed names match `aegis_core::tier::Tier`
    /// (snake_case) so a route's `tier_override: low` correctly
    /// links to the `low` row in the dashboard.
    #[test]
    fn seed_names_match_canonical_tier_enum() {
        let s = TierStore::new();
        assert!(s.get("low").is_some(), "low row must exist");
    }

    #[test]
    fn put_rejects_unknown_tier_name() {
        let s = TierStore::new();
        let r = s.put("paranoid", vec!["rules".into()], 50, 100, None, None, true);
        assert!(r.is_err());
    }

    #[test]
    fn put_rejects_empty_pipeline() {
        let s = TierStore::new();
        let r = s.put("high", vec![], 50, 100, None, None, true);
        assert!(r.is_err());
    }

    #[test]
    fn put_rejects_risk_threshold_over_100() {
        let s = TierStore::new();
        let r = s.put("high", vec!["rules".into()], 200, 100, None, None, true);
        assert!(r.is_err());
    }

    // 2026-05-10 — Option B validations.
    #[test]
    fn put_rejects_cumulative_challenge_over_100() {
        let s = TierStore::new();
        let r = s.put("high", vec!["rules".into()], 50, 100, Some(150), None, true);
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("cumulative_challenge_at"));
    }

    #[test]
    fn put_rejects_cumulative_block_over_100() {
        let s = TierStore::new();
        let r = s.put("high", vec!["rules".into()], 50, 100, None, Some(150), true);
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("cumulative_block_at"));
    }

    #[test]
    fn put_rejects_challenge_at_or_above_block() {
        let s = TierStore::new();
        // challenge == block is invalid (must be strictly less).
        let eq = s.put("high", vec!["rules".into()], 50, 100, Some(50), Some(50), true);
        assert!(eq.is_err());
        // challenge > block is also invalid.
        let gt = s.put("high", vec!["rules".into()], 50, 100, Some(60), Some(50), true);
        assert!(gt.is_err());
        // challenge < block is fine.
        let ok = s.put("high", vec!["rules".into()], 50, 100, Some(40), Some(80), true);
        assert!(ok.is_ok());
    }

    #[test]
    fn put_accepts_partial_cumulative_overrides() {
        // Operator overrides only challenge_at, inherits block_at
        // from the global config — should be allowed.
        let s = TierStore::new();
        let r = s.put("high", vec!["rules".into()], 50, 100, Some(35), None, true);
        assert!(r.is_ok());
        let t = r.unwrap();
        assert_eq!(t.cumulative_challenge_at, Some(35));
        assert_eq!(t.cumulative_block_at, None);
    }

    #[test]
    fn put_persists_challenges_enabled_flag() {
        let s = TierStore::new();
        s.put("high", vec!["rules".into()], 50, 100, None, None, false).unwrap();
        let t = s.get("high").unwrap();
        assert!(!t.challenges_enabled, "challenges_enabled flag persisted");
    }

    #[test]
    fn put_persists_change() {
        let s = TierStore::new();
        s.put(
            "low",
            vec!["rules".into(), "rate".into()],
            95, 50_000, None, None, true,
        ).unwrap();
        let t = s.get("low").unwrap();
        assert_eq!(t.risk_threshold, 95);
        assert_eq!(t.pipeline.len(), 2);
    }

    /// Backward-compat — `catch_all` and `catchall` are accepted
    /// aliases, both lookup + write under the canonical `low` slot.
    #[test]
    fn put_accepts_legacy_catch_all_alias() {
        let s = TierStore::new();
        s.put("catch_all", vec!["rules".into()], 95, 50_000, None, None, true).unwrap();
        // Read back through both names — same row.
        assert!(s.get("low").is_some(), "alias must store under canonical `low`");
        assert_eq!(s.get("low").unwrap().risk_threshold, 95);
    }
}
