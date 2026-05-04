//! `/api/tiers` (D-M4-T4.4).
//!
//! Tier definition CRUD. Backed by an in-memory store seeded with
//! the four canonical tiers (`critical`, `high`, `medium`, `low`).
//! Real config persistence is wired when the M3 audit-mutation
//! pipeline lands.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tier {
    pub name: String,
    /// Detector pipeline names enabled for this tier.
    pub pipeline: Vec<String>,
    /// Risk threshold used by the challenge engine.
    pub risk_threshold: u32,
    /// Block threshold (events / sec) above which fail-closed kicks in.
    pub block_threshold: u32,
    pub updated_at: chrono::DateTime<chrono::Utc>,
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
            _ => (vec!["rate", "rules"], 90, 10_000),
        };
        Tier {
            name: name.into(),
            pipeline: pipeline.into_iter().map(String::from).collect(),
            risk_threshold: risk,
            block_threshold: block,
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
    /// validation failure (out-of-range thresholds, empty pipeline).
    pub fn put(
        &self,
        name: &str,
        pipeline: Vec<String>,
        risk_threshold: u32,
        block_threshold: u32,
    ) -> Result<Tier, String> {
        if !matches!(name, "critical" | "high" | "medium" | "low") {
            return Err(format!("unknown tier: {name}"));
        }
        if pipeline.is_empty() {
            return Err("pipeline must not be empty".into());
        }
        if risk_threshold > 100 {
            return Err("risk_threshold > 100".into());
        }
        let tier = Tier {
            name: name.into(),
            pipeline,
            risk_threshold,
            block_threshold,
            updated_at: chrono::Utc::now(),
        };
        let mut s = self.inner.lock().expect("tier store poisoned");
        s.tiers.insert(name.into(), tier.clone());
        Ok(tier)
    }
}

fn tier_order(name: &str) -> u32 {
    match name {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
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

    #[test]
    fn put_rejects_unknown_tier_name() {
        let s = TierStore::new();
        let r = s.put("paranoid", vec!["rules".into()], 50, 100);
        assert!(r.is_err());
    }

    #[test]
    fn put_rejects_empty_pipeline() {
        let s = TierStore::new();
        let r = s.put("high", vec![], 50, 100);
        assert!(r.is_err());
    }

    #[test]
    fn put_rejects_risk_threshold_over_100() {
        let s = TierStore::new();
        let r = s.put("high", vec!["rules".into()], 200, 100);
        assert!(r.is_err());
    }

    #[test]
    fn put_persists_change() {
        let s = TierStore::new();
        s.put("low", vec!["rules".into(), "rate".into()], 95, 50_000).unwrap();
        let t = s.get("low").unwrap();
        assert_eq!(t.risk_threshold, 95);
        assert_eq!(t.pipeline.len(), 2);
    }
}
