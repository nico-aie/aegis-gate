//! `/api/rules/*` (D-M4-T4.1..T4.3).
//!
//! In-memory rule store + validator + per-rule stats. The real
//! persistence layer (etcd-backed config + audit-logged mutations)
//! is wired in when the M3 audit-mutation pipeline lands; until
//! then the dashboard CRUD round-trips through this in-process
//! store so the UI works end-to-end.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aegis_core::audit::AuditEvent;
use serde::{Deserialize, Serialize};

const STATS_RETENTION: Duration = Duration::from_secs(3600);
const MAX_BODY_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub body: String,
    pub enabled: bool,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidateMessage {
    pub line: u32,
    pub col: u32,
    pub message: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidateResponse {
    pub ok: bool,
    pub errors: Vec<ValidateMessage>,
    pub warnings: Vec<ValidateMessage>,
}

/// Toy validator. Real grammar lives in `aegis-security`; we
/// surface the same shape so the page can be wired now.
pub fn validate_rule_body(body: &str) -> ValidateResponse {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    if body.trim().is_empty() {
        errors.push(ValidateMessage {
            line: 1,
            col: 1,
            message: "rule body is empty".into(),
        });
    }
    if body.len() > MAX_BODY_BYTES {
        errors.push(ValidateMessage {
            line: 1,
            col: 1,
            message: format!("body exceeds {MAX_BODY_BYTES} bytes"),
        });
    }
    for (i, line) in body.lines().enumerate() {
        if line.trim_start().starts_with("# todo")
            || line.trim_start().starts_with("# TODO")
        {
            warnings.push(ValidateMessage {
                line: (i + 1) as u32,
                col: 1,
                message: "TODO marker in rule body".into(),
            });
        }
    }
    ValidateResponse {
        ok: errors.is_empty(),
        errors,
        warnings,
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RuleStatsResponse {
    pub rule_id: String,
    pub window_seconds: u32,
    pub hits: u64,
    pub blocks: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct TopRulesResponse {
    pub window_seconds: u32,
    pub limit: u32,
    pub rules: Vec<RuleHits>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RuleHits {
    pub rule_id: String,
    pub hits: u64,
}

#[derive(Default)]
struct RuleStatsState {
    /// (when, rule_id, was_block) — bounded by retention.
    events: std::collections::VecDeque<(Instant, String, bool)>,
}

#[derive(Clone, Default)]
pub struct RuleStats {
    inner: Arc<Mutex<RuleStatsState>>,
}

impl RuleStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, ev: &AuditEvent) {
        let Some(rule_id) = ev.rule_id.clone() else {
            return;
        };
        let was_block = ev.action == "block";
        let now = Instant::now();
        let mut s = self.inner.lock().expect("rule stats poisoned");
        s.events.push_back((now, rule_id, was_block));
        while let Some(&(t, _, _)) = s.events.front() {
            if now.duration_since(t) > STATS_RETENTION {
                s.events.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn rule(&self, rule_id: &str, window_seconds: u32) -> RuleStatsResponse {
        let dur = Duration::from_secs(u64::from(window_seconds.clamp(1, 3600)));
        let s = self.inner.lock().expect("rule stats poisoned");
        let now = Instant::now();
        let mut hits = 0u64;
        let mut blocks = 0u64;
        for (t, id, b) in s.events.iter().rev() {
            if now.duration_since(*t) > dur {
                break;
            }
            if id == rule_id {
                hits += 1;
                if *b {
                    blocks += 1;
                }
            }
        }
        RuleStatsResponse {
            rule_id: rule_id.into(),
            window_seconds: window_seconds.clamp(1, 3600),
            hits,
            blocks,
        }
    }

    pub fn top(&self, window_seconds: u32, limit: u32) -> TopRulesResponse {
        let window = window_seconds.clamp(1, 3600);
        let limit = limit.clamp(1, 100);
        let dur = Duration::from_secs(u64::from(window));
        let s = self.inner.lock().expect("rule stats poisoned");
        let now = Instant::now();
        let mut counts: HashMap<String, u64> = HashMap::new();
        for (t, id, _) in s.events.iter().rev() {
            if now.duration_since(*t) > dur {
                break;
            }
            *counts.entry(id.clone()).or_insert(0) += 1;
        }
        let mut rules: Vec<RuleHits> = counts
            .into_iter()
            .map(|(rule_id, hits)| RuleHits { rule_id, hits })
            .collect();
        rules.sort_by(|a, b| b.hits.cmp(&a.hits).then_with(|| a.rule_id.cmp(&b.rule_id)));
        rules.truncate(limit as usize);
        TopRulesResponse {
            window_seconds: window,
            limit,
            rules,
        }
    }
}

#[derive(Default)]
struct RuleStoreState {
    rules: HashMap<String, Rule>,
}

#[derive(Clone, Default)]
pub struct RuleStore {
    inner: Arc<Mutex<RuleStoreState>>,
}

impl RuleStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn list(&self) -> Vec<Rule> {
        let s = self.inner.lock().expect("rule store poisoned");
        let mut v: Vec<Rule> = s.rules.values().cloned().collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }

    pub fn get(&self, id: &str) -> Option<Rule> {
        let s = self.inner.lock().expect("rule store poisoned");
        s.rules.get(id).cloned()
    }

    /// Validate, then upsert. Returns the validation response; on
    /// `ok = true` the rule is stored. Always returns the validator
    /// shape so the page can render warnings on a successful save.
    pub fn upsert(&self, id: &str, body: &str, enabled: bool) -> ValidateResponse {
        let v = validate_rule_body(body);
        if v.ok {
            let mut s = self.inner.lock().expect("rule store poisoned");
            s.rules.insert(
                id.into(),
                Rule {
                    id: id.into(),
                    body: body.into(),
                    enabled,
                    updated_at: chrono::Utc::now(),
                },
            );
        }
        v
    }

    pub fn delete(&self, id: &str) -> bool {
        let mut s = self.inner.lock().expect("rule store poisoned");
        s.rules.remove(id).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::audit::AuditClass;

    fn ev(rule_id: Option<&str>, action: &str) -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "test".into(),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: None,
            action: action.into(),
            reason: "test".into(),
            client_ip: "1.1.1.1".into(),
            route_id: None,
            rule_id: rule_id.map(|s| s.into()),
            risk_score: None,
            fields: serde_json::Value::Null,
        }
    }

    #[test]
    fn validator_flags_empty_body() {
        let v = validate_rule_body("");
        assert!(!v.ok);
        assert_eq!(v.errors.len(), 1);
    }

    #[test]
    fn validator_warns_on_todo_marker() {
        let v = validate_rule_body("rule x {\n# TODO finish me\n}");
        assert!(v.ok);
        assert_eq!(v.warnings.len(), 1);
    }

    #[test]
    fn validator_rejects_body_over_limit() {
        let body = "x".repeat(MAX_BODY_BYTES + 1);
        let v = validate_rule_body(&body);
        assert!(!v.ok);
    }

    #[test]
    fn store_upsert_get_delete_roundtrip() {
        let s = RuleStore::new();
        let v = s.upsert("r1", "rule r1 { allow }", true);
        assert!(v.ok);
        let r = s.get("r1").unwrap();
        assert_eq!(r.id, "r1");
        assert!(r.enabled);
        assert_eq!(s.list().len(), 1);
        assert!(s.delete("r1"));
        assert!(s.get("r1").is_none());
    }

    #[test]
    fn store_does_not_store_invalid_body() {
        let s = RuleStore::new();
        let v = s.upsert("r1", "", true);
        assert!(!v.ok);
        assert!(s.get("r1").is_none());
    }

    #[test]
    fn rule_stats_per_rule_window() {
        let r = RuleStats::new();
        for _ in 0..5 {
            r.record(&ev(Some("sqli-1"), "block"));
        }
        for _ in 0..2 {
            r.record(&ev(Some("xss-1"), "challenge"));
        }
        r.record(&ev(None, "allow"));
        let s = r.rule("sqli-1", 60);
        assert_eq!(s.hits, 5);
        assert_eq!(s.blocks, 5);
        let s2 = r.rule("xss-1", 60);
        assert_eq!(s2.hits, 2);
        assert_eq!(s2.blocks, 0);
    }

    #[test]
    fn rule_stats_top_sorted_by_hits_desc() {
        let r = RuleStats::new();
        for _ in 0..3 {
            r.record(&ev(Some("a"), "block"));
        }
        for _ in 0..7 {
            r.record(&ev(Some("b"), "block"));
        }
        let top = r.top(60, 5);
        assert_eq!(top.rules.len(), 2);
        assert_eq!(top.rules[0].rule_id, "b");
        assert_eq!(top.rules[0].hits, 7);
    }
}
