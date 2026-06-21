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

/// HU-T1 — rule IDs that collide with built-in detector class
/// names. Operators who create a rule named "sqli" or "xss"
/// haven't *broken* anything (rules and detectors live in
/// separate stores — see audit), but the id collision corrupts
/// audit-log filtering and the dashboard's "rule X applied"
/// toast becomes ambiguous. Reject up-front with a clear error.
///
/// The list mirrors `aegis_security::detectors::DetectorClass::as_str()`
/// — kept hard-coded here to avoid a cross-crate dep just for
/// eight string literals; if a new detector class lands, add
/// its stable name here too. Tests pin the list against the
/// real detector mask names.
const RESERVED_RULE_IDS: &[&str] = &[
    "sqli",
    "xss",
    "path_traversal",
    "ssrf",
    "header_injection",
    "body_abuse",
    "recon",
    "brute_force",
    "command_injection",
    "template_injection",
    "nosql_injection",
    "open_redirect",
    // 2026-06-12 (JWT report) — JWT attack-shape detector promoted to a
    // first-class togglable `DetectorClass`.
    "jwt_inspection",
    // 2026-06-12 (WS report P2) — cookie-injection detector.
    "cookie_injection",
    // 2026-05-19 — DetectorClass extension (Phase F + AI promotion
    // to first-class togglable classes). Keep this list in sync with
    // `DetectorClass::ALL`; `reserved_list_matches_detector_class_names`
    // is the drift guard.
    "behavior_signals",
    "velocity",
    "canary",
    "ai",
];

/// Validate a candidate rule id. Returns `None` on accept,
/// `Some(ValidateMessage)` on reject so the caller can fold
/// the rejection into the same `ValidateResponse.errors` shape
/// the body validator uses.
pub fn validate_rule_id(id: &str) -> Option<ValidateMessage> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return Some(ValidateMessage {
            line: 1,
            col: 1,
            message: "rule id must not be empty".into(),
        });
    }
    if RESERVED_RULE_IDS.contains(&trimmed) {
        return Some(ValidateMessage {
            line: 1,
            col: 1,
            message: format!(
                "rule id '{trimmed}' is reserved (matches a built-in detector class); pick a different id"
            ),
        });
    }
    None
}

/// Validate a candidate rule body against the *real* rule DSL the
/// engine consumes — not just non-empty/size. The body is the same
/// YAML-list grammar `aegis_security::rules::parse` accepts; we parse
/// it (capturing line/col on failure) and then run the same linter
/// `RuleSet::load` runs, so the validator and the engine agree on
/// exactly which bodies are acceptable.
///
/// 2026-06-18 (rule-body-validation-gap report): previously this only
/// checked empty/size, so a syntactically-broken body returned `ok`
/// and the POST/PUT path activated an inert rule with a misleading
/// 201 "config activated". Folding the parse + lint errors here closes
/// that gap with no new wiring — `handle_rules_post`/`put` already
/// gate on `!ok → 400`.
pub fn validate_rule_body(body: &str) -> ValidateResponse {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // Cheap, friendly guards before we hand anything to the parser:
    // an empty body or an over-cap body gets a clear message rather
    // than a cryptic YAML "EOF"/huge-input parse error.
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

    // Real DSL parse + lint — only when the cheap guards passed (no
    // point parsing an empty or oversized body).
    if errors.is_empty() {
        match serde_yaml::from_str::<Vec<aegis_security::rules::ast::Rule>>(body) {
            Ok(rules) => {
                for lint_err in aegis_security::rules::linter::lint(&rules) {
                    errors.push(ValidateMessage {
                        line: 1,
                        col: 1,
                        message: format!("rule lint error: {lint_err}"),
                    });
                }
            }
            Err(e) => {
                let (line, col) = e
                    .location()
                    .map(|l| (l.line() as u32, l.column() as u32))
                    .unwrap_or((1, 1));
                errors.push(ValidateMessage {
                    line,
                    col,
                    message: format!("rule body parse error: {e}"),
                });
            }
        }
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

/// 2026-06-21 — the rule ENGINE matches/audits on the DSL body's `id:`, while
/// the store keys under the form `id` the POST/PUT carries. If those diverge,
/// the list/detail show one id while traffic is matched under another (the
/// `block-bad-ips` vs `custom-block-ip` bug). Reject the mismatch at the
/// mutation boundary so the two can never drift.
///
/// Returns `None` when the body doesn't parse or carries no rule — those are
/// already reported by [`validate_rule_body`], so we don't double-flag.
pub fn validate_rule_id_matches_body(form_id: &str, body: &str) -> Option<ValidateMessage> {
    let rules: Vec<aegis_security::rules::ast::Rule> = serde_yaml::from_str(body).ok()?;
    let first = rules.first()?;
    let form_id = form_id.trim();
    if first.id != form_id {
        return Some(ValidateMessage {
            line: 1,
            col: 1,
            message: format!(
                "rule id mismatch: form id '{form_id}' must match the body's `id: {}` \
                 — the engine matches on the body id, so they must be identical",
                first.id,
            ),
        });
    }
    None
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
    /// HU-T1 — id collisions with built-in detector class names
    /// are rejected before the body validator even runs (the body
    /// might be valid; the id never will).
    pub fn upsert(&self, id: &str, body: &str, enabled: bool) -> ValidateResponse {
        let mut v = validate_rule_body(body);
        if let Some(id_err) = validate_rule_id(id) {
            v.errors.push(id_err);
            v.ok = false;
        }
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

    /// 2026-05-27 (Phase B rules fold) — atomically replace the entire
    /// rule set from the config-plane inline list (`cfg.rules.inline`),
    /// which is the source of truth: rules absent from `inline` are
    /// dropped. Each entry is validated (id + body); invalid entries
    /// are skipped and returned as `(id, ValidateResponse)` so the
    /// caller (boot seed / config watcher) can log them without
    /// aborting the swap. Valid entries land with a fresh `updated_at`.
    pub fn replace_all(
        &self,
        inline: &[aegis_core::config::RuleDef],
    ) -> Vec<(String, ValidateResponse)> {
        let now = chrono::Utc::now();
        let mut next: HashMap<String, Rule> = HashMap::new();
        let mut rejected = Vec::new();
        for r in inline {
            let mut v = validate_rule_body(&r.body);
            if let Some(id_err) = validate_rule_id(&r.id) {
                v.errors.push(id_err);
                v.ok = false;
            }
            if v.ok {
                next.insert(
                    r.id.clone(),
                    Rule {
                        id: r.id.clone(),
                        body: r.body.clone(),
                        enabled: r.enabled,
                        updated_at: now,
                    },
                );
            } else {
                rejected.push((r.id.clone(), v));
            }
        }
        let mut s = self.inner.lock().expect("rule store poisoned");
        s.rules = next;
        rejected
    }
}

/// 2026-05-17 F-CRITICAL-001 (control audit): bridge from the
/// dashboard's `RuleStore` (operator-authored bodies, keyed by
/// `id`) into the security engine's live `Arc<RuleSet>` (parsed
/// AST consumed by the request path). Called after every
/// audit-mutated CRUD operation: POST/PUT/DELETE/toggle.
///
/// Strategy: pick up every `enabled` rule's body, concatenate
/// them into one DSL document, parse via
/// [`aegis_security::rules::parser::parse`] (no lint — operators
/// already saw lint warnings at PUT-time via `validate_rule_body`),
/// then `replace_rules` atomically into the engine's ArcSwap.
///
/// `Ok(rule_count)` reports how many rules are now live.
/// `Err(msg)` returned when the concatenated body fails to parse
/// — caller logs but does NOT roll back the `RuleStore` change
/// (operators expect the dashboard state to reflect their save;
/// parse failure is observable via the next `/api/rules/validate`
/// or simulator run, and the live engine keeps the previous
/// rule set until the operator fixes the body).
pub fn rebuild_active_ruleset(
    store: &RuleStore,
    ruleset: &aegis_security::RuleSet,
) -> Result<usize, String> {
    let rules = store.list();
    let mut combined = String::new();
    for r in &rules {
        if !r.enabled {
            continue;
        }
        combined.push_str(&r.body);
        if !r.body.ends_with('\n') {
            combined.push('\n');
        }
    }
    if combined.trim().is_empty() {
        ruleset.replace_rules(Vec::new());
        return Ok(0);
    }
    match aegis_security::rules::parse(&combined) {
        Ok(parsed) => {
            let n = parsed.len();
            ruleset.replace_rules(parsed);
            Ok(n)
        }
        Err(e) => Err(format!("rule body parse failed: {e}")),
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
            method: None,
            path: None,
            mode: None,
            fields: serde_json::Value::Null,
        }
    }

    /// Minimal valid rule DSL (a one-element YAML list) for tests that
    /// just need a body the engine actually parses.
    fn valid_body(id: &str) -> String {
        format!("- id: {id}\n  when: true\n  then: allow\n")
    }

    #[test]
    fn validator_flags_empty_body() {
        let v = validate_rule_body("");
        assert!(!v.ok);
        assert_eq!(v.errors.len(), 1);
    }

    // 2026-06-18 (rule-body-validation-gap report) — the validator must
    // parse the real rule DSL, not just check non-empty/size. A body
    // that is not valid rule YAML has to be rejected up front so the
    // POST/PUT path returns 400 instead of a misleading 201.

    #[test]
    fn validator_rejects_invalid_yaml_dsl() {
        // Same string the engine uses as its `invalid_rules_yaml()` fixture.
        let v = validate_rule_body("not: [valid: yaml: for: rules");
        assert!(!v.ok, "broken DSL must be rejected");
        assert!(
            v.errors.iter().any(|e| e.message.contains("parse")),
            "expected a parse error, got: {:?}",
            v.errors
        );
    }

    #[test]
    fn validator_rejects_lint_failure() {
        // Parses fine, but priority is out of the linter's allowed range.
        let body = "- id: bad\n  priority: 99999\n  when: true\n  then: allow\n";
        let v = validate_rule_body(body);
        assert!(!v.ok, "lint failure must be rejected");
        assert!(
            v.errors.iter().any(|e| e.message.contains("priority")),
            "expected a priority lint error, got: {:?}",
            v.errors
        );
    }

    #[test]
    fn validator_accepts_valid_dsl() {
        let v = validate_rule_body(&valid_body("ok-1"));
        assert!(v.ok, "valid DSL should pass, got: {:?}", v.errors);
    }

    #[test]
    fn upsert_does_not_store_unparseable_body() {
        let store = RuleStore::new();
        let v = store.upsert("qa-rule-bad", "not: [valid: yaml: for: rules", true);
        assert!(!v.ok);
        assert!(store.list().is_empty(), "invalid body must not be stored");
    }

    // ----- HU-T1 — id collision guard ---------------------------------

    #[test]
    fn validate_rule_id_accepts_normal_ids() {
        assert!(validate_rule_id("custom-xss-001").is_none());
        assert!(validate_rule_id("internal_blocklist").is_none());
        assert!(validate_rule_id("rule-1").is_none());
        // Suffixed forms are fine — only exact matches on the reserved
        // list are rejected.
        assert!(validate_rule_id("sqli-custom").is_none());
        assert!(validate_rule_id("xss_extra").is_none());
    }

    #[test]
    fn validate_rule_id_rejects_empty_or_whitespace() {
        let err = validate_rule_id("").unwrap();
        assert!(err.message.contains("must not be empty"));
        let err = validate_rule_id("   ").unwrap();
        assert!(err.message.contains("must not be empty"));
    }

    // 2026-06-21 — form id ↔ body id must agree (the engine uses the body id).
    #[test]
    fn rule_id_matches_body_accepts_when_equal() {
        let body = "- id: custom-block-ip\n  priority: 100\n  when: { ip_in: [\"1.2.3.4\"] }\n  then: { block: { status: 403 } }\n";
        assert!(validate_rule_id_matches_body("custom-block-ip", body).is_none());
        // trims the form id before comparing
        assert!(validate_rule_id_matches_body("  custom-block-ip  ", body).is_none());
    }

    #[test]
    fn rule_id_matches_body_flags_divergence() {
        // The reported bug: form id custom-block-ip, body id block-bad-ips.
        let body = "- id: block-bad-ips\n  priority: 100\n  when: { ip_in: [\"1.2.3.4\"] }\n  then: { block: { status: 403 } }\n";
        let err = validate_rule_id_matches_body("custom-block-ip", body).unwrap();
        assert!(err.message.contains("mismatch"));
        assert!(err.message.contains("block-bad-ips"));
        assert!(err.message.contains("custom-block-ip"));
    }

    #[test]
    fn rule_id_matches_body_tolerates_unparseable_body() {
        // A broken body is reported by validate_rule_body, not double-flagged here.
        assert!(validate_rule_id_matches_body("x", "this: is: not: valid").is_none());
        assert!(validate_rule_id_matches_body("x", "").is_none());
    }

    #[test]
    fn validate_rule_id_rejects_every_reserved_detector_name() {
        for reserved in RESERVED_RULE_IDS {
            let err = validate_rule_id(reserved).unwrap_or_else(|| {
                panic!("reserved id '{reserved}' should be rejected")
            });
            assert!(err.message.contains("reserved"));
            assert!(err.message.contains(reserved));
        }
    }

    #[test]
    fn validate_rule_id_trims_whitespace_before_checking() {
        // "  sqli  " is just sqli with padding; still reserved.
        assert!(validate_rule_id("  sqli  ").is_some());
    }

    #[test]
    fn upsert_rejects_reserved_detector_name_as_id() {
        let store = RuleStore::new();
        let v = store.upsert("sqli", &valid_body("sqli"), true);
        assert!(!v.ok);
        assert!(v.errors.iter().any(|e| e.message.contains("reserved")));
        // Store remains empty — failed validation skips the insert.
        assert!(store.list().is_empty());
    }

    #[test]
    fn upsert_accepts_normal_id_with_valid_body() {
        let store = RuleStore::new();
        let v = store.upsert("custom-1", &valid_body("custom-1"), true);
        assert!(v.ok, "got errors: {:?}", v.errors);
        assert_eq!(store.list().len(), 1);
    }

    #[test]
    fn upsert_aggregates_id_and_body_errors() {
        // Both invalid: reserved id + empty body. Both errors should
        // surface so the dashboard renders a single complete diagnostic.
        let store = RuleStore::new();
        let v = store.upsert("xss", "", true);
        assert!(!v.ok);
        let messages: Vec<&str> = v.errors.iter().map(|e| e.message.as_str()).collect();
        assert!(
            messages.iter().any(|m| m.contains("reserved")),
            "id error missing: {messages:?}"
        );
        assert!(
            messages.iter().any(|m| m.contains("empty")),
            "body error missing: {messages:?}"
        );
    }

    /// Pin the hand-coded reserved list against the real
    /// `DetectorClass` strings — drift gets caught at test time.
    #[test]
    fn reserved_list_matches_detector_class_names() {
        use aegis_security::detectors::DetectorClass;
        let mut from_enum: Vec<&str> =
            DetectorClass::ALL.iter().map(|c| c.as_str()).collect();
        from_enum.sort();
        let mut from_const: Vec<&str> = RESERVED_RULE_IDS.to_vec();
        from_const.sort();
        assert_eq!(
            from_enum, from_const,
            "RESERVED_RULE_IDS drifted from DetectorClass — sync the list",
        );
    }

    #[test]
    fn validator_warns_on_todo_marker() {
        // Valid DSL with a YAML comment carrying a TODO marker — the
        // body parses + lints clean, so only the warning surfaces.
        let v = validate_rule_body("- id: x\n  # TODO finish me\n  when: true\n  then: allow\n");
        assert!(v.ok, "got errors: {:?}", v.errors);
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
        let v = s.upsert("r1", &valid_body("r1"), true);
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

    // 2026-05-27 (Phase B rules fold) — replace_all makes the store
    // match cfg.rules.inline exactly (source of truth).
    #[test]
    fn replace_all_replaces_whole_set_and_drops_absent() {
        use aegis_core::config::RuleDef;
        let s = RuleStore::new();
        s.upsert("stale", &valid_body("stale"), true);

        let inline = vec![
            RuleDef { id: "r1".into(), body: valid_body("r1"), enabled: true },
            RuleDef { id: "r2".into(), body: valid_body("r2"), enabled: false },
        ];
        let rejected = s.replace_all(&inline);
        assert!(rejected.is_empty(), "all valid");
        assert!(s.get("stale").is_none(), "rule absent from inline is dropped");
        assert_eq!(s.list().len(), 2);
        assert!(s.get("r1").unwrap().enabled);
        assert!(!s.get("r2").unwrap().enabled);
    }

    #[test]
    fn replace_all_collects_invalid_rules() {
        use aegis_core::config::RuleDef;
        let s = RuleStore::new();
        let inline = vec![
            RuleDef { id: "ok".into(), body: valid_body("ok"), enabled: true },
            RuleDef { id: "sqli".into(), body: valid_body("sqli"), enabled: true }, // reserved id
            RuleDef { id: "empty".into(), body: "".into(), enabled: true }, // empty body
        ];
        let rejected = s.replace_all(&inline);
        let rejected_ids: Vec<&str> = rejected.iter().map(|(id, _)| id.as_str()).collect();
        assert!(rejected_ids.contains(&"sqli"));
        assert!(rejected_ids.contains(&"empty"));
        assert_eq!(s.list().len(), 1, "only the valid rule landed");
        assert!(s.get("ok").is_some());
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

    /// 2026-05-17 F-CRITICAL-001 (control audit): `rebuild_active_ruleset`
    /// parses + applies every enabled rule body, ignoring disabled ones.
    /// After this call the engine's `RuleSet::len` reflects the count
    /// of `enabled: true` rule bodies that parsed.
    #[test]
    fn rebuild_active_ruleset_applies_only_enabled() {
        let store = RuleStore::new();
        let body_a = "- id: a\n  priority: 100\n  when: true\n  then: allow\n";
        let body_b = "- id: b\n  priority:  90\n  when: true\n  then: log_only\n";
        store.upsert("a", body_a, true);
        store.upsert("b", body_b, false); // disabled

        let engine = aegis_security::RuleSet::new();
        let n = rebuild_active_ruleset(&store, &engine).unwrap();
        assert_eq!(n, 1, "only enabled rules should be applied");
        assert_eq!(engine.len(), 1);

        // Flip b on — now both apply.
        store.upsert("b", body_b, true);
        let n = rebuild_active_ruleset(&store, &engine).unwrap();
        assert_eq!(n, 2);
        assert_eq!(engine.len(), 2);

        // Delete a — only b remains.
        assert!(store.delete("a"));
        let n = rebuild_active_ruleset(&store, &engine).unwrap();
        assert_eq!(n, 1);
        assert_eq!(engine.len(), 1);

        // Empty store — engine drains to empty.
        assert!(store.delete("b"));
        let n = rebuild_active_ruleset(&store, &engine).unwrap();
        assert_eq!(n, 0);
        assert!(engine.is_empty());
    }
}
