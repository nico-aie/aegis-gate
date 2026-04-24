use std::collections::HashSet;

use super::ast::{Condition, MatchOp, Rule};

const MAX_NESTING_DEPTH: usize = 8;
const MAX_PRIORITY: u32 = 10_000;

/// Lint errors.
#[derive(Debug)]
pub enum LintError {
    DuplicateId(String),
    NestingTooDeep { rule_id: String, depth: usize },
    PriorityOutOfRange { rule_id: String, priority: u32 },
    InvalidRegex { rule_id: String, pattern: String, err: String },
}

impl std::fmt::Display for LintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LintError::DuplicateId(id) => write!(f, "duplicate rule id: {id}"),
            LintError::NestingTooDeep { rule_id, depth } => {
                write!(f, "rule {rule_id}: nesting depth {depth} exceeds max {MAX_NESTING_DEPTH}")
            }
            LintError::PriorityOutOfRange { rule_id, priority } => {
                write!(f, "rule {rule_id}: priority {priority} out of range [0, {MAX_PRIORITY}]")
            }
            LintError::InvalidRegex { rule_id, pattern, err } => {
                write!(f, "rule {rule_id}: invalid regex `{pattern}`: {err}")
            }
        }
    }
}

/// Lint a set of rules.  Returns all errors found.
pub fn lint(rules: &[Rule]) -> Vec<LintError> {
    let mut errors = Vec::new();

    // Check unique IDs.
    let mut seen = HashSet::new();
    for rule in rules {
        if !seen.insert(&rule.id) {
            errors.push(LintError::DuplicateId(rule.id.clone()));
        }
    }

    for rule in rules {
        // Priority range.
        if rule.priority > MAX_PRIORITY {
            errors.push(LintError::PriorityOutOfRange {
                rule_id: rule.id.clone(),
                priority: rule.priority,
            });
        }

        // Nesting depth.
        let depth = condition_depth(&rule.condition);
        if depth > MAX_NESTING_DEPTH {
            errors.push(LintError::NestingTooDeep {
                rule_id: rule.id.clone(),
                depth,
            });
        }

        // Regex compilation.
        check_regexes(&rule.condition, &rule.id, &mut errors);
    }

    errors
}

fn condition_depth(cond: &Condition) -> usize {
    match cond {
        Condition::All(children) | Condition::Any(children) => {
            1 + children.iter().map(condition_depth).max().unwrap_or(0)
        }
        Condition::Not(inner) => 1 + condition_depth(inner),
        _ => 1,
    }
}

fn check_regexes(cond: &Condition, rule_id: &str, errors: &mut Vec<LintError>) {
    match cond {
        Condition::All(children) | Condition::Any(children) => {
            for child in children {
                check_regexes(child, rule_id, errors);
            }
        }
        Condition::Not(inner) => check_regexes(inner, rule_id, errors),
        Condition::PathMatches(op)
        | Condition::HostMatches(op)
        | Condition::BodyMatches(op) => {
            check_match_op_regex(op, rule_id, errors);
        }
        Condition::HeaderMatches { op, .. }
        | Condition::QueryMatches { op, .. }
        | Condition::CookieMatches { op, .. }
        | Condition::JwtClaim { op, .. } => {
            check_match_op_regex(op, rule_id, errors);
        }
        _ => {}
    }
}

fn check_match_op_regex(op: &MatchOp, rule_id: &str, errors: &mut Vec<LintError>) {
    if let MatchOp::Regex(pattern) = op {
        if let Err(e) = regex::Regex::new(pattern) {
            errors.push(LintError::InvalidRegex {
                rule_id: rule_id.to_string(),
                pattern: pattern.clone(),
                err: e.to_string(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::ast::{RuleAction, Scope};

    fn make_rule(id: &str, priority: u32, cond: Condition) -> Rule {
        Rule {
            id: id.into(),
            priority,
            scope: Scope::Global,
            condition: cond,
            action: RuleAction::Allow,
        }
    }

    #[test]
    fn lint_valid_rules() {
        let rules = vec![
            make_rule("r1", 100, Condition::True),
            make_rule("r2", 200, Condition::True),
        ];
        assert!(lint(&rules).is_empty());
    }

    #[test]
    fn lint_duplicate_ids() {
        let rules = vec![
            make_rule("dup", 1, Condition::True),
            make_rule("dup", 2, Condition::True),
        ];
        let errs = lint(&rules);
        assert!(errs.iter().any(|e| matches!(e, LintError::DuplicateId(id) if id == "dup")));
    }

    #[test]
    fn lint_priority_out_of_range() {
        let rules = vec![make_rule("r1", 99999, Condition::True)];
        let errs = lint(&rules);
        assert!(errs.iter().any(|e| matches!(e, LintError::PriorityOutOfRange { .. })));
    }

    #[test]
    fn lint_nesting_too_deep() {
        // Build a chain 10 levels deep.
        let mut cond = Condition::True;
        for _ in 0..10 {
            cond = Condition::Not(Box::new(cond));
        }
        let rules = vec![make_rule("deep", 1, cond)];
        let errs = lint(&rules);
        assert!(errs.iter().any(|e| matches!(e, LintError::NestingTooDeep { .. })));
    }

    #[test]
    fn lint_invalid_regex() {
        let rules = vec![make_rule(
            "bad-regex",
            1,
            Condition::PathMatches(MatchOp::Regex("[invalid".into())),
        )];
        let errs = lint(&rules);
        assert!(errs.iter().any(|e| matches!(e, LintError::InvalidRegex { .. })));
    }

    #[test]
    fn lint_valid_regex() {
        let rules = vec![make_rule(
            "good-regex",
            1,
            Condition::PathMatches(MatchOp::Regex(r"^/api/\d+$".into())),
        )];
        assert!(lint(&rules).is_empty());
    }

    #[test]
    fn lint_max_priority_accepted() {
        let rules = vec![make_rule("max-pri", 10_000, Condition::True)];
        assert!(lint(&rules).is_empty());
    }

    #[test]
    fn lint_depth_exactly_8_accepted() {
        let mut cond = Condition::True;
        for _ in 0..7 {
            cond = Condition::Not(Box::new(cond));
        }
        // depth = 8 (7 Nots + 1 True)
        let rules = vec![make_rule("ok-depth", 1, cond)];
        assert!(lint(&rules).is_empty());
    }
}
