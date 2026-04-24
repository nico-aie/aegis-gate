pub mod ast;
pub mod eval;
pub mod linter;
pub mod parser;

use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;

use ast::Rule;
use linter::LintError;
use parser::ParseError;

pub use ast::{Condition, MatchOp, RuleAction, Scope};
pub use eval::evaluate;
pub use parser::parse;

/// Thread-safe rule set with hot-reload.
pub struct RuleSet {
    rules: ArcSwap<Vec<Rule>>,
}

/// Errors from RuleSet operations.
#[derive(Debug)]
pub enum RuleSetError {
    Io(std::io::Error),
    Parse(ParseError),
    Lint(Vec<LintError>),
}

impl std::fmt::Display for RuleSetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleSetError::Io(e) => write!(f, "IO error: {e}"),
            RuleSetError::Parse(e) => write!(f, "parse error: {e}"),
            RuleSetError::Lint(errs) => {
                write!(f, "lint errors: ")?;
                for e in errs {
                    write!(f, "{e}; ")?;
                }
                Ok(())
            }
        }
    }
}

impl RuleSet {
    /// Create a new empty rule set.
    pub fn new() -> Self {
        Self {
            rules: ArcSwap::from_pointee(Vec::new()),
        }
    }

    /// Create from an already-parsed set of rules.
    pub fn from_rules(rules: Vec<Rule>) -> Self {
        Self {
            rules: ArcSwap::from_pointee(rules),
        }
    }

    /// Load rules from a YAML file.  Lints before accepting.
    pub fn load(path: &Path) -> Result<Self, RuleSetError> {
        let yaml = std::fs::read_to_string(path).map_err(RuleSetError::Io)?;
        let rules = parser::parse(&yaml).map_err(RuleSetError::Parse)?;
        let lint_errs = linter::lint(&rules);
        if !lint_errs.is_empty() {
            return Err(RuleSetError::Lint(lint_errs));
        }
        Ok(Self::from_rules(rules))
    }

    /// Reload rules from a YAML file.  On failure, the existing rules are kept.
    pub fn reload(&self, path: &Path) -> Result<(), RuleSetError> {
        let yaml = std::fs::read_to_string(path).map_err(RuleSetError::Io)?;
        let rules = parser::parse(&yaml).map_err(RuleSetError::Parse)?;
        let lint_errs = linter::lint(&rules);
        if !lint_errs.is_empty() {
            return Err(RuleSetError::Lint(lint_errs));
        }
        self.rules.store(Arc::new(rules));
        Ok(())
    }

    /// Get a snapshot of the current rules.
    pub fn snapshot(&self) -> Arc<Vec<Rule>> {
        self.rules.load_full()
    }

    /// Number of rules currently loaded.
    pub fn len(&self) -> usize {
        self.rules.load().len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.load().is_empty()
    }
}

impl Default for RuleSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn valid_rules_yaml() -> &'static str {
        r#"
- id: block-evil
  priority: 100
  when:
    path_matches:
      exact: "/evil"
  then:
    block:
      status: 403
"#
    }

    fn invalid_rules_yaml() -> &'static str {
        "not: [valid: yaml: for: rules"
    }

    fn lint_fail_yaml() -> &'static str {
        r#"
- id: bad
  priority: 99999
  when: true
  then: allow
"#
    }

    #[test]
    fn load_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.yaml");
        std::fs::write(&path, valid_rules_yaml()).unwrap();

        let rs = RuleSet::load(&path).unwrap();
        assert_eq!(rs.len(), 1);
    }

    #[test]
    fn load_invalid_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.yaml");
        std::fs::write(&path, invalid_rules_yaml()).unwrap();

        let result = RuleSet::load(&path);
        assert!(matches!(result, Err(RuleSetError::Parse(_))));
    }

    #[test]
    fn load_lint_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.yaml");
        std::fs::write(&path, lint_fail_yaml()).unwrap();

        let result = RuleSet::load(&path);
        assert!(matches!(result, Err(RuleSetError::Lint(_))));
    }

    #[test]
    fn reload_keeps_old_on_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.yaml");
        std::fs::write(&path, valid_rules_yaml()).unwrap();

        let rs = RuleSet::load(&path).unwrap();
        assert_eq!(rs.len(), 1);

        // Overwrite with bad content.
        std::fs::write(&path, invalid_rules_yaml()).unwrap();
        let result = rs.reload(&path);
        assert!(result.is_err());

        // Old rules still in place.
        assert_eq!(rs.len(), 1);
    }

    #[test]
    fn reload_updates_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.yaml");
        std::fs::write(&path, valid_rules_yaml()).unwrap();

        let rs = RuleSet::load(&path).unwrap();
        assert_eq!(rs.len(), 1);

        // Add a second rule.
        let two_rules = r#"
- id: r1
  priority: 100
  when: true
  then: allow

- id: r2
  priority: 50
  when: true
  then: log_only
"#;
        std::fs::write(&path, two_rules).unwrap();
        rs.reload(&path).unwrap();
        assert_eq!(rs.len(), 2);
    }

    #[test]
    fn empty_ruleset() {
        let rs = RuleSet::new();
        assert!(rs.is_empty());
        assert_eq!(rs.len(), 0);
    }

    #[test]
    fn snapshot_returns_current() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.yaml");
        std::fs::write(&path, valid_rules_yaml()).unwrap();

        let rs = RuleSet::load(&path).unwrap();
        let snap = rs.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].id, "block-evil");
    }
}
