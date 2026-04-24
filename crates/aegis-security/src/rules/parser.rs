use std::collections::HashSet;

use super::ast::Rule;

/// Parse a YAML string into a list of rules.
pub fn parse(yaml: &str) -> Result<Vec<Rule>, ParseError> {
    let rules: Vec<Rule> =
        serde_yaml::from_str(yaml).map_err(|e| ParseError::Yaml(e.to_string()))?;

    validate_no_duplicate_ids(&rules)?;

    Ok(rules)
}

/// Parse errors.
#[derive(Debug)]
pub enum ParseError {
    Yaml(String),
    DuplicateId(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Yaml(e) => write!(f, "YAML parse error: {e}"),
            ParseError::DuplicateId(id) => write!(f, "duplicate rule id: {id}"),
        }
    }
}

fn validate_no_duplicate_ids(rules: &[Rule]) -> Result<(), ParseError> {
    let mut seen = HashSet::new();
    for rule in rules {
        if !seen.insert(&rule.id) {
            return Err(ParseError::DuplicateId(rule.id.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::ast::{RuleAction, Scope};

    const BLOCK_EVIL: &str = r#"
- id: block-evil
  priority: 100
  when:
    path_matches:
      exact: "/evil"
  then:
    block:
      status: 403
"#;

    const TWO_RULES: &str = r#"
- id: block-evil
  priority: 100
  when:
    path_matches:
      exact: "/evil"
  then:
    block:
      status: 403

- id: log-admin
  priority: 50
  scope:
    route: admin-panel
  when:
    path_matches:
      prefix: "/admin"
  then: log_only
"#;

    const DUPLICATE_IDS: &str = r#"
- id: dup
  priority: 1
  when: true
  then: allow

- id: dup
  priority: 2
  when: true
  then: log_only
"#;

    const COMPLEX_RULE: &str = r#"
- id: complex-and
  priority: 200
  when:
    all:
      - method: ["POST", "PUT"]
      - path_matches:
          prefix: "/api"
      - header_matches:
          name: content-type
          op:
            contains: "json"
  then:
    raise_risk: 10
"#;

    const IP_RULE: &str = r#"
- id: ip-block
  priority: 300
  when:
    ip_in:
      - "10.0.0.0/8"
      - "192.168.1.0/24"
  then:
    block:
      status: 403
"#;

    #[test]
    fn parse_single_rule() {
        let rules = parse(BLOCK_EVIL).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "block-evil");
        assert_eq!(rules[0].priority, 100);
        assert!(matches!(rules[0].action, RuleAction::Block { status: 403 }));
    }

    #[test]
    fn parse_two_rules() {
        let rules = parse(TWO_RULES).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].id, "block-evil");
        assert_eq!(rules[1].id, "log-admin");
        assert!(matches!(rules[1].scope, Scope::Route(ref r) if r == "admin-panel"));
        assert!(matches!(rules[1].action, RuleAction::LogOnly));
    }

    #[test]
    fn reject_duplicate_ids() {
        let result = parse(DUPLICATE_IDS);
        assert!(matches!(result, Err(ParseError::DuplicateId(ref id)) if id == "dup"));
    }

    #[test]
    fn parse_complex_all_condition() {
        let rules = parse(COMPLEX_RULE).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "complex-and");
        assert!(matches!(rules[0].action, RuleAction::RaiseRisk(10)));
    }

    #[test]
    fn parse_ip_rule() {
        let rules = parse(IP_RULE).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "ip-block");
    }

    #[test]
    fn reject_invalid_yaml() {
        let result = parse("not valid: [yaml: {");
        assert!(matches!(result, Err(ParseError::Yaml(_))));
    }

    #[test]
    fn default_scope_is_global() {
        let rules = parse(BLOCK_EVIL).unwrap();
        assert_eq!(rules[0].scope, Scope::Global);
    }

    #[test]
    fn default_block_status_is_403() {
        let yaml = r#"
- id: default-status
  when: true
  then:
    block: {}
"#;
        let rules = parse(yaml).unwrap();
        assert!(matches!(rules[0].action, RuleAction::Block { status: 403 }));
    }

    #[test]
    fn parse_any_condition() {
        let yaml = r#"
- id: any-rule
  when:
    any:
      - path_matches:
          exact: "/a"
      - path_matches:
          exact: "/b"
  then: allow
"#;
        let rules = parse(yaml).unwrap();
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn parse_not_condition() {
        let yaml = r#"
- id: not-rule
  when:
    not:
      method: ["DELETE"]
  then: allow
"#;
        let rules = parse(yaml).unwrap();
        assert_eq!(rules.len(), 1);
    }
}
