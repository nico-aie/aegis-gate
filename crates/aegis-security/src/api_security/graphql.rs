/// GraphQL query guard.
///
/// Computes depth, node count, and complexity. Rejects queries beyond limits.
use std::collections::HashSet;

/// GraphQL guard configuration.
#[derive(Clone, Debug)]
pub struct GraphqlConfig {
    pub max_depth: u32,
    pub max_node_count: u32,
    pub max_complexity: u32,
    pub allow_introspection: bool,
    pub persisted_queries: Option<HashSet<String>>,
}

impl Default for GraphqlConfig {
    fn default() -> Self {
        Self {
            max_depth: 10,
            max_node_count: 500,
            max_complexity: 1000,
            allow_introspection: false,
            persisted_queries: None,
        }
    }
}

/// GraphQL validation result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GraphqlResult {
    Allowed,
    Rejected { reason: String },
}

/// Simplified GraphQL query analysis.
///
/// Counts nesting depth by `{` and `}` balance, and field nodes by word tokens.
pub fn analyze_query(query: &str, config: &GraphqlConfig) -> GraphqlResult {
    // Check introspection.
    if !config.allow_introspection && (query.contains("__schema") || query.contains("__type")) {
        return GraphqlResult::Rejected {
            reason: "introspection is disabled".into(),
        };
    }

    let mut depth: u32 = 0;
    let mut max_depth: u32 = 0;
    let mut node_count: u32 = 0;

    for ch in query.chars() {
        match ch {
            '{' => {
                depth += 1;
                if depth > max_depth {
                    max_depth = depth;
                }
            }
            '}' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }

    // Count field-like tokens (simplified: words that aren't keywords).
    let keywords = ["query", "mutation", "subscription", "fragment", "on", "true", "false", "null"];
    for word in query.split(|c: char| !c.is_alphanumeric() && c != '_') {
        if !word.is_empty() && !keywords.contains(&word) {
            node_count += 1;
        }
    }

    // Simple complexity = depth * node_count.
    let complexity = max_depth * node_count;

    if max_depth > config.max_depth {
        return GraphqlResult::Rejected {
            reason: format!("query depth {max_depth} exceeds max {}", config.max_depth),
        };
    }

    if node_count > config.max_node_count {
        return GraphqlResult::Rejected {
            reason: format!("node count {node_count} exceeds max {}", config.max_node_count),
        };
    }

    if complexity > config.max_complexity {
        return GraphqlResult::Rejected {
            reason: format!("complexity {complexity} exceeds max {}", config.max_complexity),
        };
    }

    GraphqlResult::Allowed
}

/// Check a persisted query by ID.
pub fn check_persisted_query(
    query_id: &str,
    config: &GraphqlConfig,
) -> GraphqlResult {
    match &config.persisted_queries {
        Some(allowed) => {
            if allowed.contains(query_id) {
                GraphqlResult::Allowed
            } else {
                GraphqlResult::Rejected {
                    reason: format!("unknown persisted query id: {query_id}"),
                }
            }
        }
        None => GraphqlResult::Allowed, // No allowlist → allow all.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_query_allowed() {
        let query = "query { user { name email } }";
        assert_eq!(analyze_query(query, &GraphqlConfig::default()), GraphqlResult::Allowed);
    }

    #[test]
    fn deep_nested_query_rejected() {
        // 12-deep nesting.
        let query = "{ a { b { c { d { e { f { g { h { i { j { k { l { m } } } } } } } } } } } } }";
        let config = GraphqlConfig { max_depth: 10, ..Default::default() };
        let result = analyze_query(query, &config);
        assert!(matches!(result, GraphqlResult::Rejected { .. }));
    }

    #[test]
    fn introspection_blocked() {
        let query = "{ __schema { types { name } } }";
        let config = GraphqlConfig { allow_introspection: false, ..Default::default() };
        let result = analyze_query(query, &config);
        assert!(matches!(result, GraphqlResult::Rejected { reason } if reason.contains("introspection")));
    }

    #[test]
    fn introspection_allowed_when_enabled() {
        let query = "{ __schema { types { name } } }";
        let config = GraphqlConfig { allow_introspection: true, ..Default::default() };
        assert_eq!(analyze_query(query, &config), GraphqlResult::Allowed);
    }

    #[test]
    fn type_introspection_blocked() {
        let query = r#"{ __type(name: "User") { fields { name } } }"#;
        let config = GraphqlConfig { allow_introspection: false, ..Default::default() };
        let result = analyze_query(query, &config);
        assert!(matches!(result, GraphqlResult::Rejected { .. }));
    }

    #[test]
    fn persisted_query_allowed() {
        let config = GraphqlConfig {
            persisted_queries: Some(["q1".into(), "q2".into()].into()),
            ..Default::default()
        };
        assert_eq!(check_persisted_query("q1", &config), GraphqlResult::Allowed);
    }

    #[test]
    fn unknown_persisted_query_rejected() {
        let config = GraphqlConfig {
            persisted_queries: Some(["q1".into()].into()),
            ..Default::default()
        };
        let result = check_persisted_query("unknown-id", &config);
        assert!(matches!(result, GraphqlResult::Rejected { .. }));
    }

    #[test]
    fn no_persisted_allowlist_allows_all() {
        let config = GraphqlConfig { persisted_queries: None, ..Default::default() };
        assert_eq!(check_persisted_query("any-id", &config), GraphqlResult::Allowed);
    }

    #[test]
    fn mutation_allowed() {
        let query = "mutation { createUser(name: \"Bob\") { id } }";
        assert_eq!(analyze_query(query, &GraphqlConfig::default()), GraphqlResult::Allowed);
    }
}
