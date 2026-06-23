//! Tier-1A — GraphQL query guard, data-plane runtime.
//!
//! Thin orchestration layer over
//! [`aegis_security::api_security::graphql`]: this module decides *whether*
//! a request is a GraphQL request worth inspecting, pulls the `query` string
//! out of the JSON POST body, and delegates the actual depth / node-count /
//! complexity / introspection analysis to the (already-tested)
//! [`analyze_query`] function.
//!
//! **Fail-open by construction.** The guard only ever returns
//! [`GraphqlGuardOutcome::Rejected`] when it positively parsed a GraphQL
//! query on a configured endpoint and that query broke a limit. A disabled
//! guard, a non-`POST` request, a path that isn't a configured GraphQL
//! endpoint, or a body that isn't a parseable `{"query": "..."}` object all
//! resolve to [`GraphqlGuardOutcome::Skipped`] — the request passes through
//! untouched. The guard never blocks on ambiguity.
//!
//! The live config is held behind an [`arc_swap::ArcSwap`] on
//! [`ProxyContext`](crate::proxy::ProxyContext) so the config plane can
//! hot-swap the whole limits struct fleet-wide without a restart (see
//! `config_source::reload::apply_cfg_change_to_graphql`).

use aegis_core::config::GraphqlGuardConfig;
use aegis_security::api_security::graphql::{analyze_query, GraphqlConfig, GraphqlResult};
use http::Method;

/// Runtime form of the GraphQL guard, derived from
/// [`GraphqlGuardConfig`] at boot / on every config reload.
#[derive(Clone, Debug)]
pub struct GraphqlGuard {
    enabled: bool,
    paths: Vec<String>,
    limits: GraphqlConfig,
}

/// Result of consulting the guard for one request.
///
/// `#[must_use]` because this is a security decision — dropping it on the
/// floor (`guard.check(...);`) would silently forward an unguarded request.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GraphqlGuardOutcome {
    /// Not a GraphQL request the guard inspects (disabled, non-`POST`,
    /// non-matching path, or an unparseable body) — forward untouched.
    Skipped,
    /// Inspected and within every configured limit.
    Allowed,
    /// Inspected and over a limit (or an introspection query while
    /// introspection is disabled). `reason` is operator-facing.
    Rejected { reason: String },
}

impl GraphqlGuard {
    /// Build the runtime guard from its YAML-facing config. The
    /// `persisted_queries` allowlist is out of scope for the caps-only
    /// wire-in, so it is always `None` here.
    pub fn from_config(cfg: &GraphqlGuardConfig) -> Self {
        Self {
            enabled: cfg.enabled,
            paths: cfg.paths.clone(),
            limits: GraphqlConfig {
                max_depth: cfg.max_depth,
                max_node_count: cfg.max_node_count,
                max_complexity: cfg.max_complexity,
                allow_introspection: cfg.allow_introspection,
                persisted_queries: None,
            },
        }
    }

    /// Whether the guard is active at all (cheap pre-check the data plane
    /// uses to avoid touching the body for the common non-GraphQL case).
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Inspect one request. `path` is the request path (no query string);
    /// `body` is the already-buffered request body.
    pub fn check(&self, method: &Method, path: &str, body: &[u8]) -> GraphqlGuardOutcome {
        if !self.enabled {
            return GraphqlGuardOutcome::Skipped;
        }
        // GraphQL-over-HTTP queries are POSTs. GET-based GraphQL exists but
        // carries the query in the URL and is read-only by spec; gating on
        // POST keeps the body-parse path tight and avoids false positives on
        // unrelated GETs to the same path.
        if method != Method::POST {
            return GraphqlGuardOutcome::Skipped;
        }
        if !self.path_matches(path) {
            return GraphqlGuardOutcome::Skipped;
        }
        // Fail-open: a body that isn't a JSON object carrying a string
        // `query` is not something this guard understands — pass it through.
        let Some(query) = extract_query(body) else {
            return GraphqlGuardOutcome::Skipped;
        };
        match analyze_query(&query, &self.limits) {
            GraphqlResult::Allowed => GraphqlGuardOutcome::Allowed,
            GraphqlResult::Rejected { reason } => GraphqlGuardOutcome::Rejected { reason },
        }
    }

    fn path_matches(&self, path: &str) -> bool {
        self.paths.iter().any(|p| p == path)
    }
}

/// Minimal envelope for a GraphQL-over-HTTP POST body. Only `query` is
/// read; `variables` / `operationName` and any other fields are ignored by
/// serde without being materialised, so we never build a full
/// `serde_json::Value` tree on the data-plane hot path.
#[derive(serde::Deserialize)]
struct GraphqlEnvelope {
    query: Option<String>,
}

/// Pull the GraphQL `query` string out of a JSON POST body.
///
/// Returns `None` (→ fail-open skip) for any body that isn't a JSON object
/// with a string `query` field: non-JSON, a JSON array, a missing/`null`
/// query, or a non-string query. Persisted-query payloads (`{"id": "..."}`
/// with no `query`) also skip — they carry no query to analyze.
fn extract_query(body: &[u8]) -> Option<String> {
    let envelope: GraphqlEnvelope = serde_json::from_slice(body).ok()?;
    let query = envelope.query?;
    if query.trim().is_empty() {
        return None;
    }
    Some(query)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(enabled: bool) -> GraphqlGuardConfig {
        GraphqlGuardConfig {
            enabled,
            paths: vec!["/graphql".to_string()],
            max_depth: 10,
            max_node_count: 500,
            max_complexity: 1000,
            allow_introspection: false,
        }
    }

    fn body(query: &str) -> Vec<u8> {
        serde_json::json!({ "query": query }).to_string().into_bytes()
    }

    #[test]
    fn disabled_guard_skips() {
        let g = GraphqlGuard::from_config(&cfg(false));
        assert_eq!(
            g.check(&Method::POST, "/graphql", &body("{ a { b } }")),
            GraphqlGuardOutcome::Skipped,
        );
    }

    #[test]
    fn non_post_skips() {
        let g = GraphqlGuard::from_config(&cfg(true));
        assert_eq!(
            g.check(&Method::GET, "/graphql", &body("{ a { b } }")),
            GraphqlGuardOutcome::Skipped,
        );
    }

    #[test]
    fn non_matching_path_skips() {
        let g = GraphqlGuard::from_config(&cfg(true));
        assert_eq!(
            g.check(&Method::POST, "/api/users", &body("{ a { b } }")),
            GraphqlGuardOutcome::Skipped,
        );
    }

    #[test]
    fn simple_query_allowed() {
        let g = GraphqlGuard::from_config(&cfg(true));
        assert_eq!(
            g.check(&Method::POST, "/graphql", &body("query { user { name email } }")),
            GraphqlGuardOutcome::Allowed,
        );
    }

    #[test]
    fn deep_query_rejected() {
        let g = GraphqlGuard::from_config(&cfg(true));
        let deep = "{ a { b { c { d { e { f { g { h { i { j { k { l { m } } } } } } } } } } } } }";
        assert!(matches!(
            g.check(&Method::POST, "/graphql", &body(deep)),
            GraphqlGuardOutcome::Rejected { .. },
        ));
    }

    #[test]
    fn introspection_rejected_when_disabled() {
        let g = GraphqlGuard::from_config(&cfg(true));
        let out = g.check(&Method::POST, "/graphql", &body("{ __schema { types { name } } }"));
        assert!(matches!(
            out,
            GraphqlGuardOutcome::Rejected { reason } if reason.contains("introspection"),
        ));
    }

    #[test]
    fn introspection_allowed_when_enabled() {
        let mut c = cfg(true);
        c.allow_introspection = true;
        let g = GraphqlGuard::from_config(&c);
        assert_eq!(
            g.check(&Method::POST, "/graphql", &body("{ __schema { types { name } } }")),
            GraphqlGuardOutcome::Allowed,
        );
    }

    #[test]
    fn malformed_json_body_skips() {
        // Fail-open: a non-JSON body on the GraphQL path is NOT blocked.
        let g = GraphqlGuard::from_config(&cfg(true));
        assert_eq!(
            g.check(&Method::POST, "/graphql", b"this is not json"),
            GraphqlGuardOutcome::Skipped,
        );
    }

    #[test]
    fn json_without_query_field_skips() {
        let g = GraphqlGuard::from_config(&cfg(true));
        let b = serde_json::json!({ "id": "persisted-123" }).to_string().into_bytes();
        assert_eq!(
            g.check(&Method::POST, "/graphql", &b),
            GraphqlGuardOutcome::Skipped,
        );
    }

    #[test]
    fn empty_query_string_skips() {
        let g = GraphqlGuard::from_config(&cfg(true));
        assert_eq!(
            g.check(&Method::POST, "/graphql", &body("   ")),
            GraphqlGuardOutcome::Skipped,
        );
    }

    #[test]
    fn non_string_query_skips() {
        let g = GraphqlGuard::from_config(&cfg(true));
        let b = serde_json::json!({ "query": 42 }).to_string().into_bytes();
        assert_eq!(
            g.check(&Method::POST, "/graphql", &b),
            GraphqlGuardOutcome::Skipped,
        );
    }

    #[test]
    fn secondary_configured_path_matches() {
        let mut c = cfg(true);
        c.paths = vec!["/graphql".to_string(), "/api/graphql".to_string()];
        let g = GraphqlGuard::from_config(&c);
        let deep = "{ a { b { c { d { e { f { g { h { i { j { k { l { m } } } } } } } } } } } } }";
        assert!(matches!(
            g.check(&Method::POST, "/api/graphql", &body(deep)),
            GraphqlGuardOutcome::Rejected { .. },
        ));
    }

    #[test]
    fn complexity_violation_rejected() {
        // Tight complexity budget: a modestly nested multi-field query
        // (depth * node_count) trips the complexity cap even under the
        // depth / node-count caps.
        let mut c = cfg(true);
        c.max_complexity = 5;
        let g = GraphqlGuard::from_config(&c);
        assert!(matches!(
            g.check(&Method::POST, "/graphql", &body("query { a { b c d } }")),
            GraphqlGuardOutcome::Rejected { reason } if reason.contains("complexity"),
        ));
    }
}
