use std::collections::HashMap;

/// OPA decision request.
#[derive(Clone, Debug)]
pub struct OpaInput {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub user: Option<String>,
    pub claims: HashMap<String, String>,
}

/// OPA decision result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpaDecision {
    Allow,
    Deny { reason: String },
}

/// OPA callout client trait.
#[async_trait::async_trait]
pub trait OpaClient: Send + Sync {
    async fn decide(&self, policy: &str, input: &OpaInput) -> aegis_core::Result<OpaDecision>;
}

/// Stub OPA client for testing.
pub struct StubOpaClient {
    pub decisions: HashMap<String, OpaDecision>,
}

impl StubOpaClient {
    pub fn new() -> Self {
        Self {
            decisions: HashMap::new(),
        }
    }

    pub fn set_decision(&mut self, policy: &str, decision: OpaDecision) {
        self.decisions.insert(policy.to_string(), decision);
    }
}

impl Default for StubOpaClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl OpaClient for StubOpaClient {
    async fn decide(&self, policy: &str, _input: &OpaInput) -> aegis_core::Result<OpaDecision> {
        Ok(self
            .decisions
            .get(policy)
            .cloned()
            .unwrap_or(OpaDecision::Deny {
                reason: "no policy found".into(),
            }))
    }
}

/// Compute a cache key for OPA decisions.
pub fn cache_key(policy: &str, input: &OpaInput) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(policy.as_bytes());
    hasher.update(input.method.as_bytes());
    hasher.update(input.path.as_bytes());
    if let Some(user) = &input.user {
        hasher.update(user.as_bytes());
    }
    for (k, v) in &input.claims {
        hasher.update(k.as_bytes());
        hasher.update(v.as_bytes());
    }
    hasher.finalize().to_hex()[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_input() -> OpaInput {
        OpaInput {
            method: "GET".into(),
            path: "/api/data".into(),
            headers: HashMap::new(),
            user: Some("user-1".into()),
            claims: [("role".into(), "admin".into())].into(),
        }
    }

    #[tokio::test]
    async fn opa_allow() {
        let mut client = StubOpaClient::new();
        client.set_decision("authz", OpaDecision::Allow);
        let result = client.decide("authz", &test_input()).await.unwrap();
        assert_eq!(result, OpaDecision::Allow);
    }

    #[tokio::test]
    async fn opa_deny() {
        let mut client = StubOpaClient::new();
        client.set_decision("authz", OpaDecision::Deny { reason: "forbidden".into() });
        let result = client.decide("authz", &test_input()).await.unwrap();
        assert!(matches!(result, OpaDecision::Deny { .. }));
    }

    #[tokio::test]
    async fn opa_unknown_policy_denies() {
        let client = StubOpaClient::new();
        let result = client.decide("unknown", &test_input()).await.unwrap();
        assert!(matches!(result, OpaDecision::Deny { .. }));
    }

    #[test]
    fn cache_key_deterministic() {
        let input = test_input();
        let a = cache_key("authz", &input);
        let b = cache_key("authz", &input);
        assert_eq!(a, b);
    }

    #[test]
    fn cache_key_different_policy() {
        let input = test_input();
        let a = cache_key("authz", &input);
        let b = cache_key("rbac", &input);
        assert_ne!(a, b);
    }

    #[test]
    fn cache_key_different_user() {
        let mut i1 = test_input();
        let mut i2 = test_input();
        i1.user = Some("alice".into());
        i2.user = Some("bob".into());
        assert_ne!(cache_key("authz", &i1), cache_key("authz", &i2));
    }
}
