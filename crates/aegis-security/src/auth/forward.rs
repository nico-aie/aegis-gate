use std::collections::HashMap;

/// Forward auth configuration.
#[derive(Clone, Debug)]
pub struct ForwardAuthConfig {
    pub address: String,
    pub allowed_response_headers: Vec<String>,
}

/// Forward auth result.
#[derive(Clone, Debug)]
pub struct ForwardAuthResult {
    pub allowed: bool,
    pub status: u16,
    pub headers: HashMap<String, String>,
}

/// Forward auth client trait.
///
/// In production, performs `GET <address><original_path>` and inspects the response.
#[async_trait::async_trait]
pub trait ForwardAuthClient: Send + Sync {
    async fn check(
        &self,
        config: &ForwardAuthConfig,
        original_path: &str,
        request_headers: &HashMap<String, String>,
    ) -> aegis_core::Result<ForwardAuthResult>;
}

/// Stub forward auth client for testing.
pub struct StubForwardAuth {
    pub result: ForwardAuthResult,
}

#[async_trait::async_trait]
impl ForwardAuthClient for StubForwardAuth {
    async fn check(
        &self,
        _config: &ForwardAuthConfig,
        _path: &str,
        _headers: &HashMap<String, String>,
    ) -> aegis_core::Result<ForwardAuthResult> {
        Ok(self.result.clone())
    }
}

/// Process forward auth result: filter headers to only allowed ones.
pub fn filter_response_headers(
    result: &ForwardAuthResult,
    config: &ForwardAuthConfig,
) -> HashMap<String, String> {
    result
        .headers
        .iter()
        .filter(|(k, _)| config.allowed_response_headers.contains(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> ForwardAuthConfig {
        ForwardAuthConfig {
            address: "http://auth-svc:9090".into(),
            allowed_response_headers: vec!["x-user-id".into(), "x-user-role".into()],
        }
    }

    #[tokio::test]
    async fn auth_200_allowed() {
        let mut headers = HashMap::new();
        headers.insert("x-user-id".into(), "user-123".into());
        headers.insert("x-user-role".into(), "admin".into());
        headers.insert("x-internal".into(), "secret".into());

        let client = StubForwardAuth {
            result: ForwardAuthResult {
                allowed: true,
                status: 200,
                headers,
            },
        };

        let config = test_config();
        let result = client.check(&config, "/api/data", &HashMap::new()).await.unwrap();
        assert!(result.allowed);
        assert_eq!(result.status, 200);

        let filtered = filter_response_headers(&result, &config);
        assert_eq!(filtered.get("x-user-id").unwrap(), "user-123");
        assert_eq!(filtered.get("x-user-role").unwrap(), "admin");
        assert!(!filtered.contains_key("x-internal"));
    }

    #[tokio::test]
    async fn auth_401_blocked() {
        let client = StubForwardAuth {
            result: ForwardAuthResult {
                allowed: false,
                status: 401,
                headers: HashMap::new(),
            },
        };

        let config = test_config();
        let result = client.check(&config, "/api/data", &HashMap::new()).await.unwrap();
        assert!(!result.allowed);
        assert_eq!(result.status, 401);
    }

    #[test]
    fn filter_only_allowed_headers() {
        let mut headers = HashMap::new();
        headers.insert("x-user-id".into(), "u1".into());
        headers.insert("x-secret".into(), "s".into());

        let result = ForwardAuthResult {
            allowed: true,
            status: 200,
            headers,
        };
        let config = test_config();
        let filtered = filter_response_headers(&result, &config);
        assert_eq!(filtered.len(), 1);
        assert!(filtered.contains_key("x-user-id"));
    }
}
