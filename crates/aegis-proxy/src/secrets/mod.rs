//! Secrets resolver — resolves `${secret:<provider>:<path>[#field]}` in config.
//!
//! Built-in providers (always available):
//! - `env` — read from process environment.
//! - `file` — read first line from a file path.
//!
//! Feature-gated providers:
//! - `vault` (B2-T1 — Phase B) — read from a HashiCorp Vault
//!   KV-v2 mount via the [`vault`] submodule. Requires the
//!   `aegis-proxy/vault` Cargo feature.
//!
//! Stubs (return `NotImplemented` until their respective tasks land):
//! - `aws` (B2-T2), `gcp` (B2-T3), `azure` (B2-T4), `hsm` (B6-T4).
//!
//! ## Sync vs async
//!
//! [`resolve_secret`] / [`expand_secrets`] are **synchronous** —
//! they cover the env + file resolvers used at config-parse time
//! (before the async runtime is up). Network-backed providers
//! (vault, aws, …) require [`resolve_secret_async`] /
//! [`expand_secrets_async`]; the sync entry point returns
//! `NotImplemented` for those even when their feature is on, so
//! callers know to retry under tokio.

// Shared helpers for the "raw-string-may-be-JSON" cloud secret
// shape (aws, gcp, azure). Vault has its own structure (KV-v2
// returns an already-parsed map) so it doesn't use this helper.
#[cfg(any(feature = "aws", feature = "gcp", feature = "azure"))]
mod json_field;

#[cfg(feature = "aws")]
pub mod aws;

#[cfg(feature = "azure")]
pub mod azure;

#[cfg(feature = "gcp")]
pub mod gcp;

#[cfg(feature = "vault")]
pub mod vault;

/// Resolved secret material.  Uses a simple wrapper; in production this would
/// use `zeroize::Zeroizing<String>` for automatic memory clearing.
#[derive(Debug, Clone)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(s: String) -> Self {
        Self(s)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        // Zero out the memory (best-effort without zeroize crate).
        unsafe {
            let bytes = self.0.as_bytes_mut();
            for b in bytes.iter_mut() {
                std::ptr::write_volatile(b, 0);
            }
        }
    }
}

/// Error from secret resolution.
#[derive(Debug)]
pub enum SecretError {
    UnknownProvider(String),
    NotFound(String),
    NotImplemented(String),
    ParseError(String),
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretError::UnknownProvider(p) => write!(f, "unknown secret provider: {p}"),
            SecretError::NotFound(p) => write!(f, "secret not found: {p}"),
            SecretError::NotImplemented(p) => write!(f, "provider not implemented: {p}"),
            SecretError::ParseError(m) => write!(f, "secret parse error: {m}"),
        }
    }
}

/// Parse a secret reference string: `${secret:<provider>:<path>[#field]}`.
pub fn parse_secret_ref(s: &str) -> Option<(String, String, Option<String>)> {
    let s = s.strip_prefix("${secret:")?.strip_suffix('}')?;
    let colon = s.find(':')?;
    let provider = s[..colon].to_string();
    let rest = &s[colon + 1..];

    if let Some(hash) = rest.find('#') {
        let path = rest[..hash].to_string();
        let field = rest[hash + 1..].to_string();
        Some((provider, path, Some(field)))
    } else {
        Some((provider, rest.to_string(), None))
    }
}

/// Resolve a secret reference synchronously.
///
/// Handles env + file. Network-backed providers (`vault`, `aws`,
/// …) return `NotImplemented` even when their Cargo feature is
/// on — call [`resolve_secret_async`] for those.
pub fn resolve_secret(
    provider: &str,
    path: &str,
    _field: Option<&str>,
) -> Result<SecretValue, SecretError> {
    match provider {
        "env" => {
            let val = std::env::var(path)
                .map_err(|_| SecretError::NotFound(format!("env:{path}")))?;
            Ok(SecretValue::new(val))
        }
        "file" => {
            let contents = std::fs::read_to_string(path)
                .map_err(|_| SecretError::NotFound(format!("file:{path}")))?;
            let trimmed = contents.trim().to_string();
            Ok(SecretValue::new(trimmed))
        }
        "vault" => Err(SecretError::NotImplemented(
            "vault: sync resolver does not handle network providers — use resolve_secret_async".into(),
        )),
        "aws" => Err(SecretError::NotImplemented(
            "aws: sync resolver does not handle network providers — use resolve_secret_async".into(),
        )),
        "gcp" => Err(SecretError::NotImplemented(
            "gcp: sync resolver does not handle network providers — use resolve_secret_async".into(),
        )),
        "azure" => Err(SecretError::NotImplemented(
            "azure: sync resolver does not handle network providers — use resolve_secret_async".into(),
        )),
        "hsm" => Err(SecretError::NotImplemented("hsm".into())),
        _ => Err(SecretError::UnknownProvider(provider.into())),
    }
}

/// Resolve a secret reference asynchronously, including
/// network-backed providers when their Cargo feature is on.
///
/// Today: `env` + `file` delegate to [`resolve_secret`]; `vault`
/// hits [`vault::resolve`] when the `vault` feature is on. Other
/// network providers return `NotImplemented` until their B2-T2..T4
/// / B6-T4 tasks land.
pub async fn resolve_secret_async(
    provider: &str,
    path: &str,
    field: Option<&str>,
) -> Result<SecretValue, SecretError> {
    match provider {
        "vault" => resolve_vault(path, field).await,
        "aws" => resolve_aws(path, field).await,
        "gcp" => resolve_gcp(path, field).await,
        "azure" => resolve_azure(path, field).await,
        // Sync providers go through the existing synchronous
        // path so we don't accidentally hold a tokio task open
        // for what should be an instant read.
        _ => resolve_secret(provider, path, field),
    }
}

#[cfg(feature = "vault")]
async fn resolve_vault(
    path: &str,
    field: Option<&str>,
) -> Result<SecretValue, SecretError> {
    vault::resolve(path, field).await
}

#[cfg(not(feature = "vault"))]
async fn resolve_vault(
    _path: &str,
    _field: Option<&str>,
) -> Result<SecretValue, SecretError> {
    Err(SecretError::NotImplemented(
        "vault: this binary was built without the `vault` feature. Rebuild with `cargo build -p aegis-proxy --features vault`.".into(),
    ))
}

#[cfg(feature = "aws")]
async fn resolve_aws(
    id: &str,
    field: Option<&str>,
) -> Result<SecretValue, SecretError> {
    aws::resolve(id, field).await
}

#[cfg(not(feature = "aws"))]
async fn resolve_aws(
    _id: &str,
    _field: Option<&str>,
) -> Result<SecretValue, SecretError> {
    Err(SecretError::NotImplemented(
        "aws: this binary was built without the `aws` feature. Rebuild with `cargo build -p aegis-proxy --features aws`.".into(),
    ))
}

#[cfg(feature = "gcp")]
async fn resolve_gcp(
    resource: &str,
    field: Option<&str>,
) -> Result<SecretValue, SecretError> {
    gcp::resolve(resource, field).await
}

#[cfg(not(feature = "gcp"))]
async fn resolve_gcp(
    _resource: &str,
    _field: Option<&str>,
) -> Result<SecretValue, SecretError> {
    Err(SecretError::NotImplemented(
        "gcp: this binary was built without the `gcp` feature. Rebuild with `cargo build -p aegis-proxy --features gcp`.".into(),
    ))
}

#[cfg(feature = "azure")]
async fn resolve_azure(
    reference: &str,
    field: Option<&str>,
) -> Result<SecretValue, SecretError> {
    azure::resolve(reference, field).await
}

#[cfg(not(feature = "azure"))]
async fn resolve_azure(
    _reference: &str,
    _field: Option<&str>,
) -> Result<SecretValue, SecretError> {
    Err(SecretError::NotImplemented(
        "azure: this binary was built without the `azure` feature. Rebuild with `cargo build -p aegis-proxy --features azure`.".into(),
    ))
}

/// Expand all `${secret:...}` references in a template string
/// using only the synchronous resolvers (env + file). Returns
/// `NotImplemented` if the template contains a network-backed
/// reference; use [`expand_secrets_async`] for those.
pub fn expand_secrets(template: &str) -> Result<String, SecretError> {
    let mut result = template.to_string();
    // Simple iterative replacement — not performance-critical (config load time).
    while let Some(start) = result.find("${secret:") {
        let end = result[start..]
            .find('}')
            .map(|i| start + i + 1)
            .ok_or_else(|| SecretError::ParseError("unclosed ${secret:...}".into()))?;

        let ref_str = &result[start..end];
        let (provider, path, _field) = parse_secret_ref(ref_str)
            .ok_or_else(|| SecretError::ParseError(format!("bad ref: {ref_str}")))?;

        let secret = resolve_secret(&provider, &path, _field.as_deref())?;
        result.replace_range(start..end, secret.expose());
    }
    Ok(result)
}

/// Expand all `${secret:...}` references in a template string,
/// including network-backed providers when their Cargo feature
/// is on. Use this from a tokio task (e.g. config-load step) so
/// Vault / AWS / GCP / Azure references resolve.
pub async fn expand_secrets_async(template: &str) -> Result<String, SecretError> {
    let mut result = template.to_string();
    while let Some(start) = result.find("${secret:") {
        let end = result[start..]
            .find('}')
            .map(|i| start + i + 1)
            .ok_or_else(|| SecretError::ParseError("unclosed ${secret:...}".into()))?;

        let ref_str = &result[start..end];
        let (provider, path, field) = parse_secret_ref(ref_str)
            .ok_or_else(|| SecretError::ParseError(format!("bad ref: {ref_str}")))?;

        let secret = resolve_secret_async(&provider, &path, field.as_deref()).await?;
        result.replace_range(start..end, secret.expose());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_ref() {
        let (p, path, field) = parse_secret_ref("${secret:env:DB_PASS}").unwrap();
        assert_eq!(p, "env");
        assert_eq!(path, "DB_PASS");
        assert!(field.is_none());
    }

    #[test]
    fn parse_ref_with_field() {
        let (p, path, field) = parse_secret_ref("${secret:vault:kv/data/myapp#password}").unwrap();
        assert_eq!(p, "vault");
        assert_eq!(path, "kv/data/myapp");
        assert_eq!(field.unwrap(), "password");
    }

    #[test]
    fn parse_invalid_ref() {
        assert!(parse_secret_ref("not-a-ref").is_none());
        assert!(parse_secret_ref("${secret:}").is_none());
    }

    #[test]
    fn resolve_env_secret() {
        std::env::set_var("TEST_SECRET_XYZ", "hunter2");
        let val = resolve_secret("env", "TEST_SECRET_XYZ", None).unwrap();
        assert_eq!(val.expose(), "hunter2");
        std::env::remove_var("TEST_SECRET_XYZ");
    }

    #[test]
    fn resolve_file_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, "file-secret-value\n").unwrap();
        let val = resolve_secret("file", path.to_str().unwrap(), None).unwrap();
        assert_eq!(val.expose(), "file-secret-value");
    }

    #[test]
    fn resolve_env_missing() {
        let result = resolve_secret("env", "NONEXISTENT_VAR_12345", None);
        assert!(matches!(result, Err(SecretError::NotFound(_))));
    }

    #[test]
    fn sync_resolve_vault_returns_not_implemented_pointing_at_async() {
        // Sync path always errors for vault — the resolver
        // tells the caller to use the async path.
        let result = resolve_secret("vault", "some/path", None);
        match result {
            Err(SecretError::NotImplemented(msg)) => {
                assert!(
                    msg.contains("resolve_secret_async"),
                    "error should redirect to async path: {msg}"
                );
            }
            other => panic!("expected NotImplemented, got {other:?}"),
        }
    }

    #[test]
    fn sync_resolve_aws_redirects_to_async_path() {
        // Same shape as vault — sync caller gets pointed at the
        // async resolver instead of a bare "not implemented".
        let result = resolve_secret("aws", "arn:aws:secretsmanager:…", None);
        match result {
            Err(SecretError::NotImplemented(msg)) => {
                assert!(
                    msg.contains("resolve_secret_async"),
                    "error should redirect to async path: {msg}"
                );
            }
            other => panic!("expected NotImplemented, got {other:?}"),
        }
    }

    #[test]
    fn sync_resolve_gcp_redirects_to_async_path() {
        let result = resolve_secret("gcp", "projects/p/secrets/s/versions/1", None);
        match result {
            Err(SecretError::NotImplemented(msg)) => {
                assert!(
                    msg.contains("resolve_secret_async"),
                    "error should redirect to async path: {msg}"
                );
            }
            other => panic!("expected NotImplemented, got {other:?}"),
        }
    }

    #[test]
    fn sync_resolve_azure_redirects_to_async_path() {
        let result = resolve_secret("azure", "vault/name", None);
        match result {
            Err(SecretError::NotImplemented(msg)) => {
                assert!(
                    msg.contains("resolve_secret_async"),
                    "error should redirect to async path: {msg}"
                );
            }
            other => panic!("expected NotImplemented, got {other:?}"),
        }
    }

    #[test]
    fn sync_resolve_hsm_not_implemented() {
        let result = resolve_secret("hsm", "some/path", None);
        assert!(
            matches!(result, Err(SecretError::NotImplemented(_))),
            "hsm should be NotImplemented, got {result:?}"
        );
    }

    #[cfg(not(feature = "azure"))]
    #[tokio::test]
    async fn async_azure_without_feature_errors_actionably() {
        let result =
            resolve_secret_async("azure", "vault/name", Some("password")).await;
        match result {
            Err(SecretError::NotImplemented(msg)) => {
                assert!(
                    msg.contains("--features azure"),
                    "error should suggest the cargo flag: {msg}"
                );
            }
            other => panic!("expected NotImplemented, got {other:?}"),
        }
    }

    #[cfg(not(feature = "gcp"))]
    #[tokio::test]
    async fn async_gcp_without_feature_errors_actionably() {
        let result = resolve_secret_async(
            "gcp",
            "projects/p/secrets/s/versions/1",
            Some("password"),
        )
        .await;
        match result {
            Err(SecretError::NotImplemented(msg)) => {
                assert!(
                    msg.contains("--features gcp"),
                    "error should suggest the cargo flag: {msg}"
                );
            }
            other => panic!("expected NotImplemented, got {other:?}"),
        }
    }

    #[cfg(not(feature = "aws"))]
    #[tokio::test]
    async fn async_aws_without_feature_errors_actionably() {
        let result =
            resolve_secret_async("aws", "arn:…", Some("password")).await;
        match result {
            Err(SecretError::NotImplemented(msg)) => {
                assert!(
                    msg.contains("--features aws"),
                    "error should suggest the cargo flag: {msg}"
                );
            }
            other => panic!("expected NotImplemented, got {other:?}"),
        }
    }

    #[test]
    fn resolve_unknown_provider() {
        let result = resolve_secret("not-a-real-provider", "some/path", None);
        assert!(matches!(result, Err(SecretError::UnknownProvider(_))));
    }

    #[cfg(not(feature = "vault"))]
    #[tokio::test]
    async fn async_vault_without_feature_errors_actionably() {
        let result =
            resolve_secret_async("vault", "kv/data/test", Some("password")).await;
        match result {
            Err(SecretError::NotImplemented(msg)) => {
                assert!(
                    msg.contains("--features vault"),
                    "error should suggest the cargo flag: {msg}"
                );
            }
            other => panic!("expected NotImplemented, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn async_env_resolution_works() {
        std::env::set_var("ASYNC_TEST_SECRET", "async-value");
        let result =
            resolve_secret_async("env", "ASYNC_TEST_SECRET", None).await.unwrap();
        assert_eq!(result.expose(), "async-value");
        std::env::remove_var("ASYNC_TEST_SECRET");
    }

    #[tokio::test]
    async fn expand_secrets_async_handles_env() {
        std::env::set_var("ASYNC_EXPAND_TEST", "expanded");
        let result =
            expand_secrets_async("foo=${secret:env:ASYNC_EXPAND_TEST}")
                .await
                .unwrap();
        assert_eq!(result, "foo=expanded");
        std::env::remove_var("ASYNC_EXPAND_TEST");
    }

    #[test]
    fn expand_secrets_in_template() {
        std::env::set_var("EXPAND_TEST_SECRET", "resolved-value");
        let result = expand_secrets("host=db.example.com pass=${secret:env:EXPAND_TEST_SECRET}").unwrap();
        assert_eq!(result, "host=db.example.com pass=resolved-value");
        assert!(!result.contains("${secret:"));
        std::env::remove_var("EXPAND_TEST_SECRET");
    }

    #[test]
    fn expand_no_secrets_noop() {
        let result = expand_secrets("no secrets here").unwrap();
        assert_eq!(result, "no secrets here");
    }
}
