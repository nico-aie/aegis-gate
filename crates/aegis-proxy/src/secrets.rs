//! Secrets resolver — resolves `${secret:<provider>:<path>[#field]}` in config.
//!
//! Providers: `env`, `file`. Vault/AWS return `NotImplemented` stubs.


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

/// Resolve a secret reference.
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
        "vault" => Err(SecretError::NotImplemented("vault".into())),
        "aws" => Err(SecretError::NotImplemented("aws".into())),
        _ => Err(SecretError::UnknownProvider(provider.into())),
    }
}

/// Expand all `${secret:...}` references in a template string.
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
    fn resolve_vault_not_implemented() {
        let result = resolve_secret("vault", "some/path", None);
        assert!(matches!(result, Err(SecretError::NotImplemented(_))));
    }

    #[test]
    fn resolve_unknown_provider() {
        let result = resolve_secret("gcp", "some/path", None);
        assert!(matches!(result, Err(SecretError::UnknownProvider(_))));
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
