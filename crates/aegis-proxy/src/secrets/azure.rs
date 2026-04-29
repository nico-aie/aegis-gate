//! Azure Key Vault secret resolver (B2-T4 — Phase B).
//!
//! Resolves `${secret:azure:<vault>/<name>[/<version>][#<field>]}`
//! references via Azure Key Vault's REST API. Auth uses the two
//! production-deployed paths and **deliberately skips** the
//! preview `azure_identity` crate:
//!
//! - **Service principal** (env vars: `AZURE_CLIENT_ID` +
//!   `AZURE_CLIENT_SECRET` + `AZURE_TENANT_ID`) — works
//!   anywhere, the production-standard for non-Azure-hosted
//!   workloads.
//! - **Managed Identity** (IMDS) — works transparently on Azure
//!   VMs, AKS pods with managed-identity-on-pod, and any
//!   environment where the Azure metadata endpoint at
//!   `169.254.169.254` resolves.
//!
//! Other auth sources (Azure CLI cached creds, federated
//! workload identity for AKS, …) are **not** wired today. AKS
//! deployments that rely on workload identity should set the
//! service-principal env vars from the projected ServiceAccount
//! token via an init container; documented as a Phase B
//! follow-up.
//!
//! ## Reference shape
//!
//! ```text
//! ${secret:azure:<vault-name>/<secret-name>[/<version>][#<field>]}
//! ```
//!
//! - `<vault-name>` is just the host prefix — the
//!   `<vault>.vault.azure.net` suffix is added automatically.
//!   For sovereign clouds (US-Gov, China, Germany), set
//!   `AEGIS_AZURE_VAULT_DOMAIN` to override (default
//!   `vault.azure.net`).
//! - `<version>` is optional; absent means "current version".
//! - `<field>` is optional. Without it the entire
//!   `value` field of the response is returned (with trailing
//!   newline trimmed). With it, the value is parsed as JSON
//!   and the named field is extracted via the shared
//!   [`crate::secrets::json_field`] helper.
//!
//! Example:
//!
//! ```yaml
//! admin:
//!   password_hash_ref: "${secret:azure:my-vault/admin-creds#hash}"
//! ```

use serde::Deserialize;

use super::{json_field, SecretError, SecretValue};

/// API version for Key Vault data-plane calls. The 7.x line
/// has been stable for years; bumping is a deliberate change.
const KV_API_VERSION: &str = "7.4";

/// Default Azure environment domain. Override for sovereign
/// clouds via `AEGIS_AZURE_VAULT_DOMAIN`.
const DEFAULT_VAULT_DOMAIN: &str = "vault.azure.net";

/// IMDS endpoint for managed-identity tokens. Always
/// `169.254.169.254` on Azure VMs + AKS. Reserved env-var
/// override `AEGIS_AZURE_IMDS_ENDPOINT` exists for proxy /
/// non-default scenarios.
const DEFAULT_IMDS_ENDPOINT: &str = "http://169.254.169.254";

/// Public entry — resolve `${secret:azure:<vault>/<name>[/<version>]#<field>}`.
pub async fn resolve(
    reference: &str,
    field: Option<&str>,
) -> Result<SecretValue, SecretError> {
    let parts = parse_reference(reference)?;

    let vault_domain = std::env::var("AEGIS_AZURE_VAULT_DOMAIN")
        .unwrap_or_else(|_| DEFAULT_VAULT_DOMAIN.to_string());
    let resource = format!("https://{vault_domain}");
    // The token's `audience` / `resource` is the vault domain
    // root — *not* the per-vault hostname.
    let scope = format!("{resource}/.default");

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| {
            SecretError::ParseError(format!("azure: building HTTP client: {e}"))
        })?;

    let token = acquire_token(&http, &resource, &scope).await?;
    let raw = fetch_secret_value(&http, &parts, &vault_domain, &token).await?;

    json_field::extract(&raw, field, reference)
}

/// Parsed reference: `<vault>/<name>[/<version>]`.
#[derive(Debug, PartialEq)]
struct ParsedRef {
    vault: String,
    name: String,
    version: Option<String>,
}

fn parse_reference(reference: &str) -> Result<ParsedRef, SecretError> {
    if reference.is_empty() {
        return Err(SecretError::ParseError(
            "azure: empty reference".into(),
        ));
    }

    let segments: Vec<&str> = reference.split('/').collect();
    match segments.as_slice() {
        [vault, name] if !vault.is_empty() && !name.is_empty() => Ok(ParsedRef {
            vault: (*vault).to_string(),
            name: (*name).to_string(),
            version: None,
        }),
        [vault, name, version]
            if !vault.is_empty() && !name.is_empty() && !version.is_empty() =>
        {
            Ok(ParsedRef {
                vault: (*vault).to_string(),
                name: (*name).to_string(),
                version: Some((*version).to_string()),
            })
        }
        _ => Err(SecretError::ParseError(format!(
            "azure: bad reference shape: {reference} \
             (expected <vault>/<name>[/<version>])"
        ))),
    }
}

/// Auth method, in precedence order.
#[derive(Debug)]
enum AuthMethod {
    /// `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET` + `AZURE_TENANT_ID`
    /// all set — use service-principal client-credentials flow.
    ServicePrincipal {
        client_id: String,
        client_secret: String,
        tenant_id: String,
    },
    /// No SP env vars — try IMDS managed identity. Optional
    /// `AZURE_CLIENT_ID` here selects a user-assigned MI.
    ManagedIdentity {
        user_assigned_client_id: Option<String>,
    },
}

fn detect_auth_method() -> AuthMethod {
    let client_id = std::env::var("AZURE_CLIENT_ID").ok().filter(|s| !s.is_empty());
    let client_secret = std::env::var("AZURE_CLIENT_SECRET")
        .ok()
        .filter(|s| !s.is_empty());
    let tenant_id = std::env::var("AZURE_TENANT_ID").ok().filter(|s| !s.is_empty());

    if let (Some(id), Some(secret), Some(tenant)) =
        (client_id.clone(), client_secret, tenant_id)
    {
        AuthMethod::ServicePrincipal {
            client_id: id,
            client_secret: secret,
            tenant_id: tenant,
        }
    } else {
        // SP env vars incomplete; fall through to MI. If
        // `AZURE_CLIENT_ID` is set without secret/tenant, treat
        // it as a user-assigned MI selector.
        AuthMethod::ManagedIdentity {
            user_assigned_client_id: client_id,
        }
    }
}

#[derive(Deserialize, Debug)]
struct TokenResponse {
    access_token: String,
}

async fn acquire_token(
    http: &reqwest::Client,
    resource: &str,
    scope: &str,
) -> Result<String, SecretError> {
    match detect_auth_method() {
        AuthMethod::ServicePrincipal {
            client_id,
            client_secret,
            tenant_id,
        } => {
            let url = format!(
                "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
            );
            let form = [
                ("grant_type", "client_credentials"),
                ("client_id", &client_id),
                ("client_secret", &client_secret),
                ("scope", scope),
            ];
            let resp = http
                .post(&url)
                .form(&form)
                .send()
                .await
                .map_err(|e| {
                    SecretError::ParseError(format!(
                        "azure: SP token transport: {e}"
                    ))
                })?;

            let status = resp.status();
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(SecretError::ParseError(format!(
                    "azure: SP token endpoint returned {status}: {body}"
                )));
            }
            let parsed: TokenResponse = resp.json().await.map_err(|e| {
                SecretError::ParseError(format!(
                    "azure: SP token response not JSON-shaped: {e}"
                ))
            })?;
            Ok(parsed.access_token)
        }
        AuthMethod::ManagedIdentity {
            user_assigned_client_id,
        } => {
            let imds = std::env::var("AEGIS_AZURE_IMDS_ENDPOINT")
                .unwrap_or_else(|_| DEFAULT_IMDS_ENDPOINT.to_string());
            let mut url = format!(
                "{}/metadata/identity/oauth2/token?api-version=2018-02-01&resource={}",
                imds.trim_end_matches('/'),
                urlencode(resource)
            );
            if let Some(client_id) = user_assigned_client_id {
                url.push_str("&client_id=");
                url.push_str(&urlencode(&client_id));
            }

            let resp = http
                .get(&url)
                .header("Metadata", "true")
                .send()
                .await
                .map_err(|e| {
                    SecretError::ParseError(format!(
                        "azure: IMDS token transport: {e}; \
                         set AZURE_CLIENT_ID + AZURE_CLIENT_SECRET + AZURE_TENANT_ID \
                         for service-principal auth instead"
                    ))
                })?;

            let status = resp.status();
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(SecretError::ParseError(format!(
                    "azure: IMDS endpoint returned {status}: {body}; \
                     this binary is likely not running on Azure — set \
                     AZURE_CLIENT_ID + AZURE_CLIENT_SECRET + AZURE_TENANT_ID for service-principal auth"
                )));
            }
            let parsed: TokenResponse = resp.json().await.map_err(|e| {
                SecretError::ParseError(format!(
                    "azure: IMDS token response not JSON-shaped: {e}"
                ))
            })?;
            Ok(parsed.access_token)
        }
    }
}

#[derive(Deserialize, Debug)]
struct GetSecretResponse {
    /// The secret payload. Present for string secrets; missing
    /// for content-type=application/octet-stream secrets which
    /// we deliberately don't support.
    value: Option<String>,
}

async fn fetch_secret_value(
    http: &reqwest::Client,
    parts: &ParsedRef,
    vault_domain: &str,
    token: &str,
) -> Result<String, SecretError> {
    let url = match &parts.version {
        Some(v) => format!(
            "https://{}.{}/secrets/{}/{}?api-version={}",
            parts.vault, vault_domain, parts.name, v, KV_API_VERSION
        ),
        None => format!(
            "https://{}.{}/secrets/{}?api-version={}",
            parts.vault, vault_domain, parts.name, KV_API_VERSION
        ),
    };

    let resp = http
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .map_err(|e| {
            SecretError::NotFound(format!("azure: read transport: {e}"))
        })?;

    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(SecretError::NotFound(format!(
            "azure: secret {}/{} not found in vault.{}",
            parts.vault, parts.name, vault_domain
        )));
    }
    if status == reqwest::StatusCode::FORBIDDEN
        || status == reqwest::StatusCode::UNAUTHORIZED
    {
        return Err(SecretError::NotFound(format!(
            "azure: {status} reading {}/{} — \
             check the principal has the `Key Vault Secrets User` role on the vault",
            parts.vault, parts.name
        )));
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(SecretError::NotFound(format!(
            "azure: read {}/{} returned {status}: {body}",
            parts.vault, parts.name
        )));
    }

    let parsed: GetSecretResponse = resp.json().await.map_err(|e| {
        SecretError::ParseError(format!(
            "azure: response not GetSecret-shaped: {e}"
        ))
    })?;
    parsed.value.ok_or_else(|| {
        SecretError::ParseError(format!(
            "azure: secret {}/{} has no `value` field — \
             binary secrets are unsupported, store base64 in a string instead",
            parts.vault, parts.name
        ))
    })
}

/// Minimal URL-encoder for the few characters that show up in
/// resource URLs. Avoids pulling `urlencoding` for one call.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Process-wide mutex serialising every test that mutates
    /// the `AZURE_*` env vars. Same pattern as the vault tests.
    static ENV_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    struct EnvGuard {
        prior: Vec<(String, Option<String>)>,
        _lock: parking_lot::MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn set(pairs: &[(&str, Option<&str>)]) -> Self {
            let lock = ENV_LOCK.lock();
            let prior: Vec<(String, Option<String>)> = pairs
                .iter()
                .map(|(k, _)| (k.to_string(), std::env::var(k).ok()))
                .collect();
            for (k, v) in pairs {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
            Self { prior, _lock: lock }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, prior) in &self.prior {
                match prior {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    #[test]
    fn parse_two_segments_no_version() {
        let parsed = parse_reference("my-vault/admin-pass").unwrap();
        assert_eq!(parsed.vault, "my-vault");
        assert_eq!(parsed.name, "admin-pass");
        assert_eq!(parsed.version, None);
    }

    #[test]
    fn parse_three_segments_with_version() {
        let parsed = parse_reference("my-vault/admin-pass/abc123").unwrap();
        assert_eq!(parsed.vault, "my-vault");
        assert_eq!(parsed.name, "admin-pass");
        assert_eq!(parsed.version, Some("abc123".to_string()));
    }

    #[test]
    fn parse_empty_errors() {
        let err = parse_reference("").unwrap_err();
        match err {
            SecretError::ParseError(m) => assert!(m.contains("empty"), "got: {m}"),
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn parse_single_segment_errors() {
        let err = parse_reference("just-vault").unwrap_err();
        match err {
            SecretError::ParseError(m) => {
                assert!(m.contains("bad reference shape"), "got: {m}");
                assert!(m.contains("<vault>/<name>"), "got: {m}");
            }
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn parse_too_many_segments_errors() {
        let err = parse_reference("a/b/c/d").unwrap_err();
        match err {
            SecretError::ParseError(m) => {
                assert!(m.contains("bad reference shape"), "got: {m}");
            }
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn parse_empty_segment_errors() {
        // Empty middle segment ("vault//version")
        let err = parse_reference("vault//abc").unwrap_err();
        match err {
            SecretError::ParseError(_) => {}
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn auth_method_picks_sp_when_all_three_set() {
        let _g = EnvGuard::set(&[
            ("AZURE_CLIENT_ID", Some("client-1")),
            ("AZURE_CLIENT_SECRET", Some("secret-1")),
            ("AZURE_TENANT_ID", Some("tenant-1")),
        ]);
        match detect_auth_method() {
            AuthMethod::ServicePrincipal {
                client_id,
                client_secret,
                tenant_id,
            } => {
                assert_eq!(client_id, "client-1");
                assert_eq!(client_secret, "secret-1");
                assert_eq!(tenant_id, "tenant-1");
            }
            other => panic!("expected SP, got {other:?}"),
        }
    }

    #[test]
    fn auth_method_falls_through_to_mi_without_secret() {
        let _g = EnvGuard::set(&[
            ("AZURE_CLIENT_ID", Some("client-1")),
            ("AZURE_CLIENT_SECRET", None),
            ("AZURE_TENANT_ID", Some("tenant-1")),
        ]);
        match detect_auth_method() {
            AuthMethod::ManagedIdentity {
                user_assigned_client_id,
            } => {
                // Client ID without secret = user-assigned MI selector.
                assert_eq!(user_assigned_client_id, Some("client-1".to_string()));
            }
            other => panic!("expected MI, got {other:?}"),
        }
    }

    #[test]
    fn auth_method_falls_through_to_mi_with_no_env_vars() {
        let _g = EnvGuard::set(&[
            ("AZURE_CLIENT_ID", None),
            ("AZURE_CLIENT_SECRET", None),
            ("AZURE_TENANT_ID", None),
        ]);
        match detect_auth_method() {
            AuthMethod::ManagedIdentity {
                user_assigned_client_id,
            } => {
                assert_eq!(user_assigned_client_id, None);
            }
            other => panic!("expected MI, got {other:?}"),
        }
    }

    #[test]
    fn empty_env_var_treated_as_unset() {
        // Operators sometimes set env vars to "" which historically
        // tripped naive `is_ok()` checks. Confirm we filter empties.
        let _g = EnvGuard::set(&[
            ("AZURE_CLIENT_ID", Some("")),
            ("AZURE_CLIENT_SECRET", Some("")),
            ("AZURE_TENANT_ID", Some("")),
        ]);
        match detect_auth_method() {
            AuthMethod::ManagedIdentity {
                user_assigned_client_id,
            } => {
                assert_eq!(user_assigned_client_id, None);
            }
            other => panic!("expected MI for empty SP envs, got {other:?}"),
        }
    }

    #[test]
    fn urlencode_passes_unreserved_through() {
        assert_eq!(urlencode("abc-123_XYZ.~"), "abc-123_XYZ.~");
    }

    #[test]
    fn urlencode_percent_encodes_special() {
        assert_eq!(urlencode("https://example.com"), "https%3A%2F%2Fexample.com");
        assert_eq!(urlencode("a b"), "a%20b");
        assert_eq!(urlencode("/&?"), "%2F%26%3F");
    }

    /// Live integration test gated by an explicit opt-in env
    /// var. Run with:
    ///
    /// ```sh
    /// AEGIS_AZURE_INTEGRATION_TEST=1 \
    /// AZURE_TENANT_ID=… AZURE_CLIENT_ID=… AZURE_CLIENT_SECRET=… \
    /// AEGIS_AZURE_TEST_REF=my-vault/test-secret \
    ///   cargo test -p aegis-proxy --features azure \
    ///     --lib secrets::azure::tests::live_azure_resolves
    /// ```
    #[tokio::test]
    async fn live_azure_resolves() {
        if std::env::var("AEGIS_AZURE_INTEGRATION_TEST").is_err() {
            eprintln!("[secrets::azure] skipped — set AEGIS_AZURE_INTEGRATION_TEST=1 to run");
            return;
        }
        let reference = std::env::var("AEGIS_AZURE_TEST_REF")
            .expect("AEGIS_AZURE_TEST_REF required when integration enabled");
        let v = resolve(&reference, None)
            .await
            .expect("live azure resolve should succeed");
        assert!(!v.expose().is_empty(), "secret should not be empty");
    }
}
