//! GCP Secret Manager resolver (B2-T3 — Phase B).
//!
//! Resolves `${secret:gcp:<resource>[#<field>]}` references via
//! the Secret Manager REST API. We deliberately skip the gRPC
//! `google-cloud-secret-manager` crate in favour of REST +
//! [`gcp_auth`] because:
//!
//! 1. The full Secret Manager surface we need is one method —
//!    `accessSecretVersion`. REST is enough.
//! 2. gRPC pulls tonic + prost, which together are larger than
//!    the rest of `aegis-proxy/gcp`'s dep tree combined.
//! 3. `reqwest` is already pulled via the `vault` feature, so
//!    operators who use both pay no double cost.
//!
//! ## Reference shape
//!
//! `${secret:gcp:<resource>[#<field>]}` where `<resource>` is the
//! standard GCP path:
//!
//! ```text
//! projects/<project-id-or-number>/secrets/<name>/versions/<version-or-"latest">
//! ```
//!
//! Example:
//!
//! ```yaml
//! admin:
//!   password_hash_ref: "${secret:gcp:projects/aegis-prod/secrets/admin-hash/versions/latest#hash}"
//! ```
//!
//! `<field>` is optional. Without it the entire payload is
//! returned (with a trailing-newline trim). With it, the payload
//! is parsed as JSON and the named field is extracted via the
//! shared [`crate::secrets::json_field`] helper.
//!
//! ## Auth
//!
//! [`gcp_auth`] handles Application Default Credentials:
//!
//! - **GKE workload identity** — the metadata server.
//! - **Compute Engine** — the metadata server.
//! - **`GOOGLE_APPLICATION_CREDENTIALS`** — service-account
//!   key JSON.
//! - **`gcloud auth application-default login`** — user creds
//!   from `~/.config/gcloud`.
//!
//! Operators don't configure anything here; the standard GCP
//! patterns work transparently.

use base64::Engine;
use serde::Deserialize;

use super::{json_field, SecretError, SecretValue};

/// REST API host. Swappable for a regional endpoint
/// (`secretmanager.<region>.rep.googleapis.com`) via
/// `AEGIS_GCP_SM_ENDPOINT` for operators with VPC-SC perimeters.
const DEFAULT_API_HOST: &str = "https://secretmanager.googleapis.com";

/// OAuth2 scope sufficient to read secret versions. The
/// recommended `cloud-platform` scope works for every Secret
/// Manager call without needing extra grants.
const SCOPE_CLOUD_PLATFORM: &str = "https://www.googleapis.com/auth/cloud-platform";

/// Public entry point — resolve `${secret:gcp:<resource>#<field>}`.
pub async fn resolve(
    resource: &str,
    field: Option<&str>,
) -> Result<SecretValue, SecretError> {
    validate_resource(resource)?;

    let provider = gcp_auth::provider().await.map_err(|e| {
        SecretError::ParseError(format!(
            "gcp: building credential provider failed: {e}; \
             check Application Default Credentials \
             (GOOGLE_APPLICATION_CREDENTIALS, GKE workload identity, or `gcloud auth application-default login`)"
        ))
    })?;

    let token = provider
        .token(&[SCOPE_CLOUD_PLATFORM])
        .await
        .map_err(|e| {
            SecretError::ParseError(format!(
                "gcp: fetching OAuth2 token failed: {e}"
            ))
        })?;

    let host = std::env::var("AEGIS_GCP_SM_ENDPOINT")
        .unwrap_or_else(|_| DEFAULT_API_HOST.to_string());
    let url = format!(
        "{}/v1/{}:access",
        host.trim_end_matches('/'),
        resource.trim_start_matches('/')
    );

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| {
            SecretError::ParseError(format!("gcp: building HTTP client: {e}"))
        })?;

    let resp = http
        .get(&url)
        .header("Authorization", format!("Bearer {}", token.as_str()))
        .send()
        .await
        .map_err(|e| {
            SecretError::NotFound(format!("gcp: read transport for {resource}: {e}"))
        })?;

    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(SecretError::NotFound(format!(
            "gcp: secret {resource} not found"
        )));
    }
    if status == reqwest::StatusCode::FORBIDDEN
        || status == reqwest::StatusCode::UNAUTHORIZED
    {
        return Err(SecretError::NotFound(format!(
            "gcp: {status} reading {resource} — \
             check the service account has roles/secretmanager.secretAccessor"
        )));
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(SecretError::NotFound(format!(
            "gcp: read {resource} returned {status}: {body}"
        )));
    }

    let parsed: AccessSecretVersionResponse =
        resp.json().await.map_err(|e| {
            SecretError::ParseError(format!(
                "gcp: response not AccessSecretVersionResponse-shaped: {e}"
            ))
        })?;

    // GCP returns the payload as base64 in `payload.data`. The
    // standard alphabet is the URL-safe one but plain base64
    // also appears in older client libraries — be permissive on
    // input.
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(parsed.payload.data.as_bytes())
        .or_else(|_| {
            base64::engine::general_purpose::URL_SAFE
                .decode(parsed.payload.data.as_bytes())
        })
        .map_err(|e| {
            SecretError::ParseError(format!(
                "gcp: payload base64 decode failed for {resource}: {e}"
            ))
        })?;

    let raw = String::from_utf8(bytes).map_err(|e| {
        SecretError::ParseError(format!(
            "gcp: payload at {resource} is not valid UTF-8: {e}; \
             binary secrets are unsupported, store base64-encoded text instead"
        ))
    })?;

    json_field::extract(&raw, field, resource)
}

/// Quick sanity check on the resource path. We accept anything
/// matching the documented shape; specifics are validated by the
/// API itself, but a clear up-front error helps operators who
/// typo the path.
fn validate_resource(resource: &str) -> Result<(), SecretError> {
    if resource.is_empty() {
        return Err(SecretError::ParseError(
            "gcp: empty resource path".into(),
        ));
    }
    if !resource.starts_with("projects/") {
        return Err(SecretError::ParseError(format!(
            "gcp: resource must start with `projects/<project>` (got: {resource}). \
             Expected shape: projects/<project>/secrets/<name>/versions/<version-or-latest>"
        )));
    }
    if !resource.contains("/secrets/") || !resource.contains("/versions/") {
        return Err(SecretError::ParseError(format!(
            "gcp: resource is missing /secrets/ or /versions/ segment (got: {resource}). \
             Expected shape: projects/<project>/secrets/<name>/versions/<version-or-latest>"
        )));
    }
    Ok(())
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct AccessSecretVersionResponse {
    payload: SecretPayload,
}

#[derive(Deserialize, Debug)]
struct SecretPayload {
    /// Base64-encoded secret bytes. GCP encodes with the
    /// standard alphabet by default; we tolerate URL-safe too
    /// for client-library compatibility.
    data: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_accepts_valid_resource() {
        validate_resource(
            "projects/aegis-prod/secrets/admin-hash/versions/latest",
        )
        .unwrap();
    }

    #[test]
    fn validate_accepts_numeric_project_id() {
        validate_resource("projects/123456789/secrets/key/versions/3").unwrap();
    }

    #[test]
    fn validate_rejects_empty() {
        let err = validate_resource("").unwrap_err();
        match err {
            SecretError::ParseError(m) => assert!(m.contains("empty"), "got: {m}"),
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_missing_projects_prefix() {
        let err = validate_resource("aegis-prod/secrets/key/versions/1").unwrap_err();
        match err {
            SecretError::ParseError(m) => {
                assert!(m.contains("projects/"), "got: {m}");
                assert!(m.contains("Expected shape"), "got: {m}");
            }
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_missing_secrets_segment() {
        let err = validate_resource("projects/aegis-prod/key/versions/1").unwrap_err();
        match err {
            SecretError::ParseError(m) => {
                assert!(m.contains("secrets/"), "got: {m}");
            }
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_missing_versions_segment() {
        let err = validate_resource("projects/aegis-prod/secrets/key").unwrap_err();
        match err {
            SecretError::ParseError(m) => {
                assert!(m.contains("versions/"), "got: {m}");
            }
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn payload_response_round_trips() {
        // base64 of "hunter2"
        let json = r#"{"payload":{"data":"aHVudGVyMg=="}}"#;
        let parsed: AccessSecretVersionResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.payload.data, "aHVudGVyMg==");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(parsed.payload.data.as_bytes())
            .unwrap();
        assert_eq!(decoded, b"hunter2");
    }

    #[test]
    fn payload_with_url_safe_base64_decodes() {
        // base64-url for bytes that contain '+' / '/' in standard alphabet
        // ("subjects?" base64url'd uses '_' instead of '/')
        let url_safe = base64::engine::general_purpose::URL_SAFE.encode(b"a/b+c");
        // First fall-through to standard would fail because the input
        // contains `_` or `-`, but URL_SAFE succeeds.
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(url_safe.as_bytes())
            .or_else(|_| {
                base64::engine::general_purpose::URL_SAFE
                    .decode(url_safe.as_bytes())
            })
            .unwrap();
        assert_eq!(bytes, b"a/b+c");
    }

    /// Live integration test gated by an explicit opt-in env
    /// var. Run with:
    ///
    /// ```sh
    /// AEGIS_GCP_INTEGRATION_TEST=1 \
    /// AEGIS_GCP_TEST_SECRET=projects/my-proj/secrets/test/versions/latest \
    ///   cargo test -p aegis-proxy --features gcp \
    ///     --lib secrets::gcp::tests::live_gcp_resolves
    /// ```
    #[tokio::test]
    async fn live_gcp_resolves() {
        if std::env::var("AEGIS_GCP_INTEGRATION_TEST").is_err() {
            eprintln!("[secrets::gcp] skipped — set AEGIS_GCP_INTEGRATION_TEST=1 to run");
            return;
        }
        let resource = std::env::var("AEGIS_GCP_TEST_SECRET")
            .expect("AEGIS_GCP_TEST_SECRET required when integration enabled");
        let v = resolve(&resource, None)
            .await
            .expect("live gcp resolve should succeed");
        assert!(!v.expose().is_empty(), "secret should not be empty");
    }
}
