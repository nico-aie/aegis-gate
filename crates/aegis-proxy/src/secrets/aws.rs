//! AWS Secrets Manager secret resolver (B2-T2 — Phase B).
//!
//! Resolves `${secret:aws:<arn-or-name>#<field>}` references via
//! the official AWS SDK. Credentials come from the SDK's standard
//! provider chain — env vars, `~/.aws/credentials` (with
//! `AWS_PROFILE`), IMDSv2 on EC2, web-identity / IRSA on EKS — so
//! operators don't have to configure anything else here.
//!
//! ## Reference shape
//!
//! `${secret:aws:<id>[#<field>]}` where `<id>` is either a full
//! ARN
//! (`arn:aws:secretsmanager:us-east-1:111122223333:secret:aegis/admin-XYZ`)
//! or a friendly name (`aegis/admin`). The SDK accepts both.
//!
//! `<field>` is optional:
//!
//! - **No field** — the entire `SecretString` is returned as-is.
//!   Use this for plain secrets (e.g. an API key).
//! - **With field** — the `SecretString` is parsed as a JSON
//!   object and the named key is extracted. Use this for the
//!   common Secrets Manager pattern of storing
//!   `{"username":"…","password":"…"}` and pulling out one
//!   field per reference.
//!
//! Binary secrets (`SecretBinary`) are deliberately not supported
//! — they're rare in practice and base64 round-tripping muddies
//! the contract. Operators with binary needs should base64-encode
//! into a string and decode in their own tooling.
//!
//! ## Region resolution
//!
//! - `AEGIS_AWS_REGION` (this crate's override) is honored if set.
//! - Otherwise the SDK's default region chain runs: `AWS_REGION`,
//!   `AWS_DEFAULT_REGION`, `~/.aws/config` profile region, IMDS
//!   region, …
//! - If no region can be resolved, the first SDK call fails with
//!   a descriptive error — we surface that as
//!   `SecretError::ParseError` so the operator sees what to fix.

use super::{json_field, SecretError, SecretValue};

/// Resolve a Secrets Manager reference. Public entry called from
/// [`crate::secrets::resolve_secret_async`].
pub async fn resolve(
    id: &str,
    field: Option<&str>,
) -> Result<SecretValue, SecretError> {
    let config = build_config().await;
    let client = aws_sdk_secretsmanager::Client::new(&config);

    let resp = client
        .get_secret_value()
        .secret_id(id)
        .send()
        .await
        .map_err(|e| {
            // The SDK's error type wraps service errors + retries
            // + connection issues. We flatten to a single string
            // so callers don't have to care about the SDK's
            // taxonomy. The Display impl includes the service
            // error code (e.g. "ResourceNotFoundException") so
            // the operator can grep for it.
            let msg = format!("{e}");
            // Map "not found" to NotFound, everything else to
            // ParseError so retryability is at least visible.
            if msg.contains("ResourceNotFound") {
                SecretError::NotFound(format!("aws: secret {id} not found"))
            } else if msg.contains("AccessDenied")
                || msg.contains("UnauthorizedOperation")
            {
                SecretError::NotFound(format!(
                    "aws: access denied reading {id} — check the IAM policy grants `secretsmanager:GetSecretValue`"
                ))
            } else {
                SecretError::ParseError(format!("aws: get_secret_value({id}): {msg}"))
            }
        })?;

    let raw = resp.secret_string().ok_or_else(|| {
        SecretError::ParseError(format!(
            "aws: secret {id} has no SecretString (binary-only secrets are unsupported; \
             store base64 in a string field if you need bytes)"
        ))
    })?;

    // Delegate to the shared `secrets/json_field.rs` helper so
    // every cloud resolver (aws / gcp / azure) behaves
    // identically for the JSON-or-plain-string secret shape.
    json_field::extract(raw, field, id)
}

/// Build the SDK `SdkConfig`. Honors the `AEGIS_AWS_REGION`
/// override; otherwise the SDK's default region chain runs.
async fn build_config() -> aws_config::SdkConfig {
    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
    if let Ok(region) = std::env::var("AEGIS_AWS_REGION") {
        if !region.is_empty() {
            loader = loader.region(aws_config::Region::new(region));
        }
    }
    loader.load().await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live integration test gated by an explicit opt-in env
    /// var. Run with:
    ///
    /// ```sh
    /// AEGIS_AWS_INTEGRATION_TEST=1 \
    /// AEGIS_AWS_REGION=us-east-1 \
    /// AEGIS_AWS_TEST_SECRET_ID=aegis/test-secret \
    ///   cargo test -p aegis-proxy --features aws \
    ///     --lib secrets::aws::tests::live_aws_resolves
    /// ```
    ///
    /// The named secret should already exist in your account
    /// and contain `{"value":"hello"}`. The test just probes
    /// for a successful round-trip; auth / region / IAM are
    /// covered by the SDK's own test suite.
    #[tokio::test]
    async fn live_aws_resolves() {
        if std::env::var("AEGIS_AWS_INTEGRATION_TEST").is_err() {
            eprintln!("[secrets::aws] skipped — set AEGIS_AWS_INTEGRATION_TEST=1 to run");
            return;
        }
        let id = std::env::var("AEGIS_AWS_TEST_SECRET_ID")
            .expect("AEGIS_AWS_TEST_SECRET_ID required when integration enabled");
        let v = resolve(&id, Some("value"))
            .await
            .expect("live aws resolve should succeed");
        assert!(!v.expose().is_empty(), "secret should not be empty");
    }
}
