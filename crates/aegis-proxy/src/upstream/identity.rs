//! Boot materialization of the state-sourced shared upstream
//! identity (P4 4a-ii, reference-only).
//!
//! When `zero_trust.upstream_identity.source: state`, the PUBLIC WAF
//! client cert + the private-key `key_ref` live in the Redis config
//! plane (key [`aegis_core::config::UPSTREAM_IDENTITY_STATE_KEY`],
//! value [`aegis_core::config::UpstreamIdentityRecord`]). The (sync)
//! pool build path (`ProxyContext::build` → `resolve_upstream_mtls`)
//! has no `StateBackend`, so the async boot path
//! ([`crate::run::run`]) calls [`materialize_upstream_identity`] to
//! read the record and fold the PUBLIC PEM into the cfg snapshot
//! before the build path runs.
//!
//! **Reference-only:** the private key is never stored in / read from
//! the config plane — `key_ref` is a path / `${secret:...}` reference
//! resolved later at client-build time.
//!
//! **Fail closed:** a state-sourced identity that can't be
//! materialized (no stored record, unreadable backend, or a corrupt
//! record) returns an error so boot aborts rather than silently
//! dialing backends without client auth.

use std::sync::Arc;

use aegis_core::config::{
    UpstreamIdentityRecord, UpstreamIdentitySource, WafConfig, UPSTREAM_IDENTITY_STATE_KEY,
};
use aegis_core::state::StateBackend;

/// Materialize a `source: state` upstream identity into a new cfg.
///
/// Returns:
/// - `Ok(Some(cfg))` — a state-sourced identity was read from the
///   config plane and folded into a cloned cfg (PUBLIC `cert_pem` +
///   `key_ref` populated on `zero_trust.upstream_identity`).
/// - `Ok(None)` — no state-sourced identity to materialize (no
///   `zero_trust.upstream_identity`, or its source is `file`); the
///   caller keeps the cfg unchanged.
/// - `Err(_)` — fail-closed: the identity is `source: state` but the
///   config plane has no record / can't be read / is corrupt.
pub async fn materialize_upstream_identity(
    cfg: &WafConfig,
    state: &Arc<dyn StateBackend>,
) -> aegis_core::Result<Option<WafConfig>> {
    let is_state = cfg
        .zero_trust
        .as_ref()
        .and_then(|z| z.upstream_identity.as_ref())
        .map(|id| id.source == UpstreamIdentitySource::State)
        .unwrap_or(false);
    if !is_state {
        return Ok(None);
    }

    let rec_bytes = state
        .get(UPSTREAM_IDENTITY_STATE_KEY)
        .await
        .map_err(|e| {
            aegis_core::WafError::Config(format!(
                "zero_trust.upstream_identity: config-plane read failed: {e}"
            ))
        })?
        .ok_or_else(|| {
            aegis_core::WafError::Config(
                "zero_trust.upstream_identity.source: state but no identity is stored \
                 in the config plane — PUT /api/zero-trust/upstream/identity first \
                 (fail-closed: refusing to dial backends without client auth)"
                    .into(),
            )
        })?;
    let rec: UpstreamIdentityRecord = serde_json::from_slice(&rec_bytes).map_err(|e| {
        aegis_core::WafError::Config(format!(
            "zero_trust.upstream_identity: stored record decode failed: {e}"
        ))
    })?;

    let mut next: WafConfig = cfg.clone();
    if let Some(id) = next
        .zero_trust
        .as_mut()
        .and_then(|z| z.upstream_identity.as_mut())
    {
        // PUBLIC cert materialized in-memory; the key stays a ref.
        id.cert_pem = Some(rec.cert_pem);
        id.key_ref = Some(rec.key_ref);
    }
    Ok(Some(next))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::in_memory::InMemoryBackend;

    fn cfg_with(zero_trust: &str) -> WafConfig {
        let yaml = format!(
            r#"
listeners:
  data: [{{ bind: "0.0.0.0:443" }}]
  admin: {{ bind: "127.0.0.1:9443" }}
routes:
  - {{ id: catch-all, path: "/", upstream: api }}
upstreams:
  api:
    members: [{{ addr: "127.0.0.1:8443" }}]
    connection: {{ tls: true }}
state: {{ backend: in_memory }}
{zero_trust}
"#
        );
        serde_yaml::from_str(&yaml).unwrap()
    }

    const STATE_ID: &str = "zero_trust:\n  upstream_identity:\n    source: state\n";

    #[tokio::test]
    async fn file_source_is_noop() {
        let cfg = cfg_with(
            "zero_trust:\n  upstream_identity:\n    source: file\n    cert_path: /x/c.pem\n    key_ref: /x/c.key\n",
        );
        let state: Arc<dyn StateBackend> = Arc::new(InMemoryBackend::new());
        assert!(materialize_upstream_identity(&cfg, &state)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn absent_identity_is_noop() {
        let cfg = cfg_with("");
        let state: Arc<dyn StateBackend> = Arc::new(InMemoryBackend::new());
        assert!(materialize_upstream_identity(&cfg, &state)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn state_source_without_record_fails_closed() {
        let cfg = cfg_with(STATE_ID);
        let state: Arc<dyn StateBackend> = Arc::new(InMemoryBackend::new());
        let err = materialize_upstream_identity(&cfg, &state)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("no identity is stored"), "got: {err}");
    }

    #[tokio::test]
    async fn state_source_corrupt_record_fails_closed() {
        let cfg = cfg_with(STATE_ID);
        let state: Arc<dyn StateBackend> = Arc::new(InMemoryBackend::new());
        state
            .cas_set(UPSTREAM_IDENTITY_STATE_KEY, None, b"not json", None)
            .await
            .unwrap();
        let err = materialize_upstream_identity(&cfg, &state)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("decode failed"), "got: {err}");
    }

    #[tokio::test]
    async fn state_source_folds_public_pem_and_key_ref() {
        let cfg = cfg_with(STATE_ID);
        let state: Arc<dyn StateBackend> = Arc::new(InMemoryBackend::new());
        let rec = UpstreamIdentityRecord {
            cert_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".into(),
            key_ref: "/run/secrets/waf-client.key".into(),
        };
        state
            .cas_set(
                UPSTREAM_IDENTITY_STATE_KEY,
                None,
                &serde_json::to_vec(&rec).unwrap(),
                None,
            )
            .await
            .unwrap();
        let out = materialize_upstream_identity(&cfg, &state)
            .await
            .unwrap()
            .expect("state source ⇒ Some");
        let id = out
            .zero_trust
            .as_ref()
            .and_then(|z| z.upstream_identity.as_ref())
            .unwrap();
        assert_eq!(id.cert_pem.as_deref(), Some(rec.cert_pem.as_str()));
        assert_eq!(id.key_ref.as_deref(), Some("/run/secrets/waf-client.key"));
    }
}
