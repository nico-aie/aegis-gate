//! Boot materialization of state-sourced Zero Trust upstream-mTLS
//! material (P4, reference-only).
//!
//! Two kinds of PUBLIC material live in the Redis config plane and
//! must be folded into the cfg snapshot before the (sync) pool build
//! path (`ProxyContext::build` → `resolve_upstream_mtls`), which has
//! no `StateBackend`:
//!
//! 1. **Shared fleet identity** (`zero_trust.upstream_identity.source:
//!    state`) — the PUBLIC WAF client cert (key
//!    [`aegis_core::config::UPSTREAM_IDENTITY_STATE_KEY`],
//!    [`aegis_core::config::UpstreamIdentityRecord`]). The private key
//!    stays a `key_ref` reference, never read here.
//! 2. **Per-pool backend-CA trust bundles** — a console-uploaded CA a
//!    pool names via `upstream_mtls.trust` (key
//!    [`aegis_core::config::upstream_trust_state_key`],
//!    [`aegis_core::config::UpstreamTrustRecord`]).
//!
//! The async boot path ([`crate::run::run`]) calls
//! [`materialize_zero_trust_state`] which reads both and returns a
//! cloned, materialized cfg.
//!
//! **Fail closed (identity):** a `source: state` identity that can't
//! be materialized (no stored record / unreadable / corrupt) returns
//! an error so boot aborts rather than dialing backends without
//! client auth.
//!
//! **Trust bundles are lookup-first:** a pool's `trust` value that
//! matches an uploaded bundle is materialized to in-memory PEM;
//! otherwise it is left as a **file path** (today's behavior). A
//! referenced bundle that exists but is corrupt fails closed; one that
//! simply isn't uploaded falls through to the file-path reading, which
//! itself fails closed at client-build time if no such file exists.

use std::sync::Arc;

use aegis_core::config::{
    upstream_trust_state_key, UpstreamIdentityRecord, UpstreamIdentitySource, UpstreamTrustRecord,
    WafConfig, UPSTREAM_IDENTITY_STATE_KEY,
};
use aegis_core::state::StateBackend;

/// Materialize state-sourced Zero Trust material into a new cfg.
///
/// Returns:
/// - `Ok(Some(cfg))` — at least one piece of state material (the
///   shared identity and/or a referenced trust bundle) was read from
///   the config plane and folded into a cloned cfg.
/// - `Ok(None)` — nothing to materialize (no `source: state` identity
///   and no enabled pool references an uploaded trust bundle); the
///   caller keeps the cfg unchanged.
/// - `Err(_)` — fail-closed: a `source: state` identity has no stored
///   record / can't be read / is corrupt, or a referenced trust
///   bundle exists but is corrupt.
pub async fn materialize_zero_trust_state(
    cfg: &WafConfig,
    state: &Arc<dyn StateBackend>,
) -> aegis_core::Result<Option<WafConfig>> {
    let id_is_state = cfg
        .zero_trust
        .as_ref()
        .and_then(|z| z.upstream_identity.as_ref())
        .map(|id| id.source == UpstreamIdentitySource::State)
        .unwrap_or(false);

    // (pool_name, bundle_name) for every enabled pool that names a
    // trust anchor — candidates for a config-plane bundle lookup.
    let trust_refs: Vec<(String, String)> = cfg
        .upstreams
        .iter()
        .filter_map(|(name, pool)| {
            let m = pool.upstream_mtls.as_ref()?;
            if !m.enabled {
                return None;
            }
            let bundle = m.trust.as_ref()?.to_str()?.to_string();
            Some((name.clone(), bundle))
        })
        .collect();

    if !id_is_state && trust_refs.is_empty() {
        return Ok(None);
    }

    let mut next: WafConfig = cfg.clone();
    let mut changed = false;

    // 1. Shared fleet identity (fail-closed).
    if id_is_state {
        let rec = read_identity(state).await?;
        if let Some(id) = next
            .zero_trust
            .as_mut()
            .and_then(|z| z.upstream_identity.as_mut())
        {
            // PUBLIC cert materialized in-memory. Key is inline PEM
            // when uploaded via the console, otherwise a file ref.
            id.cert_pem = Some(rec.cert_pem);
            id.key_pem = rec.key_pem;
            if !rec.key_ref.is_empty() {
                id.key_ref = Some(rec.key_ref);
            }
        }
        changed = true;
    }

    // 2. Per-pool backend-CA trust bundles (lookup-first).
    for (pool_name, bundle) in &trust_refs {
        let key = upstream_trust_state_key(bundle);
        let Some(bytes) = state.get(&key).await.map_err(|e| {
            aegis_core::WafError::Config(format!(
                "upstream '{pool_name}': trust bundle '{bundle}' config-plane read failed: {e}"
            ))
        })?
        else {
            // Not an uploaded bundle — `trust` is a file path.
            continue;
        };
        let rec: UpstreamTrustRecord = serde_json::from_slice(&bytes).map_err(|e| {
            aegis_core::WafError::Config(format!(
                "upstream '{pool_name}': trust bundle '{bundle}' stored record decode failed: {e}"
            ))
        })?;
        if let Some(m) = next
            .upstreams
            .get_mut(pool_name)
            .and_then(|p| p.upstream_mtls.as_mut())
        {
            m.trust_pem = Some(rec.ca_pem);
            changed = true;
        }
    }

    if changed {
        Ok(Some(next))
    } else {
        Ok(None)
    }
}

/// Read + decode the shared identity record; fail-closed when absent
/// / unreadable / corrupt.
async fn read_identity(
    state: &Arc<dyn StateBackend>,
) -> aegis_core::Result<UpstreamIdentityRecord> {
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
    serde_json::from_slice(&rec_bytes).map_err(|e| {
        aegis_core::WafError::Config(format!(
            "zero_trust.upstream_identity: stored record decode failed: {e}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::in_memory::InMemoryBackend;

    fn cfg_with(pool_extra: &str, zero_trust: &str) -> WafConfig {
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
{pool_extra}
state: {{ backend: in_memory }}
{zero_trust}
"#
        );
        serde_yaml::from_str(&yaml).unwrap()
    }

    const STATE_ID: &str = "zero_trust:\n  upstream_identity:\n    source: state\n";
    const FILE_ID: &str = "zero_trust:\n  upstream_identity:\n    source: file\n    cert_path: /x/c.pem\n    key_ref: /x/c.key\n";

    #[tokio::test]
    async fn nothing_to_materialize_is_noop() {
        let cfg = cfg_with("", FILE_ID);
        let state: Arc<dyn StateBackend> = Arc::new(InMemoryBackend::new());
        assert!(materialize_zero_trust_state(&cfg, &state)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn state_identity_without_record_fails_closed() {
        let cfg = cfg_with("", STATE_ID);
        let state: Arc<dyn StateBackend> = Arc::new(InMemoryBackend::new());
        let err = materialize_zero_trust_state(&cfg, &state)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("no identity is stored"), "got: {err}");
    }

    #[tokio::test]
    async fn state_identity_corrupt_record_fails_closed() {
        let cfg = cfg_with("", STATE_ID);
        let state: Arc<dyn StateBackend> = Arc::new(InMemoryBackend::new());
        state
            .cas_set(UPSTREAM_IDENTITY_STATE_KEY, None, b"not json", None)
            .await
            .unwrap();
        let err = materialize_zero_trust_state(&cfg, &state)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("decode failed"), "got: {err}");
    }

    #[tokio::test]
    async fn state_identity_folds_public_pem_and_key_ref() {
        let cfg = cfg_with("", STATE_ID);
        let state: Arc<dyn StateBackend> = Arc::new(InMemoryBackend::new());
        let rec = UpstreamIdentityRecord {
            cert_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".into(),
            key_pem: None,
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
        let out = materialize_zero_trust_state(&cfg, &state)
            .await
            .unwrap()
            .expect("state identity ⇒ Some");
        let id = out
            .zero_trust
            .as_ref()
            .and_then(|z| z.upstream_identity.as_ref())
            .unwrap();
        assert_eq!(id.cert_pem.as_deref(), Some(rec.cert_pem.as_str()));
        assert_eq!(id.key_ref.as_deref(), Some("/run/secrets/waf-client.key"));
    }

    #[tokio::test]
    async fn trust_bundle_present_folds_ca_pem() {
        // File-source identity (so identity isn't the trigger) + a
        // pool naming an uploaded trust bundle.
        let cfg = cfg_with(
            "    upstream_mtls: { enabled: true, trust: backend-ca }\n",
            FILE_ID,
        );
        let state: Arc<dyn StateBackend> = Arc::new(InMemoryBackend::new());
        let rec = UpstreamTrustRecord {
            ca_pem: "-----BEGIN CERTIFICATE-----\nMIIBca\n-----END CERTIFICATE-----\n".into(),
        };
        state
            .cas_set(
                &upstream_trust_state_key("backend-ca"),
                None,
                &serde_json::to_vec(&rec).unwrap(),
                None,
            )
            .await
            .unwrap();
        let out = materialize_zero_trust_state(&cfg, &state)
            .await
            .unwrap()
            .expect("uploaded trust bundle ⇒ Some");
        let m = out.upstreams["api"].upstream_mtls.as_ref().unwrap();
        assert_eq!(m.trust_pem.as_deref(), Some(rec.ca_pem.as_str()));
    }

    #[tokio::test]
    async fn trust_bundle_absent_falls_through_to_file_path() {
        // Pool names `trust: /etc/waf/backend.pem` but no such bundle
        // is uploaded ⇒ no materialization, treated as a file path.
        let cfg = cfg_with(
            "    upstream_mtls: { enabled: true, trust: /etc/waf/backend.pem }\n",
            FILE_ID,
        );
        let state: Arc<dyn StateBackend> = Arc::new(InMemoryBackend::new());
        assert!(materialize_zero_trust_state(&cfg, &state)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn trust_bundle_corrupt_record_fails_closed() {
        let cfg = cfg_with(
            "    upstream_mtls: { enabled: true, trust: backend-ca }\n",
            FILE_ID,
        );
        let state: Arc<dyn StateBackend> = Arc::new(InMemoryBackend::new());
        state
            .cas_set(
                &upstream_trust_state_key("backend-ca"),
                None,
                b"not json",
                None,
            )
            .await
            .unwrap();
        let err = materialize_zero_trust_state(&cfg, &state)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("decode failed"), "got: {err}");
    }

    #[tokio::test]
    async fn disabled_pool_trust_is_not_materialized() {
        let cfg = cfg_with(
            "    upstream_mtls: { enabled: false, trust: backend-ca }\n",
            FILE_ID,
        );
        let state: Arc<dyn StateBackend> = Arc::new(InMemoryBackend::new());
        // Even if a bundle is uploaded, a disabled pool isn't touched.
        state
            .cas_set(
                &upstream_trust_state_key("backend-ca"),
                None,
                &serde_json::to_vec(&UpstreamTrustRecord { ca_pem: "x".into() }).unwrap(),
                None,
            )
            .await
            .unwrap();
        assert!(materialize_zero_trust_state(&cfg, &state)
            .await
            .unwrap()
            .is_none());
    }
}
