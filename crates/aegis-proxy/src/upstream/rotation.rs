//! P5 — hot rotation of the Zero Trust upstream-mTLS material on a
//! config-plane (`cas_set`) change, **no restart, no dropped
//! connections**.
//!
//! Storing a new shared identity or backend-CA trust bundle writes to
//! the config plane (`aegis:zt:upstream:identity` / `:trust:<name>`),
//! but nodes only materialize the PUBLIC PEM at boot. In a fleet,
//! "rotate = rolling restart of every node" is a real operational tax.
//! This background task closes that gap: it polls the plane, and when
//! the ZT material changes it re-materializes the PUBLIC PEM, re-seeds
//! the registry's shared identity, and re-applies the pool table.
//!
//! Why that is enough: `PoolKey` (forward.rs) includes the resolved
//! mTLS fingerprint, and the per-process client cache is keyed by it.
//! A re-apply with fresh material changes each affected pool's
//! fingerprint, so the **next dial** builds a new client with the new
//! cert while in-flight requests finish on the old `Arc<PooledClient>`
//! — eventual, per-node convergence with zero connection drops.
//!
//! Fail-safe: the task only re-seeds the identity when it successfully
//! reads + decodes a record; a *deleted* identity keeps the last-good
//! one (it never downgrades a pool to no-client-auth). File-source
//! identities are not managed here (rotate the file + reload).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;

use aegis_core::config::{
    upstream_trust_state_key, PoolConfig, UpstreamIdentityConfig, UpstreamIdentityRecord,
    UpstreamIdentitySource, UpstreamTrustRecord, WafConfig, UPSTREAM_IDENTITY_STATE_KEY,
};
use aegis_core::state::StateBackend;

use crate::upstream::registry::PoolRegistry;

/// Default reconcile interval. ZT cert changes are rare; 5 s is
/// responsive for an operator action without polling the plane hot.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Live rotation status (observability — the dashboard reads this so it can
// show the LIVE applied cert without a restart / stale boot snapshot).
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct RotationStatus {
    /// Increments on every applied rotation (0 = nothing applied yet).
    pub generation: u64,
    /// Unix-ms of the last applied rotation (0 = never).
    pub applied_ms: u64,
    /// PUBLIC cert PEM of the currently-applied shared identity, when
    /// state-sourced. Lets the read API reflect a live rotation.
    pub identity_cert_pem: Option<String>,
}

fn status_cell() -> &'static ArcSwap<RotationStatus> {
    static S: std::sync::OnceLock<ArcSwap<RotationStatus>> = std::sync::OnceLock::new();
    S.get_or_init(|| ArcSwap::from_pointee(RotationStatus::default()))
}

/// Snapshot the live rotation status.
pub fn status() -> RotationStatus {
    (**status_cell().load()).clone()
}

/// Immediately update the rotation status after a console PUT to
/// `/api/zero-trust/upstream/identity`, so the GET endpoint reflects
/// the new cert without waiting for the next poll cycle (≤5 s).
/// Called from `admin_mutate::handle_zt_upstream_identity_put` on
/// a successful `cas_set`.
pub fn notify_identity_updated(cert_pem: Option<String>) {
    record_applied(cert_pem);
}

fn record_applied(identity_cert_pem: Option<String>) {
    let prev = status_cell().load();
    status_cell().store(Arc::new(RotationStatus {
        generation: prev.generation + 1,
        applied_ms: now_ms(),
        // Keep the last-known cert when this rotation only changed trust.
        identity_cert_pem: identity_cert_pem.or_else(|| prev.identity_cert_pem.clone()),
    }));
}

/// Render the `/api/zero-trust/upstream/rotation` body.
pub fn render() -> String {
    let s = status();
    serde_json::json!({
        "generation": s.generation,
        "applied_ms": s.applied_ms,
        "live": s.generation > 0,
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// Reconcile core (testable: pure fingerprint + fold, IO isolated in `read`)
// ---------------------------------------------------------------------------

/// The desired ZT material read from the config plane for one tick.
#[derive(Clone, Debug, Default)]
pub struct ZtMaterial {
    /// The state-sourced shared identity (PUBLIC cert + key_ref), or
    /// `None` for a file-source / absent / unreadable identity.
    pub identity: Option<UpstreamIdentityConfig>,
    /// `bundle name → PUBLIC CA PEM` for every uploaded bundle an
    /// enabled pool references.
    pub trust: HashMap<String, String>,
    /// Change-detection fingerprint over the public material.
    pub fingerprint: String,
}

/// Read the desired ZT material from the config plane for the given
/// live pool set + config snapshot. IO-only; the fold is pure.
pub async fn read_material(
    state: &Arc<dyn StateBackend>,
    cfg: &WafConfig,
    pools: &HashMap<String, PoolConfig>,
) -> ZtMaterial {
    let id_is_state = cfg
        .zero_trust
        .as_ref()
        .and_then(|z| z.upstream_identity.as_ref())
        .map(|id| id.source == UpstreamIdentitySource::State)
        .unwrap_or(false);

    // Shared identity (state source only).
    let identity = if id_is_state {
        match state.get(UPSTREAM_IDENTITY_STATE_KEY).await {
            Ok(Some(bytes)) => serde_json::from_slice::<UpstreamIdentityRecord>(&bytes)
                .ok()
                .map(|rec| UpstreamIdentityConfig {
                    source: UpstreamIdentitySource::State,
                    cert_path: None,
                    key_ref: if rec.key_ref.is_empty() { None } else { Some(rec.key_ref) },
                    cert_pem: Some(rec.cert_pem),
                    key_pem: rec.key_pem,
                }),
            _ => None,
        }
    } else {
        None
    };

    // Bundle names referenced by enabled pools (bare names only).
    let mut wanted: Vec<String> = pools
        .values()
        .filter_map(|p| {
            let m = p.upstream_mtls.as_ref()?;
            if !m.enabled {
                return None;
            }
            let t = m.trust.as_ref()?.to_str()?;
            if t.contains('/') {
                return None; // file path, not a bundle
            }
            Some(t.to_string())
        })
        .collect();
    wanted.sort();
    wanted.dedup();

    let mut trust: HashMap<String, String> = HashMap::new();
    for name in wanted {
        if let Ok(Some(bytes)) = state.get(&upstream_trust_state_key(&name)).await {
            if let Ok(rec) = serde_json::from_slice::<UpstreamTrustRecord>(&bytes) {
                trust.insert(name, rec.ca_pem);
            }
        }
    }

    let fingerprint = fingerprint(&identity, &trust);
    ZtMaterial {
        identity,
        trust,
        fingerprint,
    }
}

/// Stable change-detection fingerprint over the PUBLIC material.
fn fingerprint(identity: &Option<UpstreamIdentityConfig>, trust: &HashMap<String, String>) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    identity
        .as_ref()
        .and_then(|i| i.cert_pem.as_deref())
        .unwrap_or("")
        .hash(&mut h);
    identity
        .as_ref()
        .and_then(|i| i.key_ref.as_deref())
        .unwrap_or("")
        .hash(&mut h);
    let mut entries: Vec<(&String, &String)> = trust.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    for (k, v) in entries {
        k.hash(&mut h);
        v.hash(&mut h);
    }
    format!("zt-rot:v1:{:016x}", h.finish())
}

/// Fold the materialized trust PEM into a copy of the live pool set.
/// Pure. Pools whose `trust` names a bundle present in `material` get
/// `trust_pem` set; everything else is untouched.
pub fn fold_pools(
    material: &ZtMaterial,
    pools: &HashMap<String, PoolConfig>,
) -> HashMap<String, PoolConfig> {
    let mut out = pools.clone();
    for pool in out.values_mut() {
        let Some(m) = pool.upstream_mtls.as_mut() else {
            continue;
        };
        if !m.enabled {
            continue;
        }
        let Some(bundle) = m.trust.as_ref().and_then(|p| p.to_str()) else {
            continue;
        };
        if let Some(pem) = material.trust.get(bundle) {
            m.trust_pem = Some(pem.clone());
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The background task
// ---------------------------------------------------------------------------

/// Spawn the reconcile loop. Cheap no-op every tick when no pool has
/// upstream mTLS enabled (the common case).
pub fn spawn(
    state: Arc<dyn StateBackend>,
    registry: PoolRegistry,
    cfg: Arc<ArcSwap<WafConfig>>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Seed `last` from the boot material so we don't re-apply an
        // unchanged identity on the first tick.
        let mut last_fp: Option<String> = None;
        loop {
            tokio::time::sleep(interval).await;
            let pools = registry.current_pools();
            let snap = cfg.load_full();

            // Always read ZT material from the config plane so that a
            // console identity upload (PUT /api/zero-trust/upstream/identity)
            // is reflected in the GET endpoint overlay even before any pool
            // has mTLS enabled. Previously the early-exit on `!any_mtls`
            // blocked this, meaning the dashboard showed `configured: false`
            // after a successful PUT until the operator turned on mTLS for
            // at least one pool.
            let material = read_material(&state, &snap, &pools).await;
            if last_fp.as_deref() == Some(material.fingerprint.as_str()) {
                continue;
            }

            // Re-seed the shared identity only on a good read (never
            // downgrade to no-client-auth on a missing/corrupt record).
            if let Some(id) = material.identity.clone() {
                registry.seed_upstream_identity(Some(id));
            }

            let any_mtls = pools
                .values()
                .any(|p| p.upstream_mtls.as_ref().map(|m| m.enabled).unwrap_or(false));

            if any_mtls {
                // Apply pool changes and record the full rotation.
                let folded = fold_pools(&material, &pools);
                match registry.apply(&folded) {
                    Ok(()) => {
                        let cert = material.identity.as_ref().and_then(|i| i.cert_pem.clone());
                        record_applied(cert);
                        last_fp = Some(material.fingerprint);
                        tracing::info!(
                            generation = status().generation,
                            "zero_trust: hot-rotated upstream-mTLS material (no restart)"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "zero_trust: hot rotation apply failed; keeping last-good");
                    }
                }
            } else {
                // No mTLS pools yet — still record the identity change so
                // the GET /api/zero-trust/upstream/identity overlay reflects
                // a console upload without requiring a restart or an enabled
                // pool.
                let cert = material.identity.as_ref().and_then(|i| i.cert_pem.clone());
                record_applied(cert);
                last_fp = Some(material.fingerprint);
                tracing::debug!(
                    generation = status().generation,
                    "zero_trust: identity updated (no mTLS pools active yet)"
                );
            }
        }
    })
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::in_memory::InMemoryBackend;

    fn cfg_with(pool_extra: &str, zt: &str) -> WafConfig {
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
{zt}
"#
        );
        serde_yaml::from_str(&yaml).unwrap()
    }

    const STATE_ID: &str = "zero_trust:\n  upstream_identity:\n    source: state\n";

    async fn store_identity(state: &Arc<dyn StateBackend>, cert: &str) {
        let rec = UpstreamIdentityRecord {
            cert_pem: cert.into(),
            key_pem: None,
            key_ref: "/run/secrets/waf.key".into(),
        };
        let bytes = serde_json::to_vec(&rec).unwrap();
        let current = state.get(UPSTREAM_IDENTITY_STATE_KEY).await.unwrap();
        state
            .cas_set(UPSTREAM_IDENTITY_STATE_KEY, current.as_deref(), &bytes, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn read_material_reads_state_identity_and_fingerprints() {
        let state: Arc<dyn StateBackend> = Arc::new(InMemoryBackend::new());
        store_identity(&state, "CERT-A").await;
        let cfg = cfg_with("    upstream_mtls: { enabled: true }\n", STATE_ID);
        let m = read_material(&state, &cfg, &cfg.upstreams).await;
        assert_eq!(m.identity.as_ref().unwrap().cert_pem.as_deref(), Some("CERT-A"));
        let fp_a = m.fingerprint.clone();
        // A new cert ⇒ a different fingerprint (triggers a rotation).
        store_identity(&state, "CERT-B").await;
        let m2 = read_material(&state, &cfg, &cfg.upstreams).await;
        assert_eq!(m2.identity.as_ref().unwrap().cert_pem.as_deref(), Some("CERT-B"));
        assert_ne!(fp_a, m2.fingerprint, "rotated cert must change the fingerprint");
    }

    #[tokio::test]
    async fn read_material_skips_file_source_identity() {
        let state: Arc<dyn StateBackend> = Arc::new(InMemoryBackend::new());
        let file_id = "zero_trust:\n  upstream_identity:\n    source: file\n    cert_path: /x/c.pem\n    key_ref: /x/c.key\n";
        let cfg = cfg_with("    upstream_mtls: { enabled: true }\n", file_id);
        let m = read_material(&state, &cfg, &cfg.upstreams).await;
        assert!(m.identity.is_none(), "file-source identity is not managed by rotation");
    }

    #[tokio::test]
    async fn read_material_folds_referenced_trust_bundle() {
        let state: Arc<dyn StateBackend> = Arc::new(InMemoryBackend::new());
        store_identity(&state, "CERT-A").await;
        let rec = UpstreamTrustRecord { ca_pem: "CA-PEM".into() };
        state
            .cas_set(&upstream_trust_state_key("backend-ca"), None, &serde_json::to_vec(&rec).unwrap(), None)
            .await
            .unwrap();
        let cfg = cfg_with("    upstream_mtls: { enabled: true, trust: backend-ca }\n", STATE_ID);
        let m = read_material(&state, &cfg, &cfg.upstreams).await;
        assert_eq!(m.trust.get("backend-ca").map(String::as_str), Some("CA-PEM"));
        let folded = fold_pools(&m, &cfg.upstreams);
        assert_eq!(
            folded["api"].upstream_mtls.as_ref().unwrap().trust_pem.as_deref(),
            Some("CA-PEM")
        );
    }

    #[tokio::test]
    async fn fold_leaves_file_path_trust_untouched() {
        let state: Arc<dyn StateBackend> = Arc::new(InMemoryBackend::new());
        store_identity(&state, "CERT-A").await;
        let cfg = cfg_with("    upstream_mtls: { enabled: true, trust: /etc/waf/ca.pem }\n", STATE_ID);
        let m = read_material(&state, &cfg, &cfg.upstreams).await;
        assert!(m.trust.is_empty(), "path-style trust is not a bundle");
        let folded = fold_pools(&m, &cfg.upstreams);
        assert!(folded["api"].upstream_mtls.as_ref().unwrap().trust_pem.is_none());
    }
}
