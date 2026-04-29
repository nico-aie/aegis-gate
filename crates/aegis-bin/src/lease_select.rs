//! Pick a `LeaseStore` impl from `cfg.state` at boot (B1-T4).
//!
//! Mirrors [`crate::state_select`]: same `redis` feature gate,
//! same fallback semantics. Selection rule:
//!
//! - `state.backend = in_memory` → `InProcessLease` (single-node)
//! - `state.backend = redis` (with `redis` feature) →
//!   `RedisLease` against the configured URL
//! - `state.backend = redis` (without the feature) → error
//!   pointing at the rebuild flag
//! - `state.backend = raft` → not implemented (Phase B)
//!
//! Returns the constructed lease store plus a one-line summary
//! suitable for the boot log.

use std::sync::Arc;

use aegis_core::cluster::{LeaseStore, NodeId};
use aegis_core::config::{StateBackendKind, WafConfig};
use aegis_core::error::{Result, WafError};
use aegis_proxy::cluster_lease::InProcessLease;

/// Derive a stable `NodeId` for this process.
///
/// Composition: hostname + PID + nanos-since-epoch. Stable
/// within one process lifetime; unique across nodes (hostname is
/// the cluster-wide discriminator) and across restarts of the
/// same node (nanos differ). For a long-lived deployment an
/// operator can override this via `AEGIS_NODE_ID` — handy for
/// testing or when the hostname is non-distinguishing.
pub fn derive_node_id() -> NodeId {
    if let Ok(explicit) = std::env::var("AEGIS_NODE_ID") {
        if !explicit.is_empty() {
            return NodeId::new(explicit);
        }
    }
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "unknown-host".to_string());
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    NodeId::new(format!("{host}-{pid}-{nanos}"))
}

/// Pick a lease store from config + the derived node id.
pub fn select(
    cfg: &WafConfig,
    node_id: NodeId,
) -> Result<(Arc<dyn LeaseStore>, String)> {
    match cfg.state.backend {
        StateBackendKind::InMemory => {
            let store = Arc::new(InProcessLease::new(node_id.clone()));
            let summary = format!(
                "in-process (single-node only — node_id={node_id})",
            );
            Ok((store, summary))
        }
        StateBackendKind::Redis => select_redis(cfg, node_id),
        StateBackendKind::Raft => Err(WafError::Config(
            "state.backend = raft for lease store is not implemented".into(),
        )),
    }
}

#[cfg(feature = "redis")]
fn select_redis(
    cfg: &WafConfig,
    node_id: NodeId,
) -> Result<(Arc<dyn LeaseStore>, String)> {
    use aegis_proxy::cluster_lease::RedisLease;
    use aegis_proxy::state::RedisConfig as ProxyRedisConfig;

    let redis_cfg = cfg.state.redis.as_ref().ok_or_else(|| {
        WafError::Config(
            "state.backend = redis but state.redis section is missing".into(),
        )
    })?;
    let url = redis_cfg
        .urls
        .first()
        .ok_or_else(|| {
            WafError::Config("state.redis.urls must contain at least one URL".into())
        })?
        .clone();

    if redis_cfg.cluster {
        return Err(WafError::Config(
            "state.redis.cluster = true requires a clustered lease store, not yet implemented (Phase B candidate)".into(),
        ));
    }

    let proxy_cfg = ProxyRedisConfig {
        url: url.clone(),
        pool_size: redis_cfg.pool_size,
        timeout: redis_cfg.timeout,
        cluster: false,
    };
    let store = RedisLease::connect(proxy_cfg, node_id.clone())?;
    let summary = format!(
        "redis @ {} (node_id={}, pool={}, timeout={:?})",
        url, node_id, redis_cfg.pool_size, redis_cfg.timeout,
    );
    Ok((Arc::new(store), summary))
}

#[cfg(not(feature = "redis"))]
fn select_redis(
    _cfg: &WafConfig,
    _node_id: NodeId,
) -> Result<(Arc<dyn LeaseStore>, String)> {
    Err(WafError::Config(
        "state.backend = redis but this binary was built without the `redis` feature. \
         Rebuild with `cargo build -p aegis-bin --features redis` to enable cluster leases."
            .into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml_with_state(state_block: &str) -> String {
        format!(
            r#"
listeners:
  data:
    - bind: "0.0.0.0:8080"
      tls: false
  admin:
    bind: "127.0.0.1:9443"
routes:
  - id: catch-all
    path: "/"
    match_type: prefix
    upstream: stub-pool
upstreams:
  stub-pool:
    members:
      - addr: "127.0.0.1:9999"
    lb: round_robin
{state_block}
"#
        )
    }

    /// `Arc<dyn LeaseStore>` doesn't impl Debug — same trick as
    /// `state_select::tests::run`.
    fn run(cfg: &WafConfig, node: NodeId) -> std::result::Result<String, String> {
        match select(cfg, node) {
            Ok((_, summary)) => Ok(summary),
            Err(e) => Err(e.to_string()),
        }
    }

    #[test]
    fn in_memory_selects_in_process_lease() {
        let cfg = aegis_core::load_config_str(&yaml_with_state(
            "state:\n  backend: in_memory",
        ))
        .unwrap();
        let summary = run(&cfg, NodeId::new("test-1"))
            .expect("in-memory should select cleanly");
        assert!(summary.contains("in-process"), "got: {summary}");
        assert!(summary.contains("test-1"), "summary should include node id: {summary}");
    }

    #[test]
    fn raft_returns_not_implemented() {
        let cfg = aegis_core::load_config_str(&yaml_with_state(
            "state:\n  backend: raft",
        ))
        .unwrap();
        let err = run(&cfg, NodeId::new("test-1"))
            .expect_err("raft should be rejected");
        assert!(err.contains("raft"), "got: {err}");
    }

    #[cfg(feature = "redis")]
    #[test]
    fn redis_with_section_selects_redis_lease() {
        let cfg = aegis_core::load_config_str(&yaml_with_state(
            "state:\n  backend: redis\n  redis:\n    urls: [\"redis://127.0.0.1:6379\"]\n    pool_size: 8\n    timeout: \"2s\"",
        )).unwrap();
        let summary = run(&cfg, NodeId::new("test-1"))
            .expect("redis should select cleanly");
        assert!(summary.contains("redis"), "got: {summary}");
        assert!(summary.contains("test-1"), "got: {summary}");
        assert!(summary.contains("127.0.0.1:6379"), "got: {summary}");
    }

    #[cfg(not(feature = "redis"))]
    #[test]
    fn redis_without_feature_errors_actionably() {
        let cfg = aegis_core::load_config_str(&yaml_with_state(
            "state:\n  backend: redis\n  redis:\n    urls: [\"redis://127.0.0.1:6379\"]",
        )).unwrap();
        let err = run(&cfg, NodeId::new("test-1"))
            .expect_err("redis without feature should error");
        assert!(
            err.contains("--features redis"),
            "error should suggest cargo flag: {err}",
        );
    }

    #[test]
    fn explicit_node_id_env_var_wins() {
        // Test isolation note: this mutates a process-wide env
        // var; safe because this is the only test that touches
        // it and we restore on exit.
        std::env::set_var("AEGIS_NODE_ID", "explicit-node");
        let derived = derive_node_id();
        std::env::remove_var("AEGIS_NODE_ID");
        assert_eq!(derived.as_str(), "explicit-node");
    }

    #[test]
    fn derived_node_id_is_non_empty() {
        std::env::remove_var("AEGIS_NODE_ID");
        let derived = derive_node_id();
        assert!(!derived.as_str().is_empty());
    }
}
