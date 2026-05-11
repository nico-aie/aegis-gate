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
/// Resolution order (first match wins):
///
/// 1. `cfg.node.id` (HA-T3) — operator-supplied stable string.
/// 2. `AEGIS_NODE_ID` env var — same intent, lower precedence
///    so YAML wins over the environment.
/// 3. `${HOSTNAME}-${PID}-${NANOS}` — derived. Stable within
///    one process lifetime; not stable across restarts.
///
/// For long-running production clusters set option 1 in YAML
/// (e.g. `node.id: "${POD_NAME}"` populated from a k8s
/// downward-API mount). Tests pass `&WafConfig::default()` if
/// they want the legacy host-pid-nanos behaviour.
pub fn derive_node_id(cfg: &WafConfig) -> NodeId {
    if let Some(explicit) = cfg.node.id.as_deref() {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            return NodeId::new(trimmed);
        }
    }
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
        // 2026-05-11 CORE-09/CTL-08 fix — raft is now rejected at
        // WafConfig::validate() time (the lint layer), not at
        // run() time. load_config_str calls validate(), so the
        // error surfaces here instead of a layer deeper.
        let err = aegis_core::load_config_str(&yaml_with_state(
            "state:\n  backend: raft",
        ))
        .expect_err("raft should be rejected at config load");
        let err = format!("{err:?}");
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

    fn minimal_cfg() -> WafConfig {
        // Smallest YAML that passes WafConfig::validate(). Keeps
        // these tests independent of the rest of the workspace.
        let yaml = r#"
listeners:
  admin:
    bind: "127.0.0.1:0"
  data:
    - bind: "127.0.0.1:0"
routes:
  - id: "default"
    path: "/"
    upstream: "default"
upstreams:
  default:
    members:
      - addr: "127.0.0.1:8080"
state:
  backend: "in_memory"
"#;
        aegis_core::config::load_config_str(yaml)
            .expect("minimal config must parse")
    }

    // The three tests below mutate `AEGIS_NODE_ID`, which is
    // process-global. Cargo runs unit tests in parallel by
    // default, so we serialize them under a single mutex.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn explicit_node_id_env_var_wins() {
        let _g = env_lock();
        std::env::set_var("AEGIS_NODE_ID", "explicit-node");
        let cfg = minimal_cfg();
        let derived = derive_node_id(&cfg);
        std::env::remove_var("AEGIS_NODE_ID");
        assert_eq!(derived.as_str(), "explicit-node");
    }

    #[test]
    fn derived_node_id_is_non_empty() {
        let _g = env_lock();
        std::env::remove_var("AEGIS_NODE_ID");
        let cfg = minimal_cfg();
        let derived = derive_node_id(&cfg);
        assert!(!derived.as_str().is_empty());
    }

    #[test]
    fn cfg_node_id_overrides_env() {
        // HA-T3 — explicit YAML config wins over env var.
        let _g = env_lock();
        std::env::set_var("AEGIS_NODE_ID", "from-env");
        let mut cfg = minimal_cfg();
        cfg.node.id = Some("from-cfg".to_string());
        let derived = derive_node_id(&cfg);
        std::env::remove_var("AEGIS_NODE_ID");
        assert_eq!(derived.as_str(), "from-cfg");
    }
}
