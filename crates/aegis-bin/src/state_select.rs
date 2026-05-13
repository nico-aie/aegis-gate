//! Pick a `StateBackend` impl from `cfg.state` at boot.
//!
//! **B1-T2 — Phase B.** Reads `cfg.state.backend` and constructs
//! the matching `Arc<dyn StateBackend>` for the data plane. The
//! `redis` branch is feature-gated so a default build never pulls
//! the Redis crate tree.
//!
//! Selection logic today is single-keyspace (one backend covers
//! every state op). Per-keyspace routing
//! (`state.routing.{rate_limit,ddos,risk,challenge}`) is
//! intentionally deferred until **B1-T6** lands the
//! partition-safe merge — once that's in, this function gets a
//! sibling that builds a `KeyspaceMap` instead of one backend.
//!
//! ## Why this is its own module
//!
//! The selection lives behind a public `select` function so the
//! `aegis-bin` integration tests can exercise it without spinning
//! up the whole gateway. That gives us live coverage for the
//! "config says Redis but feature is off" error path, which is
//! the most-likely operator footgun.

use std::sync::Arc;

use aegis_core::config::{StateBackendKind, WafConfig};
use aegis_core::error::{Result, WafError};
use aegis_core::state::StateBackend;
use aegis_proxy::state::InMemoryBackend;

/// Pick a state backend from config. Returns the constructed
/// backend plus a one-line summary suitable for the boot log.
pub fn select(cfg: &WafConfig) -> Result<(Arc<dyn StateBackend>, String)> {
    match cfg.state.backend {
        StateBackendKind::InMemory => {
            let backend = Arc::new(InMemoryBackend::new());
            let summary = "in-memory (single-node only — no shared state)".to_string();
            Ok((backend, summary))
        }
        StateBackendKind::Redis => select_redis(cfg),
        StateBackendKind::Raft => Err(WafError::Config(
            "state.backend = raft is not implemented (Phase B candidate, not on B1)".into(),
        )),
    }
}

#[cfg(feature = "redis")]
fn select_redis(cfg: &WafConfig) -> Result<(Arc<dyn StateBackend>, String)> {
    use aegis_core::config::ReconcileMode;
    use aegis_proxy::state::{
        RedisBackend, RedisConfig as ProxyRedisConfig, ReconcilingBackend,
    };

    let redis_cfg = cfg.state.redis.as_ref().ok_or_else(|| {
        WafError::Config(
            "state.backend = redis but state.redis section is missing".into(),
        )
    })?;

    // The aegis-core schema allows a list of URLs (for cluster
    // mode); the single-node RedisBackend takes the first. A
    // future RedisClusterBackend (Phase B candidate beyond B1)
    // will consume the whole list.
    let url = redis_cfg
        .urls
        .first()
        .ok_or_else(|| {
            WafError::Config(
                "state.redis.urls must contain at least one URL".into(),
            )
        })?
        .clone();

    if redis_cfg.cluster {
        return Err(WafError::Config(
            "state.redis.cluster = true requires the redis_cluster backend, not yet implemented (Phase B candidate)".into(),
        ));
    }

    // Honor reconcile.mode. Only `Max` is implemented today;
    // the other variants exist in the schema for forward
    // compatibility (Phase B candidate).
    match cfg.state.reconcile.mode {
        ReconcileMode::Max => {}
        ReconcileMode::Latest => {
            return Err(WafError::Config(
                "state.reconcile.mode = latest is not implemented; use `max` until a Phase B follow-up lands the latest-wins merge".into(),
            ));
        }
        ReconcileMode::FailSafe => {
            return Err(WafError::Config(
                "state.reconcile.mode = fail_safe is not implemented; use `max` until a Phase B follow-up lands the fail-safe merge".into(),
            ));
        }
    }

    let proxy_cfg = ProxyRedisConfig {
        url: url.clone(),
        pool_size: redis_cfg.pool_size,
        timeout: redis_cfg.timeout,
        cluster: false,
    };
    let primary: Arc<dyn StateBackend> = Arc::new(RedisBackend::connect(proxy_cfg)?);

    // B1-T6 — wrap the Redis primary in ReconcilingBackend so a
    // Redis partition transparently falls through to a local
    // in-memory fallback. Block lists are buffered for replay
    // on heal; counters fall through but don't merge back (see
    // module docs in `state::reconcile`).
    let backend: Arc<dyn StateBackend> = Arc::new(ReconcilingBackend::new(primary));

    let summary = format!(
        "redis @ {} (pool={}, timeout={:?}, reconcile=max+local-fallback)",
        url, redis_cfg.pool_size, redis_cfg.timeout,
    );
    Ok((backend, summary))
}

#[cfg(not(feature = "redis"))]
fn select_redis(_cfg: &WafConfig) -> Result<(Arc<dyn StateBackend>, String)> {
    Err(WafError::Config(
        "state.backend = redis but this binary was built without the `redis` feature. \
         Rebuild with `cargo build -p aegis-bin --features redis`."
            .into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimum-viable config YAML with the given `state:` block.
    /// Schema mirrors `config/dev.yaml` — listeners + one route + one
    /// upstream pool are mandatory.
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

    fn yaml_in_memory() -> String {
        yaml_with_state("state:\n  backend: in_memory")
    }

    fn yaml_redis() -> String {
        yaml_with_state(
            "state:\n  backend: redis\n  redis:\n    urls: [\"redis://127.0.0.1:6379\"]\n    pool_size: 8\n    timeout: \"2s\"",
        )
    }

    #[cfg(feature = "redis")]
    fn yaml_redis_no_section() -> String {
        yaml_with_state("state:\n  backend: redis")
    }

    fn yaml_raft() -> String {
        yaml_with_state("state:\n  backend: raft")
    }

    /// `Arc<dyn StateBackend>` doesn't impl Debug, so we can't
    /// use `unwrap` / `expect_err` directly on the `Result`. This
    /// helper returns the summary on success and the error
    /// message on failure — both as `String` so tests can assert
    /// substrings without caring which side they got.
    fn run(cfg: &WafConfig) -> std::result::Result<String, String> {
        match select(cfg) {
            Ok((_, summary)) => Ok(summary),
            Err(e) => Err(e.to_string()),
        }
    }

    #[test]
    fn in_memory_selects_in_memory_backend() {
        let cfg = aegis_core::load_config_str(&yaml_in_memory()).unwrap();
        let summary = run(&cfg).expect("in-memory should select cleanly");
        assert!(summary.contains("in-memory"), "got summary: {summary}");
    }

    #[test]
    fn raft_returns_not_implemented() {
        // 2026-05-11 CORE-09/CTL-08 fix — raft now rejected at
        // load_config_str's validate() step. The state_select::run
        // guard is preserved as defense-in-depth but never fires
        // in normal operation; this test asserts the validate
        // layer catches it first.
        let err = aegis_core::load_config_str(&yaml_raft())
            .expect_err("raft should be rejected at config load");
        let err = format!("{err:?}");
        assert!(err.contains("raft"), "expected raft-related error, got: {err}");
    }

    #[cfg(feature = "redis")]
    #[test]
    fn redis_with_section_selects_redis_backend() {
        let cfg = aegis_core::load_config_str(&yaml_redis()).unwrap();
        let summary = run(&cfg).expect("redis should select cleanly");
        assert!(summary.contains("redis"), "got summary: {summary}");
        assert!(
            summary.contains("127.0.0.1:6379"),
            "summary should include URL, got: {summary}"
        );
    }

    #[cfg(feature = "redis")]
    #[test]
    fn redis_without_section_errors_with_actionable_message() {
        let cfg = aegis_core::load_config_str(&yaml_redis_no_section()).unwrap();
        let err = run(&cfg).expect_err("redis backend without section should error");
        assert!(err.contains("state.redis section"), "got: {err}");
    }

    #[cfg(not(feature = "redis"))]
    #[test]
    fn redis_without_feature_errors_with_actionable_message() {
        let cfg = aegis_core::load_config_str(&yaml_redis()).unwrap();
        let err = run(&cfg)
            .expect_err("redis backend without `redis` feature should error");
        assert!(
            err.contains("--features redis"),
            "error should suggest the cargo flag, got: {err}"
        );
    }
}
