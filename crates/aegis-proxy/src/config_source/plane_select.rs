//! CONFIG-PLANE store selection (H2b P2c, 2026-06-25) — pick the durable
//! config backend from `config_plane.store` at boot.
//!
//! Mirrors [`crate::state::*`] / `aegis-bin::state_select` for the data
//! plane: reads `cfg.config_plane.store` and constructs the matching
//! [`aegis_core::config_backend::ConfigBackend`] (+ an optional native
//! [`ConfigWatch`]) for the config plane. The `etcd` arm is feature-gated so
//! a default build never pulls the etcd-client gRPC tree, and selecting
//! `etcd` on a binary built without the `etcd_config` feature is a **loud
//! boot error** — the same operator-footgun guard as `state.backend = redis`
//! without the `redis` feature.
//!
//! - `shared_state` (default): the config doc rides the data-plane
//!   [`StateBackend`] via [`SharedStateConfigBackend`] — today's behaviour,
//!   zero change. Returns `watch: None` so the caller keeps using the
//!   existing pub/sub nudge.
//! - `etcd`: a dedicated [`EtcdConfigBackend`](super::etcd_backend) plus its
//!   native [`ConfigWatch`] (so `notify_change` is a no-op and convergence is
//!   watch-driven, not poll-driven).

use std::sync::Arc;

use aegis_core::config::{ConfigPlaneStore, WafConfig};
use aegis_core::config_backend::{ConfigBackend, ConfigWatch, SharedStateConfigBackend};
use aegis_core::error::Result;
use aegis_core::state::StateBackend;

/// The selected config plane: the durable backend, an optional native watch
/// (etcd only — `None` means "use the existing nudge bus"), and a one-line
/// boot-log summary.
pub struct ConfigPlaneSelection {
    pub backend: Arc<dyn ConfigBackend>,
    pub watch: Option<Arc<dyn ConfigWatch>>,
    pub summary: String,
}

/// Pick the config-plane store from `cfg.config_plane.store`. `state` is the
/// already-selected data-plane backend, used for the `shared_state` default.
pub async fn select(
    cfg: &WafConfig,
    state: Arc<dyn StateBackend>,
) -> Result<ConfigPlaneSelection> {
    match cfg.config_plane.store {
        ConfigPlaneStore::SharedState => Ok(ConfigPlaneSelection {
            backend: SharedStateConfigBackend::arc(state),
            watch: None,
            summary: "shared_state (config doc rides state.backend)".to_string(),
        }),
        ConfigPlaneStore::Etcd => select_etcd(cfg).await,
    }
}

#[cfg(feature = "etcd_config")]
async fn select_etcd(cfg: &WafConfig) -> Result<ConfigPlaneSelection> {
    use super::etcd_backend::EtcdConfigBackend;

    // validate() already guarantees a non-empty endpoint list when
    // store == etcd; default to empty so connect() emits the precise error
    // if a caller skipped validation.
    let endpoints = cfg
        .config_plane
        .etcd
        .as_ref()
        .map(|e| e.endpoints.clone())
        .unwrap_or_default();
    let etcd = EtcdConfigBackend::connect(&endpoints).await?;
    let watch = etcd.config_watch();
    let summary = format!("etcd @ {} (native KV/Txn/Watch/Lease)", endpoints.join(","));
    Ok(ConfigPlaneSelection {
        backend: etcd.into_backend(),
        watch: Some(watch),
        summary,
    })
}

#[cfg(not(feature = "etcd_config"))]
async fn select_etcd(_cfg: &WafConfig) -> Result<ConfigPlaneSelection> {
    Err(aegis_core::error::WafError::Config(
        "config_plane.store = etcd but this binary was built without the \
         `etcd_config` feature. Rebuild with \
         `cargo build -p aegis-bin --features etcd_config`, or set \
         config_plane.store: shared_state."
            .into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::in_memory::InMemoryBackend;

    fn cfg_with_store(block: &str) -> WafConfig {
        let yaml = format!(
            "listeners:\n  data:\n    - bind: \"127.0.0.1:8080\"\n  admin:\n    \
             bind: \"127.0.0.1:9090\"\nroutes:\n  - id: r\n    path: \"/\"\n    \
             upstream: u\nupstreams:\n  u:\n    members:\n      - addr: \
             \"127.0.0.1:3000\"\nstate:\n  backend: in_memory\n{block}",
        );
        aegis_core::load_config_str(&yaml).expect("test config parses + validates")
    }

    #[tokio::test]
    async fn shared_state_is_the_default_and_needs_no_watch_override() {
        let cfg = cfg_with_store("");
        let state: Arc<dyn StateBackend> = Arc::new(InMemoryBackend::new());
        let sel = select(&cfg, state).await.unwrap();
        assert!(sel.watch.is_none(), "shared_state reuses the pub/sub nudge");
        assert!(sel.summary.contains("shared_state"));
        // The selected backend is usable (a CAS write round-trips through the
        // wrapped state backend).
        assert!(sel
            .backend
            .cas_set("config:waf:doc", None, b"v1", None)
            .await
            .unwrap());
    }

    // The "store: etcd without the etcd_config feature → loud error" guard.
    // Only meaningful in the default (no-feature) build; under --features
    // etcd_config this arm connects instead, so compile it out there.
    #[cfg(not(feature = "etcd_config"))]
    #[tokio::test]
    async fn etcd_without_feature_is_a_loud_boot_error() {
        let cfg = cfg_with_store(
            "config_plane:\n  store: etcd\n  etcd:\n    endpoints:\n      - \"http://127.0.0.1:2379\"\n",
        );
        let state: Arc<dyn StateBackend> = Arc::new(InMemoryBackend::new());
        let res = select(&cfg, state).await;
        let err = match res {
            Ok(_) => panic!("etcd store without the feature must fail boot"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("etcd_config") && err.contains("feature"),
            "error must point at the missing cargo feature: {err}",
        );
    }
}
