//! ETCD-T1 — alternate config sources beyond a local YAML file.
//!
//! Today the WAF boots from a local YAML file via
//! `aegis_core::load_config(path)`. This module adds opt-in
//! sources that fetch the same `WafConfig` shape from a remote
//! key-value store, so multi-node deployments don't have to
//! ship a YAML file to every node and operators can centralise
//! configuration changes.
//!
//! ## Why YAML-as-blob, not a richer schema
//!
//! The etcd value is the *same* YAML the file loader accepts —
//! verbatim. This keeps the validation surface single-sourced
//! (every config still flows through `WafConfig::validate`) and
//! lets operators move between sources by copying the file's
//! contents into the etcd key. A future enhancement could split
//! `/aegis/config/rules/<id>` into separate keys per the
//! `deploy/etcd/README.md` design, but the single-blob form is
//! the smallest valid first slice.
//!
//! ## Sources
//!
//! - [`etcd_source`] — etcd v3 REST gateway (`/v3/kv/range`).
//!   Reuses the auth + TLS plumbing pattern from `sd::etcd`.
//!
//! ## Boot path
//!
//! `aegis-bin::main::run_gateway` checks `AEGIS_CONFIG_SOURCE`:
//! when unset (default) it loads YAML; when `etcd` it pulls the
//! initial config from `AEGIS_CONFIG_ETCD_KEY` (default
//! `/aegis/config/waf`) before falling through to the same boot
//! sequence.

#[cfg(feature = "etcd")]
pub mod etcd_source;

pub mod config_store;
pub mod redis_source;
pub mod reload;
