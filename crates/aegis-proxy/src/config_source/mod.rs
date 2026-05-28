//! Config sources + the cluster config plane.
//!
//! The WAF boots from a local YAML file (`aegis_core::load_config`)
//! and hot-reloads it on change ([`crate::supervisor`]). Runtime
//! console edits propagate fleet-wide through the redis-backed config
//! plane (versioned `config:waf:doc`).
//!
//! 2026-05-28 — the etcd config *source* (`AEGIS_CONFIG_SOURCE=etcd`)
//! was removed: it was redundant with file delivery (image / ConfigMap
//! / GitOps) plus the redis config plane, and every reload-path change
//! had to be mirrored into it. Distributing a `waf.yaml` + the config
//! plane is the supported path. (etcd is still available as a *service-
//! discovery* adapter for upstream pools — see [`crate::sd::etcd`].)
//!
//! ## Modules
//!
//! - [`config_store`] — versioned `config:waf:doc` (CAS activation,
//!   immutable snapshots, rollback, per-node applied-version ACK).
//! - [`redis_source`] — the shared-store watcher that converges every
//!   node on the active config version.
//! - [`reload`] — the on-reload apply helpers shared by the file
//!   watcher and the config-plane watcher.

pub mod config_store;
pub mod redis_source;
pub mod reload;
