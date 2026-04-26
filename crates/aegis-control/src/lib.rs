// aegis-control: control plane (M3)
//
// Owns: observability (prometheus, otel, access logs, health),
//       audit (hash chain, SIEM sinks), admin plane (dashboard, auth),
//       compliance profiles, GitOps, cluster membership view.

pub mod access_log;
pub mod api;
pub mod audit;
pub mod dashboard;
pub mod health;
pub mod metrics;
pub mod tracing_init;

pub mod admin_auth;
// pub mod compliance;
// pub mod gitops;
// pub mod slo;
// pub mod residency;
