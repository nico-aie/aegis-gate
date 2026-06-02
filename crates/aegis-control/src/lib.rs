// aegis-control: control plane (M3)
//
// Owns: observability (prometheus, otel, access logs, health),
//       audit (hash chain, SIEM sinks), admin plane (dashboard, auth),
//       compliance profiles, GitOps, cluster membership view.

pub mod access_log;
pub mod api;
pub mod audit;
pub mod copilot;
pub mod dashboard;
pub mod dashboard_services;
pub mod health;
pub mod metrics;
// 2026-05-17 F-CRITICAL-008 (control audit): `tracing_init` module
// deleted — its `init()` was a stub returning `true`, zero production
// callers, and `aegis-bin/src/main.rs` already uses the standard
// `tracing-subscriber` boot. The module was reinvention.

pub mod admin_auth;
// 2026-05-17 (user decision): `compliance` module deleted — the
// v2.3 interop contract does NOT require regulatory compliance
// modes (FIPS / PCI / HIPAA / SOC2 / GDPR). The framework files
// were 5 sets of detector-clamp + TLS-pin descriptions wired
// through `COMPLIANCE_PINNED = &[]` (always empty) and never
// enforced. Removed in full rather than carrying dead
// infrastructure.
// pub mod compliance;
// 2026-05-17 F-CRITICAL-005 (control audit): `gitops` module deleted
// — `GitOpsLoader::sync` had zero production callers and
// `set_gitops_loader` was never invoked from boot. The `/api/gitops/
// status` endpoint always returned `placeholder()` shape. Removed
// the entire subsystem rather than leaving dead infrastructure;
// re-introduce when there's a real customer requirement for the
// Round-3 §5.9 bonus.
// pub mod gitops;
pub mod identity_tracker;
pub mod interop;
// 2026-05-17 F-CRITICAL-007 (control audit): `residency` module
// deleted — 527 LoC, zero production callers, never enforced GDPR
// region pinning despite README claim. Re-introduce when there's
// a customer requirement.
pub mod slo;
