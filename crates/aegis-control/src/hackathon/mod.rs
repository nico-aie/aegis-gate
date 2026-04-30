//! Hackathon 2026 v2.3 interop-contract surface.
//!
//! Every required deliverable for the hackathon contract lives
//! here, isolated from the rest of `aegis-control` so the
//! adapter is replaceable / removable without touching internal
//! systems. See [`plans/hackathon-2026.md`](../../../plans/hackathon-2026.md)
//! for the gap analysis and track plan.
//!
//! Modules:
//!
//! - [`headers`]: the always-on `X-WAF-*` response headers.
//! - [`audit`]: the minimal-schema JSONL sink writing to
//!   `./waf_audit.log` (HK-T1).
//! - [`mode`]: per-policy `enforce` / `log_only` map (HK-T4).
//! - [`control`]: `/__waf_control/*` endpoint dispatch (HK-T3).
//!
//! Stability contract: field names + header names + endpoint
//! paths defined here MUST match the spec exactly. Renames are
//! breaking changes to the benchmarker.

pub mod audit;
pub mod control;
pub mod headers;
pub mod mode;

/// Required `X-Benchmark-Secret` header value. Hard-coded per
/// the contract — operators MUST NOT change it for the hackathon
/// run, though future versions might thread it through config.
pub const BENCHMARK_SECRET: &str = "waf-hackathon-2026-ctrl";

/// Required `X-Benchmark-Secret` header name (lowercase per the
/// hyper convention). Compared case-insensitively at the
/// dispatch layer.
pub const BENCHMARK_SECRET_HEADER: &str = "x-benchmark-secret";

/// Default audit-log path mandated by the contract. Working
/// directory at the time the WAF starts (per §8 of the
/// contract). Configurable via `audit.hackathon.path` in YAML.
pub const DEFAULT_AUDIT_PATH: &str = "./waf_audit.log";
