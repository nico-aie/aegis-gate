//! External interop surface — observability headers, minimal-
//! schema audit log, external control plane, and per-policy
//! mode toggle.
//!
//! These are universal WAF features that benchmark harnesses,
//! SIEMs, and operations tooling expect. They are always-on; no
//! profile gate, no specific tenant. The wire format follows
//! widely-used conventions (e.g. `X-WAF-*` response headers,
//! per-line JSONL audit) so external tooling can integrate
//! without bespoke adapters.
//!
//! Submodules:
//!
//! - [`headers`]: always-on `X-WAF-*` response headers stamped
//!   on every data-plane response.
//! - [`audit`]: minimal-schema JSONL sink writing to a
//!   configurable path (default `./waf_audit.log`).
//! - [`mode`]: per-feature/per-policy `enforce` / `log_only`
//!   override store, lock-free on the hot path.
//! - [`control`]: `/__waf_control/*` endpoints — capability
//!   discovery, runtime-state reset, mode toggle, cache flush.

pub mod audit;
pub mod control;
pub mod headers;
pub mod mode;
pub mod rule_map;

use std::sync::Arc;

/// Default secret value for the external control-plane header.
/// Operators override via `interop.control_secret` in YAML.
pub const DEFAULT_CONTROL_SECRET: &str = "waf-hackathon-2026-ctrl";

/// HTTP header carrying the control-plane secret. Hyper expects
/// lowercase names; comparisons are case-insensitive at the
/// layer above this constant.
pub const CONTROL_SECRET_HEADER: &str = "x-benchmark-secret";

/// Default path for the minimal-schema audit log.
pub const DEFAULT_AUDIT_PATH: &str = "./waf_audit.log";

/// Live interop runtime. One per process. Holds the audit sink,
/// the policy-mode store, and the control-plane context;
/// threaded through every code path that needs to stamp
/// observability headers, write the audit line, or honour a
/// per-policy mode override.
pub struct InteropRuntime {
    pub audit: Option<Arc<audit::MinimalJsonlSink>>,
    pub modes: Arc<mode::ModeStore>,
    pub control: control::ControlContext,
    /// F-HIGH-005 (2026-05-17 s-tester audit): flag set true while
    /// `reset_state` is iterating callbacks. v2.3 §2.4 mandates
    /// `reset_state` be atomic "from the benchmarker's POV" — a
    /// concurrent request must not see a half-cleared state. The
    /// data-plane consults this at the entry of `handle_data_request`
    /// (via a clone of this `Arc` installed in `ProxyContext`) and
    /// short-circuits with 503 + `Retry-After: 0` when set; per
    /// §2.4 "implementations MAY temporarily reject in-flight non-
    /// control requests" during the reset window. Cheaper than an
    /// RwLock around the entire data-plane pipeline — hot-path cost
    /// is one relaxed `AtomicBool::load`.
    pub reset_in_progress: Arc<std::sync::atomic::AtomicBool>,
}
