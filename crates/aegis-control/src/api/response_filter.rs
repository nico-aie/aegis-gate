//! `/api/response-filter` — runtime toggle for the three-rung
//! response-body filter shipped in PR #7 (2026-05-11).
//!
//! `Pipeline::on_body_frame` runs three filter rungs over every
//! upstream response body: stack-trace scrubbing, RFC-1918 IP
//! masking, and DLP redaction. Each rung is independently
//! toggleable via [`ResponseFilterConfig`] held in an `ArcSwap`
//! on the `Pipeline` instance — this module is the dashboard
//! surface that flips those toggles hot.
//!
//! Same indirection as
//! [`AiToggleWriter`](crate::api::ai_toggle::AiToggleWriter):
//! `aegis-control` defines the trait, the bin crate stashes the
//! live `Arc<Pipeline>` here, and the audit-mutated handler in
//! `aegis-proxy` flips it through this trait so test bundles
//! that don't wire the proxy can fake it without pulling the
//! real Pipeline.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// Wire shape for `PUT /api/response-filter`. All three rungs
/// are independently toggleable; defaults match the shipped
/// `ResponseFilterConfig::default()` (all rungs **on**) so a
/// `PUT {}` body restores safe-by-default posture.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResponseFilterPatch {
    #[serde(default = "default_true")]
    pub scrub_stack_traces: bool,
    #[serde(default = "default_true")]
    pub mask_internal_ips: bool,
    #[serde(default = "default_true")]
    pub redact_dlp: bool,
    /// AC-P1-a (2026-07-03) — fourth rung: strip leak headers
    /// (`Server`, `X-Powered-By`, `X-Debug*`, …) from proxied
    /// responses. Same default-on posture as the body rungs.
    #[serde(default = "default_true")]
    pub strip_response_headers: bool,
}

fn default_true() -> bool {
    true
}

/// Read shape for `GET /api/response-filter`. Same fields as the
/// patch plus a `wired` discriminator the dashboard uses to
/// render an empty-state banner when the writer isn't plumbed
/// (test bundles, future no-pipeline builds).
#[derive(Clone, Debug, Serialize)]
pub struct ResponseFilterView {
    pub scrub_stack_traces: bool,
    pub mask_internal_ips: bool,
    pub redact_dlp: bool,
    pub strip_response_headers: bool,
    pub wired: bool,
}

impl ResponseFilterView {
    pub fn empty() -> Self {
        Self {
            scrub_stack_traces: true,
            mask_internal_ips: true,
            redact_dlp: true,
            strip_response_headers: true,
            wired: false,
        }
    }
}

/// Bridge to the live `Pipeline::set_filter_config` /
/// `Pipeline::filter_snapshot` methods on the running data plane.
///
/// Production impl is `aegis_security::Pipeline` (the boot path
/// stashes the same `Arc<Pipeline>` instance here that the data
/// plane reads `on_body_frame` through). Tests can substitute
/// any type that satisfies the trait to verify the handler shape
/// without spinning up a real proxy.
pub trait ResponseFilterWriter: Send + Sync {
    fn set(&self, patch: ResponseFilterPatch);
    fn get(&self) -> ResponseFilterPatch;
}

impl ResponseFilterWriter for aegis_security::Pipeline {
    fn set(&self, patch: ResponseFilterPatch) {
        self.set_filter_config(aegis_security::pipeline::ResponseFilterConfig {
            scrub_stack_traces: patch.scrub_stack_traces,
            mask_internal_ips: patch.mask_internal_ips,
            redact_dlp: patch.redact_dlp,
            strip_response_headers: patch.strip_response_headers,
        });
    }
    fn get(&self) -> ResponseFilterPatch {
        let snap = self.filter_snapshot();
        ResponseFilterPatch {
            scrub_stack_traces: snap.scrub_stack_traces,
            mask_internal_ips: snap.mask_internal_ips,
            redact_dlp: snap.redact_dlp,
            strip_response_headers: snap.strip_response_headers,
        }
    }
}

/// Helper for `aegis-proxy::run` boot path: take an
/// `Arc<aegis_security::Pipeline>` and hand back the same handle
/// behind the `Arc<dyn ResponseFilterWriter>` shape the dashboard
/// services struct expects. Keeps the boot-path type-juggling
/// out of `aegis-bin`'s main.
pub fn writer_from_pipeline(
    pipeline: Arc<aegis_security::Pipeline>,
) -> Arc<dyn ResponseFilterWriter> {
    pipeline
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn patch_round_trips_json() {
        let p = ResponseFilterPatch {
            scrub_stack_traces: true,
            mask_internal_ips: false,
            redact_dlp: true,
            strip_response_headers: true,
        };
        let s = serde_json::to_string(&p).unwrap();
        let back: ResponseFilterPatch = serde_json::from_str(&s).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn patch_defaults_to_all_on() {
        let p: ResponseFilterPatch =
            serde_json::from_str("{}").expect("empty object parses");
        assert!(p.scrub_stack_traces);
        assert!(p.mask_internal_ips);
        assert!(p.redact_dlp);
        assert!(p.strip_response_headers);
    }

    #[test]
    fn empty_view_marks_unwired() {
        let v = ResponseFilterView::empty();
        assert!(!v.wired);
        // Display values match the safe-by-default shape so the
        // dashboard doesn't lie about what's running when it
        // renders the empty-state banner.
        assert!(v.scrub_stack_traces);
        assert!(v.mask_internal_ips);
        assert!(v.redact_dlp);
        assert!(v.strip_response_headers);
    }

    #[test]
    fn pipeline_writer_round_trip() {
        let rules = Arc::new(aegis_security::RuleSet::new());
        let pipe: Arc<dyn ResponseFilterWriter> =
            Arc::new(aegis_security::Pipeline::new(rules));
        // Defaults: all on.
        let initial = pipe.get();
        assert!(initial.scrub_stack_traces);
        assert!(initial.mask_internal_ips);
        assert!(initial.redact_dlp);
        // Flip one rung off via the trait, read it back.
        pipe.set(ResponseFilterPatch {
            scrub_stack_traces: true,
            mask_internal_ips: false,
            redact_dlp: true,
            strip_response_headers: false,
        });
        let after = pipe.get();
        assert!(after.scrub_stack_traces);
        assert!(!after.mask_internal_ips);
        assert!(after.redact_dlp);
        assert!(!after.strip_response_headers);
    }
}
