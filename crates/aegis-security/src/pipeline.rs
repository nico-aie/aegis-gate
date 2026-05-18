use aegis_core::context::{RequestCtx, RouteCtx};
use aegis_core::decision::Decision;
use aegis_core::pipeline::{OutboundAction, RequestView, SecurityPipeline};
use aegis_core::tier::{FailureMode, Tier};

use crate::rules::RuleSet;

use std::sync::Arc;

/// Tier classification based on route config and path heuristics.
pub fn classify_tier(
    route: Option<&RouteCtx>,
    req: &RequestView<'_>,
) -> (Tier, FailureMode) {
    // Route override wins.
    if let Some(rctx) = route {
        return (rctx.tier, rctx.failure_mode);
    }

    // Path heuristic.
    let path = req.uri.path();
    let (tier, fm) = path_heuristic(path);
    (tier, fm)
}

/// 2026-05-18 (QC Sprint 1.2 — F-CRITICAL-005): path-only tier
/// classifier. The DDoS gate in the data plane runs BEFORE the
/// full RequestView is assembled (and BEFORE route resolution),
/// so it needs a path-only shortcut. Returns the same value as
/// [`classify_tier`] would when route is `None`, just with a
/// narrower input contract.
pub fn classify_tier_from_path(path: &str) -> (Tier, FailureMode) {
    path_heuristic(path)
}

fn path_heuristic(path: &str) -> (Tier, FailureMode) {
    let lower = path.to_ascii_lowercase();

    // Critical paths.
    if lower.starts_with("/login")
        || lower.starts_with("/signin")
        || lower.starts_with("/auth")
        || lower.starts_with("/payments")
        || lower.starts_with("/checkout")
        || lower.starts_with("/transfer")
        || lower.starts_with("/2fa")
        || lower.starts_with("/mfa")
        || lower.starts_with("/password")
    {
        return (Tier::Critical, FailureMode::FailClose);
    }

    // High paths.
    if lower.starts_with("/api")
        || lower.starts_with("/admin")
        || lower.starts_with("/graphql")
        || lower.starts_with("/webhook")
    {
        return (Tier::High, FailureMode::FailClose);
    }

    // Medium paths.
    if lower.starts_with("/user")
        || lower.starts_with("/account")
        || lower.starts_with("/profile")
        || lower.starts_with("/settings")
    {
        return (Tier::Medium, FailureMode::FailOpen);
    }

    (Tier::Low, FailureMode::FailOpen)
}

/// Runtime knobs for the response-filter pipeline. Wrapped in an
/// `ArcSwap` so the dashboard can flip the toggles without a
/// restart. All three default to **on**: the contract requires
/// that responses with internal stack traces / DLP payloads / RFC
/// 1918 IPs not leak to clients, so the safe-by-default posture
/// is "scrub everything." Operators can flip them off per-deploy
/// if a downstream tier already handles the scrubbing.
#[derive(Clone, Debug)]
pub struct ResponseFilterConfig {
    pub scrub_stack_traces: bool,
    pub mask_internal_ips: bool,
    pub redact_dlp: bool,
}

impl Default for ResponseFilterConfig {
    fn default() -> Self {
        Self {
            scrub_stack_traces: true,
            mask_internal_ips: true,
            redact_dlp: true,
        }
    }
}

/// Production `SecurityPipeline` impl.
///
/// **2026-05-11 PR #7 wire-up.** Pre-fix `Pipeline::on_body_frame`
/// always returned `PassThrough` and the binary entry point wired
/// `NoopPipeline` instead. Inbound detection still ran (data plane
/// calls `run_all_filtered_timed` directly), but every response
/// body went out unfiltered — stack traces, internal IPs, and
/// credit-card / SSN payloads in upstream errors all leaked.
///
/// Now `on_body_frame` runs:
/// 1. `response_filter::scrub_stack_traces` — node.js / JVM /
///    Python / Rust / PHP / .NET / Ruby / Go traces → `[REDACTED]`.
/// 2. `response_filter::mask_internal_ips` — RFC 1918 + loopback +
///    link-local → `[INTERNAL]`.
/// 3. `dlp::redact` — credit cards (Luhn-validated), SSN, IBAN,
///    emails, AWS keys, GitHub tokens, Stripe keys, Slack tokens.
///
/// Each step is independently toggleable via [`ResponseFilterConfig`].
/// When all three are off the impl short-circuits to `PassThrough`
/// so the per-frame cost goes to zero.
pub struct Pipeline {
    rules: Arc<RuleSet>,
    filter: arc_swap::ArcSwap<ResponseFilterConfig>,
}

impl Pipeline {
    pub fn new(rules: Arc<RuleSet>) -> Self {
        Self::with_filter(rules, ResponseFilterConfig::default())
    }

    pub fn with_filter(rules: Arc<RuleSet>, filter: ResponseFilterConfig) -> Self {
        Self {
            rules,
            filter: arc_swap::ArcSwap::from_pointee(filter),
        }
    }

    /// Hot-swap the response-filter config. Used by the dashboard's
    /// audit-mutated PUT path so operators can flip a filter rung
    /// off without a restart.
    pub fn set_filter_config(&self, cfg: ResponseFilterConfig) {
        self.filter.store(Arc::new(cfg));
    }

    pub fn filter_snapshot(&self) -> ResponseFilterConfig {
        (**self.filter.load()).clone()
    }

    /// 2026-05-17 F-CRITICAL-001 (control audit): expose the live
    /// `Arc<RuleSet>` so the dashboard CRUD bridge in
    /// `aegis-control` can hot-swap the rule set after every
    /// audit-mutated CRUD operation. Caller clones the Arc; both
    /// the Pipeline and the dashboard end up pointing at the same
    /// inner `ArcSwap`, so a `replace_rules()` call from either
    /// surface is observed by the other.
    pub fn rules_arc(&self) -> Arc<RuleSet> {
        Arc::clone(&self.rules)
    }
}

#[async_trait::async_trait]
impl SecurityPipeline for Pipeline {
    /// LT-RUN-6 SEC-07 closure (2026-05-14) — this method is the
    /// `SecurityPipeline` trait surface but is **not** the
    /// production hot path.  The data plane in
    /// `aegis_proxy::data_plane` reaches detectors directly via
    /// [`crate::detectors::run_all_filtered_timed`] (see
    /// `crates/aegis-proxy/src/data_plane.rs` around line 507),
    /// using a `Vec<Box<dyn Detector>>` seeded in
    /// `crates/aegis-proxy/src/lib.rs:143`.
    ///
    /// Several static audits (LT-RUN-5 / LT-RUN-6) flagged that
    /// "detectors are never called from `inbound()`" — that's
    /// expected.  This method delegates to the rules engine only
    /// because the engine itself currently has zero production
    /// callers; once the engine is wired (planned for the dashboard
    /// simulator surface), this method becomes the canonical
    /// composite entry point (rules + detectors).
    ///
    /// **Do not** call this from a new aegis-proxy code path
    /// without coordinating with the data plane — you'd double-run
    /// detectors on every request.
    async fn inbound(
        &self,
        view: RequestView<'_>,
        _rctx: &mut RequestCtx,
        route: &RouteCtx,
    ) -> Decision {
        let snapshot = self.rules.snapshot();
        crate::rules::evaluate(&snapshot, &view, route)
    }

    /// LT-RUN-6 SEC-20 (2026-05-14) — pass-through stub.  The data
    /// plane today reads `on_body_frame` only (see
    /// `data_plane.rs:1469`) and never invokes this trait method.
    /// ICAP wiring is a deferred substantive feature — tracked in
    /// `plans/future/unwired-stubs-catalog.md` (search "ICAP").
    /// When the wiring lands, this method should call
    /// `self.icap_client.scan(IcapMode::Respmod, ...)` and return
    /// `OutboundAction::Block` on `ScanResult::Infected`.
    async fn on_response_start(
        &self,
        _head: &http::response::Parts,
        _rctx: &RequestCtx,
        _route: &RouteCtx,
    ) -> OutboundAction {
        OutboundAction::PassThrough
    }

    async fn on_body_frame(
        &self,
        frame: &[u8],
        _rctx: &RequestCtx,
        _route: &RouteCtx,
    ) -> OutboundAction {
        let cfg = self.filter.load();
        if !cfg.scrub_stack_traces && !cfg.mask_internal_ips && !cfg.redact_dlp {
            return OutboundAction::PassThrough;
        }
        // Binary bodies (`image/*`, `application/octet-stream`,
        // protobuf, etc.) fail UTF-8 decode — short-circuit so we
        // don't waste regex passes. The forwarder buffers full
        // responses into a single frame today; once streaming
        // lands we'll see this branch hit per chunk.
        let Ok(text) = std::str::from_utf8(frame) else {
            return OutboundAction::PassThrough;
        };
        let original_len = text.len();
        let mut working = std::borrow::Cow::Borrowed(text);
        if cfg.scrub_stack_traces {
            let scrubbed = crate::response_filter::scrub_stack_traces(&working);
            if scrubbed != *working {
                working = std::borrow::Cow::Owned(scrubbed);
            }
        }
        if cfg.mask_internal_ips {
            let masked = crate::response_filter::mask_internal_ips(&working);
            if masked != *working {
                working = std::borrow::Cow::Owned(masked);
            }
        }
        if cfg.redact_dlp {
            let redacted = crate::dlp::redact(&working);
            if redacted != *working {
                working = std::borrow::Cow::Owned(redacted);
            }
        }
        // Nothing changed → pass through. The hot path on clean
        // responses (the vast majority) pays one Cow::Borrowed
        // check per filter rung and zero allocations.
        if matches!(&working, std::borrow::Cow::Borrowed(s) if s.len() == original_len) {
            return OutboundAction::PassThrough;
        }
        OutboundAction::Rewrite(bytes::Bytes::from(working.into_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::pipeline::BodyPeek;

    fn view_for_path(path: &str) -> (http::Method, http::Uri, http::HeaderMap, BodyPeek) {
        (
            http::Method::GET,
            path.parse().unwrap(),
            http::HeaderMap::new(),
            BodyPeek::empty(),
        )
    }

    fn make_view<'a>(
        m: &'a http::Method,
        u: &'a http::Uri,
        h: &'a http::HeaderMap,
        b: &'a BodyPeek,
    ) -> RequestView<'a> {
        RequestView {
            method: m,
            uri: u,
            version: http::Version::HTTP_11,
            headers: h,
            peer: "127.0.0.1:1234".parse().unwrap(),
            tls: None,
            body: b,
        }
    }

    #[test]
    fn login_is_critical() {
        let (m, u, h, b) = view_for_path("/login");
        let req = make_view(&m, &u, &h, &b);
        let (tier, fm) = classify_tier(None, &req);
        assert_eq!(tier, Tier::Critical);
        assert_eq!(fm, FailureMode::FailClose);
    }

    #[test]
    fn payments_is_critical() {
        let (m, u, h, b) = view_for_path("/payments/submit");
        let req = make_view(&m, &u, &h, &b);
        let (tier, _) = classify_tier(None, &req);
        assert_eq!(tier, Tier::Critical);
    }

    #[test]
    fn auth_is_critical() {
        let (m, u, h, b) = view_for_path("/auth/callback");
        let req = make_view(&m, &u, &h, &b);
        let (tier, _) = classify_tier(None, &req);
        assert_eq!(tier, Tier::Critical);
    }

    #[test]
    fn api_is_high() {
        let (m, u, h, b) = view_for_path("/api/users");
        let req = make_view(&m, &u, &h, &b);
        let (tier, fm) = classify_tier(None, &req);
        assert_eq!(tier, Tier::High);
        assert_eq!(fm, FailureMode::FailClose);
    }

    #[test]
    fn admin_is_high() {
        let (m, u, h, b) = view_for_path("/admin/dashboard");
        let req = make_view(&m, &u, &h, &b);
        let (tier, _) = classify_tier(None, &req);
        assert_eq!(tier, Tier::High);
    }

    #[test]
    fn graphql_is_high() {
        let (m, u, h, b) = view_for_path("/graphql");
        let req = make_view(&m, &u, &h, &b);
        let (tier, _) = classify_tier(None, &req);
        assert_eq!(tier, Tier::High);
    }

    #[test]
    fn user_profile_is_medium() {
        let (m, u, h, b) = view_for_path("/user/profile");
        let req = make_view(&m, &u, &h, &b);
        let (tier, fm) = classify_tier(None, &req);
        assert_eq!(tier, Tier::Medium);
        assert_eq!(fm, FailureMode::FailOpen);
    }

    #[test]
    fn settings_is_medium() {
        let (m, u, h, b) = view_for_path("/settings");
        let req = make_view(&m, &u, &h, &b);
        let (tier, _) = classify_tier(None, &req);
        assert_eq!(tier, Tier::Medium);
    }

    #[test]
    fn static_is_catchall() {
        let (m, u, h, b) = view_for_path("/static/logo.png");
        let req = make_view(&m, &u, &h, &b);
        let (tier, fm) = classify_tier(None, &req);
        assert_eq!(tier, Tier::Low);
        assert_eq!(fm, FailureMode::FailOpen);
    }

    #[test]
    fn root_is_catchall() {
        let (m, u, h, b) = view_for_path("/");
        let req = make_view(&m, &u, &h, &b);
        let (tier, _) = classify_tier(None, &req);
        assert_eq!(tier, Tier::Low);
    }

    #[test]
    fn route_override_wins() {
        let rctx = RouteCtx {
            route_id: "force-critical".into(),
            tier: Tier::Critical,
            failure_mode: FailureMode::FailClose,
            upstream: "pool".into(),
            tenant_id: None,
            auth_required: Vec::new(),
            pool_scheme: aegis_core::config::UpstreamScheme::Auto,
            tcp_destination_allowlist: Vec::new(),
            max_concurrent_tunnels_per_ip: 0,
            path_strip_prefix: None,
        };
        let (m, u, h, b) = view_for_path("/static/logo.png");
        let req = make_view(&m, &u, &h, &b);
        let (tier, fm) = classify_tier(Some(&rctx), &req);
        assert_eq!(tier, Tier::Critical);
        assert_eq!(fm, FailureMode::FailClose);
    }
}
