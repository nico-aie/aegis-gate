use aegis_core::context::{RequestCtx, RouteCtx};
use aegis_core::decision::Decision;
use aegis_core::pipeline::{OutboundAction, RequestView, SecurityPipeline};
use aegis_core::tier::{FailureMode, Tier};

use crate::rules::RuleSet;

use std::sync::Arc;

/// Tier classification. A per-route `tier_override` wins; otherwise
/// traffic defaults to the most permissive tier (`Low`).
///
/// 2026-05-21 — the hardcoded path→tier heuristic was REMOVED. It
/// classified `/login`/`/payments`→Critical, `/api`/`/admin`→High,
/// etc., which blocked traffic at stricter per-request thresholds
/// based on URL patterns the operator never configured — surprising
/// behaviour, and NOT part of the interop contract (the contract
/// specifies the observability headers + control endpoints, never an
/// internal path-tiering scheme). Operators now express path
/// sensitivity explicitly via per-route `tier_override` and the
/// canary honeypot detector, rather than a hidden built-in map.
pub fn classify_tier(
    route: Option<&RouteCtx>,
    _req: &RequestView<'_>,
) -> (Tier, FailureMode) {
    match route {
        Some(rctx) => (rctx.tier, rctx.failure_mode),
        None => default_tier(),
    }
}

/// Path-only tier shortcut used by the DDoS gate (which runs before
/// route resolution). Always returns the default tier now that the
/// path heuristic is gone; kept for call-site compatibility.
pub fn classify_tier_from_path(_path: &str) -> (Tier, FailureMode) {
    default_tier()
}

/// Default tier for traffic with no route override: the most
/// permissive tier. Operators raise sensitivity per-route
/// (`tier_override`) or via the canary detector.
fn default_tier() -> (Tier, FailureMode) {
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
    /// AC-P1-a (2026-07-03) — strip version-banner / debug / internal
    /// headers (`response_filter::should_strip_header` set) from
    /// proxied responses. Fourth rung, header-side peer of the three
    /// body rungs above; same safe-by-default posture. Strip-only:
    /// security-header *injection* (CSP/HSTS) stays opt-in and
    /// unwired here — forcing those onto arbitrary upstreams breaks
    /// apps.
    pub strip_response_headers: bool,
}

impl Default for ResponseFilterConfig {
    fn default() -> Self {
        Self {
            scrub_stack_traces: true,
            mask_internal_ips: true,
            redact_dlp: true,
            strip_response_headers: true,
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
    /// LT-RUN-6 SEC-07 closure (2026-05-14, reconfirmed 2026-05-18
    /// QC Sprint 3.2) — this method is the `SecurityPipeline`
    /// trait surface but is **NOT** the production hot path. It
    /// runs the rules engine ONLY, not the OWASP detector chain,
    /// not the canary detector, not the per-IP rate-limit, not
    /// the DDoS gate, not the risk tracker. That's deliberate.
    ///
    /// **Why the bypass is correct:**
    ///
    /// The data plane in `aegis_proxy::data_plane::handle_data_request_inner`
    /// runs the full security pipeline DIRECTLY in the request-
    /// handler hot path: blacklist gate → DDoS gate → per-IP rate-
    /// limit → strike-block → detector chain (via
    /// [`crate::detectors::run_all_filtered_timed`]) → rules engine
    /// (commit `c760d8f` Phase D F-CRITICAL-001) → risk tracker
    /// (commit `2521d17` Phase E F-CRITICAL-001) → route resolution
    /// → upstream forward.
    ///
    /// Each step is wired explicitly in the data plane because
    /// it needs the per-step:
    /// - tracing span context (per-stage histograms),
    /// - audit-bus emission point,
    /// - load-shed admission control,
    /// - tier classification for §5.8 fail-mode lookup,
    /// - composite RiskKey construction.
    ///
    /// Wrapping that 200-line hot path behind one `inbound()`
    /// trait method would either:
    /// 1. duplicate all the per-step machinery as trait params,
    ///    losing the hot-path inlining the data plane gets today,
    ///    OR
    /// 2. force the data plane to call `inbound()` AND also do
    ///    the per-step machinery separately — running the
    ///    detector chain twice.
    ///
    /// The audit's "bypass" framing predates the data plane fully
    /// landing the pipeline (Phase D + E + F closed it on the
    /// data-plane side). The trait kept the rules-engine-only
    /// shape because:
    /// - it's the dashboard's `POST /api/rules/simulate` entry
    ///   (rules-only is the right shape for rule preview), AND
    /// - it's a backward-compat surface for the `NoopPipeline`
    ///   that other tests use.
    ///
    /// **Do not** call this from a new aegis-proxy code path
    /// without coordinating with the data plane — you'd double-
    /// run the rules engine and (if you wire detectors too) end
    /// up double-running the OWASP chain.
    ///
    /// **Tracking:** F-CRITICAL-008 (security audit, 2026-05-17)
    /// flagged this as "bypass". After the Phase E/F/D
    /// land-the-pipeline-in-the-data-plane commits, that finding
    /// is reclassified — the data plane has all of it, so
    /// consolidating it under `inbound()` would be a refactor
    /// (architecture-only) not a security fix.
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
            // RF-3 (2026-07-06) — internal hostnames + infra DSNs, sibling of
            // the IP mask under the same toggle.
            let masked_hosts = crate::response_filter::mask_internal_hostnames(&working);
            if masked_hosts != *working {
                working = std::borrow::Cow::Owned(masked_hosts);
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

    /// AC-P1-a — strip the leak-header set in place. O(header count)
    /// key comparisons; the common clean-response path allocates
    /// nothing (the removal Vec stays empty). Collect-then-remove
    /// because `HeaderMap` has no retain and removal invalidates
    /// iteration.
    fn on_response_headers(&self, headers: &mut http::HeaderMap) {
        if !self.filter.load().strip_response_headers {
            return;
        }
        let to_remove: Vec<http::HeaderName> = headers
            .keys()
            .filter(|k| crate::response_filter::should_strip_header(k.as_str()))
            .cloned()
            .collect();
        for name in to_remove {
            headers.remove(&name);
        }
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

    /// 2026-05-21 — the hardcoded path→tier heuristic was removed.
    /// Paths that used to be auto-classified Critical/High/Medium
    /// (`/login`, `/api`, `/admin`, `/user`, …) now default to `Low`
    /// like everything else; sensitivity is operator-configured via
    /// route `tier_override` + the canary detector. This guards
    /// against the heuristic being reintroduced.
    #[test]
    fn all_paths_default_to_low_without_route_override() {
        for p in [
            "/login", "/payments/submit", "/auth/callback", "/api/users",
            "/admin/dashboard", "/graphql", "/user/profile", "/settings",
            "/static/logo.png", "/",
        ] {
            let (m, u, h, b) = view_for_path(p);
            let req = make_view(&m, &u, &h, &b);
            let (tier, fm) = classify_tier(None, &req);
            assert_eq!(tier, Tier::Low, "path {p} must default to Low (no path heuristic)");
            assert_eq!(fm, FailureMode::FailOpen, "default tier fails open");
        }
    }

    #[test]
    fn classify_tier_from_path_also_defaults_to_low() {
        for p in ["/login", "/api/x", "/"] {
            assert_eq!(classify_tier_from_path(p).0, Tier::Low);
        }
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

    /// AC-P1-a (2026-07-03) — response-header strip wire-up. The
    /// leak-header predicate (`response_filter::should_strip_header`)
    /// shipped 2026-05-18 with only test callers; these three pin the
    /// Pipeline-level hook the data plane now calls on every proxied
    /// response (buffered AND streaming — headers are available on
    /// both paths even when the body can't be re-read).
    #[test]
    fn on_response_headers_strips_leak_headers_by_default() {
        let pipe = Pipeline::new(Arc::new(crate::rules::RuleSet::new()));
        let mut headers = http::HeaderMap::new();
        headers.insert("server", "nginx/1.27.0".parse().unwrap());
        headers.insert("x-powered-by", "PHP/8.1".parse().unwrap());
        headers.insert("x-aspnet-version", "4.0.30319".parse().unwrap());
        headers.insert("x-debug-user", "root".parse().unwrap());
        headers.insert("x-internal-latency", "12ms".parse().unwrap());
        headers.insert("content-type", "text/html".parse().unwrap());
        headers.insert("content-length", "42".parse().unwrap());
        pipe.on_response_headers(&mut headers);
        assert!(headers.get("server").is_none(), "Server banner must be stripped");
        assert!(headers.get("x-powered-by").is_none());
        assert!(headers.get("x-aspnet-version").is_none());
        assert!(headers.get("x-debug-user").is_none(), "X-Debug* prefix family must be stripped");
        assert!(headers.get("x-internal-latency").is_none(), "X-Internal* prefix family must be stripped");
        // Pass-through headers are untouched.
        assert_eq!(headers.get("content-type").unwrap(), "text/html");
        assert_eq!(headers.get("content-length").unwrap(), "42");
    }

    #[test]
    fn on_response_headers_disabled_leaves_headers_intact() {
        let cfg = ResponseFilterConfig {
            strip_response_headers: false,
            ..ResponseFilterConfig::default()
        };
        let pipe = Pipeline::with_filter(Arc::new(crate::rules::RuleSet::new()), cfg);
        let mut headers = http::HeaderMap::new();
        headers.insert("server", "nginx/1.27.0".parse().unwrap());
        headers.insert("x-powered-by", "PHP/8.1".parse().unwrap());
        pipe.on_response_headers(&mut headers);
        assert_eq!(headers.get("server").unwrap(), "nginx/1.27.0");
        assert_eq!(headers.get("x-powered-by").unwrap(), "PHP/8.1");
    }

    /// Default-ON is the safe posture (leak scrub is contract-shaped,
    /// same rationale as the three body rungs). A config that omits
    /// the field behaves exactly like today's body-scrub defaults.
    #[test]
    fn strip_response_headers_defaults_on() {
        assert!(ResponseFilterConfig::default().strip_response_headers);
    }

    #[test]
    fn route_override_wins() {
        let rctx = RouteCtx {
            route_id: "force-critical".into(),
            tier: Tier::Critical,
            failure_mode: FailureMode::FailClose,
            upstream: "pool".into(),
            pool_scheme: aegis_core::config::UpstreamScheme::Auto,
            tcp_destination_allowlist: Vec::new(),
            max_concurrent_tunnels_per_ip: 0,
            path_strip_prefix: None,
            ws_inspect: None,
            log_only: false,
        };
        let (m, u, h, b) = view_for_path("/static/logo.png");
        let req = make_view(&m, &u, &h, &b);
        let (tier, fm) = classify_tier(Some(&rctx), &req);
        assert_eq!(tier, Tier::Critical);
        assert_eq!(fm, FailureMode::FailClose);
    }
}
