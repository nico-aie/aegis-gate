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
    /// RF-FP (2026-07-08 QC) — broad-PII opt-in rungs (default OFF): most
    /// apps legitimately return emails / phone numbers, so redacting every
    /// one is the largest response-filter FP source. Financial (Luhn/mod97)
    /// + distinctive credential rungs stay on under `redact_dlp`.
    pub redact_email: bool,
    pub redact_phone: bool,
    /// RF-FP (2026-07-09 QC — "full key-first") — run the free-floating
    /// VALUE-shape secret/financial DLP patterns (aws/github/stripe/slack/
    /// google/pem/ssh/hash/jwt/card/ssn/iban). Default **OFF**: only the
    /// structural KEY-value patterns redact (a value is scrubbed only when its
    /// key names a secret), which is the low-FP posture — opaque IDs that merely
    /// look like a token/IBAN/card are never touched. Trade-off: a keyless
    /// secret dumped bare (e.g. an `AKIA…` in a stack trace) is not caught until
    /// an operator flips this on.
    pub redact_value_shapes: bool,
    /// RF-FP (2026-07-08 QC) — token-issuing (auth) endpoint paths. On these
    /// the token-class DLP patterns (jwt + structural access_token/
    /// refresh_token/token) are skipped so a legit login/OAuth response keeps
    /// its token; every other secret still redacts. Segment-boundary matched.
    pub auth_paths: Vec<String>,
}

impl Default for ResponseFilterConfig {
    fn default() -> Self {
        Self {
            scrub_stack_traces: true,
            mask_internal_ips: true,
            redact_dlp: true,
            strip_response_headers: true,
            redact_email: false,
            redact_phone: false,
            redact_value_shapes: false,
            auth_paths: default_auth_paths(),
        }
    }
}

/// RF-FP (2026-07-08) — default token-issuing endpoint list, mirrored from
/// `aegis_core::config::default_auth_paths` so a `Default`-constructed
/// pipeline (tests, `NoopPipeline`) carries the same safe list the boot path
/// installs from config.
pub fn default_auth_paths() -> Vec<String> {
    [
        "/login",
        "/signin",
        "/sign-in",
        "/auth",
        "/authenticate",
        "/authorize",
        "/token",
        "/oauth/token",
        "/oauth2/token",
        "/connect/token",
        "/refresh",
        "/session",
        "/sso",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// RF-FP (2026-07-08) — does `path` name a token-issuing endpoint in
/// `auth_paths`? Query-stripped, lowercased, **segment-boundary** match: an
/// entry `e` matches when the request path equals `e` or contains `e` as a
/// whole `/`-delimited segment run (so `/oauth/token` matches
/// `/api/v1/oauth/token` and `/token`, but `/token` never matches
/// `/tokenizer` or `/authors`).
pub fn is_auth_path(path: &str, auth_paths: &[String]) -> bool {
    let p = path.split(['?', '#']).next().unwrap_or(path);
    let mut p = p.to_ascii_lowercase();
    // Normalise a trailing slash (but keep the root "/").
    if p.len() > 1 && p.ends_with('/') {
        p.pop();
    }
    auth_paths.iter().any(|entry| {
        let e = entry.trim().trim_end_matches('/').to_ascii_lowercase();
        if e.is_empty() {
            return false;
        }
        // Compare on a leading-slash "needle" so every match is bounded by a
        // '/' before the entry (an operator entry without a leading slash is
        // normalised in). `ends_with` covers a trailing segment run
        // (`/api/v1/oauth/token`); `contains("{needle}/")` covers an interior
        // segment (`/auth/login`). The leading '/' guarantees `/token` never
        // matches `/tokenizer` and `/auth` never matches `/authors`.
        let needle = if e.starts_with('/') { e } else { format!("/{e}") };
        p == needle || p.ends_with(&needle) || p.contains(&format!("{needle}/"))
    })
}

/// RF-PERF (2026-07-09) — max bytes of a response body the scrub / mask /
/// redact rungs scan. Each rung runs several regex passes; on a multi-MB
/// payload that repeated scanning blows the response-latency budget. Bodies
/// larger than this are scanned on their first `MAX_REDACT_SCAN_BYTES` only
/// and the remainder passes through untouched — error bodies, API JSON, HTML
/// and stack traces (where disclosures actually occur) sit well under 1 MiB,
/// so the tail scan's security value is low relative to its cost. This
/// reverses the earlier "redact rung left full-body" note in `data_plane.rs`.
const MAX_REDACT_SCAN_BYTES: usize = 1024 * 1024;

/// Largest prefix of `text` that is `<= cap` bytes AND ends on a UTF-8 char
/// boundary. Used to bound the redact-rung scan without splitting a multi-byte
/// codepoint (which would corrupt the passed-through tail).
fn redact_scan_boundary(text: &str, cap: usize) -> usize {
    if text.len() <= cap {
        return text.len();
    }
    let mut b = cap;
    while b > 0 && !text.is_char_boundary(b) {
        b -= 1;
    }
    b
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
        rctx: &RequestCtx,
        _route: &RouteCtx,
    ) -> OutboundAction {
        let cfg = self.filter.load();
        if !cfg.scrub_stack_traces && !cfg.mask_internal_ips && !cfg.redact_dlp {
            return OutboundAction::PassThrough;
        }
        // RF-FP (2026-07-09 S-Tester) — content-type gate. Served code/asset
        // bodies (JS/CSS/media) are not data payloads; running the secret /
        // hostname / IP rungs over them only corrupts them (a real replay
        // rewrote `credentials: "same-origin"` in an app.js bundle to
        // `[REDACTED]`). The response content-type is threaded in via
        // `rctx.fields["response_content_type"]` at the data-plane call site;
        // absent → scan (default-scan so no data type silently bypasses DLP).
        if let Some(aegis_core::context::FieldValue::Str(ct)) =
            rctx.fields.get("response_content_type")
        {
            if crate::response_filter::is_non_scannable_content_type(ct) {
                return OutboundAction::PassThrough;
            }
        }
        // Binary bodies (`image/*`, `application/octet-stream`,
        // protobuf, etc.) fail UTF-8 decode — short-circuit so we
        // don't waste regex passes. The forwarder buffers full
        // responses into a single frame today; once streaming
        // lands we'll see this branch hit per chunk.
        let Ok(text) = std::str::from_utf8(frame) else {
            return OutboundAction::PassThrough;
        };
        // RF-PERF (2026-07-09) — bound the regex work: scan at most
        // `MAX_REDACT_SCAN_BYTES` (on a char boundary) and pass any tail
        // through untouched. `head` is what the rungs rewrite; `tail` is
        // re-appended verbatim.
        let scan_end = redact_scan_boundary(text, MAX_REDACT_SCAN_BYTES);
        let (head, tail) = text.split_at(scan_end);
        let head_len = head.len();
        let mut working = std::borrow::Cow::Borrowed(head);
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
            // RF-FP (2026-07-08) — build the redaction policy from config +
            // request context. `keep_tokens` is set on token-issuing (auth)
            // endpoints so a legit login/OAuth response keeps its token;
            // email/phone are opt-in. The path is threaded in via
            // `rctx.fields["path"]` at the data-plane call site.
            let path = match rctx.fields.get("path") {
                Some(aegis_core::context::FieldValue::Str(s)) => s.as_str(),
                _ => "",
            };
            let policy = crate::dlp::RedactPolicy {
                redact_email: cfg.redact_email,
                redact_phone: cfg.redact_phone,
                keep_tokens: is_auth_path(path, &cfg.auth_paths),
                redact_value_shapes: cfg.redact_value_shapes,
            };
            let redacted = crate::dlp::redact_with(&working, &policy);
            if redacted != *working {
                working = std::borrow::Cow::Owned(redacted);
            }
        }
        // Nothing changed in the scanned head → pass the WHOLE body through.
        // The hot path on clean responses (the vast majority) pays one
        // Cow::Borrowed check per filter rung and zero allocations.
        if matches!(&working, std::borrow::Cow::Borrowed(s) if s.len() == head_len) {
            return OutboundAction::PassThrough;
        }
        // Head was rewritten → emit rewritten head + untouched tail.
        if tail.is_empty() {
            OutboundAction::Rewrite(bytes::Bytes::from(working.into_owned()))
        } else {
            let mut out = working.into_owned();
            out.push_str(tail);
            OutboundAction::Rewrite(bytes::Bytes::from(out))
        }
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

    // ---- on_body_frame: the response-filter seam (2026-07-07) ------------
    // These lock the Rewrite-vs-PassThrough contract the data plane relies
    // on: the redaction SIGNAL fires iff `on_body_frame` returns `Rewrite`,
    // and the gzip BYPASS exists precisely because a non-UTF-8 (compressed)
    // body returns `PassThrough` (which is why the fix strips Accept-Encoding
    // upstream so the origin answers in the clear).

    fn body_route() -> RouteCtx {
        RouteCtx {
            route_id: "test".into(),
            tier: Tier::Low,
            failure_mode: FailureMode::FailOpen,
            upstream: "default".into(),
            pool_scheme: aegis_core::config::UpstreamScheme::Auto,
            tcp_destination_allowlist: Vec::new(),
            max_concurrent_tunnels_per_ip: 0,
            path_strip_prefix: None,
            ws_inspect: None,
            log_only: false,
        }
    }

    fn body_ctx() -> RequestCtx {
        use std::net::{IpAddr, Ipv4Addr};
        RequestCtx {
            request_id: "t".into(),
            received_at: std::time::Instant::now(),
            client: aegis_core::context::ClientInfo {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                tls_fingerprint: None,
                h2_fingerprint: None,
                user_agent: None,
            },
            trace_id: None,
            fields: std::collections::BTreeMap::new(),
        }
    }

    /// RF-FP — same as [`body_ctx`] but with the request `path` threaded into
    /// `fields` exactly as the data-plane call site does, so `on_body_frame`
    /// can resolve the auth-path policy.
    fn body_ctx_with_path(path: &str) -> RequestCtx {
        let mut ctx = body_ctx();
        ctx.fields.insert(
            "path".into(),
            aegis_core::context::FieldValue::Str(path.into()),
        );
        ctx
    }

    // ---- RF-FP (2026-07-08 QC) — auth-path matcher + policy behaviour ------

    #[test]
    fn is_auth_path_segment_boundaries() {
        let paths = default_auth_paths();
        // Positive: exact, prefixed, and interior segments.
        assert!(is_auth_path("/login", &paths));
        assert!(is_auth_path("/oauth/token", &paths));
        assert!(is_auth_path("/api/v1/oauth/token", &paths));
        assert!(is_auth_path("/auth/login", &paths));
        assert!(is_auth_path("/LOGIN", &paths), "case-insensitive");
        assert!(is_auth_path("/oauth/token?grant_type=x", &paths), "query stripped");
        assert!(is_auth_path("/login/", &paths), "trailing slash");
        // Negative: substring collisions must NOT match.
        assert!(!is_auth_path("/tokenizer", &paths), "/token must not match /tokenizer");
        assert!(!is_auth_path("/authors", &paths), "/auth must not match /authors");
        assert!(!is_auth_path("/api/users", &paths));
    }

    /// On an auth path the token payload survives, but a non-token secret in
    /// the SAME body still redacts.
    #[tokio::test]
    async fn on_body_frame_auth_path_keeps_token_redacts_other_secret() {
        let pipe = Pipeline::new(Arc::new(crate::rules::RuleSet::new()));
        let body = br#"{"access_token":"eyJreal.secret.value","db_password":"sup3rs3cret"}"#;
        let action = pipe
            .on_body_frame(body, &body_ctx_with_path("/oauth/token"), &body_route())
            .await;
        match action {
            OutboundAction::Rewrite(new) => {
                let s = String::from_utf8(new.to_vec()).unwrap();
                assert!(s.contains("eyJreal.secret.value"), "access_token kept on auth path: {s}");
                assert!(!s.contains("sup3rs3cret"), "db_password still redacted: {s}");
            }
            other => panic!("db_password must force a Rewrite, got {other:?}"),
        }
    }

    /// The SAME token body on a NON-auth path is fully redacted (PassThrough
    /// only if nothing matched — here access_token matches → Rewrite).
    #[tokio::test]
    async fn on_body_frame_non_auth_path_redacts_token() {
        let pipe = Pipeline::new(Arc::new(crate::rules::RuleSet::new()));
        let body = br#"{"access_token":"eyJreal.secret.value"}"#;
        let action = pipe
            .on_body_frame(body, &body_ctx_with_path("/api/users"), &body_route())
            .await;
        match action {
            OutboundAction::Rewrite(new) => {
                let s = String::from_utf8(new.to_vec()).unwrap();
                assert!(!s.contains("eyJreal.secret.value"), "token redacted off auth path: {s}");
            }
            other => panic!("token off auth path must Rewrite, got {other:?}"),
        }
    }

    /// RF-FP — same as [`body_ctx`] but with the response content-type threaded
    /// into `fields` as the data-plane call site does.
    fn body_ctx_with_ct(ct: &str) -> RequestCtx {
        let mut ctx = body_ctx();
        ctx.fields.insert(
            "response_content_type".into(),
            aegis_core::context::FieldValue::Str(ct.into()),
        );
        ctx
    }

    /// RF-FP (2026-07-09 S-Tester) — a served `application/javascript` body
    /// carrying `credentials`/`loginToken` keys must pass through untouched:
    /// the content-type gate skips all body rungs for code assets so DLP can't
    /// corrupt the script.
    #[tokio::test]
    async fn on_body_frame_skips_javascript_content_type() {
        let pipe = Pipeline::new(Arc::new(crate::rules::RuleSet::new()));
        let body = br#"state.loginToken = r.data.login_token; credentials: "same-origin","#;
        let action = pipe
            .on_body_frame(body, &body_ctx_with_ct("application/javascript"), &body_route())
            .await;
        assert!(
            matches!(action, OutboundAction::PassThrough),
            "JS asset must pass through (content-type gate), got {action:?}",
        );
    }

    /// The gate is content-type-specific: the SAME secret-bearing body under a
    /// data content-type is still scanned + rewritten.
    #[tokio::test]
    async fn on_body_frame_still_scans_json_content_type() {
        let pipe = Pipeline::new(Arc::new(crate::rules::RuleSet::new()));
        let body = br#"{"db_password":"sup3rs3cret"}"#;
        let action = pipe
            .on_body_frame(body, &body_ctx_with_ct("application/json"), &body_route())
            .await;
        match action {
            OutboundAction::Rewrite(new) => {
                let s = String::from_utf8(new.to_vec()).unwrap();
                assert!(!s.contains("sup3rs3cret"), "json secret still redacted: {s}");
            }
            other => panic!("json body must still Rewrite, got {other:?}"),
        }
    }

    /// RF-PERF (2026-07-09) — `redact_scan_boundary` never splits a multi-byte
    /// codepoint (that would corrupt the passed-through tail).
    #[test]
    fn redact_scan_boundary_respects_char_boundaries() {
        let s = format!("{}{}", "a".repeat(9), "é"); // 9 + 2 = 11 bytes
        assert_eq!(redact_scan_boundary(&s, 10), 9, "byte 10 is mid-'é' → back off to 9");
        assert_eq!(redact_scan_boundary(&s, 100), s.len(), "cap over len → whole string");
        assert_eq!(redact_scan_boundary("abc", 3), 3);
    }

    /// A secret within the first `MAX_REDACT_SCAN_BYTES` of a large body is
    /// still redacted, and the (unscanned) tail is preserved verbatim.
    #[tokio::test]
    async fn on_body_frame_scan_cap_redacts_head_preserves_tail() {
        let pipe = Pipeline::new(Arc::new(crate::rules::RuleSet::new()));
        let mut body = br#"{"db_password":"sup3rs3cret","pad":""#.to_vec();
        body.extend(std::iter::repeat(b'a').take(MAX_REDACT_SCAN_BYTES + 4096));
        body.extend_from_slice(br#""}"#);
        let action = pipe.on_body_frame(&body, &body_ctx(), &body_route()).await;
        match action {
            OutboundAction::Rewrite(new) => {
                let s = String::from_utf8(new.to_vec()).unwrap();
                assert!(!s.contains("sup3rs3cret"), "head secret must be redacted");
                assert!(s.len() > MAX_REDACT_SCAN_BYTES, "tail must be preserved");
            }
            other => panic!("head secret must Rewrite, got {other:?}"),
        }
    }

    /// A secret located PAST the scan cap is deliberately not scanned — the
    /// perf guard bounds the regex work, and the tail passes through. Locks the
    /// documented trade-off.
    #[tokio::test]
    async fn on_body_frame_scan_cap_skips_secret_past_cap() {
        let pipe = Pipeline::new(Arc::new(crate::rules::RuleSet::new()));
        let mut body: Vec<u8> = std::iter::repeat(b'a')
            .take(MAX_REDACT_SCAN_BYTES + 4096)
            .collect();
        body.extend_from_slice(br#"{"db_password":"sup3rs3cret"}"#);
        let action = pipe.on_body_frame(&body, &body_ctx(), &body_route()).await;
        assert!(
            matches!(action, OutboundAction::PassThrough),
            "a secret past MAX_REDACT_SCAN_BYTES is not scanned (perf cap), got {action:?}",
        );
    }

    /// email/phone are opt-in: a body carrying only an email passes through
    /// untouched under the default (off) policy.
    #[tokio::test]
    async fn on_body_frame_email_passes_through_when_opt_in_off() {
        let pipe = Pipeline::new(Arc::new(crate::rules::RuleSet::new()));
        let body = br#"{"user":"alice","email":"alice@example.com"}"#;
        let action = pipe
            .on_body_frame(body, &body_ctx_with_path("/api/profile"), &body_route())
            .await;
        assert!(
            matches!(action, OutboundAction::PassThrough),
            "email must pass through when redact_email is off (default), got {action:?}",
        );
    }

    /// Clean body → PassThrough. Critical for the redaction signal: a
    /// response with nothing to scrub must NOT report `Rewrite`, or every
    /// clean response would emit a false "redacted" audit row.
    #[tokio::test]
    async fn on_body_frame_clean_body_passes_through() {
        let pipe = Pipeline::new(Arc::new(crate::rules::RuleSet::new()));
        let body = br#"{"status":"ok","items":[1,2,3]}"#;
        let action = pipe.on_body_frame(body, &body_ctx(), &body_route()).await;
        assert!(
            matches!(action, OutboundAction::PassThrough),
            "clean body must pass through (no false redaction signal), got {action:?}",
        );
    }

    /// Body with an internal IP → Rewrite with the value masked. This is the
    /// path that both scrubs AND triggers the `redact` audit row.
    #[tokio::test]
    async fn on_body_frame_secret_body_rewrites_and_scrubs() {
        let pipe = Pipeline::new(Arc::new(crate::rules::RuleSet::new()));
        let body = b"upstream error contacting 10.0.0.5:5432";
        let action = pipe.on_body_frame(body, &body_ctx(), &body_route()).await;
        match action {
            OutboundAction::Rewrite(new) => {
                let s = String::from_utf8(new.to_vec()).unwrap();
                assert!(!s.contains("10.0.0.5"), "internal IP must be masked: {s}");
                assert!(s.contains("[INTERNAL]"), "mask marker expected: {s}");
            }
            other => panic!("a body with an internal IP must Rewrite, got {other:?}"),
        }
    }

    /// Non-UTF-8 (compressed) body → PassThrough. This is the gzip-bypass
    /// gap: `on_body_frame` can't decode a gzip stream, so it forwards it
    /// unfiltered — which is exactly why the upstream `Accept-Encoding` is
    /// pinned to `identity` so this branch is never hit for real responses.
    #[tokio::test]
    async fn on_body_frame_binary_body_passes_through_unfiltered() {
        let pipe = Pipeline::new(Arc::new(crate::rules::RuleSet::new()));
        // gzip magic + invalid UTF-8 continuation byte (0x8b).
        let gz = [0x1f_u8, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef];
        let action = pipe.on_body_frame(&gz, &body_ctx(), &body_route()).await;
        assert!(
            matches!(action, OutboundAction::PassThrough),
            "a non-UTF-8 (compressed) body can't be filtered → PassThrough, got {action:?}",
        );
    }

    /// All rungs off → PassThrough even when the body carries a secret; the
    /// per-frame cost goes to zero and nothing is rewritten (no signal).
    #[tokio::test]
    async fn on_body_frame_all_rungs_off_passes_through() {
        let cfg = ResponseFilterConfig {
            scrub_stack_traces: false,
            mask_internal_ips: false,
            redact_dlp: false,
            strip_response_headers: false,
            ..ResponseFilterConfig::default()
        };
        let pipe = Pipeline::with_filter(Arc::new(crate::rules::RuleSet::new()), cfg);
        let body = b"contacting 10.0.0.5 with secret_key=sk_live_abcdefghijklmnop";
        let action = pipe.on_body_frame(body, &body_ctx(), &body_route()).await;
        assert!(
            matches!(action, OutboundAction::PassThrough),
            "all rungs off must short-circuit to PassThrough, got {action:?}",
        );
    }

    /// RF-FP (2026-07-09 QC — "full key-first") — the wired data-plane default
    /// (`ResponseFilterConfig::default()`, value-shapes OFF) redacts a secret
    /// whose KEY names it (structural) but leaves a KEYLESS value-shape secret
    /// (a bare `AKIA…`) untouched. This is the FP/recall trade-off the operator
    /// chose: opaque IDs that merely look like tokens survive.
    #[tokio::test]
    async fn on_body_frame_default_is_key_first() {
        let pipe = Pipeline::new(Arc::new(crate::rules::RuleSet::new()));
        // Structural (keyed) secret + a keyless AWS key value.
        let body = br#"{"db_password":"sup3rs3cret","note":"AKIAIOSFODNN7EXAMPLE"}"#;
        match pipe.on_body_frame(body, &body_ctx(), &body_route()).await {
            OutboundAction::Rewrite(new) => {
                let s = String::from_utf8(new.to_vec()).unwrap();
                assert!(!s.contains("sup3rs3cret"), "keyed secret must redact (structural): {s}");
                assert!(
                    s.contains("AKIAIOSFODNN7EXAMPLE"),
                    "keyless AKIA must survive under key-first default: {s}",
                );
            }
            other => panic!("keyed db_password must force a Rewrite, got {other:?}"),
        }
    }

    /// With value-shapes explicitly enabled, the same keyless `AKIA…` is caught.
    #[tokio::test]
    async fn on_body_frame_value_shapes_on_catches_keyless_secret() {
        let cfg = ResponseFilterConfig { redact_value_shapes: true, ..ResponseFilterConfig::default() };
        let pipe = Pipeline::with_filter(Arc::new(crate::rules::RuleSet::new()), cfg);
        let body = br#"{"note":"AKIAIOSFODNN7EXAMPLE"}"#;
        match pipe.on_body_frame(body, &body_ctx(), &body_route()).await {
            OutboundAction::Rewrite(new) => {
                let s = String::from_utf8(new.to_vec()).unwrap();
                assert!(!s.contains("AKIAIOSFODNN7EXAMPLE"), "value-shapes on must redact keyless AKIA: {s}");
            }
            other => panic!("value-shapes on must Rewrite the AKIA body, got {other:?}"),
        }
    }

    #[test]
    fn default_config_is_key_first() {
        assert!(!ResponseFilterConfig::default().redact_value_shapes, "value-shapes off by default");
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
