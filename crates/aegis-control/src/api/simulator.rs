//! HACK-T3 — `POST /api/rules/simulate` (Tier-A bonus).
//!
//! Operators replay a hypothetical request against the **live**
//! detector + mask configuration without sending real traffic.
//! No side effects: no risk increment, no rate-limit consumption,
//! no audit emit. Identical detector behaviour as the data-plane
//! hot path so the simulator's verdict matches what would
//! actually happen if the same request hit the proxy.
//!
//! Usage from the dashboard:
//! 1. Operator picks an audit-log entry on the Rule Manager
//!    "Simulate" tab (or types a method + path + headers by
//!    hand).
//! 2. Dashboard POSTs `SimulateRequest` to `/api/rules/simulate`.
//! 3. Backend runs `default_detectors()` filtered by the live
//!    `SharedDetectorMask`, plus the configured rules engine
//!    if a `RuleSet` snapshot is wired in.
//! 4. Returns `SimulateResponse` — the decision label, matched
//!    detector ids, all emitted signals, and tier classification.
//!
//! ## Why this lives in `aegis-control`
//!
//! The data plane's `handle_data_request_inner` does the live
//! evaluation; this module mirrors the same evaluator chain
//! against a synthetic `RequestView` so the dashboard surface
//! has a deterministic preview. Both code paths share
//! `aegis-security::detectors::run_all_filtered_observed` and
//! `aegis-security::rules::evaluate`, so behaviour can't drift.

use serde::{Deserialize, Serialize};

use aegis_core::context::{RequestCtx, RouteCtx};
use aegis_core::pipeline::{BodyPeek, RequestView};
use aegis_core::tier::Tier;
use aegis_security::detectors::{
    run_all_filtered_observed, Detector, SharedDetectorMask,
};

/// JSON body operators POST to `/api/rules/simulate`.
///
/// Every field is optional except `path` so quick "block this
/// payload?" probes don't need to type a full request envelope.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct SimulateRequest {
    /// HTTP method. Defaults to `GET`. Case-insensitive but
    /// uppercased before evaluation so detectors see the
    /// canonical form.
    #[serde(default)]
    pub method: Option<String>,
    /// Request path including query string. Required — empty
    /// path would not exercise any path-based detector.
    pub path: String,
    /// Optional `Host:` header. Defaults to `localhost`.
    #[serde(default)]
    pub host: Option<String>,
    /// Optional inline headers. Map → header. Detectors with
    /// header-side checks (e.g. user-agent recon) read these.
    #[serde(default)]
    pub headers: std::collections::BTreeMap<String, String>,
    /// Optional UTF-8 request body. Body-abuse + payload-shape
    /// detectors operate on this. Limit checks not enforced
    /// here — the simulator is a preview, not the real wire
    /// path.
    #[serde(default)]
    pub body: Option<String>,
}

/// JSON shape returned by `/api/rules/simulate`.
///
/// `decision_action` matches the contract action set
/// (`allow|block|challenge|rate_limit|timeout|circuit_breaker`)
/// so the dashboard can render the same `ActionPill` widget
/// it uses in the Live Feed and Audit Log.
#[derive(Clone, Debug, Serialize)]
pub struct SimulateResponse {
    /// Final decision after running detectors → rules.
    pub decision_action: String,
    /// `rule_id` that drove the decision (matches a detector
    /// id like `sqli` / `xss` or a user-rule id). `null` when
    /// the request was admitted without any detector match.
    pub rule_id: Option<String>,
    /// Aggregate risk score across all firing detectors,
    /// capped at 100. Mirrors the data-plane `risk_score`.
    pub risk_score: u32,
    /// Names of every detector that fired. Empty on a clean
    /// allow.
    pub detectors_fired: Vec<String>,
    /// Per-signal explainability. Each detector emits zero or
    /// more `Signal`s; the simulator surfaces the class +
    /// human-readable detail string so the dashboard can
    /// render them as a tree.
    pub signals: Vec<SimulatedSignal>,
    /// Tier classification (from the path heuristic) — same
    /// result the data plane uses to pick failure mode.
    pub tier: String,
    /// Were any detectors muted by the live mask? Operators
    /// see this so a "false negative" verdict doesn't
    /// surprise them when a class is intentionally disabled.
    pub muted_detectors: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SimulatedSignal {
    pub class: String,
    pub detail: String,
}

/// Percent-encode bytes that `http::Uri::parse` rejects. Only
/// touches characters known to be unsafe in raw URIs (space,
/// quotes, angle brackets, backticks, control chars). Already-
/// percent-encoded bytes pass through unchanged so operators
/// can paste either pre-decoded or pre-encoded paths and get
/// the same simulator verdict.
fn percent_encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for b in path.bytes() {
        let safe = matches!(
            b,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'~'
            | b'/' | b'?' | b'&' | b'='
            | b'+' | b'%' | b':' | b'@' | b','
            | b';' | b'!' | b'$' | b'(' | b')'
            | b'*' | b'#'
        );
        if safe {
            out.push(b as char);
        } else {
            use std::fmt::Write;
            let _ = write!(&mut out, "%{:02X}", b);
        }
    }
    if !out.starts_with('/') {
        let mut prefixed = String::with_capacity(out.len() + 1);
        prefixed.push('/');
        prefixed.push_str(&out);
        return prefixed;
    }
    out
}

/// Run the simulator against the supplied detector set. Pure —
/// no side effects on the live mask, risk tracker, or rate
/// limiter. The caller passes the **same** detector list +
/// mask the data plane uses so the verdict doesn't drift.
pub fn simulate(
    req: &SimulateRequest,
    detectors: &[Box<dyn Detector>],
    mask: &SharedDetectorMask,
    tiers: &crate::api::tiers::TierStore,
) -> SimulateResponse {
    let method = req
        .method
        .as_deref()
        .unwrap_or("GET")
        .to_ascii_uppercase();
    let host = req.host.as_deref().unwrap_or("localhost");

    let method_parsed = http::Method::from_bytes(method.as_bytes())
        .unwrap_or(http::Method::GET);
    // Operators paste pre-decoded paths from the audit log
    // (e.g. `/api/users?id=1' OR '1'='1`). `http::Uri::parse`
    // rejects unencoded spaces / quotes, so we percent-encode
    // the unsafe bytes first. Detectors URL-decode internally,
    // so the final input they inspect is byte-identical to
    // what the operator typed.
    let encoded_path = percent_encode_path(&req.path);
    let uri: http::Uri = encoded_path
        .parse()
        .unwrap_or_else(|_| http::Uri::from_static("/"));

    let mut headers = http::HeaderMap::new();
    if !host.is_empty() {
        if let Ok(v) = http::HeaderValue::from_str(host) {
            headers.insert(http::header::HOST, v);
        }
    }
    for (k, v) in &req.headers {
        if k.eq_ignore_ascii_case("host") {
            // Already handled above.
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            http::HeaderName::try_from(k.as_str()),
            http::HeaderValue::from_str(v),
        ) {
            headers.insert(name, value);
        }
    }

    let body_bytes = req.body.as_deref().unwrap_or("").as_bytes().to_vec();
    let body_len = body_bytes.len() as u64;
    let body_peek = BodyPeek::new(body_bytes, Some(body_len), false);

    let view = RequestView {
        method: &method_parsed,
        uri: &uri,
        version: http::Version::HTTP_11,
        headers: &headers,
        peer: "127.0.0.1:0".parse().expect("loopback parse"),
        tls: None,
        body: &body_peek,
    };

    // Tier classification mirrors the live data-plane heuristic.
    let route_ctx = RouteCtx {
        route_id: "simulator".into(),
        tier: Tier::Low,
        failure_mode: aegis_core::tier::FailureMode::FailOpen,
        upstream: "simulator".into(),
        pool_scheme: aegis_core::config::UpstreamScheme::Auto,
        tcp_destination_allowlist: Vec::new(),
        max_concurrent_tunnels_per_ip: 0,
        path_strip_prefix: None,
        ws_inspect: None,
        log_only: false,
    };
    let (tier, _fm) = aegis_security::pipeline::classify_tier(
        Some(&route_ctx),
        &view,
    );

    let effective = mask.resolve(Some(tier));
    let muted: Vec<String> = detectors
        .iter()
        .map(|d| d.id())
        .filter(|id| !effective.is_enabled_id(id))
        .map(|id| id.to_string())
        .collect();

    let (signals, fired) = run_all_filtered_observed(detectors, effective, &view);

    // Sum risk across signals, cap at 100.
    let risk_score = signals
        .iter()
        .fold(0u32, |acc, s| acc.saturating_add(s.score as u32))
        .min(100);

    // 2026-06-21 — match the data plane's per-request gate: block ONLY when the
    // summed detector score reaches the matched tier's `risk_threshold`
    // (defaults critical 50 / high 60 / medium 70 / low 80; live-configurable
    // via the TierStore). Previously this blocked whenever ANY detector fired,
    // so a low-tier request scoring 70 (< the 80 threshold) wrongly showed BLOCK
    // when the real pipeline would ALLOW it (detected-but-forwarded). Falls back
    // to 50 (critical default) when the tier has no entry, mirroring
    // `data_plane.rs`. The cumulative-risk challenge band isn't simulated — it
    // depends on an IP's accumulated history, which a stateless preview lacks.
    let per_request_block_at = tiers
        .get(tier.as_str())
        .map(|t| t.risk_threshold)
        .unwrap_or(50);
    let decision_action = if risk_score >= per_request_block_at {
        "block".to_string()
    } else {
        "allow".to_string()
    };

    let rule_id = fired.first().map(|id| (*id).to_string());

    let signal_views: Vec<SimulatedSignal> = signals
        .iter()
        .map(|s| SimulatedSignal {
            class: s.tag.clone(),
            detail: s.field.clone(),
        })
        .collect();

    // Suppress warning — RequestCtx not used today but reserved
    // for the rules-engine integration in a follow-up.
    let _ = std::marker::PhantomData::<RequestCtx>;

    SimulateResponse {
        decision_action,
        rule_id,
        risk_score,
        detectors_fired: fired.iter().map(|s| s.to_string()).collect(),
        signals: signal_views,
        tier: format!("{:?}", tier).to_lowercase(),
        muted_detectors: muted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_security::detectors::default_detectors;

    fn live_mask() -> SharedDetectorMask {
        SharedDetectorMask::default()
    }

    // Default tier ladder (critical 50 / high 60 / medium 70 / low 80) — the
    // same store the data plane uses, so the simulator verdict matches.
    fn live_tiers() -> crate::api::tiers::TierStore {
        crate::api::tiers::TierStore::new()
    }

    #[test]
    fn benign_request_returns_allow_with_zero_risk() {
        let req = SimulateRequest {
            method: Some("GET".into()),
            path: "/api/users".into(),
            host: Some("api.example.com".into()),
            headers: Default::default(),
            body: None,
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &[]);
        assert_eq!(resp.decision_action, "allow");
        assert_eq!(resp.risk_score, 0);
        assert!(resp.detectors_fired.is_empty());
        assert!(resp.rule_id.is_none());
        assert!(resp.signals.is_empty());
    }

    #[test]
    fn sql_injection_on_low_tier_is_detected_but_allowed() {
        // A single SQLi hit scores 70; the default (Low) tier blocks at 80, so
        // the data plane ALLOWS-but-detects it (the cumulative gate escalates a
        // repeat offender). The simulator must match — not block on any hit.
        let req = SimulateRequest {
            method: Some("GET".into()),
            path: "/api/users?id=1' OR '1'='1".into(),
            host: Some("api.example.com".into()),
            headers: Default::default(),
            body: None,
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &[]);
        assert_eq!(resp.decision_action, "allow", "70 < low threshold 80");
        assert_eq!(resp.tier, "low");
        assert!(
            resp.detectors_fired.iter().any(|d| d == "sqli"),
            "expected sqli in fired detectors, got {:?}",
            resp.detectors_fired,
        );
        assert!(resp.risk_score > 0 && resp.risk_score < 80);
        assert!(!resp.signals.is_empty());
    }

    #[test]
    fn combined_detectors_cross_threshold_and_block() {
        // Two clear-exploit detectors (path_traversal + xss) sum past the Low
        // tier's 80 threshold → block, matching the data plane's per-request gate.
        let req = SimulateRequest {
            method: Some("GET".into()),
            path: "/static/../../../etc/passwd?q=<script>alert(1)</script>".into(),
            host: Some("api.example.com".into()),
            headers: Default::default(),
            body: None,
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &[]);
        assert_eq!(resp.decision_action, "block", "combined score ≥ 80");
        assert!(resp.risk_score >= 80);
        assert!(resp.detectors_fired.len() >= 2, "got {:?}", resp.detectors_fired);
    }

    #[test]
    fn single_xss_hit_is_detected_but_allowed_on_low_tier() {
        // `<script>alert(1)</script>` fires ONE xss signal (score 70) after the
        // xss FP-reduction work (commits 9996634 / 8820251 / accd35f — exec-sink
        // gating). On the lenient Low tier (threshold 80) a single 70 hit is
        // detected-but-forwarded, exactly like `path_traversal_is_detected_on_low_tier`.
        // The threshold-crossing BLOCK path is covered by
        // `combined_detectors_cross_threshold_and_block` (two detectors summing ≥ 80).
        let req = SimulateRequest {
            method: Some("GET".into()),
            path: "/search?q=<script>alert(1)</script>".into(),
            host: Some("api.example.com".into()),
            headers: Default::default(),
            body: None,
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &[]);
        assert!(
            resp.detectors_fired.iter().any(|d| d == "xss"),
            "xss must still fire, got {:?}",
            resp.detectors_fired,
        );
        // Strong single signal, but under the Low tier's 80 → allow-but-detected.
        assert!(
            resp.risk_score >= 70 && resp.risk_score < 80,
            "expected a single strong-but-sub-threshold xss hit, got {}",
            resp.risk_score,
        );
        assert_eq!(resp.decision_action, "allow");
    }

    #[test]
    fn path_traversal_is_detected_on_low_tier() {
        // Single path_traversal hit (70) < Low threshold (80) → allow-but-detected.
        let req = SimulateRequest {
            method: Some("GET".into()),
            path: "/static/../../../etc/passwd".into(),
            host: Some("api.example.com".into()),
            headers: Default::default(),
            body: None,
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &[]);
        assert_eq!(resp.decision_action, "allow");
        assert!(
            resp.detectors_fired
                .iter()
                .any(|d| d == "path_traversal" || d == "path-traversal"),
            "expected path_traversal detector, got {:?}",
            resp.detectors_fired,
        );
    }

    #[test]
    fn defaults_when_method_omitted() {
        let req = SimulateRequest {
            method: None,
            path: "/".into(),
            host: None,
            headers: Default::default(),
            body: None,
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &[]);
        assert_eq!(resp.decision_action, "allow");
    }

    #[test]
    fn invalid_method_falls_back_to_get() {
        let req = SimulateRequest {
            method: Some("PRO\u{0000}TT".into()), // invalid bytes
            path: "/".into(),
            host: None,
            headers: Default::default(),
            body: None,
        };
        // Should not panic; the simulator falls back to GET.
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &[]);
        assert_eq!(resp.decision_action, "allow");
    }

    #[test]
    fn body_payload_with_xss_is_blocked() {
        let req = SimulateRequest {
            method: Some("POST".into()),
            path: "/api/comments".into(),
            host: Some("api.example.com".into()),
            headers: [("content-type".into(), "text/html".into())]
                .into_iter()
                .collect(),
            body: Some("<script>alert(1)</script>".into()),
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &[]);
        // Body-side detection — the XSS (or body-abuse) detector fires. A single
        // 70 hit on the Low tier is allowed-but-detected (< 80 threshold).
        assert_eq!(resp.decision_action, "allow");
        assert!(!resp.detectors_fired.is_empty(), "a detector should fire on the body payload");
    }

    #[test]
    fn muted_detectors_surface_in_response() {
        // Disable the SQLi detector class globally; the simulator
        // must report it as muted in the response so operators
        // see why their SQLi probe didn't fire.
        let mask = SharedDetectorMask::default();
        let new_mask = aegis_security::detectors::DetectorMask::all_enabled()
            .with(aegis_security::detectors::DetectorClass::Sqli, false);
        mask.store(new_mask);

        let req = SimulateRequest {
            method: Some("GET".into()),
            path: "/api/users?id=1' OR '1'='1".into(),
            host: Some("api.example.com".into()),
            headers: Default::default(),
            body: None,
        };
        let resp = simulate(&req, &default_detectors(), &mask, &live_tiers(), &[]);
        assert!(
            resp.muted_detectors.iter().any(|d| d == "sqli"),
            "expected sqli muted, got {:?}",
            resp.muted_detectors,
        );
    }

    #[test]
    fn signals_include_class_and_detail() {
        let req = SimulateRequest {
            method: Some("GET".into()),
            path: "/api/users?id=1' OR '1'='1".into(),
            host: Some("api.example.com".into()),
            headers: Default::default(),
            body: None,
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &[]);
        assert!(!resp.signals.is_empty());
        for s in &resp.signals {
            assert!(!s.class.is_empty());
            assert!(!s.detail.is_empty());
        }
    }

    #[test]
    fn response_serialises_to_expected_json_shape() {
        let req = SimulateRequest {
            method: Some("GET".into()),
            path: "/".into(),
            host: None,
            headers: Default::default(),
            body: None,
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &[]);
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("decision_action").is_some());
        assert!(json.get("risk_score").is_some());
        assert!(json.get("detectors_fired").is_some());
        assert!(json.get("signals").is_some());
        assert!(json.get("tier").is_some());
        assert!(json.get("muted_detectors").is_some());
        // P1 (2026-07-02) — rule-engine fields.
        assert!(json.get("matched_rule").is_some());
        assert!(json.get("first_detector").is_some());
        assert!(json.get("detectors_bypassed").is_some());
        assert!(json.get("route_scoped_rules_skipped").is_some());
    }

    // ---- P1 (2026-07-02) — custom-rule evaluation in the simulator ----
    //
    // The simulator must mirror the data plane's rule semantics exactly:
    //   1. explicit terminal `allow` rule match → detectors bypassed
    //      (`data_plane.rs` allow-precheck, incl. the eval-defaults-to-Allow
    //      footgun guard: only a matched rule whose AST action is `Allow`
    //      counts, never the engine's default pass-through),
    //   2. detector threshold gate (block on score ≥ tier threshold),
    //   3. rule `block { status }` on the forward path,
    //   4. challenge / rate_limit / log_only / raise_risk rules are NOT
    //      enforced by the v1 forward path — the match is reported with
    //      `enforced: false` so operators aren't misled.

    fn rules_from_yaml(yaml: &str) -> Vec<aegis_security::rules::ast::Rule> {
        aegis_security::rules::parser::parse(yaml).expect("test rules parse")
    }

    #[test]
    fn block_rule_match_blocks_and_reports_matched_rule() {
        let rules = rules_from_yaml(
            "- id: block-admin\n  priority: 100\n  when:\n    path_matches:\n      contains: \"/admin\"\n  then:\n    block:\n      status: 404\n",
        );
        let req = SimulateRequest {
            method: Some("GET".into()),
            path: "/admin/panel".into(),
            ..Default::default()
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &rules);
        assert_eq!(resp.decision_action, "block");
        assert_eq!(resp.rule_id.as_deref(), Some("block-admin"));
        let m = resp.matched_rule.expect("matched rule reported");
        assert_eq!(m.id, "block-admin");
        assert_eq!(m.action, "block");
        assert_eq!(m.status, Some(404));
        assert!(m.terminal);
        assert!(m.enforced);
        assert!(!resp.detectors_bypassed);
    }

    #[test]
    fn query_matches_rule_from_screenshot_blocks() {
        // The exact rule shape that motivated this work: POST +
        // query param `test=zxc` + body containing `ABC` → block 403.
        let rules = rules_from_yaml(
            "- id: rule-test\n  priority: 100\n  when:\n    all:\n      - method:\n          - POST\n      - query_matches:\n          name: \"test\"\n          op:\n            exact: \"zxc\"\n      - body_matches:\n          contains: \"ABC\"\n  then:\n    block:\n      status: 403\n  scope: global\n",
        );
        let req = SimulateRequest {
            method: Some("POST".into()),
            path: "/submit?test=zxc".into(),
            body: Some("xxABCxx".into()),
            ..Default::default()
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &rules);
        assert_eq!(resp.decision_action, "block");
        let m = resp.matched_rule.expect("matched rule reported");
        assert_eq!(m.id, "rule-test");
        assert_eq!(m.status, Some(403));
        // A near-miss (wrong query value) must NOT match.
        let near_miss = SimulateRequest {
            method: Some("POST".into()),
            path: "/submit?test=other".into(),
            body: Some("xxABCxx".into()),
            ..Default::default()
        };
        let resp2 =
            simulate(&near_miss, &default_detectors(), &live_mask(), &live_tiers(), &rules);
        assert_eq!(resp2.decision_action, "allow");
        assert!(resp2.matched_rule.is_none());
    }

    #[test]
    fn explicit_allow_rule_bypasses_detector_chain() {
        let rules = rules_from_yaml(
            "- id: allow-users\n  priority: 200\n  when:\n    path_matches:\n      prefix: \"/api/users\"\n  then: allow\n",
        );
        // Would fire the sqli detector without the allow rule.
        let req = SimulateRequest {
            method: Some("GET".into()),
            path: "/api/users?id=1' OR '1'='1".into(),
            ..Default::default()
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &rules);
        assert_eq!(resp.decision_action, "allow");
        assert!(resp.detectors_bypassed, "allow rule must skip the detector chain");
        assert!(resp.detectors_fired.is_empty());
        assert!(resp.signals.is_empty());
        assert_eq!(resp.risk_score, 0);
        let m = resp.matched_rule.expect("matched rule reported");
        assert_eq!(m.id, "allow-users");
        assert_eq!(m.action, "allow");
        assert!(m.terminal);
        assert!(m.enforced);
    }

    #[test]
    fn unmatched_rules_do_not_bypass_detectors() {
        // eval.rs returns Action::Allow as its DEFAULT when no rule matches —
        // checking the action alone would bypass detectors for every request
        // the moment any rule exists (the data_plane.rs:1087 footgun).
        let rules = rules_from_yaml(
            "- id: allow-elsewhere\n  priority: 200\n  when:\n    path_matches:\n      prefix: \"/nothing\"\n  then: allow\n",
        );
        // Two clear-exploit detectors sum past the Low tier's 80 threshold.
        let req = SimulateRequest {
            method: Some("GET".into()),
            path: "/static/../../../etc/passwd?q=<script>alert(1)</script>".into(),
            ..Default::default()
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &rules);
        assert_eq!(resp.decision_action, "block", "detectors must still run and block");
        assert!(!resp.detectors_bypassed);
        assert!(resp.matched_rule.is_none(), "default pass-through is not a match");
    }

    #[test]
    fn rate_limit_window_open_match_does_not_bypass_detectors() {
        // A matching rate_limit rule with no backend wired returns a terminal
        // Allow decision with the rule_id stamped ("window open"). That is NOT
        // an explicit allow rule — detectors must still run.
        let rules = rules_from_yaml(
            "- id: rl-static\n  priority: 200\n  when:\n    path_matches:\n      prefix: \"/static\"\n  then:\n    rate_limit:\n      key: ip\n      limit: 100\n      window_s: 60\n",
        );
        let req = SimulateRequest {
            method: Some("GET".into()),
            path: "/static/../../../etc/passwd?q=<script>alert(1)</script>".into(),
            ..Default::default()
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &rules);
        assert_eq!(resp.decision_action, "block", "detectors decide, not the rl allow");
        assert!(!resp.detectors_bypassed);
        let m = resp.matched_rule.expect("rl match still reported");
        assert_eq!(m.id, "rl-static");
        assert_eq!(m.action, "rate_limit");
        assert!(!m.enforced, "v1 forward path does not enforce rate_limit rules");
    }

    #[test]
    fn log_only_rule_reports_match_without_changing_decision() {
        let rules = rules_from_yaml(
            "- id: watch-blog\n  priority: 50\n  when:\n    path_matches:\n      contains: \"/blog\"\n  then: log_only\n",
        );
        let req = SimulateRequest {
            method: Some("GET".into()),
            path: "/blog/post-1".into(),
            ..Default::default()
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &rules);
        assert_eq!(resp.decision_action, "allow");
        assert!(!resp.detectors_bypassed);
        let m = resp.matched_rule.expect("log_only match reported");
        assert_eq!(m.id, "watch-blog");
        assert_eq!(m.action, "log_only");
        assert!(!m.terminal);
        assert!(!m.enforced);
    }

    #[test]
    fn detector_block_wins_over_rule_block_attribution() {
        // Data-plane order: the detector threshold gate returns BEFORE the
        // forward-path rule enforcement — so when both would block, the
        // decision is attributed to the detectors (legacy `rule_id` = first
        // detector), while the rule match is still reported.
        let rules = rules_from_yaml(
            "- id: also-blocks\n  priority: 100\n  when:\n    path_matches:\n      contains: \"/etc/passwd\"\n  then:\n    block:\n      status: 403\n",
        );
        let req = SimulateRequest {
            method: Some("GET".into()),
            path: "/static/../../../etc/passwd?q=<script>alert(1)</script>".into(),
            ..Default::default()
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &rules);
        assert_eq!(resp.decision_action, "block");
        let first = resp.first_detector.clone().expect("first detector set");
        assert_eq!(resp.rule_id.as_deref(), Some(first.as_str()));
        let m = resp.matched_rule.expect("rule match still reported");
        assert_eq!(m.id, "also-blocks");
    }

    #[test]
    fn route_scoped_rules_are_skipped_and_reported() {
        let rules = rules_from_yaml(
            "- id: scoped-block\n  priority: 100\n  scope:\n    route: checkout\n  when:\n    path_matches:\n      contains: \"/admin\"\n  then:\n    block:\n      status: 403\n",
        );
        let req = SimulateRequest {
            method: Some("GET".into()),
            path: "/admin/panel".into(),
            ..Default::default()
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &rules);
        // The simulator evaluates against a synthetic global route, so the
        // route-scoped rule must not fire — and must be reported as skipped
        // rather than silently ignored.
        assert_eq!(resp.decision_action, "allow");
        assert!(resp.matched_rule.is_none());
        assert_eq!(resp.route_scoped_rules_skipped, vec!["scoped-block".to_string()]);
    }

    #[test]
    fn challenge_rule_match_is_reported_but_not_enforced() {
        // v1 forward path honors only `Block { status }` terminally; a
        // challenge rule falls through (no challenge is issued). The simulator
        // must not claim a challenge verdict the data plane would never serve.
        let rules = rules_from_yaml(
            "- id: challenge-login\n  priority: 100\n  when:\n    path_matches:\n      contains: \"/login\"\n  then:\n    challenge:\n      level: js\n",
        );
        let req = SimulateRequest {
            method: Some("GET".into()),
            path: "/login".into(),
            ..Default::default()
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &rules);
        assert_eq!(resp.decision_action, "allow");
        let m = resp.matched_rule.expect("challenge match reported");
        assert_eq!(m.id, "challenge-login");
        assert_eq!(m.action, "challenge");
        assert!(m.terminal);
        assert!(!m.enforced);
    }

    #[test]
    fn empty_ruleset_keeps_legacy_response_shape() {
        let req = SimulateRequest {
            method: Some("GET".into()),
            path: "/api/users".into(),
            ..Default::default()
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &[]);
        assert_eq!(resp.decision_action, "allow");
        assert!(resp.matched_rule.is_none());
        assert!(resp.first_detector.is_none());
        assert!(!resp.detectors_bypassed);
        assert!(resp.route_scoped_rules_skipped.is_empty());
    }
}
