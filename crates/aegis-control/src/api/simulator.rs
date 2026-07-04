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
//!
//! ## Rule semantics (P1, 2026-07-02)
//!
//! Operator rules are evaluated with the same precedence the
//! data plane applies:
//!
//! 1. an explicit terminal `then: allow` rule match bypasses the
//!    detector chain (the `data_plane.rs` allow-precheck — only a
//!    matched rule whose AST action is `Allow` counts; the
//!    engine's default pass-through `Allow` does NOT),
//! 2. the per-request detector threshold gate blocks next,
//! 3. a matching `block { status }` rule enforces on the forward
//!    path,
//! 4. `challenge` / `rate_limit` / `log_only` / `raise_risk`
//!    matches are reported with `enforced: false` — the v1
//!    forward path honors only `Block` terminally, and the
//!    simulator must not claim a verdict the data plane would
//!    never serve.
//!
//! The simulator evaluates against a synthetic **global** route,
//! so route-scoped rules never fire; their ids are returned in
//! `route_scoped_rules_skipped` instead of being silently
//! ignored.

use serde::{Deserialize, Serialize};

use aegis_core::context::RouteCtx;
use aegis_security::rules::ast::{Rule, RuleAction};
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
    /// P2 (2026-07-02) — optional simulated peer IP so `ip_in` /
    /// `country` / `asn` rules are testable. Defaults to loopback.
    /// Typed `IpAddr` so garbage fails at deserialization (the
    /// handler's 400 invalid-body path) instead of silently
    /// simulating from 127.0.0.1.
    #[serde(default)]
    pub peer_ip: Option<std::net::IpAddr>,
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
    /// Id that drove (or would drive) the decision — a detector
    /// id like `sqli` / `xss` when the detector gate decided, or
    /// the user-rule id when an operator rule did. `null` when
    /// the request was admitted without any match. Kept for
    /// back-compat; prefer `matched_rule` / `first_detector`.
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
    /// P1 — the operator rule the engine matched (terminal or
    /// non-terminal), or `null` when no rule matched. The
    /// engine's default pass-through is NOT a match.
    pub matched_rule: Option<MatchedRuleView>,
    /// P1 — first detector that fired, always detector-attributed
    /// (unlike the legacy `rule_id`, which now carries the rule id
    /// when a rule drove the decision).
    pub first_detector: Option<String>,
    /// P1 — `true` when an explicit `then: allow` rule match
    /// skipped the detector chain (mirrors the data plane's
    /// allow-precheck / whitelist contract).
    pub detectors_bypassed: bool,
    /// P1 — ids of route-scoped rules that were NOT evaluated
    /// because the simulator runs against a synthetic global
    /// route. Surfaced so operators aren't misled by a rule that
    /// "doesn't fire" here but would on its real route.
    pub route_scoped_rules_skipped: Vec<String>,
}

/// P1 — dashboard view of the rule match the engine reported.
#[derive(Clone, Debug, Serialize)]
pub struct MatchedRuleView {
    pub id: String,
    /// AST action name: `allow | block | challenge | rate_limit |
    /// log_only | raise_risk`.
    pub action: String,
    /// `block.status` when the action is `block`.
    pub status: Option<u16>,
    /// Whether the action terminates rule evaluation.
    pub terminal: bool,
    /// Whether the live data plane enforces this action. v1
    /// honors `allow` (detector bypass) and `block` only;
    /// challenge / rate_limit / log_only / raise_risk matches are
    /// observable but change nothing on the wire.
    pub enforced: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct SimulatedSignal {
    pub class: String,
    pub detail: String,
}

/// Build the dashboard view for the rule the engine matched.
/// Returns `None` when the decision's `rule_id` does not
/// correspond to a known rule (defensive — should not happen).
fn matched_rule_view(rules: &[Rule], rule_id: &str) -> Option<MatchedRuleView> {
    let rule = rules.iter().find(|r| r.id == rule_id)?;
    let (action, status, enforced) = match &rule.action {
        RuleAction::Allow => ("allow", None, true),
        RuleAction::Block { status } => ("block", Some(*status), true),
        RuleAction::Challenge { .. } => ("challenge", None, false),
        RuleAction::RateLimit { .. } => ("rate_limit", None, false),
        RuleAction::LogOnly => ("log_only", None, false),
        RuleAction::RaiseRisk(_) => ("raise_risk", None, false),
    };
    Some(MatchedRuleView {
        id: rule.id.clone(),
        action: action.to_string(),
        status,
        terminal: rule.action.is_terminal(),
        enforced,
    })
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

/// Run the simulator against the supplied detector set + rule
/// snapshot. Pure — no side effects on the live mask, risk
/// tracker, or rate limiter. The caller passes the **same**
/// detector list + mask + ruleset snapshot the data plane uses
/// so the verdict doesn't drift.
pub fn simulate(
    req: &SimulateRequest,
    detectors: &[Box<dyn Detector>],
    mask: &SharedDetectorMask,
    tiers: &crate::api::tiers::TierStore,
    rules: &[Rule],
    // AC-P2-c (2026-07-03) — GeoIP reader so `Country`/`Asn` rule
    // conditions resolve in the preview exactly as the data plane does.
    // `None` (no feature / no MMDB) → geo conditions stay false, matching
    // a no-geoip deployment.
    geoip: Option<std::sync::Arc<dyn aegis_security::geoip::GeoIpLookup>>,
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

    let peer_ip = req
        .peer_ip
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let view = RequestView {
        method: &method_parsed,
        uri: &uri,
        version: http::Version::HTTP_11,
        headers: &headers,
        peer: std::net::SocketAddr::new(peer_ip, 0),
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

    // P1 — the simulator's synthetic route is global, so route-scoped
    // rules are skipped by the engine's scope check. Report them so a
    // "rule didn't fire" verdict isn't mistaken for a broken rule.
    let route_scoped_rules_skipped: Vec<String> = rules
        .iter()
        .filter(|r| !matches!(r.scope, aegis_security::rules::ast::Scope::Global))
        .map(|r| r.id.clone())
        .collect();

    // P1 — evaluate operator rules with the exact function + EvalContext
    // the data-plane call sites use (`data_plane.rs` allow-precheck and
    // forward-path enforcement), so simulator and live verdicts can't
    // drift. AC-P2-c — thread the same geoip reader so Country/Asn rules
    // resolve identically (both were empty-context before this).
    let eval_ctx = match &geoip {
        Some(g) => aegis_security::rules::EvalContext::empty().with_geoip(g.clone()),
        None => aegis_security::rules::EvalContext::empty(),
    };
    let rule_decision =
        aegis_security::rules::evaluate_with_ctx(rules, &view, &route_ctx, &eval_ctx);
    let matched_rule = rule_decision
        .rule_id
        .as_deref()
        .and_then(|id| matched_rule_view(rules, id));

    // Allow-precheck footgun guard (mirrors `data_plane.rs:1087`):
    // `evaluate` returns `Action::Allow` as its DEFAULT when no rule
    // matches, so the action alone must never bypass detectors — only
    // an explicit match on a rule whose AST action is `Allow` counts.
    let rule_allow = matches!(rule_decision.action, aegis_core::decision::Action::Allow)
        && matched_rule
            .as_ref()
            .is_some_and(|m| m.action == "allow");

    if rule_allow {
        // Explicit allow rule → the data plane skips the detector chain
        // entirely (same trust contract as the static whitelist).
        let rule_id = matched_rule.as_ref().map(|m| m.id.clone());
        return SimulateResponse {
            decision_action: "allow".to_string(),
            rule_id,
            risk_score: 0,
            detectors_fired: Vec::new(),
            signals: Vec::new(),
            tier: format!("{:?}", tier).to_lowercase(),
            muted_detectors: muted,
            matched_rule,
            first_detector: None,
            detectors_bypassed: true,
            route_scoped_rules_skipped,
        };
    }

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
    let detector_block = risk_score >= per_request_block_at;

    // P1 — rule `block` enforces on the forward path, i.e. AFTER the
    // detector gate (a detector block returns first on the live path,
    // so it keeps the attribution here too). Only `Block` is honored
    // terminally by the v1 forward path — challenge / rate_limit
    // matches surface via `matched_rule.enforced == false` instead of
    // claiming a verdict the data plane would never serve.
    let rule_block = matches!(
        rule_decision.action,
        aegis_core::decision::Action::Block { .. }
    );

    let first_detector = fired.first().map(|id| (*id).to_string());
    let (decision_action, rule_id) = if detector_block {
        ("block".to_string(), first_detector.clone())
    } else if rule_block {
        (
            "block".to_string(),
            matched_rule.as_ref().map(|m| m.id.clone()),
        )
    } else {
        ("allow".to_string(), first_detector.clone())
    };

    let signal_views: Vec<SimulatedSignal> = signals
        .iter()
        .map(|s| SimulatedSignal {
            class: s.tag.clone(),
            detail: s.field.clone(),
        })
        .collect();

    SimulateResponse {
        decision_action,
        rule_id,
        risk_score,
        detectors_fired: fired.iter().map(|s| s.to_string()).collect(),
        signals: signal_views,
        tier: format!("{:?}", tier).to_lowercase(),
        muted_detectors: muted,
        matched_rule,
        first_detector,
        detectors_bypassed: false,
        route_scoped_rules_skipped,
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

    // AC-P2-c (2026-07-03) — the simulator must agree with the data plane
    // on `Country`/`Asn` rules: threading a geoip reader lets a country
    // rule fire in the preview exactly as it does live. Pre-fix the
    // simulator used the empty-context `evaluate()` shim → geo always
    // false → the operator saw "won't fire" for a rule that DOES block.
    #[test]
    fn country_rule_fires_in_simulator_with_geoip() {
        use aegis_security::rules::ast::{Condition, Rule, RuleAction, Scope};
        let rules = vec![Rule {
            id: "geo-block".into(),
            priority: 100,
            scope: Scope::Global,
            condition: Condition::Country(vec!["CN".into()]),
            action: RuleAction::Block { status: 451 },
        }];
        let req = SimulateRequest {
            method: Some("GET".into()),
            path: "/".into(),
            host: Some("app.example.com".into()),
            headers: Default::default(),
            body: None,
            peer_ip: Some("203.0.113.9".parse().unwrap()),
        };
        let geo: std::sync::Arc<dyn aegis_security::geoip::GeoIpLookup> = std::sync::Arc::new(
            aegis_security::geoip::StaticGeoIp::new().with_country("203.0.113.9", "CN"),
        );
        let resp = simulate(
            &req,
            &default_detectors(),
            &live_mask(),
            &live_tiers(),
            &rules,
            Some(geo),
        );
        assert_eq!(resp.decision_action, "block", "geo rule must block in the simulator");
        assert_eq!(resp.rule_id.as_deref(), Some("geo-block"));
    }

    #[test]
    fn benign_request_returns_allow_with_zero_risk() {
        let req = SimulateRequest {
            method: Some("GET".into()),
            path: "/api/users".into(),
            host: Some("api.example.com".into()),
            headers: Default::default(),
            body: None,
            peer_ip: None,
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &[], None);
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
            peer_ip: None,
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &[], None);
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
            peer_ip: None,
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &[], None);
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
            peer_ip: None,
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &[], None);
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
            peer_ip: None,
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &[], None);
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
            peer_ip: None,
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &[], None);
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
            peer_ip: None,
        };
        // Should not panic; the simulator falls back to GET.
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &[], None);
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
            peer_ip: None,
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &[], None);
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
            peer_ip: None,
        };
        let resp = simulate(&req, &default_detectors(), &mask, &live_tiers(), &[], None);
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
            peer_ip: None,
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &[], None);
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
            peer_ip: None,
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &[], None);
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
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &rules, None);
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
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &rules, None);
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
            simulate(&near_miss, &default_detectors(), &live_mask(), &live_tiers(), &rules, None);
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
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &rules, None);
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
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &rules, None);
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
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &rules, None);
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
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &rules, None);
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
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &rules, None);
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
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &rules, None);
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
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &rules, None);
        assert_eq!(resp.decision_action, "allow");
        let m = resp.matched_rule.expect("challenge match reported");
        assert_eq!(m.id, "challenge-login");
        assert_eq!(m.action, "challenge");
        assert!(m.terminal);
        assert!(!m.enforced);
    }

    // ---- P2 (2026-07-02) — peer_ip input so ip_in rules are testable ----

    #[test]
    fn peer_ip_is_respected_by_ip_in_rules() {
        let rules = rules_from_yaml(
            "- id: block-bad-ip\n  priority: 100\n  when:\n    ip_in:\n      - \"203.0.113.10\"\n  then:\n    block:\n      status: 403\n",
        );
        let req = SimulateRequest {
            method: Some("GET".into()),
            path: "/".into(),
            peer_ip: Some("203.0.113.10".parse().unwrap()),
            ..Default::default()
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &rules, None);
        assert_eq!(resp.decision_action, "block");
        assert_eq!(
            resp.matched_rule.expect("ip rule matched").id,
            "block-bad-ip"
        );
        // Default peer (loopback) must not match the same rule.
        let default_peer = SimulateRequest {
            method: Some("GET".into()),
            path: "/".into(),
            ..Default::default()
        };
        let resp2 =
            simulate(&default_peer, &default_detectors(), &live_mask(), &live_tiers(), &rules, None);
        assert_eq!(resp2.decision_action, "allow");
        assert!(resp2.matched_rule.is_none());
    }

    #[test]
    fn invalid_peer_ip_is_rejected_at_deserialization() {
        // Typed as IpAddr so the existing 400 invalid-body path in
        // handle_simulate rejects garbage instead of silently
        // simulating from loopback (which would mislead an operator
        // testing an ip_in rule).
        let r = serde_json::from_str::<SimulateRequest>(
            r#"{"path":"/","peer_ip":"not-an-ip"}"#,
        );
        assert!(r.is_err(), "invalid peer_ip must fail to parse");
        let ok = serde_json::from_str::<SimulateRequest>(
            r#"{"path":"/","peer_ip":"198.51.100.7"}"#,
        )
        .expect("valid peer_ip parses");
        assert_eq!(ok.peer_ip, Some("198.51.100.7".parse().unwrap()));
    }

    #[test]
    fn empty_ruleset_keeps_legacy_response_shape() {
        let req = SimulateRequest {
            method: Some("GET".into()),
            path: "/api/users".into(),
            ..Default::default()
        };
        let resp = simulate(&req, &default_detectors(), &live_mask(), &live_tiers(), &[], None);
        assert_eq!(resp.decision_action, "allow");
        assert!(resp.matched_rule.is_none());
        assert!(resp.first_detector.is_none());
        assert!(!resp.detectors_bypassed);
        assert!(resp.route_scoped_rules_skipped.is_empty());
    }
}
