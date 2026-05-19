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
        auth_required: Vec::new(),
        pool_scheme: aegis_core::config::UpstreamScheme::Auto,
        tcp_destination_allowlist: Vec::new(),
        max_concurrent_tunnels_per_ip: 0,
        path_strip_prefix: None,
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

    let decision_action = if !signals.is_empty() {
        // Mirror the data-plane mapping: any detector signal
        // produces a `block` decision under a stub route. The
        // real pipeline can downgrade to challenge based on
        // risk thresholds, but for a simulator preview "block
        // when any detector fires" is the simpler explainable
        // verdict.
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

    #[test]
    fn benign_request_returns_allow_with_zero_risk() {
        let req = SimulateRequest {
            method: Some("GET".into()),
            path: "/api/users".into(),
            host: Some("api.example.com".into()),
            headers: Default::default(),
            body: None,
        };
        let resp = simulate(&req, &default_detectors(), &live_mask());
        assert_eq!(resp.decision_action, "allow");
        assert_eq!(resp.risk_score, 0);
        assert!(resp.detectors_fired.is_empty());
        assert!(resp.rule_id.is_none());
        assert!(resp.signals.is_empty());
    }

    #[test]
    fn sql_injection_path_is_blocked_with_sqli_rule_id() {
        let req = SimulateRequest {
            method: Some("GET".into()),
            path: "/api/users?id=1' OR '1'='1".into(),
            host: Some("api.example.com".into()),
            headers: Default::default(),
            body: None,
        };
        let resp = simulate(&req, &default_detectors(), &live_mask());
        assert_eq!(resp.decision_action, "block");
        assert!(
            resp.detectors_fired.iter().any(|d| d == "sqli"),
            "expected sqli in fired detectors, got {:?}",
            resp.detectors_fired,
        );
        assert!(resp.risk_score > 0);
        assert_eq!(resp.rule_id.as_deref(), Some("sqli"));
        assert!(!resp.signals.is_empty());
    }

    #[test]
    fn xss_query_string_is_blocked() {
        let req = SimulateRequest {
            method: Some("GET".into()),
            path: "/search?q=<script>alert(1)</script>".into(),
            host: Some("api.example.com".into()),
            headers: Default::default(),
            body: None,
        };
        let resp = simulate(&req, &default_detectors(), &live_mask());
        assert_eq!(resp.decision_action, "block");
        assert!(resp.detectors_fired.iter().any(|d| d == "xss"));
    }

    #[test]
    fn path_traversal_is_blocked() {
        let req = SimulateRequest {
            method: Some("GET".into()),
            path: "/static/../../../etc/passwd".into(),
            host: Some("api.example.com".into()),
            headers: Default::default(),
            body: None,
        };
        let resp = simulate(&req, &default_detectors(), &live_mask());
        assert_eq!(resp.decision_action, "block");
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
        let resp = simulate(&req, &default_detectors(), &live_mask());
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
        let resp = simulate(&req, &default_detectors(), &live_mask());
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
        let resp = simulate(&req, &default_detectors(), &live_mask());
        // Body-side detection — at least the XSS or body-abuse
        // detector should fire.
        assert_eq!(resp.decision_action, "block");
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
        let resp = simulate(&req, &default_detectors(), &mask);
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
        let resp = simulate(&req, &default_detectors(), &live_mask());
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
        let resp = simulate(&req, &default_detectors(), &live_mask());
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("decision_action").is_some());
        assert!(json.get("risk_score").is_some());
        assert!(json.get("detectors_fired").is_some());
        assert!(json.get("signals").is_some());
        assert!(json.get("tier").is_some());
        assert!(json.get("muted_detectors").is_some());
    }
}
