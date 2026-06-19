use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aegis_core::context::RouteCtx;
use aegis_core::decision::{Action, ChallengeLevel, Decision};
use aegis_core::pipeline::RequestView;

use crate::geoip::GeoIpLookup;

use super::ast::{Condition, MatchOp, Rule, RuleAction, Scope};

/// LT-RUN-6 EVAL-02 (2026-05-14) — backend trait the
/// `RuleAction::RateLimit` arm consults. Pre-fix the arm
/// ignored `key` and `limit` and returned `RateLimited` on
/// every matching request — so `limit: 1000` and `limit: 1`
/// were functionally identical. With a backend wired the
/// engine enforces a sliding-window count per `(rule_id, key,
/// client_ip)` bucket.
///
/// Returns `true` when the request fits within the window
/// (allow), `false` when the window is exhausted (rate-limit).
pub trait RuleRateLimit: Send + Sync {
    /// Bump the per-bucket counter and decide.  `bucket` is the
    /// resolved discriminator (caller composes from `rule.id`,
    /// `RuleAction::RateLimit.key`, and any request-derived
    /// value such as client IP).
    fn check(&self, bucket: &str, limit: u64, window: Duration) -> bool;
}

/// Default in-process [`RuleRateLimit`] impl using a per-bucket
/// `Vec<Instant>` sliding window.  Suitable for single-node
/// deployments and tests; multi-node deployments would wire a
/// Redis-backed implementation behind the same trait.
#[derive(Default)]
pub struct InProcessRuleRateLimit {
    buckets: Mutex<HashMap<String, Vec<Instant>>>,
}

impl InProcessRuleRateLimit {
    pub fn new() -> Self {
        Self::default()
    }

    fn check_at(&self, bucket: &str, limit: u64, window: Duration, now: Instant) -> bool {
        let mut state = self.buckets.lock().expect("rule rate-limit state poisoned");
        let entry = state.entry(bucket.to_string()).or_default();
        let cutoff = now.checked_sub(window).unwrap_or(now);
        entry.retain(|&t| t >= cutoff);
        if (entry.len() as u64) >= limit {
            // Window full — deny (no insert so the count doesn't
            // grow unbounded under sustained pressure).
            return false;
        }
        entry.push(now);
        // Cap the per-bucket vec so memory stays bounded under
        // sustained allow traffic.  `limit * 2` is plenty —
        // anything above limit is already a deny.
        let cap = ((limit * 2).min(10_000)) as usize;
        if entry.len() > cap {
            let drop_n = entry.len() - cap;
            entry.drain(0..drop_n);
        }
        true
    }
}

impl RuleRateLimit for InProcessRuleRateLimit {
    fn check(&self, bucket: &str, limit: u64, window: Duration) -> bool {
        self.check_at(bucket, limit, window, Instant::now())
    }
}

/// Side-channel context the evaluator uses for conditions that
/// can't be answered from `RequestView` alone (currently:
/// `Country`, `Asn`), plus the rate-limit backend.
///
/// All fields are optional — when a feature isn't wired the
/// matching condition simply evaluates to `false`, mirroring
/// the existing `JwtClaim` / `BotClass` / `ThreatFeed`
/// behaviour. This keeps every rule file backwards-compatible
/// regardless of which features the build was compiled with.
#[derive(Clone, Default)]
pub struct EvalContext {
    /// GeoIP lookup. When `None`, `Country` / `Asn` always
    /// match `false`.
    pub geoip: Option<Arc<dyn GeoIpLookup>>,
    /// Rate-limit backend for `RuleAction::RateLimit`.  When
    /// `None` the engine *allows* matching requests (preserves
    /// pre-EVAL-02 backwards-compat for callers that haven't
    /// wired a backend) rather than the pre-fix behaviour of
    /// returning `RateLimited` immediately.
    pub rate_limit: Option<Arc<dyn RuleRateLimit>>,
}

impl EvalContext {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn with_geoip(mut self, geoip: Arc<dyn GeoIpLookup>) -> Self {
        self.geoip = Some(geoip);
        self
    }

    pub fn with_rate_limit(mut self, rl: Arc<dyn RuleRateLimit>) -> Self {
        self.rate_limit = Some(rl);
        self
    }
}

/// Evaluate rules against a request.  Rules are evaluated in priority order
/// (highest first).  Terminal actions short-circuit; non-terminal actions
/// (RaiseRisk, LogOnly) accumulate and evaluation continues.
///
/// Backwards-compatible shim — calls
/// [`evaluate_with_ctx`] with an empty [`EvalContext`].
pub fn evaluate(rules: &[Rule], req: &RequestView<'_>, route: &RouteCtx) -> Decision {
    evaluate_with_ctx(rules, req, route, &EvalContext::empty())
}

/// Like [`evaluate`] but threads an [`EvalContext`] through to
/// `Country` / `Asn` conditions.
pub fn evaluate_with_ctx(
    rules: &[Rule],
    req: &RequestView<'_>,
    route: &RouteCtx,
    ctx: &EvalContext,
) -> Decision {
    let mut sorted: Vec<&Rule> = rules.iter().collect();
    sorted.sort_by(|a, b| b.priority.cmp(&a.priority));

    let mut accumulated_risk: u32 = 0;
    let mut matched_rule_id: Option<String> = None;

    for rule in &sorted {
        // Scope check.
        match &rule.scope {
            Scope::Global => {}
            Scope::Route(route_id) => {
                if route_id != &route.route_id {
                    continue;
                }
            }
        }

        if !matches_condition(&rule.condition, req, ctx) {
            continue;
        }

        match &rule.action {
            RuleAction::Allow => {
                return Decision {
                    action: Action::Allow,
                    reason: format!("rule {} allowed", rule.id),
                    rule_id: Some(rule.id.clone()),
                    risk_score: accumulated_risk,
                };
            }
            RuleAction::Block { status } => {
                return Decision {
                    action: Action::Block { status: *status },
                    reason: format!("rule {} blocked", rule.id),
                    rule_id: Some(rule.id.clone()),
                    risk_score: accumulated_risk,
                };
            }
            RuleAction::Challenge { level } => {
                let cl = match level.as_str() {
                    "pow" => ChallengeLevel::Pow,
                    "captcha" => ChallengeLevel::Captcha,
                    _ => ChallengeLevel::Js,
                };
                return Decision {
                    action: Action::Challenge { level: cl },
                    reason: format!("rule {} challenged", rule.id),
                    rule_id: Some(rule.id.clone()),
                    risk_score: accumulated_risk,
                };
            }
            RuleAction::RateLimit {
                key,
                limit,
                window_s,
            } => {
                // LT-RUN-6 EVAL-02 (2026-05-14) — consult the
                // rate-limit backend instead of unconditionally
                // returning `RateLimited`. Bucket key is
                // `{rule_id}:{key}:{client_ip}` so per-rule,
                // per-key, per-IP windows stay distinct.
                //
                // Terminal in both branches:
                //   within window → Allow with rule_id stamped
                //                    (matched rule decided)
                //   over window   → RateLimited + retry-after
                //
                // No backend wired: stay permissive (Allow) so
                // the engine doesn't enforce — matches
                // "rate-limit feature not yet wired" rather than
                // the pre-fix "always block matching traffic".
                let bucket = format!(
                    "{}:{}:{}",
                    rule.id,
                    key,
                    req.peer.ip(),
                );
                let window = Duration::from_secs(u64::from(*window_s));
                let allowed = match ctx.rate_limit.as_ref() {
                    Some(rl) => rl.check(&bucket, *limit, window),
                    None => true,
                };
                if allowed {
                    return Decision {
                        action: Action::Allow,
                        reason: format!("rule {} rate-limit window open", rule.id),
                        rule_id: Some(rule.id.clone()),
                        risk_score: accumulated_risk,
                    };
                }
                return Decision {
                    action: Action::RateLimited {
                        retry_after_s: *window_s,
                    },
                    reason: format!("rule {} rate limited", rule.id),
                    rule_id: Some(rule.id.clone()),
                    risk_score: accumulated_risk,
                };
            }
            RuleAction::RaiseRisk(delta) => {
                accumulated_risk = accumulated_risk.saturating_add(*delta);
                matched_rule_id = Some(rule.id.clone());
                // Non-terminal — continue evaluation.
            }
            RuleAction::LogOnly => {
                matched_rule_id = Some(rule.id.clone());
                // Non-terminal — continue evaluation.
            }
        }
    }

    // No terminal action hit — default allow.
    Decision {
        action: Action::Allow,
        reason: "no rule matched".into(),
        rule_id: matched_rule_id,
        risk_score: accumulated_risk,
    }
}

fn matches_condition(cond: &Condition, req: &RequestView<'_>, ctx: &EvalContext) -> bool {
    match cond {
        Condition::True => true,
        Condition::All(children) => children.iter().all(|c| matches_condition(c, req, ctx)),
        Condition::Any(children) => children.iter().any(|c| matches_condition(c, req, ctx)),
        Condition::Not(inner) => !matches_condition(inner, req, ctx),
        Condition::Method(methods) => {
            let m = req.method.as_str();
            methods.iter().any(|allowed| allowed.eq_ignore_ascii_case(m))
        }
        Condition::PathMatches(op) => {
            let path = req.uri.path();
            matches_op(op, path)
        }
        Condition::HostMatches(op) => {
            let host = req
                .headers
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .or_else(|| req.uri.host())
                .unwrap_or("");
            matches_op(op, host)
        }
        Condition::HeaderMatches { name, op } => {
            req.headers
                .get(name.as_str())
                .and_then(|v| v.to_str().ok())
                .map(|v| matches_op(op, v))
                .unwrap_or(false)
        }
        Condition::QueryMatches { name, op } => {
            let query = req.uri.query().unwrap_or("");
            // Simple query param extraction.
            query
                .split('&')
                .find_map(|pair| {
                    let mut parts = pair.splitn(2, '=');
                    let key = parts.next()?;
                    let val = parts.next().unwrap_or("");
                    if key == name { Some(val) } else { None }
                })
                .map(|v| matches_op(op, v))
                .unwrap_or(false)
        }
        Condition::BodyMatches(op) => {
            let body_str = std::str::from_utf8(req.body.peek(8192)).unwrap_or("");
            matches_op(op, body_str)
        }
        Condition::CookieMatches { name, op } => {
            extract_cookie(req.headers, name)
                .map(|v| matches_op(op, &v))
                .unwrap_or(false)
        }
        Condition::IpIn(cidrs) => {
            // LT-RUN-6 EVAL-01 (2026-05-14) — pre-fix used a
            // string-prefix check (`ip_str.starts_with(net_str)`)
            // which only matched the network address itself; every
            // host in the subnet failed.  Use `ipnet::IpNet` for
            // real network-membership.  The `ipnet` crate is
            // already a dependency (used in `threat_intel/mod.rs`
            // and `ip_rep/`).  Bare-IP entries (no `/` mask) still
            // work because `IpAddr::from_str` parses them and we
            // compare directly.
            let ip = req.peer.ip();
            cidrs.iter().any(|cidr| {
                if cidr.contains('/') {
                    cidr.parse::<ipnet::IpNet>()
                        .map(|net| net.contains(&ip))
                        .unwrap_or(false)
                } else {
                    cidr.parse::<std::net::IpAddr>()
                        .map(|peer| peer == ip)
                        .unwrap_or(false)
                }
            })
        }
        Condition::Country(codes) => match &ctx.geoip {
            Some(geoip) => match geoip.country(req.peer.ip()) {
                Some(c) => codes.iter().any(|wanted| wanted.eq_ignore_ascii_case(&c)),
                None => false,
            },
            None => false,
        },
        Condition::Asn(asns) => match &ctx.geoip {
            Some(geoip) => match geoip.asn(req.peer.ip()) {
                Some(found) => asns.contains(&found),
                None => false,
            },
            None => false,
        },
        // These require external context not available in simple eval:
        Condition::JwtClaim { .. }
        | Condition::BotClass(_)
        | Condition::ThreatFeed { .. }
        | Condition::SchemaViolation => false,
    }
}

fn matches_op(op: &MatchOp, value: &str) -> bool {
    match op {
        MatchOp::Exact(s) => value == s,
        MatchOp::Prefix(s) => value.starts_with(s.as_str()),
        MatchOp::Suffix(s) => value.ends_with(s.as_str()),
        MatchOp::Contains(s) => value.contains(s.as_str()),
        MatchOp::Regex(pattern) => regex::Regex::new(pattern)
            .map(|re| re.is_match(value))
            .unwrap_or(false),
    }
}

fn extract_cookie(headers: &http::HeaderMap, name: &str) -> Option<String> {
    for value in headers.get_all(http::header::COOKIE) {
        if let Ok(s) = value.to_str() {
            for pair in s.split(';') {
                let pair = pair.trim();
                if let Some((k, v)) = pair.split_once('=') {
                    if k.trim() == name {
                        return Some(v.trim().to_string());
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::context::RouteCtx;
    use aegis_core::pipeline::BodyPeek;
    use aegis_core::tier::{FailureMode, Tier};

    fn route() -> RouteCtx {
        RouteCtx {
            route_id: "default".into(),
            tier: Tier::Medium,
            failure_mode: FailureMode::FailOpen,
            upstream: "pool".into(),
            pool_scheme: aegis_core::config::UpstreamScheme::Auto,
            tcp_destination_allowlist: Vec::new(),
            max_concurrent_tunnels_per_ip: 0,
            path_strip_prefix: None,
            ws_inspect: None,
            log_only: false,
        }
    }

    fn view(method: &str, path: &str) -> (http::Method, http::Uri, http::HeaderMap, BodyPeek) {
        let m: http::Method = method.parse().unwrap();
        let u: http::Uri = path.parse().unwrap();
        let h = http::HeaderMap::new();
        let b = BodyPeek::empty();
        (m, u, h, b)
    }

    fn make_view<'a>(
        method: &'a http::Method,
        uri: &'a http::Uri,
        headers: &'a http::HeaderMap,
        body: &'a BodyPeek,
    ) -> RequestView<'a> {
        RequestView {
            method,
            uri,
            version: http::Version::HTTP_11,
            headers,
            peer: "127.0.0.1:1234".parse().unwrap(),
            tls: None,
            body,
        }
    }

    fn block_rule(id: &str, path: &str) -> Rule {
        Rule {
            id: id.into(),
            priority: 100,
            scope: Scope::Global,
            condition: Condition::PathMatches(MatchOp::Exact(path.into())),
            action: RuleAction::Block { status: 403 },
        }
    }

    #[test]
    fn no_rules_allows() {
        let (m, u, h, b) = view("GET", "/");
        let req = make_view(&m, &u, &h, &b);
        let d = evaluate(&[], &req, &route());
        assert!(matches!(d.action, Action::Allow));
    }

    #[test]
    fn block_matching_path() {
        let rules = vec![block_rule("block-evil", "/evil")];
        let (m, u, h, b) = view("GET", "/evil");
        let req = make_view(&m, &u, &h, &b);
        let d = evaluate(&rules, &req, &route());
        assert!(matches!(d.action, Action::Block { status: 403 }));
        assert_eq!(d.rule_id.as_deref(), Some("block-evil"));
    }

    #[test]
    fn non_matching_path_allows() {
        let rules = vec![block_rule("block-evil", "/evil")];
        let (m, u, h, b) = view("GET", "/good");
        let req = make_view(&m, &u, &h, &b);
        let d = evaluate(&rules, &req, &route());
        assert!(matches!(d.action, Action::Allow));
    }

    #[test]
    fn higher_priority_wins() {
        let rules = vec![
            Rule {
                id: "allow-all".into(),
                priority: 50,
                scope: Scope::Global,
                condition: Condition::True,
                action: RuleAction::Allow,
            },
            Rule {
                id: "block-evil".into(),
                priority: 200,
                scope: Scope::Global,
                condition: Condition::PathMatches(MatchOp::Exact("/evil".into())),
                action: RuleAction::Block { status: 403 },
            },
        ];
        let (m, u, h, b) = view("GET", "/evil");
        let req = make_view(&m, &u, &h, &b);
        let d = evaluate(&rules, &req, &route());
        assert!(matches!(d.action, Action::Block { status: 403 }));
    }

    #[test]
    fn risk_accumulates_across_rules() {
        let rules = vec![
            Rule {
                id: "risk-10".into(),
                priority: 200,
                scope: Scope::Global,
                condition: Condition::True,
                action: RuleAction::RaiseRisk(10),
            },
            Rule {
                id: "risk-20".into(),
                priority: 100,
                scope: Scope::Global,
                condition: Condition::True,
                action: RuleAction::RaiseRisk(20),
            },
        ];
        let (m, u, h, b) = view("GET", "/");
        let req = make_view(&m, &u, &h, &b);
        let d = evaluate(&rules, &req, &route());
        assert_eq!(d.risk_score, 30);
    }

    #[test]
    fn scope_route_filter() {
        let rules = vec![Rule {
            id: "admin-only".into(),
            priority: 100,
            scope: Scope::Route("admin-panel".into()),
            condition: Condition::True,
            action: RuleAction::Block { status: 403 },
        }];
        // Route doesn't match scope.
        let (m, u, h, b) = view("GET", "/");
        let req = make_view(&m, &u, &h, &b);
        let d = evaluate(&rules, &req, &route());
        assert!(matches!(d.action, Action::Allow));
    }

    #[test]
    fn method_condition() {
        let rules = vec![Rule {
            id: "block-delete".into(),
            priority: 100,
            scope: Scope::Global,
            condition: Condition::Method(vec!["DELETE".into()]),
            action: RuleAction::Block { status: 405 },
        }];
        let (m, u, h, b) = view("DELETE", "/resource");
        let req = make_view(&m, &u, &h, &b);
        let d = evaluate(&rules, &req, &route());
        assert!(matches!(d.action, Action::Block { status: 405 }));
    }

    #[test]
    fn method_condition_no_match() {
        let rules = vec![Rule {
            id: "block-delete".into(),
            priority: 100,
            scope: Scope::Global,
            condition: Condition::Method(vec!["DELETE".into()]),
            action: RuleAction::Block { status: 405 },
        }];
        let (m, u, h, b) = view("GET", "/resource");
        let req = make_view(&m, &u, &h, &b);
        let d = evaluate(&rules, &req, &route());
        assert!(matches!(d.action, Action::Allow));
    }

    #[test]
    fn prefix_match() {
        let rules = vec![Rule {
            id: "api-prefix".into(),
            priority: 100,
            scope: Scope::Global,
            condition: Condition::PathMatches(MatchOp::Prefix("/api".into())),
            action: RuleAction::Block { status: 403 },
        }];
        let (m, u, h, b) = view("GET", "/api/users");
        let req = make_view(&m, &u, &h, &b);
        let d = evaluate(&rules, &req, &route());
        assert!(matches!(d.action, Action::Block { status: 403 }));
    }

    #[test]
    fn regex_match() {
        let rules = vec![Rule {
            id: "regex-digits".into(),
            priority: 100,
            scope: Scope::Global,
            condition: Condition::PathMatches(MatchOp::Regex(r"^/user/\d+$".into())),
            action: RuleAction::LogOnly,
        }];
        let (m, u, h, b) = view("GET", "/user/123");
        let req = make_view(&m, &u, &h, &b);
        let d = evaluate(&rules, &req, &route());
        assert!(matches!(d.action, Action::Allow)); // LogOnly is non-terminal
        assert_eq!(d.rule_id.as_deref(), Some("regex-digits"));
    }

    #[test]
    fn all_condition() {
        let rules = vec![Rule {
            id: "all-cond".into(),
            priority: 100,
            scope: Scope::Global,
            condition: Condition::All(vec![
                Condition::Method(vec!["POST".into()]),
                Condition::PathMatches(MatchOp::Prefix("/api".into())),
            ]),
            action: RuleAction::Block { status: 403 },
        }];
        // Both match.
        let (m, u, h, b) = view("POST", "/api/data");
        let req = make_view(&m, &u, &h, &b);
        let d = evaluate(&rules, &req, &route());
        assert!(matches!(d.action, Action::Block { .. }));

        // Only path matches.
        let (m2, u2, h2, b2) = view("GET", "/api/data");
        let req2 = make_view(&m2, &u2, &h2, &b2);
        let d2 = evaluate(&rules, &req2, &route());
        assert!(matches!(d2.action, Action::Allow));
    }

    #[test]
    fn not_condition() {
        let rules = vec![Rule {
            id: "not-get".into(),
            priority: 100,
            scope: Scope::Global,
            condition: Condition::Not(Box::new(Condition::Method(vec!["GET".into()]))),
            action: RuleAction::Block { status: 403 },
        }];
        // POST is not GET → blocked.
        let (m, u, h, b) = view("POST", "/");
        let req = make_view(&m, &u, &h, &b);
        let d = evaluate(&rules, &req, &route());
        assert!(matches!(d.action, Action::Block { .. }));

        // GET → allowed.
        let (m2, u2, h2, b2) = view("GET", "/");
        let req2 = make_view(&m2, &u2, &h2, &b2);
        let d2 = evaluate(&rules, &req2, &route());
        assert!(matches!(d2.action, Action::Allow));
    }

    #[test]
    fn challenge_action() {
        let rules = vec![Rule {
            id: "challenge-r".into(),
            priority: 100,
            scope: Scope::Global,
            condition: Condition::True,
            action: RuleAction::Challenge { level: "pow".into() },
        }];
        let (m, u, h, b) = view("GET", "/");
        let req = make_view(&m, &u, &h, &b);
        let d = evaluate(&rules, &req, &route());
        assert!(matches!(
            d.action,
            Action::Challenge { level: ChallengeLevel::Pow }
        ));
    }

    #[test]
    fn header_match() {
        let rules = vec![Rule {
            id: "ua-match".into(),
            priority: 100,
            scope: Scope::Global,
            condition: Condition::HeaderMatches {
                name: "user-agent".into(),
                op: MatchOp::Contains("sqlmap".into()),
            },
            action: RuleAction::Block { status: 403 },
        }];
        let m: http::Method = "GET".parse().unwrap();
        let u: http::Uri = "/".parse().unwrap();
        let mut h = http::HeaderMap::new();
        h.insert("user-agent", "sqlmap/1.0".parse().unwrap());
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        let d = evaluate(&rules, &req, &route());
        assert!(matches!(d.action, Action::Block { status: 403 }));
    }

    #[test]
    fn query_match() {
        let rules = vec![Rule {
            id: "query-match".into(),
            priority: 100,
            scope: Scope::Global,
            condition: Condition::QueryMatches {
                name: "debug".into(),
                op: MatchOp::Exact("true".into()),
            },
            action: RuleAction::Block { status: 403 },
        }];
        let m: http::Method = "GET".parse().unwrap();
        let u: http::Uri = "/?debug=true&foo=bar".parse().unwrap();
        let h = http::HeaderMap::new();
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        let d = evaluate(&rules, &req, &route());
        assert!(matches!(d.action, Action::Block { status: 403 }));
    }

    #[test]
    fn rate_limit_action() {
        let rules = vec![Rule {
            id: "rl".into(),
            priority: 100,
            scope: Scope::Global,
            condition: Condition::True,
            action: RuleAction::RateLimit {
                key: "ip".into(),
                limit: 100,
                window_s: 60,
            },
        }];
        let (m, u, h, b) = view("GET", "/");
        let req = make_view(&m, &u, &h, &b);
        // LT-RUN-6 EVAL-02 — without a backend wired the engine
        // stays permissive (Allow with rule_id stamped).  Pre-fix
        // this test expected Action::RateLimited; that was the
        // bug behaviour.  With a backend wired, see
        // `eval02_in_process_backend_allows_first_n_then_429s`.
        let d = evaluate(&rules, &req, &route());
        assert!(matches!(d.action, Action::Allow), "no backend → Allow");
        assert_eq!(d.rule_id.as_deref(), Some("rl"));

        // With a backend + tight limit, the same rule does
        // rate-limit on req #2.
        let rl = Arc::new(InProcessRuleRateLimit::new());
        let ctx = EvalContext::default().with_rate_limit(rl);
        assert!(matches!(
            evaluate_with_ctx(&rules, &req, &route(), &ctx).action,
            Action::Allow
        ));
        // Drive the limit (100 reqs) to exhaustion in one tight
        // loop — 101st must rate-limit.
        for _ in 0..99 {
            evaluate_with_ctx(&rules, &req, &route(), &ctx);
        }
        assert!(matches!(
            evaluate_with_ctx(&rules, &req, &route(), &ctx).action,
            Action::RateLimited { retry_after_s: 60 }
        ));
    }

    // ---- Country / ASN conditions (B3-T3) ----

    fn country_block_rule(codes: &[&str]) -> Rule {
        Rule {
            id: "geo-block".into(),
            priority: 100,
            scope: Scope::Global,
            condition: Condition::Country(codes.iter().map(|s| s.to_string()).collect()),
            action: RuleAction::Block { status: 451 },
        }
    }

    fn asn_block_rule(asns: &[u32]) -> Rule {
        Rule {
            id: "asn-block".into(),
            priority: 100,
            scope: Scope::Global,
            condition: Condition::Asn(asns.to_vec()),
            action: RuleAction::Block { status: 403 },
        }
    }

    fn ctx_with_country(ip: &str, code: &str) -> EvalContext {
        let geo = crate::geoip::StaticGeoIp::new().with_country(ip, code);
        EvalContext::empty().with_geoip(Arc::new(geo))
    }

    fn ctx_with_asn(ip: &str, asn: u32) -> EvalContext {
        let geo = crate::geoip::StaticGeoIp::new().with_asn(ip, asn);
        EvalContext::empty().with_geoip(Arc::new(geo))
    }

    #[test]
    fn country_condition_blocks_matching_country() {
        let rules = vec![country_block_rule(&["CN", "RU"])];
        let (m, u, h, b) = view("GET", "/");
        let req = make_view(&m, &u, &h, &b);
        let ctx = ctx_with_country("127.0.0.1", "CN");
        let d = evaluate_with_ctx(&rules, &req, &route(), &ctx);
        assert!(matches!(d.action, Action::Block { status: 451 }));
    }

    #[test]
    fn country_condition_allows_non_matching_country() {
        let rules = vec![country_block_rule(&["CN", "RU"])];
        let (m, u, h, b) = view("GET", "/");
        let req = make_view(&m, &u, &h, &b);
        let ctx = ctx_with_country("127.0.0.1", "US");
        let d = evaluate_with_ctx(&rules, &req, &route(), &ctx);
        assert!(matches!(d.action, Action::Allow));
    }

    #[test]
    fn country_condition_is_case_insensitive() {
        let rules = vec![country_block_rule(&["cn"])];
        let (m, u, h, b) = view("GET", "/");
        let req = make_view(&m, &u, &h, &b);
        let ctx = ctx_with_country("127.0.0.1", "CN");
        let d = evaluate_with_ctx(&rules, &req, &route(), &ctx);
        assert!(matches!(d.action, Action::Block { .. }));
    }

    #[test]
    fn country_condition_returns_false_when_no_geoip_wired() {
        let rules = vec![country_block_rule(&["CN"])];
        let (m, u, h, b) = view("GET", "/");
        let req = make_view(&m, &u, &h, &b);
        // Default `evaluate` has no context — geo always false.
        let d = evaluate(&rules, &req, &route());
        assert!(matches!(d.action, Action::Allow));
    }

    #[test]
    fn country_condition_returns_false_when_ip_unknown() {
        let rules = vec![country_block_rule(&["CN"])];
        let (m, u, h, b) = view("GET", "/");
        let req = make_view(&m, &u, &h, &b);
        // GeoIP wired but knows a different IP.
        let ctx = ctx_with_country("8.8.8.8", "CN");
        let d = evaluate_with_ctx(&rules, &req, &route(), &ctx);
        assert!(matches!(d.action, Action::Allow));
    }

    #[test]
    fn asn_condition_blocks_matching_asn() {
        let rules = vec![asn_block_rule(&[15169, 16509])];
        let (m, u, h, b) = view("GET", "/");
        let req = make_view(&m, &u, &h, &b);
        let ctx = ctx_with_asn("127.0.0.1", 15169);
        let d = evaluate_with_ctx(&rules, &req, &route(), &ctx);
        assert!(matches!(d.action, Action::Block { status: 403 }));
    }

    #[test]
    fn asn_condition_allows_non_matching_asn() {
        let rules = vec![asn_block_rule(&[15169])];
        let (m, u, h, b) = view("GET", "/");
        let req = make_view(&m, &u, &h, &b);
        let ctx = ctx_with_asn("127.0.0.1", 16509);
        let d = evaluate_with_ctx(&rules, &req, &route(), &ctx);
        assert!(matches!(d.action, Action::Allow));
    }

    #[test]
    fn asn_condition_returns_false_without_geoip() {
        let rules = vec![asn_block_rule(&[15169])];
        let (m, u, h, b) = view("GET", "/");
        let req = make_view(&m, &u, &h, &b);
        let d = evaluate(&rules, &req, &route());
        assert!(matches!(d.action, Action::Allow));
    }

    #[test]
    fn empty_country_list_never_matches() {
        let rules = vec![country_block_rule(&[])];
        let (m, u, h, b) = view("GET", "/");
        let req = make_view(&m, &u, &h, &b);
        let ctx = ctx_with_country("127.0.0.1", "CN");
        let d = evaluate_with_ctx(&rules, &req, &route(), &ctx);
        assert!(matches!(d.action, Action::Allow));
    }

    #[test]
    fn country_in_compound_condition() {
        // Block POST /admin only from a specific country.
        let rules = vec![Rule {
            id: "compound".into(),
            priority: 100,
            scope: Scope::Global,
            condition: Condition::All(vec![
                Condition::Method(vec!["POST".into()]),
                Condition::PathMatches(MatchOp::Prefix("/admin".into())),
                Condition::Country(vec!["CN".into()]),
            ]),
            action: RuleAction::Block { status: 451 },
        }];
        let ctx = ctx_with_country("127.0.0.1", "CN");
        // All three match → blocked.
        let (m, u, h, b) = view("POST", "/admin/users");
        let req = make_view(&m, &u, &h, &b);
        assert!(matches!(
            evaluate_with_ctx(&rules, &req, &route(), &ctx).action,
            Action::Block { .. }
        ));
        // Wrong path → allowed.
        let (m2, u2, h2, b2) = view("POST", "/public");
        let req2 = make_view(&m2, &u2, &h2, &b2);
        assert!(matches!(
            evaluate_with_ctx(&rules, &req2, &route(), &ctx).action,
            Action::Allow
        ));
    }

    // ------------------------------------------------------------------
    // LT-RUN-6 EVAL-01 + EVAL-02 regression coverage (2026-05-14)
    // ------------------------------------------------------------------

    fn make_view_peer<'a>(
        method: &'a http::Method,
        uri: &'a http::Uri,
        headers: &'a http::HeaderMap,
        body: &'a BodyPeek,
        peer: &str,
    ) -> RequestView<'a> {
        RequestView {
            method,
            uri,
            version: http::Version::HTTP_11,
            headers,
            peer: peer.parse().unwrap(),
            tls: None,
            body,
        }
    }

    fn block_on_cidr(cidr: &str) -> Vec<Rule> {
        vec![Rule {
            id: "block-subnet".into(),
            priority: 100,
            scope: Scope::Global,
            condition: Condition::IpIn(vec![cidr.into()]),
            action: RuleAction::Block { status: 403 },
        }]
    }

    fn rate_limit_rule(limit: u64, window_s: u32) -> Vec<Rule> {
        vec![Rule {
            id: "limit-login".into(),
            priority: 100,
            scope: Scope::Global,
            condition: Condition::PathMatches(MatchOp::Prefix("/login".into())),
            action: RuleAction::RateLimit {
                key: "ip".into(),
                limit,
                window_s,
            },
        }]
    }

    // ---- EVAL-01 — IpIn must use CIDR network match, not string prefix ----

    #[test]
    fn eval01_cidr_24_matches_host_inside_subnet() {
        let rules = block_on_cidr("10.0.0.0/24");
        let (m, u, h, b) = view("GET", "/");
        // Pre-fix: "10.0.0.5".starts_with("10.0.0.0") was false →
        // the rule would not fire and request would Allow.  With
        // the ipnet fix, 10.0.0.5 IS in 10.0.0.0/24 so we Block.
        let req = make_view_peer(&m, &u, &h, &b, "10.0.0.5:443");
        assert!(matches!(
            evaluate(&rules, &req, &route()).action,
            Action::Block { .. }
        ));
    }

    #[test]
    fn eval01_cidr_24_does_not_match_host_outside_subnet() {
        let rules = block_on_cidr("10.0.0.0/24");
        let (m, u, h, b) = view("GET", "/");
        // 10.0.1.5 is NOT in 10.0.0.0/24 — must Allow.
        let req = make_view_peer(&m, &u, &h, &b, "10.0.1.5:443");
        assert!(matches!(
            evaluate(&rules, &req, &route()).action,
            Action::Allow
        ));
    }

    #[test]
    fn eval01_cidr_8_matches_broad_range() {
        let rules = block_on_cidr("10.0.0.0/8");
        let (m, u, h, b) = view("GET", "/");
        for host in ["10.0.0.1", "10.250.99.255", "10.255.255.255"] {
            let peer = format!("{host}:443");
            let req = make_view_peer(&m, &u, &h, &b, &peer);
            assert!(
                matches!(
                    evaluate(&rules, &req, &route()).action,
                    Action::Block { .. }
                ),
                "expected block for {host} in /8",
            );
        }
        // 11.0.0.1 is OUTSIDE /8 — must Allow.
        let req2 = make_view_peer(&m, &u, &h, &b, "11.0.0.1:443");
        assert!(matches!(
            evaluate(&rules, &req2, &route()).action,
            Action::Allow
        ));
    }

    #[test]
    fn eval01_bare_ip_no_mask_still_matches() {
        // Back-compat: entries without `/` were previously treated
        // as an exact match.  Confirm the fix didn't break that.
        let rules = block_on_cidr("203.0.113.7");
        let (m, u, h, b) = view("GET", "/");
        let req = make_view_peer(&m, &u, &h, &b, "203.0.113.7:443");
        assert!(matches!(
            evaluate(&rules, &req, &route()).action,
            Action::Block { .. }
        ));
        let req2 = make_view_peer(&m, &u, &h, &b, "203.0.113.8:443");
        assert!(matches!(
            evaluate(&rules, &req2, &route()).action,
            Action::Allow
        ));
    }

    // ---- EVAL-02 — RateLimit must honour `limit`, not block immediately ----

    #[test]
    fn eval02_in_process_backend_allows_first_n_then_429s() {
        let rl = Arc::new(InProcessRuleRateLimit::new());
        let ctx = EvalContext::default().with_rate_limit(rl.clone());
        let rules = rate_limit_rule(3, 60);
        let (m, u, h, b) = view("POST", "/login");
        let req = make_view_peer(&m, &u, &h, &b, "192.0.2.10:443");

        // First 3 requests within the window → Allow with rule stamped.
        for i in 1..=3 {
            let d = evaluate_with_ctx(&rules, &req, &route(), &ctx);
            assert!(
                matches!(d.action, Action::Allow),
                "req {i} expected Allow, got {:?}",
                d.action,
            );
            assert_eq!(d.rule_id.as_deref(), Some("limit-login"));
        }
        // 4th tips over → RateLimited.
        let d = evaluate_with_ctx(&rules, &req, &route(), &ctx);
        assert!(matches!(d.action, Action::RateLimited { .. }));
    }

    #[test]
    fn eval02_different_ips_have_independent_buckets() {
        // limit=1 makes the boundary obvious: the SECOND request from
        // the SAME ip is rate-limited, but a different ip's first
        // request still allowed.
        let rl = Arc::new(InProcessRuleRateLimit::new());
        let ctx = EvalContext::default().with_rate_limit(rl.clone());
        let rules = rate_limit_rule(1, 60);
        let (m, u, h, b) = view("POST", "/login");

        let req_a = make_view_peer(&m, &u, &h, &b, "192.0.2.10:443");
        let req_b = make_view_peer(&m, &u, &h, &b, "198.51.100.5:443");

        assert!(matches!(
            evaluate_with_ctx(&rules, &req_a, &route(), &ctx).action,
            Action::Allow
        ));
        assert!(matches!(
            evaluate_with_ctx(&rules, &req_a, &route(), &ctx).action,
            Action::RateLimited { .. }
        ));
        // Different IP — fresh bucket.
        assert!(matches!(
            evaluate_with_ctx(&rules, &req_b, &route(), &ctx).action,
            Action::Allow
        ));
    }

    #[test]
    fn eval02_high_limit_does_not_block_normal_traffic() {
        // The exact "limit=1000 vs limit=1 behave identically"
        // L-tester regression.  At limit=1000, 50 requests must
        // all Allow.
        let rl = Arc::new(InProcessRuleRateLimit::new());
        let ctx = EvalContext::default().with_rate_limit(rl.clone());
        let rules = rate_limit_rule(1000, 60);
        let (m, u, h, b) = view("POST", "/login");
        let req = make_view_peer(&m, &u, &h, &b, "203.0.113.20:443");
        for i in 0..50 {
            let d = evaluate_with_ctx(&rules, &req, &route(), &ctx);
            assert!(
                matches!(d.action, Action::Allow),
                "req #{i} expected Allow, got {:?}",
                d.action,
            );
        }
    }

    #[test]
    fn eval02_no_backend_is_permissive_not_blocking() {
        // Pre-fix behaviour: no backend wired → every matching
        // request got RateLimited immediately.  Post-fix: no
        // backend → Allow.
        let ctx = EvalContext::default();  // no rate_limit
        let rules = rate_limit_rule(1, 60);
        let (m, u, h, b) = view("POST", "/login");
        let req = make_view_peer(&m, &u, &h, &b, "192.0.2.10:443");
        // 5 requests in quick succession — all must Allow.
        for _ in 0..5 {
            assert!(matches!(
                evaluate_with_ctx(&rules, &req, &route(), &ctx).action,
                Action::Allow
            ));
        }
    }

    #[test]
    fn eval02_window_recovers_after_expiry() {
        // Build the limiter directly so we can drive
        // `check_at` with controlled timestamps.
        let rl = InProcessRuleRateLimit::new();
        let t0 = Instant::now();
        // limit=2 per 10s window.
        let bucket = "test-bucket";
        let window = Duration::from_secs(10);
        assert!(rl.check_at(bucket, 2, window, t0));
        assert!(rl.check_at(bucket, 2, window, t0 + Duration::from_millis(1)));
        // Third call within window → denied.
        assert!(!rl.check_at(bucket, 2, window, t0 + Duration::from_millis(2)));
        // After the window slides past, the bucket is empty
        // again.
        let later = t0 + window + Duration::from_secs(1);
        assert!(rl.check_at(bucket, 2, window, later));
    }
}
