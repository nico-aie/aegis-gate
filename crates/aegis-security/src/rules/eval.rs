use aegis_core::context::RouteCtx;
use aegis_core::decision::{Action, ChallengeLevel, Decision};
use aegis_core::pipeline::RequestView;

use super::ast::{Condition, MatchOp, Rule, RuleAction, Scope};

/// Evaluate rules against a request.  Rules are evaluated in priority order
/// (highest first).  Terminal actions short-circuit; non-terminal actions
/// (RaiseRisk, LogOnly) accumulate and evaluation continues.
pub fn evaluate(rules: &[Rule], req: &RequestView<'_>, route: &RouteCtx) -> Decision {
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

        if !matches_condition(&rule.condition, req) {
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
                key: _,
                limit: _,
                window_s,
            } => {
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

fn matches_condition(cond: &Condition, req: &RequestView<'_>) -> bool {
    match cond {
        Condition::True => true,
        Condition::All(children) => children.iter().all(|c| matches_condition(c, req)),
        Condition::Any(children) => children.iter().any(|c| matches_condition(c, req)),
        Condition::Not(inner) => !matches_condition(inner, req),
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
            let ip_str = req.peer.ip().to_string();
            cidrs.iter().any(|cidr| {
                // Simple prefix match for CIDR — full impl would use ipnet.
                ip_str.starts_with(cidr.split('/').next().unwrap_or(""))
                    || cidr == &ip_str
            })
        }
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
            tenant_id: None,
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
        let d = evaluate(&rules, &req, &route());
        assert!(matches!(
            d.action,
            Action::RateLimited { retry_after_s: 60 }
        ));
    }
}
