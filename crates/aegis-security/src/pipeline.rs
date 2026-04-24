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

    (Tier::CatchAll, FailureMode::FailOpen)
}

/// Stub pipeline that wires the rule engine into `SecurityPipeline`.
pub struct Pipeline {
    rules: Arc<RuleSet>,
}

impl Pipeline {
    pub fn new(rules: Arc<RuleSet>) -> Self {
        Self { rules }
    }
}

#[async_trait::async_trait]
impl SecurityPipeline for Pipeline {
    async fn inbound(
        &self,
        view: RequestView<'_>,
        _rctx: &mut RequestCtx,
        route: &RouteCtx,
    ) -> Decision {
        let snapshot = self.rules.snapshot();
        crate::rules::evaluate(&snapshot, &view, route)
    }

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
        _frame: &[u8],
        _rctx: &RequestCtx,
        _route: &RouteCtx,
    ) -> OutboundAction {
        OutboundAction::PassThrough
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
        assert_eq!(tier, Tier::CatchAll);
        assert_eq!(fm, FailureMode::FailOpen);
    }

    #[test]
    fn root_is_catchall() {
        let (m, u, h, b) = view_for_path("/");
        let req = make_view(&m, &u, &h, &b);
        let (tier, _) = classify_tier(None, &req);
        assert_eq!(tier, Tier::CatchAll);
    }

    #[test]
    fn route_override_wins() {
        let rctx = RouteCtx {
            route_id: "force-critical".into(),
            tier: Tier::Critical,
            failure_mode: FailureMode::FailClose,
            upstream: "pool".into(),
            tenant_id: None,
        };
        let (m, u, h, b) = view_for_path("/static/logo.png");
        let req = make_view(&m, &u, &h, &b);
        let (tier, fm) = classify_tier(Some(&rctx), &req);
        assert_eq!(tier, Tier::Critical);
        assert_eq!(fm, FailureMode::FailClose);
    }
}
