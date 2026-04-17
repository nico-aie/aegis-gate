use aegis_core::context::{RequestCtx, RouteCtx};
use aegis_core::decision::{Action, Decision};
use aegis_core::pipeline::{OutboundAction, RequestView, SecurityPipeline};

/// A no-op security pipeline that allows all requests.
/// Used as a placeholder for week 1 before detectors are wired up.
pub struct NoopPipeline;

#[async_trait::async_trait]
impl SecurityPipeline for NoopPipeline {
    async fn inbound(
        &self,
        _view: RequestView<'_>,
        _rctx: &mut RequestCtx,
        _route: &RouteCtx,
    ) -> Decision {
        Decision {
            action: Action::Allow,
            reason: "noop pipeline".into(),
            rule_id: None,
            risk_score: 0,
        }
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
    use aegis_core::context::ClientInfo;
    use aegis_core::pipeline::BodyPeek;
    use aegis_core::tier::{FailureMode, Tier};
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn make_ctx() -> RequestCtx {
        RequestCtx {
            request_id: "test-req".into(),
            received_at: std::time::Instant::now(),
            client: ClientInfo {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                tls_fingerprint: None,
                h2_fingerprint: None,
                user_agent: None,
            },
            tenant_id: None,
            trace_id: None,
            fields: BTreeMap::new(),
        }
    }

    fn make_route() -> RouteCtx {
        RouteCtx {
            route_id: "test".into(),
            tier: Tier::CatchAll,
            failure_mode: FailureMode::FailOpen,
            upstream: "default".into(),
            tenant_id: None,
        }
    }

    #[tokio::test]
    async fn noop_pipeline_allows_all() {
        let pipeline = NoopPipeline;
        let mut ctx = make_ctx();
        let route = make_route();
        let body = BodyPeek::empty();

        let view = RequestView {
            method: &http::Method::GET,
            uri: &"/".parse().unwrap(),
            version: http::Version::HTTP_11,
            headers: &http::HeaderMap::new(),
            peer: "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            tls: None,
            body: &body,
        };

        let decision = pipeline.inbound(view, &mut ctx, &route).await;
        assert!(matches!(decision.action, Action::Allow));
        assert_eq!(decision.risk_score, 0);
    }

    #[tokio::test]
    async fn noop_pipeline_passes_through_responses() {
        let pipeline = NoopPipeline;
        let ctx = make_ctx();
        let route = make_route();

        let action = pipeline.on_body_frame(b"hello", &ctx, &route).await;
        assert!(matches!(action, OutboundAction::PassThrough));
    }
}
