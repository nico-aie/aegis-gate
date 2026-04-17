use crate::context::{RequestCtx, RouteCtx, TlsFingerprint};
use crate::decision::Decision;

pub struct RequestView<'a> {
    pub method: &'a http::Method,
    pub uri: &'a http::Uri,
    pub version: http::Version,
    pub headers: &'a http::HeaderMap,
    pub peer: std::net::SocketAddr,
    pub tls: Option<&'a TlsFingerprint>,
    pub body: &'a BodyPeek,
}

pub struct BodyPeek {
    data: Vec<u8>,
    content_length: Option<u64>,
    chunked: bool,
}

impl BodyPeek {
    pub fn new(data: Vec<u8>, content_length: Option<u64>, chunked: bool) -> Self {
        Self { data, content_length, chunked }
    }

    pub fn empty() -> Self {
        Self { data: Vec::new(), content_length: Some(0), chunked: false }
    }

    pub fn peek(&self, max: usize) -> &[u8] {
        let end = max.min(self.data.len());
        &self.data[..end]
    }

    pub fn content_length(&self) -> Option<u64> {
        self.content_length
    }

    pub fn is_chunked(&self) -> bool {
        self.chunked
    }
}

#[derive(Clone, Debug)]
pub enum OutboundAction {
    PassThrough,
    Rewrite(bytes::Bytes),
    Abort { reason: String },
}

pub struct DetectorLimits {
    pub max_body_peek: usize,
    pub max_body_scan: usize,
}

impl Default for DetectorLimits {
    fn default() -> Self {
        Self {
            max_body_peek: 1_048_576,  // 1 MiB
            max_body_scan: 2_097_152,  // 2 MiB
        }
    }
}

#[async_trait::async_trait]
pub trait SecurityPipeline: Send + Sync + 'static {
    async fn inbound(
        &self,
        view: RequestView<'_>,
        rctx: &mut RequestCtx,
        route: &RouteCtx,
    ) -> Decision;

    async fn on_response_start(
        &self,
        head: &http::response::Parts,
        rctx: &RequestCtx,
        route: &RouteCtx,
    ) -> OutboundAction;

    async fn on_body_frame(
        &self,
        frame: &[u8],
        rctx: &RequestCtx,
        route: &RouteCtx,
    ) -> OutboundAction;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_peek_empty() {
        let bp = BodyPeek::empty();
        assert_eq!(bp.peek(1024), &[] as &[u8]);
        assert_eq!(bp.content_length(), Some(0));
        assert!(!bp.is_chunked());
    }

    #[test]
    fn body_peek_returns_up_to_max() {
        let data = vec![1, 2, 3, 4, 5];
        let bp = BodyPeek::new(data, Some(5), false);
        assert_eq!(bp.peek(3), &[1, 2, 3]);
        assert_eq!(bp.peek(100), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn body_peek_chunked() {
        let bp = BodyPeek::new(vec![0; 10], None, true);
        assert!(bp.is_chunked());
        assert!(bp.content_length().is_none());
    }

    #[test]
    fn detector_limits_defaults() {
        let lim = DetectorLimits::default();
        assert_eq!(lim.max_body_peek, 1_048_576);
        assert_eq!(lim.max_body_scan, 2_097_152);
    }

    #[test]
    fn outbound_action_passthrough() {
        let a = OutboundAction::PassThrough;
        assert!(matches!(a, OutboundAction::PassThrough));
    }

    #[test]
    fn outbound_action_rewrite() {
        let a = OutboundAction::Rewrite(bytes::Bytes::from_static(b"redacted"));
        assert!(matches!(a, OutboundAction::Rewrite(_)));
    }

    #[test]
    fn outbound_action_abort() {
        let a = OutboundAction::Abort { reason: "dlp match".into() };
        assert!(matches!(a, OutboundAction::Abort { .. }));
    }
}
