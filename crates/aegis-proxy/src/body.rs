//! Unified data-plane response body type (SSE plan, decision 1).
//!
//! The data plane historically emitted `Full<Bytes>` at every layer. To
//! let `text/event-stream` responses stream through incrementally (rather
//! than buffer to a size cap), the whole data-plane response chain moves
//! to one streamable type: [`DataBody`] = `UnsyncBoxBody<Bytes,
//! Infallible>`. The buffered path boxes a `Full<Bytes>` (the per-response
//! box alloc is noise next to network latency); the streaming path
//! (Phase 2) boxes a frame stream. Mirrors the in-repo `admin_sse`
//! precedent (`admin_sse::into_boxed`).
//!
//! Phase 1 is a pure type migration — no behaviour change. Builders keep
//! constructing `Response<Full<Bytes>>` and wrap their return value with
//! [`boxed`]; the bytes are identical, just type-erased.

use std::convert::Infallible;

use bytes::Bytes;
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full};

/// The single response-body type the data plane flows end to end.
pub type DataBody = UnsyncBoxBody<Bytes, Infallible>;

/// Box a buffered `Full<Bytes>` response into the unified [`DataBody`].
/// No behaviour change — same bytes, same status, same headers.
pub fn boxed(resp: hyper::Response<Full<Bytes>>) -> hyper::Response<DataBody> {
    resp.map(|b| b.boxed_unsync())
}

/// Build a buffered [`DataBody`] directly from bytes — for response
/// builders that construct a body inline rather than via `Full`.
pub fn full(bytes: impl Into<Bytes>) -> DataBody {
    Full::new(bytes.into()).boxed_unsync()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn boxed_preserves_status_headers_and_bytes() {
        let resp = hyper::Response::builder()
            .status(418)
            .header("x-test", "1")
            .body(Full::new(Bytes::from_static(b"hello")))
            .unwrap();
        let out = boxed(resp);
        assert_eq!(out.status(), 418);
        assert_eq!(out.headers().get("x-test").unwrap(), "1");
        let body = out.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"hello");
    }

    #[tokio::test]
    async fn full_builds_databody_from_bytes() {
        let body = full(Bytes::from_static(b"abc"));
        let bytes = body.collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], b"abc");
    }
}
