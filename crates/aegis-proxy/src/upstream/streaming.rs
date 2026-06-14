//! Response-mode classification for the data plane (SSE plan, decisions
//! 2 + 2a).
//!
//! A response is classified **exactly once**, in `forward()`, the moment
//! the upstream response headers arrive: its media type is matched
//! against a config allowlist to decide [`ResponseMode::Streaming`] vs
//! [`ResponseMode::Buffered`]. The result then rides the `DecisionTag` to
//! every later consumer (filter/cache bypass, audit, metrics) — those
//! sites read the carried mode and never re-parse `Content-Type`, which
//! is what prevents the classification from drifting between phases.
//!
//! Media-type matching is a proper parse, not a `starts_with`: SSE is
//! sent as both `text/event-stream` and `text/event-stream;
//! charset=utf-8`, so we compare only the `type/subtype` essence
//! (parameters and surrounding whitespace stripped, ASCII-lowercased).

/// Whether a response is buffered (today's behaviour: size-capped,
/// body-inspected) or streamed through incrementally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseMode {
    /// Buffered to a size cap, response body inspected (the default).
    Buffered,
    /// Streamed through frame-by-frame; response body is **not** buffered
    /// or body-inspected (header-inspected only — see plan decision 3).
    Streaming,
}

impl ResponseMode {
    pub fn is_streaming(self) -> bool {
        matches!(self, ResponseMode::Streaming)
    }
}

/// Extract the `type/subtype` essence of a `Content-Type` value:
/// everything before the first `;`, trimmed and ASCII-lowercased.
/// `None` when the value carries no media type.
fn media_type_essence(content_type: &str) -> Option<String> {
    let essence = content_type.split(';').next()?.trim();
    if essence.is_empty() {
        return None;
    }
    Some(essence.to_ascii_lowercase())
}

/// Classify a response from its `Content-Type` against the streaming
/// allowlist. Returns [`ResponseMode::Streaming`] only when the media-type
/// essence matches an allowlist entry (case-insensitively); everything
/// else — including a missing `Content-Type` or an empty allowlist —
/// buffers. This is the single source of the streaming decision
/// (plan decision 2a); call it exactly once, in `forward()`.
pub fn classify_response_mode(content_type: Option<&str>, allowlist: &[String]) -> ResponseMode {
    let Some(essence) = content_type.and_then(media_type_essence) else {
        return ResponseMode::Buffered;
    };
    if allowlist.iter().any(|a| a.trim().eq_ignore_ascii_case(&essence)) {
        ResponseMode::Streaming
    } else {
        ResponseMode::Buffered
    }
}

// ---------------------------------------------------------------------------
// Streaming body builder (plan §4 streaming branch)
// ---------------------------------------------------------------------------

use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use hyper::body::{Body, Frame, SizeHint};

use crate::body::DataBody;
use crate::upstream::idle_timeout::IdleTimeoutBody;

/// Adapts a fallible streaming body into one whose `Error` is
/// `Infallible` by treating an inner error as **end of stream**: frames
/// up to the error are forwarded, then the stream ends. A streamed
/// response is header-inspected only and can't inject an error body
/// downstream, so closing the stream is the honest signal; the error is
/// logged for forensics.
pub struct EndOnError<B> {
    inner: B,
}

impl<B> EndOnError<B> {
    pub fn new(inner: B) -> Self {
        Self { inner }
    }
}

impl<B> Body for EndOnError<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(Some(Err(e))) => {
                tracing::warn!(error = %e, "streamed upstream body error; ending stream");
                Poll::Ready(None)
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Build a pass-through streaming [`DataBody`] from an upstream response
/// body: apply the idle (inactivity) timeout (plan decision 4), fold any
/// inner error into a clean end-of-stream, and box into the unified body
/// type. Hop-by-hop header filtering happens separately on the response
/// head in `forward()`; this handles the body only — no buffering, no
/// size cap.
pub fn stream_through<B>(upstream: B, idle: Duration) -> DataBody
where
    B: Body<Data = Bytes> + Unpin + Send + 'static,
    B::Error: std::fmt::Display,
{
    use http_body_util::BodyExt;
    EndOnError::new(IdleTimeoutBody::new(upstream, idle)).boxed_unsync()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow() -> Vec<String> {
        vec!["text/event-stream".to_string()]
    }

    #[test]
    fn bare_event_stream_streams() {
        assert_eq!(
            classify_response_mode(Some("text/event-stream"), &allow()),
            ResponseMode::Streaming,
        );
    }

    #[test]
    fn event_stream_with_charset_param_streams() {
        assert_eq!(
            classify_response_mode(Some("text/event-stream; charset=utf-8"), &allow()),
            ResponseMode::Streaming,
        );
        // No space after the semicolon either.
        assert_eq!(
            classify_response_mode(Some("text/event-stream;charset=utf-8"), &allow()),
            ResponseMode::Streaming,
        );
    }

    #[test]
    fn matching_is_case_insensitive_and_trims() {
        assert_eq!(
            classify_response_mode(Some("Text/Event-Stream"), &allow()),
            ResponseMode::Streaming,
        );
        assert_eq!(
            classify_response_mode(Some("  text/event-stream  "), &allow()),
            ResponseMode::Streaming,
        );
    }

    #[test]
    fn non_allowlisted_types_buffer() {
        assert_eq!(
            classify_response_mode(Some("text/html"), &allow()),
            ResponseMode::Buffered,
        );
        assert_eq!(
            classify_response_mode(Some("application/json"), &allow()),
            ResponseMode::Buffered,
        );
        // `text/event-streamx` must NOT match (essence compare, not prefix).
        assert_eq!(
            classify_response_mode(Some("text/event-streamx"), &allow()),
            ResponseMode::Buffered,
        );
    }

    #[test]
    fn missing_content_type_buffers() {
        assert_eq!(
            classify_response_mode(None, &allow()),
            ResponseMode::Buffered,
        );
    }

    #[test]
    fn empty_allowlist_never_streams() {
        let empty: Vec<String> = Vec::new();
        assert_eq!(
            classify_response_mode(Some("text/event-stream"), &empty),
            ResponseMode::Buffered,
        );
    }

    // A scripted body yielding a fixed sequence of Ok(frame) / Err steps,
    // immediately ready (no timers) — for the error-folding logic.
    struct Scripted {
        steps: std::collections::VecDeque<Result<&'static str, &'static str>>,
    }
    impl Scripted {
        fn new(steps: Vec<Result<&'static str, &'static str>>) -> Self {
            Self {
                steps: steps.into_iter().collect(),
            }
        }
    }
    impl Body for Scripted {
        type Data = Bytes;
        type Error = String; // Display

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            match self.get_mut().steps.pop_front() {
                Some(Ok(s)) => Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(s.as_bytes()))))),
                Some(Err(e)) => Poll::Ready(Some(Err(e.to_string()))),
                None => Poll::Ready(None),
            }
        }
    }

    #[tokio::test]
    async fn end_on_error_keeps_frames_before_error_then_ends() {
        use http_body_util::BodyExt;
        let body = EndOnError::new(Scripted::new(vec![Ok("a"), Ok("b"), Err("boom"), Ok("c")]));
        // collect() drives to end-of-stream; the error must terminate it
        // cleanly (Infallible), keeping only the frames before it.
        let bytes = body.collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], b"ab", "frames before the error survive; error ends the stream");
    }

    #[tokio::test]
    async fn end_on_error_passes_clean_stream_through() {
        use http_body_util::BodyExt;
        let body = EndOnError::new(Scripted::new(vec![Ok("x"), Ok("y"), Ok("z")]));
        let bytes = body.collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], b"xyz");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn stream_through_forwards_then_folds_error() {
        use http_body_util::BodyExt;
        // Generous idle so the timeout never fires; the error folds to end.
        let body = stream_through(
            Scripted::new(vec![Ok("hello "), Ok("world"), Err("reset")]),
            Duration::from_secs(60),
        );
        let bytes = body.collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], b"hello world");
    }
}
