//! Idle (inactivity) timeout for streaming response bodies.
//!
//! SSE plan decision 4: the data plane's whole-body read deadline
//! (`response_body_read_timeout`, default 30 s) would kill any
//! long-lived stream. For streamed responses we instead apply an
//! **inactivity** timeout — the deadline resets every time the upstream
//! produces a frame. SSE servers send heartbeats as comment frames
//! (`:keepalive\n\n`) or `event: ping` every 15–30 s; those are data
//! frames and keep the stream alive. Only true silence past the deadline
//! ends the stream, which releases the pinned upstream connection.
//!
//! Standalone primitive (built first per §11.3) — decoupled from the
//! `Full<Bytes>` → `DataBody` migration so it can be unit-tested in
//! isolation with paused time.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use hyper::body::{Body, Frame, SizeHint};
use tokio::time::{Instant, Sleep};

/// Wraps a streaming body with an inactivity timeout on its frames.
///
/// The idle deadline resets on every frame the inner body yields (data
/// **or** trailers — any upstream activity counts). When the inner body
/// stays `Pending` past `idle`, the stream ends gracefully
/// (`Poll::Ready(None)`); the caller drops the body, releasing the
/// upstream connection. Inner errors and natural end-of-stream pass
/// through unchanged.
pub struct IdleTimeoutBody<B> {
    inner: B,
    idle: Duration,
    sleep: Pin<Box<Sleep>>,
}

impl<B> IdleTimeoutBody<B> {
    pub fn new(inner: B, idle: Duration) -> Self {
        Self {
            inner,
            idle,
            sleep: Box::pin(tokio::time::sleep(idle)),
        }
    }
}

impl<B> Body for IdleTimeoutBody<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            // Any frame from upstream resets the idle deadline.
            Poll::Ready(Some(Ok(frame))) => {
                this.sleep.as_mut().reset(Instant::now() + this.idle);
                Poll::Ready(Some(Ok(frame)))
            }
            // Inner error or natural end-of-stream: pass through.
            Poll::Ready(other) => Poll::Ready(other),
            // Inner has nothing right now — race the idle timer.
            Poll::Pending => match this.sleep.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use std::convert::Infallible;

    /// A mock upstream body that yields `n` data frames spaced `gap`
    /// apart (each frame waits `gap` of its own timer), then ends. Models
    /// an SSE stream emitting an event (or heartbeat) every `gap`.
    struct SpacedBody {
        remaining: usize,
        gap: Duration,
        timer: Pin<Box<Sleep>>,
    }

    impl SpacedBody {
        fn new(n: usize, gap: Duration) -> Self {
            Self {
                remaining: n,
                gap,
                timer: Box::pin(tokio::time::sleep(gap)),
            }
        }
    }

    impl Body for SpacedBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            let this = self.get_mut();
            if this.remaining == 0 {
                return Poll::Ready(None);
            }
            match this.timer.as_mut().poll(cx) {
                Poll::Ready(()) => {
                    this.remaining -= 1;
                    if this.remaining > 0 {
                        this.timer.as_mut().reset(Instant::now() + this.gap);
                    }
                    Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"data: x\n\n")))))
                }
                Poll::Pending => Poll::Pending,
            }
        }
    }

    /// Count the data frames a body yields before it ends.
    async fn count_frames<B>(mut body: B) -> usize
    where
        B: Body<Data = Bytes> + Unpin,
        B::Error: std::fmt::Debug,
    {
        let mut n = 0;
        while let Some(frame) = body.frame().await {
            if frame.unwrap().is_data() {
                n += 1;
            }
        }
        n
    }

    /// A heartbeat/event every `gap` < `idle` must keep the stream alive:
    /// the idle timer resets on each frame, so all frames are delivered
    /// and the stream ends only when the upstream itself ends.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn resets_on_each_frame_so_all_frames_are_delivered() {
        // 5 frames × 50ms gap = 250ms total, well past the 80ms idle —
        // so this only passes if the deadline RESETS on each frame (each
        // gap 50ms < 80ms idle). Without the reset the original 80ms
        // deadline fires after the first frame.
        let upstream = SpacedBody::new(5, Duration::from_millis(50));
        let body = IdleTimeoutBody::new(upstream, Duration::from_millis(80));
        assert_eq!(
            count_frames(body).await,
            5,
            "each frame (gap 50ms < idle 80ms) resets the timer; all delivered",
        );
    }

    /// When the upstream goes silent longer than `idle`, the stream ends
    /// before the next frame would have arrived.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn ends_stream_when_upstream_goes_silent_past_idle() {
        let upstream = SpacedBody::new(3, Duration::from_millis(200));
        let body = IdleTimeoutBody::new(upstream, Duration::from_millis(50));
        assert_eq!(
            count_frames(body).await,
            0,
            "gap(200ms) > idle(50ms): idle fires before the first frame",
        );
    }
}
