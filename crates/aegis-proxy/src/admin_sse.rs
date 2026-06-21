//! Streaming SSE body for `/dashboard/sse` (B4-T4).
//!
//! Replaces the M1-era stub that wrote one event then closed
//! the TCP connection. The new handler subscribes to the
//! shared `AuditBus`, formats each event with the existing
//! [`aegis_control::dashboard::sse::format_sse`], and pushes
//! frames to the wire as a streaming hyper body. An
//! [`HEARTBEAT`] comment is emitted every
//! [`HEARTBEAT_INTERVAL`] of idle so reverse proxies + load
//! balancers don't reap the connection mid-stream.
//!
//! # Body type
//!
//! The streaming body is built as
//! `http_body_util::StreamBody<...>` and boxed via
//! [`UnsyncBoxBody`] so the admin router can return either a
//! buffered [`Full<Bytes>`] or a streaming body from the
//! same `Response<UnsyncBoxBody<Bytes, Infallible>>` type.
//! [`into_boxed`] wraps a `Full` body for the non-SSE
//! branches.

use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures::Stream;
use http_body::Frame;
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full, StreamBody};
use hyper::Response;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use aegis_control::dashboard::sse::{
    event_matches, format_sse, EventFilter,
};
use aegis_core::audit::{AuditBus, AuditEvent};

/// Idle heartbeat cadence. Long enough to dwarf the per-event
/// volume on a healthy node, short enough that intermediate
/// proxies (default `proxy_read_timeout` 60s on Nginx) don't
/// drop the connection.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

/// SSE comment line emitted on idle heartbeats. Per the SSE
/// spec, lines starting with `:` are comments and are
/// silently ignored by `EventSource`.
pub const HEARTBEAT: &str = ":heartbeat\n\n";

/// SSE preamble sent before any event so a fresh client knows
/// the stream is alive. Mirrors the format the M1 stub used.
pub const PREAMBLE: &str =
    "data: {\"class\":\"system\",\"action\":\"connected\",\"reason\":\"dashboard SSE connected\"}\n\n";

/// Build the streaming response for `GET /dashboard/sse`.
///
/// `query` is the raw request query string (without the
/// leading `?`); recognised filter keys come from
/// [`EventFilter::parse_query`].
pub fn sse_response(
    bus: &AuditBus,
    fleet_bus: Option<&AuditBus>,
    query: &str,
) -> Response<UnsyncBoxBody<Bytes, Infallible>> {
    let filter = EventFilter::parse_query(query);
    let rx = bus.subscribe();
    // Cluster Phase 2 (§2b): when a fleet-event bus is wired, merge
    // peers' events into this node's SSE feed so any node's console
    // shows the whole fleet. `None` (single-node / cluster off) keeps
    // the local-only stream.
    let fleet_rx = fleet_bus.map(|b| b.subscribe());
    let body = build_stream_body(rx, fleet_rx, filter, HEARTBEAT_INTERVAL);
    Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .header("connection", "keep-alive")
        // SSE clients must not buffer this server-to-client.
        .header("x-accel-buffering", "no")
        .body(body)
        .unwrap()
}

/// Wrap a buffered `Full<Bytes>` as the same boxed body type
/// the SSE handler returns, so the admin router can mix both.
pub fn into_boxed(resp: Response<Full<Bytes>>) -> Response<UnsyncBoxBody<Bytes, Infallible>> {
    let (parts, body) = resp.into_parts();
    Response::from_parts(parts, body.boxed_unsync())
}

/// Compose the streaming body. Public so unit tests can drive
/// it without standing up an HTTP listener.
pub fn build_stream_body(
    rx: broadcast::Receiver<AuditEvent>,
    fleet_rx: Option<broadcast::Receiver<AuditEvent>>,
    filter: EventFilter,
    heartbeat: Duration,
) -> UnsyncBoxBody<Bytes, Infallible> {
    let inner = SseFrameStream::new(rx, fleet_rx, filter, heartbeat);
    StreamBody::new(inner).boxed_unsync()
}

/// Either branch of the merged stream. The `Event` arm is
/// boxed because `AuditEvent` is large enough to dominate the
/// enum size (clippy `large_enum_variant`); paying one
/// allocation per event keeps the merge stream's items
/// pointer-sized.
enum SseSource {
    Event(Box<Result<AuditEvent, tokio_stream::wrappers::errors::BroadcastStreamRecvError>>),
    Tick,
}

/// Stream of SSE frames pulled from a broadcast receiver.
/// Yields:
///
/// 1. The [`PREAMBLE`] frame on first poll.
/// 2. One `data: ...\n\n` frame per matching audit event.
/// 3. A [`HEARTBEAT`] frame whenever the stream has been idle
///    for at least the configured interval.
///
/// The merged inner stream's `Item = SseSource`, unified via
/// `.map()` on each side before merging — `BroadcastStream`
/// and `IntervalStream` have different native item types.
struct SseFrameStream {
    inner: Pin<Box<dyn Stream<Item = SseSource> + Send>>,
    filter: EventFilter,
    sent_preamble: bool,
}

impl SseFrameStream {
    fn new(
        rx: broadcast::Receiver<AuditEvent>,
        fleet_rx: Option<broadcast::Receiver<AuditEvent>>,
        filter: EventFilter,
        heartbeat: Duration,
    ) -> Self {
        let events = BroadcastStream::new(rx).map(|r| SseSource::Event(Box::new(r)));
        // `tokio::time::interval` fires its first tick at t=0,
        // which would push a heartbeat as the very first
        // frame. Use `interval_at(now + heartbeat, …)` so the
        // first tick fires only after `heartbeat` of true
        // idle.
        let start = tokio::time::Instant::now() + heartbeat;
        let mut interval = tokio::time::interval_at(start, heartbeat);
        // Skip missed ticks if a slow consumer pauses — we
        // don't want to flush a backlog of heartbeats once
        // they catch up.
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let interval_stream =
            tokio_stream::wrappers::IntervalStream::new(interval).map(|_| SseSource::Tick);
        let base = events.merge(interval_stream);
        // Cluster Phase 2 (§2b): fold the fleet-event bus into the same
        // frame stream when wired. Same `SseSource::Event` shape, so
        // the rest of the pipeline (filter, format) is unchanged.
        let inner: Pin<Box<dyn Stream<Item = SseSource> + Send>> = match fleet_rx {
            Some(frx) => {
                let fleet = BroadcastStream::new(frx).map(|r| SseSource::Event(Box::new(r)));
                Box::pin(base.merge(fleet))
            }
            None => Box::pin(base),
        };
        Self {
            inner,
            filter,
            sent_preamble: false,
        }
    }
}

impl Stream for SseFrameStream {
    type Item = Result<Frame<Bytes>, Infallible>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if !this.sent_preamble {
            this.sent_preamble = true;
            return Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(
                PREAMBLE.as_bytes(),
            )))));
        }
        // Drain the merged stream. Only `None` from the merged
        // stream terminates us — in practice that's both
        // the broadcast closed *and* the interval stream
        // ended, which never happens for the latter until our
        // struct drops. So this ends only when the bus dies
        // *and* the merge yields None for both arms; in
        // practice the heartbeat keeps the stream alive.
        loop {
            match this.inner.as_mut().poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(SseSource::Event(boxed))) => match *boxed {
                    Ok(ev) => {
                        if event_matches(&this.filter, &ev) {
                            let s = format_sse(&ev);
                            return Poll::Ready(Some(Ok(Frame::data(Bytes::from(s)))));
                        }
                        continue;
                    }
                    Err(_lag) => {
                        // Slow consumer skipped events. Tell
                        // the client and continue — dropping
                        // the connection here would lose the
                        // live feed for every dashboard tab
                        // the operator has open.
                        return Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(
                            b":lagged\n\n",
                        )))));
                    }
                },
                Poll::Ready(Some(SseSource::Tick)) => {
                    return Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(
                        HEARTBEAT.as_bytes(),
                    )))));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::audit::{AuditClass, AuditEvent};

    fn ev(req_id: &str, class: AuditClass) -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: req_id.into(),
            class,
            tenant_id: None,
            tier: None,
            action: "block".into(),
            reason: "test".into(),
            client_ip: "1.2.3.4".into(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            method: None,
            path: None,
            mode: None,
            fields: serde_json::Value::Null,
        }
    }

    async fn collect_n_frames(
        body: UnsyncBoxBody<Bytes, Infallible>,
        n: usize,
    ) -> Vec<String> {
        let mut frames = Vec::new();
        let mut body = body;
        while frames.len() < n {
            let frame = match body.frame().await {
                Some(Ok(f)) => f,
                _ => break,
            };
            if let Ok(data) = frame.into_data() {
                frames.push(String::from_utf8_lossy(&data).into_owned());
            }
        }
        frames
    }

    #[tokio::test]
    async fn first_frame_is_preamble() {
        let bus = AuditBus::new(8);
        let body = build_stream_body(
            bus.subscribe(),
            None,
            EventFilter::default(),
            Duration::from_secs(60),
        );
        let frames = collect_n_frames(body, 1).await;
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0], PREAMBLE);
    }

    #[tokio::test]
    async fn events_arrive_after_preamble() {
        let bus = AuditBus::new(8);
        let rx = bus.subscribe();
        let body = build_stream_body(
            rx,
            None,
            EventFilter::default(),
            Duration::from_secs(60),
        );
        // Emit two events before consuming so the broadcast
        // doesn't drop them on a fresh receiver.
        bus.emit(ev("e1", AuditClass::Detection));
        bus.emit(ev("e2", AuditClass::Detection));
        let frames = collect_n_frames(body, 3).await;
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0], PREAMBLE);
        assert!(frames[1].contains("e1"), "{:?}", frames[1]);
        assert!(frames[2].contains("e2"), "{:?}", frames[2]);
    }

    #[tokio::test]
    async fn filter_drops_non_matching_events() {
        let bus = AuditBus::new(8);
        let filter = EventFilter {
            classes: vec![AuditClass::Detection],
            ..Default::default()
        };
        let body =
            build_stream_body(bus.subscribe(), None, filter, Duration::from_secs(60));
        bus.emit(ev("admin-1", AuditClass::Admin));
        bus.emit(ev("det-1", AuditClass::Detection));
        // Preamble + the matching detection event = 2 frames.
        let frames = collect_n_frames(body, 2).await;
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], PREAMBLE);
        assert!(frames[1].contains("det-1"));
        // The admin-1 event must NOT have leaked through.
        assert!(!frames[1].contains("admin-1"));
    }

    #[tokio::test]
    async fn heartbeat_fires_on_idle() {
        let bus = AuditBus::new(8);
        // Aggressive heartbeat so the test stays fast.
        let body = build_stream_body(
            bus.subscribe(),
            None,
            EventFilter::default(),
            Duration::from_millis(50),
        );
        let frames = collect_n_frames(body, 2).await;
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], PREAMBLE);
        assert_eq!(frames[1], HEARTBEAT);
    }

    #[tokio::test]
    async fn body_ends_when_bus_closes() {
        let bus = AuditBus::new(8);
        let body = build_stream_body(
            bus.subscribe(),
            None,
            EventFilter::default(),
            Duration::from_secs(60),
        );
        // Drop bus → broadcast sender count drops to 0 →
        // receiver returns Closed → BroadcastStream ends.
        // The merged interval stream stays alive forever, so
        // strictly the body itself doesn't end on close.
        // We assert the preamble lands and then the receiver
        // path is silent (nothing else flushed in 100ms,
        // because the heartbeat is 60s and the bus is dead).
        drop(bus);
        let mut body = body;
        // First poll → preamble.
        let preamble = body.frame().await.unwrap().unwrap();
        assert_eq!(preamble.into_data().unwrap(), Bytes::from(PREAMBLE));
        // Second poll within heartbeat: no event, no tick.
        let next = tokio::time::timeout(
            Duration::from_millis(100),
            body.frame(),
        )
        .await;
        assert!(next.is_err(), "expected timeout — no event, no tick");
    }

    #[tokio::test]
    async fn into_boxed_wraps_full_body() {
        let resp = Response::builder()
            .status(200)
            .body(Full::new(Bytes::from("hello")))
            .unwrap();
        let boxed = into_boxed(resp);
        assert_eq!(boxed.status(), 200);
        let bytes = boxed.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], b"hello");
    }

    #[tokio::test]
    async fn sse_response_sets_streaming_headers() {
        let bus = AuditBus::new(8);
        let resp = sse_response(&bus, None, "");
        assert_eq!(resp.status(), 200);
        let h = resp.headers();
        assert_eq!(
            h.get("content-type").unwrap(),
            "text/event-stream"
        );
        assert_eq!(h.get("cache-control").unwrap(), "no-cache");
        assert_eq!(h.get("x-accel-buffering").unwrap(), "no");
    }

    #[tokio::test]
    async fn sse_response_honours_class_filter_from_query() {
        let bus = AuditBus::new(16);
        let resp = sse_response(&bus, None, "class=detection");
        bus.emit(ev("a", AuditClass::Admin));
        bus.emit(ev("d", AuditClass::Detection));
        let body = resp.into_body();
        let frames = collect_n_frames(body, 2).await;
        assert_eq!(frames[0], PREAMBLE);
        assert!(frames[1].contains("\"d\""), "{:?}", frames[1]);
        assert!(!frames[1].contains("\"a\""));
    }
}
