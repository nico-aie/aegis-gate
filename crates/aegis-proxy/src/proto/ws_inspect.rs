//! Inspecting WebSocket bridge — the opt-in replacement for the
//! zero-copy `copy_bidirectional` tunnel when a route sets
//! `ws_inspect.enabled`.
//!
//! Shape (design §3): one task, two directions via `tokio::select!`.
//! - **upstream → client:** verbatim byte copy (never inspected in v1).
//! - **client → upstream:** RFC 6455 frames are decoded; binary and
//!   control frames pass through **verbatim** (original masked bytes),
//!   and **text** messages are reassembled across fragments and handed
//!   to the inspection hook before forwarding.
//!
//! Forwarding preserves the original client masking (we re-emit the raw
//! received frame bytes), because real WS servers — including
//! `tokio-tungstenite`, our test backend — reject unmasked client
//! frames. This overrides design decision §4.1's "unmasked" lean in
//! favour of the documented preserve-masking fallback.
//!
//! ## Oversize policy (operator steer, 2026-06-11)
//!
//! A reassembled text message that exceeds `max_message_bytes` is **not
//! closed**. Inspection is **skipped** and the message is forwarded
//! (bounded memory: we stop buffering at the cap and stream the rest),
//! incrementing a skip counter. This favours availability for
//! legitimately large messages over the design's fail-closed `1009`.
//! The trade-off — an attacker can pad past the cap to evade — is
//! metered so operators can see it and tune the cap. A single *frame*
//! over [`ws_codec::MAX_FRAME_PAYLOAD`] is still a protocol-level close
//! (an individual multi-MiB text frame is anomalous).
//!
//! WS-MSG2 lands the bridge + reassembly (no detection yet — the hook
//! is "allow all"). WS-MSG3 plugs the body detectors into the
//! `InspectText` action; WS-MSG4 adds the verdict I/O + audit + metrics.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::ws_codec::{self, FrameHeader, HeaderParse, Opcode, WsCodecError};

/// Upstream→client copy chunk size. Matches the `MAX_HEAD_BYTES`-class
/// buffering used elsewhere in the proto layer.
const COPY_CHUNK: usize = 16 * 1024;

/// Per-bridge configuration (from `RouteConfig.ws_inspect`).
#[derive(Clone, Copy, Debug)]
pub struct WsBridgeConfig {
    /// Reassembled-message cap; over this, inspection is skipped and the
    /// message forwarded. 0 ⇒ [`ws_codec::MAX_MESSAGE_BYTES`].
    pub max_message_bytes: usize,
}

impl WsBridgeConfig {
    fn effective_max(&self) -> usize {
        if self.max_message_bytes == 0 {
            ws_codec::MAX_MESSAGE_BYTES
        } else {
            self.max_message_bytes
        }
    }
}

/// The inspection verdict for one reassembled text message, returned by
/// the caller-supplied hook. The hook owns the detector run, threshold,
/// mode (enforce vs log_only), and any audit/metric emission; the bridge
/// only acts on the I/O decision here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WsVerdict {
    /// Forward the message to the upstream (clean, under threshold, or
    /// `log_only` — the hook already audited the would-block).
    Allow,
    /// Enforce a block: drop the message and close the socket with WS
    /// Close `1008` (policy violation).
    Block,
}

/// Counters returned when the bridge tears down (folded into the
/// `websocket_close` audit + metrics by the caller).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WsBridgeStats {
    pub client_to_upstream: u64,
    pub upstream_to_client: u64,
    /// Text messages that were reassembled and handed to inspection.
    pub messages_inspected: u64,
    /// Text messages forwarded **without** inspection because they
    /// exceeded `max_message_bytes` (the skip policy above).
    pub messages_skipped_oversize: u64,
    /// Text messages the inspection hook enforced a block on (→ close).
    pub messages_blocked: u64,
    /// Set when the bridge closed the connection itself (protocol error
    /// or a policy block).
    pub close_code: Option<u16>,
}

/// An owned, fully-read frame: the original bytes (for verbatim
/// forwarding) plus the unmasked payload (for inspection).
struct OwnedFrame {
    header: FrameHeader,
    raw: Vec<u8>,
    unmasked_payload: Vec<u8>,
}

/// Result of reading one frame off the client.
enum FrameRead {
    Frame(OwnedFrame),
    /// Clean EOF — the client half closed.
    Eof,
    /// A protocol-level error that maps to a close code.
    Protocol(WsCodecError),
}

/// What to do with a decoded client frame, decided by the reassembly
/// state machine.
enum FrameAction {
    /// Forward these raw bytes to the upstream now. `skipped_oversize`
    /// marks a text message that bypassed inspection due to the cap.
    Forward {
        raw: Vec<u8>,
        skipped_oversize: bool,
    },
    /// Buffered into the in-progress text message; nothing to forward.
    Buffered,
    /// A text message completed: inspect `payload`; forward `raw` if
    /// allowed. (WS-MSG3 wires the detector; WS-MSG2 always forwards.)
    InspectText { payload: Vec<u8>, raw: Vec<u8> },
    /// Protocol violation → close with this error's code.
    Protocol(WsCodecError),
}

/// Reassembles fragmented text messages and decides per-frame whether to
/// forward, buffer, or surface a completed message for inspection.
struct Reassembly {
    max: usize,
    /// The opcode that started the in-progress fragmented message
    /// (`Text` or `Binary`); `None` between messages.
    current: Option<Opcode>,
    /// True once the in-progress *text* message exceeded the cap — its
    /// frames stream through un-inspected.
    skipping: bool,
    text_payload: Vec<u8>,
    text_raw: Vec<u8>,
}

impl Reassembly {
    fn new(max: usize) -> Self {
        Self {
            max,
            current: None,
            skipping: false,
            text_payload: Vec::new(),
            text_raw: Vec::new(),
        }
    }

    fn reset_text(&mut self) {
        self.current = None;
        self.skipping = false;
        self.text_payload.clear();
        self.text_raw.clear();
    }

    fn accept(&mut self, frame: OwnedFrame) -> FrameAction {
        // Fail closed on a compressed frame. WS-MSG5 strips
        // `permessage-deflate` from the forwarded handshake, so RSV1
        // should never be set on an inspecting listener; if it is, we
        // can't decode the payload to inspect it — close rather than
        // forward an un-inspected compressed message.
        if frame.header.rsv1 {
            return FrameAction::Protocol(WsCodecError::CompressionUnsupported);
        }
        let fin = frame.header.fin;
        match frame.header.opcode {
            // Control frames never participate in fragmentation and are
            // never inspected — forward verbatim.
            Opcode::Close | Opcode::Ping | Opcode::Pong => FrameAction::Forward {
                raw: frame.raw,
                skipped_oversize: false,
            },

            Opcode::Binary => {
                // Binary is never inspected. Track fragmentation only so
                // following continuation frames are attributed correctly.
                self.current = if fin { None } else { Some(Opcode::Binary) };
                FrameAction::Forward {
                    raw: frame.raw,
                    skipped_oversize: false,
                }
            }

            Opcode::Text => {
                if self.current.is_some() {
                    // A new data frame while a message is in progress.
                    return FrameAction::Protocol(WsCodecError::ReservedBits);
                }
                if fin {
                    // Single-frame text message.
                    if frame.unmasked_payload.len() > self.max {
                        FrameAction::Forward {
                            raw: frame.raw,
                            skipped_oversize: true,
                        }
                    } else {
                        FrameAction::InspectText {
                            payload: frame.unmasked_payload,
                            raw: frame.raw,
                        }
                    }
                } else {
                    // First fragment of a multi-frame text message.
                    self.current = Some(Opcode::Text);
                    if frame.unmasked_payload.len() > self.max {
                        self.skipping = true;
                        FrameAction::Forward {
                            raw: frame.raw,
                            skipped_oversize: true,
                        }
                    } else {
                        self.text_payload = frame.unmasked_payload;
                        self.text_raw = frame.raw;
                        FrameAction::Buffered
                    }
                }
            }

            Opcode::Continuation => match self.current {
                Some(Opcode::Binary) => {
                    if fin {
                        self.current = None;
                    }
                    FrameAction::Forward {
                        raw: frame.raw,
                        skipped_oversize: false,
                    }
                }
                Some(Opcode::Text) => {
                    if self.skipping {
                        // Already over the cap — stream through.
                        if fin {
                            self.reset_text();
                        }
                        FrameAction::Forward {
                            raw: frame.raw,
                            skipped_oversize: true,
                        }
                    } else if self.text_payload.len() + frame.unmasked_payload.len() > self.max {
                        // This fragment tips the message over the cap →
                        // flush buffered + this frame, switch to skip.
                        self.skipping = true;
                        let mut out = std::mem::take(&mut self.text_raw);
                        out.extend_from_slice(&frame.raw);
                        self.text_payload.clear();
                        if fin {
                            self.reset_text();
                        }
                        FrameAction::Forward {
                            raw: out,
                            skipped_oversize: true,
                        }
                    } else {
                        self.text_payload.extend_from_slice(&frame.unmasked_payload);
                        self.text_raw.extend_from_slice(&frame.raw);
                        if fin {
                            let payload = std::mem::take(&mut self.text_payload);
                            let raw = std::mem::take(&mut self.text_raw);
                            self.reset_text();
                            FrameAction::InspectText { payload, raw }
                        } else {
                            FrameAction::Buffered
                        }
                    }
                }
                // Continuation with no message in progress is illegal.
                None => FrameAction::Protocol(WsCodecError::ReservedBits),
                // `current` is only ever set to Text/Binary above; any
                // other value is unreachable but kept exhaustive.
                Some(_) => FrameAction::Protocol(WsCodecError::ReservedBits),
            },
        }
    }
}

/// Read exactly one frame off `reader`, accumulating into `buf` across
/// partial reads. Returns `Eof` on a clean close, `Protocol` on a
/// codec-level violation, otherwise the owned frame.
async fn read_one_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> std::io::Result<FrameRead> {
    loop {
        match ws_codec::parse_header(buf) {
            Err(e) => return Ok(FrameRead::Protocol(e)),
            Ok(HeaderParse::Header(header)) => {
                let total = header.header_len + header.payload_len;
                if buf.len() < total {
                    // Need the payload too — read more before slicing.
                    if !read_more(reader, buf).await? {
                        // EOF mid-frame: a truncated frame is a clean
                        // teardown from our perspective.
                        return Ok(FrameRead::Eof);
                    }
                    continue;
                }
                let raw = buf[..total].to_vec();
                let mut unmasked_payload = buf[header.header_len..total].to_vec();
                if let Some(key) = header.mask_key {
                    ws_codec::unmask(&mut unmasked_payload, key);
                }
                buf.drain(..total);
                return Ok(FrameRead::Frame(OwnedFrame {
                    header,
                    raw,
                    unmasked_payload,
                }));
            }
            Ok(HeaderParse::Incomplete) => {
                if !read_more(reader, buf).await? {
                    // EOF with no (or a partial) header → clean close.
                    return Ok(FrameRead::Eof);
                }
            }
        }
    }
}

/// Append one chunk from `reader` to `buf`. Returns `false` on EOF.
async fn read_more<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> std::io::Result<bool> {
    let mut chunk = [0u8; COPY_CHUNK];
    let n = reader.read(&mut chunk).await?;
    if n == 0 {
        return Ok(false);
    }
    buf.extend_from_slice(&chunk[..n]);
    Ok(true)
}

/// Run the inspecting bridge until either side closes. Returns the byte
/// + message counters for the close audit.
///
/// `inspect` is called once per reassembled client→upstream **text**
/// message with its unmasked payload; it returns [`WsVerdict`]. Binary,
/// control, and oversize-skipped messages never reach it.
pub async fn run_bridge<C, U, F>(
    client: C,
    upstream: U,
    cfg: WsBridgeConfig,
    mut inspect: F,
) -> std::io::Result<WsBridgeStats>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
    F: FnMut(&[u8]) -> WsVerdict,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let mut cbuf: Vec<u8> = Vec::new();
    let mut up_chunk = [0u8; COPY_CHUNK];
    let mut reasm = Reassembly::new(cfg.effective_max());
    let mut stats = WsBridgeStats::default();

    loop {
        tokio::select! {
            // client → upstream: frame-parsed, text reassembled.
            read = read_one_frame(&mut client_read, &mut cbuf) => {
                match read? {
                    FrameRead::Eof => break,
                    FrameRead::Protocol(err) => {
                        let code = err.close_code();
                        let _ = client_write.write_all(&ws_codec::encode_close(code)).await;
                        stats.close_code = Some(code);
                        break;
                    }
                    FrameRead::Frame(frame) => {
                        match reasm.accept(frame) {
                            FrameAction::Forward { raw, skipped_oversize } => {
                                upstream_write.write_all(&raw).await?;
                                stats.client_to_upstream += raw.len() as u64;
                                if skipped_oversize {
                                    stats.messages_skipped_oversize += 1;
                                }
                            }
                            FrameAction::Buffered => {}
                            FrameAction::InspectText { payload, raw } => {
                                stats.messages_inspected += 1;
                                match inspect(&payload) {
                                    WsVerdict::Allow => {
                                        upstream_write.write_all(&raw).await?;
                                        stats.client_to_upstream += raw.len() as u64;
                                    }
                                    WsVerdict::Block => {
                                        // Enforce — drop the message, close
                                        // the client with policy violation.
                                        let code = ws_codec::close_code::POLICY_VIOLATION;
                                        let _ = client_write
                                            .write_all(&ws_codec::encode_close(code))
                                            .await;
                                        stats.messages_blocked += 1;
                                        stats.close_code = Some(code);
                                        break;
                                    }
                                }
                            }
                            FrameAction::Protocol(err) => {
                                let code = err.close_code();
                                let _ = client_write
                                    .write_all(&ws_codec::encode_close(code))
                                    .await;
                                stats.close_code = Some(code);
                                break;
                            }
                        }
                    }
                }
            }
            // upstream → client: verbatim copy.
            read = upstream_read.read(&mut up_chunk) => {
                let n = read?;
                if n == 0 { break; }
                client_write.write_all(&up_chunk[..n]).await?;
                stats.upstream_to_client += n as u64;
            }
        }
    }

    let _ = upstream_write.shutdown().await;
    let _ = client_write.shutdown().await;
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    /// Mask `payload` with `key` and build a client→server frame.
    fn client_frame(opcode: Opcode, payload: &[u8], fin: bool, key: [u8; 4]) -> Vec<u8> {
        let nibble = match opcode {
            Opcode::Continuation => 0x0,
            Opcode::Text => 0x1,
            Opcode::Binary => 0x2,
            Opcode::Close => 0x8,
            Opcode::Ping => 0x9,
            Opcode::Pong => 0xA,
        };
        let mut out = vec![(if fin { 0x80 } else { 0 }) | nibble];
        let len = payload.len();
        if len < 126 {
            out.push(0x80 | len as u8);
        } else {
            out.push(0x80 | 126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        out.extend_from_slice(&key);
        let mut masked = payload.to_vec();
        ws_codec::unmask(&mut masked, key); // unmask == mask (XOR)
        out.extend_from_slice(&masked);
        out
    }

    /// Drive the bridge with a custom inspector.
    async fn run_with_inspector<F>(
        client_bytes: Vec<u8>,
        cfg: WsBridgeConfig,
        inspect: F,
    ) -> (Vec<u8>, WsBridgeStats)
    where
        F: FnMut(&[u8]) -> WsVerdict + Send + 'static,
    {
        run_inner(client_bytes, cfg, inspect).await
    }

    /// Drive the bridge with an allow-all inspector (passthrough tests).
    async fn run_with(client_bytes: Vec<u8>, cfg: WsBridgeConfig) -> (Vec<u8>, WsBridgeStats) {
        run_inner(client_bytes, cfg, |_: &[u8]| WsVerdict::Allow).await
    }

    /// Write `client_bytes` to the client side, run the bridge against an
    /// echo-style upstream that records what it received, return (bytes
    /// upstream received, bridge stats).
    async fn run_inner<F>(
        client_bytes: Vec<u8>,
        cfg: WsBridgeConfig,
        inspect: F,
    ) -> (Vec<u8>, WsBridgeStats)
    where
        F: FnMut(&[u8]) -> WsVerdict + Send + 'static,
    {
        let (client_a, mut client_b) = duplex(64 * 1024);
        let (upstream_a, mut upstream_b) = duplex(64 * 1024);

        // Upstream consumer: read everything the bridge forwards.
        let upstream_task = tokio::spawn(async move {
            let mut got = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                match upstream_b.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got.extend_from_slice(&chunk[..n]),
                }
            }
            got
        });

        // Client writer: send the frames then close its write half.
        let client_task = tokio::spawn(async move {
            client_b.write_all(&client_bytes).await.unwrap();
            client_b.shutdown().await.unwrap();
            // Drain anything the bridge sends back (close frames) so the
            // bridge's client_write doesn't stall.
            let mut sink = Vec::new();
            let _ = client_b.read_to_end(&mut sink).await;
        });

        let stats = run_bridge(client_a, upstream_a, cfg, inspect)
            .await
            .unwrap();
        client_task.await.unwrap();
        let got = upstream_task.await.unwrap();
        (got, stats)
    }

    const KEY: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
    fn big_cfg() -> WsBridgeConfig {
        WsBridgeConfig {
            max_message_bytes: 0,
        }
    }

    #[tokio::test]
    async fn single_text_frame_forwarded_verbatim() {
        let frame = client_frame(Opcode::Text, b"hello chat", true, KEY);
        let (got, stats) = run_with(frame.clone(), big_cfg()).await;
        assert_eq!(got, frame, "text frame forwarded byte-identical (masked)");
        assert_eq!(stats.messages_inspected, 1);
        assert_eq!(stats.messages_skipped_oversize, 0);
    }

    #[tokio::test]
    async fn binary_frame_passthrough_byte_identical() {
        let frame = client_frame(Opcode::Binary, &[0xDE, 0xAD, 0xBE, 0xEF], true, KEY);
        let (got, stats) = run_with(frame.clone(), big_cfg()).await;
        assert_eq!(got, frame);
        // Binary is never inspected.
        assert_eq!(stats.messages_inspected, 0);
    }

    #[tokio::test]
    async fn fragmented_text_reassembled_and_forwarded_in_order() {
        // "Hel" (text, !fin) + "lo!" (continuation, fin).
        let f1 = client_frame(Opcode::Text, b"Hel", false, KEY);
        let f2 = client_frame(Opcode::Continuation, b"lo!", true, KEY);
        let mut input = f1.clone();
        input.extend_from_slice(&f2);
        let (got, stats) = run_with(input.clone(), big_cfg()).await;
        // Both raw fragments forwarded, in order, byte-identical.
        assert_eq!(got, input);
        assert_eq!(stats.messages_inspected, 1, "one reassembled message");
    }

    #[tokio::test]
    async fn oversize_text_message_is_skipped_not_closed() {
        // Cap at 8 bytes; send a 20-byte single text frame.
        let cfg = WsBridgeConfig {
            max_message_bytes: 8,
        };
        let payload = vec![b'A'; 20];
        let frame = client_frame(Opcode::Text, &payload, true, KEY);
        let (got, stats) = run_with(frame.clone(), cfg).await;
        assert_eq!(got, frame, "oversize message forwarded un-inspected");
        assert_eq!(stats.messages_skipped_oversize, 1);
        assert_eq!(stats.messages_inspected, 0);
        assert_eq!(stats.close_code, None, "must NOT close on oversize");
    }

    #[tokio::test]
    async fn fragmented_text_over_cap_switches_to_skip() {
        // Cap 5: "abcd" (4, ok so far) + "efgh" (tips over) → skip.
        let cfg = WsBridgeConfig {
            max_message_bytes: 5,
        };
        let f1 = client_frame(Opcode::Text, b"abcd", false, KEY);
        let f2 = client_frame(Opcode::Continuation, b"efgh", true, KEY);
        let mut input = f1.clone();
        input.extend_from_slice(&f2);
        let (got, stats) = run_with(input.clone(), cfg).await;
        assert_eq!(got, input, "both fragments forwarded");
        assert_eq!(stats.messages_skipped_oversize, 1);
        assert_eq!(stats.messages_inspected, 0);
    }

    #[tokio::test]
    async fn unmasked_client_frame_closes_with_protocol_error() {
        // An unmasked text frame is illegal client→server.
        let frame = vec![0x81, 0x03, b'a', b'b', b'c'];
        let (_got, stats) = run_with(frame, big_cfg()).await;
        assert_eq!(stats.close_code, Some(ws_codec::close_code::PROTOCOL_ERROR));
    }

    // ---- WS-MSG3: inspection verdict ------------------------------

    #[tokio::test]
    async fn blocked_text_message_is_dropped_and_socket_closed() {
        // Inspector blocks any message containing "ATTACK".
        let frame = client_frame(Opcode::Text, b"x ATTACK x", true, KEY);
        let (got, stats) = run_with_inspector(frame, big_cfg(), |payload| {
            if payload.windows(6).any(|w| w == b"ATTACK") {
                WsVerdict::Block
            } else {
                WsVerdict::Allow
            }
        })
        .await;
        assert!(
            got.is_empty(),
            "blocked message must NOT reach the upstream"
        );
        assert_eq!(stats.messages_blocked, 1);
        assert_eq!(
            stats.close_code,
            Some(ws_codec::close_code::POLICY_VIOLATION)
        );
    }

    #[tokio::test]
    async fn benign_text_passes_when_inspector_allows() {
        let frame = client_frame(Opcode::Text, b"just a chat message", true, KEY);
        let (got, stats) = run_with_inspector(frame.clone(), big_cfg(), |payload| {
            if payload.windows(6).any(|w| w == b"ATTACK") {
                WsVerdict::Block
            } else {
                WsVerdict::Allow
            }
        })
        .await;
        assert_eq!(got, frame, "benign message forwarded verbatim");
        assert_eq!(stats.messages_blocked, 0);
        assert_eq!(stats.close_code, None);
    }

    #[tokio::test]
    async fn compressed_rsv1_frame_fails_closed() {
        // RSV1 set on a text frame (permessage-deflate) — the bridge
        // can't decode it to inspect, so it closes (defence-in-depth;
        // WS-MSG5 strips the extension at handshake so this is rare).
        let mut frame = client_frame(Opcode::Text, b"compressed?", true, KEY);
        frame[0] |= 0x40; // set RSV1
        let (got, stats) = run_with(frame, big_cfg()).await;
        assert!(got.is_empty(), "compressed frame must not be forwarded");
        assert_eq!(stats.close_code, Some(ws_codec::close_code::PROTOCOL_ERROR));
    }

    #[tokio::test]
    async fn fragmented_attack_blocked_after_reassembly() {
        // Split "AT" + "TACK" across two frames — neither fragment
        // contains "ATTACK", but the reassembled message does. Proves
        // there's no fragmentation evasion.
        let f1 = client_frame(Opcode::Text, b"x AT", false, KEY);
        let f2 = client_frame(Opcode::Continuation, b"TACK x", true, KEY);
        let mut input = f1;
        input.extend_from_slice(&f2);
        let (got, stats) = run_with_inspector(input, big_cfg(), |payload| {
            if payload.windows(6).any(|w| w == b"ATTACK") {
                WsVerdict::Block
            } else {
                WsVerdict::Allow
            }
        })
        .await;
        assert!(
            got.is_empty(),
            "fragmented attack blocked, nothing forwarded"
        );
        assert_eq!(stats.messages_blocked, 1);
    }
}
