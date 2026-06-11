//! Bounded RFC 6455 WebSocket frame codec — header decode, unmask, and
//! an unmasked frame writer. Pure (no I/O): it operates on byte slices
//! so the inspecting bridge (`data_plane`) owns the socket reads and
//! enforces back-pressure.
//!
//! Scope (WS-MSG1): exactly what the message-inspection bridge needs —
//! decode a client→server frame header, unmask the payload, reassemble
//! text messages across fragments, and re-emit a frame to the upstream
//! unmasked. It is **not** a full WebSocket implementation: the
//! handshake already happened, and we never generate masking keys.
//!
//! Design: `plans/future/websocket-message-inspection.md` §4. Bounds
//! mirror the `MAX_HEAD_BYTES` discipline in `proto/ws_forward.rs`.

/// Single-frame payload cap. A frame declaring more than this closes
/// the connection with `1009` (message too big) — an attacker can't
/// force unbounded buffering. (1 MiB.)
pub const MAX_FRAME_PAYLOAD: usize = 1 << 20;

/// Reassembled-message cap across continuation frames. Over this →
/// close `1009`. (4 MiB.)
pub const MAX_MESSAGE_BYTES: usize = 4 << 20;

/// RFC 6455 §7.4.1 close codes the bridge emits.
pub mod close_code {
    /// Endpoint terminating the connection due to a protocol error.
    pub const PROTOCOL_ERROR: u16 = 1002;
    /// Data within a text message was not consistent with UTF-8.
    pub const INVALID_PAYLOAD: u16 = 1007;
    /// Generic policy violation (an inspected frame was blocked).
    pub const POLICY_VIOLATION: u16 = 1008;
    /// Message too big to process (frame/message bound exceeded).
    pub const MESSAGE_TOO_BIG: u16 = 1009;
}

/// WebSocket frame opcodes (RFC 6455 §5.2). Reserved opcodes are
/// rejected at parse time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl Opcode {
    fn from_nibble(n: u8) -> Result<Opcode, WsCodecError> {
        match n {
            0x0 => Ok(Opcode::Continuation),
            0x1 => Ok(Opcode::Text),
            0x2 => Ok(Opcode::Binary),
            0x8 => Ok(Opcode::Close),
            0x9 => Ok(Opcode::Ping),
            0xA => Ok(Opcode::Pong),
            other => Err(WsCodecError::ReservedOpcode(other)),
        }
    }

    /// Control frames (close/ping/pong) — never inspected, never
    /// fragmented, and capped at 125 bytes by RFC 6455.
    pub fn is_control(self) -> bool {
        matches!(self, Opcode::Close | Opcode::Ping | Opcode::Pong)
    }

    fn nibble(self) -> u8 {
        match self {
            Opcode::Continuation => 0x0,
            Opcode::Text => 0x1,
            Opcode::Binary => 0x2,
            Opcode::Close => 0x8,
            Opcode::Ping => 0x9,
            Opcode::Pong => 0xA,
        }
    }
}

/// A decoded frame header (everything before the payload bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    pub fin: bool,
    /// RSV1 — set by `permessage-deflate`. The bridge fails closed when
    /// inspecting (compressed frames aren't decodable here in v1).
    pub rsv1: bool,
    pub opcode: Opcode,
    pub masked: bool,
    pub mask_key: Option<[u8; 4]>,
    pub payload_len: usize,
    /// Total bytes the header occupies (incl. extended length + mask).
    pub header_len: usize,
}

/// Errors that map to a WebSocket close code; the bridge closes the
/// connection with [`WsCodecError::close_code`] on any of these.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WsCodecError {
    #[error("reserved opcode 0x{0:x}")]
    ReservedOpcode(u8),
    #[error("reserved RSV2/RSV3 bit set")]
    ReservedBits,
    #[error("client→server frame was not masked")]
    NotMasked,
    #[error("control frame with payload > 125 bytes")]
    ControlFrameTooLong,
    #[error("control frame must not be fragmented")]
    FragmentedControlFrame,
    #[error("frame payload {0} exceeds MAX_FRAME_PAYLOAD")]
    FrameTooLarge(usize),
    #[error("reassembled message exceeds MAX_MESSAGE_BYTES")]
    MessageTooLarge,
    #[error("64-bit length has the high bit set")]
    LengthHighBitSet,
}

impl WsCodecError {
    /// The RFC 6455 close code to send when this error fires.
    pub fn close_code(self) -> u16 {
        match self {
            WsCodecError::FrameTooLarge(_) | WsCodecError::MessageTooLarge => {
                close_code::MESSAGE_TOO_BIG
            }
            _ => close_code::PROTOCOL_ERROR,
        }
    }
}

/// Result of attempting to decode a frame header from a buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderParse {
    /// A complete header was decoded.
    Header(FrameHeader),
    /// Not enough bytes buffered yet to decode the header — read more.
    Incomplete,
}

/// Decode a frame header from the front of `buf`, validating the bits
/// the inspecting bridge cares about. Does **not** consume the payload;
/// the caller reads `header.payload_len` more bytes after `header_len`.
///
/// `is_control` fragmentation / length rules are enforced here so the
/// bridge can treat any `Ok(Header)` as well-formed.
pub fn parse_header(buf: &[u8]) -> Result<HeaderParse, WsCodecError> {
    if buf.len() < 2 {
        return Ok(HeaderParse::Incomplete);
    }
    let b0 = buf[0];
    let b1 = buf[1];

    let fin = b0 & 0x80 != 0;
    let rsv1 = b0 & 0x40 != 0;
    // RSV2/RSV3 are only valid with negotiated extensions we don't
    // support — always a protocol error.
    if b0 & 0x30 != 0 {
        return Err(WsCodecError::ReservedBits);
    }
    let opcode = Opcode::from_nibble(b0 & 0x0F)?;

    let masked = b1 & 0x80 != 0;
    // Client→server frames MUST be masked (RFC 6455 §5.1).
    if !masked {
        return Err(WsCodecError::NotMasked);
    }

    if opcode.is_control() && !fin {
        return Err(WsCodecError::FragmentedControlFrame);
    }

    let len7 = (b1 & 0x7F) as usize;
    let (payload_len, len_bytes) = match len7 {
        126 => {
            if buf.len() < 4 {
                return Ok(HeaderParse::Incomplete);
            }
            (u16::from_be_bytes([buf[2], buf[3]]) as usize, 2)
        }
        127 => {
            if buf.len() < 10 {
                return Ok(HeaderParse::Incomplete);
            }
            let raw = u64::from_be_bytes([
                buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
            ]);
            // RFC 6455: the most-significant bit MUST be 0.
            if raw & 0x8000_0000_0000_0000 != 0 {
                return Err(WsCodecError::LengthHighBitSet);
            }
            (raw as usize, 8)
        }
        n => (n, 0),
    };

    // Control frames are capped at 125 bytes (no extended length).
    if opcode.is_control() && payload_len > 125 {
        return Err(WsCodecError::ControlFrameTooLong);
    }
    if payload_len > MAX_FRAME_PAYLOAD {
        return Err(WsCodecError::FrameTooLarge(payload_len));
    }

    let mask_offset = 2 + len_bytes;
    let header_len = mask_offset + 4; // masked is guaranteed above
    if buf.len() < header_len {
        return Ok(HeaderParse::Incomplete);
    }
    let mask_key = [
        buf[mask_offset],
        buf[mask_offset + 1],
        buf[mask_offset + 2],
        buf[mask_offset + 3],
    ];

    Ok(HeaderParse::Header(FrameHeader {
        fin,
        rsv1,
        opcode,
        masked,
        mask_key: Some(mask_key),
        payload_len,
        header_len,
    }))
}

/// Unmask `payload` in place with the 4-byte `key` (RFC 6455 §5.3 — a
/// simple repeating XOR). No-op for an all-zero key.
pub fn unmask(payload: &mut [u8], key: [u8; 4]) {
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte ^= key[i & 3];
    }
}

/// Encode a frame to forward to the upstream, **unmasked** (the WAF is
/// the server-side peer; server→backend frames need no mask). Used to
/// re-emit an inspected/allowed text message. `payload` is the final
/// (reassembled or single-frame) bytes.
pub fn encode_unmasked(opcode: Opcode, payload: &[u8], fin: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 10);
    let b0 = (if fin { 0x80 } else { 0 }) | opcode.nibble();
    out.push(b0);
    let len = payload.len();
    if len < 126 {
        out.push(len as u8); // MASK bit 0 — unmasked
    } else if len <= u16::MAX as usize {
        out.push(126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(payload);
    out
}

/// Encode a server→client Close frame (unmasked) carrying a 2-byte
/// status code. Sent to the client when the bridge tears down on a
/// policy block (`1008`), protocol error (`1002`/`1007`), or an
/// oversize message (`1009`).
pub fn encode_close(code: u16) -> Vec<u8> {
    encode_unmasked(Opcode::Close, &code.to_be_bytes(), true)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6455 §5.7 canonical vectors.
    // Unmasked "Hello" text frame.
    const UNMASKED_HELLO: &[u8] = &[0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f];
    // Masked "Hello": key 0x37fa213d.
    const MASKED_HELLO: &[u8] = &[
        0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
    ];

    fn header_of(buf: &[u8]) -> FrameHeader {
        match parse_header(buf).unwrap() {
            HeaderParse::Header(h) => h,
            HeaderParse::Incomplete => panic!("expected complete header"),
        }
    }

    #[test]
    fn parses_masked_text_header_and_unmasks_to_hello() {
        let h = header_of(MASKED_HELLO);
        assert!(h.fin);
        assert!(!h.rsv1);
        assert_eq!(h.opcode, Opcode::Text);
        assert!(h.masked);
        assert_eq!(h.payload_len, 5);
        assert_eq!(h.header_len, 6); // 2 + 4 mask
        let mut payload = MASKED_HELLO[h.header_len..].to_vec();
        unmask(&mut payload, h.mask_key.unwrap());
        assert_eq!(&payload, b"Hello");
    }

    #[test]
    fn unmasked_client_frame_is_protocol_error() {
        // A server-style unmasked frame from a client is illegal.
        let err = parse_header(UNMASKED_HELLO).unwrap_err();
        assert_eq!(err, WsCodecError::NotMasked);
        assert_eq!(err.close_code(), close_code::PROTOCOL_ERROR);
    }

    #[test]
    fn incomplete_header_when_buffer_short() {
        assert_eq!(parse_header(&[0x81]).unwrap(), HeaderParse::Incomplete);
        // 126 length class needs 2 length bytes + 4 mask = 8 total.
        assert_eq!(
            parse_header(&[0x81, 0xFE, 0x01]).unwrap(),
            HeaderParse::Incomplete
        );
    }

    #[test]
    fn parses_16bit_length_class() {
        // FIN+text, masked, len=126 → 200 bytes, key 0x01020304.
        let mut frame = vec![0x81, 0xFE, 0x00, 0xC8, 0x01, 0x02, 0x03, 0x04];
        frame.extend(std::iter::repeat(0xAA).take(200));
        let h = header_of(&frame);
        assert_eq!(h.payload_len, 200);
        assert_eq!(h.header_len, 8); // 2 + 2 len + 4 mask
    }

    #[test]
    fn rejects_rsv2_rsv3() {
        // RSV2 set (0x20) with masked text.
        let err = parse_header(&[0xA1, 0x80, 0, 0, 0, 0]).unwrap_err();
        assert_eq!(err, WsCodecError::ReservedBits);
    }

    #[test]
    fn surfaces_rsv1_for_deflate_failclose() {
        // RSV1 set (0x40) — bridge fails closed, but parse succeeds so
        // the caller can decide. Masked text, len 0.
        let h = header_of(&[0xC1, 0x80, 0, 0, 0, 0]);
        assert!(h.rsv1);
        assert_eq!(h.opcode, Opcode::Text);
    }

    #[test]
    fn rejects_reserved_opcode() {
        // Opcode 0x3 is reserved (non-control).
        let err = parse_header(&[0x83, 0x80, 0, 0, 0, 0]).unwrap_err();
        assert_eq!(err, WsCodecError::ReservedOpcode(0x3));
    }

    #[test]
    fn rejects_fragmented_control_frame() {
        // Ping (0x9) without FIN.
        let err = parse_header(&[0x09, 0x80, 0, 0, 0, 0]).unwrap_err();
        assert_eq!(err, WsCodecError::FragmentedControlFrame);
    }

    #[test]
    fn rejects_oversize_control_frame() {
        // Close (0x8) FIN, masked, declared len 126 → control too long.
        let err = parse_header(&[0x88, 0xFE, 0x00, 0x7E, 0, 0, 0, 0]).unwrap_err();
        assert_eq!(err, WsCodecError::ControlFrameTooLong);
    }

    #[test]
    fn rejects_frame_over_max_payload() {
        // 64-bit length just over MAX_FRAME_PAYLOAD.
        let big = (MAX_FRAME_PAYLOAD as u64 + 1).to_be_bytes();
        let mut buf = vec![0x82, 0xFF];
        buf.extend_from_slice(&big);
        buf.extend_from_slice(&[0, 0, 0, 0]); // mask
        let err = parse_header(&buf).unwrap_err();
        assert!(matches!(err, WsCodecError::FrameTooLarge(_)));
        assert_eq!(err.close_code(), close_code::MESSAGE_TOO_BIG);
    }

    #[test]
    fn rejects_64bit_high_bit() {
        let bad = 0x8000_0000_0000_0001u64.to_be_bytes();
        let mut buf = vec![0x82, 0xFF];
        buf.extend_from_slice(&bad);
        buf.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            parse_header(&buf).unwrap_err(),
            WsCodecError::LengthHighBitSet
        );
    }

    #[test]
    fn encode_unmasked_roundtrips_through_parse_as_server_frame() {
        // encode_unmasked emits a server-style (unmasked) frame; flip
        // the mask expectation to confirm the wire layout is correct.
        let frame = encode_unmasked(Opcode::Text, b"Hello", true);
        assert_eq!(frame[0], 0x81); // FIN + text
        assert_eq!(frame[1], 0x05); // unmasked, len 5
        assert_eq!(&frame[2..], b"Hello");
    }

    #[test]
    fn encode_unmasked_uses_16bit_length_over_125() {
        let payload = vec![0x61u8; 300];
        let frame = encode_unmasked(Opcode::Binary, &payload, true);
        assert_eq!(frame[0], 0x82);
        assert_eq!(frame[1], 126);
        assert_eq!(u16::from_be_bytes([frame[2], frame[3]]), 300);
        assert_eq!(&frame[4..], &payload[..]);
    }

    #[test]
    fn unmask_is_its_own_inverse() {
        let key = [0xDE, 0xAD, 0xBE, 0xEF];
        let original = b"' OR 1=1--".to_vec();
        let mut buf = original.clone();
        unmask(&mut buf, key);
        assert_ne!(buf, original);
        unmask(&mut buf, key);
        assert_eq!(buf, original);
    }
}
