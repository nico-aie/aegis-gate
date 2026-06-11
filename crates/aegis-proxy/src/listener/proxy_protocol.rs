//! PROXY-protocol (v1 text + v2 binary) header reader for the
//! pre-TLS accept path — real client IP behind an L4 / TCP-passthrough
//! load balancer.
//!
//! Design: `plans/future/proxy-protocol.md` §3.1 (read discipline) and
//! §3.6 (failure-mode table). Tracker:
//! `plans/issues/FEAT-proxy-protocol-l4-client-ip.md`.
//!
//! ## Read discipline (why this module owns the read, not `ppp`)
//!
//! We must consume **exactly** the PROXY header off the raw `TcpStream`
//! and not one byte of the client's TLS ClientHello — otherwise JA3/JA4
//! and the handshake break. `ppp` parses a `&[u8]`; it does no I/O. So
//! the flow is:
//!
//! 1. **Peek one byte** (does not consume). A v2 header starts `0x0D`,
//!    a v1 header starts `b'P'` (`"PROXY "`). A direct TLS client starts
//!    `0x16` — so an absent header is detected without consuming
//!    anything, and `optional` mode can fall through to TLS cleanly.
//! 2. Once a signature byte commits us to a header, every subsequent
//!    byte up to the header terminator belongs to the header (the
//!    ClientHello only starts after it) — so we switch to **consuming**
//!    exact-length reads: v1 reads to the first `\r\n` (cap 107 bytes);
//!    v2 reads the fixed 16-byte header, then exactly the declared
//!    payload length. No over-read, no replay buffer.
//! 3. The whole pre-TLS read is deadline-bounded so a peer that opens a
//!    socket and stalls cannot tie up a task ahead of TLS.
//!
//! **P1 (this phase) is observe-only:** the accept loop logs + counts
//! the outcome but does NOT yet override the effective peer or enforce
//! the `trusted_proxies` boundary. That is P2.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// v2 binary signature (`ppp::v2::PROTOCOL_PREFIX`): `\r\n\r\n\0\r\nQUIT\n`.
/// First byte is `0x0D`.
const V2_SIGNATURE: &[u8] = b"\r\n\r\n\x00\r\nQUIT\n";
/// v2 fixed header length: 12-byte signature + version/command +
/// family/protocol + 2-byte payload length.
const V2_FIXED_HEADER_LEN: usize = 16;
/// Upper bound on the v2 address+TLV payload we will read. The spec
/// field is a `u16` (≤ 65 535); we cap well under that — a TCP6
/// address block is 36 bytes and we do not consume TLVs (design §10
/// decision 7), so this is generous headroom, not a functional limit.
const V2_MAX_PAYLOAD: usize = 1024;
/// v1 text header maximum line length, including the trailing `\r\n`
/// (PROXY-protocol spec §2.1).
const V1_MAX_LINE: usize = 107;

/// Deadline for the entire pre-TLS PROXY read. A peer that sends a
/// partial header (or nothing) past this is closed — no slowloris on
/// the raw socket. Design §3.1.
pub const PRE_TLS_READ_DEADLINE: Duration = Duration::from_secs(5);

/// Protocol version a header was parsed as (for logging / metrics).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyVersion {
    V1,
    V2,
}

/// The PROXY command. v2 distinguishes `Proxy` (carries a client
/// address) from `Local` (an LB health-check with no asserted address);
/// v1 is always `Proxy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyCommand {
    Proxy,
    Local,
}

/// A successfully parsed PROXY header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProxyHeader {
    /// The asserted client socket address. `None` when no usable TCP
    /// address is asserted: v2 `LOCAL`, `UNSPEC` family, or `UNIX`
    /// family — in those cases the real transport peer is used (§3.6).
    pub source: Option<SocketAddr>,
    pub command: ProxyCommand,
    pub version: ProxyVersion,
}

/// Outcome of attempting to read a PROXY header. Maps 1:1 to the
/// failure-mode table (design §3.6); the accept loop decides what each
/// outcome means (P2: trust + close policy). In P1 it is logged only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyParse {
    /// A valid header was parsed (may carry no `source` for LOCAL /
    /// UNSPEC / UNIX — the caller then keeps the real transport peer).
    Parsed(ProxyHeader),
    /// `optional` mode and no signature present → treat as a direct
    /// client. **Nothing was consumed from the stream.**
    Absent,
    /// `strict` mode and no signature present → close (fail-closed).
    /// Nothing was consumed.
    MissingStrict,
    /// Malformed / truncated / bad-signature header → close. The stream
    /// is partially consumed and must not fall through to TLS.
    Malformed,
    /// Header payload exceeded the cap → close.
    Oversize,
    /// Pre-TLS read deadline exceeded → close.
    Timeout,
    /// Peer closed before a header arrived → close.
    Eof,
}

impl ProxyParse {
    /// Whether this outcome should proceed to the TLS handshake under
    /// the **final (P2) policy**: only a clean parse or an absent header
    /// in `optional` mode. `strict`-missing and every error close.
    pub fn stream_is_clean(self) -> bool {
        matches!(self, ProxyParse::Parsed(_) | ProxyParse::Absent)
    }

    /// Whether the stream was left partially consumed / unusable and so
    /// cannot proceed to TLS even in the P1 observe-only path. A
    /// `MissingStrict` consumed nothing (the strict-close decision is
    /// deferred to P2), so it is NOT corruption.
    pub fn is_stream_corrupted(self) -> bool {
        matches!(
            self,
            ProxyParse::Malformed | ProxyParse::Oversize | ProxyParse::Timeout | ProxyParse::Eof
        )
    }

    /// Short stable label for logs / the P3 metrics counter.
    pub fn label(self) -> &'static str {
        match self {
            ProxyParse::Parsed(h) => match h.command {
                ProxyCommand::Local => "local_command",
                ProxyCommand::Proxy => "parsed",
            },
            ProxyParse::Absent => "absent_optional",
            ProxyParse::MissingStrict => "missing_strict",
            ProxyParse::Malformed => "malformed",
            ProxyParse::Oversize => "oversize",
            ProxyParse::Timeout => "read_timeout",
            ProxyParse::Eof => "eof",
        }
    }
}

/// Read (and consume) a PROXY-protocol header from `stream`, if one is
/// present, honouring `mode`. Deadline-bounded by
/// [`PRE_TLS_READ_DEADLINE`]. Never reads past the end of the header,
/// so `stream` is left positioned at the first ClientHello byte on a
/// successful parse. See the module docs for the read discipline.
pub async fn read_proxy_header(stream: &mut TcpStream, mode: ProxyProtocolModeRef) -> ProxyParse {
    match tokio::time::timeout(PRE_TLS_READ_DEADLINE, read_inner(stream, mode)).await {
        Ok(outcome) => outcome,
        Err(_elapsed) => ProxyParse::Timeout,
    }
}

/// `mode` is taken as a small copy enum local to the read path so this
/// module does not depend on `aegis-core`'s config types directly; the
/// accept loop maps `config::ProxyProtocolMode` → this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyProtocolModeRef {
    Strict,
    Optional,
}

async fn read_inner(stream: &mut TcpStream, mode: ProxyProtocolModeRef) -> ProxyParse {
    // Step 1 — peek a single byte to sniff the signature without
    // consuming. A direct TLS client (first byte 0x16) is detected here
    // and never has its ClientHello touched.
    let mut probe = [0u8; 1];
    match stream.peek(&mut probe).await {
        Ok(0) => return ProxyParse::Eof,
        Ok(_) => {}
        Err(_) => return ProxyParse::Eof,
    }

    match probe[0] {
        // v2 binary signature begins with carriage-return.
        0x0D => read_v2(stream).await,
        // v1 text header begins with 'P' of "PROXY ".
        b'P' => read_v1(stream).await,
        // Anything else is not a PROXY header. In `optional` we fall
        // through to TLS untouched; in `strict` every connection must
        // carry one, so this is a fail-closed miss.
        _ => match mode {
            ProxyProtocolModeRef::Optional => ProxyParse::Absent,
            ProxyProtocolModeRef::Strict => ProxyParse::MissingStrict,
        },
    }
}

/// Read a v2 binary header: fixed 16 bytes, then exactly the declared
/// payload length. Every byte read here belongs to the header.
async fn read_v2(stream: &mut TcpStream) -> ProxyParse {
    let mut buf = vec![0u8; V2_FIXED_HEADER_LEN];
    if stream.read_exact(&mut buf).await.is_err() {
        return ProxyParse::Malformed;
    }
    if buf[..V2_SIGNATURE.len()] != *V2_SIGNATURE {
        return ProxyParse::Malformed;
    }
    let payload_len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    if payload_len > V2_MAX_PAYLOAD {
        return ProxyParse::Oversize;
    }
    if payload_len > 0 {
        let mut rest = vec![0u8; payload_len];
        if stream.read_exact(&mut rest).await.is_err() {
            return ProxyParse::Malformed;
        }
        buf.extend_from_slice(&rest);
    }

    match ppp::v2::Header::try_from(buf.as_slice()) {
        Ok(header) => ProxyParse::Parsed(from_v2(&header)),
        Err(_) => ProxyParse::Malformed,
    }
}

/// Read a v1 text header up to the first `\r\n`, capped at 107 bytes.
async fn read_v1(stream: &mut TcpStream) -> ProxyParse {
    let mut buf = Vec::with_capacity(V1_MAX_LINE);
    let mut byte = [0u8; 1];
    loop {
        if stream.read_exact(&mut byte).await.is_err() {
            return ProxyParse::Malformed;
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n") {
            break;
        }
        if buf.len() >= V1_MAX_LINE {
            // No terminator within the spec cap → malformed.
            return ProxyParse::Malformed;
        }
    }

    match ppp::v1::Header::try_from(buf.as_slice()) {
        Ok(header) => ProxyParse::Parsed(from_v1(&header)),
        Err(_) => ProxyParse::Malformed,
    }
}

/// Project a parsed `ppp` v2 header onto our minimal [`ProxyHeader`].
/// `LOCAL` (LB health check) and non-IP families assert no client
/// address → `source: None` (the caller keeps the real transport peer).
fn from_v2(header: &ppp::v2::Header<'_>) -> ProxyHeader {
    let command = match header.command {
        ppp::v2::Command::Proxy => ProxyCommand::Proxy,
        ppp::v2::Command::Local => ProxyCommand::Local,
    };
    let source = match (command, header.addresses) {
        (ProxyCommand::Local, _) => None,
        (ProxyCommand::Proxy, ppp::v2::Addresses::IPv4(a)) => {
            Some(SocketAddr::new(IpAddr::V4(a.source_address), a.source_port))
        }
        (ProxyCommand::Proxy, ppp::v2::Addresses::IPv6(a)) => {
            Some(SocketAddr::new(IpAddr::V6(a.source_address), a.source_port))
        }
        (ProxyCommand::Proxy, ppp::v2::Addresses::Unspecified)
        | (ProxyCommand::Proxy, ppp::v2::Addresses::Unix(_)) => None,
    };
    ProxyHeader {
        source,
        command,
        version: ProxyVersion::V2,
    }
}

/// Project a parsed `ppp` v1 header. v1 has no LOCAL command; `UNKNOWN`
/// asserts no address → `source: None`.
fn from_v1(header: &ppp::v1::Header<'_>) -> ProxyHeader {
    let source = match header.addresses {
        ppp::v1::Addresses::Tcp4(a) => {
            Some(SocketAddr::new(IpAddr::V4(a.source_address), a.source_port))
        }
        ppp::v1::Addresses::Tcp6(a) => {
            Some(SocketAddr::new(IpAddr::V6(a.source_address), a.source_port))
        }
        ppp::v1::Addresses::Unknown => None,
    };
    ProxyHeader {
        source,
        command: ProxyCommand::Proxy,
        version: ProxyVersion::V1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    /// Marker bytes standing in for the TLS ClientHello that follows a
    /// PROXY header on the wire. We assert these survive intact — i.e.
    /// the reader consumed exactly the header and not one byte more.
    const CLIENT_HELLO_MARKER: &[u8] = b"\x16\x03\x01CLIENTHELLO-BYTES";

    /// Spawn a loopback pair; the writer task sends `prefix` (the PROXY
    /// header, or nothing) immediately followed by the ClientHello
    /// marker. Returns the server-side accepted stream for the reader.
    async fn wire_with(prefix: Vec<u8>) -> TcpStream {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.unwrap();
            if !prefix.is_empty() {
                client.write_all(&prefix).await.unwrap();
            }
            client.write_all(CLIENT_HELLO_MARKER).await.unwrap();
            client.flush().await.unwrap();
            // Hold the connection open so the server can read.
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
        let (server, _peer) = listener.accept().await.unwrap();
        server
    }

    /// Build a valid v2 IPv4 PROXY header via `ppp`'s writer.
    fn v2_ipv4_header(src: Ipv4Addr, src_port: u16) -> Vec<u8> {
        use ppp::v2::{Builder, Command, Protocol, Version};
        let addrs = (
            SocketAddr::new(IpAddr::V4(src), src_port),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443),
        );
        Builder::with_addresses(Version::Two | Command::Proxy, Protocol::Stream, addrs)
            .build()
            .unwrap()
    }

    fn v2_ipv6_header(src: Ipv6Addr, src_port: u16) -> Vec<u8> {
        use ppp::v2::{Builder, Command, Protocol, Version};
        let dst = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let addrs = (
            SocketAddr::new(IpAddr::V6(src), src_port),
            SocketAddr::new(IpAddr::V6(dst), 443),
        );
        Builder::with_addresses(Version::Two | Command::Proxy, Protocol::Stream, addrs)
            .build()
            .unwrap()
    }

    /// v2 LOCAL command (LB health check) — no asserted address.
    fn v2_local_header() -> Vec<u8> {
        use ppp::v2::{AddressFamily, Builder, Command, Protocol, Version};
        Builder::new(
            Version::Two | Command::Local,
            AddressFamily::Unspecified | Protocol::Unspecified,
        )
        .build()
        .unwrap()
    }

    /// Drain whatever the reader left and assert it equals the marker —
    /// proves no ClientHello byte was swallowed.
    async fn assert_clienthello_intact(stream: &mut TcpStream) {
        let mut rest = vec![0u8; CLIENT_HELLO_MARKER.len()];
        stream.read_exact(&mut rest).await.unwrap();
        assert_eq!(
            rest, CLIENT_HELLO_MARKER,
            "reader over-read into the ClientHello"
        );
    }

    #[tokio::test]
    async fn parses_v1_tcp4_and_leaves_clienthello() {
        let mut stream = wire_with(b"PROXY TCP4 203.0.113.7 10.0.0.1 56324 443\r\n".to_vec()).await;
        let out = read_proxy_header(&mut stream, ProxyProtocolModeRef::Strict).await;
        let ProxyParse::Parsed(h) = out else {
            panic!("expected Parsed, got {out:?}");
        };
        assert_eq!(h.version, ProxyVersion::V1);
        assert_eq!(
            h.source,
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
                56324
            ))
        );
        assert_clienthello_intact(&mut stream).await;
    }

    #[tokio::test]
    async fn parses_v2_ipv4_and_leaves_clienthello() {
        let header = v2_ipv4_header(Ipv4Addr::new(198, 51, 100, 23), 41020);
        let mut stream = wire_with(header).await;
        let out = read_proxy_header(&mut stream, ProxyProtocolModeRef::Strict).await;
        let ProxyParse::Parsed(h) = out else {
            panic!("expected Parsed, got {out:?}");
        };
        assert_eq!(h.version, ProxyVersion::V2);
        assert_eq!(h.command, ProxyCommand::Proxy);
        assert_eq!(
            h.source,
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 23)),
                41020
            ))
        );
        assert_clienthello_intact(&mut stream).await;
    }

    #[tokio::test]
    async fn parses_v2_ipv6() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x7);
        let header = v2_ipv6_header(src, 51000);
        let mut stream = wire_with(header).await;
        let out = read_proxy_header(&mut stream, ProxyProtocolModeRef::Strict).await;
        let ProxyParse::Parsed(h) = out else {
            panic!("expected Parsed, got {out:?}");
        };
        assert_eq!(h.source, Some(SocketAddr::new(IpAddr::V6(src), 51000)));
        assert_clienthello_intact(&mut stream).await;
    }

    #[tokio::test]
    async fn v2_local_asserts_no_source() {
        let mut stream = wire_with(v2_local_header()).await;
        let out = read_proxy_header(&mut stream, ProxyProtocolModeRef::Strict).await;
        let ProxyParse::Parsed(h) = out else {
            panic!("expected Parsed, got {out:?}");
        };
        assert_eq!(h.command, ProxyCommand::Local);
        assert_eq!(h.source, None, "LOCAL command must not assert a client");
        assert_eq!(out.label(), "local_command");
        assert_clienthello_intact(&mut stream).await;
    }

    #[tokio::test]
    async fn optional_mode_absent_consumes_nothing() {
        // No PROXY header — the stream is just the ClientHello marker
        // (first byte 0x16, neither signature).
        let mut stream = wire_with(Vec::new()).await;
        let out = read_proxy_header(&mut stream, ProxyProtocolModeRef::Optional).await;
        assert_eq!(out, ProxyParse::Absent);
        assert!(out.stream_is_clean());
        assert_clienthello_intact(&mut stream).await;
    }

    #[tokio::test]
    async fn strict_mode_missing_header() {
        let mut stream = wire_with(Vec::new()).await;
        let out = read_proxy_header(&mut stream, ProxyProtocolModeRef::Strict).await;
        assert_eq!(out, ProxyParse::MissingStrict);
        assert!(!out.stream_is_clean());
    }

    #[tokio::test]
    async fn malformed_v1_no_crlf_within_cap() {
        // Starts with 'P' (commits to v1) but never sends a CRLF.
        let junk = vec![b'P'; V1_MAX_LINE + 8];
        let mut stream = wire_with(junk).await;
        let out = read_proxy_header(&mut stream, ProxyProtocolModeRef::Strict).await;
        assert_eq!(out, ProxyParse::Malformed);
    }

    #[tokio::test]
    async fn malformed_v2_bad_signature() {
        // First byte 0x0D commits to v2, but the rest is not the sig.
        let mut bytes = vec![0x0D; V2_FIXED_HEADER_LEN];
        bytes[1] = 0xFF;
        let mut stream = wire_with(bytes).await;
        let out = read_proxy_header(&mut stream, ProxyProtocolModeRef::Strict).await;
        assert_eq!(out, ProxyParse::Malformed);
    }

    #[tokio::test]
    async fn oversize_v2_payload_rejected() {
        // Valid signature, but a declared payload length beyond the cap.
        let mut bytes = V2_SIGNATURE.to_vec();
        bytes.push(0x21); // version 2 | PROXY
        bytes.push(0x11); // AF_INET | STREAM
        let big = (V2_MAX_PAYLOAD as u16 + 1).to_be_bytes();
        bytes.extend_from_slice(&big);
        let mut stream = wire_with(bytes).await;
        let out = read_proxy_header(&mut stream, ProxyProtocolModeRef::Strict).await;
        assert_eq!(out, ProxyParse::Oversize);
    }

    #[tokio::test]
    async fn label_matches_outcome() {
        assert_eq!(ProxyParse::Absent.label(), "absent_optional");
        assert_eq!(ProxyParse::Malformed.label(), "malformed");
        assert_eq!(ProxyParse::Timeout.label(), "read_timeout");
    }
}
