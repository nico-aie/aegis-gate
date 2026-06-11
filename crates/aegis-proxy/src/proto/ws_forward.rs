//! WS-T2 — raw-TCP forwarder for WebSocket upgrade requests.
//!
//! ## Why a raw forwarder
//!
//! Hyper's pooled HTTP client (used by `forward.rs`) silently
//! drops the upgrade hook because a successful 101 takes the TCP
//! socket out of the keep-alive cycle forever — that violates
//! the connection-pool contract.  The plan in
//! `plans/websocket-bridge.md §2` walks through this in detail.
//!
//! This module bypasses hyper on the upstream side entirely:
//!
//! 1. open a raw `TcpStream` to the chosen upstream member
//! 2. re-serialize the request line + headers (+ optional body)
//!    and write the bytes
//! 3. read the response head until `\r\n\r\n`, parse status +
//!    headers
//! 4. return the parsed head plus the raw socket so the caller
//!    can `copy_bidirectional` it against the upgraded client
//!    after hyper resolves `OnUpgrade`.
//!
//! Byte-for-byte preservation of `Sec-WebSocket-Key` /
//! `Sec-WebSocket-Accept` / `Sec-WebSocket-Protocol` /
//! `Sec-WebSocket-Version` falls out naturally — no header
//! re-builder in the path.

use std::net::SocketAddr;
use std::time::Duration;

use http::HeaderMap;
use hyper::StatusCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Result of a single upstream upgrade-attempt.
#[derive(Debug)]
pub struct UpstreamHandshake {
    /// HTTP status the upstream returned. `101` is the happy
    /// path; anything else means the upstream rejected the
    /// upgrade and we proxy the response straight back.
    pub status: StatusCode,
    /// Header map parsed from the upstream's response head.
    /// Returned to the caller verbatim so the WAF doesn't
    /// reorder / drop the WebSocket negotiation headers.
    pub headers: HeaderMap,
    /// Body bytes that landed in the read buffer past the
    /// header terminator.  Empty for 101 (the 101 body is
    /// always empty by spec); for non-101 fallthrough the
    /// caller may receive part of the body here and need to
    /// drain the rest off [`socket`].
    pub leftover: Vec<u8>,
    /// Raw upstream socket. `Some` regardless of status — for
    /// 101 the caller bridges it against the upgraded client;
    /// for non-101 the caller drains + closes it.
    pub socket: TcpStream,
}

/// Maximum bytes we'll consume looking for the `\r\n\r\n` head
/// terminator. Anything past this is hostile / malformed and we
/// abort — keeps a runaway upstream from filling RAM.
const MAX_HEAD_BYTES: usize = 16 * 1024;

/// WS-T2 — open a raw connection to `upstream_addr`, write the
/// original request bytes, parse the response head.  Returns the
/// parsed head + the live socket so the data-plane handler can
/// bridge after `OnUpgrade` resolves.
///
/// `body` is forwarded verbatim after the headers; WebSocket
/// upgrade requests are typically body-less but we tolerate a
/// small payload to keep the contract symmetric with the
/// non-upgrade path.
pub async fn forward_websocket_upgrade(
    method: &http::Method,
    uri: &http::Uri,
    headers: &HeaderMap,
    body: &[u8],
    upstream_addr: SocketAddr,
    connect_timeout: Duration,
    // WS-MSG5 — when the route inspects frames, drop
    // `Sec-WebSocket-Extensions` from the forwarded handshake so the
    // upstream cannot negotiate `permessage-deflate`; the resulting
    // connection is uncompressed and therefore inspectable.
    strip_extensions: bool,
) -> std::io::Result<UpstreamHandshake> {
    let mut socket = tokio::time::timeout(
        connect_timeout,
        TcpStream::connect(upstream_addr),
    )
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "ws upstream connect timeout",
        )
    })??;

    // Re-serialize request line + headers.  The path-and-query
    // are forwarded as-is; if the operator wants host rewriting
    // they configure `forward.headers` per-route which we
    // currently don't apply in this code path (see plan
    // §"Out of scope" — header policy stays on the regular
    // forward path; upgrade requests use the verbatim shape).
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let mut head = Vec::with_capacity(512 + body.len());
    head.extend_from_slice(method.as_str().as_bytes());
    head.push(b' ');
    head.extend_from_slice(path_and_query.as_bytes());
    head.extend_from_slice(b" HTTP/1.1\r\n");
    for (name, value) in headers.iter() {
        if strip_extensions
            && name.as_str().eq_ignore_ascii_case("sec-websocket-extensions")
        {
            // Drop the whole extensions offer so no compression is
            // negotiated (fail-safe for inspectability).
            continue;
        }
        head.extend_from_slice(name.as_str().as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"\r\n");
    head.extend_from_slice(body);
    socket.write_all(&head).await?;

    let (status, headers, leftover) = read_response_head(&mut socket).await?;
    Ok(UpstreamHandshake {
        status,
        headers,
        leftover,
        socket,
    })
}

/// Read bytes from `socket` until `\r\n\r\n`, parse the response
/// status + headers, return the parsed head plus any bytes that
/// followed the terminator (already in our read buffer).
async fn read_response_head(
    socket: &mut TcpStream,
) -> std::io::Result<(StatusCode, HeaderMap, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = socket.read(&mut chunk).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "ws upstream closed before response head",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_HEAD_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ws upstream response head exceeded 16 KiB",
            ));
        }
        if let Some(pos) = find_head_terminator(&buf) {
            let head_bytes = &buf[..pos];
            let leftover = buf[pos + 4..].to_vec();
            let (status, headers) = parse_response_head(head_bytes)?;
            return Ok((status, headers, leftover));
        }
    }
}

fn find_head_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_response_head(
    bytes: &[u8],
) -> std::io::Result<(StatusCode, HeaderMap)> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ws upstream response head not UTF-8",
        )
    })?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ws upstream response missing status line",
        )
    })?;
    // status_line shape: "HTTP/1.1 101 Switching Protocols"
    let mut parts = status_line.split_whitespace();
    let _version = parts.next();
    let code = parts
        .next()
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("ws upstream status line malformed: {status_line:?}"),
            )
        })?;
    let status = StatusCode::from_u16(code).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("ws upstream status code invalid: {e}"),
        )
    })?;

    let mut headers = HeaderMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("ws upstream header line malformed: {line:?}"),
            )
        })?;
        let name = http::HeaderName::from_bytes(name.trim().as_bytes())
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("ws upstream header name invalid: {e}"),
                )
            })?;
        let value =
            http::HeaderValue::from_str(value.trim()).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("ws upstream header value invalid: {e}"),
                )
            })?;
        headers.append(name, value);
    }
    Ok((status, headers))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn forwards_request_and_parses_101_response() {
        // Stand up a fake upstream that returns 101 with a
        // canned WebSocket accept header.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await.unwrap();
            sock.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Upgrade: websocket\r\n\
                  Connection: Upgrade\r\n\
                  Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
                  \r\n",
            )
            .await
            .unwrap();
            // Send a frame after the handshake to verify the
            // socket is live for bridging.
            sock.write_all(b"frame-bytes").await.unwrap();
            // Hold the connection open briefly.
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            http::HeaderValue::from_static("example.test"),
        );
        headers.insert(
            "upgrade",
            http::HeaderValue::from_static("websocket"),
        );
        headers.insert(
            "connection",
            http::HeaderValue::from_static("Upgrade"),
        );
        headers.insert(
            "sec-websocket-key",
            http::HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        );
        headers.insert(
            "sec-websocket-version",
            http::HeaderValue::from_static("13"),
        );

        let mut result = forward_websocket_upgrade(
            &http::Method::GET,
            &"/chat".parse().unwrap(),
            &headers,
            b"",
            addr,
            Duration::from_secs(2),
            false,
        )
        .await
        .unwrap();

        assert_eq!(result.status, StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(
            result.headers.get("sec-websocket-accept").unwrap(),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        );
        // Socket is live — we can read the post-handshake frame
        // off it.  Leftover may or may not already contain those
        // bytes depending on whether they arrived in the same
        // read as the head terminator.
        let mut frame = result.leftover.clone();
        let mut read_buf = [0u8; 64];
        while frame.len() < b"frame-bytes".len() {
            let n = result.socket.read(&mut read_buf).await.unwrap();
            if n == 0 {
                break;
            }
            frame.extend_from_slice(&read_buf[..n]);
        }
        assert_eq!(&frame[..b"frame-bytes".len()], b"frame-bytes");
        server.await.unwrap();
    }

    // WS-MSG5 — with `strip_extensions`, the forwarded handshake must NOT
    // carry `Sec-WebSocket-Extensions`, so the upstream can't negotiate
    // permessage-deflate and the connection stays inspectable.
    #[tokio::test]
    async fn strips_sec_websocket_extensions_when_requested() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let n = sock.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            sock.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Upgrade: websocket\r\nConnection: Upgrade\r\n\
                  Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
            )
            .await
            .unwrap();
            String::from_utf8_lossy(&buf).to_string()
        });

        let mut headers = HeaderMap::new();
        headers.insert("host", http::HeaderValue::from_static("example.test"));
        headers.insert("upgrade", http::HeaderValue::from_static("websocket"));
        headers.insert("connection", http::HeaderValue::from_static("Upgrade"));
        headers.insert(
            "sec-websocket-key",
            http::HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        );
        headers.insert(
            "sec-websocket-version",
            http::HeaderValue::from_static("13"),
        );
        headers.insert(
            "sec-websocket-extensions",
            http::HeaderValue::from_static("permessage-deflate; client_max_window_bits"),
        );

        let _ = forward_websocket_upgrade(
            &http::Method::GET,
            &"/chat".parse().unwrap(),
            &headers,
            b"",
            addr,
            Duration::from_secs(2),
            true, // strip extensions
        )
        .await
        .unwrap();

        let received = server.await.unwrap().to_ascii_lowercase();
        assert!(
            !received.contains("sec-websocket-extensions"),
            "extensions header must be stripped; got:\n{received}"
        );
        assert!(received.contains("sec-websocket-key"));
    }

    #[tokio::test]
    async fn forwards_non_101_response_unchanged() {
        // Upstream returns 426 — we should pass it through
        // untouched.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await.unwrap();
            sock.write_all(
                b"HTTP/1.1 426 Upgrade Required\r\n\
                  Content-Type: text/plain\r\n\
                  Content-Length: 18\r\n\
                  \r\n\
                  upgrade-required\r\n",
            )
            .await
            .unwrap();
        });

        let mut headers = HeaderMap::new();
        headers.insert("host", http::HeaderValue::from_static("x.test"));
        headers.insert(
            "upgrade",
            http::HeaderValue::from_static("websocket"),
        );
        headers.insert(
            "connection",
            http::HeaderValue::from_static("Upgrade"),
        );

        let result = forward_websocket_upgrade(
            &http::Method::GET,
            &"/".parse().unwrap(),
            &headers,
            b"",
            addr,
            Duration::from_secs(2),
            false,
        )
        .await
        .unwrap();
        assert_eq!(result.status, StatusCode::UPGRADE_REQUIRED);
        assert_eq!(
            result.headers.get("content-type").unwrap(),
            "text/plain",
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn returns_timeout_when_upstream_unreachable() {
        // 192.0.2.1 is RFC 5737 TEST-NET-1 — guaranteed not to
        // route, so the connect call returns ETIMEDOUT or
        // EHOSTUNREACH. We use a very short timeout so this
        // doesn't drag.
        let upstream: SocketAddr = "192.0.2.1:80".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("host", http::HeaderValue::from_static("x.test"));
        let res = forward_websocket_upgrade(
            &http::Method::GET,
            &"/".parse().unwrap(),
            &headers,
            b"",
            upstream,
            Duration::from_millis(50),
            false,
        )
        .await;
        assert!(res.is_err(), "expected timeout / unreachable");
    }
}
