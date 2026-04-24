use std::net::SocketAddr;

/// Returns `true` if the request contains `Upgrade: websocket` + `Connection: Upgrade`.
pub fn is_websocket_upgrade<B>(req: &hyper::Request<B>) -> bool {
    let upgrade = req
        .headers()
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    let connection = req
        .headers()
        .get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false);

    upgrade && connection
}

/// After the HTTP 101 handshake, bridge the upgraded client I/O with a new TCP
/// connection to `upstream_addr`.  Uses `tokio::io::copy_bidirectional` for
/// zero-copy passthrough.
pub async fn bridge_upgrade(
    upgraded: hyper::upgrade::Upgraded,
    upstream_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut upstream = tokio::net::TcpStream::connect(upstream_addr).await?;

    // `Upgraded` implements `tokio::io::{AsyncRead, AsyncWrite}` via TokioIo.
    let mut client = hyper_util::rt::TokioIo::new(upgraded);

    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::Full;

    #[test]
    fn detects_websocket_upgrade() {
        let req = hyper::Request::builder()
            .header("upgrade", "websocket")
            .header("connection", "Upgrade")
            .body(Full::<Bytes>::default())
            .unwrap();
        assert!(is_websocket_upgrade(&req));
    }

    #[test]
    fn rejects_non_websocket() {
        let req = hyper::Request::builder()
            .header("upgrade", "h2c")
            .header("connection", "Upgrade")
            .body(Full::<Bytes>::default())
            .unwrap();
        assert!(!is_websocket_upgrade(&req));
    }

    #[test]
    fn rejects_missing_connection_upgrade() {
        let req = hyper::Request::builder()
            .header("upgrade", "websocket")
            .body(Full::<Bytes>::default())
            .unwrap();
        assert!(!is_websocket_upgrade(&req));
    }

    #[test]
    fn detects_multi_value_connection() {
        let req = hyper::Request::builder()
            .header("upgrade", "websocket")
            .header("connection", "keep-alive, Upgrade")
            .body(Full::<Bytes>::default())
            .unwrap();
        assert!(is_websocket_upgrade(&req));
    }

    #[test]
    fn case_insensitive_headers() {
        let req = hyper::Request::builder()
            .header("Upgrade", "WebSocket")
            .header("Connection", "UPGRADE")
            .body(Full::<Bytes>::default())
            .unwrap();
        assert!(is_websocket_upgrade(&req));
    }

    /// End-to-end test: raw TCP tunnel proxy that lets the WS handshake
    /// pass through to the backend, then bridges frames bidirectionally.
    #[tokio::test]
    async fn websocket_echo_through_tunnel() {
        use futures::SinkExt;
        use tokio_tungstenite::tungstenite::Message;

        // 1. Start a WebSocket echo backend.
        let backend_tcp = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let backend_addr = backend_tcp.local_addr().unwrap();

        let backend = tokio::spawn(async move {
            let (stream, _) = backend_tcp.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut tx, mut rx) = futures::StreamExt::split(ws);
            while let Some(Ok(msg)) = futures::StreamExt::next(&mut rx).await {
                if msg.is_text() || msg.is_binary() {
                    tx.send(msg).await.unwrap();
                }
            }
        });

        // 2. Start a raw TCP tunnel proxy — bridges bytes end-to-end.
        let proxy_tcp = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let proxy_addr = proxy_tcp.local_addr().unwrap();

        let proxy = tokio::spawn(async move {
            let (mut client, _) = proxy_tcp.accept().await.unwrap();
            let mut upstream = tokio::net::TcpStream::connect(backend_addr)
                .await
                .unwrap();
            tokio::io::copy_bidirectional(&mut client, &mut upstream)
                .await
                .ok();
        });

        // 3. Client: connect WS through the tunnel proxy.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let url = format!("ws://127.0.0.1:{}", proxy_addr.port());
        let (ws, _resp) =
            tokio_tungstenite::connect_async(&url).await.unwrap();
        let (mut tx, mut rx) = futures::StreamExt::split(ws);

        tx.send(Message::Text("hello".into())).await.unwrap();
        let echo = futures::StreamExt::next(&mut rx).await.unwrap().unwrap();
        assert_eq!(echo.into_text().unwrap(), "hello");

        tx.send(Message::Text("world".into())).await.unwrap();
        let echo2 = futures::StreamExt::next(&mut rx).await.unwrap().unwrap();
        assert_eq!(echo2.into_text().unwrap(), "world");

        drop(tx);
        backend.abort();
        proxy.abort();
    }
}
