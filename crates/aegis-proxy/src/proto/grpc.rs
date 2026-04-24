/// Returns `true` if the request carries a gRPC content-type.
pub fn is_grpc<B>(req: &hyper::Request<B>) -> bool {
    req.headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.starts_with("application/grpc")
        })
        .unwrap_or(false)
}

/// A streaming body wrapper that transparently forwards data frames and
/// trailers from an `Incoming` body.  This is the key to gRPC proxy support:
/// we never buffer the full body, and trailers (including `grpc-status`)
/// are forwarded as-is.
pub struct StreamingBody {
    inner: hyper::body::Incoming,
}

impl StreamingBody {
    pub fn new(inner: hyper::body::Incoming) -> Self {
        Self { inner }
    }
}

impl hyper::body::Body for StreamingBody {
    type Data = bytes::Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let inner = unsafe { self.map_unchecked_mut(|s| &mut s.inner) };
        inner.poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::Full;

    #[test]
    fn detects_grpc_content_type() {
        let req = hyper::Request::builder()
            .header("content-type", "application/grpc")
            .body(Full::<Bytes>::default())
            .unwrap();
        assert!(is_grpc(&req));
    }

    #[test]
    fn detects_grpc_proto_content_type() {
        let req = hyper::Request::builder()
            .header("content-type", "application/grpc+proto")
            .body(Full::<Bytes>::default())
            .unwrap();
        assert!(is_grpc(&req));
    }

    #[test]
    fn rejects_non_grpc() {
        let req = hyper::Request::builder()
            .header("content-type", "application/json")
            .body(Full::<Bytes>::default())
            .unwrap();
        assert!(!is_grpc(&req));
    }

    #[test]
    fn missing_content_type_not_grpc() {
        let req = hyper::Request::builder()
            .body(Full::<Bytes>::default())
            .unwrap();
        assert!(!is_grpc(&req));
    }

    /// End-to-end test: mock gRPC backend that sends trailers, proxy
    /// forwards the full response including trailers.
    #[tokio::test]
    async fn grpc_trailers_preserved_through_proxy() {
        use http_body_util::BodyExt;
        use hyper::body::Frame;
        use std::convert::Infallible;
        use std::sync::Arc;

        // 1. Mock gRPC backend — returns body + trailers with grpc-status.
        let backend_tcp = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let backend_addr = backend_tcp.local_addr().unwrap();

        let backend = tokio::spawn(async move {
            let (stream, _) = backend_tcp.accept().await.unwrap();
            let io = hyper_util::rt::TokioIo::new(stream);

            hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(
                    io,
                    hyper::service::service_fn(|_req: hyper::Request<hyper::body::Incoming>| async {
                        // Build a streaming response with body + trailers.
                        let (tx, rx) = tokio::sync::mpsc::channel::<Result<hyper::body::Frame<Bytes>, Infallible>>(4);

                        tokio::spawn(async move {
                            // Send a data frame.
                            let _ = tx
                                .send(Ok(Frame::data(Bytes::from("\x00\x00\x00\x00\x05hello"))))
                                .await;
                            // Send trailers.
                            let mut trailers = hyper::HeaderMap::new();
                            trailers.insert("grpc-status", "0".parse().unwrap());
                            trailers.insert("grpc-message", "OK".parse().unwrap());
                            let _ = tx.send(Ok(Frame::trailers(trailers))).await;
                        });

                        let body = http_body_util::StreamBody::new(
                            tokio_stream::wrappers::ReceiverStream::new(rx),
                        );

                        Ok::<_, Infallible>(
                            hyper::Response::builder()
                                .status(200)
                                .header("content-type", "application/grpc")
                                .body(body)
                                .unwrap(),
                        )
                    }),
                )
                .await
                .ok();
        });

        // 2. Proxy: forward to backend over h2, stream body+trailers back.
        let proxy_tcp = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let proxy_addr = proxy_tcp.local_addr().unwrap();

        let proxy = tokio::spawn(async move {
            let (stream, _) = proxy_tcp.accept().await.unwrap();
            let io = hyper_util::rt::TokioIo::new(stream);

            hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(
                    io,
                    hyper::service::service_fn(move |_req: hyper::Request<hyper::body::Incoming>| {
                        let upstream_addr = backend_addr;
                        async move {
                            // Connect to upstream.
                            let upstream_tcp =
                                tokio::net::TcpStream::connect(upstream_addr).await.unwrap();
                            let io = hyper_util::rt::TokioIo::new(upstream_tcp);
                            let (mut sender, conn) = hyper::client::conn::http2::handshake(
                                hyper_util::rt::TokioExecutor::new(),
                                io,
                            )
                            .await
                            .unwrap();
                            tokio::spawn(conn);

                            let fwd_req = hyper::Request::builder()
                                .header("content-type", "application/grpc")
                                .body(http_body_util::Empty::<Bytes>::new())
                                .unwrap();
                            let resp = sender.send_request(fwd_req).await.unwrap();

                            // Stream body + trailers through StreamingBody.
                            let status = resp.status();
                            let headers = resp.headers().clone();
                            let streaming = StreamingBody::new(resp.into_body());

                            let mut builder = hyper::Response::builder().status(status);
                            for (k, v) in &headers {
                                builder = builder.header(k, v);
                            }
                            Ok::<_, Infallible>(builder.body(streaming).unwrap())
                        }
                    }),
                )
                .await
                .ok();
        });

        // 3. Client: h2 request, collect body + trailers.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let tcp = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let io = hyper_util::rt::TokioIo::new(tcp);
        let (mut sender, conn) = hyper::client::conn::http2::handshake(
            hyper_util::rt::TokioExecutor::new(),
            io,
        )
        .await
        .unwrap();
        tokio::spawn(conn);

        let req = hyper::Request::builder()
            .header("content-type", "application/grpc")
            .body(http_body_util::Empty::<Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), 200);

        // Collect all frames.
        let mut body = resp.into_body();
        let mut got_data = false;
        let mut got_trailers = false;
        let mut grpc_status = None;

        while let Some(frame) = body.frame().await {
            let frame = frame.unwrap();
            if frame.is_data() {
                got_data = true;
            }
            if frame.is_trailers() {
                got_trailers = true;
                let trailers = frame.trailers_ref().unwrap();
                grpc_status = trailers
                    .get("grpc-status")
                    .map(|v| v.to_str().unwrap().to_string());
            }
        }

        assert!(got_data, "expected data frames");
        assert!(got_trailers, "expected trailer frames");
        assert_eq!(grpc_status.as_deref(), Some("0"));

        backend.abort();
        proxy.abort();
    }
}
