//! Real upstream HTTP/1.1 forwarding (B4-T3).
//!
//! Replaces the earlier stub that opened a TCP connection,
//! sent a hard-coded `GET /` with no body, and returned the
//! upstream's response — so the operator's actual method,
//! path, headers, and body never reached the upstream. This
//! module forwards the request faithfully:
//!
//! * Method, path + query, version preserved.
//! * Hop-by-hop headers stripped per RFC 7230 §6.1.
//! * `X-Forwarded-Host` recorded from the original `Host`
//!   header.
//! * `Host` header rewritten to the upstream member address
//!   so virtual-host upstreams resolve correctly.
//! * Body forwarded byte-for-byte (collected — the rest of
//!   the proxy is currently `Full<Bytes>`-shaped; streaming
//!   is a separate refactor).
//!
//! Pure helpers (`is_hop_by_hop_header`,
//! `build_upstream_headers`, `path_and_query`,
//! `replay_response_status_and_headers`) live here so the
//! framing edges are unit-tested without sockets.

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response};

use super::Member;

/// RFC 7230 §6.1 hop-by-hop headers + the few well-known
/// extensions that show up in practice. Compared
/// case-insensitively.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// True iff `name` is a hop-by-hop header that must not be
/// forwarded between proxy and upstream.
pub fn is_hop_by_hop_header(name: &str) -> bool {
    HOP_BY_HOP
        .iter()
        .any(|h| h.eq_ignore_ascii_case(name))
}

/// Path + optional `?query` from a URI, defaulting to `/` for
/// an empty path. Used as the request line we send upstream.
pub fn path_and_query(uri: &Uri) -> String {
    match uri.path_and_query() {
        Some(pq) if !pq.as_str().is_empty() => pq.as_str().to_string(),
        _ => {
            if uri.path().is_empty() {
                "/".to_string()
            } else {
                uri.path().to_string()
            }
        }
    }
}

/// Build the headers we send to the upstream:
///
/// * Drop every hop-by-hop header.
/// * Drop the original `Host` header (we replace it).
/// * Drop the `Connection` header's enumerated tokens
///   (already covered by the hop-by-hop list, but RFC also
///   says to drop anything *named* by Connection).
/// * Insert `X-Forwarded-Host` if the original Host was
///   present and `X-Forwarded-Host` wasn't already set by an
///   upstream proxy.
/// * Insert `Host: <upstream addr>`.
pub fn build_upstream_headers(
    original: &HeaderMap,
    upstream_host_header: &str,
) -> HeaderMap {
    let mut out = HeaderMap::with_capacity(original.len() + 2);
    let original_host = original
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Tokens listed in `Connection: ...` are also hop-by-hop
    // for *this* hop only. Collect them to filter below.
    let mut connection_listed: Vec<String> = Vec::new();
    if let Some(v) = original.get(http::header::CONNECTION).and_then(|v| v.to_str().ok()) {
        for tok in v.split(',') {
            let t = tok.trim();
            if !t.is_empty() {
                connection_listed.push(t.to_ascii_lowercase());
            }
        }
    }

    for (name, value) in original.iter() {
        let n = name.as_str();
        if is_hop_by_hop_header(n) {
            continue;
        }
        if connection_listed.iter().any(|c| c == n) {
            continue;
        }
        if n.eq_ignore_ascii_case("host") {
            // Replaced below.
            continue;
        }
        out.append(name.clone(), value.clone());
    }

    // Preserve the original Host as X-Forwarded-Host if not
    // already present (operators in front of us may have
    // set it).
    if let Some(orig) = original_host {
        let xfh = HeaderName::from_static("x-forwarded-host");
        if !out.contains_key(&xfh) {
            if let Ok(v) = HeaderValue::from_str(&orig) {
                out.insert(xfh, v);
            }
        }
    }

    // Rewrite Host to point at the upstream member.
    if let Ok(v) = HeaderValue::from_str(upstream_host_header) {
        out.insert(http::header::HOST, v);
    }

    out
}

/// Mirror status + headers from the upstream response back to
/// the client. Drops hop-by-hop on the *response* path too —
/// upstreams can also send `Connection: close` etc., which
/// would confuse the client connection.
pub fn replay_response_status_and_headers<B>(
    upstream: &Response<B>,
) -> Response<Full<Bytes>> {
    let status = upstream.status();
    let mut builder = Response::builder().status(status);
    if let Some(headers) = builder.headers_mut() {
        let mut connection_listed: Vec<String> = Vec::new();
        if let Some(v) = upstream
            .headers()
            .get(http::header::CONNECTION)
            .and_then(|v| v.to_str().ok())
        {
            for tok in v.split(',') {
                let t = tok.trim();
                if !t.is_empty() {
                    connection_listed.push(t.to_ascii_lowercase());
                }
            }
        }
        for (name, value) in upstream.headers().iter() {
            let n = name.as_str();
            if is_hop_by_hop_header(n) {
                continue;
            }
            if connection_listed.iter().any(|c| c == n) {
                continue;
            }
            headers.append(name.clone(), value.clone());
        }
    }
    builder.body(Full::default()).unwrap()
}

/// Forward a request to `member` and return the upstream's
/// response. Body is collected (not streamed) — matches the
/// rest of the proxy's `Full<Bytes>` shape.
pub async fn forward(
    member: &Member,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response<Full<Bytes>>, ForwardError> {
    let stream = tokio::net::TcpStream::connect(member.addr)
        .await
        .map_err(|e| ForwardError::Connect(e.to_string()))?;
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| ForwardError::Handshake(e.to_string()))?;
    tokio::spawn(async move {
        // Drive the connection. If it errors there's nothing
        // useful to log here — the request future will see
        // the failure.
        let _ = conn.await;
    });

    let upstream_host_header = member.addr.to_string();
    let pq = path_and_query(&uri);
    let fwd_headers = build_upstream_headers(&headers, &upstream_host_header);

    let mut builder = Request::builder().method(method).uri(pq);
    if let Some(h) = builder.headers_mut() {
        *h = fwd_headers;
    }
    let fwd_req = builder
        .body(Full::new(body))
        .map_err(|e| ForwardError::BadRequest(e.to_string()))?;

    let resp = sender
        .send_request(fwd_req)
        .await
        .map_err(|e| ForwardError::Send(e.to_string()))?;

    let status = resp.status();
    let resp_headers = resp.headers().clone();
    let body_bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| ForwardError::ReadBody(e.to_string()))?
        .to_bytes();

    // Use replay to filter hop-by-hop on the response side.
    let mut filtered: Response<Full<Bytes>> = replay_response_status_and_headers(
        &Response::builder().status(status).body(()).unwrap(),
    );
    if let Some(out_headers) = Some(filtered.headers_mut()) {
        out_headers.clear();
        let mut connection_listed: Vec<String> = Vec::new();
        if let Some(v) = resp_headers
            .get(http::header::CONNECTION)
            .and_then(|v| v.to_str().ok())
        {
            for tok in v.split(',') {
                let t = tok.trim();
                if !t.is_empty() {
                    connection_listed.push(t.to_ascii_lowercase());
                }
            }
        }
        for (name, value) in resp_headers.iter() {
            let n = name.as_str();
            if is_hop_by_hop_header(n) {
                continue;
            }
            if connection_listed.iter().any(|c| c == n) {
                continue;
            }
            out_headers.append(name.clone(), value.clone());
        }
    }
    *filtered.body_mut() = Full::new(body_bytes);
    Ok(filtered)
}

/// Errors raised by [`forward`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardError {
    Connect(String),
    Handshake(String),
    BadRequest(String),
    Send(String),
    ReadBody(String),
}

impl std::fmt::Display for ForwardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForwardError::Connect(m) => write!(f, "upstream connect failed: {m}"),
            ForwardError::Handshake(m) => write!(f, "upstream handshake failed: {m}"),
            ForwardError::BadRequest(m) => write!(f, "upstream request build failed: {m}"),
            ForwardError::Send(m) => write!(f, "upstream send failed: {m}"),
            ForwardError::ReadBody(m) => write!(f, "upstream body read failed: {m}"),
        }
    }
}

impl std::error::Error for ForwardError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn hm(items: &[(&str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in items {
            m.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        m
    }

    // ---- is_hop_by_hop_header ----

    #[test]
    fn hop_by_hop_recognised_case_insensitively() {
        for h in &[
            "Connection",
            "CONNECTION",
            "Keep-Alive",
            "proxy-authenticate",
            "proxy-authorization",
            "TE",
            "Trailer",
            "transfer-encoding",
            "Upgrade",
        ] {
            assert!(is_hop_by_hop_header(h), "should be hop-by-hop: {h}");
        }
    }

    #[test]
    fn end_to_end_headers_not_hop_by_hop() {
        for h in &[
            "host",
            "user-agent",
            "accept",
            "content-type",
            "content-length",
            "x-forwarded-for",
            "authorization",
        ] {
            assert!(!is_hop_by_hop_header(h), "should NOT be hop-by-hop: {h}");
        }
    }

    // ---- path_and_query ----

    #[test]
    fn path_and_query_includes_query() {
        let u: Uri = "/api/users?id=42&debug=true".parse().unwrap();
        assert_eq!(path_and_query(&u), "/api/users?id=42&debug=true");
    }

    #[test]
    fn path_and_query_no_query() {
        let u: Uri = "/healthz".parse().unwrap();
        assert_eq!(path_and_query(&u), "/healthz");
    }

    #[test]
    fn path_and_query_empty_path_defaults_to_slash() {
        // hyper Uri::default() has empty path.
        let u: Uri = Uri::default();
        assert_eq!(path_and_query(&u), "/");
    }

    // ---- build_upstream_headers ----

    #[test]
    fn build_upstream_strips_hop_by_hop() {
        let original = hm(&[
            ("host", "api.example.com"),
            ("connection", "keep-alive"),
            ("keep-alive", "timeout=5"),
            ("transfer-encoding", "chunked"),
            ("user-agent", "curl/8"),
        ]);
        let out = build_upstream_headers(&original, "10.0.0.1:8080");
        assert!(out.contains_key("user-agent"));
        assert!(!out.contains_key("connection"));
        assert!(!out.contains_key("keep-alive"));
        assert!(!out.contains_key("transfer-encoding"));
    }

    #[test]
    fn build_upstream_replaces_host_header() {
        let original = hm(&[("host", "api.example.com")]);
        let out = build_upstream_headers(&original, "10.0.0.1:8080");
        assert_eq!(out.get("host").unwrap().to_str().unwrap(), "10.0.0.1:8080");
    }

    #[test]
    fn build_upstream_records_x_forwarded_host() {
        let original = hm(&[("host", "api.example.com")]);
        let out = build_upstream_headers(&original, "10.0.0.1:8080");
        assert_eq!(
            out.get("x-forwarded-host").unwrap().to_str().unwrap(),
            "api.example.com"
        );
    }

    #[test]
    fn build_upstream_preserves_existing_x_forwarded_host() {
        let original = hm(&[
            ("host", "edge.example.com"),
            ("x-forwarded-host", "client.example.com"),
        ]);
        let out = build_upstream_headers(&original, "10.0.0.1:8080");
        // We do NOT clobber an upstream-set XFH.
        assert_eq!(
            out.get("x-forwarded-host").unwrap().to_str().unwrap(),
            "client.example.com"
        );
    }

    #[test]
    fn build_upstream_drops_connection_listed_tokens() {
        let original = hm(&[
            ("host", "api.example.com"),
            ("connection", "close, x-custom-end-to-end"),
            ("x-custom-end-to-end", "secret"),
            ("user-agent", "curl/8"),
        ]);
        let out = build_upstream_headers(&original, "10.0.0.1:8080");
        // x-custom-end-to-end was named in Connection, must drop.
        assert!(!out.contains_key("x-custom-end-to-end"));
        // user-agent unaffected.
        assert!(out.contains_key("user-agent"));
    }

    #[test]
    fn build_upstream_passes_through_normal_headers() {
        let original = hm(&[
            ("host", "api.example.com"),
            ("authorization", "Bearer abc"),
            ("user-agent", "curl/8"),
            ("accept", "application/json"),
        ]);
        let out = build_upstream_headers(&original, "10.0.0.1:8080");
        assert_eq!(out.get("authorization").unwrap().to_str().unwrap(), "Bearer abc");
        assert_eq!(out.get("accept").unwrap().to_str().unwrap(), "application/json");
    }

    // ---- replay_response_status_and_headers ----

    #[test]
    fn replay_drops_hop_by_hop_from_response() {
        let upstream: Response<()> = Response::builder()
            .status(200)
            .header("connection", "close")
            .header("transfer-encoding", "chunked")
            .header("x-app", "v1")
            .body(())
            .unwrap();
        let out = replay_response_status_and_headers(&upstream);
        assert_eq!(out.status(), http::StatusCode::OK);
        assert!(out.headers().contains_key("x-app"));
        assert!(!out.headers().contains_key("connection"));
        assert!(!out.headers().contains_key("transfer-encoding"));
    }

    #[test]
    fn replay_preserves_status_code() {
        let upstream: Response<()> = Response::builder().status(418).body(()).unwrap();
        let out = replay_response_status_and_headers(&upstream);
        assert_eq!(out.status(), 418);
    }

    // ---- ForwardError display ----

    #[test]
    fn forward_error_display_messages() {
        assert!(ForwardError::Connect("x".into()).to_string().contains("connect"));
        assert!(ForwardError::Handshake("x".into()).to_string().contains("handshake"));
        assert!(ForwardError::BadRequest("x".into()).to_string().contains("request"));
        assert!(ForwardError::Send("x".into()).to_string().contains("send"));
        assert!(ForwardError::ReadBody("x".into()).to_string().contains("body"));
    }
}
