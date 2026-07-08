//! Real upstream HTTP/1.1 forwarding (B4-T3 + UP-T1 pooling).
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
//! UP-T1 — connection pooling. Replaces per-request
//! `TcpStream::connect + http1::handshake` with a per-pool
//! [`hyper_util::client::legacy::Client`] that keeps idle
//! HTTP/1.1 keep-alive connections around. The pool is keyed
//! on the `(host, port)` of each [`Member`], so multiple
//! pools sharing a target reuse the same connection cache.
//! Pre-UP-T1 behaviour (one TCP per request) is preserved by
//! `ConnectionPoolConfig::max_idle_per_host = 0`.
//!
//! Pure helpers (`is_hop_by_hop_header`,
//! `build_upstream_headers`, `path_and_query`,
//! `replay_response_status_and_headers`) live here so the
//! framing edges are unit-tested without sockets.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;

use aegis_core::config::ConnectionPoolConfig;

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
        if n.eq_ignore_ascii_case("accept-encoding") {
            // Response-filter gzip fix (2026-07-07): forced to `identity`
            // below. A compressed upstream body defeats `on_body_frame`
            // (UTF-8 decode fails → the DLP/redact rungs pass the raw
            // compressed secrets through). Dropping the client's value
            // here + pinning identity makes the origin answer in the
            // clear so the response filter can actually scrub it.
            continue;
        }
        out.append(name.clone(), value.clone());
    }

    // Force an uncompressed upstream response so the response-filter
    // pipeline can decode + scrub the body. See the copy-loop note.
    out.insert(
        http::header::ACCEPT_ENCODING,
        HeaderValue::from_static("identity"),
    );

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

/// Pooled HTTP/1.1 client built from a [`ConnectionPoolConfig`].
///
/// `Client` is `Clone` (internally `Arc`-shared); cheap to share
/// across hot-path tasks. We hold one per distinct upstream
/// configuration (different `max_idle_per_host` / `idle_timeout`
/// / `keep_alive` settings) — the cache below keys on the config
/// signature, not the member address, so two pools that point at
/// the same backend with the same tuning share the connection
/// cache.
/// HP-T1: the connector is `HttpsConnector<HttpConnector>` for
/// every pool. The connector inspects the URL scheme and only
/// performs a TLS handshake on `https://`; `http://` URLs use
/// the inner plain TCP path. One `Client` shape covers both
/// modes without a duplicated cache.
type PooledClient = Client<
    HttpsConnector<HttpConnector<crate::upstream::pinned_resolver::PinnedResolver>>,
    Full<Bytes>,
>;

/// Build a pooled HTTP client honouring `cfg`. The protocol
/// selection follows `cfg.scheme` (Phase 3 multi-protocol):
///
/// | Scheme  | Transport         | Wire framing                    |
/// |---------|-------------------|---------------------------------|
/// | `Auto`  | TLS iff `tls`     | ALPN negotiation (h1 or h2)     |
/// | `Http`  | plaintext         | HTTP/1.1                        |
/// | `Https` | TLS               | ALPN h1+h2 (same as Auto+TLS)   |
/// | `H2c`   | plaintext         | HTTP/2 prior knowledge          |
/// | `Grpc`  | TLS               | HTTP/2 only (ALPN h2)           |
/// | `Tcp`   | raw byte stream   | CONNECT-method tunnel via       |
/// |         |                   | `data_plane::forward_connect_tunnel` |
///
/// `max_idle_per_host = 0` OR `keep_alive = false` disables
/// pooling at the connector layer (pre-UP-T1 behaviour). The
/// `keep_alive = false` path *also* injects a request-side
/// `Connection: close` header so the upstream sees the intent;
/// the actual reuse decision lives in the pool ceiling.
fn build_client(cfg: &ConnectionPoolConfig) -> Result<PooledClient, String> {
    use aegis_core::config::UpstreamScheme;
    // rustls 0.23 requires an explicit CryptoProvider when more
    // than one cipher backend feature is reachable. Install
    // the ring provider once per process; subsequent calls
    // succeed silently. Idempotent.
    static PROVIDER_INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    PROVIDER_INIT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });

    // 2026-05-03 PM — use the process-global pinned resolver so
    // upstream URLs that name a host_header'd vhost
    // (`https://example.com/path`) connect to the configured IP
    // instead of the system DNS answer.  Unpinned hosts fall
    // through to GaiResolver — non-pinned destinations behave
    // exactly as before.
    let resolver = crate::upstream::pinned_resolver::global().clone();
    let mut http = HttpConnector::new_with_resolver(resolver);
    http.set_nodelay(true);
    // Allow plain `http://` URLs through the underlying connector
    // — without this, hyper-rustls would refuse them and force
    // every member to be `https://`.
    http.enforce_http(false);

    // ALPN advertisement depends on the scheme. The hyper-rustls
    // builder uses typestate transitions (`WantsProtocols2` →
    // `WantsProtocols3`), so we can't conditionally call
    // `.enable_http2()` on a single bound; build either
    // [h1] or [h1+h2] via separate branches.
    // 2026-05-13 — only advertise HTTP/2 to upstreams that EXPLICITLY
    // require it (`grpc`, `h2c`).  `auto` and `https` previously
    // advertised both h1 + h2, but real-world edges (nginx with
    // certain header configurations — verified against
    // `znews.vn` returning a generic 400 with `server: TTTT` over
    // h2 while accepting the identical request over h1) reject
    // hyper's HTTP/2 framing on requests that direct curl-over-h2
    // handles fine.  HTTP/1.1 is the universal lowest-common-
    // denominator for reverse-proxy forwarding; operators who
    // need h2 to a backend pick `grpc` or `h2c` explicitly.
    let advertise_h2 = matches!(
        cfg.scheme,
        UpstreamScheme::Grpc | UpstreamScheme::H2c,
    );
    // P2 — when this pool has resolved upstream-mTLS material, build
    // an explicit rustls `ClientConfig` that presents the WAF client
    // cert and pins the configured trust anchors, and force
    // `https_only()` so a cert/load failure or a plaintext backend
    // fails the dial closed (never a silent downgrade). Pools without
    // mTLS keep the exact pre-P2 path (`with_webpki_roots`,
    // server-auth only, `https_or_http`).
    let connector = match cfg.upstream_mtls.as_ref() {
        Some(m) => {
            let tls = crate::upstream::tls::client_config_from_resolved(m)
                .map_err(|e| format!("upstream mTLS client config build failed: {e}"))?;
            if advertise_h2 {
                hyper_rustls::HttpsConnectorBuilder::new()
                    .with_tls_config(tls)
                    .https_only()
                    .enable_http1()
                    .enable_http2()
                    .wrap_connector(http)
            } else {
                hyper_rustls::HttpsConnectorBuilder::new()
                    .with_tls_config(tls)
                    .https_only()
                    .enable_http1()
                    .wrap_connector(http)
            }
        }
        None if advertise_h2 => hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http),
        None => hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .wrap_connector(http),
    };

    let effective_pool_size = if cfg.keep_alive {
        cfg.max_idle_per_host
    } else {
        0
    };
    let mut client_builder = Client::builder(TokioExecutor::new());
    client_builder
        .pool_max_idle_per_host(effective_pool_size)
        .pool_idle_timeout(cfg.idle_timeout)
        .pool_timer(hyper_util::rt::TokioTimer::new())
        .http1_preserve_header_case(true)
        .http1_title_case_headers(false);
    // HTTP/2-only schemes flip `http2_only` so the client uses
    // HTTP/2 prior-knowledge framing (no h1 negotiation).
    if cfg.scheme.forces_http2() {
        client_builder.http2_only(true);
    }
    Ok(client_builder.build(connector))
}

/// Stable signature of a [`ConnectionPoolConfig`] used to dedupe
/// clients in the cache. Two pools with the same tuning share a
/// single client (and therefore a single idle-conn cache).
///
/// HIGH-RU-02 (2026-05-12) — `scheme` is part of the key because
/// `build_client` consumes it for ALPN advertisement
/// (`advertise_h2` branch) and forced HTTP/2 framing
/// (`forces_http2`).  Without it, a scheme flip on hot-reload
/// hit a stale cached client whose internal shape didn't match
/// the current config — operators had to restart the WAF to pick
/// up the change.  Including the scheme makes
/// `PoolRegistry::apply` close the round-trip end-to-end.
///
/// P2 — `mtls_fingerprint` follows the same HIGH-RU-02 rule for the
/// resolved upstream-mTLS material: `build_client` consumes the cert
/// / trust anchors, so the key must include their fingerprint or a
/// rotation (enable mTLS, swap the trust CA) would hit a stale cached
/// client built for the prior material. Fingerprint is over PUBLIC
/// inputs only (cert/key paths, trust path, flags) — never key bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct PoolKey {
    max_idle_per_host: usize,
    idle_timeout_ms: u64,
    keep_alive: bool,
    tls: bool,
    scheme: aegis_core::config::UpstreamScheme,
    mtls_fingerprint: Option<String>,
}

impl From<&ConnectionPoolConfig> for PoolKey {
    fn from(c: &ConnectionPoolConfig) -> Self {
        Self {
            max_idle_per_host: c.max_idle_per_host,
            idle_timeout_ms: c.idle_timeout.as_millis().min(u64::MAX as u128) as u64,
            keep_alive: c.keep_alive,
            tls: c.tls,
            scheme: c.scheme,
            mtls_fingerprint: c.upstream_mtls.as_ref().map(|m| m.fingerprint.clone()),
        }
    }
}

fn client_cache() -> &'static RwLock<HashMap<PoolKey, Arc<PooledClient>>> {
    static CACHE: OnceLock<RwLock<HashMap<PoolKey, Arc<PooledClient>>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Resolve to a shared, pooled [`PooledClient`] for `cfg`.
///
/// Cheap on cache-hit (read lock + `Arc::clone`); on the first
/// request for a given config signature we pay one client build
/// under the write lock, then reuse forever.
fn pooled_client(cfg: &ConnectionPoolConfig) -> Result<Arc<PooledClient>, String> {
    let key = PoolKey::from(cfg);
    {
        let r = client_cache().read().unwrap_or_else(|p| p.into_inner());
        if let Some(c) = r.get(&key) {
            return Ok(c.clone());
        }
    }
    // Build OUTSIDE the entry closure so a fallible mTLS client build
    // can propagate (fail closed) without being cached — a fixed cert
    // on the next reload then builds cleanly.
    let client = Arc::new(build_client(cfg)?);
    let mut w = client_cache().write().unwrap_or_else(|p| p.into_inner());
    Ok(w.entry(key).or_insert(client).clone())
}

/// Test-only helper: drop every pooled client. Lets tests that
/// exercise pool semantics start from a clean slate. Production
/// code never calls this; the cache is intentionally process-wide.
#[doc(hidden)]
pub fn _reset_client_cache() {
    let mut w = client_cache().write().unwrap_or_else(|p| p.into_inner());
    w.clear();
}

/// Forward a request to `member` and return the upstream's
/// response. Body is collected (not streamed) — matches the
/// rest of the proxy's `Full<Bytes>` shape.
///
/// UP-T1 path: requests reuse pooled HTTP/1.1 keep-alive
/// connections via `hyper-util`'s legacy [`Client`]. The pool's
/// idle-conn ceiling and idle-timeout come from
/// [`ConnectionPoolConfig`]; `keep_alive: false` injects
/// `Connection: close` to disable reuse on a per-pool basis
/// (e.g. for diagnosing keep-alive interactions).
pub async fn forward(
    member: &Member,
    cfg: &ConnectionPoolConfig,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
    streaming: &aegis_core::config::StreamingConfig,
    stream_permits: &std::sync::Arc<tokio::sync::Semaphore>,
) -> Result<
    (
        Response<crate::body::DataBody>,
        crate::upstream::streaming::ResponseMode,
    ),
    ForwardError,
> {
    // P2 — a failure here is an upstream-mTLS client-config/cert load
    // error; fail the dial closed rather than connecting without the
    // client cert.
    let client = pooled_client(cfg).map_err(ForwardError::Handshake)?;

    // FIX 2026-05-03 — when the operator pinned a Host header on
    // this member (multi-vhost backend support), use it instead
    // of the addr-derived default.  Backwards-compatible: members
    // without `host_header:` set keep the legacy addr-rewrite
    // behaviour.
    let upstream_host_header = member
        .host_override
        .clone()
        .unwrap_or_else(|| member.addr.to_string());
    let pq = path_and_query(&uri);
    let mut fwd_headers = build_upstream_headers(&headers, &upstream_host_header);

    // `keep_alive: false` means we want every request to use a
    // fresh socket. Hyper's pool decides reuse off the response's
    // `Connection: close` (set by the server) OR the request's
    // — set it on the request so the upstream knows not to keep
    // the connection around.
    if !cfg.keep_alive {
        fwd_headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("close"),
        );
    }

    // TCP-T6 — `scheme: tcp` routes do NOT flow through this
    // HTTP forwarder. The data-plane handler
    // (`data_plane::forward_allow_to_upstream`) dispatches
    // CONNECT-method requests to `forward_connect_tunnel`
    // before reaching here, and rejects non-CONNECT methods
    // to tcp routes with a 502 `non_connect_to_tcp_route`.
    // Reaching this point with `scheme: tcp` would mean the
    // dispatcher upstream of us is broken — surface a loud
    // configuration error so the regression is obvious.
    if cfg.scheme == aegis_core::config::UpstreamScheme::Tcp {
        return Err(ForwardError::BadRequest(
            "internal: HTTP forwarder reached with scheme=tcp — dispatch in data_plane.rs is broken".into(),
        ));
    }

    // URL scheme follows the protocol selector. Auto + tls=true
    // mirrors the legacy behaviour; explicit Https/Grpc force
    // `https://`; H2c stays plaintext.
    let scheme = if cfg.scheme.uses_tls(cfg.tls) { "https" } else { "http" };
    // 2026-05-03 PM — for HTTPS upstreams with a pinned
    // host_header, the URL host carries the override hostname
    // (controls SNI + cert validation) while the pinned resolver
    // routes the actual TCP connection to `member.addr`.  Plain
    // HTTP keeps the addr-as-host shape since SNI doesn't apply
    // and a custom Host header rewrite happened at the header
    // layer.
    let url_authority = if cfg.scheme.uses_tls(cfg.tls) {
        match member.host_override.as_deref() {
            // 2026-05-13 — omit the port when it's the default for
            // the scheme (443/https, 80/http). Some upstream edges
            // (e.g. znews.vn's nginx) return 400 when the HTTP/2
            // `:authority` carries the redundant port while peer
            // `Host` doesn't — being conservative here is what curl
            // and browsers do anyway.
            Some(h) => {
                let port = member.addr.port();
                if port == 443 {
                    h.to_string()
                } else {
                    format!("{}:{}", h, port)
                }
            }
            None => member.addr.to_string(),
        }
    } else {
        member.addr.to_string()
    };
    let target_uri: Uri = format!("{scheme}://{url_authority}{pq}")
        .parse()
        .map_err(|e: http::uri::InvalidUri| {
            ForwardError::BadRequest(e.to_string())
        })?;
    tracing::debug!(
        target_uri = %target_uri,
        cfg_scheme = ?cfg.scheme,
        cfg_tls = cfg.tls,
        member_addr = %member.addr,
        host_override = ?member.host_override,
        "upstream forward target URI",
    );

    let mut builder = Request::builder().method(method).uri(target_uri);
    if let Some(h) = builder.headers_mut() {
        *h = fwd_headers;
    }
    let fwd_req = builder
        .body(Full::new(body))
        .map_err(|e| ForwardError::BadRequest(e.to_string()))?;

    // Single-shot per-request timeout — the connector itself has
    // an internal connect timeout (default 30 s) but a stuck
    // upstream after handshake can still hang us indefinitely.
    // Cap at 30 s for now; later we'll wire the route's
    // `total_deadline` here.
    let send_fut = client.request(fwd_req);
    let resp = match tokio::time::timeout(Duration::from_secs(30), send_fut).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            // hyper-util surfaces connect failures as `is_connect()`.
            return Err(if e.is_connect() {
                ForwardError::Connect(e.to_string())
            } else {
                ForwardError::Send(e.to_string())
            });
        }
        Err(_) => {
            return Err(ForwardError::Send(
                "upstream send timed out (30 s)".to_string(),
            ));
        }
    };

    let status = resp.status();
    let resp_headers = resp.headers().clone();

    // SSE plan decisions 2 + 2a — classify the response ONCE, here, from
    // its media type against the streaming allowlist. The mode rides out
    // on the return value; no later phase re-parses Content-Type.
    let content_type = resp_headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());
    // gRPC P1 — a gRPC response is forced onto the streaming path so its
    // HTTP/2 `grpc-status` / `grpc-message` trailers survive (the buffered
    // `.collect()` drops them). This is detection, NOT operator config, so it
    // holds even when `streaming.enabled` is false. `is_grpc_resp` also gates
    // the on-exhaustion guard below (gRPC must never buffer-degrade).
    let is_grpc_resp = content_type
        .map(crate::proto::grpc::content_type_is_grpc)
        .unwrap_or(false);
    let mode = if is_grpc_resp {
        crate::upstream::streaming::ResponseMode::Streaming
    } else if streaming.enabled {
        crate::upstream::streaming::classify_response_mode(content_type, &streaming.content_types)
    } else {
        crate::upstream::streaming::ResponseMode::Buffered
    };

    // Build the filtered response head (hop-by-hop / Connection-listed
    // headers stripped) from the cloned head — shared by both modes,
    // touches no body.
    let mut filtered: Response<Full<Bytes>> = replay_response_status_and_headers(
        &Response::builder().status(status).body(()).unwrap(),
    );
    {
        let out_headers = filtered.headers_mut();
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

    // Decision 5 — bound concurrent live streams. Each pins an upstream
    // connection for its whole lifetime, which the legacy client pool
    // (idle-only) does NOT cap. Acquire a permit before committing to
    // stream; on exhaustion fall back per `on_exhaustion`. `None` here
    // means "buffer this response" (either it isn't a stream, or the cap
    // is full and we're degrading to buffered).
    let stream_permit = if matches!(
        mode,
        crate::upstream::streaming::ResponseMode::Streaming
    ) {
        match std::sync::Arc::clone(stream_permits).try_acquire_owned() {
            Ok(permit) => Some(permit),
            // gRPC P1 guard — a gRPC stream that loses the permit race must
            // REJECT (503), never `Buffer`: the buffer-degrade path re-collects
            // and drops the `grpc-status` trailers, turning every call into an
            // opaque INTERNAL error. So gRPC ignores `on_exhaustion: buffer`.
            Err(_) if is_grpc_resp
                || matches!(
                    streaming.on_exhaustion,
                    aegis_core::config::OnStreamExhaustion::Reject
                ) =>
            {
                // Drop the upstream `resp` (releases its connection at
                // once) and shed with 503. Returned as Buffered so the
                // data plane handles it as a normal small response.
                let resp_503 = Response::builder()
                    .status(http::StatusCode::SERVICE_UNAVAILABLE)
                    .body(Full::new(Bytes::from_static(
                        b"streaming capacity exceeded\n",
                    )))
                    .map_err(|e| ForwardError::BadRequest(e.to_string()))?;
                return Ok((
                    crate::body::boxed(resp_503),
                    crate::upstream::streaming::ResponseMode::Buffered,
                ));
            }
            // `on_exhaustion: buffer` for a NON-gRPC stream → degrade to the
            // buffered collect (the `_` arm below).
            Err(_) => None,
        }
    } else {
        None
    };

    match mode {
        crate::upstream::streaming::ResponseMode::Streaming if stream_permit.is_some() => {
            // Header-inspected only: stream the body through frame-by-frame
            // with an idle (inactivity) timeout — NO size cap and NO whole-
            // body read deadline (the deadline would kill a live stream).
            // The data plane bypasses its response-filter/cache collect for
            // this mode (decision 2a / Phase 3). The permit rides the body
            // and releases when the stream ends / the client disconnects.
            let body = crate::upstream::streaming::stream_through(
                resp.into_body(),
                streaming.idle_timeout,
                stream_permit,
            );
            Ok((filtered.map(|_| body), crate::upstream::streaming::ResponseMode::Streaming))
        }
        // Buffered, OR streaming-but-cap-exhausted-with-on_exhaustion=buffer.
        _ => {
            // F-HIGH-003 — cap the buffered body; F-HIGH-stateful — wrap
            // the collect in the read deadline so a slowloris upstream
            // can't pin the slot. Size cap → ReadBody; deadline → Timeout
            // (the data plane maps the latter onto v2.3 §3 `timeout`).
            let max_response = cfg.max_response_body_bytes as usize;
            let read_deadline = cfg.response_body_read_timeout;
            let body_bytes = match tokio::time::timeout(
                read_deadline,
                http_body_util::Limited::new(resp.into_body(), max_response).collect(),
            )
            .await
            {
                Ok(Ok(collected)) => collected.to_bytes(),
                Ok(Err(e)) => {
                    return Err(ForwardError::ReadBody(format!(
                        "response body exceeds cap or read error: {e}",
                    )));
                }
                Err(_) => {
                    return Err(ForwardError::Timeout(format!(
                        "response body read exceeded {:?}",
                        read_deadline,
                    )));
                }
            };
            *filtered.body_mut() = Full::new(body_bytes);
            // Always Buffered here — either it was classified Buffered, or
            // it was a stream that lost the concurrency race and degraded
            // (on_exhaustion = buffer). Reporting Buffered keeps the data
            // plane on its normal collect/filter/cache path.
            Ok((
                crate::body::boxed(filtered),
                crate::upstream::streaming::ResponseMode::Buffered,
            ))
        }
    }
}

/// Errors raised by [`forward`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardError {
    Connect(String),
    Handshake(String),
    BadRequest(String),
    Send(String),
    ReadBody(String),
    /// 2026-05-17 F-HIGH-stateful sub-finding: the upstream body
    /// read can stall indefinitely on a slowloris-style upstream
    /// that trickles bytes below the per-byte budget. Surfaced
    /// separately from `ReadBody` so the data plane can map it
    /// onto v2.3 §3 `timeout` action (vs `block` for size cap).
    Timeout(String),
}

impl ForwardError {
    /// Whether this failure indicates the **member itself** is unreachable
    /// (so it should count toward passive per-member eviction — P2 of
    /// `plans/future/passive-upstream-health.md`).
    ///
    /// `Connect` / `Handshake` / `Timeout` mean we couldn't reach or
    /// complete a conversation with this backend → member-level. `Send` /
    /// `ReadBody` can fail mid-stream for client/app reasons, and
    /// `BadRequest` is the proxy's own fault — none of those evict a member.
    pub fn is_member_failure(&self) -> bool {
        matches!(
            self,
            ForwardError::Connect(_) | ForwardError::Handshake(_) | ForwardError::Timeout(_)
        )
    }
}

impl std::fmt::Display for ForwardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForwardError::Connect(m) => write!(f, "upstream connect failed: {m}"),
            ForwardError::Handshake(m) => write!(f, "upstream handshake failed: {m}"),
            ForwardError::BadRequest(m) => write!(f, "upstream request build failed: {m}"),
            ForwardError::Send(m) => write!(f, "upstream send failed: {m}"),
            ForwardError::ReadBody(m) => write!(f, "upstream body read failed: {m}"),
            ForwardError::Timeout(m) => write!(f, "upstream read timed out: {m}"),
        }
    }
}

impl std::error::Error for ForwardError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes tests that touch the process-global client `CACHE` via
    /// `_reset_client_cache()`. Without it, a concurrent test resetting the
    /// cache mid-loop forces a counting test to rebuild its client → an extra
    /// TCP `accept()` → flaky `observed == 1` assertions under `cargo test`'s
    /// parallel execution. A `tokio::sync::Mutex` so it's held cleanly across
    /// `.await` in the async tests; the one sync test uses `blocking_lock()`.
    static CACHE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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

    // ---- ForwardError::is_member_failure (passive upstream health P2) ----

    #[test]
    fn member_level_failures_are_connect_handshake_timeout() {
        // These mean "couldn't reach / talk to this member" — they count
        // toward passive per-member eviction.
        assert!(ForwardError::Connect("refused".into()).is_member_failure());
        assert!(ForwardError::Handshake("tls".into()).is_member_failure());
        assert!(ForwardError::Timeout("read stalled".into()).is_member_failure());
    }

    #[test]
    fn ambiguous_failures_are_not_member_failures() {
        // Send/ReadBody can fail mid-stream for client/app reasons, and
        // BadRequest is our own fault — none should evict a member.
        assert!(!ForwardError::Send("write".into()).is_member_failure());
        assert!(!ForwardError::ReadBody("trickle".into()).is_member_failure());
        assert!(!ForwardError::BadRequest("uri".into()).is_member_failure());
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

    // Response-filter gzip fix (2026-07-07) — the WAF must force an
    // identity (uncompressed) upstream response so `on_body_frame`'s
    // DLP/redaction can decode + scrub the body. A client advertising
    // `Accept-Encoding: gzip` otherwise defeats the whole response
    // filter: the origin returns a gzip body, UTF-8 decode fails, and
    // the compressed secrets pass straight through.
    #[test]
    fn build_upstream_forces_identity_accept_encoding() {
        let original = hm(&[
            ("host", "api.example.com"),
            ("accept-encoding", "gzip, deflate, br"),
        ]);
        let out = build_upstream_headers(&original, "10.0.0.1:8080");
        // Exactly one Accept-Encoding value, and it is `identity`.
        let vals: Vec<_> = out.get_all("accept-encoding").iter().collect();
        assert_eq!(vals.len(), 1, "one accept-encoding header expected");
        assert_eq!(vals[0].to_str().unwrap(), "identity");
    }

    #[test]
    fn build_upstream_sets_identity_when_client_sent_none() {
        // Even when the client sends no Accept-Encoding, pin identity so
        // the upstream can't opportunistically compress.
        let original = hm(&[("host", "api.example.com")]);
        let out = build_upstream_headers(&original, "10.0.0.1:8080");
        assert_eq!(
            out.get("accept-encoding").unwrap().to_str().unwrap(),
            "identity"
        );
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
    fn build_upstream_honours_host_override_when_set() {
        // FIX 2026-05-03 — multi-vhost upstream support.
        // When an operator pins `host_header: example.com` on
        // a member, the upstream sees that vhost regardless of
        // the underlying IP-port the connection lands on.
        let original = hm(&[("host", "client-supplied.example")]);
        // Caller passes the resolved override string in place
        // of the addr.toString() default.
        let out = build_upstream_headers(&original, "vhost.example.com");
        assert_eq!(out.get("host").unwrap().to_str().unwrap(), "vhost.example.com");
        // The original Host still rides as X-Forwarded-Host so
        // the upstream can see what the client asked for.
        assert_eq!(
            out.get("x-forwarded-host").unwrap().to_str().unwrap(),
            "client-supplied.example",
        );
    }

    #[test]
    fn member_runtime_round_trips_host_override() {
        use crate::upstream::Member;
        use std::net::SocketAddr;
        let addr: SocketAddr = "10.0.0.1:8080".parse().unwrap();
        let with = Member::with_host_override(
            addr,
            1,
            None,
            Some("api.example.com".into()),
        );
        assert_eq!(with.host_override.as_deref(), Some("api.example.com"));
        let without = Member::new(addr, 1, None);
        assert!(without.host_override.is_none());
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

    // ---- UP-T1 — connection pool reuse ------------------------------

    /// Spin up a counting HTTP/1.1 echo server. Returns the
    /// bound address and a counter incremented on every accepted
    /// TCP connection (NOT every request). Used to assert that
    /// keep-alive pooled requests share TCP connections.
    async fn spawn_counting_server() -> (
        std::net::SocketAddr,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let conns = std::sync::Arc::new(AtomicUsize::new(0));
        let conns_for_loop = conns.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut sock, _peer) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                conns_for_loop.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    // HTTP/1.1 lets us serve multiple requests on
                    // one TCP. Loop until the peer drops.
                    loop {
                        let n = match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        let req = String::from_utf8_lossy(&buf[..n]);
                        if !req.contains("\r\n\r\n") {
                            // Partial frame; bail.
                            return;
                        }
                        let body = b"ok";
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\nok",
                            body.len()
                        );
                        if sock.write_all(resp.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (addr, conns)
    }

    #[tokio::test]
    async fn pooled_keep_alive_reuses_tcp_connection() {
        // Reset cache so a previous test's client doesn't leak in.
        let _serial = CACHE_LOCK.lock().await;
        super::_reset_client_cache();
        let (addr, conns) = spawn_counting_server().await;
        let member = Member::new(addr, 1, None);
        let cfg = ConnectionPoolConfig {
            max_idle_per_host: 32,
            idle_timeout: Duration::from_secs(30),
            keep_alive: true,
            tls: false,
            scheme: aegis_core::config::UpstreamScheme::Auto,
            max_response_body_bytes: 10 * 1024 * 1024,
            response_body_read_timeout: Duration::from_secs(30),
            upstream_mtls: None,
        };

        for _ in 0..5 {
            let (resp, _mode) = forward(
                &member,
                &cfg,
                Method::GET,
                "/healthz".parse().unwrap(),
                hm(&[("host", "ignored.example.com")]),
                Bytes::new(),
                &aegis_core::config::StreamingConfig::default(),
                &std::sync::Arc::new(tokio::sync::Semaphore::new(256)),
            )
            .await
            .expect("forward must succeed");
            assert_eq!(resp.status(), 200);
        }

        // 5 requests, exactly 1 TCP connection accepted.
        let observed = conns.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            observed, 1,
            "keep-alive pool must reuse one TCP across 5 requests; \
             observed {observed} accept()s",
        );
    }

    #[test]
    fn tls_flag_makes_distinct_pool_keys() {
        // HP-T1: two configs differing only on `tls` MUST hash
        // to distinct keys so an HTTP pool and an HTTPS pool
        // never share the same cached `Client`.
        let http = ConnectionPoolConfig {
            max_idle_per_host: 32,
            idle_timeout: Duration::from_secs(30),
            keep_alive: true,
            tls: false,
            scheme: aegis_core::config::UpstreamScheme::Auto,
            max_response_body_bytes: 10 * 1024 * 1024,
            response_body_read_timeout: Duration::from_secs(30),
            upstream_mtls: None,
        };
        let https = ConnectionPoolConfig { tls: true, ..http.clone() };
        assert_ne!(super::PoolKey::from(&http), super::PoolKey::from(&https));
    }

    #[test]
    fn scheme_makes_distinct_pool_keys() {
        // HIGH-RU-02 (2026-05-12) — two configs differing only on
        // `scheme` must hash to distinct keys so the client cache
        // invalidates whenever the scheme axis moves on hot-reload.
        // Without the `scheme` field on PoolKey, an operator who
        // flipped a pool from `auto` to `https` (or `http` to `h2c`)
        // kept hitting the previously-built client whose ALPN /
        // http2_only flags didn't match the new config — and had to
        // restart the WAF to pick up the change.
        let auto = ConnectionPoolConfig {
            max_idle_per_host: 32,
            idle_timeout: Duration::from_secs(30),
            keep_alive: true,
            tls: false,
            scheme: aegis_core::config::UpstreamScheme::Auto,
            max_response_body_bytes: 10 * 1024 * 1024,
            response_body_read_timeout: Duration::from_secs(30),
            upstream_mtls: None,
        };
        let https = ConnectionPoolConfig {
            scheme: aegis_core::config::UpstreamScheme::Https,
            max_response_body_bytes: 10 * 1024 * 1024,
            response_body_read_timeout: Duration::from_secs(30),
            ..auto.clone()
        };
        let h2c = ConnectionPoolConfig {
            scheme: aegis_core::config::UpstreamScheme::H2c,
            max_response_body_bytes: 10 * 1024 * 1024,
            response_body_read_timeout: Duration::from_secs(30),
            ..auto.clone()
        };
        let grpc = ConnectionPoolConfig {
            scheme: aegis_core::config::UpstreamScheme::Grpc,
            max_response_body_bytes: 10 * 1024 * 1024,
            response_body_read_timeout: Duration::from_secs(30),
            ..auto.clone()
        };
        // Every variant produces a distinct cache key.
        assert_ne!(super::PoolKey::from(&auto),  super::PoolKey::from(&https));
        assert_ne!(super::PoolKey::from(&auto),  super::PoolKey::from(&h2c));
        assert_ne!(super::PoolKey::from(&auto),  super::PoolKey::from(&grpc));
        assert_ne!(super::PoolKey::from(&https), super::PoolKey::from(&h2c));
        assert_ne!(super::PoolKey::from(&https), super::PoolKey::from(&grpc));
        assert_ne!(super::PoolKey::from(&h2c),   super::PoolKey::from(&grpc));
    }

    #[test]
    fn pooled_client_distinguishes_schemes() {
        // HIGH-RU-02 — the empirical guarantee: calling pooled_client
        // back-to-back with different schemes must return different
        // Arc<PooledClient> instances (no Arc::ptr_eq).  Combined
        // with the cache-key test above, this confirms the cache
        // builds a fresh client on a scheme change instead of
        // returning the stale one.
        let _serial = CACHE_LOCK.blocking_lock();
        super::_reset_client_cache();
        let auto = ConnectionPoolConfig {
            max_idle_per_host: 32,
            idle_timeout: Duration::from_secs(30),
            keep_alive: true,
            tls: false,
            scheme: aegis_core::config::UpstreamScheme::Auto,
            max_response_body_bytes: 10 * 1024 * 1024,
            response_body_read_timeout: Duration::from_secs(30),
            upstream_mtls: None,
        };
        let https = ConnectionPoolConfig {
            scheme: aegis_core::config::UpstreamScheme::Https,
            max_response_body_bytes: 10 * 1024 * 1024,
            response_body_read_timeout: Duration::from_secs(30),
            ..auto.clone()
        };
        let c_auto  = super::pooled_client(&auto).unwrap();
        let c_https = super::pooled_client(&https).unwrap();
        assert!(
            !Arc::ptr_eq(&c_auto, &c_https),
            "scheme change must produce a different cached client",
        );
        // Same config back-to-back still hits the cache.
        let c_auto_again = super::pooled_client(&auto).unwrap();
        assert!(
            Arc::ptr_eq(&c_auto, &c_auto_again),
            "identical config must reuse the cached client",
        );
    }

    /// P2 scope isolation — the resolved upstream-mTLS material is
    /// part of `PoolKey`, so enabling mTLS on one pool (or pointing
    /// it at a different trust CA) yields a DIFFERENT cache key than a
    /// pool without mTLS. Without this the client cache would alias an
    /// mTLS pool onto a plaintext pool's connector (the HIGH-RU-02
    /// class of bug). Asserted at the key level so it needs no on-disk
    /// certs.
    #[test]
    fn poolkey_isolates_upstream_mtls_pools() {
        use aegis_core::config::{CertSource, UpstreamMtlsResolved};
        let base = ConnectionPoolConfig {
            max_idle_per_host: 32,
            idle_timeout: Duration::from_secs(30),
            keep_alive: true,
            tls: true,
            scheme: aegis_core::config::UpstreamScheme::Https,
            max_response_body_bytes: 10 * 1024 * 1024,
            response_body_read_timeout: Duration::from_secs(30),
            upstream_mtls: None,
        };
        let resolved = |fp: &str, trust: Option<&str>| UpstreamMtlsResolved {
            client_cert: CertSource::File("/x/client.pem".into()),
            client_key: CertSource::File("/x/client.key".into()),
            trust: trust.map(|t| CertSource::File(t.into())),
            verify: true,
            allowed_sans: Vec::new(),
            fingerprint: fp.into(),
        };
        let plain = super::PoolKey::from(&base);
        let mtls_a = super::PoolKey::from(&ConnectionPoolConfig {
            upstream_mtls: Some(resolved("v1|a", None)),
            ..base.clone()
        });
        let mtls_b = super::PoolKey::from(&ConnectionPoolConfig {
            upstream_mtls: Some(resolved("v1|b", Some("/x/backend-ca.pem"))),
            ..base.clone()
        });
        assert_ne!(plain, mtls_a, "mTLS pool must not alias a plaintext pool");
        assert_ne!(mtls_a, mtls_b, "different trust material ⇒ different key");
        // Identical material ⇒ same key (clients are shared/reused).
        let mtls_a2 = super::PoolKey::from(&ConnectionPoolConfig {
            upstream_mtls: Some(resolved("v1|a", None)),
            ..base.clone()
        });
        assert_eq!(mtls_a, mtls_a2, "identical material must reuse the key");
    }

    /// P2 fail-closed (build path) — a pool with mTLS enabled whose
    /// client cert file is missing makes `build_client` return `Err`,
    /// so `forward` fails the dial closed (mapped to
    /// `ForwardError::Handshake`) instead of connecting without the
    /// client cert.
    #[test]
    fn build_client_fails_closed_on_missing_cert() {
        use aegis_core::config::{CertSource, UpstreamMtlsResolved};
        let cfg = ConnectionPoolConfig {
            max_idle_per_host: 32,
            idle_timeout: Duration::from_secs(30),
            keep_alive: true,
            tls: true,
            scheme: aegis_core::config::UpstreamScheme::Https,
            max_response_body_bytes: 10 * 1024 * 1024,
            response_body_read_timeout: Duration::from_secs(30),
            upstream_mtls: Some(UpstreamMtlsResolved {
                client_cert: CertSource::File("/nonexistent/waf-client.pem".into()),
                client_key: CertSource::File("/nonexistent/waf-client.key".into()),
                trust: None,
                verify: true,
                allowed_sans: Vec::new(),
                fingerprint: "v1|missing".into(),
            }),
        };
        let err = super::build_client(&cfg).unwrap_err();
        assert!(
            err.contains("client config build failed") || err.contains("No such file"),
            "expected a fail-closed build error, got: {err}",
        );
    }

    #[tokio::test]
    async fn keep_alive_disabled_opens_a_connection_per_request() {
        let _serial = CACHE_LOCK.lock().await;
        super::_reset_client_cache();
        let (addr, conns) = spawn_counting_server().await;
        let member = Member::new(addr, 1, None);
        let cfg = ConnectionPoolConfig {
            max_idle_per_host: 32,
            idle_timeout: Duration::from_secs(30),
            keep_alive: false, // request-side `Connection: close`
            tls: false,
            scheme: aegis_core::config::UpstreamScheme::Auto,
            max_response_body_bytes: 10 * 1024 * 1024,
            response_body_read_timeout: Duration::from_secs(30),
            upstream_mtls: None,
        };

        for _ in 0..3 {
            let (resp, _mode) = forward(
                &member,
                &cfg,
                Method::GET,
                "/healthz".parse().unwrap(),
                HeaderMap::new(),
                Bytes::new(),
                &aegis_core::config::StreamingConfig::default(),
                &std::sync::Arc::new(tokio::sync::Semaphore::new(256)),
            )
            .await
            .expect("forward must succeed");
            assert_eq!(resp.status(), 200);
        }

        // 3 requests, 3 TCPs — pre-pool baseline.
        let observed = conns.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            observed, 3,
            "keep_alive=false must open one TCP per request; observed {observed}",
        );
    }

    // ---- SSE streaming (SSE plan §8 — slow-SSE regression) ----------

    /// Spin up an HTTP/1.1 upstream that replies `text/event-stream` and
    /// trickles `n` chunked SSE events `gap` apart, then closes. Models a
    /// live SSE source emitting an event every `gap`.
    async fn spawn_sse_upstream(
        n: usize,
        gap: Duration,
        content_type: &'static str,
    ) -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _peer) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let mut buf = vec![0u8; 4096];
            let _ = sock.read(&mut buf).await; // consume the request head
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nTransfer-Encoding: chunked\r\n\r\n",
            );
            if sock.write_all(head.as_bytes()).await.is_err() {
                return;
            }
            for i in 0..n {
                tokio::time::sleep(gap).await;
                let event = format!("data: {i}\n\n");
                // chunked framing: <hex-len>\r\n<payload>\r\n
                let framed = format!("{:x}\r\n{}\r\n", event.len(), event);
                if sock.write_all(framed.as_bytes()).await.is_err() {
                    return;
                }
                let _ = sock.flush().await;
            }
            let _ = sock.write_all(b"0\r\n\r\n").await; // terminating chunk
        });
        addr
    }

    fn streaming_cfg(read_timeout: Duration) -> ConnectionPoolConfig {
        ConnectionPoolConfig {
            max_idle_per_host: 32,
            idle_timeout: Duration::from_secs(30),
            keep_alive: true,
            tls: false,
            scheme: aegis_core::config::UpstreamScheme::Auto,
            max_response_body_bytes: 10 * 1024 * 1024,
            response_body_read_timeout: read_timeout,
            upstream_mtls: None,
        }
    }

    /// Mock **cleartext h2 (h2c)** gRPC backend: one connection, returns
    /// `200 application/grpc` with a data frame followed by `grpc-status` /
    /// `grpc-message` **trailers**. Returns the bound address.
    async fn spawn_grpc_h2c_upstream() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let io = hyper_util::rt::TokioIo::new(stream);
                    let _ = hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(
                        io,
                        hyper::service::service_fn(
                            |_req: hyper::Request<hyper::body::Incoming>| async {
                                use hyper::body::Frame;
                                let (tx, rx) = tokio::sync::mpsc::channel::<
                                    Result<Frame<Bytes>, std::convert::Infallible>,
                                >(4);
                                tokio::spawn(async move {
                                    let _ = tx
                                        .send(Ok(Frame::data(Bytes::from_static(
                                            b"\x00\x00\x00\x00\x05hello",
                                        ))))
                                        .await;
                                    let mut trailers = hyper::HeaderMap::new();
                                    trailers.insert("grpc-status", "0".parse().unwrap());
                                    trailers.insert("grpc-message", "OK".parse().unwrap());
                                    let _ = tx.send(Ok(Frame::trailers(trailers))).await;
                                });
                                let body = http_body_util::StreamBody::new(
                                    tokio_stream::wrappers::ReceiverStream::new(rx),
                                );
                                Ok::<_, std::convert::Infallible>(
                                    hyper::Response::builder()
                                        .status(200)
                                        .header("content-type", "application/grpc")
                                        .body(body)
                                        .unwrap(),
                                )
                            },
                        ),
                    )
                    .await;
                });
            }
        });
        addr
    }

    /// gRPC P1 — a gRPC response is forced onto the streaming path so its
    /// HTTP/2 `grpc-status` / `grpc-message` trailers survive end-to-end
    /// through `forward()`. The buffered path would `.collect()` and drop them.
    #[tokio::test]
    async fn grpc_response_streams_and_preserves_trailers() {
        let _serial = CACHE_LOCK.lock().await;
        super::_reset_client_cache();
        let addr = spawn_grpc_h2c_upstream().await;
        let member = Member::new(addr, 1, None);
        let mut cfg = streaming_cfg(Duration::from_millis(50));
        // Cleartext prior-knowledge h2 so `forward()` speaks gRPC to the backend.
        cfg.scheme = aegis_core::config::UpstreamScheme::H2c;
        let streaming = aegis_core::config::StreamingConfig::default();

        let (resp, mode) = forward(
            &member,
            &cfg,
            Method::POST,
            "/pkg.Svc/Method".parse().unwrap(),
            hm(&[("content-type", "application/grpc")]),
            Bytes::new(),
            &streaming,
            &std::sync::Arc::new(tokio::sync::Semaphore::new(256)),
        )
        .await
        .expect("gRPC forward must succeed");

        // Forced onto the streaming path regardless of the allowlist.
        assert_eq!(mode, crate::upstream::streaming::ResponseMode::Streaming);
        assert_eq!(resp.status(), 200);

        use http_body_util::BodyExt;
        let collected = resp.into_body().collect().await.unwrap();
        let grpc_status = collected
            .trailers()
            .and_then(|t| t.get("grpc-status"))
            .cloned();
        let body = collected.to_bytes();
        assert!(body.windows(5).any(|w| w == b"hello"), "data frame survived");
        assert_eq!(
            grpc_status.expect("grpc-status trailer must survive"),
            "0",
            "the gRPC status trailer is preserved end-to-end",
        );
    }

    /// gRPC P1 guard — under streaming-permit exhaustion, gRPC must REJECT
    /// (503), never `Buffer`-degrade: the buffer path re-collects and drops the
    /// `grpc-status` trailers. So gRPC overrides `on_exhaustion: buffer`.
    #[tokio::test]
    async fn grpc_rejects_503_on_permit_exhaustion_never_buffer_degrades() {
        let _serial = CACHE_LOCK.lock().await;
        super::_reset_client_cache();
        let addr = spawn_grpc_h2c_upstream().await;
        let member = Member::new(addr, 1, None);
        let mut cfg = streaming_cfg(Duration::from_millis(50));
        cfg.scheme = aegis_core::config::UpstreamScheme::H2c;
        let mut streaming = aegis_core::config::StreamingConfig::default();
        streaming.on_exhaustion = aegis_core::config::OnStreamExhaustion::Buffer;

        // Zero permits → the gRPC stream loses the concurrency race.
        let (resp, _mode) = forward(
            &member,
            &cfg,
            Method::POST,
            "/pkg.Svc/Method".parse().unwrap(),
            hm(&[("content-type", "application/grpc")]),
            Bytes::new(),
            &streaming,
            &std::sync::Arc::new(tokio::sync::Semaphore::new(0)),
        )
        .await
        .expect("forward returns a 503 response, not an error");

        assert_eq!(
            resp.status(),
            503,
            "gRPC must reject on exhaustion, never buffer-degrade (drops trailers)",
        );
    }

    /// The regression proof: an SSE upstream that trickles events over far
    /// longer than the whole-body read deadline still streams through. The
    /// old buffered path would `collect()` and hit `response_body_read_
    /// timeout` (→ Timeout); the streaming path ignores that deadline and
    /// delivers every event.
    #[tokio::test]
    async fn sse_streams_through_past_the_read_deadline() {
        let _serial = CACHE_LOCK.lock().await;
        super::_reset_client_cache();
        // 3 events, 80ms apart (~240ms total) — well past the 20ms buffered
        // read deadline below, which proves that deadline no longer applies.
        let addr = spawn_sse_upstream(3, Duration::from_millis(80), "text/event-stream").await;
        let member = Member::new(addr, 1, None);
        let cfg = streaming_cfg(Duration::from_millis(20));
        let streaming = aegis_core::config::StreamingConfig::default();

        let (resp, mode) = forward(
            &member,
            &cfg,
            Method::GET,
            "/events".parse().unwrap(),
            HeaderMap::new(),
            Bytes::new(),
            &streaming,
            &std::sync::Arc::new(tokio::sync::Semaphore::new(256)),
        )
        .await
        .expect("SSE response must stream, not time out on the read deadline");

        assert_eq!(mode, crate::upstream::streaming::ResponseMode::Streaming);
        assert_eq!(resp.status(), 200);

        use http_body_util::BodyExt;
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("data: 0"), "first event missing: {text:?}");
        assert!(text.contains("data: 2"), "last event missing: {text:?}");
    }

    /// Kill-switch: with `streaming.enabled = false`, even a
    /// `text/event-stream` response is classified Buffered (and would be
    /// subject to the buffered read deadline / size cap as before).
    #[tokio::test]
    async fn streaming_disabled_buffers_event_stream() {
        let _serial = CACHE_LOCK.lock().await;
        super::_reset_client_cache();
        // Fast upstream so the buffered collect completes within the cfg
        // read deadline.
        let addr = spawn_sse_upstream(2, Duration::from_millis(1), "text/event-stream").await;
        let member = Member::new(addr, 1, None);
        let cfg = streaming_cfg(Duration::from_secs(5));
        let streaming = aegis_core::config::StreamingConfig {
            enabled: false,
            ..Default::default()
        };

        let (_resp, mode) = forward(
            &member,
            &cfg,
            Method::GET,
            "/events".parse().unwrap(),
            HeaderMap::new(),
            Bytes::new(),
            &streaming,
            &std::sync::Arc::new(tokio::sync::Semaphore::new(256)),
        )
        .await
        .expect("buffered SSE still succeeds for a fast upstream");

        assert_eq!(
            mode,
            crate::upstream::streaming::ResponseMode::Buffered,
            "kill-switch off must force buffering regardless of media type",
        );
    }

    /// Decision 5 — the concurrency cap. With `max_concurrent = 1`, a
    /// second concurrent stream is shed with 503 (default on_exhaustion =
    /// reject); once the first stream's body is dropped (releasing its
    /// permit + upstream connection) a new stream is admitted again.
    #[tokio::test]
    async fn streaming_cap_rejects_then_recovers() {
        use crate::upstream::streaming::ResponseMode;
        let _serial = CACHE_LOCK.lock().await;
        super::_reset_client_cache();
        let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let cfg = streaming_cfg(Duration::from_secs(5));
        let streaming = aegis_core::config::StreamingConfig::default(); // on_exhaustion: reject

        let call = |addr: std::net::SocketAddr, p: std::sync::Arc<tokio::sync::Semaphore>, s: aegis_core::config::StreamingConfig, c: ConnectionPoolConfig| async move {
            forward(
                &Member::new(addr, 1, None),
                &c,
                Method::GET,
                "/events".parse().unwrap(),
                HeaderMap::new(),
                Bytes::new(),
                &s,
                &p,
            )
            .await
            .expect("forward must return a response")
        };

        // First stream takes the only permit; keep its body alive so the
        // permit stays held.
        let addr1 = spawn_sse_upstream(3, Duration::from_millis(40), "text/event-stream").await;
        let (resp1, mode1) = call(addr1, permits.clone(), streaming.clone(), cfg.clone()).await;
        assert_eq!(mode1, ResponseMode::Streaming);
        let held_body = resp1.into_body();

        // Second stream: cap exhausted → 503, classified Buffered.
        let addr2 = spawn_sse_upstream(3, Duration::from_millis(40), "text/event-stream").await;
        let (resp2, mode2) = call(addr2, permits.clone(), streaming.clone(), cfg.clone()).await;
        assert_eq!(resp2.status(), 503, "2nd stream must be shed when the cap is full");
        assert_eq!(mode2, ResponseMode::Buffered);

        // Release the first stream → permit freed.
        drop(held_body);

        // Third stream is admitted again.
        let addr3 = spawn_sse_upstream(1, Duration::from_millis(10), "text/event-stream").await;
        let (_resp3, mode3) = call(addr3, permits.clone(), streaming.clone(), cfg.clone()).await;
        assert_eq!(
            mode3,
            ResponseMode::Streaming,
            "dropping the first stream's body must free the permit",
        );
    }
}
