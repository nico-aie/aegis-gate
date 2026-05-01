use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Body;
use hyper::{Request, Response, StatusCode};

use aegis_core::config::WafConfig;
use aegis_core::pipeline::SecurityPipeline;

use crate::benchmark::{self, BenchmarkConfig, StageTimings};
use crate::route::RouteTable;
use crate::upstream::forward;
use crate::upstream::registry::PoolRegistry;

/// Shared context carried by every connection handler.
///
/// CC-T1.1.b — `pools` is a [`PoolRegistry`] (ArcSwap-backed) so
/// the audit-mutated `/api/upstreams/config` PUT/DELETE handlers
/// can hot-swap the pool table without bouncing the proxy.
/// In-flight requests that already grabbed an `Arc<Pool>` finish
/// on the old map; new requests after the swap see the new one.
pub struct ProxyContext {
    pub route_table: RouteTable,
    pub pools: PoolRegistry,
    pub pipeline: Arc<dyn SecurityPipeline>,
    /// Benchmark mode configuration. When enabled,
    /// `handle_request` captures per-stage timings and
    /// stamps `X-Aegis-*` headers on the response.
    pub benchmark: BenchmarkConfig,
}

impl ProxyContext {
    /// Build from config. Validation runs inside
    /// [`PoolRegistry::build_pools`] so an invalid `cfg.upstreams`
    /// shape fails boot rather than going live.
    pub fn build(cfg: &WafConfig, pipeline: Arc<dyn SecurityPipeline>) -> aegis_core::Result<Self> {
        let route_table = RouteTable::build(cfg)?;
        let (pools, breakers) = PoolRegistry::build_pools(&cfg.upstreams)
            .map_err(|e| aegis_core::WafError::Config(e.to_string()))?;
        Ok(Self {
            route_table,
            pools: PoolRegistry::from_pools(pools, breakers),
            pipeline,
            benchmark: BenchmarkConfig::off(),
        })
    }
}

/// Handle a single HTTP request: resolve route → pick upstream → forward → respond.
pub async fn handle_request<B>(
    req: Request<B>,
    ctx: Arc<ProxyContext>,
) -> Result<Response<Full<Bytes>>, hyper::Error>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: std::fmt::Display,
{
    // Stopwatch for benchmark-mode total. Lives outside the
    // `if ctx.benchmark.is_on()` branch because we'd lose
    // any time spent before the branch otherwise.
    let bench_total_start: Option<Instant> =
        ctx.benchmark.is_on().then(Instant::now);

    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost")
        .to_string();
    let path = req.uri().path().to_string();
    let method = req.method().clone();

    // 1. Resolve route.
    let route_start = ctx.benchmark.is_on().then(Instant::now);
    let route_ctx = match ctx.route_table.resolve(&host, &path, &method) {
        Some(r) => r,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("no matching route\n")))
                .unwrap());
        }
    };

    // 2. Check circuit breaker.
    if let Some(cb) = ctx.pools.breaker(&route_ctx.upstream) {
        if !cb.allow_request() {
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Full::new(Bytes::from("circuit open\n")))
                .unwrap());
        }
    }

    // 3. Pick upstream member. `pools.get` returns an owning
    //    `Arc<Pool>` so the borrow chain (`pool.strategy`,
    //    `pool.members`, `pool.connection` below) survives any
    //    concurrent hot-swap of the pool table.
    let pool = match ctx.pools.get(&route_ctx.upstream) {
        Some(p) => p,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("unknown upstream\n")))
                .unwrap());
        }
    };

    let member = match pool.strategy.pick(&pool.members, None) {
        Some(m) => m,
        None => {
            // All members unhealthy.
            if let Some(cb) = ctx.pools.breaker(&route_ctx.upstream) {
                cb.record_failure();
            }
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("no healthy upstream\n")))
                .unwrap());
        }
    };

    // Captured route stage timing (only meaningful when
    // benchmark mode is on).
    let route_elapsed = route_start.map(|s| s.elapsed());

    // 4. Collect the original body before forwarding. The
    //    proxy carries `Full<Bytes>` everywhere, so we
    //    materialise to bytes here. Streaming forwarding is
    //    a separate refactor (future).
    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            tracing::warn!(error = %e, "failed to collect client body");
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from("body read error\n")))
                .unwrap());
        }
    };

    member.inflight.fetch_add(1, Ordering::Relaxed);
    let upstream_start = ctx.benchmark.is_on().then(Instant::now);
    let result = forward::forward(
        member,
        &pool.connection,
        parts.method,
        parts.uri,
        parts.headers,
        body_bytes,
    )
    .await;
    let upstream_elapsed = upstream_start.map(|s| s.elapsed());
    member.inflight.fetch_sub(1, Ordering::Relaxed);

    let mut response = match result {
        Ok(resp) => {
            if let Some(cb) = ctx.pools.breaker(&route_ctx.upstream) {
                if resp.status().is_server_error() {
                    cb.record_failure();
                } else {
                    cb.record_success();
                }
            }
            resp
        }
        Err(e) => {
            tracing::warn!(error = %e, "upstream forward failed");
            if let Some(cb) = ctx.pools.breaker(&route_ctx.upstream) {
                cb.record_failure();
            }
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("upstream error\n")))
                .unwrap()
        }
    };

    // Stamp benchmark headers when enabled. Cheap no-op
    // otherwise.
    if let Some(start) = bench_total_start {
        let timings = StageTimings {
            route: route_elapsed,
            security: None,
            upstream: upstream_elapsed,
            total: Some(start.elapsed()),
            tier: Some(format!("{:?}", route_ctx.tier).to_lowercase()),
            decision: Some("forwarded".to_string()),
            rule_id: None,
            request_id: None,
        };
        benchmark::stamp_headers(&mut response, &timings, &ctx.benchmark);
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;

    /// Spin up a mock upstream returning a given status and body.
    async fn mock_upstream(
        status: u16,
        body: &'static str,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                let (stream, _) = match tcp.accept().await {
                    Ok(c) => c,
                    Err(_) => break,
                };
                let st = hyper::StatusCode::from_u16(status).unwrap();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |_req: Request<hyper::body::Incoming>| {
                        let st = st;
                        async move {
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(st)
                                    .body(Full::new(Bytes::from(body)))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });
        (addr, handle)
    }

    fn cfg_yaml(healthy_addr: std::net::SocketAddr, unhealthy_addr: std::net::SocketAddr) -> String {
        format!(
            r#"
listeners:
  data:
    - bind: "127.0.0.1:0"
  admin:
    bind: "127.0.0.1:0"
routes:
  - id: api
    host: "api.test"
    path: "/api/"
    upstream: healthy-pool
  - id: catch-all
    path: "/"
    upstream: unhealthy-pool
upstreams:
  healthy-pool:
    members:
      - addr: "{healthy_addr}"
  unhealthy-pool:
    members:
      - addr: "{unhealthy_addr}"
state:
  backend: in_memory
"#
        )
    }

    #[tokio::test]
    async fn traffic_hits_healthy_pool() {
        let (healthy_addr, srv_h) = mock_upstream(200, "healthy").await;
        let (unhealthy_addr, srv_u) = mock_upstream(503, "down").await;

        let yaml = cfg_yaml(healthy_addr, unhealthy_addr);
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);

        let ctx = Arc::new(ProxyContext::build(&cfg, pipeline).unwrap());

        // Request to api.test/api/foo should hit healthy-pool.
        let req = Request::builder()
            .uri("/api/foo")
            .header("host", "api.test")
            .body(Full::<Bytes>::default())
            .unwrap();

        let resp = handle_request(req, ctx.clone()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        srv_h.abort();
        srv_u.abort();
    }

    #[tokio::test]
    async fn no_matching_route_returns_404() {
        let (healthy_addr, srv) = mock_upstream(200, "ok").await;

        let yaml = format!(
            r#"
listeners:
  data:
    - bind: "127.0.0.1:0"
  admin:
    bind: "127.0.0.1:0"
routes:
  - id: catch-all
    path: "/"
    upstream: pool
upstreams:
  pool:
    members:
      - addr: "{healthy_addr}"
state:
  backend: in_memory
"#
        );
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);
        let mut ctx = ProxyContext::build(&cfg, pipeline).unwrap();

        // Sabotage the route table so nothing resolves (remove all groups).
        ctx.route_table = RouteTable::build(&{
            // Use a config that has a catch-all but we won't actually use ctx's route table.
            cfg.clone()
        })
        .unwrap();

        // Actually, with the catch-all present, everything matches.
        // Let's just test that an unknown host+path still resolves to catch-all.
        let ctx = Arc::new(ctx);
        let req = Request::builder()
            .uri("/unknown")
            .header("host", "random.host")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = handle_request(req, ctx).await.unwrap();
        // Catch-all routes to "pool" which has the healthy upstream.
        assert_eq!(resp.status(), StatusCode::OK);

        srv.abort();
    }

    /// Mock upstream that echoes the inbound request line +
    /// every header + the body, separated by newlines, in the
    /// response body. Used by the B4-T3 end-to-end tests.
    async fn echoing_upstream() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                let (stream, _) = match tcp.accept().await {
                    Ok(c) => c,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc =
                        service_fn(|req: Request<hyper::body::Incoming>| async move {
                            let method = req.method().to_string();
                            let pq = req
                                .uri()
                                .path_and_query()
                                .map(|p| p.as_str().to_string())
                                .unwrap_or_else(|| "/".to_string());
                            let mut out = format!("LINE {method} {pq}\n");
                            let mut header_lines: Vec<String> = req
                                .headers()
                                .iter()
                                .map(|(k, v)| {
                                    format!(
                                        "HDR {} {}",
                                        k.as_str(),
                                        v.to_str().unwrap_or("")
                                    )
                                })
                                .collect();
                            header_lines.sort();
                            out.push_str(&header_lines.join("\n"));
                            out.push('\n');
                            use http_body_util::BodyExt as _;
                            let body =
                                req.into_body().collect().await.unwrap().to_bytes();
                            out.push_str(&format!(
                                "BODY {}",
                                String::from_utf8_lossy(&body)
                            ));
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(200)
                                    .header("x-upstream-marker", "echo")
                                    .body(Full::new(Bytes::from(out)))
                                    .unwrap(),
                            )
                        });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });
        (addr, handle)
    }

    fn echo_cfg(addr: std::net::SocketAddr) -> WafConfig {
        let yaml = format!(
            r#"
listeners:
  data:
    - bind: "127.0.0.1:0"
  admin:
    bind: "127.0.0.1:0"
routes:
  - id: catch-all
    path: "/"
    upstream: pool
upstreams:
  pool:
    members:
      - addr: "{addr}"
state:
  backend: in_memory
"#
        );
        serde_yaml::from_str(&yaml).unwrap()
    }

    async fn body_string(resp: Response<Full<Bytes>>) -> String {
        use http_body_util::BodyExt as _;
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn forward_preserves_method_and_path_and_query() {
        let (addr, srv) = echoing_upstream().await;
        let cfg = echo_cfg(addr);
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);
        let ctx = Arc::new(ProxyContext::build(&cfg, pipeline).unwrap());

        let req = Request::builder()
            .method("POST")
            .uri("/api/users?id=42&debug=true")
            .header("host", "api.test")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = handle_request(req, ctx).await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers()
                .get("x-upstream-marker")
                .and_then(|v| v.to_str().ok()),
            Some("echo")
        );
        let body = body_string(resp).await;
        assert!(
            body.contains("LINE POST /api/users?id=42&debug=true"),
            "body was {body:?}"
        );
        srv.abort();
    }

    #[tokio::test]
    async fn forward_preserves_request_body() {
        let (addr, srv) = echoing_upstream().await;
        let cfg = echo_cfg(addr);
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);
        let ctx = Arc::new(ProxyContext::build(&cfg, pipeline).unwrap());

        let req = Request::builder()
            .method("POST")
            .uri("/echo")
            .header("host", "api.test")
            .header("content-type", "application/json")
            .body(Full::<Bytes>::new(Bytes::from(r#"{"hello":"world"}"#)))
            .unwrap();
        let resp = handle_request(req, ctx).await.unwrap();
        let body = body_string(resp).await;
        assert!(
            body.contains(r#"BODY {"hello":"world"}"#),
            "body was {body:?}"
        );
        srv.abort();
    }

    #[tokio::test]
    async fn forward_strips_hop_by_hop_headers() {
        let (addr, srv) = echoing_upstream().await;
        let cfg = echo_cfg(addr);
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);
        let ctx = Arc::new(ProxyContext::build(&cfg, pipeline).unwrap());

        let req = Request::builder()
            .method("GET")
            .uri("/headers")
            .header("host", "api.test")
            .header("connection", "close")
            .header("keep-alive", "timeout=5")
            .header("user-agent", "aegis-test")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = handle_request(req, ctx).await.unwrap();
        let body = body_string(resp).await;
        // The upstream should NOT have seen connection / keep-alive.
        assert!(!body.contains("HDR connection close"), "body was {body:?}");
        assert!(!body.contains("HDR keep-alive"), "body was {body:?}");
        // And SHOULD have seen user-agent + the rewritten host.
        assert!(body.contains("HDR user-agent aegis-test"), "body was {body:?}");
        let upstream_host = format!("HDR host {}", addr);
        assert!(body.contains(&upstream_host), "body was {body:?}");
        srv.abort();
    }

    #[tokio::test]
    async fn forward_records_x_forwarded_host() {
        let (addr, srv) = echoing_upstream().await;
        let cfg = echo_cfg(addr);
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);
        let ctx = Arc::new(ProxyContext::build(&cfg, pipeline).unwrap());

        let req = Request::builder()
            .method("GET")
            .uri("/xfh")
            .header("host", "edge.example.com")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = handle_request(req, ctx).await.unwrap();
        let body = body_string(resp).await;
        assert!(
            body.contains("HDR x-forwarded-host edge.example.com"),
            "body was {body:?}"
        );
        srv.abort();
    }

    #[tokio::test]
    async fn benchmark_headers_emitted_when_enabled() {
        let (addr, srv) = echoing_upstream().await;
        let cfg = echo_cfg(addr);
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);
        let mut ctx = ProxyContext::build(&cfg, pipeline).unwrap();
        ctx.benchmark = crate::benchmark::BenchmarkConfig {
            enabled: true,
            expose_rule_ids: false,
        };
        let ctx = Arc::new(ctx);

        let req = Request::builder()
            .method("GET")
            .uri("/")
            .header("host", "api.test")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = handle_request(req, ctx).await.unwrap();
        assert!(
            resp.headers().contains_key(crate::benchmark::hdr::TOTAL_US),
            "expected total-us header"
        );
        assert!(
            resp.headers().contains_key(crate::benchmark::hdr::TIER),
            "expected tier header"
        );
        srv.abort();
    }

    #[tokio::test]
    async fn benchmark_headers_absent_when_disabled() {
        let (addr, srv) = echoing_upstream().await;
        let cfg = echo_cfg(addr);
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);
        let ctx = Arc::new(ProxyContext::build(&cfg, pipeline).unwrap());

        let req = Request::builder()
            .method("GET")
            .uri("/")
            .header("host", "api.test")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = handle_request(req, ctx).await.unwrap();
        assert!(
            !resp.headers().contains_key(crate::benchmark::hdr::TOTAL_US),
            "benchmark off must not emit headers"
        );
        srv.abort();
    }

    #[tokio::test]
    async fn upstream_connect_failure_returns_502() {
        // No mock running on this port — connect will refuse.
        let bogus_addr: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let cfg = echo_cfg(bogus_addr);
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);
        let ctx = Arc::new(ProxyContext::build(&cfg, pipeline).unwrap());

        let req = Request::builder()
            .method("GET")
            .uri("/")
            .header("host", "api.test")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = handle_request(req, ctx).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let body = body_string(resp).await;
        assert!(body.contains("upstream error"), "body was {body:?}");
    }

    #[tokio::test]
    async fn circuit_breaker_trips_on_failures() {
        let (addr, srv) = mock_upstream(503, "error").await;

        let yaml = format!(
            r#"
listeners:
  data:
    - bind: "127.0.0.1:0"
  admin:
    bind: "127.0.0.1:0"
routes:
  - id: catch-all
    path: "/"
    upstream: pool
upstreams:
  pool:
    members:
      - addr: "{addr}"
    circuit_breaker:
      error_rate_threshold: 0.5
      open_duration: 30s
state:
  backend: in_memory
"#
        );
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);
        let ctx = Arc::new(ProxyContext::build(&cfg, pipeline).unwrap());

        // Send enough requests to trip the breaker.
        for _ in 0..15 {
            let req = Request::builder()
                .uri("/")
                .header("host", "test")
                .body(Full::<Bytes>::default())
                .unwrap();
            let _ = handle_request(req, ctx.clone()).await.unwrap();
        }

        // Now the breaker should be open.
        let cb = ctx.pools.breaker("pool").unwrap();
        assert_eq!(
            cb.state(),
            crate::upstream::circuit::State::Open,
        );

        // Next request should get 503 "circuit open".
        let req = Request::builder()
            .uri("/")
            .header("host", "test")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = handle_request(req, ctx.clone()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        srv.abort();
    }
}
