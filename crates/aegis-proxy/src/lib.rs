// aegis-proxy: data-plane proxy core (M1)
//
// Owns: listeners, TLS, routing, upstream pools, transforms,
//       state backend impls, service discovery, caching, load shedding.
//
// PRE-T7 — `lib.rs` is now a thin facade. The boot orchestrator
// (`run` + `ConfigReloadSource`) lives in [`run`]; the
// admin/data-plane accept loops in [`accept`]; the request
// dispatch in [`admin_dispatch`]; mutation/get handlers in
// [`admin_mutate`] / [`admin_get`]; the data-plane request
// handler in [`data_plane`]; auth in [`admin_login`]; and
// shared response helpers in [`responses`]. Public API surface
// (`run`, `ConfigReloadSource`) is re-exported below.

pub mod acme;
pub mod acme_instant;
pub mod admin_sse;
pub mod benchmark;
// 2026-05-11 PROXY-08/09 — `cache` module retired. The `TierCache`
// type was implemented + unit-tested but had zero call sites in
// any handler / listener / pipeline. All configured cache tiers
// (hot/warm TTLs, max-size limits) had no effect on live traffic.
// Removed the module + the `moka` dependency. The
// contract's `POST /__waf_control/flush_cache` endpoint stays
// in place returning `{ok: true, supported: false}` per
// v2.3 §9 (caching not operational is an acceptable report).
pub mod cluster;
pub mod cluster_lease;
pub mod config_source;
mod accept;
mod admin_auth_middleware;
mod admin_dispatch;
mod admin_get;
mod admin_login;
mod admin_mutate;
pub mod cache;
mod data_plane;
mod responses;
mod run;
pub use run::{run, ConfigReloadSource};
pub mod dr;
pub mod hotbin;
pub mod listener;
pub mod ocsp;
pub mod proto;
pub mod proxy;
pub mod quota;
pub mod route;
pub mod sd;
pub mod secrets;
pub mod session;
pub mod shed;
pub mod state;
pub mod supervisor;
pub mod tcp_tunnel;
pub mod traffic;
pub mod transform;
pub mod upstream;



#[cfg(test)]
mod tests {
    use crate::accept::accept_loop;
    use crate::admin_login::{process_admin_login, process_admin_logout};
    use crate::responses::{dashboard_response, dashboard_shell_response};
    use crate::run::force_https_loop;
    use aegis_core::config::WafConfig;
    use aegis_core::ReadinessSignal;
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::Response;
    use hyper_util::rt::TokioIo;
    use std::sync::Arc;

    /// Spin up a tokio HTTP/1.1 mock that answers every request
    /// with `200 OK` + `body`. Returns the bound address +
    /// the join handle.
    async fn spawn_mock_upstream(
        body: &'static [u8],
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        use hyper::service::service_fn;
        use std::convert::Infallible;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                let (sock, _) = match listener.accept().await {
                    Ok(c) => c,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let io = TokioIo::new(sock);
                    let svc =
                        service_fn(move |_req: hyper::Request<hyper::body::Incoming>| async move {
                            Ok::<_, Infallible>(
                                hyper::Response::builder()
                                    .status(200)
                                    .body(Full::new(Bytes::from(body)))
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

    #[tokio::test]
    async fn run_binds_and_serves_200() {
        // B4-T3 carry-over A: data plane now actually forwards
        // through `upstream::forward`. Stand up a mock upstream
        // and point the route table at it so the Allow branch
        // returns the upstream's 200, not a synthetic stub.
        let (upstream_addr, _upstream_h) = spawn_mock_upstream(b"upstream-ok").await;
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
    upstream: default
upstreams:
  default:
    members:
      - addr: "{upstream_addr}"
state:
  backend: in_memory
"#
        );
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();

        // We can't use port 0 with the current `run()` because it spawns
        // tasks internally. Instead, bind manually and test the accept loop.
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();

        let detectors: Arc<Vec<Box<dyn aegis_security::detectors::Detector>>> =
            Arc::new(aegis_security::detectors::default_detectors());
        let mask = aegis_security::detectors::SharedDetectorMask::default();
        let risk = aegis_security::risk::RiskTracker::new(
            &aegis_core::config::RiskConfig::default(),
        );
        let ip_rate_limiter = Arc::new(
            aegis_security::rate_limit::IpRateLimiter::new(Default::default()),
        );
        let load_gauge = aegis_core::LoadGauge::new(aegis_core::LoadModeConfig::default());
        let verbosity = aegis_core::SharedVerbosity::default();
        let metrics_reg = aegis_control::metrics::MetricsRegistry::init();
        let request_stage_hist = std::sync::Arc::new(
            aegis_control::metrics::request_duration::RequestStageHistogram::register(&metrics_reg)
                .unwrap(),
        );
        let route_latency_hist = std::sync::Arc::new(
            aegis_control::metrics::route_latency::RouteLatencyHistogram::register(&metrics_reg)
                .unwrap(),
        );
        let detector_latency_hist = std::sync::Arc::new(
            aegis_control::metrics::detector_latency::DetectorLatencyHistogram::register(&metrics_reg)
                .unwrap(),
        );
        let bus = aegis_core::AuditBus::new(64);
        let upstream_ctx = std::sync::Arc::new(
            crate::proxy::ProxyContext::build(
                &cfg,
                std::sync::Arc::new(aegis_security::NoopPipeline),
            )
            .unwrap(),
        );
        let _handle = tokio::spawn(accept_loop(
            tcp,
            detectors,
            mask,
            risk,
            ip_rate_limiter,
            load_gauge,
            verbosity,
            request_stage_hist,
            route_latency_hist,
            aegis_control::metrics::route_activity::RouteActivityWindow::new(),
            detector_latency_hist,
            bus,
            upstream_ctx,
            None, // no tls_acceptor in this plain-http test
            None, // no Alt-Svc advertise_h3 port in this test
            None, // no interop runtime in this plain-http test
            std::sync::Arc::new(
                aegis_control::metrics::decisions::DecisionMetrics::register(&metrics_reg)
                    .unwrap(),
            ),
            std::sync::Arc::new(
                aegis_control::metrics::detector_hits::DetectorHitMetrics::register(&metrics_reg)
                    .unwrap(),
            ),
            None, // MTLS-T3 — no identity tracker in this plain-http test
            // 2026-05-08 NEW-2 — in-memory state backend; the data
            // plane never reaches /__waf_control/challenge_verify
            // in this plain-http test, but accept_loop requires
            // the parameter.
            std::sync::Arc::new(crate::state::InMemoryBackend::new()),
        ));

        // Give the accept loop a moment to start.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect and send a minimal HTTP/1.1 request.
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);

        let req = hyper::Request::builder()
            .uri("/")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), 200);

        // Verify readiness defaults (run() was not called here, just accept_loop)
        let readiness = ReadinessSignal::default();
        assert!(!readiness.is_ready());

        // Verify that a WafConfig with port 0 parses (for the skeleton)
        let _ = cfg;
    }

    // ---------- MTLS-T4 — route-scoped client-identity gate ---------------

    /// Drive `accept_loop` end-to-end with a route that requires
    /// `auth_required: [mtls]`. Plain-HTTP (Anonymous) request
    /// must hit the gate and 403 with `mtls_required` rule_id.
    /// Pulls the same mock-upstream + TCP handshake pattern
    /// as `run_binds_and_serves_200`.
    #[tokio::test]
    async fn anonymous_request_to_mtls_required_route_returns_403() {
        let (upstream_addr, _upstream_h) = spawn_mock_upstream(b"upstream-ok").await;
        let yaml = format!(
            r#"
listeners:
  data:
    - bind: "127.0.0.1:0"
  admin:
    bind: "127.0.0.1:0"
routes:
  - id: secure
    path: "/"
    upstream: default
    auth_required: ["mtls"]
upstreams:
  default:
    members:
      - addr: "{upstream_addr}"
state:
  backend: in_memory
"#
        );
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();

        let detectors: Arc<Vec<Box<dyn aegis_security::detectors::Detector>>> =
            Arc::new(aegis_security::detectors::default_detectors());
        let mask = aegis_security::detectors::SharedDetectorMask::default();
        let risk = aegis_security::risk::RiskTracker::new(
            &aegis_core::config::RiskConfig::default(),
        );
        let ip_rate_limiter = Arc::new(
            aegis_security::rate_limit::IpRateLimiter::new(Default::default()),
        );
        let load_gauge = aegis_core::LoadGauge::new(aegis_core::LoadModeConfig::default());
        let verbosity = aegis_core::SharedVerbosity::default();
        let metrics_reg = aegis_control::metrics::MetricsRegistry::init();
        let request_stage_hist = std::sync::Arc::new(
            aegis_control::metrics::request_duration::RequestStageHistogram::register(&metrics_reg)
                .unwrap(),
        );
        let route_latency_hist = std::sync::Arc::new(
            aegis_control::metrics::route_latency::RouteLatencyHistogram::register(&metrics_reg)
                .unwrap(),
        );
        let detector_latency_hist = std::sync::Arc::new(
            aegis_control::metrics::detector_latency::DetectorLatencyHistogram::register(&metrics_reg)
                .unwrap(),
        );
        let bus = aegis_core::AuditBus::new(64);
        let upstream_ctx = std::sync::Arc::new(
            crate::proxy::ProxyContext::build(
                &cfg,
                std::sync::Arc::new(aegis_security::NoopPipeline),
            )
            .unwrap(),
        );
        let _handle = tokio::spawn(accept_loop(
            tcp,
            detectors,
            mask,
            risk,
            ip_rate_limiter,
            load_gauge,
            verbosity,
            request_stage_hist,
            route_latency_hist,
            aegis_control::metrics::route_activity::RouteActivityWindow::new(),
            detector_latency_hist,
            bus,
            upstream_ctx,
            None,
            None, // no Alt-Svc advertise_h3 port in this test
            None,
            std::sync::Arc::new(
                aegis_control::metrics::decisions::DecisionMetrics::register(&metrics_reg)
                    .unwrap(),
            ),
            std::sync::Arc::new(
                aegis_control::metrics::detector_hits::DetectorHitMetrics::register(&metrics_reg)
                    .unwrap(),
            ),
            None, // MTLS-T3 — no identity tracker for this test
            // 2026-05-08 NEW-2 — in-memory state for accept_loop
            std::sync::Arc::new(crate::state::InMemoryBackend::new()),
        ));

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);

        let req = hyper::Request::builder()
            .uri("/")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        // Plain HTTP → connection identity stays Anonymous;
        // route requires `mtls`; the policy gate must return
        // 403 before the upstream is touched.
        assert_eq!(
            resp.status(),
            403,
            "anonymous request to mtls-required route must be rejected",
        );
    }

    // ---------- P4 force-HTTPS redirect loop ------------------------------

    #[tokio::test]
    async fn force_https_loop_returns_301_with_https_location() {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let challenges = crate::acme::ChallengeStore::new();
        let _handle = tokio::spawn(force_https_loop(tcp, 301, challenges));

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);

        let req = hyper::Request::builder()
            .uri("/api/secret?x=1")
            .header("host", "shop.example.com")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status().as_u16(), 301);
        let loc = resp.headers().get("location").unwrap().to_str().unwrap();
        assert_eq!(loc, "https://shop.example.com/api/secret?x=1");
    }

    #[tokio::test]
    async fn force_https_loop_honours_308_status() {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let challenges = crate::acme::ChallengeStore::new();
        let _handle = tokio::spawn(force_https_loop(tcp, 308, challenges));

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);

        let req = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri("/")
            .header("host", "api.example.com")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status().as_u16(), 308);
    }

    // ---------- P5 ACME HTTP-01 challenge responder -----------------------

    #[tokio::test]
    async fn force_https_loop_serves_http01_challenge_when_token_published() {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let challenges = crate::acme::ChallengeStore::new();
        challenges.insert("acme-tok-1".into(), "acme-tok-1.thumb".into());
        let _handle = tokio::spawn(force_https_loop(tcp, 301, challenges));

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);

        let req = hyper::Request::builder()
            .uri("/.well-known/acme-challenge/acme-tok-1")
            .header("host", "shop.example.com")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        use http_body_util::BodyExt;
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], b"acme-tok-1.thumb");
    }

    #[tokio::test]
    async fn force_https_loop_returns_404_for_unknown_acme_token() {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let challenges = crate::acme::ChallengeStore::new();
        let _handle = tokio::spawn(force_https_loop(tcp, 301, challenges));

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);

        let req = hyper::Request::builder()
            .uri("/.well-known/acme-challenge/missing")
            .header("host", "shop.example.com")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        // ACME directory expects a definitive 404, not a redirect.
        assert_eq!(resp.status().as_u16(), 404);
    }

    // ---------- D-M1-T1.5 dashboard security headers ---------------------

    use aegis_control::dashboard::dispatch::{dispatch, DashboardResponse};
    use aegis_control::dashboard::security::SECURITY_HEADERS;

    /// Every header in SECURITY_HEADERS must appear on the response,
    /// with the canonical value.
    fn assert_security_headers(headers: &hyper::HeaderMap) {
        for (name, value) in SECURITY_HEADERS {
            let got = headers.get(*name).unwrap_or_else(|| {
                panic!("missing security header {name}");
            });
            assert_eq!(
                got.to_str().unwrap_or(""),
                *value,
                "wrong value for {name}"
            );
        }
    }

    #[test]
    fn dashboard_shell_response_carries_security_headers() {
        let resp = dashboard_shell_response(false);
        assert_eq!(resp.status(), 200);
        assert_security_headers(resp.headers());
    }

    // ---------- F-T1 admin login + logout end-to-end --------------------

    /// Build a `DashboardServices` with a real argon2id-hashed
    /// admin so the login handler can succeed.
    fn services_with_admin(
        password: &str,
    ) -> std::sync::Arc<aegis_control::dashboard_services::DashboardServices> {
        use aegis_control::admin_auth::password::hash_password;
        use aegis_control::admin_auth::rate_limit::LoginRateLimiter;
        use aegis_control::admin_auth::session::SessionStore as AuthSessionStore;
        use aegis_control::api::login::{derive_session_key, AdminIdentity};

        let bus = aegis_core::AuditBus::new(8);
        let pool = std::sync::Arc::new(|| {
            aegis_control::api::upstreams::PoolHealthSnapshot { pools: Vec::new() }
        });
        let identity = std::sync::Arc::new(AdminIdentity {
            user: "admin".into(),
            password_hash: hash_password(password).unwrap(),
            ..AdminIdentity::default()
        });
        let key = derive_session_key("test-secret-32b");
        let auth_sessions = std::sync::Arc::new(AuthSessionStore::new(key));
        let rate_limiter =
            std::sync::Arc::new(LoginRateLimiter::new(Default::default()));
        let (services, _drain) = aegis_control::dashboard_services::DashboardServices::spawn_with_mask(
            bus,
            pool,
            None,
            aegis_security::detectors::SharedDetectorMask::default(),
            aegis_security::risk::RiskTracker::new(
                &aegis_core::config::RiskConfig::default(),
            ),
            std::sync::Arc::new(
                aegis_security::rate_limit::IpRateLimiter::new(Default::default()),
            ),
            aegis_core::LoadGauge::new(aegis_core::LoadModeConfig::default()),
            aegis_core::SharedVerbosity::default(),
            auth_sessions,
            rate_limiter,
            identity,
            1800,
        );
        std::sync::Arc::new(services)
    }

    #[tokio::test]
    async fn login_handler_issues_two_set_cookies_on_success() {
        let services = services_with_admin("test-pw-1234");
        let body = serde_json::json!({"user":"admin","password":"test-pw-1234"})
            .to_string();
        let resp = process_admin_login(
            &services,
            "127.0.0.1:54321".parse().unwrap(),
            "test-ua/1.0",
            body.as_bytes(),
        ).await;
        assert_eq!(resp.status().as_u16(), 200);
        let cookies: Vec<&str> = resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|h| h.to_str().ok())
            .collect();
        assert_eq!(cookies.len(), 2, "expected aegis_session + aegis_csrf");
        assert!(
            cookies.iter().any(|c| c.starts_with("aegis_session=")),
            "session cookie missing: {cookies:?}",
        );
        assert!(
            cookies.iter().any(|c| c.starts_with("aegis_csrf=")),
            "csrf cookie missing: {cookies:?}",
        );
        // Cache-Control: no-store on every credential-handling response.
        assert_eq!(
            resp.headers().get("cache-control").unwrap(),
            "no-store",
        );
    }

    #[tokio::test]
    async fn login_handler_returns_401_on_wrong_password() {
        let services = services_with_admin("right");
        let body = serde_json::json!({"user":"admin","password":"wrong"}).to_string();
        let resp = process_admin_login(
            &services,
            "127.0.0.1:0".parse().unwrap(),
            "ua",
            body.as_bytes(),
        ).await;
        assert_eq!(resp.status().as_u16(), 401);
    }

    #[tokio::test]
    async fn login_handler_returns_400_on_invalid_json() {
        let services = services_with_admin("right");
        let resp = process_admin_login(
            &services,
            "127.0.0.1:0".parse().unwrap(),
            "ua",
            b"not json",
        ).await;
        assert_eq!(resp.status().as_u16(), 400);
    }

    #[tokio::test]
    async fn logout_handler_clears_both_cookies_after_login() {
        let services = services_with_admin("test-pw-1234");
        let body = serde_json::json!({"user":"admin","password":"test-pw-1234"})
            .to_string();
        let login_resp = process_admin_login(
            &services,
            "127.0.0.1:0".parse().unwrap(),
            "ua",
            body.as_bytes(),
        ).await;
        assert_eq!(login_resp.status().as_u16(), 200);

        // Pull the signed session cookie value back out so logout
        // can validate it.
        let session_cookie_str = login_resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|h| h.to_str().ok())
            .find(|c| c.starts_with("aegis_session="))
            .unwrap()
            .to_string();
        let session_value = session_cookie_str
            .strip_prefix("aegis_session=")
            .and_then(|s| s.split(';').next())
            .unwrap();

        let resp = process_admin_logout(&services, Some(session_value)).await;
        assert_eq!(resp.status().as_u16(), 204);
        let clears: Vec<&str> = resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|h| h.to_str().ok())
            .collect();
        assert_eq!(clears.len(), 2);
        assert!(
            clears.iter().all(|c| c.contains("Max-Age=0")),
            "logout must clear both cookies, got {clears:?}",
        );
        // Auth session is gone — no more accepting that cookie.
        assert_eq!(services.auth_sessions.active_count().await, 0);
    }

    #[tokio::test]
    async fn logout_handler_is_idempotent_without_cookie() {
        let services = services_with_admin("test-pw-1234");
        let resp = process_admin_logout(&services, None).await;
        // Same 204 + cookie-clearing whether or not a session
        // existed — caller never has to know.
        assert_eq!(resp.status().as_u16(), 204);
        assert_eq!(resp.headers().get_all("set-cookie").iter().count(), 2);
    }

    #[test]
    fn dashboard_asset_response_carries_security_headers() {
        let r = dispatch("/dashboard/assets/app.js")
            .expect("known asset must resolve");
        let resp = match r {
            DashboardResponse::Asset(_) => dashboard_response(r, false),
            _ => panic!("expected Asset"),
        };
        assert_eq!(resp.status(), 200);
        assert_security_headers(resp.headers());
    }

    #[test]
    fn dashboard_asset_not_found_carries_security_headers() {
        // 404s also need the headers — a missing asset must not become
        // a CSP-bypass vector.
        let r = dispatch("/dashboard/assets/missing.js")
            .expect("must dispatch");
        let resp = dashboard_response(r, false);
        assert_eq!(resp.status(), 404);
        assert_security_headers(resp.headers());
    }

    // ---------- D-M1-T1.6 legacy shell flag ------------------------------

    async fn body_string(resp: Response<Full<Bytes>>) -> String {
        use http_body_util::BodyExt;
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn dashboard_shell_response_default_serves_spa_shell() {
        // DD-T1: the redesign mounts at #root via React 18.
        let resp = dashboard_shell_response(false);
        assert_eq!(resp.status(), 200);
        let body = body_string(resp).await;
        assert!(
            body.contains(r#"id="root""#),
            "default shell must be the new SPA"
        );
    }

    #[tokio::test]
    async fn dashboard_shell_response_legacy_now_returns_spa() {
        // D-M6-T6.9 removed the legacy shell. The legacy flag is a
        // no-op for back-compat — every shell response is now the SPA.
        let resp = dashboard_shell_response(true);
        assert_eq!(resp.status(), 200);
        let body = body_string(resp).await;
        assert!(
            body.contains(r#"id="root""#),
            "legacy flag must now return the SPA shell"
        );
    }

    #[test]
    fn dashboard_shell_response_legacy_keeps_security_headers() {
        // The legacy shell still goes through the security-header
        // middleware — the toggle must not become a header bypass.
        let resp = dashboard_shell_response(true);
        assert_security_headers(resp.headers());
    }
}
