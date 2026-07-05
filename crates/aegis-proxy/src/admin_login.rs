//! PRE-T4 — `/admin/login`, `/admin/logout` handlers extracted
//! from `lib.rs` into a focused module.
//!
//! Four functions form the auth surface:
//!
//! - [`handle_admin_login`] / [`handle_admin_logout`] — the
//!   hyper-shaped wrappers that route reaches via dispatch
//!   (`POST /admin/login` / `POST /admin/logout`). They collect
//!   the body / extract the session cookie and delegate to the
//!   pure body-shaped helpers below.
//! - [`process_admin_login`] / [`process_admin_logout`] — pure
//!   bodies, no `Incoming`. Unit tests in `lib.rs::tests` drive
//!   these directly without faking a TCP body.
//!
//! `pub(crate)` visibility for all four — the dispatch in
//! `lib.rs` and the existing login tests both reach in via
//! `crate::admin_login::...`.

use bytes::Bytes;
use http_body_util::Full;
use hyper::Response;

use crate::responses::{extract_named_cookie, json_body_response};


/// FIX 2026-05-03 — GET `/admin/login` — render the login page.
///
/// Prior to this commit the server only handled `POST /admin/login`
/// (the JSON authenticate endpoint).  The dashboard SPA's CSRF
/// interceptor + the explicit logout button both navigate the
/// browser to `/admin/login`, but a GET there returned a JSON
/// `{"error":"not found"}` 404 — the operator saw "page not found"
/// with no way to re-authenticate.  This handler serves the
/// embedded `login.html`, which loads `/admin/login.js` (handled
/// by [`handle_admin_login_js`] below) for the form-submit logic.
///
/// The page honours `?next=<path>` so callers can preserve the
/// intended destination across re-auth (the JS validates it stays
/// same-origin before navigating).
pub(crate) fn handle_admin_login_page() -> Response<Full<Bytes>> {
    static LOGIN_HTML: &[u8] = include_bytes!("assets/login.html");
    crate::responses::apply_dashboard_security_headers(
        Response::builder()
            .status(200)
            .header("content-type", "text/html; charset=utf-8")
            .header("cache-control", "no-store"),
    )
    .body(Full::new(Bytes::from_static(LOGIN_HTML)))
    .unwrap()
}

/// FIX 2026-05-03 — GET `/admin/login.js` — the login page's
/// form-submit client.  Lives at this path so CSP `script-src
/// 'self'` covers it without an inline-script hash.  Same
/// dashboard security headers as the page itself.
pub(crate) fn handle_admin_login_js() -> Response<Full<Bytes>> {
    static LOGIN_JS: &[u8] = include_bytes!("assets/login.js");
    crate::responses::apply_dashboard_security_headers(
        Response::builder()
            .status(200)
            .header("content-type", "application/javascript; charset=utf-8")
            .header("cache-control", "no-store"),
    )
    .body(Full::new(Bytes::from_static(LOGIN_JS)))
    .unwrap()
}

pub(crate) async fn handle_admin_login(
    req: hyper::Request<hyper::body::Incoming>,
    peer: std::net::SocketAddr,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let user_agent = req
        .headers()
        .get(hyper::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return json_body_response(
                400,
                serde_json::json!({"ok":false,"reason":"bad_request",
                                   "message":"failed to read request body"})
                    .to_string(),
                "private, no-store",
            );
        }
    };
    process_admin_login(services, peer, &user_agent, body_bytes.as_ref()).await
}

/// Pure body of the login handler — no `Incoming`, so unit
/// tests can drive it without faking a TCP body. The async
/// wrapper above just collects the body and delegates here.
pub(crate) async fn process_admin_login(
    services: &aegis_control::dashboard_services::DashboardServices,
    peer: std::net::SocketAddr,
    user_agent: &str,
    body_bytes: &[u8],
) -> Response<Full<Bytes>> {
    let body_str = std::str::from_utf8(body_bytes).unwrap_or("");
    let outcome = aegis_control::api::login::authenticate(
        body_str,
        &services.admin_directory,
        &services.login_rate_limiter,
        &services.auth_sessions,
        &services.sessions,
        &peer.ip().to_string(),
        user_agent,
        services.session_idle_seconds,
    ).await;

    // AU-1 — every real auth attempt leaves an Access-class trail.
    // BadRequest is excluded: a garbage body carries no credentials,
    // so there's nothing to audit (and nothing worth flooding over).
    let ip = peer.ip().to_string();
    use aegis_control::api::login::LoginOutcome;
    match &outcome {
        LoginOutcome::Ok { user, .. } => {
            // TOTP-1 — audit the account that actually authenticated,
            // not a hard-coded single-admin name.
            services.login_auditor.record_success(&ip, user);
        }
        LoginOutcome::Unauthorized { .. } => {
            services
                .login_auditor
                .record_failure(&ip, None, "invalid_credentials");
        }
        LoginOutcome::RateLimited { locked_out, .. } => {
            let reason = if *locked_out { "locked_out" } else { "rate_limited" };
            services.login_auditor.record_failure(&ip, None, reason);
        }
        LoginOutcome::StoreUnavailable { .. } => {
            // Credentials were RIGHT — the session store failed.
            // High-value ops signal, distinct bucket.
            services
                .login_auditor
                .record_failure(&ip, None, "store_unavailable");
        }
        LoginOutcome::BadRequest { .. } => {}
    }

    match outcome {
        LoginOutcome::Ok {
            session_cookie,
            csrf_cookie,
            body,
            ..
        } => Response::builder()
            .status(200)
            .header("content-type", "application/json; charset=utf-8")
            .header("cache-control", "no-store")
            .header("set-cookie", session_cookie)
            .header("set-cookie", csrf_cookie)
            .body(Full::new(Bytes::from(body)))
            .unwrap(),
        LoginOutcome::Unauthorized { body } => {
            json_body_response(401, body, "no-store")
        }
        LoginOutcome::RateLimited {
            retry_after_seconds,
            body,
            ..
        } => Response::builder()
            .status(429)
            .header("content-type", "application/json; charset=utf-8")
            .header("cache-control", "no-store")
            .header("retry-after", retry_after_seconds.to_string())
            .body(Full::new(Bytes::from(body)))
            .unwrap(),
        LoginOutcome::BadRequest { body } => {
            json_body_response(400, body, "no-store")
        }
        // R-1 (2026-06-19) — credentials OK but the session store write failed
        // (read-only / down Redis). 503 so the operator retries instead of
        // looping on a silently-unstored session.
        LoginOutcome::StoreUnavailable { body } => {
            json_body_response(503, body, "no-store")
        }
    }
}

pub(crate) async fn handle_admin_logout(
    req: hyper::Request<hyper::body::Incoming>,
    peer: std::net::SocketAddr,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let cookie_value = req
        .headers()
        .get_all(hyper::header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|raw| extract_named_cookie(raw, "aegis_session"))
        .map(|s| s.to_string());
    process_admin_logout(services, peer, cookie_value.as_deref()).await
}

/// Pure body of logout — same testability story as
/// [`process_admin_login`].
pub(crate) async fn process_admin_logout(
    services: &aegis_control::dashboard_services::DashboardServices,
    peer: std::net::SocketAddr,
    session_cookie: Option<&str>,
) -> Response<Full<Bytes>> {
    let outcome = aegis_control::api::login::logout(
        session_cookie,
        &services.auth_sessions,
        &services.sessions,
    ).await;
    use aegis_control::api::login::LogoutOutcome;
    // AU-1 — only a real revocation is audited; the idempotent
    // no-cookie path changed nothing.
    if matches!(outcome, LogoutOutcome::Ok { .. }) {
        services
            .login_auditor
            .record_logout(&peer.ip().to_string());
    }
    let (clear_session, clear_csrf) = match outcome {
        LogoutOutcome::Ok {
            clear_session_cookie,
            clear_csrf_cookie,
        }
        | LogoutOutcome::NoSession {
            clear_session_cookie,
            clear_csrf_cookie,
        } => (clear_session_cookie, clear_csrf_cookie),
    };
    Response::builder()
        .status(204)
        .header("cache-control", "no-store")
        .header("set-cookie", clear_session)
        .header("set-cookie", clear_csrf)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

#[cfg(test)]
mod au1_wiring_tests {
    // AU-1 (committee round-2 🟡3) — the login path must leave an
    // audit trail. These drive the real process_admin_login /
    // process_admin_logout and assert events land on the bus.
    use std::sync::Arc;

    use aegis_control::api::upstreams::PoolHealthSnapshot;
    use aegis_control::dashboard_services::DashboardServices;
    use aegis_core::audit::{AuditClass, AuditEvent};
    use aegis_core::AuditBus;

    fn spawn_with_bus() -> (
        DashboardServices,
        tokio::task::JoinHandle<()>,
        tokio::sync::broadcast::Receiver<AuditEvent>,
    ) {
        let bus = AuditBus::new(64);
        let rx = bus.subscribe();
        let (services, drain) = DashboardServices::spawn(
            bus,
            Arc::new(|| PoolHealthSnapshot {
                pools: Vec::new(),
                ..Default::default()
            }),
            None,
        );
        (services, drain, rx)
    }

    fn drain_access(
        rx: &mut tokio::sync::broadcast::Receiver<AuditEvent>,
    ) -> Vec<AuditEvent> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if matches!(ev.class, AuditClass::Access) {
                out.push(ev);
            }
        }
        out
    }

    #[tokio::test]
    async fn failed_login_emits_access_event_without_secret_material() {
        let (services, _drain, mut rx) = spawn_with_bus();
        let body = br#"{"user":"admin","password":"secret-hunter2-pw"}"#;
        let resp = super::process_admin_login(
            &services,
            "10.0.0.9:5555".parse().unwrap(),
            "test-ua",
            body,
        )
        .await;
        assert_eq!(resp.status(), 401);
        let evs = drain_access(&mut rx);
        assert_eq!(evs.len(), 1, "failed login must leave exactly one Access event");
        assert_eq!(evs[0].action.as_str(), "login_failure");
        assert_eq!(evs[0].reason, "invalid_credentials");
        assert_eq!(evs[0].client_ip, "10.0.0.9");
        let wire = serde_json::to_string(&evs[0]).unwrap();
        assert!(
            !wire.contains("secret-hunter2-pw"),
            "audit event must never carry the submitted password",
        );
    }

    #[tokio::test]
    async fn malformed_body_is_not_an_auth_attempt_and_emits_nothing() {
        let (services, _drain, mut rx) = spawn_with_bus();
        let resp = super::process_admin_login(
            &services,
            "10.0.0.9:5555".parse().unwrap(),
            "test-ua",
            b"not json",
        )
        .await;
        assert_eq!(resp.status(), 400);
        assert!(
            drain_access(&mut rx).is_empty(),
            "garbage bodies carry no credentials — no auth event",
        );
    }

    #[tokio::test]
    async fn cookieless_logout_emits_no_event() {
        let (services, _drain, mut rx) = spawn_with_bus();
        let resp = super::process_admin_logout(
            &services,
            "10.0.0.9:5555".parse().unwrap(),
            None,
        )
        .await;
        assert_eq!(resp.status(), 204);
        assert!(
            drain_access(&mut rx).is_empty(),
            "idempotent no-session logout revoked nothing — no event",
        );
    }
}
