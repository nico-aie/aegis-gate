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
    process_admin_login(services, peer, &user_agent, body_bytes.as_ref())
}

/// Pure body of the login handler — no `Incoming`, so unit
/// tests can drive it without faking a TCP body. The async
/// wrapper above just collects the body and delegates here.
pub(crate) fn process_admin_login(
    services: &aegis_control::dashboard_services::DashboardServices,
    peer: std::net::SocketAddr,
    user_agent: &str,
    body_bytes: &[u8],
) -> Response<Full<Bytes>> {
    let body_str = std::str::from_utf8(body_bytes).unwrap_or("");
    let outcome = aegis_control::api::login::authenticate(
        body_str,
        &services.admin_identity,
        &services.login_rate_limiter,
        &services.auth_sessions,
        &services.sessions,
        &peer.ip().to_string(),
        user_agent,
        services.session_idle_seconds,
    );

    use aegis_control::api::login::LoginOutcome;
    match outcome {
        LoginOutcome::Ok {
            session_cookie,
            csrf_cookie,
            body,
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
    }
}

pub(crate) fn handle_admin_logout(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let cookie_value = req
        .headers()
        .get_all(hyper::header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|raw| extract_named_cookie(raw, "aegis_session"))
        .map(|s| s.to_string());
    process_admin_logout(services, cookie_value.as_deref())
}

/// Pure body of logout — same testability story as
/// [`process_admin_login`].
pub(crate) fn process_admin_logout(
    services: &aegis_control::dashboard_services::DashboardServices,
    session_cookie: Option<&str>,
) -> Response<Full<Bytes>> {
    let outcome = aegis_control::api::login::logout(
        session_cookie,
        &services.auth_sessions,
        &services.sessions,
    );
    use aegis_control::api::login::LogoutOutcome;
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
