//! Admin-port auth gate (F-CRITICAL-002 / 005, Phase 3 step 4+5).
//!
//! Sits in front of `handle_admin_request` and runs the 7-step
//! auth chain from `plans/issue-fix/2026-05-17-s-tester-audits-fix/
//! PHASE-3-admin-auth-design.md`:
//!
//! 1. IP allowlist (skipped when empty — operator opt-in)
//! 2. mTLS (already enforced at the TLS handshake layer)
//! 3. Per-IP login rate-limit (only for `/admin/login`, runs inside
//!    that handler)
//! 4. Password (argon2id) verify (only for `/admin/login`)
//! 5. TOTP verify (only for `/admin/login` when enabled)
//! 6. Session validate (cookie OR service-account bearer token)
//! 7. CSRF (state-changing methods only: POST / PUT / PATCH / DELETE
//!    except `/admin/login` itself)
//!
//! This module owns steps 1, 6, and 7. Steps 3-5 stay inside
//! `api::login::authenticate`; step 2 is the TLS handshake.
//!
//! On success the middleware returns an `Identity` carrying the
//! validated actor name + scopes, which the caller injects into the
//! request as an `X-Aegis-Actor` extension header. Mutation handlers
//! consume that to stamp the audit chain — never the client-supplied
//! `X-Actor` header, which is silently stripped by [`strip_client_actor`]
//! at the gate (F-CRITICAL-004).

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Request, Response, StatusCode};

use aegis_core::config::WafConfig;
use aegis_control::admin_auth::csrf;
use aegis_control::admin_auth::password::verify_password;
use aegis_control::admin_auth::session::SessionStore as AuthSessionStore;

/// Identity carried through to the handler after a successful
/// admit. `actor` lands on the audit chain's `actor` field; `scopes`
/// gates which handlers the request can reach.
#[derive(Clone, Debug)]
#[allow(dead_code)] // `is_service_account` is set but currently only audited indirectly via `actor`; kept for future per-account telemetry.
pub struct Identity {
    pub actor: String,
    pub scopes: Scopes,
    /// `true` when the request authenticated via a service-account
    /// bearer token; `false` for a logged-in dashboard session.
    pub is_service_account: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scopes {
    pub read: bool,
    pub write: bool,
}

impl Scopes {
    pub const FULL: Self = Self { read: true, write: true };
    // `READ_ONLY` is constructed dynamically inside `try_bearer_auth`
    // from the per-account scopes list; the const is kept for
    // readability of test fixtures that want to opt into the
    // common case.
    #[allow(dead_code)]
    pub const READ_ONLY: Self = Self { read: true, write: false };
}

/// Verdict from the gate. Three terminal states:
/// - `Authenticated`: caller threads `identity` to the handler.
/// - `OpenEndpoint`: the request targets an unauthenticated surface
///   (health probe, login page, static asset) — caller dispatches
///   without an identity.
/// - `Denied`: caller returns the pre-built response directly.
pub enum Admit {
    Authenticated(Identity),
    OpenEndpoint,
    Denied(Response<Full<Bytes>>),
}

/// 2026-05-17 F-CRITICAL-002 + 004 + 005 — primary gate.
///
/// Generic over the body type (TOTP-6): the gate only reads
/// method/path/headers, and `B: ()` lets unit tests drive the full
/// admit path without faking a hyper `Incoming`.
pub async fn admit<B>(
    req: &Request<B>,
    peer: SocketAddr,
    cfg: &WafConfig,
    auth_sessions: &Arc<AuthSessionStore>,
) -> Admit {
    let method = req.method();
    let path = req.uri().path();

    // Step 1 — IP allowlist (empty list = allow-all, matches the
    // decision in PHASE-3-admin-auth-design.md).
    if !cfg.admin.dashboard_auth.ip_allowlist.is_empty() {
        let allowed = cfg
            .admin
            .dashboard_auth
            .ip_allowlist
            .iter()
            .any(|net| net.contains(&peer.ip()));
        if !allowed {
            tracing::warn!(
                peer = %peer.ip(),
                "admin: IP-allowlist deny",
            );
            return Admit::Denied(deny_response(
                StatusCode::FORBIDDEN,
                "admin_ip_denied",
                "client IP not in admin.dashboard_auth.ip_allowlist",
            ));
        }
    }

    // F-HIGH-admin (2026-05-17): pre-check `Content-Length` against
    // `cfg.admin.dashboard_auth.max_request_body_bytes` (default
    // 1 MiB). Pre-fix every admin mutation handler did
    // `into_body().collect()` with no cap, so a single oversized
    // payload could OOM the WAF before the JSON parser rejected
    // it. This gate covers the common case (clients that send a
    // Content-Length header); chunked-without-length bodies still
    // need per-handler `Limited<_>` wrapping — tracked as a
    // separate item in the unwired-stubs catalogue.
    if let Some(len_hdr) = req.headers().get(hyper::header::CONTENT_LENGTH) {
        if let Some(len) = len_hdr.to_str().ok().and_then(|s| s.parse::<u64>().ok()) {
            if len > cfg.admin.dashboard_auth.max_request_body_bytes {
                tracing::warn!(
                    peer = %peer.ip(),
                    declared_bytes = len,
                    cap = cfg.admin.dashboard_auth.max_request_body_bytes,
                    "admin: rejected oversized request body",
                );
                return Admit::Denied(deny_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "admin_body_too_large",
                    "request body exceeds cfg.admin.dashboard_auth.max_request_body_bytes",
                ));
            }
        }
    }

    // Step 2 — mTLS happens at TLS handshake; nothing to do here.

    // Open endpoints — no session required.
    if is_open_endpoint(method, path, &peer) {
        return Admit::OpenEndpoint;
    }

    // Step 6 — try bearer token (service account) first, then
    // session cookie.
    if let Some(id) = try_bearer_auth(req, cfg) {
        // Scope check before allowing mutations.
        if requires_write_scope(method) && !id.scopes.write {
            tracing::warn!(
                actor = %id.actor,
                method = %method,
                "admin: service-account scope=read attempted write",
            );
            return Admit::Denied(deny_response(
                StatusCode::FORBIDDEN,
                "service_account_scope_insufficient",
                "this service account has scopes=[\"read\"] but the request is a mutation",
            ));
        }
        // Service accounts are stateless — CSRF cookie+header pair
        // isn't applicable (no cookie at all). Bearer auth replaces
        // the CSRF defence with the bearer-secret-is-required
        // property.
        return Admit::Authenticated(id);
    }

    if let Some((id, totp_verified)) = try_session_auth(req, cfg, auth_sessions).await {
        // TOTP-2 (TF-1) — enrollment-only sessions. A login that passed
        // the password check but has no enrolled second factor (under
        // `require_totp`) carries `totp_verified=false`; it may reach
        // ONLY the TOTP enroll/confirm endpoints until a code from the
        // authenticator app confirms enrollment. Everything else on the
        // admin surface is denied — this is what makes "password alone
        // never grants admin access" hold.
        if !totp_verified && !is_enrollment_allowed(method, path) {
            tracing::warn!(
                actor = %id.actor,
                method = %method,
                path = %path,
                "admin: enrollment-only session attempted a non-enrollment endpoint",
            );
            // TOTP-6 — a human navigating in a tab gets bounced to the
            // login page (which hosts the QR enrollment flow) exactly
            // like an unauthenticated navigation; only programmatic
            // fetches see the JSON 403.
            if wants_html_navigation(req) {
                let next = request_path_with_query(req);
                return Admit::Denied(login_redirect_response(&next));
            }
            return Admit::Denied(deny_response(
                StatusCode::FORBIDDEN,
                "totp_enrollment_required",
                "this session requires TOTP enrollment — \
                 POST /api/admin/totp/enroll then /api/admin/totp/confirm",
            ));
        }
        // Step 7 — CSRF on state-changing methods.
        // Browser-initiated reporting endpoints (CSP `report-uri`) are
        // exempt: the browser sends these automatically and never adds the
        // `x-csrf-token` header, so CSRF-token validation would always fail.
        // An attacker can't cause meaningful harm by forging a CSP report
        // (the session is still validated above).
        if requires_write_scope(method) && !is_csrf_exempt(path) {
            match csrf::validate(
                extract_cookie(req, "aegis_csrf"),
                req.headers()
                    .get("x-csrf-token")
                    .and_then(|h| h.to_str().ok()),
            ) {
                csrf::CsrfResult::Valid => {}
                csrf::CsrfResult::MissingCookie
                | csrf::CsrfResult::MissingHeader
                | csrf::CsrfResult::Mismatch => {
                    tracing::warn!(
                        actor = %id.actor,
                        method = %method,
                        path = %path,
                        "admin: CSRF rejected",
                    );
                    return Admit::Denied(deny_response(
                        StatusCode::FORBIDDEN,
                        "admin_csrf_invalid",
                        "CSRF cookie + header missing or mismatched",
                    ));
                }
            }
        }
        return Admit::Authenticated(id);
    }

    // 2026-05-19 — friendly UX for browser navigations. If this is a
    // GET that a browser issued for a document (Accept: text/html or
    // Sec-Fetch-Dest: document), bounce to /admin/login?next=<path>
    // instead of returning a raw JSON 401. Programmatic clients
    // (SPA fetches, curl, service-account bearer probes) still get
    // the 401 envelope so they can detect + handle it themselves —
    // we only redirect when the request shape says "human in a tab".
    if wants_html_navigation(req) {
        let next = request_path_with_query(req);
        return Admit::Denied(login_redirect_response(&next));
    }

    Admit::Denied(deny_response(
        StatusCode::UNAUTHORIZED,
        "admin_unauthenticated",
        "missing or invalid session cookie / bearer token",
    ))
}

/// True when the unauthenticated request looks like a browser
/// navigating to a page — not an XHR / fetch / curl call. We use
/// this signal to decide between a 303 redirect (friendly) and a
/// JSON 401 (machine-readable). Heuristics:
///
/// - Method must be GET (POST/PUT etc. can't be redirected safely
///   anyway — the body would be dropped).
/// - `Sec-Fetch-Dest: document` is the strongest signal (set by
///   every modern browser on top-level navigation, never by
///   `fetch()` / `XMLHttpRequest`).
/// - Fallback: `Accept` header explicitly asks for `text/html`.
/// - Reject `application/json` Accept (SPA fetches that the
///   dashboard JS wants to handle inline).
/// - Reject paths under `/api/` — those are JSON surfaces no
///   matter what Accept says.
fn wants_html_navigation<B>(req: &Request<B>) -> bool {
    if req.method() != Method::GET {
        return false;
    }
    let path = req.uri().path();
    if path.starts_with("/api/") {
        return false;
    }
    // Strongest signal: browser top-level navigation.
    if let Some(dest) = req.headers().get("sec-fetch-dest").and_then(|h| h.to_str().ok()) {
        if dest.eq_ignore_ascii_case("document") {
            return true;
        }
    }
    // Accept-header fallback for clients that don't send Sec-Fetch-*.
    let Some(accept) = req.headers().get(hyper::header::ACCEPT).and_then(|h| h.to_str().ok()) else {
        return false;
    };
    let accept_lc = accept.to_ascii_lowercase();
    // SPA fetches usually pin Accept to application/json — don't
    // hijack those even if the URL happens to be HTML-ish.
    if accept_lc.contains("application/json") {
        return false;
    }
    accept_lc.contains("text/html")
}

/// Pull the path + query out of the request URI as an absolute
/// path. Defaults to "/dashboard/" if the URI doesn't expose one
/// (shouldn't happen in practice, but we never want to feed an
/// empty `next=` to the login page).
fn request_path_with_query<B>(req: &Request<B>) -> String {
    req.uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/dashboard/".to_string())
}

/// Build a 303 See Other → `/admin/login?next=<url-encoded path>`.
/// 303 (not 302) so a future POST-after-login flow gets coerced to
/// GET on the login page, matching the existing `login.js` UX.
fn login_redirect_response(next: &str) -> Response<Full<Bytes>> {
    let location = aegis_control::dashboard::login_redirect(next);
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(hyper::header::LOCATION, location)
        .header(hyper::header::CACHE_CONTROL, "no-store")
        .header("x-waf-rule-id", "admin_unauthenticated")
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// Strip client-supplied identity headers that the trusted admin edge
/// owns. F-CRITICAL-004 — callers must not let arbitrary clients
/// dictate the audit chain's actor field (`x-actor`). RC-5a / V9 — the
/// same rule applies to the server-namespace headers the listener
/// injects (`x-aegis-actor`, `x-aegis-client-ip`): scrub any inbound
/// copy so a client can never pre-seed one that survives to a handler
/// (belt-and-suspenders with the authenticated arm's `insert`, and the
/// only guard on the open-endpoint arm). Done unconditionally on every
/// admin-port request.
pub fn strip_client_actor<B>(req: &mut Request<B>) {
    let headers = req.headers_mut();
    headers.remove("x-actor");
    headers.remove("x-aegis-actor");
    headers.remove("x-aegis-client-ip");
}

/// Open endpoints — no auth required. Kept tight; everything else
/// requires a session or bearer token.
fn is_open_endpoint(method: &Method, path: &str, peer: &SocketAddr) -> bool {
    // Interop control plane checked first because it spans both
    // GET and POST and has its own X-Benchmark-Secret auth in the
    // dispatcher — admin-port session auth would double-gate it.
    //
    // 2026-05-19 committee bind contract: only loopback peers may
    // skip admin auth on /__waf_control/*. Non-loopback callers
    // get routed through the normal session-cookie gate, which
    // means they hit the login redirect for any path that isn't
    // an open-by-design endpoint — same UX as any unknown route.
    if path.starts_with("/__waf_control/") {
        return peer.ip().is_loopback();
    }
    if method == Method::GET {
        // Health probes + login page + static SPA assets.
        //
        // F11 (2026-06-11 cluster QC): exempt the WHOLE `/healthz/*`
        // namespace, not just `ready`. `/healthz/live` and
        // `/healthz/startup` were falling through to the session gate
        // → 401 for orchestrator probes that can't present a cookie,
        // which crash-loops liveness and pins startup un-ready. Health
        // probes expose no sensitive data (see `health.rs`), so the
        // whole namespace is open + future-proofed for new probes.
        // `/login` — TOTP-7 convenience alias (303 → /admin/login). Open
        // for the same reason the login page is: gating it would send
        // the operator through /admin/login?next=%2Flogin and back to a
        // 404 after signing in.
        return matches!(
            path,
            "/readyz" | "/metrics" | "/login" | "/admin/login" | "/admin/login.js"
        ) || path == "/healthz"
            || path.starts_with("/healthz/")
            || path.starts_with("/dashboard")
            || path.starts_with("/static/")
            || path.starts_with("/assets/");
    }
    if method == Method::POST {
        // Login itself is the entry point — auth runs inside the
        // handler (rate-limit, password, TOTP). Logout is the
        // counterpart.
        return matches!(path, "/admin/login" | "/admin/logout");
    }
    false
}

/// Endpoints that are CSRF-exempt even for state-changing methods.
/// These are browser-initiated reports (e.g. CSP `report-uri`) where the
/// browser never adds the `x-csrf-token` header but the session cookie IS
/// present. An attacker can't cause harm by forging these — the payload
/// is observability data, not a privileged mutation.
fn is_csrf_exempt(path: &str) -> bool {
    matches!(path, "/api/csp/report")
}

/// TOTP-2 (TF-1) — the ONLY endpoints an enrollment-only session
/// (`totp_verified=false`) may reach. Login/logout/health/static assets
/// are open endpoints and never consult this. Kept as a tight literal
/// match — new admin surfaces must NOT leak into the pre-enrollment
/// state by default.
fn is_enrollment_allowed(method: &Method, path: &str) -> bool {
    *method == Method::POST
        && matches!(path, "/api/admin/totp/enroll" | "/api/admin/totp/confirm")
}

fn requires_write_scope(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE,
    )
}

fn try_bearer_auth<B>(
    req: &Request<B>,
    cfg: &WafConfig,
) -> Option<Identity> {
    let header = req.headers().get("authorization")?.to_str().ok()?;
    let token = header.strip_prefix("Bearer ")?.trim();
    if token.is_empty() {
        return None;
    }
    for sa in &cfg.admin.dashboard_auth.service_accounts {
        if verify_password(&sa.token_hash, token) {
            return Some(Identity {
                actor: sa.name.clone(),
                scopes: Scopes {
                    read: sa.scopes.iter().any(|s| s == "read")
                        || sa.scopes.iter().any(|s| s == "write"),
                    write: sa.scopes.iter().any(|s| s == "write"),
                },
                is_service_account: true,
            });
        }
    }
    None
}

/// Validate the session cookie. Returns the identity plus the record's
/// `totp_verified` flag so `admit` can hold enrollment-only sessions to
/// the TOTP surface (TOTP-2).
async fn try_session_auth<B>(
    req: &Request<B>,
    _cfg: &WafConfig,
    sessions: &Arc<AuthSessionStore>,
) -> Option<(Identity, bool)> {
    let cookie = extract_cookie(req, "aegis_session")?;
    let record = sessions.validate(cookie).await?;
    // TOTP-1 (TF-4) — the session record carries the account it was
    // issued to (multi-admin model); the audit chain's `actor` is that
    // username. Pre-multi-account records serde-default to `admin`.
    let totp_verified = record.totp_verified;
    Some((
        Identity {
            actor: record.user,
            scopes: Scopes::FULL,
            is_service_account: false,
        },
        totp_verified,
    ))
}

/// Extract a named cookie value from the Cookie header. RFC 6265
/// minimal parser — pairs are `name=value` separated by `; `.
fn extract_cookie<'a, B>(
    req: &'a Request<B>,
    name: &str,
) -> Option<&'a str> {
    let header = req.headers().get(hyper::header::COOKIE)?;
    let raw = header.to_str().ok()?;
    for pair in raw.split(';') {
        let pair = pair.trim();
        if let Some(rest) = pair.strip_prefix(name) {
            if let Some(v) = rest.strip_prefix('=') {
                return Some(v);
            }
        }
    }
    None
}

fn deny_response(
    status: StatusCode,
    rule_id: &str,
    detail: &str,
) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("x-waf-rule-id", rule_id.to_string())
        .body(Full::new(Bytes::from(
            serde_json::json!({
                "ok": false,
                "reason": rule_id,
                "detail": detail,
            })
            .to_string(),
        )))
        .unwrap()
}

#[cfg(test)]
mod tests {
    // The full `admit()` path is exercised by integration tests
    // (where building a real `Incoming` body via hyper is
    // ergonomic). These unit tests target the pure helpers.
    use super::*;

    fn loopback_peer() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 50_000))
    }

    fn remote_peer() -> SocketAddr {
        SocketAddr::from(([203, 0, 113, 7], 50_000))
    }

    #[test]
    fn health_probes_are_open() {
        let p = loopback_peer();
        assert!(is_open_endpoint(&Method::GET, "/healthz", &p));
        assert!(is_open_endpoint(&Method::GET, "/healthz/ready", &p));
        // F11 (2026-06-11): liveness + startup probes must be open
        // too — orchestrators can't present a session cookie, so
        // gating these crash-loops the container / pins it un-ready.
        assert!(is_open_endpoint(&Method::GET, "/healthz/live", &p));
        assert!(is_open_endpoint(&Method::GET, "/healthz/startup", &p));
        // Probes also arrive from non-loopback LBs / VIP checkers.
        let rem = remote_peer();
        assert!(is_open_endpoint(&Method::GET, "/healthz/live", &rem));
        assert!(is_open_endpoint(&Method::GET, "/healthz/startup", &rem));
        assert!(is_open_endpoint(&Method::GET, "/readyz", &p));
        assert!(is_open_endpoint(&Method::GET, "/metrics", &p));
    }

    #[test]
    fn login_endpoints_are_open() {
        let p = remote_peer();
        assert!(is_open_endpoint(&Method::GET, "/admin/login", &p));
        assert!(is_open_endpoint(&Method::GET, "/admin/login.js", &p));
        assert!(is_open_endpoint(&Method::POST, "/admin/login", &p));
        assert!(is_open_endpoint(&Method::POST, "/admin/logout", &p));
    }

    #[test]
    fn login_alias_is_open() {
        // TOTP-7 — `GET /login` is a convenience alias that 303s to
        // /admin/login. It must be OPEN: if it required auth, the gate
        // would redirect to /admin/login?next=%2Flogin and the operator
        // would land back on /login → JSON 404 after signing in.
        let p = remote_peer();
        assert!(is_open_endpoint(&Method::GET, "/login", &p));
        // Only the GET alias — no POST surface at the alias path.
        assert!(!is_open_endpoint(&Method::POST, "/login", &p));
    }

    #[test]
    fn dashboard_assets_are_open() {
        let p = remote_peer();
        assert!(is_open_endpoint(&Method::GET, "/dashboard", &p));
        assert!(is_open_endpoint(&Method::GET, "/dashboard/index.html", &p));
        assert!(is_open_endpoint(&Method::GET, "/static/app.js", &p));
        assert!(is_open_endpoint(&Method::GET, "/assets/icon.png", &p));
    }

    #[test]
    fn interop_control_open_only_from_loopback() {
        // Interop has its own X-Benchmark-Secret check inside the
        // dispatch, but the committee bind contract requires the
        // surface itself to be local-only — non-loopback callers
        // must NOT be admitted as OpenEndpoint.
        let lo = loopback_peer();
        assert!(is_open_endpoint(&Method::POST, "/__waf_control/reset_state", &lo));
        assert!(is_open_endpoint(&Method::GET, "/__waf_control/capabilities", &lo));

        let rem = remote_peer();
        assert!(!is_open_endpoint(&Method::POST, "/__waf_control/reset_state", &rem));
        assert!(!is_open_endpoint(&Method::GET, "/__waf_control/capabilities", &rem));
    }

    #[test]
    fn api_endpoints_require_auth() {
        let p = remote_peer();
        assert!(!is_open_endpoint(&Method::GET, "/api/routes", &p));
        assert!(!is_open_endpoint(&Method::PUT, "/api/detectors", &p));
        assert!(!is_open_endpoint(&Method::POST, "/api/rules", &p));
        assert!(!is_open_endpoint(&Method::DELETE, "/api/rules/abc", &p));
    }

    #[test]
    fn enrollment_only_sessions_reach_only_the_totp_surface() {
        // TOTP-2 (TF-1) — a session issued in the enrollment_required
        // state (totp_verified=false) may reach ONLY the TOTP
        // enroll/confirm endpoints; everything else on the admin surface
        // is denied until the second factor is confirmed. (Login/logout/
        // health/static are open endpoints and never get here.)
        assert!(is_enrollment_allowed(&Method::POST, "/api/admin/totp/enroll"));
        assert!(is_enrollment_allowed(&Method::POST, "/api/admin/totp/confirm"));
        // Nothing else unlocks.
        assert!(!is_enrollment_allowed(&Method::GET, "/api/stats"));
        assert!(!is_enrollment_allowed(&Method::GET, "/api/admin/sessions"));
        assert!(!is_enrollment_allowed(&Method::PUT, "/api/detectors"));
        assert!(!is_enrollment_allowed(&Method::POST, "/api/rules"));
        assert!(!is_enrollment_allowed(&Method::GET, "/api/admin/totp/enroll"));
        assert!(!is_enrollment_allowed(&Method::DELETE, "/api/admin/totp/enroll"));
    }

    #[test]
    fn csp_report_is_csrf_exempt() {
        assert!(is_csrf_exempt("/api/csp/report"));
        // Other POST endpoints are NOT exempt.
        assert!(!is_csrf_exempt("/api/routes"));
        assert!(!is_csrf_exempt("/api/zero-trust/upstream/identity"));
    }

    #[test]
    fn write_scope_required_for_mutations() {
        assert!(!requires_write_scope(&Method::GET));
        assert!(!requires_write_scope(&Method::HEAD));
        assert!(!requires_write_scope(&Method::OPTIONS));
        assert!(requires_write_scope(&Method::POST));
        assert!(requires_write_scope(&Method::PUT));
        assert!(requires_write_scope(&Method::PATCH));
        assert!(requires_write_scope(&Method::DELETE));
    }

    fn req(method: Method, uri: &str, headers: &[(&str, &str)]) -> Request<()> {
        let mut b = Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(()).unwrap()
    }

    #[test]
    fn strip_client_actor_scrubs_spoofable_identity_headers() {
        // RC-5a / V9: a client must not be able to pre-seed the audit
        // identity headers the trusted edge owns.
        let mut r = req(
            Method::PUT,
            "/api/mode",
            &[
                ("x-actor", "spoofed"),
                ("x-aegis-actor", "spoofed-admin"),
                ("x-aegis-client-ip", "1.2.3.4"),
                ("x-request-id", "keep-me"),
            ],
        );
        strip_client_actor(&mut r);
        assert!(r.headers().get("x-actor").is_none());
        assert!(r.headers().get("x-aegis-actor").is_none());
        assert!(r.headers().get("x-aegis-client-ip").is_none());
        // Unrelated headers survive.
        assert_eq!(r.headers().get("x-request-id").unwrap(), "keep-me");
    }

    #[test]
    fn redirect_fires_for_browser_navigation() {
        let r = req(
            Method::GET,
            "/dashboard/",
            &[("accept", "text/html,application/xhtml+xml,application/xml;q=0.9")],
        );
        assert!(wants_html_navigation(&r));
    }

    #[test]
    fn redirect_fires_on_sec_fetch_dest_document() {
        // Modern browsers send this even when Accept is unusual.
        let r = req(Method::GET, "/dashboard/", &[("sec-fetch-dest", "document")]);
        assert!(wants_html_navigation(&r));
    }

    #[test]
    fn no_redirect_for_api_paths_even_with_html_accept() {
        let r = req(Method::GET, "/api/ai/status", &[("accept", "text/html")]);
        assert!(!wants_html_navigation(&r));
    }

    #[test]
    fn no_redirect_for_json_fetch() {
        let r = req(Method::GET, "/dashboard/", &[("accept", "application/json")]);
        assert!(!wants_html_navigation(&r));
    }

    #[test]
    fn no_redirect_for_non_get_methods() {
        let r = req(Method::POST, "/dashboard/", &[("accept", "text/html")]);
        assert!(!wants_html_navigation(&r));
    }

    #[test]
    fn no_redirect_when_accept_missing() {
        // curl / probes without Accept aren't browser navigations.
        let r = req(Method::GET, "/dashboard/", &[]);
        assert!(!wants_html_navigation(&r));
    }

    #[test]
    fn request_path_preserves_query() {
        let r = req(Method::GET, "/dashboard/rules?filter=ai", &[]);
        assert_eq!(request_path_with_query(&r), "/dashboard/rules?filter=ai");
    }

    // ---- TOTP-6 — enrollment-only sessions in a browser -----------------
    //
    // A session that passed the password check but hasn't confirmed its
    // factor is enrollment-only. When such a session NAVIGATES (GET /,
    // Accept: text/html) it must be bounced to /admin/login — the page
    // that hosts the QR flow — not shown the raw JSON 403 that fetch()
    // clients get. Mirrors the existing unauthenticated-navigation
    // redirect (`wants_html_navigation`).

    async fn enrollment_only_fixture() -> (
        Arc<AuthSessionStore>,
        aegis_core::config::WafConfig,
        String,
    ) {
        let key = [7u8; 32];
        let sessions = Arc::new(AuthSessionStore::new(key));
        let (_, cookie) = sessions
            .create_for_user("liud", "127.0.0.1", "ua", false)
            .await
            .expect("session create");
        let cfg = aegis_core::load_config_str(
            r#"
listeners:
  data: [{ bind: "0.0.0.0:443" }]
  admin: { bind: "127.0.0.1:9443" }
routes:
  - { id: catch-all, path: "/", upstream: api }
upstreams:
  api: { members: [{ addr: "127.0.0.1:3000" }] }
state: { backend: in_memory }
"#,
        )
        .expect("minimal cfg parses");
        (sessions, cfg, cookie)
    }

    #[tokio::test]
    async fn enrollment_only_browser_navigation_redirects_to_login() {
        let (sessions, cfg, cookie) = enrollment_only_fixture().await;
        let r = req(
            Method::GET,
            "/",
            &[
                ("cookie", &format!("aegis_session={cookie}")),
                ("accept", "text/html,application/xhtml+xml"),
                ("sec-fetch-dest", "document"),
            ],
        );
        match admit(&r, loopback_peer(), &cfg, &sessions).await {
            Admit::Denied(resp) => {
                assert_eq!(
                    resp.status(),
                    StatusCode::SEE_OTHER,
                    "browser navigation must redirect, not dump JSON",
                );
                let loc = resp
                    .headers()
                    .get(hyper::header::LOCATION)
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("");
                assert!(
                    loc.starts_with("/admin/login"),
                    "redirect must land on the login page (QR flow host): {loc}",
                );
            }
            _ => panic!("enrollment-only navigation must be Denied(redirect)"),
        }
    }

    #[tokio::test]
    async fn enrollment_only_api_fetch_still_gets_json_403() {
        let (sessions, cfg, cookie) = enrollment_only_fixture().await;
        let r = req(
            Method::GET,
            "/api/stats",
            &[
                ("cookie", &format!("aegis_session={cookie}")),
                ("accept", "application/json"),
            ],
        );
        match admit(&r, loopback_peer(), &cfg, &sessions).await {
            Admit::Denied(resp) => {
                assert_eq!(resp.status(), StatusCode::FORBIDDEN);
                assert_eq!(
                    resp.headers()
                        .get("x-waf-rule-id")
                        .and_then(|h| h.to_str().ok()),
                    Some("totp_enrollment_required"),
                );
            }
            _ => panic!("enrollment-only API fetch must stay a JSON 403"),
        }
    }

    #[tokio::test]
    async fn enrollment_only_session_reaches_the_enroll_endpoint() {
        let (sessions, cfg, cookie) = enrollment_only_fixture().await;
        let r = req(
            Method::POST,
            "/api/admin/totp/enroll",
            &[
                ("cookie", &format!("aegis_session={cookie}; aegis_csrf=tok")),
                ("x-csrf-token", "tok"),
            ],
        );
        match admit(&r, loopback_peer(), &cfg, &sessions).await {
            Admit::Authenticated(id) => assert_eq!(id.actor, "liud"),
            _ => panic!("the enroll endpoint must admit enrollment-only sessions"),
        }
    }

    #[tokio::test]
    async fn fully_verified_session_navigates_without_redirect() {
        let (sessions, cfg, _) = enrollment_only_fixture().await;
        let (_, cookie) = sessions
            .create_for_user("liud", "127.0.0.1", "ua", true)
            .await
            .expect("session create");
        let r = req(
            Method::GET,
            "/",
            &[
                ("cookie", &format!("aegis_session={cookie}")),
                ("accept", "text/html"),
            ],
        );
        assert!(
            matches!(
                admit(&r, loopback_peer(), &cfg, &sessions).await,
                Admit::Authenticated(_),
            ),
            "verified sessions must not be redirected",
        );
    }
}
