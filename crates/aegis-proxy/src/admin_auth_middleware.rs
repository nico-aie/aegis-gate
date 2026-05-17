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
pub async fn admit(
    req: &Request<hyper::body::Incoming>,
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

    // Step 2 — mTLS happens at TLS handshake; nothing to do here.

    // Open endpoints — no session required.
    if is_open_endpoint(method, path) {
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

    if let Some(id) = try_session_auth(req, cfg, auth_sessions) {
        // Step 7 — CSRF on state-changing methods.
        if requires_write_scope(method) {
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

    Admit::Denied(deny_response(
        StatusCode::UNAUTHORIZED,
        "admin_unauthenticated",
        "missing or invalid session cookie / bearer token",
    ))
}

/// Strip the client-supplied `X-Actor` header. F-CRITICAL-004 —
/// callers must not let arbitrary clients dictate the audit chain's
/// actor field. Done unconditionally on every admin-port request so
/// no handler accidentally reads a spoofed value.
pub fn strip_client_actor(req: &mut Request<hyper::body::Incoming>) {
    req.headers_mut().remove("x-actor");
}

/// Open endpoints — no auth required. Kept tight; everything else
/// requires a session or bearer token.
fn is_open_endpoint(method: &Method, path: &str) -> bool {
    // Interop control plane checked first because it spans both
    // GET and POST and has its own X-Benchmark-Secret auth in the
    // dispatcher — admin-port session auth would double-gate it.
    if path.starts_with("/__waf_control/") {
        return true;
    }
    if method == Method::GET {
        // Health probes + login page + static SPA assets.
        return matches!(
            path,
            "/healthz" | "/healthz/ready" | "/readyz" | "/metrics"
                | "/admin/login" | "/admin/login.js"
        ) || path.starts_with("/dashboard")
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

fn requires_write_scope(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE,
    )
}

fn try_bearer_auth(
    req: &Request<hyper::body::Incoming>,
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

fn try_session_auth(
    req: &Request<hyper::body::Incoming>,
    _cfg: &WafConfig,
    sessions: &Arc<AuthSessionStore>,
) -> Option<Identity> {
    let cookie = extract_cookie(req, "aegis_session")?;
    let record = sessions.validate(cookie)?;
    let _ = record; // SessionRecord doesn't carry user_id yet
    // Single-admin model: every session belongs to "admin" until
    // RBAC lands. When multi-user auth ships, SessionRecord will
    // gain a `user_id` field and this hard-coded literal goes
    // away.
    Some(Identity {
        actor: "admin".into(),
        scopes: Scopes::FULL,
        is_service_account: false,
    })
}

/// Extract a named cookie value from the Cookie header. RFC 6265
/// minimal parser — pairs are `name=value` separated by `; `.
fn extract_cookie<'a>(
    req: &'a Request<hyper::body::Incoming>,
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

    #[test]
    fn health_probes_are_open() {
        assert!(is_open_endpoint(&Method::GET, "/healthz"));
        assert!(is_open_endpoint(&Method::GET, "/healthz/ready"));
        assert!(is_open_endpoint(&Method::GET, "/readyz"));
        assert!(is_open_endpoint(&Method::GET, "/metrics"));
    }

    #[test]
    fn login_endpoints_are_open() {
        assert!(is_open_endpoint(&Method::GET, "/admin/login"));
        assert!(is_open_endpoint(&Method::GET, "/admin/login.js"));
        assert!(is_open_endpoint(&Method::POST, "/admin/login"));
        assert!(is_open_endpoint(&Method::POST, "/admin/logout"));
    }

    #[test]
    fn dashboard_assets_are_open() {
        assert!(is_open_endpoint(&Method::GET, "/dashboard"));
        assert!(is_open_endpoint(&Method::GET, "/dashboard/index.html"));
        assert!(is_open_endpoint(&Method::GET, "/static/app.js"));
        assert!(is_open_endpoint(&Method::GET, "/assets/icon.png"));
    }

    #[test]
    fn interop_control_is_open_from_this_gate() {
        // Interop has its own X-Benchmark-Secret check inside the
        // dispatch — this gate must let it through.
        assert!(is_open_endpoint(&Method::POST, "/__waf_control/reset_state"));
        assert!(is_open_endpoint(&Method::GET, "/__waf_control/capabilities"));
    }

    #[test]
    fn api_endpoints_require_auth() {
        assert!(!is_open_endpoint(&Method::GET, "/api/routes"));
        assert!(!is_open_endpoint(&Method::PUT, "/api/detectors"));
        assert!(!is_open_endpoint(&Method::POST, "/api/rules"));
        assert!(!is_open_endpoint(&Method::DELETE, "/api/rules/abc"));
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
}
