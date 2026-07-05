//! AM-P2b — `/api/admin/accounts*` HTTP handlers.
//!
//! Thin hyper wrappers over `aegis_control::api::admin_accounts` (the
//! list/create/reset/delete logic lives there, unit-tested without hyper).
//! All routes sit BEHIND the auth middleware (session + CSRF + write scope);
//! the acting admin comes from the middleware-injected `x-aegis-actor` header
//! (never a client-supplied value — the gate strips `x-actor`).
//!
//! Equal-privilege v1: any admin may manage accounts. The safety rails
//! (last-admin guard, no self-target) live in the control-crate helpers; the
//! self-service endpoints (change own password / re-enrol own 2FA with
//! step-up) are a separate surface (AM-P2d).

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Response;

use aegis_control::api::admin_accounts::{
    change_own_password, create_account, delete_account, list_accounts, reset_password, reset_totp,
    CreateError, MutateError, SelfPwError,
};
use aegis_control::dashboard_services::DashboardServices;

use crate::responses::{extract_named_cookie, json_body_response, json_response};

fn actor_from(req: &hyper::Request<hyper::body::Incoming>) -> String {
    req.headers()
        .get("x-aegis-actor")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("admin")
        .to_string()
}

/// Emit an AU-1-shaped Admin audit event for an account-management action.
/// Never carries a password or secret — only who/whom/what.
fn emit_account_audit(services: &DashboardServices, action: &str, actor: &str, target: &str, ip: &str) {
    services.bus.emit(aegis_core::audit::AuditEvent {
        schema_version: 1,
        ts: chrono::Utc::now(),
        request_id: String::new(),
        class: aegis_core::audit::AuditClass::Admin,
        tenant_id: None,
        tier: None,
        action: action.to_string().into(),
        reason: "admin account management".into(),
        client_ip: ip.to_string(),
        route_id: None,
        rule_id: None,
        risk_score: None,
        method: None,
        path: None,
        mode: None,
        fields: serde_json::json!({
            "actor": actor,
            "user": actor,
            "target": target,
            "resource": "/api/admin/accounts",
            "source": "dashboard",
        }),
    });
}

/// `GET /api/admin/accounts` — non-secret account list for the UI. `actor` is
/// the requesting admin (from `x-aegis-actor`) so each row can be flagged
/// `is_self` and the UI can hide self-only actions.
pub(crate) async fn handle_accounts_list(
    actor: &str,
    services: &DashboardServices,
) -> Response<Full<Bytes>> {
    let accounts = list_accounts(&services.admin_directory, &services.totp_store, actor).await;
    let body = serde_json::json!({ "ok": true, "accounts": accounts });
    json_body_response(200, body.to_string(), "private, no-store")
}

/// `POST /api/admin/accounts {username, password}` — create a runtime admin.
pub(crate) async fn handle_accounts_create(
    req: hyper::Request<hyper::body::Incoming>,
    peer: std::net::SocketAddr,
    services: &DashboardServices,
) -> Response<Full<Bytes>> {
    #[derive(serde::Deserialize)]
    struct Body {
        username: String,
        password: String,
    }
    let actor = actor_from(&req);
    let Some(body) = read_json::<Body>(req).await else {
        return bad_request("invalid_json", "expected {\"username\":..., \"password\":...}");
    };

    match create_account(&services.admin_directory, &body.username, &body.password).await {
        Ok(()) => {
            emit_account_audit(services, "admin_account_created", &actor, &body.username, &peer.ip().to_string());
            json_body_response(
                201,
                serde_json::json!({
                    "ok": true,
                    "username": body.username,
                    "message": "account created — first login enrolls 2FA",
                })
                .to_string(),
                "private, no-store",
            )
        }
        Err(CreateError::InvalidUsername) => bad_request(
            "invalid_username",
            "username must be 1–64 chars of [A-Za-z0-9_.-]",
        ),
        Err(CreateError::WeakPassword) => bad_request(
            "weak_password",
            "password must be at least 12 characters",
        ),
        Err(CreateError::Duplicate) => {
            json_response(409, &err("duplicate", "an account with that username already exists"))
        }
        Err(CreateError::Unavailable) => unavailable(),
        Err(CreateError::Store(e)) => store_error(&e),
    }
}

/// `POST /api/admin/accounts/{user}/password {new_password}` — admin reset.
pub(crate) async fn handle_account_reset_password(
    req: hyper::Request<hyper::body::Incoming>,
    peer: std::net::SocketAddr,
    target: &str,
    services: &DashboardServices,
) -> Response<Full<Bytes>> {
    #[derive(serde::Deserialize)]
    struct Body {
        new_password: String,
    }
    let actor = actor_from(&req);
    let Some(body) = read_json::<Body>(req).await else {
        return bad_request("invalid_json", "expected {\"new_password\":...}");
    };
    let outcome = reset_password(
        &services.admin_directory,
        &services.auth_sessions,
        target,
        &actor,
        &body.new_password,
    )
    .await;
    mutate_response(services, outcome, "admin_account_password_reset", &actor, target, peer,
        "password reset — the account's sessions were revoked")
}

/// `POST /api/admin/accounts/{user}/totp/reset` — admin 2FA reset (recovery).
pub(crate) async fn handle_account_reset_totp(
    req: hyper::Request<hyper::body::Incoming>,
    peer: std::net::SocketAddr,
    target: &str,
    services: &DashboardServices,
) -> Response<Full<Bytes>> {
    let actor = actor_from(&req);
    let outcome = reset_totp(
        &services.admin_directory,
        &services.totp_store,
        &services.auth_sessions,
        target,
        &actor,
    )
    .await;
    mutate_response(services, outcome, "admin_account_totp_reset", &actor, target, peer,
        "2FA reset — the account re-enrolls at next login")
}

/// `DELETE /api/admin/accounts/{user}` — remove an account.
pub(crate) async fn handle_account_delete(
    req: hyper::Request<hyper::body::Incoming>,
    peer: std::net::SocketAddr,
    target: &str,
    services: &DashboardServices,
) -> Response<Full<Bytes>> {
    let actor = actor_from(&req);
    let outcome = delete_account(
        &services.admin_directory,
        &services.totp_store,
        &services.auth_sessions,
        target,
        &actor,
    )
    .await;
    mutate_response(services, outcome, "admin_account_deleted", &actor, target, peer,
        "account deleted — its 2FA factor and sessions were purged")
}

/// `POST /api/admin/self/password {current_password, new_password}` — the
/// acting admin rotates their OWN password. Verifies the current password
/// (an admin reset does not) and keeps this session while revoking the rest.
pub(crate) async fn handle_self_password(
    req: hyper::Request<hyper::body::Incoming>,
    peer: std::net::SocketAddr,
    services: &DashboardServices,
) -> Response<Full<Bytes>> {
    #[derive(serde::Deserialize)]
    struct Body {
        current_password: String,
        new_password: String,
    }
    let actor = actor_from(&req);
    // Keep THIS session alive across the change: the session record's id is
    // the pre-HMAC prefix of the `aegis_session` cookie value.
    let keep = req
        .headers()
        .get_all(hyper::header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|raw| extract_named_cookie(raw, "aegis_session"))
        .map(|c| c.split('.').next().unwrap_or(c).to_string());

    let Some(body) = read_json::<Body>(req).await else {
        return bad_request("invalid_json", "expected {\"current_password\":..., \"new_password\":...}");
    };
    match change_own_password(
        &services.admin_directory,
        &services.auth_sessions,
        &actor,
        &body.current_password,
        &body.new_password,
        keep.as_deref(),
    )
    .await
    {
        Ok(()) => {
            emit_account_audit(services, "admin_self_password_changed", &actor, &actor, &peer.ip().to_string());
            json_body_response(
                200,
                serde_json::json!({
                    "ok": true,
                    "message": "password changed — your other sessions were signed out",
                })
                .to_string(),
                "private, no-store",
            )
        }
        Err(SelfPwError::CurrentIncorrect) => {
            json_response(403, &err("current_incorrect", "current password is incorrect"))
        }
        Err(SelfPwError::SameAsCurrent) => {
            bad_request("same_password", "new password must differ from the current one")
        }
        Err(SelfPwError::WeakPassword) => {
            bad_request("weak_password", "password must be at least 12 characters")
        }
        Err(SelfPwError::NotFound) => json_response(404, &err("not_found", "account not found")),
        Err(SelfPwError::Unavailable) => unavailable(),
        Err(SelfPwError::Store(e)) => store_error(&e),
    }
}

/// Shared mapping of a `MutateError` outcome → HTTP response + audit on success.
fn mutate_response(
    services: &DashboardServices,
    outcome: Result<(), MutateError>,
    audit_action: &str,
    actor: &str,
    target: &str,
    peer: std::net::SocketAddr,
    ok_message: &str,
) -> Response<Full<Bytes>> {
    match outcome {
        Ok(()) => {
            emit_account_audit(services, audit_action, actor, target, &peer.ip().to_string());
            json_body_response(
                200,
                serde_json::json!({ "ok": true, "message": ok_message }).to_string(),
                "private, no-store",
            )
        }
        Err(MutateError::SelfTarget) => json_response(
            403,
            &err(
                "self_target",
                "use the self-service endpoints to manage your own account",
            ),
        ),
        Err(MutateError::LastAdmin) => json_response(
            409,
            &err("last_admin", "refusing to remove the last remaining admin"),
        ),
        Err(MutateError::NotFound) => json_response(404, &err("not_found", "no such account")),
        Err(MutateError::WeakPassword) => {
            bad_request("weak_password", "password must be at least 12 characters")
        }
        Err(MutateError::Unavailable) => unavailable(),
        Err(MutateError::Store(e)) => store_error(&e),
    }
}

// ---- small response helpers ------------------------------------------------

async fn read_json<T: serde::de::DeserializeOwned>(
    req: hyper::Request<hyper::body::Incoming>,
) -> Option<T> {
    let bytes = req.into_body().collect().await.ok()?.to_bytes();
    serde_json::from_slice::<T>(&bytes).ok()
}

fn err(reason: &str, message: &str) -> serde_json::Value {
    serde_json::json!({ "ok": false, "reason": reason, "message": message })
}

fn bad_request(reason: &str, message: &str) -> Response<Full<Bytes>> {
    json_response(400, &err(reason, message))
}

fn unavailable() -> Response<Full<Bytes>> {
    json_response(
        503,
        &err(
            "accounts_store_unavailable",
            "runtime account management is not available on this node",
        ),
    )
}

fn store_error(detail: &str) -> Response<Full<Bytes>> {
    tracing::error!(error = %detail, "admin account op: store write failed");
    json_response(
        503,
        &err("store_error", "the account change could not be persisted; please retry"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_control::admin_auth::account_store::AdminAccountStore;
    use aegis_control::admin_auth::password::hash_password;
    use aegis_control::api::login::{AdminDirectory, AdminIdentity};
    use aegis_control::api::upstreams::PoolHealthSnapshot;
    use aegis_control::dashboard_services::DashboardServices;
    use aegis_core::AuditBus;
    use std::sync::Arc;

    async fn body_json(resp: Response<Full<Bytes>>) -> (u16, serde_json::Value) {
        let status = resp.status().as_u16();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[tokio::test]
    async fn list_handler_merges_seed_and_runtime_without_leaking_hashes() {
        let bus = AuditBus::new(64);
        let (mut services, _drain) = DashboardServices::spawn(
            bus,
            Arc::new(|| PoolHealthSnapshot { pools: Vec::new(), ..Default::default() }),
            None,
        );
        // Swap in a directory with a YAML seed + wired runtime store, then add
        // a runtime account (the boot path does this via with_account_store).
        let store = Arc::new(AdminAccountStore::in_memory());
        let seed = Arc::new(AdminIdentity {
            user: "admin".into(),
            password_hash: hash_password("aegis-test-1234").unwrap(),
            ..AdminIdentity::default()
        });
        services.admin_directory =
            Arc::new(AdminDirectory::new(vec![seed]).with_account_store(Arc::clone(&store)));
        services.admin_account_store = Arc::clone(&store);
        store.upsert("alice", &hash_password("alice-pw-123456").unwrap()).await.unwrap();

        let resp = handle_accounts_list("admin", &services).await;
        let (status, json) = body_json(resp).await;
        assert_eq!(status, 200);
        let accounts = json["accounts"].as_array().unwrap();
        let names: Vec<&str> = accounts.iter().map(|a| a["username"].as_str().unwrap()).collect();
        assert_eq!(names, vec!["admin", "alice"]);
        // The requesting actor's own row is flagged.
        assert_eq!(accounts[0]["is_self"], serde_json::json!(true));
        assert_eq!(accounts[1]["is_self"], serde_json::json!(false));
        // Non-secret metadata only — a password hash must never appear.
        assert!(
            !serde_json::to_string(&json).unwrap().contains("$argon2"),
            "accounts list must never carry a password hash",
        );
    }
}
