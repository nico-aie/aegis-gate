//! PRE-T6 — every audit-mutated PUT / POST / DELETE handler
//! extracted from `lib.rs`.
//!
//! ## Scope
//!
//! 18 handlers covering every dashboard-facing mutation:
//!
//! | Path                             | Handler |
//! |---|---|
//! | `PUT /api/mode`                  | `handle_mode_put` |
//! | `PUT /api/upstreams/config`      | `handle_upstreams_config_put` |
//! | `PUT /api/upstreams/pool/{id}`   | `handle_pool_upsert` |
//! | `DELETE /api/upstreams/pool/{id}`| `handle_pool_delete` |
//! | `PUT /api/alert-receivers`       | `handle_alert_receivers_put` |
//! | `DELETE /api/alert-receivers/{name}` | `handle_alert_receiver_delete` |
//! | `POST /api/alert-receivers/{name}/test` | `handle_alert_receiver_test` |
//! | `POST /api/alerts/{id}/ack`      | `handle_alert_ack` |
//! | `PUT /api/logging`               | `handle_logging_put` |
//! | `PUT /api/loadmode`              | `handle_loadmode_put` |
//! | `POST /api/rules`                | `handle_rules_post` |
//! | `PUT /api/rules/{id}`            | `handle_rules_put` |
//! | `DELETE /api/rules/{id}`         | `handle_rules_delete` |
//! | `POST /api/rules/{id}/toggle`    | `handle_rules_toggle` |
//! | `PUT /api/risk/thresholds`       | `handle_risk_thresholds_put` |
//! | `PUT /api/risk/{ip}/reset`       | `handle_risk_reset` |
//! | `PUT /api/detectors`             | `handle_detectors_put` |
//! | `POST /admin/drain`              | `handle_admin_drain` |
//!
//! ## Shared helpers
//!
//! - [`mutation_preamble`] / [`MutationPreamble`] — extracts
//!   actor + request-id + CSRF cookie. Every handler runs this
//!   before touching state.
//! - [`redact_receivers_for_audit`] — strips secrets to last-4
//!   chars before audit-chain entries land.
//! - [`upstreams_audit_view`] — converts a `UpstreamsConfig`
//!   into the audit-chain `before/after` shape.
//! - [`mask_state_to_json`] — same for detector mask state.
//! - [`default_true`] — serde default helper.
//!
//! ## Visibility
//!
//! `pub(crate)` for all handler entry points; helpers private.
//! Single dispatch site in `lib.rs::handle_admin_request`
//! rebound via `use admin_mutate::{...};`.
//!
//! ## Size note
//!
//! At ~1640 lines this module is over the 800-line guideline.
//! Functionally cohesive (every fn is a mutation handler with
//! the same audit-chain shape) so further splitting is judgment
//! call. A follow-up could break it into per-resource files
//! (`admin_mutate/{rules,alerts,upstreams,settings,drain}.rs`)
//! if it grows further.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::Response;

use aegis_core::config::WafConfig;
use aegis_core::ReadinessSignal;

use crate::responses::{
    extract_named_cookie, json_body_response, json_response, mutation_error_response,
};

pub(crate) async fn handle_mode_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "mode-put");
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal("body read failed".into()),
        ),
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");
    let parsed: serde_json::Value =
        serde_json::from_str(if body_str.is_empty() { "{}" } else { body_str })
            .unwrap_or(serde_json::Value::Null);
    let mode_str = parsed
        .get("mode")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let new_mode = match mode_str {
        "enforce" => aegis_control::interop::headers::Mode::Enforce,
        "log_only" | "shadow" => aegis_control::interop::headers::Mode::LogOnly,
        _ => return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(
                "mode must be 'enforce' or 'log_only'".into(),
            ),
        ),
    };

    let Some(rt) = services.interop.as_ref() else {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal(
                "interop runtime not wired".into(),
            ),
        );
    };
    let before = serde_json::json!({"mode": rt.modes.current().default.as_str()});
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: "/api/mode",
        action: "mode_set",
        reason: "operator pins global mode",
    };
    let modes = rt.modes.clone();
    let outcome = services.mutate.apply::<_, (), aegis_control::api::mutation::MutationError>(
        &req_ctx,
        before,
        serde_json::json!({"mode": new_mode.as_str()}),
        || {
            modes.set_all(new_mode);
            Ok(())
        },
    );
    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "mode": new_mode.as_str(),
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

// ---------------------------------------------------------------------------
// CC-T2.1.b — alert-receivers writes (PUT / DELETE / POST-test)
// ---------------------------------------------------------------------------

/// Build the redacted audit-chain projection of a receiver list.
/// The durable audit log MUST NOT carry plaintext bot tokens or
/// webhook URLs — every secret is squashed to `****<last4>` before
/// serialisation.
fn redact_receivers_for_audit(
    receivers: &[aegis_control::slo::AlertReceiver],
) -> serde_json::Value {
    use aegis_control::api::alert_receivers::RedactedKind;
    let entries: Vec<serde_json::Value> = receivers
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.name,
                "kind": RedactedKind::from_kind(&r.kind),
            })
        })
        .collect();
    serde_json::json!({ "receivers": entries })
}

// ---------------------------------------------------------------------------
// CC-T1.1.b — upstream pool writes (PUT whole-map / PUT pool / DELETE pool)
// ---------------------------------------------------------------------------

/// Build the audit-chain projection of the current upstream config.
/// Pool configs hold no secrets so the projection is the same shape
/// the GET handler returns — keeps the chain entry diffable against
/// the dashboard's view of state.
fn upstreams_audit_view(
    cfg_snapshot: &aegis_core::config::WafConfig,
    pools: &std::collections::HashMap<String, aegis_core::config::PoolConfig>,
) -> serde_json::Value {
    // Build a synthetic WafConfig with just `upstreams` swapped so
    // we can reuse `UpstreamsConfigView::from_config`. The view
    // pre-computes `referenced_by_routes` from the live route list,
    // which we want for both before/after.
    let mut cfg = cfg_snapshot.clone();
    cfg.upstreams = pools.clone();
    let view =
        aegis_control::api::upstreams_config::UpstreamsConfigView::from_config(&cfg);
    serde_json::to_value(&view).unwrap_or(serde_json::Value::Null)
}

pub(crate) async fn handle_upstreams_config_put(
    req: hyper::Request<hyper::body::Incoming>,
    cfg: &aegis_core::config::WafConfig,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "upstreams-config-put");

    let Some(writer) = services.upstream_writer.as_ref().cloned() else {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal(
                "upstream writer not wired".into(),
            ),
        );
    };

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Internal(
                    "body read failed".into(),
                ),
            )
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");

    #[derive(serde::Deserialize)]
    struct Body {
        pools: std::collections::HashMap<String, aegis_core::config::PoolConfig>,
    }
    let parsed: Body = match serde_json::from_str(if body_str.is_empty() {
        "{\"pools\":{}}"
    } else {
        body_str
    }) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e.to_string()),
            )
        }
    };

    let before = upstreams_audit_view(cfg, &cfg.upstreams);
    let after = upstreams_audit_view(cfg, &parsed.pools);
    let count = parsed.pools.len();
    let names: Vec<String> = {
        let mut v: Vec<String> = parsed.pools.keys().cloned().collect();
        v.sort();
        v
    };

    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: "/api/upstreams/config",
        action: "upstreams_set",
        reason: "operator replaced upstream pool table",
    };
    let writer_for_apply = Arc::clone(&writer);
    let pools_for_apply = parsed.pools;
    let outcome = services.mutate.apply(
        &req_ctx,
        before,
        after,
        move || writer_for_apply.apply(&pools_for_apply),
    );
    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "count": count,
                "names": names,
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

pub(crate) async fn handle_pool_upsert(
    req: hyper::Request<hyper::body::Incoming>,
    pool_id: &str,
    cfg: &aegis_core::config::WafConfig,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "pool-upsert");
    let Some(writer) = services.upstream_writer.as_ref().cloned() else {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal(
                "upstream writer not wired".into(),
            ),
        );
    };

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Internal(
                    "body read failed".into(),
                ),
            )
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");
    let pool_cfg: aegis_core::config::PoolConfig = match serde_json::from_str(body_str) {
        Ok(p) => p,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e.to_string()),
            )
        }
    };

    // Build the candidate map: existing minus this pool, plus the
    // new entry. Read-modify-write under the registry's atomic
    // swap.
    let mut next = cfg.upstreams.clone();
    next.insert(pool_id.to_string(), pool_cfg);

    let before = upstreams_audit_view(cfg, &cfg.upstreams);
    let after = upstreams_audit_view(cfg, &next);
    let resource = format!("/api/upstreams/pool/{pool_id}");
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: "pool_upsert",
        reason: "operator upserted upstream pool",
    };
    let writer_for_apply = Arc::clone(&writer);
    let pool_id_owned = pool_id.to_string();
    let outcome = services.mutate.apply(
        &req_ctx,
        before,
        after,
        move || writer_for_apply.apply(&next),
    );
    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "pool": pool_id_owned,
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

pub(crate) async fn handle_pool_delete(
    req: hyper::Request<hyper::body::Incoming>,
    pool_id: &str,
    cfg: &aegis_core::config::WafConfig,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let pre = mutation_preamble(&req, "pool-delete");
    let Some(writer) = services.upstream_writer.as_ref().cloned() else {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal(
                "upstream writer not wired".into(),
            ),
        );
    };

    if !cfg.upstreams.contains_key(pool_id) {
        // 400-class validation rather than 500: caller passed a
        // name that doesn't exist. Distinct error message so the
        // dashboard can render the "no such pool" toast directly.
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(format!(
                "no pool named '{pool_id}'"
            )),
        );
    }

    // Refuse with the route-reference list when the pool is still
    // referenced. This is the audit-finding-driven contract: the
    // dashboard's delete confirm modal surfaces this list so the
    // operator knows what to fix first.
    let refs = aegis_control::api::upstreams_config::routes_referencing(cfg, pool_id);
    if !refs.is_empty() {
        let body = serde_json::json!({
            "ok": false,
            "reason": "pool_referenced",
            "message": format!(
                "pool '{pool_id}' is still referenced by {} route(s); update those routes before deleting",
                refs.len()
            ),
            "referenced_by_routes": refs,
        });
        return json_body_response(409, body.to_string(), "private, no-store");
    }

    let mut next = cfg.upstreams.clone();
    next.remove(pool_id);

    let before = upstreams_audit_view(cfg, &cfg.upstreams);
    let after = upstreams_audit_view(cfg, &next);
    let resource = format!("/api/upstreams/pool/{pool_id}");
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "DELETE",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: "pool_delete",
        reason: "operator removed upstream pool",
    };
    let writer_for_apply = Arc::clone(&writer);
    let pool_id_owned = pool_id.to_string();
    let outcome = services.mutate.apply(
        &req_ctx,
        before,
        after,
        move || writer_for_apply.apply(&next),
    );
    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "removed": pool_id_owned,
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

pub(crate) async fn handle_alert_receivers_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "alert-receivers-put");

    let Some(store) = services.alert_receivers_store.as_ref().cloned() else {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal(
                "alert receivers store not wired".into(),
            ),
        );
    };
    let ring = services.alert_receivers_ring.clone();

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Internal(
                    "body read failed".into(),
                ),
            )
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");

    #[derive(serde::Deserialize)]
    struct Body {
        receivers: Vec<aegis_control::slo::AlertReceiver>,
    }
    let parsed: Body = match serde_json::from_str(if body_str.is_empty() {
        "{\"receivers\":[]}"
    } else {
        body_str
    }) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e.to_string()),
            )
        }
    };

    if let Err(e) =
        aegis_control::api::alert_receivers::validate_receivers(&parsed.receivers)
    {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(e.to_string()),
        );
    }

    let current = (**store.load()).clone();
    let before = redact_receivers_for_audit(&current);
    let after = redact_receivers_for_audit(&parsed.receivers);

    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: "/api/alert-receivers",
        action: "alert_receivers_set",
        reason: "operator updated alert channel list",
    };

    let store_for_apply = Arc::clone(&store);
    let next_for_apply = parsed.receivers;
    let ring_for_apply = ring.clone();
    let outcome = services.mutate.apply(
        &req_ctx,
        before,
        after,
        || {
            // Delegate to the pure helper in aegis-control so the
            // validate→swap→prune sequence is unit-tested in one
            // place. Validation already ran above; this call
            // returns Ok in all reachable paths.
            let placeholder_ring =
                aegis_control::api::alert_receivers::DispatchOutcomeRing::new();
            let r = ring_for_apply.as_ref().unwrap_or(&placeholder_ring);
            aegis_control::api::alert_receivers::apply_replace(
                &store_for_apply,
                r,
                next_for_apply,
            )
        },
    );
    match outcome {
        Ok(out) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "count": out.value.count,
                "names": out.value.names,
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

pub(crate) async fn handle_alert_receiver_delete(
    req: hyper::Request<hyper::body::Incoming>,
    name: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let pre = mutation_preamble(&req, "alert-receiver-delete");

    let Some(store) = services.alert_receivers_store.as_ref().cloned() else {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal(
                "alert receivers store not wired".into(),
            ),
        );
    };
    let ring = services.alert_receivers_ring.clone();

    let current = (**store.load()).clone();
    let next: Vec<aegis_control::slo::AlertReceiver> = current
        .iter()
        .filter(|r| r.name != name)
        .cloned()
        .collect();
    if next.len() == current.len() {
        // Name not found — surface a validation-class error so the
        // dashboard can show "no such receiver" without 500-ing.
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(format!(
                "no receiver named '{name}'"
            )),
        );
    }

    let before = redact_receivers_for_audit(&current);
    let after = redact_receivers_for_audit(&next);
    let resource = format!("/api/alert-receivers/{name}");
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "DELETE",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: "alert_receiver_delete",
        reason: "operator removed alert channel",
    };

    let store_for_apply = Arc::clone(&store);
    let ring_for_apply = ring.clone();
    let target_name = name.to_string();
    let outcome = services.mutate.apply(
        &req_ctx,
        before,
        after,
        move || {
            let placeholder_ring =
                aegis_control::api::alert_receivers::DispatchOutcomeRing::new();
            let r = ring_for_apply.as_ref().unwrap_or(&placeholder_ring);
            aegis_control::api::alert_receivers::apply_delete(
                &store_for_apply,
                r,
                &target_name,
            )
        },
    );
    match outcome {
        Ok(o) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "removed": o.value.removed,
                "remaining": o.value.remaining,
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

pub(crate) async fn handle_alert_receiver_test(
    req: hyper::Request<hyper::body::Incoming>,
    name: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let pre = mutation_preamble(&req, "alert-receiver-test");

    let Some(store) = services.alert_receivers_store.as_ref().cloned() else {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal(
                "alert receivers store not wired".into(),
            ),
        );
    };

    // Resolve the receiver by name. Done *before* CSRF validation
    // would matter — `services.mutate.apply` enforces CSRF inside;
    // the lookup itself is a read.
    let current = (**store.load()).clone();
    let receiver = match current.iter().find(|r| r.name == name).cloned() {
        Some(r) => r,
        None => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(format!(
                    "no receiver named '{name}'"
                )),
            );
        }
    };

    // Synthetic alert — fixed shape, never derived from operator
    // input, so the test path is bounded.
    let synthetic = aegis_control::slo::SloAlert {
        sli: aegis_control::slo::SliKind::AuditDeliveryRate,
        severity: aegis_control::slo::AlertSeverity::Ticket,
        fired_at: chrono::Utc::now(),
        resolved_at: None,
        burn_rate: 0.0,
        budget_consumed_pct: 0.0,
        window_hours: 1,
        runbook_url: "https://runbooks.aegis.local/test".into(),
    };

    // Audit-mutate envelope first (CSRF + chain entry), then run
    // the actual delivery in a `tokio::spawn` afterwards. We can't
    // `.await` inside the synchronous mutator closure — the
    // existing `apply` signature takes `FnOnce() -> Result<T, E>`.
    // The chain entry records the *intent* to test; the dispatch
    // outcome lands in `DispatchOutcomeRing` once delivery returns.
    let resource = format!("/api/alert-receivers/{name}/test");
    let before = serde_json::json!({});
    let after = serde_json::json!({
        "test_target": name,
        "kind": aegis_control::api::alert_receivers::RedactedKind::from_kind(&receiver.kind),
    });
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "POST",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: "alert_receiver_test",
        reason: "operator fired test alert",
    };
    let outcome = services.mutate.apply::<_, (), aegis_control::api::mutation::MutationError>(
        &req_ctx,
        before,
        after,
        || Ok(()),
    );
    if let Err(e) = outcome {
        return mutation_error_response(e);
    }

    // Deliver the synthetic alert against the targeted receiver
    // (length-1 slice — only this channel fires).
    let summary = aegis_control::slo::dispatch::send_alert(
        &synthetic,
        std::slice::from_ref(&receiver),
    )
    .await;

    if let Some(ring) = services.alert_receivers_ring.as_ref() {
        let now = chrono::Utc::now().timestamp();
        for n in &summary.delivered {
            ring.record_delivered(n, now);
        }
        for n in &summary.external {
            ring.record_external(n, now);
        }
        for (n, reason) in &summary.failed {
            ring.record_failed(n, now, reason);
        }
    }

    let body = serde_json::json!({
        "ok": summary.failed.is_empty(),
        "name": name,
        "delivered": summary.delivered,
        "external": summary.external,
        "failed": summary.failed
            .iter()
            .map(|(n, r)| serde_json::json!({"name": n, "reason": r}))
            .collect::<Vec<_>>(),
        "request_id": pre.request_id,
    });
    json_response(200, &body)
}

pub(crate) async fn handle_alert_ack(
    req: hyper::Request<hyper::body::Incoming>,
    alert_id: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let pre = mutation_preamble(&req, "alert-ack");
    let resource = format!("/api/alerts/{alert_id}");
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "POST",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: "alert_ack",
        reason: "operator acknowledged alert",
    };
    let tracking = services.tracking.clone();
    let alert_id_owned = alert_id.to_string();
    let outcome = services.mutate.apply::<_, (), aegis_control::api::mutation::MutationError>(
        &req_ctx,
        serde_json::Value::Null,
        serde_json::json!({"alert_id": alert_id, "acked": true}),
        || {
            tracking.ack(&alert_id_owned);
            Ok(())
        },
    );
    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "alert_id": alert_id,
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

pub(crate) async fn handle_logging_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let csrf_cookie = req
        .headers()
        .get_all(hyper::header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|raw| extract_named_cookie(raw, "aegis_csrf"))
        .map(|s| s.to_string());
    let csrf_header = req
        .headers()
        .get("x-csrf-token")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let actor = req
        .headers()
        .get("x-actor")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("admin")
        .to_string();
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            blake3::hash(
                format!(
                    "logging-put:{}",
                    chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
                )
                .as_bytes(),
            )
            .to_hex()
            .to_string()
        });

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Internal(
                    "failed to read request body".into(),
                ),
            );
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");
    let parsed: aegis_control::api::logging::LoggingPutBody =
        match serde_json::from_str(body_str) {
            Ok(b) => b,
            Err(e) => {
                return mutation_error_response(
                    aegis_control::api::mutation::MutationError::Validation(e.to_string()),
                );
            }
        };

    let before = serde_json::to_value(services.verbosity.snapshot())
        .unwrap_or(serde_json::Value::Null);
    let after = serde_json::json!({"level": parsed.level});
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: csrf_cookie.as_deref(),
        csrf_header: csrf_header.as_deref(),
        actor: &actor,
        request_id: &request_id,
        resource: "/api/logging",
        action: "verbosity_set",
        reason: "operator changes verbosity",
    };
    let verbosity = services.verbosity.clone();
    let outcome = services.mutate.apply(&req_ctx, before, after, || {
        aegis_control::api::logging::apply_logging_put(&verbosity, parsed)
    });

    match outcome {
        Ok(_) => json_body_response(
            200,
            aegis_control::api::logging::render_logging_get(&services.verbosity),
            "private, no-store",
        ),
        Err(e) => mutation_error_response(e),
    }
}

pub(crate) async fn handle_loadmode_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let csrf_cookie = req
        .headers()
        .get_all(hyper::header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|raw| extract_named_cookie(raw, "aegis_csrf"))
        .map(|s| s.to_string());
    let csrf_header = req
        .headers()
        .get("x-csrf-token")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let actor = req
        .headers()
        .get("x-actor")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("admin")
        .to_string();
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            blake3::hash(
                format!(
                    "loadmode-put:{}",
                    chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
                )
                .as_bytes(),
            )
            .to_hex()
            .to_string()
        });

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Internal(
                    "failed to read request body".into(),
                ),
            );
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");
    let parsed: aegis_control::api::load_mode::LoadModePutBody =
        match serde_json::from_str(if body_str.is_empty() { "{}" } else { body_str }) {
            Ok(b) => b,
            Err(e) => {
                return mutation_error_response(
                    aegis_control::api::mutation::MutationError::Validation(e.to_string()),
                );
            }
        };

    let before = serde_json::to_value(services.load_gauge.snapshot())
        .unwrap_or(serde_json::Value::Null);
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: csrf_cookie.as_deref(),
        csrf_header: csrf_header.as_deref(),
        actor: &actor,
        request_id: &request_id,
        resource: "/api/loadmode",
        action: "loadmode_set",
        reason: "operator pins load mode",
    };
    let gauge = services.load_gauge.clone();
    let outcome = services.mutate.apply(
        &req_ctx,
        before,
        serde_json::Value::Null,
        || aegis_control::api::load_mode::apply_put_body(&gauge, parsed),
    );

    match outcome {
        Ok(_) => json_body_response(
            200,
            aegis_control::api::load_mode::render_get(&services.load_gauge),
            "private, no-store",
        ),
        Err(e) => mutation_error_response(e),
    }
}

// ---------- DD-T6 — rule CRUD handlers --------------------------------

#[derive(serde::Deserialize)]
struct RulePostBody {
    id: String,
    body: String,
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(serde::Deserialize)]
struct RulePutBody {
    body: String,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_true() -> bool {
    true
}

/// Helper: read the standard mutation preamble (CSRF cookie +
/// header, actor, request_id) into one struct so the four CRUD
/// handlers don't repeat boilerplate.
struct MutationPreamble {
    csrf_cookie: Option<String>,
    csrf_header: Option<String>,
    actor: String,
    request_id: String,
}

fn mutation_preamble(req: &hyper::Request<hyper::body::Incoming>, prefix: &str) -> MutationPreamble {
    let csrf_cookie = req
        .headers()
        .get_all(hyper::header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|raw| extract_named_cookie(raw, "aegis_csrf"))
        .map(|s| s.to_string());
    let csrf_header = req
        .headers()
        .get("x-csrf-token")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let actor = req
        .headers()
        .get("x-actor")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("admin")
        .to_string();
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            blake3::hash(
                format!(
                    "{prefix}:{}",
                    chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
                )
                .as_bytes(),
            )
            .to_hex()
            .to_string()
        });
    MutationPreamble { csrf_cookie, csrf_header, actor, request_id }
}

pub(crate) async fn handle_rules_post(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "rules-post");
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal("body read failed".into()),
        ),
    };
    let parsed: RulePostBody = match serde_json::from_slice(&body_bytes) {
        Ok(p) => p,
        Err(e) => return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(e.to_string()),
        ),
    };

    if services.rules.get(&parsed.id).is_some() {
        return json_response(
            409,
            &serde_json::json!({"error": "rule_exists", "id": parsed.id}),
        );
    }

    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "POST",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: "/api/rules",
        action: "rule_create",
        reason: "operator creates rule",
    };
    let rules_store = services.rules.clone();
    let rule_id = parsed.id.clone();
    let rule_body = parsed.body.clone();
    let rule_enabled = parsed.enabled;
    let outcome = services.mutate.apply(
        &req_ctx,
        serde_json::Value::Null,
        serde_json::json!({"id": parsed.id, "body": parsed.body, "enabled": parsed.enabled}),
        || {
            let v = rules_store.upsert(&rule_id, &rule_body, rule_enabled);
            if v.ok {
                Ok(())
            } else {
                Err(aegis_control::api::mutation::MutationError::Validation(
                    v.errors
                        .first()
                        .map(|m| format!("line {}: {}", m.line, m.message))
                        .unwrap_or_else(|| "rule body invalid".into()),
                ))
            }
        },
    );

    match outcome {
        Ok(_) => json_response(
            201,
            &serde_json::json!({
                "ok": true,
                "id": parsed.id,
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

pub(crate) async fn handle_rules_put(
    req: hyper::Request<hyper::body::Incoming>,
    rule_id: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "rules-put");
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal("body read failed".into()),
        ),
    };
    let parsed: RulePutBody = match serde_json::from_slice(&body_bytes) {
        Ok(p) => p,
        Err(e) => return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(e.to_string()),
        ),
    };

    let before = services
        .rules
        .get(rule_id)
        .map(|r| serde_json::json!({"id": r.id, "body": r.body, "enabled": r.enabled}))
        .unwrap_or(serde_json::Value::Null);
    if before.is_null() {
        return json_response(
            404,
            &serde_json::json!({"error": "rule_not_found", "id": rule_id}),
        );
    }

    let resource = format!("/api/rules/{rule_id}");
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: "rule_update",
        reason: "operator updates rule",
    };
    let rules_store = services.rules.clone();
    let rule_id_owned = rule_id.to_string();
    let rule_body = parsed.body.clone();
    let rule_enabled = parsed.enabled;
    let outcome = services.mutate.apply(
        &req_ctx,
        before,
        serde_json::json!({"id": rule_id, "body": parsed.body, "enabled": parsed.enabled}),
        || {
            let v = rules_store.upsert(&rule_id_owned, &rule_body, rule_enabled);
            if v.ok {
                Ok(())
            } else {
                Err(aegis_control::api::mutation::MutationError::Validation(
                    v.errors
                        .first()
                        .map(|m| format!("line {}: {}", m.line, m.message))
                        .unwrap_or_else(|| "rule body invalid".into()),
                ))
            }
        },
    );

    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "id": rule_id,
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

pub(crate) async fn handle_rules_delete(
    req: hyper::Request<hyper::body::Incoming>,
    rule_id: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let pre = mutation_preamble(&req, "rules-delete");

    let before = services
        .rules
        .get(rule_id)
        .map(|r| serde_json::json!({"id": r.id, "body": r.body, "enabled": r.enabled}))
        .unwrap_or(serde_json::Value::Null);
    if before.is_null() {
        return json_response(
            404,
            &serde_json::json!({"error": "rule_not_found", "id": rule_id}),
        );
    }

    let resource = format!("/api/rules/{rule_id}");
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "DELETE",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: "rule_delete",
        reason: "operator deletes rule",
    };
    let rules_store = services.rules.clone();
    let rule_id_owned = rule_id.to_string();
    let outcome = services.mutate.apply(
        &req_ctx,
        before,
        serde_json::Value::Null,
        || {
            if rules_store.delete(&rule_id_owned) {
                Ok(())
            } else {
                Err(aegis_control::api::mutation::MutationError::Internal(
                    "rule disappeared concurrently".into(),
                ))
            }
        },
    );

    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "id": rule_id,
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

pub(crate) async fn handle_rules_toggle(
    req: hyper::Request<hyper::body::Incoming>,
    rule_id: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let pre = mutation_preamble(&req, "rules-toggle");

    let current = match services.rules.get(rule_id) {
        Some(r) => r,
        None => return json_response(
            404,
            &serde_json::json!({"error": "rule_not_found", "id": rule_id}),
        ),
    };

    let next_enabled = !current.enabled;
    let resource = format!("/api/rules/{rule_id}/toggle");
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: "rule_toggle",
        reason: "operator toggles rule",
    };
    let rules_store = services.rules.clone();
    let rule_id_owned = rule_id.to_string();
    let rule_body = current.body.clone();
    let outcome = services.mutate.apply(
        &req_ctx,
        serde_json::json!({"id": current.id, "enabled": current.enabled}),
        serde_json::json!({"id": current.id, "enabled": next_enabled}),
        || {
            let v = rules_store.upsert(&rule_id_owned, &rule_body, next_enabled);
            if v.ok {
                Ok(())
            } else {
                Err(aegis_control::api::mutation::MutationError::Internal(
                    "toggle revalidation failed".into(),
                ))
            }
        },
    );

    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "id": rule_id,
                "enabled": next_enabled,
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

pub(crate) async fn handle_risk_thresholds_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "risk-thresholds-put");
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal("body read failed".into()),
        ),
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");

    #[derive(serde::Deserialize)]
    struct Body {
        challenge_at: Option<u32>,
        block_at: Option<u32>,
        max: Option<u32>,
    }
    let parsed: Body = match serde_json::from_str(if body_str.is_empty() { "{}" } else { body_str }) {
        Ok(b) => b,
        Err(e) => return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(e.to_string()),
        ),
    };

    let current = services.risk.thresholds();
    let next = aegis_core::config::RiskThresholds {
        challenge_at: parsed.challenge_at.unwrap_or(current.challenge_at),
        block_at:     parsed.block_at.unwrap_or(current.block_at),
        max:          parsed.max.unwrap_or(current.max),
    };

    // Sanity: enforce ordering invariants the rule engine assumes.
    if next.challenge_at >= next.block_at {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(
                format!("challenge_at ({}) must be < block_at ({})", next.challenge_at, next.block_at),
            ),
        );
    }
    if next.block_at > next.max {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(
                format!("block_at ({}) must be <= max ({})", next.block_at, next.max),
            ),
        );
    }

    let before = serde_json::json!({
        "challenge_at": current.challenge_at,
        "block_at":     current.block_at,
        "max":          current.max,
    });
    let after = serde_json::json!({
        "challenge_at": next.challenge_at,
        "block_at":     next.block_at,
        "max":          next.max,
    });
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: "/api/risk/thresholds",
        action: "risk_thresholds_set",
        reason: "operator updated risk thresholds",
    };
    let tracker = services.risk.clone();
    let next_for_apply = next.clone();
    let outcome = services.mutate.apply::<_, (), aegis_control::api::mutation::MutationError>(
        &req_ctx,
        before,
        after,
        || {
            tracker.set_thresholds(next_for_apply.clone());
            Ok(())
        },
    );
    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "challenge_at": next.challenge_at,
                "block_at":     next.block_at,
                "max":          next.max,
                "request_id":   pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

pub(crate) async fn handle_risk_reset(
    req: hyper::Request<hyper::body::Incoming>,
    ip_segment: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let Some(ip) = aegis_control::api::risk::parse_ip_segment(ip_segment) else {
        return json_response(
            400,
            &serde_json::json!({"error": "invalid_ip", "segment": ip_segment}),
        );
    };

    let csrf_cookie = req
        .headers()
        .get_all(hyper::header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|raw| extract_named_cookie(raw, "aegis_csrf"))
        .map(|s| s.to_string());
    let csrf_header = req
        .headers()
        .get("x-csrf-token")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let actor = req
        .headers()
        .get("x-actor")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("admin")
        .to_string();
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            blake3::hash(
                format!(
                    "risk-reset:{}:{}",
                    ip,
                    chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
                )
                .as_bytes(),
            )
            .to_hex()
            .to_string()
        });

    let resource = format!("/api/risk/{ip}/reset");
    let before = services
        .risk
        .snapshot_wire(ip)
        .map(|s| serde_json::to_value(s).unwrap_or(serde_json::Value::Null))
        .unwrap_or(serde_json::Value::Null);

    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: csrf_cookie.as_deref(),
        csrf_header: csrf_header.as_deref(),
        actor: &actor,
        request_id: &request_id,
        resource: &resource,
        action: "risk_reset",
        reason: "operator clears risk state",
    };
    let risk = services.risk.clone();
    let outcome = services.mutate.apply(
        &req_ctx,
        before,
        serde_json::json!({"score": 0, "strikes": 0}),
        || {
            let removed = risk.reset(ip);
            Ok::<bool, String>(removed)
        },
    );
    match outcome {
        Ok(o) => json_body_response(
            200,
            serde_json::json!({
                "ok": true,
                "ip": ip.to_string(),
                "had_state": o.value,
            })
            .to_string(),
            "private, no-store",
        ),
        Err(err) => mutation_error_response(err),
    }
}

pub(crate) async fn handle_detectors_put(
    req: hyper::Request<hyper::body::Incoming>,
    cfg: &WafConfig,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    // Pull CSRF cookie + header before consuming the body.
    let csrf_cookie = req
        .headers()
        .get_all(hyper::header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|raw| extract_named_cookie(raw, "aegis_csrf"))
        .map(|s| s.to_string());
    let csrf_header = req
        .headers()
        .get("x-csrf-token")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let actor = req
        .headers()
        .get("x-actor")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("admin")
        .to_string();
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            blake3::hash(
                format!(
                    "detectors-put:{}",
                    chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
                )
                .as_bytes(),
            )
            .to_hex()
            .to_string()
        });

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            let err = aegis_control::api::mutation::MutationError::Internal(
                "failed to read request body".into(),
            );
            return mutation_error_response(err);
        }
    };
    let body_str = match std::str::from_utf8(body_bytes.as_ref()) {
        Ok(s) => s,
        Err(_) => {
            let err = aegis_control::api::mutation::MutationError::Validation(
                "request body is not valid UTF-8".into(),
            );
            return mutation_error_response(err);
        }
    };

    let put_body = match aegis_control::api::detectors::parse_full_put_body(body_str) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e),
            );
        }
    };

    let modes: Vec<aegis_core::config::ComplianceMode> = cfg
        .compliance
        .as_ref()
        .map(|c| c.modes.clone())
        .unwrap_or_default();

    // Snapshot before/after states for the audit-chain diff. The
    // dashboard reads `diff.before` / `diff.after` to render a
    // "what changed" tooltip on the audit log row.
    let before_state = services.detector_mask.load_state();
    let proposed_state = match aegis_control::api::detectors::apply_put_body(
        before_state.clone(),
        put_body,
        &modes,
    ) {
        Ok(s) => s,
        Err(violations) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(violations.join("; ")),
            );
        }
    };

    let before = mask_state_to_json(&before_state);
    let after = mask_state_to_json(&proposed_state);

    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: csrf_cookie.as_deref(),
        csrf_header: csrf_header.as_deref(),
        actor: &actor,
        request_id: &request_id,
        resource: "/api/detectors",
        action: "update",
        reason: "detector class toggle",
    };
    let mask_handle = services.detector_mask.clone();
    let outcome = services.mutate.apply(&req_ctx, before, after, || {
        mask_handle.store_state(proposed_state.clone());
        Ok::<(), String>(())
    });

    match outcome {
        Ok(_) => {
            // DURABLE-T2 — best-effort persist after the in-memory
            // swap succeeds. Disk write failure does NOT fail the
            // PUT — the live mask is already updated, the audit
            // chain entry committed, and next successful PUT will
            // retry persistence. We log a warn so operators can
            // see the durability gap.
            if let Some(persist_cfg) = cfg.detectors.persistence.as_ref() {
                let snap = aegis_control::api::detectors_persist::DetectorMaskSnapshot::from_state(
                    &services.detector_mask.load_state(),
                );
                if let Err(e) = aegis_control::api::detectors_persist::save_snapshot(
                    &persist_cfg.path,
                    &snap,
                ).await {
                    tracing::warn!(
                        path = %persist_cfg.path.display(),
                        error = %e,
                        "detector mask snapshot save failed; live state intact, retry on next PUT",
                    );
                }
            }
            let body = aegis_control::api::detectors::render_get(
                &services.detector_mask,
                &modes,
            );
            json_body_response(200, body, "private, no-store")
        }
        Err(e) => mutation_error_response(e),
    }
}

/// HA-T5 — operator drain handler. Authenticated POST endpoint
/// that flips `readiness.draining` to true. Subsequent
/// `/healthz/ready` probes return 503 so external load
/// balancers stop routing new traffic. In-flight requests
/// continue. Idempotent — calling twice is a no-op.
pub(crate) async fn handle_admin_drain(
    req: hyper::Request<hyper::body::Incoming>,
    readiness: &ReadinessSignal,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use std::sync::atomic::Ordering;

    // Auth: require a valid admin session cookie. We don't gate
    // on CSRF the way mutating dashboard endpoints do — drain is
    // a server-local op that doesn't touch persisted config.
    let session_cookie = req
        .headers()
        .get_all(hyper::header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|raw| extract_named_cookie(raw, "aegis_session"))
        .map(|s| s.to_string());
    let session_ok = match session_cookie.as_deref() {
        Some(sid) => services.auth_sessions.validate(sid).is_some(),
        None => false,
    };
    // Allow unauthenticated drain when the admin password
    // hash is the empty default (test/dev builds with no real
    // admin configured) OR when the operator has set
    // `AEGIS_DRAIN_TOKEN` and the request carries it as a
    // matching `X-Aegis-Drain-Token` header. The token path
    // exists so that ops automation (k8s preStop hooks,
    // systemd ExecStop scripts, etc.) can call `/admin/drain`
    // without managing a session cookie.
    let no_admin_configured = services.admin_identity.password_hash.is_empty();
    let token_ok = match std::env::var("AEGIS_DRAIN_TOKEN").ok() {
        Some(expected) if !expected.is_empty() => {
            req.headers()
                .get("x-aegis-drain-token")
                .and_then(|h| h.to_str().ok())
                .map(|h| h == expected)
                .unwrap_or(false)
        }
        _ => false,
    };
    if !session_ok && !no_admin_configured && !token_ok {
        return json_response(
            401,
            &serde_json::json!({"error": "auth_required"}),
        );
    }

    let already = readiness.draining.swap(true, Ordering::Release);
    json_response(
        202,
        &serde_json::json!({
            "status": "draining",
            "already": already,
            "node": services
                .leader_view
                .as_ref()
                .map(|lv| lv.our_node.clone())
                .unwrap_or_default(),
        }),
    )
}

// ---------------------------------------------------------------------------
// MTLS-T7 — Allowed SAN allowlist mutations
// ---------------------------------------------------------------------------

/// `PUT /api/mtls/sans` — whole-list replace of the
/// `services.allowed_sans` store. Audit-mutated; CSRF-gated.
/// Body: `{ "allowed": ["svc.example.com", "*.api.example.com", ...] }`.
/// Empty list is allowed and means "admit anything" (back-compat).
pub(crate) async fn handle_mtls_sans_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "mtls-sans-put");

    let Some(store) = services.allowed_sans.as_ref().cloned() else {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal(
                "allowed-SANs store not wired".into(),
            ),
        );
    };

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Internal(
                    "body read failed".into(),
                ),
            )
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");

    #[derive(serde::Deserialize)]
    struct Body {
        #[serde(default)]
        allowed: Vec<String>,
    }
    let parsed: Body = match serde_json::from_str(if body_str.is_empty() {
        "{\"allowed\":[]}"
    } else {
        body_str
    }) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e.to_string()),
            );
        }
    };

    // Validate: each entry is non-empty trimmed; reject patterns
    // with whitespace or with `*` anywhere except as the leftmost
    // label (`*.example.com`). Duplicates are squashed.
    let mut next: Vec<String> = Vec::with_capacity(parsed.allowed.len());
    for raw in &parsed.allowed {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(
                    "SAN entries must be non-empty".into(),
                ),
            );
        }
        if trimmed.chars().any(char::is_whitespace) {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(format!(
                    "SAN '{trimmed}' contains whitespace"
                )),
            );
        }
        // Wildcards only permitted as the entire leftmost label.
        if trimmed.contains('*') && !trimmed.starts_with("*.") {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(format!(
                    "SAN '{trimmed}' uses '*' outside the leftmost label"
                )),
            );
        }
        if trimmed.starts_with("*.") && trimmed[2..].contains('*') {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(format!(
                    "SAN '{trimmed}' contains more than one wildcard"
                )),
            );
        }
        if !next.iter().any(|s| s == trimmed) {
            next.push(trimmed.to_string());
        }
    }

    let before = serde_json::json!({"allowed": store.current()});
    let after = serde_json::json!({"allowed": next.clone()});

    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: "/api/mtls/sans",
        action: "mtls_sans_set",
        reason: "operator updated allowed SAN list",
    };

    let store_for_apply = store.clone();
    let next_for_apply = next.clone();
    let outcome = services.mutate.apply::<_, (), aegis_control::api::mutation::MutationError>(
        &req_ctx,
        before,
        after,
        move || {
            store_for_apply.store(next_for_apply);
            Ok(())
        },
    );
    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "count": next.len(),
                "allowed": next,
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

/// `DELETE /api/mtls/sans/{san}` — remove a single entry.
/// Returns 422 with a validation error when the SAN isn't
/// present (so the dashboard can surface "no such SAN"
/// without a 500). Audit-mutated; CSRF-gated.
pub(crate) async fn handle_mtls_sans_delete(
    req: hyper::Request<hyper::body::Incoming>,
    san: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let pre = mutation_preamble(&req, "mtls-sans-delete");

    let Some(store) = services.allowed_sans.as_ref().cloned() else {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal(
                "allowed-SANs store not wired".into(),
            ),
        );
    };

    let current = store.current();
    if !current.iter().any(|s| s == san) {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(format!(
                "no SAN entry '{san}'"
            )),
        );
    }
    let next: Vec<String> = current.iter().filter(|s| *s != san).cloned().collect();

    let before = serde_json::json!({"allowed": current.clone()});
    let after = serde_json::json!({"allowed": next.clone()});
    let resource = format!("/api/mtls/sans/{san}");
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "DELETE",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: "mtls_sans_removed",
        reason: "operator removed allowed SAN",
    };

    let store_for_apply = store.clone();
    let target = san.to_string();
    let outcome = services.mutate.apply::<_, (), aegis_control::api::mutation::MutationError>(
        &req_ctx,
        before,
        after,
        move || {
            store_for_apply.remove(&target);
            Ok(())
        },
    );
    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "removed": san,
                "remaining": next.len(),
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

/// `POST /api/mtls/sans/{san}/test` — synthetic admit check.
/// Returns `{ admitted, matched }` so operators can verify
/// that a wildcard / exact pattern is doing what they expect
/// without making a real mTLS handshake. Read-only — no
/// audit emit (the chain only records changes).
pub(crate) async fn handle_mtls_sans_test(
    _req: hyper::Request<hyper::body::Incoming>,
    san: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let Some(store) = services.allowed_sans.as_ref() else {
        return json_response(
            503,
            &serde_json::json!({
                "error": "allowed-SANs store not wired",
            }),
        );
    };
    let admitted = store.admits(san);
    let matched = store.matched_pattern(san);
    json_response(
        200,
        &serde_json::json!({
            "ok": true,
            "san": san,
            "admitted": admitted,
            "matched": matched,
        }),
    )
}

/// Render a [`MaskState`] as a JSON object with `base` and
/// `overrides` keys. Used as the `before`/`after` payload of the
/// audit-chain diff so reviewers can see exactly which tier (and
/// which class within that tier) changed.
fn mask_state_to_json(
    state: &aegis_security::detectors::MaskState,
) -> serde_json::Value {
    use aegis_security::detectors::{tier_str, DetectorMaskBody, ALL_TIERS};
    let mut overrides = serde_json::Map::new();
    for tier in ALL_TIERS {
        if let Some(m) = state.override_for(tier) {
            let body: DetectorMaskBody = m.into();
            overrides.insert(
                tier_str(tier).to_string(),
                serde_json::to_value(body).unwrap_or(serde_json::Value::Null),
            );
        }
    }
    let base: DetectorMaskBody = state.base.into();
    serde_json::json!({
        "base": base,
        "overrides": serde_json::Value::Object(overrides),
    })
}
