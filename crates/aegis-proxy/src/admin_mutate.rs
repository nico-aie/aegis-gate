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

    // 2026-05-11 (PR-DNS-1) — resolve any hostname members before
    // they reach the live `PoolRegistry`. The before/after audit
    // view reflects the operator's authored shape (which may carry
    // hostnames); the registry-bound config carries the resolved
    // IP literals so the LB strategies have something to distribute
    // across.
    let resolved_pools = match crate::upstream::dns_resolve::expand_hostname_members(
        parsed.pools.clone(),
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e.to_string()),
            );
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
    let pools_for_apply = resolved_pools;
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

    // 2026-05-11 (PR-DNS-1) — resolve hostnames in the candidate
    // map so the registry only ever sees IP-literal members. The
    // audit view (`after`) keeps the operator's authored shape so
    // hostnames show up in the chain.
    let next = match crate::upstream::dns_resolve::expand_hostname_members(next).await {
        Ok(r) => r,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e.to_string()),
            );
        }
    };

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
        for n in &summary.skipped_feature_off {
            ring.record_failed(
                n,
                now,
                "binary built without `alerts` feature — rebuild with FEATURES=\"... alerts\"",
            );
        }
    }

    // Honest `ok` flag: dispatch is only OK when nothing
    // failed AND nothing was silently skipped due to a
    // feature-off binary. Previous code returned ok=true on
    // skip — dashboard showed "sent" while no message left
    // the WAF.
    let body = serde_json::json!({
        "ok": summary.failed.is_empty() && summary.skipped_feature_off.is_empty(),
        "name": name,
        "delivered": summary.delivered,
        "external": summary.external,
        "failed": summary.failed
            .iter()
            .map(|(n, r)| serde_json::json!({"name": n, "reason": r}))
            .collect::<Vec<_>>(),
        "skipped_feature_off": summary.skipped_feature_off,
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

// MTLS-T10 — CA bundle validation + audit-emit. Audit-mutated,
// CSRF-gated, gated behind cfg.admin.dashboard_auth.allow_ca_upload.
//
// **Phase 1 of T10**: parse + preview + audit. The actual hot-swap
// of the live `ClientTrustStore` lands with the listener-rebuild
// track (the listeners' `TlsAcceptor` Arc has to be rotated to
// pick up new roots; the existing cfg-reload watcher does this
// for cfg.tls.certificates but not yet for the bundle alone).
//
// Request body: raw PEM bytes (`Content-Type: application/x-pem-file`
// or `text/plain`). Multipart parsing is deliberately avoided —
// the dashboard reads the file as text + posts it directly.
//
// Response: PreviewResponse + diff vs the previously-uploaded
// preview (we don't read the live trust store here; we only
// know what a previous upload looked like via the audit ring).
/// MTLS-T10 Phase 2 — read the `apply` query parameter. `apply=1` and
/// `apply=true` (case-insensitive) flip the PUT handler into hot-swap
/// mode. Anything else (absent, `0`, `false`, garbage) stays preview-
/// only so dashboards that fire the endpoint for diff-card preflight
/// don't accidentally swap roots.
pub(crate) fn ca_bundle_apply_flag(query: Option<&str>) -> bool {
    let Some(q) = query else {
        return false;
    };
    q.split('&').any(|pair| {
        let mut it = pair.splitn(2, '=');
        let k = it.next().unwrap_or("");
        let v = it.next().unwrap_or("");
        k == "apply" && (v == "1" || v.eq_ignore_ascii_case("true"))
    })
}

pub(crate) async fn handle_mtls_ca_bundle_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;
    if !services.allow_ca_upload {
        return json_response(
            403,
            &serde_json::json!({
                "error": "feature_disabled",
                "message": "CA bundle upload is gated behind cfg.admin.dashboard_auth.allow_ca_upload — flip to true and restart to enable.",
            }),
        );
    }

    // MTLS-T10 Phase 2 — `?apply=true` flips the handler from
    // preview-only into hot-swap mode. Default (absent / `false`)
    // stays preview so the dashboard's pre-flight diff card keeps
    // working without a payload change.
    let apply = ca_bundle_apply_flag(req.uri().query());

    let pre = mutation_preamble(&req, "mtls-ca-bundle-put");
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => bytes::Bytes::new(),
    };
    if body_bytes.is_empty() {
        return json_response(
            400,
            &serde_json::json!({"error": "empty_body", "message": "expected PEM bytes in body"}),
        );
    }

    let now = chrono::Utc::now().timestamp();
    let preview = aegis_control::api::mtls_ca_bundle::parse_and_preview(
        body_bytes.as_ref(),
        now,
    );

    if !preview.valid {
        return json_response(
            400,
            &serde_json::json!({
                "error": "invalid_pem",
                "preview": preview,
            }),
        );
    }

    // Phase 1 path — preview + audit, no hot-swap. Used by the
    // dashboard's pre-flight "Save & Apply" confirmation card.
    if !apply {
        let after_payload = serde_json::json!({
            "blocks_seen": preview.blocks_seen,
            "certificates": preview.certificates,
        });
        let req_ctx = aegis_control::api::mutation::MutationRequest {
            method: "PUT",
            csrf_cookie: pre.csrf_cookie.as_deref(),
            csrf_header: pre.csrf_header.as_deref(),
            actor: &pre.actor,
            request_id: &pre.request_id,
            resource: "/api/mtls/ca-bundle",
            action: "mtls_ca_bundle_validated",
            reason: "operator previewed CA bundle (no swap)",
        };
        let outcome = services.mutate.apply::<_, (), aegis_control::api::mutation::MutationError>(
            &req_ctx,
            serde_json::Value::Null,
            after_payload,
            || Ok(()),
        );
        return match outcome {
            Ok(_) => json_response(
                200,
                &serde_json::json!({
                    "ok": true,
                    "request_id": pre.request_id,
                    "preview": preview,
                    "applied": false,
                    "message": "Preview only — re-PUT with ?apply=true to hot-swap roots.",
                }),
            ),
            Err(e) => mutation_error_response(e),
        };
    }

    // Phase 2 path — hot-swap. Requires a wired
    // `trust_anchor_writer`; without it the proxy was booted
    // without inbound mTLS so there's nothing to swap.
    let Some(writer) = services.trust_anchor_writer.as_ref() else {
        return json_response(
            409,
            &serde_json::json!({
                "error": "trust_store_unavailable",
                "message": "Live trust store is not wired (proxy booted without inbound mTLS). Configure cfg.tls.client_auth + restart to enable hot-swap.",
            }),
        );
    };

    // Snapshot the live PEM (if any) before swapping so the audit
    // chain can carry an exact before/after `PreviewDiff` instead of
    // the lossy "what we last uploaded" view.
    let before_pem = writer.current_pem();
    let before_preview = if before_pem.is_empty() {
        Vec::new()
    } else {
        aegis_control::api::mtls_ca_bundle::parse_and_preview(&before_pem, now)
            .certificates
    };
    let diff = aegis_control::api::mtls_ca_bundle::diff_previews(
        &before_preview,
        &preview.certificates,
    );

    let before_payload = serde_json::json!({
        "blocks_seen": before_preview.len(),
        "certificates": before_preview,
    });
    let after_payload = serde_json::json!({
        "blocks_seen": preview.blocks_seen,
        "certificates": preview.certificates,
        "diff": {
            "added_count": diff.added.len(),
            "removed_count": diff.removed.len(),
            "kept_count": diff.kept.len(),
        },
    });

    let writer_cl = writer.clone();
    let body_for_swap = body_bytes.clone();
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: "/api/mtls/ca-bundle",
        action: "mtls_ca_bundle_swapped",
        reason: "operator hot-swapped CA bundle",
    };

    let outcome = services.mutate.apply::<_, usize, String>(
        &req_ctx,
        before_payload,
        after_payload,
        || {
            writer_cl
                .swap_pem(body_for_swap.as_ref())
                .map_err(|e| format!("trust anchor swap failed: {e}"))
        },
    );

    match outcome {
        Ok(out) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "request_id": pre.request_id,
                "preview": preview,
                "applied": true,
                "cert_count": out.value,
                "diff": {
                    "added": diff.added,
                    "removed": diff.removed,
                    "kept_count": diff.kept.len(),
                },
                "message": "Trust anchors hot-swapped. New verifiers see the new roots immediately; in-flight handshakes complete on the old ones.",
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

// MTLS-T8 — runtime mode override. Audit-mutated, CSRF-gated.
// Body shape: `{"mode": "disabled"|"optional"|"required"}` to
// set the override; `{"clear": true}` to remove it. `clear` is
// also accepted as the only key — both forms supported because
// the dashboard's confirm modal is easier to wire as one shape.

pub(crate) async fn handle_mtls_mode_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;
    let pre = mutation_preamble(&req, "mtls-mode-put");
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => bytes::Bytes::new(),
    };
    let body: serde_json::Value =
        serde_json::from_slice(&body_bytes).unwrap_or(serde_json::Value::Null);

    // Decide the requested operation: clear or set.
    let clear = body.get("clear").and_then(|v| v.as_bool()).unwrap_or(false);
    let mode_str = body.get("mode").and_then(|v| v.as_str());

    let store = services.mtls_mode_store.clone();
    let configured = store.configured();
    let prev_override = store.current();

    let (action_label, before_payload, after_payload, applier): (
        &'static str,
        serde_json::Value,
        serde_json::Value,
        Box<dyn FnOnce() -> Result<(), aegis_control::api::mutation::MutationError> + Send>,
    ) = if clear {
        let store_cl = store.clone();
        (
            "mtls_mode_clear",
            serde_json::json!({
                "configured": aegis_control::api::mtls_mode::mode_label(configured),
                "override": prev_override.map(aegis_control::api::mtls_mode::mode_label),
            }),
            serde_json::json!({
                "configured": aegis_control::api::mtls_mode::mode_label(configured),
                "override": serde_json::Value::Null,
            }),
            Box::new(move || {
                store_cl.clear();
                Ok(())
            }),
        )
    } else {
        let parsed = match mode_str.and_then(aegis_control::api::mtls_mode::parse_mode) {
            Some(m) => m,
            None => {
                return json_response(
                    400,
                    &serde_json::json!({
                        "error": "invalid_mode",
                        "message": "expected `mode` ∈ {disabled, optional, required} or `clear: true`",
                    }),
                );
            }
        };
        let store_cl = store.clone();
        (
            "mtls_mode_set",
            serde_json::json!({
                "configured": aegis_control::api::mtls_mode::mode_label(configured),
                "override": prev_override.map(aegis_control::api::mtls_mode::mode_label),
            }),
            serde_json::json!({
                "configured": aegis_control::api::mtls_mode::mode_label(configured),
                "override": aegis_control::api::mtls_mode::mode_label(parsed),
            }),
            Box::new(move || {
                store_cl.set(parsed);
                Ok(())
            }),
        )
    };

    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: "/api/mtls/mode",
        action: action_label,
        reason: "operator changed mtls mode override",
    };

    let outcome = services.mutate.apply::<_, (), aegis_control::api::mutation::MutationError>(
        &req_ctx,
        before_payload,
        after_payload.clone(),
        applier,
    );

    match outcome {
        Ok(_) => {
            // Echo the new effective state in the response so the
            // dashboard doesn't need an immediate GET round-trip.
            let body = aegis_control::api::mtls_mode::render_mode_response(
                configured,
                store.current(),
            );
            json_response(
                200,
                &serde_json::json!({
                    "ok": true,
                    "request_id": pre.request_id,
                    "mode": body,
                }),
            )
        }
        Err(e) => mutation_error_response(e),
    }
}

// Phase-3 Incidents — operator overlay on top of SLO alerts.
// All three handlers are audit-mutated + CSRF-gated, same shape
// as handle_alert_ack above.

pub(crate) async fn handle_incident_ack(
    req: hyper::Request<hyper::body::Incoming>,
    alert_id: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;
    let pre = mutation_preamble(&req, "incident-ack");
    // Drain the body so we can pass `note` into the overlay.
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => bytes::Bytes::new(),
    };
    let body: serde_json::Value =
        serde_json::from_slice(&body_bytes).unwrap_or(serde_json::Value::Null);
    let note = body
        .get("note")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let resource = format!("/api/incidents/{alert_id}");
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "POST",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: "incident_ack",
        reason: "operator acknowledged incident",
    };
    let tracking = services.tracking.clone();
    let incidents = services.incidents.clone();
    let alert_id_owned = alert_id.to_string();
    let actor_owned = pre.actor.clone();
    let outcome = services.mutate.apply::<_, (), aegis_control::api::mutation::MutationError>(
        &req_ctx,
        serde_json::Value::Null,
        serde_json::json!({"alert_id": alert_id, "status": "acknowledged"}),
        || {
            // Keep the legacy tracking.ack store in sync so
            // /api/alerts continues to return the same view.
            tracking.ack(&alert_id_owned);
            incidents.ack(&alert_id_owned, Some(actor_owned.clone()), note.clone());
            Ok(())
        },
    );
    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "alert_id": alert_id,
                "status": "acknowledged",
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

pub(crate) async fn handle_incident_snooze(
    req: hyper::Request<hyper::body::Incoming>,
    alert_id: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;
    let pre = mutation_preamble(&req, "incident-snooze");
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => bytes::Bytes::new(),
    };
    let body: serde_json::Value =
        serde_json::from_slice(&body_bytes).unwrap_or(serde_json::Value::Null);
    // Default to 15-minute snooze when no field provided.
    let minutes = body
        .get("minutes")
        .and_then(|v| v.as_u64())
        .unwrap_or(15);
    let note = body.get("note").and_then(|v| v.as_str()).map(String::from);
    let until = chrono::Utc::now() + chrono::Duration::minutes(minutes as i64);

    let resource = format!("/api/incidents/{alert_id}");
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "POST",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: "incident_snooze",
        reason: "operator snoozed incident",
    };
    let incidents = services.incidents.clone();
    let alert_id_owned = alert_id.to_string();
    let outcome = services.mutate.apply::<_, (), aegis_control::api::mutation::MutationError>(
        &req_ctx,
        serde_json::Value::Null,
        serde_json::json!({"alert_id": alert_id, "snoozed_until": until.to_rfc3339(), "minutes": minutes}),
        || {
            incidents.snooze(&alert_id_owned, until, note.clone());
            Ok(())
        },
    );
    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "alert_id": alert_id,
                "snoozed_until": until.to_rfc3339(),
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

pub(crate) async fn handle_incident_resolve(
    req: hyper::Request<hyper::body::Incoming>,
    alert_id: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;
    let pre = mutation_preamble(&req, "incident-resolve");
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => bytes::Bytes::new(),
    };
    let body: serde_json::Value =
        serde_json::from_slice(&body_bytes).unwrap_or(serde_json::Value::Null);
    let note = body.get("note").and_then(|v| v.as_str()).map(String::from);

    let resource = format!("/api/incidents/{alert_id}");
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "POST",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: "incident_resolve",
        reason: "operator resolved incident",
    };
    let incidents = services.incidents.clone();
    let alert_id_owned = alert_id.to_string();
    let actor_owned = pre.actor.clone();
    let outcome = services.mutate.apply::<_, (), aegis_control::api::mutation::MutationError>(
        &req_ctx,
        serde_json::Value::Null,
        serde_json::json!({"alert_id": alert_id, "status": "resolved"}),
        || {
            incidents.resolve(&alert_id_owned, Some(actor_owned.clone()), note.clone());
            Ok(())
        },
    );
    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "alert_id": alert_id,
                "status": "resolved",
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
    // F-CRITICAL-004 (2026-05-17 Phase 3 step 5): read the
    // validated actor identity set by `admin_auth_middleware` —
    // the client-supplied `X-Actor` header is silently stripped
    // at the gate so this code never sees a spoofed value.
    // `unwrap_or("admin")` is a defensive fallback for paths
    // that bypass the gate (open endpoints don't normally land
    // on mutation handlers, but be paranoid).
    let actor = req
        .headers()
        .get("x-aegis-actor")
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
    // F-CRITICAL-004 (2026-05-17 Phase 3 step 5): read the
    // validated actor identity set by `admin_auth_middleware` —
    // the client-supplied `X-Actor` header is silently stripped
    // at the gate so this code never sees a spoofed value.
    // `unwrap_or("admin")` is a defensive fallback for paths
    // that bypass the gate (open endpoints don't normally land
    // on mutation handlers, but be paranoid).
    let actor = req
        .headers()
        .get("x-aegis-actor")
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

/// 2026-05-17 F-CRITICAL-001 (control audit): rebuild the live
/// `Arc<RuleSet>` after a successful CRUD mutation so the data
/// plane sees the operator's change on the next request. Logs at
/// `info` on success and `warn` on parse failure (the operator's
/// dashboard already shows the lint warnings; this is the
/// server-side accounting trace). No-op when
/// `services.active_ruleset` is `None` (single-node test fixture
/// without a security pipeline wired).
fn rebuild_ruleset_after_mutation(
    services: &aegis_control::dashboard_services::DashboardServices,
    label: &str,
) {
    let Some(active) = services.active_ruleset.as_ref() else {
        // No engine wired (test fixture / partial harness) — nothing
        // to refresh. The RuleStore mutation already landed.
        return;
    };
    match aegis_control::api::rules::rebuild_active_ruleset(&services.rules, active) {
        Ok(n) => {
            tracing::info!(
                target: "aegis.rules.live",
                trigger = label,
                active_rule_count = n,
                "rule set refreshed",
            );
        }
        Err(e) => {
            tracing::warn!(
                target: "aegis.rules.live",
                trigger = label,
                error = %e,
                "rule set refresh skipped — operator must fix body and re-save",
            );
        }
    }
}

fn default_true() -> bool {
    true
}

/// Body for `PUT /api/config` — activate a new config version.
#[derive(serde::Deserialize)]
struct ConfigPutBody {
    /// The version the editor started from (optimistic concurrency).
    #[serde(default)]
    expected_version: u64,
    /// The full `WafConfig` as YAML.
    blob: String,
    /// Short human summary of the change.
    #[serde(default)]
    summary: String,
}

/// Body for `POST /api/config/rollback`.
#[derive(serde::Deserialize)]
struct ConfigRollbackBody {
    target_version: u64,
}

/// 2026-05-27 — `PUT /api/config`. Activate a new cluster-wide config
/// version through the shared `ConfigStore`. Audit-mutated + CSRF-gated
/// via the **async** `AuditedMutate::apply_async` path (activation is a
/// `StateBackend` round-trip). Returns 200 `{version}` on apply, 409
/// `{current}` on an optimistic-concurrency conflict. A conflict still
/// produces an audit entry — recording the *attempt* is desirable for a
/// config-authority endpoint.
pub(crate) async fn handle_config_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;
    let pre = mutation_preamble(&req, "config-put");

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
    let parsed: ConfigPutBody = match serde_json::from_str(body_str) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e.to_string()),
            );
        }
    };

    // Single validation surface: the blob must parse as a WafConfig
    // before it can be activated. Reject early — nothing is written.
    if let Err(e) = aegis_core::load_config_str(&parsed.blob) {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(format!(
                "config blob failed validation: {e}"
            )),
        );
    }

    let Some(backend) = services.state_backend.as_ref() else {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal(
                "config plane unavailable: no state backend wired".into(),
            ),
        );
    };
    let store = crate::config_source::config_store::ConfigStore::new(backend.clone());

    let current = store.current_version().await.unwrap_or(0);
    let before = serde_json::json!({ "version": current });
    let after = serde_json::json!({
        "expected_version": parsed.expected_version,
        "summary": parsed.summary,
    });

    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: "/api/config",
        action: "config_activate",
        reason: "operator activated config version",
    };

    let store_for_apply = store.clone();
    let blob = parsed.blob;
    let actor = pre.actor.clone();
    let summary = parsed.summary;
    let expected = parsed.expected_version;
    let outcome = services
        .mutate
        .apply_async(&req_ctx, before, after, move || async move {
            store_for_apply
                .activate(expected, blob, &actor, &summary)
                .await
        })
        .await;

    match outcome {
        Ok(mo) => match mo.value {
            crate::config_source::config_store::Activate::Applied { version } => json_response(
                200,
                &serde_json::json!({
                    "ok": true,
                    "version": version,
                    "request_id": pre.request_id,
                }),
            ),
            crate::config_source::config_store::Activate::Conflict { current } => json_response(
                409,
                &serde_json::json!({
                    "ok": false,
                    "error": "version_conflict",
                    "current": current,
                    "request_id": pre.request_id,
                }),
            ),
        },
        Err(e) => mutation_error_response(e),
    }
}

/// 2026-05-27 — `POST /api/config/rollback`. Re-activate a prior
/// (immutable) snapshot as a new version. Same async audited path.
pub(crate) async fn handle_config_rollback(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;
    let pre = mutation_preamble(&req, "config-rollback");

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
    let parsed: ConfigRollbackBody = match serde_json::from_str(body_str) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e.to_string()),
            );
        }
    };

    let Some(backend) = services.state_backend.as_ref() else {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal(
                "config plane unavailable: no state backend wired".into(),
            ),
        );
    };
    let store = crate::config_source::config_store::ConfigStore::new(backend.clone());

    let current = store.current_version().await.unwrap_or(0);
    let before = serde_json::json!({ "version": current });
    let after = serde_json::json!({ "rollback_to": parsed.target_version });

    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "POST",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: "/api/config/rollback",
        action: "config_rollback",
        reason: "operator rolled back config version",
    };

    let store_for_apply = store.clone();
    let actor = pre.actor.clone();
    let target = parsed.target_version;
    let outcome = services
        .mutate
        .apply_async(&req_ctx, before, after, move || async move {
            store_for_apply.rollback(target, &actor).await
        })
        .await;

    match outcome {
        Ok(mo) => match mo.value {
            crate::config_source::config_store::Activate::Applied { version } => json_response(
                200,
                &serde_json::json!({
                    "ok": true,
                    "version": version,
                    "rolled_back_to": target,
                    "request_id": pre.request_id,
                }),
            ),
            crate::config_source::config_store::Activate::Conflict { current } => json_response(
                409,
                &serde_json::json!({
                    "ok": false,
                    "error": "version_conflict",
                    "current": current,
                    "request_id": pre.request_id,
                }),
            ),
        },
        Err(e) => mutation_error_response(e),
    }
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
    // F-CRITICAL-004 (2026-05-17 Phase 3 step 5): read the
    // validated actor identity set by `admin_auth_middleware` —
    // the client-supplied `X-Actor` header is silently stripped
    // at the gate so this code never sees a spoofed value.
    // `unwrap_or("admin")` is a defensive fallback for paths
    // that bypass the gate (open endpoints don't normally land
    // on mutation handlers, but be paranoid).
    let actor = req
        .headers()
        .get("x-aegis-actor")
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

    if outcome.is_ok() {
        rebuild_ruleset_after_mutation(services, "rule_create");
    }
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

    if outcome.is_ok() {
        rebuild_ruleset_after_mutation(services, "rule_update");
    }
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

    if outcome.is_ok() {
        rebuild_ruleset_after_mutation(services, "rule_delete");
    }
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

    if outcome.is_ok() {
        rebuild_ruleset_after_mutation(services, "rule_toggle");
    }
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
        enabled: Option<bool>,
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
        // 2026-05-21 — cumulative-gate master toggle. Numeric
        // thresholds stay valid even when disabled (so re-enabling is
        // a one-flag change), so we keep the ordering checks below.
        enabled:      parsed.enabled.unwrap_or(current.enabled),
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
        "enabled":      current.enabled,
        "challenge_at": current.challenge_at,
        "block_at":     current.block_at,
        "max":          current.max,
    });
    let after = serde_json::json!({
        "enabled":      next.enabled,
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
                "enabled":      next.enabled,
                "challenge_at": next.challenge_at,
                "block_at":     next.block_at,
                "max":          next.max,
                "request_id":   pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

/// 2026-05-20 — `PUT /api/risk/canary-paths`. Audit-mutated; replaces
/// the live canary honeypot path set and hot-applies it via the
/// shared [`CanaryPaths`] handle (no chain rebuild / restart). The
/// data-plane `CanaryDetector` reads the new set on the next request.
///
/// Body: `{"paths": ["/wp-admin", "/.env", "/phpmyadmin/*", ...]}`.
/// Entries are trimmed; blanks dropped; duplicates removed (first
/// wins). Each entry must start with `/` (canary entries are request
/// paths) and stay within the length / count caps so a runaway PUT
/// can't bloat the per-request matcher loop.
pub(crate) async fn handle_risk_canary_paths_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    // Caps: honeypot lists are small by nature. These bound the
    // per-request matcher loop and the audit-log payload size.
    const MAX_CANARY_PATHS: usize = 256;
    const MAX_CANARY_PATH_LEN: usize = 512;

    let pre = mutation_preamble(&req, "risk-canary-paths-put");
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal("body read failed".into()),
        ),
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");

    #[derive(serde::Deserialize)]
    struct Body {
        paths: Vec<String>,
    }
    let parsed: Body = match serde_json::from_str(if body_str.is_empty() { "{}" } else { body_str }) {
        Ok(b) => b,
        Err(e) => return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(format!(
                "expected {{\"paths\": [\"/wp-admin\", ...]}}: {e}"
            )),
        ),
    };

    // Normalize: trim, drop blanks, dedupe (first occurrence wins,
    // order preserved). Validate shape + caps before applying.
    let mut normalized: Vec<String> = Vec::with_capacity(parsed.paths.len());
    for raw in &parsed.paths {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !trimmed.starts_with('/') {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(format!(
                    "canary path must start with '/': {trimmed:?}"
                )),
            );
        }
        if trimmed.len() > MAX_CANARY_PATH_LEN {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(format!(
                    "canary path exceeds {MAX_CANARY_PATH_LEN} chars: {:?}…",
                    &trimmed[..MAX_CANARY_PATH_LEN.min(trimmed.len())]
                )),
            );
        }
        let owned = trimmed.to_string();
        if !normalized.contains(&owned) {
            normalized.push(owned);
        }
    }
    if normalized.len() > MAX_CANARY_PATHS {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(format!(
                "too many canary paths ({}); max is {MAX_CANARY_PATHS}",
                normalized.len()
            )),
        );
    }

    let current = services.canary_paths.raw();
    let before = serde_json::json!({ "paths": current });
    let after = serde_json::json!({ "paths": normalized });
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: "/api/risk/canary-paths",
        action: "risk_canary_paths_set",
        reason: "operator updated canary honeypot paths",
    };
    let handle = services.canary_paths.clone();
    let to_apply = normalized.clone();
    let outcome = services.mutate.apply::<_, (), aegis_control::api::mutation::MutationError>(
        &req_ctx,
        before,
        after,
        || {
            handle.set(&to_apply);
            Ok(())
        },
    );
    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "paths": normalized,
                "count": normalized.len(),
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

/// 2026-05-21 — `PUT /api/gates/bots`. Audit-mutated gate-style
/// on/off for the bot classifier. Body: `{"enabled": true|false}`.
/// Hot-applies by flipping the shared `AtomicBool` the data-plane
/// listener reads (no restart). When off, no classification runs and
/// `bot_category` is left unset.
pub(crate) async fn handle_bots_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;
    use std::sync::atomic::Ordering;

    let pre = mutation_preamble(&req, "bots-gate-put");
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal("body read failed".into()),
        ),
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");

    #[derive(serde::Deserialize)]
    struct Body {
        enabled: bool,
    }
    let parsed: Body = match serde_json::from_str(if body_str.is_empty() { "{}" } else { body_str }) {
        Ok(b) => b,
        Err(e) => return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(format!(
                "expected {{\"enabled\": true|false}}: {e}"
            )),
        ),
    };

    let current = services.bots_enabled.load(Ordering::Relaxed);
    let next = parsed.enabled;
    let before = serde_json::json!({ "enabled": current });
    let after = serde_json::json!({ "enabled": next });
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: "/api/gates/bots",
        action: "bots_gate_set",
        reason: "operator toggled the bot classifier gate",
    };
    let toggle = services.bots_enabled.clone();
    let outcome = services.mutate.apply::<_, (), aegis_control::api::mutation::MutationError>(
        &req_ctx,
        before,
        after,
        || {
            toggle.store(next, Ordering::Relaxed);
            Ok(())
        },
    );
    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "enabled": next,
                "request_id": pre.request_id,
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
    // F-CRITICAL-004 (2026-05-17 Phase 3 step 5): read the
    // validated actor identity set by `admin_auth_middleware` —
    // the client-supplied `X-Actor` header is silently stripped
    // at the gate so this code never sees a spoofed value.
    // `unwrap_or("admin")` is a defensive fallback for paths
    // that bypass the gate (open endpoints don't normally land
    // on mutation handlers, but be paranoid).
    let actor = req
        .headers()
        .get("x-aegis-actor")
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

/// 2026-05-19 — surgical reset for one composite-key bucket.
///
/// Distinct from [`handle_risk_reset`] which keys by IP only and
/// wipes every bucket sharing that IP. This handler takes a JSON
/// body `{ip, device_fp?, session?}` and deletes exactly one
/// `RiskKey` — useful when an operator wants to clear one
/// flagged session on a NAT'd IP without disturbing legit
/// sessions on the same egress.
///
/// Audit-mutated through the existing `AuditedMutate` pipeline;
/// CSRF + actor handling identical to `handle_risk_reset`.
pub(crate) async fn handle_risk_reset_key(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    #[derive(serde::Deserialize)]
    struct Body {
        ip: String,
        #[serde(default)]
        device_fp: Option<String>,
        #[serde(default)]
        session: Option<String>,
    }

    // CSRF + actor + request_id — same pattern as handle_risk_reset.
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
        .get("x-aegis-actor")
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
                    "risk-reset-key:{}",
                    chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
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
                    "body read failed".into(),
                ),
            );
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");
    let parsed: Body = match serde_json::from_str(body_str) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e.to_string()),
            );
        }
    };
    let Ok(ip): Result<std::net::IpAddr, _> = parsed.ip.parse() else {
        return json_response(
            400,
            &serde_json::json!({"error": "invalid_ip", "value": parsed.ip}),
        );
    };

    let key = aegis_core::risk::RiskKey {
        ip,
        device_fp: parsed.device_fp.clone(),
        session: parsed.session.clone(),
    };

    let resource = "/api/risk/reset_key";
    let before = serde_json::json!({
        "ip": ip.to_string(),
        "device_fp": parsed.device_fp,
        "session": parsed.session,
    });
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "POST",
        csrf_cookie: csrf_cookie.as_deref(),
        csrf_header: csrf_header.as_deref(),
        actor: &actor,
        request_id: &request_id,
        resource,
        action: "risk_reset_key",
        reason: "operator clears one composite-key risk bucket",
    };
    let risk = services.risk.clone();
    let outcome = services.mutate.apply(
        &req_ctx,
        before,
        serde_json::json!({"score": 0, "strikes": 0}),
        move || {
            let removed = risk.reset_with_key(&key);
            Ok::<bool, String>(removed)
        },
    );
    match outcome {
        Ok(o) => json_body_response(
            200,
            serde_json::json!({
                "ok": true,
                "ip": ip.to_string(),
                "device_fp": parsed.device_fp,
                "session": parsed.session,
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
    // F-CRITICAL-004 (2026-05-17 Phase 3 step 5): read the
    // validated actor identity set by `admin_auth_middleware` —
    // the client-supplied `X-Actor` header is silently stripped
    // at the gate so this code never sees a spoofed value.
    // `unwrap_or("admin")` is a defensive fallback for paths
    // that bypass the gate (open endpoints don't normally land
    // on mutation handlers, but be paranoid).
    let actor = req
        .headers()
        .get("x-aegis-actor")
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
        // CQF-T3 quality fix — was "update" for everything; the
        // generic label made the rollback dispatcher unable to
        // match this row vs. e.g. `mode_set` or
        // `risk_thresholds_set`. The new label is consistent
        // with the other audit-mutated handlers
        // (`{resource}_set`).
        action: "detector_mask_set",
        reason: "operator updated detector mask",
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
// CQF-T2 — Blacklist + Whitelist CRUD (audit-mutated)
// ---------------------------------------------------------------------------

/// Pick the right `AccessListStore` from `services` based on the
/// `kind` discriminator. Returns the store + a stable lowercase
/// label used in audit-chain `action` strings + a resource prefix.
fn access_list_store(
    kind: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Option<(std::sync::Arc<aegis_control::api::blacklist::AccessListStore>, &'static str)> {
    match kind {
        "blacklist" => Some((services.blacklist.clone(), "blacklist")),
        "whitelist" => Some((services.whitelist.clone(), "whitelist")),
        _ => None,
    }
}

/// `POST /api/{blacklist,whitelist}` — add a single entry.
/// Body: `{ "id":"<id>", "kind":"ip|cidr|asn", "value":"<v>",
/// "note":"<>", "expires_at":"<rfc3339>"|null, "bypass":[…] }`.
/// Audit-mutated; CSRF-gated. The store applies any compliance
/// `expires_at` clamp before insert; the audit-chain entry shows
/// the clamped value.
pub(crate) async fn handle_access_list_post(
    req: hyper::Request<hyper::body::Incoming>,
    kind: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "access-list-post");

    let Some((store, label)) = access_list_store(kind, services) else {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(
                format!("unknown access list kind '{kind}'"),
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
    let parsed: aegis_control::api::blacklist::AccessListEntry =
        match serde_json::from_str(body_str) {
            Ok(e) => e,
            Err(e) => {
                return mutation_error_response(
                    aegis_control::api::mutation::MutationError::Validation(
                        format!("invalid {label} entry: {e}"),
                    ),
                );
            }
        };

    let before = serde_json::Value::Null;
    let after = serde_json::to_value(&parsed)
        .unwrap_or(serde_json::Value::Null);
    let resource = format!("/api/{label}");
    let action = format!("{label}_add");
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "POST",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: &action,
        reason: "operator added access-list entry",
    };

    let store_for_apply = store.clone();
    let entry_for_apply = parsed.clone();
    let outcome = services.mutate.apply::<_, aegis_control::api::blacklist::AccessListEntry, aegis_control::api::mutation::MutationError>(
        &req_ctx,
        before,
        after,
        move || {
            store_for_apply
                .put(entry_for_apply)
                .map_err(aegis_control::api::mutation::MutationError::Validation)
        },
    );
    match outcome {
        Ok(o) => json_response(
            201,
            &serde_json::json!({
                "ok": true,
                "entry": o.value,
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

/// `DELETE /api/{blacklist,whitelist}/{id}` — remove a single entry.
/// Returns 422 with `validation` reason when the id isn't present
/// so the dashboard can surface "no such entry" without 500-ing.
pub(crate) async fn handle_access_list_delete(
    req: hyper::Request<hyper::body::Incoming>,
    kind: &str,
    id: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let pre = mutation_preamble(&req, "access-list-delete");

    let Some((store, label)) = access_list_store(kind, services) else {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(
                format!("unknown access list kind '{kind}'"),
            ),
        );
    };

    let existing = store.get(id);
    let Some(existing) = existing else {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(
                format!("no {label} entry with id '{id}'"),
            ),
        );
    };

    let before = serde_json::to_value(&existing)
        .unwrap_or(serde_json::Value::Null);
    let after = serde_json::Value::Null;
    let resource = format!("/api/{label}/{id}");
    let action = format!("{label}_remove");
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "DELETE",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: &action,
        reason: "operator removed access-list entry",
    };

    let store_for_apply = store.clone();
    let id_owned = id.to_string();
    let outcome = services.mutate.apply::<_, (), aegis_control::api::mutation::MutationError>(
        &req_ctx,
        before,
        after,
        move || {
            store_for_apply.delete(&id_owned);
            Ok(())
        },
    );
    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "removed": id,
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
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

// FIX 2026-05-04 — convert a `&[RouteConfig]` to the
// `RouteSummary` shape `services.routes` exposes via
// `/api/routes`. The boot path does this from `accept.rs`; we
// re-invoke after a successful route upsert/delete so the read
// endpoint stays in sync with the live RouteTable.
fn route_summaries(
    routes: &[aegis_core::config::RouteConfig],
) -> Vec<aegis_control::api::routes::RouteSummary> {
    crate::route::route_summaries(routes)
}

// ---------------------------------------------------------------------------
// TI-T — audit-mutated tier definitions
// ---------------------------------------------------------------------------

/// PUT /api/tiers/{name} — update one tier's pipeline + thresholds.
///
/// Audit-mutated, CSRF-gated. The tier `name` must be one of
/// the four canonical names (`critical | high | medium | catch_all`)
/// — these match `aegis_core::tier::Tier`, so a route's
/// `tier_override: catch_all` correctly links to the same row.
/// Operators can edit thresholds + pipeline, not invent new tiers.
pub(crate) async fn handle_tier_put(
    req: hyper::Request<hyper::body::Incoming>,
    tier_name: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "tier-put");

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Internal("body read failed".into()),
            )
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");
    let patch: TierPatch = match serde_json::from_str(body_str) {
        Ok(p) => p,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e.to_string()),
            )
        }
    };

    // 2026-05-27 (Phase B fold, option A — eventual). Patch
    // `tiers.<name>` on the shared config doc + activate; every node
    // re-derives the tier via `apply_cfg_change_to_tiers` on its next
    // watcher poll.
    let Some(backend) = services.state_backend.as_ref() else {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal(
                "config plane unavailable: no state backend wired".into(),
            ),
        );
    };
    let store = crate::config_source::config_store::ConfigStore::new(backend.clone());

    let (base_blob, expected) = match store.load().await {
        Ok(Some(doc)) => (doc.blob, doc.version),
        Ok(None) => match services.config_yaml_path.as_ref() {
            Some(path) => match std::fs::read_to_string(path) {
                Ok(s) => (s, 0u64),
                Err(e) => {
                    return mutation_error_response(
                        aegis_control::api::mutation::MutationError::Internal(format!(
                            "cannot read boot config {} to seed the config plane: {e}",
                            path.display()
                        )),
                    )
                }
            },
            None => {
                return mutation_error_response(
                    aegis_control::api::mutation::MutationError::Validation(
                        "no shared config activated yet — publish a baseline via PUT /api/config first".into(),
                    ),
                )
            }
        },
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Internal(format!(
                    "config store read failed: {e}"
                )),
            )
        }
    };

    let new_blob = match patch_tier(&base_blob, tier_name, &patch) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e),
            )
        }
    };
    if let Err(e) = aegis_core::load_config_str(&new_blob) {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(format!(
                "patched config failed validation: {e}"
            )),
        );
    }

    let before = serde_json::json!({ "version": expected });
    let after = serde_json::json!({
        "name": tier_name,
        "pipeline": patch.pipeline,
        "risk_threshold": patch.risk_threshold,
        "block_threshold": patch.block_threshold,
        "cumulative_challenge_at": patch.cumulative_challenge_at,
        "cumulative_block_at": patch.cumulative_block_at,
        "challenges_enabled": patch.challenges_enabled,
    });
    let resource = format!("/api/tiers/{tier_name}");
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: "tier_set",
        reason: "operator updated tier",
    };

    let store_for_apply = store.clone();
    let blob = new_blob;
    let actor = pre.actor.clone();
    let outcome = services
        .mutate
        .apply_async(&req_ctx, before, after, move || async move {
            store_for_apply
                .activate(expected, blob, &actor, "update tier")
                .await
        })
        .await;
    match outcome {
        Ok(mo) => match mo.value {
            crate::config_source::config_store::Activate::Applied { version } => json_response(
                200,
                &serde_json::json!({
                    "ok": true,
                    "tier": tier_name,
                    "version": version,
                    "note": "config activated; propagates to all nodes within a few seconds",
                    "request_id": pre.request_id,
                }),
            ),
            crate::config_source::config_store::Activate::Conflict { current } => json_response(
                409,
                &serde_json::json!({
                    "ok": false,
                    "error": "version_conflict",
                    "current": current,
                    "request_id": pre.request_id,
                }),
            ),
        },
        Err(e) => mutation_error_response(e),
    }
}

/// PUT /api/tiers/<name> body. Module-level (was inline) so `patch_tier`
/// can borrow it.
#[derive(serde::Deserialize)]
struct TierPatch {
    pipeline: Vec<String>,
    risk_threshold: u32,
    block_threshold: u32,
    #[serde(default)]
    cumulative_challenge_at: Option<u32>,
    #[serde(default)]
    cumulative_block_at: Option<u32>,
    #[serde(default)]
    challenges_enabled: bool,
}

/// Patch `tiers.<name>` on a YAML config blob via `serde_yaml::Value`
/// (`WafConfig` isn't `Serialize`). Writes every field the PUT carries so
/// the activated config fully represents the tier. Creates the `tiers`
/// mapping (and the per-tier entry) if absent.
fn patch_tier(base: &str, tier_name: &str, patch: &TierPatch) -> Result<String, String> {
    let mut doc: serde_yaml::Value =
        serde_yaml::from_str(base).map_err(|e| format!("base config not YAML: {e}"))?;
    let serde_yaml::Value::Mapping(map) = &mut doc else {
        return Err("base config is not a YAML mapping".into());
    };
    let tiers = map
        .entry(serde_yaml::Value::String("tiers".into()))
        .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
    let serde_yaml::Value::Mapping(tiers_map) = tiers else {
        return Err("`tiers` config is not a mapping".into());
    };
    let mut entry = serde_yaml::Mapping::new();
    let s = |x: &str| serde_yaml::Value::String(x.into());
    entry.insert(s("risk_threshold"), (patch.risk_threshold as u64).into());
    entry.insert(s("block_threshold"), (patch.block_threshold as u64).into());
    entry.insert(s("challenges_enabled"), patch.challenges_enabled.into());
    entry.insert(
        s("pipeline"),
        serde_yaml::Value::Sequence(patch.pipeline.iter().map(|p| s(p)).collect()),
    );
    if let Some(c) = patch.cumulative_challenge_at {
        entry.insert(s("cumulative_challenge_at"), (c as u64).into());
    }
    if let Some(c) = patch.cumulative_block_at {
        entry.insert(s("cumulative_block_at"), (c as u64).into());
    }
    tiers_map.insert(s(tier_name), serde_yaml::Value::Mapping(entry));
    serde_yaml::to_string(&doc).map_err(|e| format!("re-serialize config: {e}"))
}

// ---------------------------------------------------------------------------
// AI-T10 — runtime toggle for the AI detector
// ---------------------------------------------------------------------------

pub(crate) async fn handle_ai_enabled_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use aegis_control::api::ai_toggle::AiEnabledPatch;
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "ai-enabled-put");

    // Distinct shape from the "writer not wired" Internal: when
    // the binary lacks the `ai` feature (or `cfg.ai.enabled` was
    // false at boot), we want the dashboard to render a clear
    // "feature off" banner — not a generic 500.
    if services.ai_toggle.is_none() {
        let body = serde_json::json!({
            "ok": false,
            "reason": "feature_off",
            "message": "AI detector not wired — rebuild with FEATURES=\"… ai\" and set cfg.ai.enabled = true",
        });
        return json_body_response(409, body.to_string(), "private, no-store");
    };

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Internal("body read failed".into()),
            )
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");
    let patch: AiEnabledPatch = match serde_json::from_str(body_str) {
        Ok(p) => p,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e.to_string()),
            )
        }
    };

    // 2026-05-27 (Phase B fold-toggles, option A — eventual). Route the
    // toggle through the cluster config plane instead of flipping the
    // local in-process atomic: patch `ai.enabled` on the shared config
    // document and activate it. Every node's watcher (incl. this one)
    // re-derives the AI gate via `apply_cfg_change_to_ai` on its next
    // poll (~3s) — the shared store is the single source of truth, so
    // the change is eventually-consistent across the fleet rather than
    // instant-local.
    let Some(backend) = services.state_backend.as_ref() else {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal(
                "config plane unavailable: no state backend wired".into(),
            ),
        );
    };
    let store = crate::config_source::config_store::ConfigStore::new(backend.clone());

    // Base blob to patch: the active shared doc, or — on a fresh cluster
    // with nothing activated yet — the boot config file (seeds v1).
    // Without either (etcd-boot / no path), the operator must publish a
    // baseline via PUT /api/config first.
    let (base_blob, expected) = match store.load().await {
        Ok(Some(doc)) => (doc.blob, doc.version),
        Ok(None) => match services.config_yaml_path.as_ref() {
            Some(path) => match std::fs::read_to_string(path) {
                Ok(s) => (s, 0u64),
                Err(e) => {
                    return mutation_error_response(
                        aegis_control::api::mutation::MutationError::Internal(format!(
                            "cannot read boot config {} to seed the config plane: {e}",
                            path.display()
                        )),
                    )
                }
            },
            None => {
                return mutation_error_response(
                    aegis_control::api::mutation::MutationError::Validation(
                        "no shared config activated yet — publish a baseline via PUT /api/config first".into(),
                    ),
                )
            }
        },
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Internal(format!(
                    "config store read failed: {e}"
                )),
            )
        }
    };

    let new_blob = match patch_ai_enabled(&base_blob, patch.enabled) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e),
            )
        }
    };
    if let Err(e) = aegis_core::load_config_str(&new_blob) {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(format!(
                "patched config failed validation: {e}"
            )),
        );
    }

    let before = serde_json::json!({ "version": expected });
    let after = serde_json::json!({ "ai_enabled": patch.enabled });
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: "/api/ai/enabled",
        action: "ai_enabled_put",
        reason: if patch.enabled { "operator enabled AI detector" } else { "operator disabled AI detector" },
    };

    let store_for_apply = store.clone();
    let blob = new_blob;
    let actor = pre.actor.clone();
    let summary = if patch.enabled { "enable AI detector" } else { "disable AI detector" };
    let outcome = services
        .mutate
        .apply_async(&req_ctx, before, after, move || async move {
            store_for_apply.activate(expected, blob, &actor, summary).await
        })
        .await;

    match outcome {
        Ok(mo) => match mo.value {
            crate::config_source::config_store::Activate::Applied { version } => json_response(
                200,
                &serde_json::json!({
                    "ok": true,
                    "enabled": patch.enabled,
                    "version": version,
                    "note": "config activated; propagates to all nodes within a few seconds",
                    "request_id": pre.request_id,
                }),
            ),
            crate::config_source::config_store::Activate::Conflict { current } => json_response(
                409,
                &serde_json::json!({
                    "ok": false,
                    "error": "version_conflict",
                    "current": current,
                    "request_id": pre.request_id,
                }),
            ),
        },
        Err(e) => mutation_error_response(e),
    }
}

/// Patch `ai.enabled` on a YAML config blob via `serde_yaml::Value`
/// (`WafConfig` isn't `Serialize`, so we edit the generic Value tree).
/// Creates the `ai` mapping if absent. Returns the re-serialized YAML.
fn patch_ai_enabled(base: &str, enabled: bool) -> Result<String, String> {
    let mut doc: serde_yaml::Value =
        serde_yaml::from_str(base).map_err(|e| format!("base config not YAML: {e}"))?;
    let serde_yaml::Value::Mapping(map) = &mut doc else {
        return Err("base config is not a YAML mapping".into());
    };
    let ai = map
        .entry(serde_yaml::Value::String("ai".into()))
        .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
    let serde_yaml::Value::Mapping(ai_map) = ai else {
        return Err("`ai` config is not a mapping".into());
    };
    ai_map.insert(
        serde_yaml::Value::String("enabled".into()),
        serde_yaml::Value::Bool(enabled),
    );
    serde_yaml::to_string(&doc).map_err(|e| format!("re-serialize config: {e}"))
}

// ---------------------------------------------------------------------------
// 2026-05-11 PR #7 — runtime toggle for the response-filter rungs
// ---------------------------------------------------------------------------

pub(crate) async fn handle_response_filter_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use aegis_control::api::response_filter::ResponseFilterPatch;
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "response-filter-put");

    if services.response_filter_writer.is_none() {
        // No writer wired — test bundles, no-pipeline builds. Return
        // the same `feature_off` shape as `/api/ai/enabled` so the
        // dashboard can render a clear "not wired" banner instead of
        // a generic 500.
        let body = serde_json::json!({
            "ok": false,
            "reason": "feature_off",
            "message": "Response filter pipeline not wired in this build",
        });
        return json_body_response(409, body.to_string(), "private, no-store");
    };

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Internal("body read failed".into()),
            )
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");
    let patch: ResponseFilterPatch = match serde_json::from_str(body_str) {
        Ok(p) => p,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e.to_string()),
            )
        }
    };

    // 2026-05-27 (Phase B fold-toggles, option A — eventual). Route the
    // rung change through the config plane: patch `response_filter` on the
    // shared doc + activate. Every node's watcher re-derives the rungs via
    // `apply_cfg_change_to_response_filter` on its next poll.
    let Some(backend) = services.state_backend.as_ref() else {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal(
                "config plane unavailable: no state backend wired".into(),
            ),
        );
    };
    let store = crate::config_source::config_store::ConfigStore::new(backend.clone());

    let (base_blob, expected) = match store.load().await {
        Ok(Some(doc)) => (doc.blob, doc.version),
        Ok(None) => match services.config_yaml_path.as_ref() {
            Some(path) => match std::fs::read_to_string(path) {
                Ok(s) => (s, 0u64),
                Err(e) => {
                    return mutation_error_response(
                        aegis_control::api::mutation::MutationError::Internal(format!(
                            "cannot read boot config {} to seed the config plane: {e}",
                            path.display()
                        )),
                    )
                }
            },
            None => {
                return mutation_error_response(
                    aegis_control::api::mutation::MutationError::Validation(
                        "no shared config activated yet — publish a baseline via PUT /api/config first".into(),
                    ),
                )
            }
        },
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Internal(format!(
                    "config store read failed: {e}"
                )),
            )
        }
    };

    let new_blob = match patch_response_filter(&base_blob, &patch) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e),
            )
        }
    };
    if let Err(e) = aegis_core::load_config_str(&new_blob) {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(format!(
                "patched config failed validation: {e}"
            )),
        );
    }

    let before = serde_json::json!({ "version": expected });
    let after = serde_json::json!({
        "scrub_stack_traces": patch.scrub_stack_traces,
        "mask_internal_ips":  patch.mask_internal_ips,
        "redact_dlp":         patch.redact_dlp,
    });
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: "/api/response-filter",
        action: "response_filter_put",
        reason: "operator updated response-filter rungs",
    };

    let store_for_apply = store.clone();
    let blob = new_blob;
    let actor = pre.actor.clone();
    let outcome = services
        .mutate
        .apply_async(&req_ctx, before, after, move || async move {
            store_for_apply
                .activate(expected, blob, &actor, "update response-filter rungs")
                .await
        })
        .await;
    match outcome {
        Ok(mo) => match mo.value {
            crate::config_source::config_store::Activate::Applied { version } => json_response(
                200,
                &serde_json::json!({
                    "ok": true,
                    "scrub_stack_traces": patch.scrub_stack_traces,
                    "mask_internal_ips":  patch.mask_internal_ips,
                    "redact_dlp":         patch.redact_dlp,
                    "version":            version,
                    "note": "config activated; propagates to all nodes within a few seconds",
                    "request_id":         pre.request_id,
                }),
            ),
            crate::config_source::config_store::Activate::Conflict { current } => json_response(
                409,
                &serde_json::json!({
                    "ok": false,
                    "error": "version_conflict",
                    "current": current,
                    "request_id": pre.request_id,
                }),
            ),
        },
        Err(e) => mutation_error_response(e),
    }
}

/// Patch the three `response_filter` rungs on a YAML config blob via
/// `serde_yaml::Value` (`WafConfig` isn't `Serialize`). Creates the
/// `response_filter` mapping if absent.
fn patch_response_filter(
    base: &str,
    patch: &aegis_control::api::response_filter::ResponseFilterPatch,
) -> Result<String, String> {
    let mut doc: serde_yaml::Value =
        serde_yaml::from_str(base).map_err(|e| format!("base config not YAML: {e}"))?;
    let serde_yaml::Value::Mapping(map) = &mut doc else {
        return Err("base config is not a YAML mapping".into());
    };
    let rf = map
        .entry(serde_yaml::Value::String("response_filter".into()))
        .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
    let serde_yaml::Value::Mapping(rf_map) = rf else {
        return Err("`response_filter` config is not a mapping".into());
    };
    for (k, v) in [
        ("scrub_stack_traces", patch.scrub_stack_traces),
        ("mask_internal_ips", patch.mask_internal_ips),
        ("redact_dlp", patch.redact_dlp),
    ] {
        rf_map.insert(
            serde_yaml::Value::String(k.into()),
            serde_yaml::Value::Bool(v),
        );
    }
    serde_yaml::to_string(&doc).map_err(|e| format!("re-serialize config: {e}"))
}

pub(crate) async fn handle_response_filter_get(
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let body = match services.response_filter_writer.as_ref() {
        Some(w) => {
            let snap = w.get();
            serde_json::json!({
                "scrub_stack_traces": snap.scrub_stack_traces,
                "mask_internal_ips":  snap.mask_internal_ips,
                "redact_dlp":         snap.redact_dlp,
                "wired":              true,
            })
        }
        None => serde_json::json!({
            "scrub_stack_traces": true,
            "mask_internal_ips":  true,
            "redact_dlp":         true,
            "wired":              false,
        }),
    };
    json_response(200, &body)
}

pub(crate) async fn handle_ai_enabled_get(
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let body = match services.ai_toggle.as_ref() {
        Some(t) => serde_json::json!({ "enabled": t.get(), "feature_present": true }),
        None    => serde_json::json!({ "enabled": false,    "feature_present": false }),
    };
    json_response(200, &body)
}

// ---------------------------------------------------------------------------
// RT-T3 — audit-mutated route CRUD
// ---------------------------------------------------------------------------

/// Project the route list of a (possibly-modified) `WafConfig`
/// into the audit-chain `before` / `after` shape — same approach
/// as `upstreams_audit_view`, but driven off `RouteConfigPatch`
/// (the Serialize+Deserialize wire shape) so the diff lands in
/// the audit log without leaking internal enum reprs.
fn routes_audit_view(routes: &[aegis_core::config::RouteConfig]) -> serde_json::Value {
    use aegis_control::api::routes_config::RouteConfigPatch;
    let patches: Vec<RouteConfigPatch> = routes.iter().map(RouteConfigPatch::from_route).collect();
    serde_json::to_value(&serde_json::json!({ "routes": patches }))
        .unwrap_or(serde_json::Value::Null)
}

pub(crate) async fn handle_route_upsert(
    req: hyper::Request<hyper::body::Incoming>,
    route_id: &str,
    cfg: &aegis_core::config::WafConfig,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use aegis_control::api::routes_config::{validate_route, RouteConfigPatch};
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "route-upsert");
    let Some(writer) = services.route_writer.as_ref().cloned() else {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal(
                "route writer not wired".into(),
            ),
        );
    };

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Internal("body read failed".into()),
            )
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");
    let mut patch: RouteConfigPatch = match serde_json::from_str(body_str) {
        Ok(p) => p,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e.to_string()),
            )
        }
    };

    // The path-param `route_id` is authoritative — operators can
    // PUT to /api/routes/foo with a body that omits `id` (or
    // contains a typo). Force consistency the same way
    // `handle_pool_upsert` keys off the URL.
    patch.id = route_id.to_string();

    // FIX 2026-05-04 — `validate_route` checks
    // `cfg.upstreams.contains_key(...)`, but the boot-time
    // `cfg` doesn't reflect pools added at runtime via
    // `PUT /api/upstreams/pool/{id}`. Read the live pool map
    // from the writer's shadow so routes pointing at a freshly-
    // added pool validate cleanly.
    let mut effective_cfg = cfg.clone();
    if let Some(writer) = services.upstream_writer.as_ref() {
        for (name, pool_cfg) in writer.current_pools() {
            effective_cfg.upstreams.insert(name, pool_cfg);
        }
    }

    if let Err(e) = validate_route(&patch, &effective_cfg) {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(e.to_string()),
        );
    }

    let new_route = match patch.into_route() {
        Ok(r) => r,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e.to_string()),
            )
        }
    };

    // Build the candidate route list: existing routes minus the
    // one with this id (if present), plus the new entry. Order
    // matters for first-match-wins resolution: replace-in-place
    // when updating, append when creating.
    //
    // FIX 2026-05-04 — read from the live writer's `current_routes`
    // (boot snapshot + every prior runtime upsert/delete) instead
    // of the stale `cfg.routes` boot snapshot. Without this, two
    // consecutive runtime upserts would silently lose the first
    // because each handler would rebuild from the boot list.
    let mut next_routes = writer.current_routes();
    if next_routes.is_empty() {
        // Default-impl fallback (test bundles / writers that
        // didn't override `current_routes`).
        next_routes = cfg.routes.clone();
    }
    let existing_idx = next_routes.iter().position(|r| r.id == route_id);
    match existing_idx {
        Some(i) => next_routes[i] = new_route,
        None => next_routes.push(new_route),
    }

    let before = routes_audit_view(&cfg.routes);
    let after = routes_audit_view(&next_routes);
    let resource = format!("/api/routes/{route_id}");
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: "route_upsert",
        reason: "operator upserted route",
    };

    // Build a candidate WafConfig for the writer to compile.
    let mut next_cfg = cfg.clone();
    next_cfg.routes = next_routes;

    let writer_for_apply = Arc::clone(&writer);
    let route_id_owned = route_id.to_string();
    // Snapshot the routes we're about to swap into the RouteTable
    // so we can seed `services.routes` once apply succeeds — keeps
    // the GET /api/routes cache in sync with the live table.
    let next_routes_for_cache = next_cfg.routes.clone();
    let outcome = services.mutate.apply(
        &req_ctx,
        before,
        after,
        move || writer_for_apply.apply(&next_cfg),
    );
    match outcome {
        Ok(_) => {
            services.routes.set(route_summaries(&next_routes_for_cache));
            json_response(
                200,
                &serde_json::json!({
                    "ok": true,
                    "route": route_id_owned,
                    "request_id": pre.request_id,
                }),
            )
        }
        Err(e) => mutation_error_response(e),
    }
}

pub(crate) async fn handle_route_delete(
    req: hyper::Request<hyper::body::Incoming>,
    route_id: &str,
    cfg: &aegis_core::config::WafConfig,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use aegis_control::api::routes_config::is_only_catchall;

    let pre = mutation_preamble(&req, "route-delete");
    let Some(writer) = services.route_writer.as_ref().cloned() else {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal(
                "route writer not wired".into(),
            ),
        );
    };

    // FIX 2026-05-04 — read from live writer state, not the
    // boot snapshot, so route deletes work after runtime upserts.
    let live_routes = writer.current_routes();
    let live_routes = if live_routes.is_empty() { cfg.routes.clone() } else { live_routes };
    if !live_routes.iter().any(|r| r.id == route_id) {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Validation(format!(
                "no route with id '{route_id}'"
            )),
        );
    }

    // Refuse to remove the last catch-all — it would brick
    // traffic on every path the more-specific routes don't cover,
    // and `RouteTable::build` rejects the resulting config
    // outright. 409 with a clear message so the dashboard can
    // surface "you must add another catch-all first" without
    // round-tripping a build error.
    //
    // Build a synthetic cfg with the live route list so the
    // catch-all check sees runtime-added routes too.
    let mut effective_cfg = cfg.clone();
    effective_cfg.routes = live_routes.clone();
    if is_only_catchall(&effective_cfg, route_id) {
        let body = serde_json::json!({
            "ok": false,
            "reason": "last_catchall",
            "message": format!(
                "route '{route_id}' is the only catch-all (path: '/' with no host) — add another catch-all before deleting"
            ),
        });
        return json_body_response(409, body.to_string(), "private, no-store");
    }

    let mut next_routes = live_routes;
    next_routes.retain(|r| r.id != route_id);

    let before = routes_audit_view(&cfg.routes);
    let after = routes_audit_view(&next_routes);
    let resource = format!("/api/routes/{route_id}");
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "DELETE",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: "route_delete",
        reason: "operator removed route",
    };

    let mut next_cfg = cfg.clone();
    next_cfg.routes = next_routes;

    let writer_for_apply = Arc::clone(&writer);
    let route_id_owned = route_id.to_string();
    let next_routes_for_cache = next_cfg.routes.clone();
    let outcome = services.mutate.apply(
        &req_ctx,
        before,
        after,
        move || writer_for_apply.apply(&next_cfg),
    );
    match outcome {
        Ok(_) => {
            services.routes.set(route_summaries(&next_routes_for_cache));
            json_response(
                200,
                &serde_json::json!({
                    "ok": true,
                    "removed": route_id_owned,
                    "request_id": pre.request_id,
                }),
            )
        }
        Err(e) => mutation_error_response(e),
    }
}

// ---------------------------------------------------------------------------
// 2026-05-09 — DDoS gate + Rate Limit gate audit-mutated PUTs
// ---------------------------------------------------------------------------

/// `PUT /api/gates/ddos` — hot-swap the DDoS detector config.
/// Audit-mutated through `AuditedMutate`. Per-IP StateBackend
/// state is preserved (operators tightening thresholds don't
/// reset every flooding source IP). Validation enforces
/// non-zero thresholds and `spike_multiplier > 1.0`.
pub(crate) async fn handle_ddos_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "ddos-put");
    // 2026-05-19 — the runtime is now installed unconditionally at
    // proxy boot (see aegis-proxy::run); `enabled` is decided
    // inside the detector, so `None` here only happens when this
    // handler is invoked against a test-bundle `DashboardServices`
    // built without the proxy wired in.
    let Some(runtime) = services.ddos.as_ref().cloned() else {
        return mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal(
                "ddos runtime not wired by proxy boot (test bundle?)".into(),
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
    let put_body: aegis_control::api::gates::DdosPutBody = match serde_json::from_str(body_str) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e.to_string()),
            )
        }
    };
    let mut new_cfg = match put_body.validate() {
        Ok(c) => c,
        Err(errs) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(errs.join("; ")),
            )
        }
    };
    let before_cfg = runtime.config_snapshot();
    // 2026-05-18 (QC Sprint 1.2 — F-CRITICAL-005, DD-06): the PUT
    // body doesn't carry `tier_overrides` / `failure_mode` today —
    // those are YAML-only knobs. Preserve the existing in-memory
    // values across the hot-swap so operators tightening the
    // global `per_ip_limit` via the dashboard don't accidentally
    // clear their YAML-configured per-tier policy. A dashboard
    // knob for the per-tier sliders is tracked in
    // plans/issue-fix/2026-05-18-qc-followup/ § DD-06.
    new_cfg.tier_overrides = before_cfg.tier_overrides.clone();
    new_cfg.failure_mode = before_cfg.failure_mode.clone();
    let before_view = aegis_control::api::gates::DdosConfigView::from(before_cfg);
    let after_view = aegis_control::api::gates::DdosConfigView::from(new_cfg.clone());

    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: "/api/gates/ddos",
        action: "ddos_set",
        reason: "operator updated DDoS gate thresholds",
    };
    let runtime_for_apply = runtime.clone();
    let new_cfg_for_apply = new_cfg.clone();
    let outcome = services.mutate.apply::<_, (), aegis_control::api::mutation::MutationError>(
        &req_ctx,
        serde_json::to_value(&before_view).unwrap_or(serde_json::Value::Null),
        serde_json::to_value(&after_view).unwrap_or(serde_json::Value::Null),
        move || {
            runtime_for_apply.set_config(new_cfg_for_apply);
            Ok(())
        },
    );
    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "applied": after_view,
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

/// `PUT /api/rate-limit` — hot-swap the per-IP token-bucket
/// limiter config. Audit-mutated through `AuditedMutate`.
/// Per-IP timestamp state preserved.
pub(crate) async fn handle_rate_limit_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "rate-limit-put");
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
    let put_body: aegis_control::api::gates::RateLimitPutBody =
        match serde_json::from_str(body_str) {
            Ok(b) => b,
            Err(e) => {
                return mutation_error_response(
                    aegis_control::api::mutation::MutationError::Validation(e.to_string()),
                )
            }
        };
    let new_cfg = match put_body.validate() {
        Ok(c) => c,
        Err(errs) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(errs.join("; ")),
            )
        }
    };
    let before_cfg = services.ip_rate_limiter.config_snapshot();
    let before_json = serde_json::json!({
        "limit": before_cfg.limit,
        "window_seconds": before_cfg.window.as_secs(),
    });
    let after_json = serde_json::json!({
        "limit": new_cfg.limit,
        "window_seconds": new_cfg.window.as_secs(),
    });

    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: "/api/rate-limit",
        action: "rate_limit_set",
        reason: "operator updated per-IP rate-limit config",
    };
    let limiter = services.ip_rate_limiter.clone();
    let outcome = services.mutate.apply::<_, (), aegis_control::api::mutation::MutationError>(
        &req_ctx,
        before_json,
        after_json.clone(),
        move || {
            limiter.set_config(new_cfg);
            Ok(())
        },
    );
    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "applied": after_json,
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

/// `PUT /api/gates/strikes` — hot-swap the Strike-Block gate
/// config (`enabled` + `block_at`). Audit-mutated through
/// `AuditedMutate`. Per-IP strike state in the `RiskTracker`
/// map is preserved across edits — operators flipping the gate
/// on/off or tightening `block_at` mid-incident don't get a free
/// reset for accumulating IPs.
pub(crate) async fn handle_strikes_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "strikes-put");
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
    let put_body: aegis_control::api::gates::StrikesPutBody =
        match serde_json::from_str(body_str) {
            Ok(b) => b,
            Err(e) => {
                return mutation_error_response(
                    aegis_control::api::mutation::MutationError::Validation(e.to_string()),
                )
            }
        };
    let new_cfg = match put_body.validate() {
        Ok(c) => c,
        Err(errs) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(errs.join("; ")),
            )
        }
    };
    let before_cfg = services.risk.strike_config_snapshot();
    let before_json = serde_json::json!({
        "enabled": before_cfg.enabled,
        "block_at": before_cfg.block_at,
    });
    let after_json = serde_json::json!({
        "enabled": new_cfg.enabled,
        "block_at": new_cfg.block_at,
    });

    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: "/api/gates/strikes",
        action: "strikes_set",
        reason: "operator updated Strike-Block gate config",
    };
    let risk = services.risk.clone();
    let new_cfg_apply = new_cfg.clone();
    let outcome = services.mutate.apply::<_, (), aegis_control::api::mutation::MutationError>(
        &req_ctx,
        before_json,
        after_json.clone(),
        move || {
            risk.set_strike_config(new_cfg_apply);
            Ok(())
        },
    );
    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "applied": after_json,
                "request_id": pre.request_id,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_ai_enabled_sets_existing_field() {
        let base = "listeners:\n  data:\n    - bind: \"127.0.0.1:8080\"\nai:\n  enabled: false\n";
        let out = patch_ai_enabled(base, true).unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
        assert_eq!(v["ai"]["enabled"], serde_yaml::Value::Bool(true));
    }

    #[test]
    fn patch_ai_enabled_creates_ai_block_when_absent() {
        let base = "listeners:\n  data:\n    - bind: \"127.0.0.1:8080\"\n";
        let out = patch_ai_enabled(base, true).unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
        assert_eq!(v["ai"]["enabled"], serde_yaml::Value::Bool(true));
    }

    #[test]
    fn patch_ai_enabled_preserves_other_fields() {
        let base = "listeners:\n  data:\n    - bind: \"127.0.0.1:8080\"\nstate:\n  backend: redis\nai:\n  enabled: true\n";
        let out = patch_ai_enabled(base, false).unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
        assert_eq!(v["ai"]["enabled"], serde_yaml::Value::Bool(false));
        assert_eq!(v["state"]["backend"], serde_yaml::Value::String("redis".into()));
    }

    #[test]
    fn patch_response_filter_sets_all_three_rungs() {
        use aegis_control::api::response_filter::ResponseFilterPatch;
        let base = "listeners:\n  data:\n    - bind: \"127.0.0.1:8080\"\n";
        let patch = ResponseFilterPatch {
            scrub_stack_traces: false,
            mask_internal_ips: true,
            redact_dlp: false,
        };
        let out = patch_response_filter(base, &patch).unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
        assert_eq!(v["response_filter"]["scrub_stack_traces"], serde_yaml::Value::Bool(false));
        assert_eq!(v["response_filter"]["mask_internal_ips"], serde_yaml::Value::Bool(true));
        assert_eq!(v["response_filter"]["redact_dlp"], serde_yaml::Value::Bool(false));
    }

    #[test]
    fn patch_tier_writes_full_entry_and_omits_none_cumulative() {
        let base = "listeners:\n  data:\n    - bind: \"127.0.0.1:8080\"\n";
        let patch = TierPatch {
            pipeline: vec!["sqli".into(), "xss".into()],
            risk_threshold: 60,
            block_threshold: 80,
            cumulative_challenge_at: Some(40),
            cumulative_block_at: None,
            challenges_enabled: true,
        };
        let out = patch_tier(base, "high", &patch).unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
        assert_eq!(v["tiers"]["high"]["risk_threshold"].as_u64(), Some(60));
        assert_eq!(v["tiers"]["high"]["block_threshold"].as_u64(), Some(80));
        assert_eq!(v["tiers"]["high"]["challenges_enabled"].as_bool(), Some(true));
        assert_eq!(v["tiers"]["high"]["cumulative_challenge_at"].as_u64(), Some(40));
        assert!(v["tiers"]["high"]["cumulative_block_at"].is_null());
        assert_eq!(v["tiers"]["high"]["pipeline"][0].as_str(), Some("sqli"));
    }

    #[test]
    fn ca_bundle_apply_flag_default_is_false() {
        assert!(!ca_bundle_apply_flag(None));
        assert!(!ca_bundle_apply_flag(Some("")));
    }

    #[test]
    fn ca_bundle_apply_flag_recognises_true_and_one() {
        assert!(ca_bundle_apply_flag(Some("apply=true")));
        assert!(ca_bundle_apply_flag(Some("apply=TRUE")));
        assert!(ca_bundle_apply_flag(Some("apply=True")));
        assert!(ca_bundle_apply_flag(Some("apply=1")));
    }

    #[test]
    fn ca_bundle_apply_flag_rejects_other_values() {
        assert!(!ca_bundle_apply_flag(Some("apply=false")));
        assert!(!ca_bundle_apply_flag(Some("apply=0")));
        assert!(!ca_bundle_apply_flag(Some("apply=yes")));
        assert!(!ca_bundle_apply_flag(Some("apply=")));
        assert!(!ca_bundle_apply_flag(Some("apply")));
    }

    #[test]
    fn ca_bundle_apply_flag_handles_extra_params() {
        // Apply flag survives sibling params on either side.
        assert!(ca_bundle_apply_flag(Some("apply=true&dry_run=1")));
        assert!(ca_bundle_apply_flag(Some("foo=bar&apply=1")));
        assert!(ca_bundle_apply_flag(Some("a=1&apply=true&b=2")));
        // No `apply` key anywhere — still false.
        assert!(!ca_bundle_apply_flag(Some("foo=true&bar=1")));
    }

    #[test]
    fn ca_bundle_apply_flag_ignores_other_keys_with_apply_in_name() {
        // Substring match must NOT match — only exact key `apply`.
        assert!(!ca_bundle_apply_flag(Some("applyless=true")));
        assert!(!ca_bundle_apply_flag(Some("preapply=1")));
    }
}
