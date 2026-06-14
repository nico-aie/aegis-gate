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
//! - [`patch_detectors`] — patches `cfg.detectors` (+ sibling
//!   `cfg.ai.enabled`) on the shared config-plane doc for the
//!   folded `PUT /api/detectors`.
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

use bytes::Bytes;
use http_body_util::Full;
use hyper::Response;

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
        Err(_) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                "body read failed".into(),
            ))
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");
    let parsed: serde_json::Value =
        serde_json::from_str(if body_str.is_empty() { "{}" } else { body_str })
            .unwrap_or(serde_json::Value::Null);
    let mode_str = parsed.get("mode").and_then(|v| v.as_str()).unwrap_or("");
    let new_mode = match mode_str {
        "enforce" => aegis_control::interop::headers::Mode::Enforce,
        "log_only" | "shadow" => aegis_control::interop::headers::Mode::LogOnly,
        _ => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(
                    "mode must be 'enforce' or 'log_only'".into(),
                ),
            )
        }
    };

    let Some(rt) = services.interop.as_ref() else {
        return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
            "interop runtime not wired".into(),
        ));
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
    let outcome = services
        .mutate
        .apply::<_, (), aegis_control::api::mutation::MutationError>(
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

/// 2026-05-27 (Phase B upstreams fold) — replace the whole
/// `cfg.upstreams` mapping on a YAML config doc with `pools_json` (the
/// raw request JSON; `PoolConfig` isn't `Serialize` so we route the
/// operator's authored value straight through JSON → YAML, preserving
/// hostnames). The apply-side resolves them per-node at activation.
fn patch_upstreams_replace(base: &str, pools_json: &serde_json::Value) -> Result<String, String> {
    let mut doc: serde_yaml::Value =
        serde_yaml::from_str(base).map_err(|e| format!("base config not YAML: {e}"))?;
    let serde_yaml::Value::Mapping(map) = &mut doc else {
        return Err("base config is not a YAML mapping".into());
    };
    let pools_yaml =
        serde_yaml::to_value(pools_json).map_err(|e| format!("pools not serialisable: {e}"))?;
    map.insert(serde_yaml::Value::String("upstreams".into()), pools_yaml);
    serde_yaml::to_string(&doc).map_err(|e| format!("re-serialize config: {e}"))
}

/// Upsert one pool into `cfg.upstreams.<id>` on a YAML config doc.
fn patch_upstream_pool_set(
    base: &str,
    id: &str,
    pool_json: &serde_json::Value,
) -> Result<String, String> {
    let mut doc: serde_yaml::Value =
        serde_yaml::from_str(base).map_err(|e| format!("base config not YAML: {e}"))?;
    let serde_yaml::Value::Mapping(map) = &mut doc else {
        return Err("base config is not a YAML mapping".into());
    };
    let upstreams = yaml_child_map(map, "upstreams")?;
    let pool_yaml =
        serde_yaml::to_value(pool_json).map_err(|e| format!("pool not serialisable: {e}"))?;
    upstreams.insert(serde_yaml::Value::String(id.into()), pool_yaml);
    serde_yaml::to_string(&doc).map_err(|e| format!("re-serialize config: {e}"))
}

/// Remove `cfg.upstreams.<id>` from a YAML config doc (idempotent).
fn patch_upstream_pool_remove(base: &str, id: &str) -> Result<String, String> {
    let mut doc: serde_yaml::Value =
        serde_yaml::from_str(base).map_err(|e| format!("base config not YAML: {e}"))?;
    let serde_yaml::Value::Mapping(map) = &mut doc else {
        return Err("base config is not a YAML mapping".into());
    };
    let upstreams = yaml_child_map(map, "upstreams")?;
    upstreams.remove(id);
    serde_yaml::to_string(&doc).map_err(|e| format!("re-serialize config: {e}"))
}

/// P4 global cross-ref gate for runtime pool edits: every enabled pool
/// that names a **bundle-style** trust anchor (a bare name, no path
/// separator) must reference a backend-CA bundle already uploaded to
/// the config plane (`aegis:zt:upstream:trust:<name>`). A **path-style**
/// value (contains `/`) is treated as a file and left to boot-time /
/// file-read enforcement — matching `materialize_zero_trust_state`'s
/// lookup-first resolution. This surfaces "enabled mTLS against a
/// bundle that isn't uploaded" as a 400 at PUT time instead of a
/// fail-closed dial at the next boot.
///
/// The structural checks (`enabled ⇒ zero_trust.upstream_identity`,
/// TLS required, P4/P5-gated knobs) already run inside
/// `aegis_core::load_config_str` (→ `validate_upstream_mtls`); this
/// adds only the state-dependent piece pure validation can't see.
/// No-op when no state backend is wired.
async fn validate_pool_trust_bundles(
    upstreams: &std::collections::HashMap<String, aegis_core::config::PoolConfig>,
    state: Option<&std::sync::Arc<dyn aegis_core::state::StateBackend>>,
) -> Result<(), aegis_control::api::mutation::MutationError> {
    use aegis_control::api::mutation::MutationError;
    let Some(state) = state else {
        return Ok(());
    };
    for (name, pool) in upstreams {
        let Some(m) = pool.upstream_mtls.as_ref() else {
            continue;
        };
        if !m.enabled {
            continue;
        }
        let Some(trust) = m.trust.as_ref().and_then(|p| p.to_str()) else {
            continue;
        };
        // Path-style ⇒ file source; boot / file-read enforces it.
        if trust.contains('/') {
            continue;
        }
        // Bare name ⇒ must be a valid identifier AND an uploaded bundle.
        if !aegis_control::api::zero_trust::is_valid_bundle_name(trust) {
            return Err(MutationError::Validation(format!(
                "upstream '{name}': upstream_mtls.trust '{trust}' is neither a valid bundle \
                 name ([A-Za-z0-9._-], ≤64) nor a file path"
            )));
        }
        let key = aegis_core::config::upstream_trust_state_key(trust);
        let exists = state
            .get(&key)
            .await
            .map_err(|e| MutationError::Internal(format!("config-plane read: {e}")))?
            .is_some();
        if !exists {
            return Err(MutationError::Validation(format!(
                "upstream '{name}': upstream_mtls.trust '{trust}' is not an uploaded backend-CA \
                 bundle — POST /api/zero-trust/upstream/trust/{trust} first (or set trust to a \
                 CA file path)"
            )));
        }
    }
    Ok(())
}

/// Local resolvability gate for the folded upstream handlers: resolve
/// `pools` against this node's resolver (Strict) purely to surface
/// typos as a 400 before activating. The result is discarded — the doc
/// stores operator-authored hostnames and every node re-resolves at
/// apply time (`reload::apply_cfg_change_to_upstreams`).
async fn validate_upstream_resolvable(
    pools: std::collections::HashMap<String, aegis_core::config::PoolConfig>,
) -> Result<(), aegis_control::api::mutation::MutationError> {
    crate::upstream::dns_resolve::expand_hostname_members(pools)
        .await
        .map(|_| ())
        .map_err(|e| aegis_control::api::mutation::MutationError::Validation(e.to_string()))
}

pub(crate) async fn handle_upstreams_config_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "upstreams-config-put");

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                "body read failed".into(),
            ))
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");
    let body_json: serde_json::Value = match serde_json::from_str(if body_str.is_empty() {
        "{\"pools\":{}}"
    } else {
        body_str
    }) {
        Ok(v) => v,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e.to_string()),
            )
        }
    };
    let pools_json = body_json
        .get("pools")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    // Validate the authored shape deserialises into PoolConfigs.
    let pools_typed: std::collections::HashMap<String, aegis_core::config::PoolConfig> =
        match serde_json::from_value(pools_json.clone()) {
            Ok(p) => p,
            Err(e) => {
                return mutation_error_response(
                    aegis_control::api::mutation::MutationError::Validation(e.to_string()),
                )
            }
        };
    let count = pools_typed.len();
    let names: Vec<String> = {
        let mut v: Vec<String> = pools_typed.keys().cloned().collect();
        v.sort();
        v
    };
    // Local resolvability gate (typos → 400) — result discarded.
    if let Err(e) = validate_upstream_resolvable(pools_typed).await {
        return mutation_error_response(e);
    }

    // 2026-05-27 (Phase B upstreams fold) — patch `cfg.upstreams` on the
    // shared doc + activate. Each node rebuilds its `PoolRegistry` from
    // the activated config via `apply_cfg_change_to_upstreams` (per-node
    // DNS). Retires the per-node direct `PoolRegistry::apply`.
    let (store, base_blob, expected) = match load_active_config_doc(services).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let new_blob = match patch_upstreams_replace(&base_blob, &pools_json) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e),
            )
        }
    };
    let patched_cfg = match aegis_core::load_config_str(&new_blob) {
        Ok(c) => c,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(format!(
                    "patched config failed validation: {e}"
                )),
            )
        }
    };
    // P4 — state-dependent cross-ref for every enabled pool's
    // bundle-style `upstream_mtls.trust`.
    if let Err(e) =
        validate_pool_trust_bundles(&patched_cfg.upstreams, services.state_backend.as_ref()).await
    {
        return mutation_error_response(e);
    }

    let before = serde_json::json!({ "version": expected });
    let after = serde_json::json!({ "count": count, "names": names });
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
    let store_for_apply = store.clone();
    let blob = new_blob;
    let actor = pre.actor.clone();
    let outcome = services
        .mutate
        .apply_async(&req_ctx, before, after, move || async move {
            store_for_apply
                .activate(expected, blob, &actor, "replace upstream pools")
                .await
        })
        .await;
    match outcome {
        Ok(mo) => match mo.value {
            crate::config_source::config_store::Activate::Applied { version } => json_response(
                200,
                &serde_json::json!({
                    "ok": true,
                    "count": count,
                    "names": names,
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

pub(crate) async fn handle_pool_upsert(
    req: hyper::Request<hyper::body::Incoming>,
    pool_id: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "pool-upsert");

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                "body read failed".into(),
            ))
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");
    let pool_json: serde_json::Value = match serde_json::from_str(body_str) {
        Ok(v) => v,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e.to_string()),
            )
        }
    };
    let pool_typed: aegis_core::config::PoolConfig = match serde_json::from_value(pool_json.clone())
    {
        Ok(p) => p,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e.to_string()),
            )
        }
    };
    let mut one = std::collections::HashMap::new();
    one.insert(pool_id.to_string(), pool_typed);
    if let Err(e) = validate_upstream_resolvable(one).await {
        return mutation_error_response(e);
    }

    let (store, base_blob, expected) = match load_active_config_doc(services).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let new_blob = match patch_upstream_pool_set(&base_blob, pool_id, &pool_json) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e),
            )
        }
    };
    let patched_cfg = match aegis_core::load_config_str(&new_blob) {
        Ok(c) => c,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(format!(
                    "patched config failed validation: {e}"
                )),
            )
        }
    };
    // P4 — state-dependent cross-ref: a bundle-style `upstream_mtls.trust`
    // must name an uploaded backend-CA bundle (pure validation above
    // can't see the config plane).
    if let Err(e) =
        validate_pool_trust_bundles(&patched_cfg.upstreams, services.state_backend.as_ref()).await
    {
        return mutation_error_response(e);
    }

    let before = serde_json::json!({ "version": expected });
    let after = serde_json::json!({ "pool": pool_id });
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
    let store_for_apply = store.clone();
    let blob = new_blob;
    let actor = pre.actor.clone();
    let pool_id_owned = pool_id.to_string();
    let outcome = services
        .mutate
        .apply_async(&req_ctx, before, after, move || async move {
            store_for_apply
                .activate(expected, blob, &actor, "upsert upstream pool")
                .await
        })
        .await;
    match outcome {
        Ok(mo) => match mo.value {
            crate::config_source::config_store::Activate::Applied { version } => json_response(
                200,
                &serde_json::json!({
                    "ok": true,
                    "pool": pool_id_owned,
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

pub(crate) async fn handle_pool_delete(
    req: hyper::Request<hyper::body::Incoming>,
    pool_id: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let pre = mutation_preamble(&req, "pool-delete");

    let (store, base_blob, expected) = match load_active_config_doc(services).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let doc_cfg = match aegis_core::load_config_str(&base_blob) {
        Ok(c) => c,
        Err(e) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                format!("active config doc failed to parse: {e}"),
            ))
        }
    };
    if !doc_cfg.upstreams.contains_key(pool_id) {
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            format!("no pool named '{pool_id}'"),
        ));
    }
    // Refuse with the route-reference list (checked against the doc —
    // the source of truth) so the dashboard's delete confirm modal can
    // surface what to fix first.
    let refs = aegis_control::api::upstreams_config::routes_referencing(&doc_cfg, pool_id);
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

    let new_blob = match patch_upstream_pool_remove(&base_blob, pool_id) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e),
            )
        }
    };
    if let Err(e) = aegis_core::load_config_str(&new_blob) {
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            format!("patched config failed validation: {e}"),
        ));
    }

    let before = serde_json::json!({ "version": expected });
    let after = serde_json::json!({ "removed": pool_id });
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
    let store_for_apply = store.clone();
    let blob = new_blob;
    let actor = pre.actor.clone();
    let pool_id_owned = pool_id.to_string();
    let outcome = services
        .mutate
        .apply_async(&req_ctx, before, after, move || async move {
            store_for_apply
                .activate(expected, blob, &actor, "delete upstream pool")
                .await
        })
        .await;
    match outcome {
        Ok(mo) => match mo.value {
            crate::config_source::config_store::Activate::Applied { version } => json_response(
                200,
                &serde_json::json!({
                    "ok": true,
                    "removed": pool_id_owned,
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

/// N1 (2026-06-11) — set `cfg.alerting.receivers` in the YAML blob so the
/// receiver list rides the shared config doc and propagates fleet-wide.
/// Always writes the whole `alerting` block, so after any receiver edit the
/// list is config-managed (an empty list is a valid, propagating state).
fn patch_receivers(
    base: &str,
    receivers: &[aegis_control::slo::AlertReceiver],
) -> Result<String, String> {
    let mut doc: serde_yaml::Value =
        serde_yaml::from_str(base).map_err(|e| format!("base config not YAML: {e}"))?;
    let serde_yaml::Value::Mapping(map) = &mut doc else {
        return Err("base config is not a YAML mapping".into());
    };
    let cfg_receivers: Vec<aegis_core::config::ReceiverConfig> = receivers
        .iter()
        .map(crate::config_source::reload::receiver_to_config)
        .collect();
    let alerting = serde_yaml::to_value(aegis_core::config::AlertingConfig {
        receivers: cfg_receivers,
    })
    .map_err(|e| format!("alerting block not serialisable: {e}"))?;
    map.insert(serde_yaml::Value::String("alerting".into()), alerting);
    serde_yaml::to_string(&doc).map_err(|e| format!("re-serialize config: {e}"))
}

pub(crate) async fn handle_alert_receivers_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "alert-receivers-put");

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                "body read failed".into(),
            ))
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

    if let Err(e) = aegis_control::api::alert_receivers::validate_receivers(&parsed.receivers) {
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            e.to_string(),
        ));
    }

    // N1 — fold the receiver list into the shared config doc (instead of
    // swapping the node-local ArcSwap) so it propagates to every node and
    // survives restart. The config-plane watcher re-derives the live store
    // on apply; the N2 nudge makes that ~ms.
    let (store, base_blob, expected) = match load_active_config_doc(services).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let new_blob = match patch_receivers(&base_blob, &parsed.receivers) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e),
            )
        }
    };
    if let Err(e) = aegis_core::load_config_str(&new_blob) {
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            format!("patched config failed validation: {e}"),
        ));
    }

    let current = services
        .alert_receivers_store
        .as_ref()
        .map(|s| (**s.load()).clone())
        .unwrap_or_default();
    let before = redact_receivers_for_audit(&current);
    let after = redact_receivers_for_audit(&parsed.receivers);
    let names: Vec<String> = parsed.receivers.iter().map(|r| r.name.clone()).collect();
    let count = parsed.receivers.len();

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

    let store_for_apply = store.clone();
    let blob = new_blob;
    let actor = pre.actor.clone();
    let outcome = services
        .mutate
        .apply_async(&req_ctx, before, after, move || async move {
            store_for_apply
                .activate(expected, blob, &actor, "update alert receivers")
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
                    "count": count,
                    "names": names,
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

pub(crate) async fn handle_alert_receiver_delete(
    req: hyper::Request<hyper::body::Incoming>,
    name: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let pre = mutation_preamble(&req, "alert-receiver-delete");

    // Current applied list (the shared store reflects the live config).
    // Filter the named receiver out, then fold the result into the doc.
    let current = services
        .alert_receivers_store
        .as_ref()
        .map(|s| (**s.load()).clone())
        .unwrap_or_default();
    let next: Vec<aegis_control::slo::AlertReceiver> =
        current.iter().filter(|r| r.name != name).cloned().collect();
    if next.len() == current.len() {
        // Name not found — surface a validation-class error so the
        // dashboard can show "no such receiver" without 500-ing.
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            format!("no receiver named '{name}'"),
        ));
    }

    // N1 — fold into the shared config doc so the removal propagates.
    let (store, base_blob, expected) = match load_active_config_doc(services).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let new_blob = match patch_receivers(&base_blob, &next) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e),
            )
        }
    };
    if let Err(e) = aegis_core::load_config_str(&new_blob) {
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            format!("patched config failed validation: {e}"),
        ));
    }

    let before = redact_receivers_for_audit(&current);
    let after = redact_receivers_for_audit(&next);
    let remaining: Vec<String> = next.iter().map(|r| r.name.clone()).collect();
    let removed = name.to_string();
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

    let store_for_apply = store.clone();
    let blob = new_blob;
    let actor = pre.actor.clone();
    let outcome = services
        .mutate
        .apply_async(&req_ctx, before, after, move || async move {
            store_for_apply
                .activate(expected, blob, &actor, "delete alert receiver")
                .await
        })
        .await;
    match outcome {
        Ok(mo) => match mo.value {
            crate::config_source::config_store::Activate::Applied { version } => json_response(
                200,
                &serde_json::json!({
                    "ok": true,
                    "removed": removed,
                    "remaining": remaining,
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

pub(crate) async fn handle_alert_receiver_test(
    req: hyper::Request<hyper::body::Incoming>,
    name: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let pre = mutation_preamble(&req, "alert-receiver-test");

    let Some(store) = services.alert_receivers_store.as_ref().cloned() else {
        return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
            "alert receivers store not wired".into(),
        ));
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
        measured: 1.0,
        target: 0.999,
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
    let outcome = services
        .mutate
        .apply::<_, (), aegis_control::api::mutation::MutationError>(
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
    let summary =
        aegis_control::slo::dispatch::send_alert(&synthetic, std::slice::from_ref(&receiver)).await;

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
    let outcome = services
        .mutate
        .apply::<_, (), aegis_control::api::mutation::MutationError>(
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
    let preview = aegis_control::api::zero_trust::ca_bundle::parse_and_preview(body_bytes.as_ref(), now);

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
            resource: "/api/zero-trust/downstream/ca-bundle",
            action: "zero_trust_ca_bundle_validated",
            reason: "operator previewed CA bundle (no swap)",
        };
        let outcome = services
            .mutate
            .apply::<_, (), aegis_control::api::mutation::MutationError>(
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
        aegis_control::api::zero_trust::ca_bundle::parse_and_preview(&before_pem, now).certificates
    };
    let diff =
        aegis_control::api::zero_trust::ca_bundle::diff_previews(&before_preview, &preview.certificates);

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
        resource: "/api/zero-trust/downstream/ca-bundle",
        action: "zero_trust_ca_bundle_swapped",
        reason: "operator hot-swapped CA bundle",
    };

    let outcome =
        services
            .mutate
            .apply::<_, usize, String>(&req_ctx, before_payload, after_payload, || {
                writer_cl
                    .swap_pem(body_for_swap.as_ref())
                    .map_err(|e| format!("trust anchor swap failed: {e}"))
            });

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
            "zero_trust_mode_clear",
            serde_json::json!({
                "configured": aegis_control::api::zero_trust::mode::mode_label(configured),
                "override": prev_override.map(aegis_control::api::zero_trust::mode::mode_label),
            }),
            serde_json::json!({
                "configured": aegis_control::api::zero_trust::mode::mode_label(configured),
                "override": serde_json::Value::Null,
            }),
            Box::new(move || {
                store_cl.clear();
                Ok(())
            }),
        )
    } else {
        let parsed = match mode_str.and_then(aegis_control::api::zero_trust::mode::parse_mode) {
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
            "zero_trust_mode_set",
            serde_json::json!({
                "configured": aegis_control::api::zero_trust::mode::mode_label(configured),
                "override": prev_override.map(aegis_control::api::zero_trust::mode::mode_label),
            }),
            serde_json::json!({
                "configured": aegis_control::api::zero_trust::mode::mode_label(configured),
                "override": aegis_control::api::zero_trust::mode::mode_label(parsed),
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
        resource: "/api/zero-trust/downstream/mode",
        action: action_label,
        reason: "operator changed mtls mode override",
    };

    let outcome = services
        .mutate
        .apply::<_, (), aegis_control::api::mutation::MutationError>(
            &req_ctx,
            before_payload,
            after_payload.clone(),
            applier,
        );

    match outcome {
        Ok(_) => {
            // Echo the new effective state in the response so the
            // dashboard doesn't need an immediate GET round-trip.
            let body =
                aegis_control::api::zero_trust::mode::render_mode_response(configured, store.current());
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

// P4 4a-ii — store the shared fleet WAF client identity (upstream
// mTLS, `source: state`) in the Redis config plane. Audit-mutated,
// CSRF-gated, and gated behind the same `allow_ca_upload` capability
// as the downstream CA-bundle upload.
//
// Accepts inline key PEM (`key_pem`) for console uploads, or a
// file/secret reference (`key_ref`) for file-backed identities.
// Persisted via `StateBackend::cas_set` under
// `aegis:zt:upstream:identity` so the fleet converges; nodes
// materialize at boot (`run::run`). The audit chain records PUBLIC
// cert metadata only.
//
// Body: `{"cert_pem": "<PUBLIC chain>", "key_pem": "<PEM>"}` or
//       `{"cert_pem": "<PUBLIC chain>", "key_ref": "<path|secret-ref>"}`.
pub(crate) async fn handle_zt_upstream_identity_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    if !services.allow_ca_upload {
        return json_response(
            403,
            &serde_json::json!({
                "error": "feature_disabled",
                "message": "Upstream identity upload is gated behind cfg.admin.dashboard_auth.allow_ca_upload — flip to true and restart to enable.",
            }),
        );
    }
    let Some(state) = services.state_backend.clone() else {
        return json_response(
            409,
            &serde_json::json!({
                "error": "state_unavailable",
                "message": "No config-plane StateBackend is wired; the shared upstream identity can't be persisted.",
            }),
        );
    };

    let pre = mutation_preamble(&req, "zt-upstream-identity-put");
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => bytes::Bytes::new(),
    };
    let upload: aegis_control::api::zero_trust::IdentityUploadRequest =
        match serde_json::from_slice(&body_bytes) {
            Ok(u) => u,
            Err(e) => {
                return json_response(
                    400,
                    &serde_json::json!({
                        "error": "invalid_body",
                        "message": format!("expected JSON {{cert_pem, key_pem|key_ref}}: {e}"),
                    }),
                )
            }
        };
    // Validate: PUBLIC cert parses, at least one of key_pem/key_ref set, no key leak.
    let certs = match aegis_control::api::zero_trust::validate_identity_upload(&upload) {
        Ok(c) => c,
        Err(e) => {
            return json_response(
                400,
                &serde_json::json!({ "error": "invalid_identity", "message": e }),
            )
        }
    };

    let record = aegis_core::config::UpstreamIdentityRecord {
        cert_pem: upload.cert_pem.clone(),
        key_pem: upload.key_pem.clone(),
        key_ref: upload.key_ref.clone().unwrap_or_default(),
    };
    let new_bytes = match serde_json::to_vec(&record) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Internal(format!(
                    "identity record encode: {e}"
                )),
            )
        }
    };

    // Audit before/after — PUBLIC cert metadata only.
    let before_existed = state
        .get(aegis_core::config::UPSTREAM_IDENTITY_STATE_KEY)
        .await
        .ok()
        .flatten()
        .is_some();
    let before = serde_json::json!({ "configured": before_existed });
    let after = serde_json::json!({
        "configured": true,
        "key_source": if upload.key_pem.is_some() { "inline_pem" } else { "key_ref" },
        "certificates": certs.clone(),
    });

    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: "/api/zero-trust/upstream/identity",
        action: "zero_trust_upstream_identity_set",
        reason: "operator stored the shared WAF client identity (public cert + key reference)",
    };

    let state_cl = state.clone();
    let outcome = services
        .mutate
        .apply_async(&req_ctx, before, after, move || async move {
            // CAS from the exact bytes we observed so a concurrent
            // writer can't be clobbered (mirrors config_store::activate).
            let current = state_cl
                .get(aegis_core::config::UPSTREAM_IDENTITY_STATE_KEY)
                .await
                .map_err(|e| format!("config-plane read: {e}"))?;
            let swapped = state_cl
                .cas_set(
                    aegis_core::config::UPSTREAM_IDENTITY_STATE_KEY,
                    current.as_deref(),
                    &new_bytes,
                    None,
                )
                .await
                .map_err(|e| format!("config-plane write: {e}"))?;
            if swapped {
                Ok(())
            } else {
                Err("config-plane conflict — the identity was updated concurrently; retry".to_string())
            }
        })
        .await;

    match outcome {
        Ok(_) => {
            // Immediately update the in-memory rotation status so the GET
            // endpoint reflects the new cert without waiting for the next
            // poll cycle (≤5 s). The rotation task will also pick it up on
            // its next tick and apply it to the pool registry.
            crate::upstream::rotation::notify_identity_updated(Some(upload.cert_pem.clone()));
            json_response(
                200,
                &serde_json::json!({
                    "ok": true,
                    "request_id": pre.request_id,
                    "configured": true,
                    "certificates": certs,
                }),
            )
        }
        Err(e) => mutation_error_response(e),
    }
}

// P4 trust bundles — upload / remove a PUBLIC backend-CA trust bundle
// a pool's `upstream_mtls.trust` references. Audit-mutated, CSRF-gated,
// allow_ca_upload-gated. Stored under `aegis:zt:upstream:trust:<name>`
// via `cas_set`; nodes materialize the bundle PEM at boot
// (`upstream::identity::materialize_zero_trust_state`). Body is raw PEM
// (matches the downstream CA-bundle upload + the dashboard's
// FileReader→text flow). A CA bundle is PUBLIC, so it is stored as-is.

/// Names of pools whose `upstream_mtls.trust` references `bundle` in
/// the given config blob. Best-effort: an unparseable blob yields no
/// refs (delete proceeds; a dangling ref just fails closed at boot).
fn pools_referencing_trust(blob: &str, bundle: &str) -> Vec<String> {
    let Ok(cfg) = aegis_core::load_config_str(blob) else {
        return Vec::new();
    };
    let mut out: Vec<String> = cfg
        .upstreams
        .iter()
        .filter(|(_, pool)| {
            pool.upstream_mtls
                .as_ref()
                .and_then(|m| m.trust.as_ref())
                .and_then(|p| p.to_str())
                .map(|t| t == bundle)
                .unwrap_or(false)
        })
        .map(|(name, _)| name.clone())
        .collect();
    out.sort();
    out
}

pub(crate) async fn handle_zt_upstream_trust_put(
    req: hyper::Request<hyper::body::Incoming>,
    bundle: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    if !services.allow_ca_upload {
        return json_response(
            403,
            &serde_json::json!({
                "error": "feature_disabled",
                "message": "Backend-CA upload is gated behind cfg.admin.dashboard_auth.allow_ca_upload — flip to true and restart to enable.",
            }),
        );
    }
    if !aegis_control::api::zero_trust::is_valid_bundle_name(bundle) {
        return json_response(
            400,
            &serde_json::json!({
                "error": "invalid_bundle_name",
                "message": "bundle name must be 1–64 chars of [A-Za-z0-9._-]",
            }),
        );
    }
    let Some(state) = services.state_backend.clone() else {
        return json_response(
            409,
            &serde_json::json!({
                "error": "state_unavailable",
                "message": "No config-plane StateBackend is wired; trust bundles can't be persisted.",
            }),
        );
    };

    let pre = mutation_preamble(&req, "zt-upstream-trust-put");
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
    let certs = match aegis_control::api::zero_trust::validate_trust_upload(body_bytes.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            return json_response(
                400,
                &serde_json::json!({ "error": "invalid_bundle", "message": e }),
            )
        }
    };

    let record = aegis_core::config::UpstreamTrustRecord {
        ca_pem: String::from_utf8_lossy(body_bytes.as_ref()).into_owned(),
    };
    let new_bytes = match serde_json::to_vec(&record) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Internal(format!(
                    "trust record encode: {e}"
                )),
            )
        }
    };

    let key = aegis_core::config::upstream_trust_state_key(bundle);
    let before_existed = state.get(&key).await.ok().flatten().is_some();
    let before = serde_json::json!({ "bundle": bundle, "configured": before_existed });
    let after = serde_json::json!({
        "bundle": bundle,
        "configured": true,
        "certificates": certs.clone(),
    });
    let resource = format!("/api/zero-trust/upstream/trust/{bundle}");
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "POST",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: "zero_trust_upstream_trust_set",
        reason: "operator uploaded a backend-CA trust bundle",
    };

    let key_cl = key.clone();
    let outcome = services
        .mutate
        .apply_async(&req_ctx, before, after, move || async move {
            let current = state
                .get(&key_cl)
                .await
                .map_err(|e| format!("config-plane read: {e}"))?;
            let swapped = state
                .cas_set(&key_cl, current.as_deref(), &new_bytes, None)
                .await
                .map_err(|e| format!("config-plane write: {e}"))?;
            if swapped {
                Ok(())
            } else {
                Err("config-plane conflict — the bundle was updated concurrently; retry".to_string())
            }
        })
        .await;

    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "request_id": pre.request_id,
                "bundle": bundle,
                "certificates": certs,
                "note": "Stored in the config plane. Pools that reference this bundle pick it up at boot (hot rotation lands in P5).",
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

pub(crate) async fn handle_zt_upstream_trust_delete(
    req: hyper::Request<hyper::body::Incoming>,
    bundle: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    if !services.allow_ca_upload {
        return json_response(
            403,
            &serde_json::json!({
                "error": "feature_disabled",
                "message": "Backend-CA management is gated behind cfg.admin.dashboard_auth.allow_ca_upload.",
            }),
        );
    }
    if !aegis_control::api::zero_trust::is_valid_bundle_name(bundle) {
        return json_response(
            400,
            &serde_json::json!({ "error": "invalid_bundle_name" }),
        );
    }
    let Some(state) = services.state_backend.clone() else {
        return json_response(
            409,
            &serde_json::json!({ "error": "state_unavailable" }),
        );
    };

    // Ref-check (like pool delete): refuse to remove a bundle a pool
    // still references, so the dashboard can't strand a pool's trust.
    if let Ok((_, blob, _)) = load_active_config_doc(services).await {
        let refs = pools_referencing_trust(&blob, bundle);
        if !refs.is_empty() {
            return json_response(
                409,
                &serde_json::json!({
                    "error": "bundle_in_use",
                    "message": format!("trust bundle '{bundle}' is referenced by upstream(s): {}", refs.join(", ")),
                    "pools": refs,
                }),
            );
        }
    }

    let pre = mutation_preamble(&req, "zt-upstream-trust-delete");
    let key = aegis_core::config::upstream_trust_state_key(bundle);
    let existed = state.get(&key).await.ok().flatten().is_some();
    let before = serde_json::json!({ "bundle": bundle, "configured": existed });
    let after = serde_json::json!({ "bundle": bundle, "configured": false });
    let resource = format!("/api/zero-trust/upstream/trust/{bundle}");
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "DELETE",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: "zero_trust_upstream_trust_removed",
        reason: "operator removed a backend-CA trust bundle",
    };

    let key_cl = key.clone();
    let outcome = services
        .mutate
        .apply_async(&req_ctx, before, after, move || async move {
            state
                .del(&key_cl)
                .await
                .map_err(|e| format!("config-plane delete: {e}"))
        })
        .await;

    match outcome {
        Ok(_) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "request_id": pre.request_id,
                "bundle": bundle,
                "removed": existed,
            }),
        ),
        Err(e) => mutation_error_response(e),
    }
}

/// GET /api/zero-trust/upstream/trust — list uploaded backend-CA
/// trust bundles with PUBLIC cert metadata (never key material; a CA
/// bundle has none). Async because it scans the config plane.
pub(crate) async fn handle_zt_upstream_trust_list(
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let Some(state) = services.state_backend.as_ref() else {
        return json_response(
            200,
            &serde_json::json!({ "bundles": [], "wired": false }),
        );
    };
    let prefix = aegis_core::config::UPSTREAM_TRUST_STATE_PREFIX;
    let keys = match state.scan_prefix(prefix).await {
        Ok(k) => k,
        Err(e) => {
            return json_response(
                503,
                &serde_json::json!({ "error": "state_unavailable", "message": e.to_string() }),
            )
        }
    };
    let mut bundles: Vec<serde_json::Value> = Vec::with_capacity(keys.len());
    for key in keys {
        let name = key.strip_prefix(prefix).unwrap_or(&key).to_string();
        let Ok(Some(bytes)) = state.get(&key).await else {
            continue;
        };
        let Ok(rec) =
            serde_json::from_slice::<aegis_core::config::UpstreamTrustRecord>(&bytes)
        else {
            bundles.push(serde_json::json!({ "name": name, "error": "corrupt record" }));
            continue;
        };
        match aegis_control::identity_tracker::parse_ca_bundle_bytes(rec.ca_pem.as_bytes()) {
            Ok(certs) => {
                bundles.push(serde_json::json!({ "name": name, "certificates": certs }))
            }
            Err(e) => bundles
                .push(serde_json::json!({ "name": name, "error": e.to_string() })),
        }
    }
    bundles.sort_by(|a, b| {
        a.get("name")
            .and_then(|v| v.as_str())
            .cmp(&b.get("name").and_then(|v| v.as_str()))
    });
    json_response(200, &serde_json::json!({ "bundles": bundles, "wired": true }))
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
    let outcome = services
        .mutate
        .apply::<_, (), aegis_control::api::mutation::MutationError>(
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
    let minutes = body.get("minutes").and_then(|v| v.as_u64()).unwrap_or(15);
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
    let outcome = services
        .mutate
        .apply::<_, (), aegis_control::api::mutation::MutationError>(
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
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                "failed to read request body".into(),
            ));
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");
    let parsed: aegis_control::api::logging::LoggingPutBody = match serde_json::from_str(body_str) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e.to_string()),
            );
        }
    };

    let before =
        serde_json::to_value(services.verbosity.snapshot()).unwrap_or(serde_json::Value::Null);
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
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                "failed to read request body".into(),
            ));
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

    let before =
        serde_json::to_value(services.load_gauge.snapshot()).unwrap_or(serde_json::Value::Null);
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
    let outcome = services
        .mutate
        .apply(&req_ctx, before, serde_json::Value::Null, || {
            aegis_control::api::load_mode::apply_put_body(&gauge, parsed)
        });

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
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                "failed to read request body".into(),
            ));
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
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            format!("config blob failed validation: {e}"),
        ));
    }

    let Some(backend) = services.state_backend.as_ref() else {
        return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
            "config plane unavailable: no state backend wired".into(),
        ));
    };
    let store = crate::config_source::config_store::ConfigStore::new(backend.clone())
        .with_nudge(services.config_nudge.clone());

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
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                "failed to read request body".into(),
            ));
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
        return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
            "config plane unavailable: no state backend wired".into(),
        ));
    };
    let store = crate::config_source::config_store::ConfigStore::new(backend.clone())
        .with_nudge(services.config_nudge.clone());

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

fn mutation_preamble(
    req: &hyper::Request<hyper::body::Incoming>,
    prefix: &str,
) -> MutationPreamble {
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
    MutationPreamble {
        csrf_cookie,
        csrf_header,
        actor,
        request_id,
    }
}

/// 2026-05-27 (Phase B rules fold) — get-or-create the
/// `cfg.rules.inline` sequence on a YAML config doc, erroring if
/// `rules`/`rules.inline` exist but have the wrong shape.
fn rules_inline_seq<'a>(
    map: &'a mut serde_yaml::Mapping,
) -> Result<&'a mut serde_yaml::Sequence, String> {
    let s = |x: &str| serde_yaml::Value::String(x.into());
    let rules = map
        .entry(s("rules"))
        .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
    let serde_yaml::Value::Mapping(rules_map) = rules else {
        return Err("`rules` config is not a mapping".into());
    };
    let inline = rules_map
        .entry(s("inline"))
        .or_insert_with(|| serde_yaml::Value::Sequence(serde_yaml::Sequence::new()));
    match inline {
        serde_yaml::Value::Sequence(seq) => Ok(seq),
        _ => Err("`rules.inline` config is not a sequence".into()),
    }
}

/// Build the `RuleDef` YAML shape (`{id, body, enabled}`).
fn rule_def_yaml(id: &str, body: &str, enabled: bool) -> serde_yaml::Value {
    let s = |x: &str| serde_yaml::Value::String(x.into());
    let mut m = serde_yaml::Mapping::new();
    m.insert(s("id"), s(id));
    m.insert(s("body"), s(body));
    m.insert(s("enabled"), serde_yaml::Value::Bool(enabled));
    serde_yaml::Value::Mapping(m)
}

/// Upsert one rule into `cfg.rules.inline` on a YAML config blob:
/// replace the entry with matching `id` in place, or append a new one.
/// Used by the folded `POST`/`PUT`/toggle rule handlers.
fn patch_rule_upsert(base: &str, id: &str, body: &str, enabled: bool) -> Result<String, String> {
    let mut doc: serde_yaml::Value =
        serde_yaml::from_str(base).map_err(|e| format!("base config not YAML: {e}"))?;
    let serde_yaml::Value::Mapping(map) = &mut doc else {
        return Err("base config is not a YAML mapping".into());
    };
    let seq = rules_inline_seq(map)?;
    let entry = rule_def_yaml(id, body, enabled);
    match seq
        .iter()
        .position(|v| v.get("id").and_then(|x| x.as_str()) == Some(id))
    {
        Some(idx) => seq[idx] = entry,
        None => seq.push(entry),
    }
    serde_yaml::to_string(&doc).map_err(|e| format!("re-serialize config: {e}"))
}

/// Remove the rule with `id` from `cfg.rules.inline` (idempotent — a
/// missing id is a no-op). Used by the folded `DELETE` rule handler.
fn patch_rule_remove(base: &str, id: &str) -> Result<String, String> {
    let mut doc: serde_yaml::Value =
        serde_yaml::from_str(base).map_err(|e| format!("base config not YAML: {e}"))?;
    let serde_yaml::Value::Mapping(map) = &mut doc else {
        return Err("base config is not a YAML mapping".into());
    };
    let seq = rules_inline_seq(map)?;
    seq.retain(|v| v.get("id").and_then(|x| x.as_str()) != Some(id));
    serde_yaml::to_string(&doc).map_err(|e| format!("re-serialize config: {e}"))
}

/// Get-or-create the top-level `routes:` YAML sequence. Unlike
/// `upstreams` (a mapping), routes are an ordered list — order is
/// load-bearing for first-match-wins resolution, so the patch helpers
/// operate on the sequence positionally.
fn routes_seq(
    map: &mut serde_yaml::Mapping,
) -> Result<&mut serde_yaml::Sequence, String> {
    let s = |x: &str| serde_yaml::Value::String(x.into());
    let routes = map
        .entry(s("routes"))
        .or_insert_with(|| serde_yaml::Value::Sequence(serde_yaml::Sequence::new()));
    match routes {
        serde_yaml::Value::Sequence(seq) => Ok(seq),
        _ => Err("`routes` config is not a sequence".into()),
    }
}

/// Upsert one route into the `routes:` sequence on a YAML config blob:
/// replace the entry with matching `id` **in place** (preserving its
/// position, so first-match-wins order is stable), or append a new one.
/// `route_json` is the operator-authored route value (a serialized
/// `RouteConfigPatch` with `id` forced) — `RouteConfig` is
/// `Deserialize`-only, so we route the authored JSON → YAML the same way
/// `patch_upstream_pool_set` does for pools.
/// Feeds the versioned config plane so route CRUD converges fleet-wide.
/// See BUG-console-route-mutation-not-fleet-convergent.md.
fn patch_routes_set(
    base: &str,
    id: &str,
    route_json: &serde_json::Value,
) -> Result<String, String> {
    let mut doc: serde_yaml::Value =
        serde_yaml::from_str(base).map_err(|e| format!("base config not YAML: {e}"))?;
    let serde_yaml::Value::Mapping(map) = &mut doc else {
        return Err("base config is not a YAML mapping".into());
    };
    let seq = routes_seq(map)?;
    let entry =
        serde_yaml::to_value(route_json).map_err(|e| format!("route not serialisable: {e}"))?;
    match seq
        .iter()
        .position(|v| v.get("id").and_then(|x| x.as_str()) == Some(id))
    {
        Some(idx) => seq[idx] = entry,
        None => seq.push(entry),
    }
    serde_yaml::to_string(&doc).map_err(|e| format!("re-serialize config: {e}"))
}

/// BUG-fix 2026-06-14 — build the config a route's upstream reference is
/// validated against. Overlays the **active config doc** upstreams
/// (authoritative — a pool write commits to the doc the instant it
/// activates) and this node's live pool shadow onto the boot cfg, so a
/// route pointing at a just-created pool validates without waiting for
/// per-node apply lag. Without the doc overlay, creating a pool inline
/// then immediately saving the route races the pool's per-node apply and
/// surfaces a spurious "pool not found".
/// See BUG-create-route-pool-not-found-race.md.
fn route_validation_cfg(
    boot: &aegis_core::config::WafConfig,
    doc: &aegis_core::config::WafConfig,
    shadow: &std::collections::HashMap<String, aegis_core::config::PoolConfig>,
) -> aegis_core::config::WafConfig {
    let mut cfg = boot.clone();
    // Doc first (authoritative + immediately consistent), then the
    // per-node shadow (covers anything applied locally but not yet
    // re-read into the doc snapshot we loaded).
    for (name, pool) in &doc.upstreams {
        cfg.upstreams.insert(name.clone(), pool.clone());
    }
    for (name, pool) in shadow {
        cfg.upstreams.insert(name.clone(), pool.clone());
    }
    cfg
}

/// Remove the route with `id` from the `routes:` sequence (idempotent —
/// a missing id is a no-op). Used by the folded `DELETE` route handler.
fn patch_route_remove(base: &str, id: &str) -> Result<String, String> {
    let mut doc: serde_yaml::Value =
        serde_yaml::from_str(base).map_err(|e| format!("base config not YAML: {e}"))?;
    let serde_yaml::Value::Mapping(map) = &mut doc else {
        return Err("base config is not a YAML mapping".into());
    };
    let seq = routes_seq(map)?;
    seq.retain(|v| v.get("id").and_then(|x| x.as_str()) != Some(id));
    serde_yaml::to_string(&doc).map_err(|e| format!("re-serialize config: {e}"))
}

/// 2026-05-27 (Phase B) — shared loader for the folded config-plane
/// CRUD handlers (rules + upstreams): return the active config doc's
/// `(ConfigStore, blob, version)`, seeding from the boot YAML file when
/// no doc has been activated yet. Handlers parse + patch the blob then
/// activate. Existence / reference checks run against this doc (the
/// source of truth), not the eventually-consistent local store.
async fn load_active_config_doc(
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Result<(crate::config_source::config_store::ConfigStore, String, u64), Response<Full<Bytes>>> {
    let Some(backend) = services.state_backend.as_ref() else {
        return Err(mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal(
                "config plane unavailable: no state backend wired".into(),
            ),
        ));
    };
    let store = crate::config_source::config_store::ConfigStore::new(backend.clone())
        .with_nudge(services.config_nudge.clone());
    match store.load().await {
        Ok(Some(doc)) => Ok((store, doc.blob, doc.version)),
        Ok(None) => match services.config_yaml_path.as_ref() {
            Some(path) => match std::fs::read_to_string(path) {
                Ok(s) => Ok((store, s, 0u64)),
                Err(e) => Err(mutation_error_response(
                    aegis_control::api::mutation::MutationError::Internal(format!(
                        "cannot read boot config {} to seed the config plane: {e}",
                        path.display()
                    )),
                )),
            },
            None => Err(mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(
                    "no shared config activated yet — publish a baseline via PUT /api/config first"
                        .into(),
                ),
            )),
        },
        Err(e) => Err(mutation_error_response(
            aegis_control::api::mutation::MutationError::Internal(format!(
                "config store read failed: {e}"
            )),
        )),
    }
}

/// Convert a `ValidateResponse` failure into the `MutationError` the
/// folded handlers surface (mirrors the old in-store upsert error).
fn rule_validation_error(
    v: &aegis_control::api::rules::ValidateResponse,
) -> aegis_control::api::mutation::MutationError {
    aegis_control::api::mutation::MutationError::Validation(
        v.errors
            .first()
            .map(|m| format!("line {}: {}", m.line, m.message))
            .unwrap_or_else(|| "rule body invalid".into()),
    )
}

pub(crate) async fn handle_rules_post(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "rules-post");
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                "body read failed".into(),
            ))
        }
    };
    let parsed: RulePostBody = match serde_json::from_slice(&body_bytes) {
        Ok(p) => p,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e.to_string()),
            )
        }
    };

    // Validate id + body up front — `load_config_str` on the patched
    // doc only checks the YAML shape, not the rule DSL, so an invalid
    // rule would otherwise activate and then be silently skipped by the
    // apply-side `replace_all`. Reject here so the operator gets a 400.
    let mut v = aegis_control::api::rules::validate_rule_body(&parsed.body);
    if let Some(id_err) = aegis_control::api::rules::validate_rule_id(&parsed.id) {
        v.errors.push(id_err);
        v.ok = false;
    }
    if !v.ok {
        return mutation_error_response(rule_validation_error(&v));
    }

    // 2026-05-27 (Phase B rules fold) — patch `cfg.rules.inline` on the
    // shared config doc + activate. The watcher re-derives the RuleStore
    // + engine ruleset on every node via `apply_cfg_change_to_rules`.
    let (store, base_blob, expected) = match load_active_config_doc(services).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    // Existence check against the doc (source of truth) so a
    // create-then-edit before the watcher polls behaves correctly.
    let doc_cfg = match aegis_core::load_config_str(&base_blob) {
        Ok(c) => c,
        Err(e) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                format!("active config doc failed to parse: {e}"),
            ))
        }
    };
    if doc_cfg.rules.inline.iter().any(|r| r.id == parsed.id) {
        return json_response(
            409,
            &serde_json::json!({"error": "rule_exists", "id": parsed.id}),
        );
    }

    let new_blob = match patch_rule_upsert(&base_blob, &parsed.id, &parsed.body, parsed.enabled) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e),
            )
        }
    };
    if let Err(e) = aegis_core::load_config_str(&new_blob) {
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            format!("patched config failed validation: {e}"),
        ));
    }

    let before = serde_json::json!({ "version": expected });
    let after = serde_json::json!({"id": parsed.id, "enabled": parsed.enabled});
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
    let store_for_apply = store.clone();
    let blob = new_blob;
    let actor = pre.actor.clone();
    let outcome = services
        .mutate
        .apply_async(&req_ctx, before, after, move || async move {
            store_for_apply
                .activate(expected, blob, &actor, "create rule")
                .await
        })
        .await;
    match outcome {
        Ok(mo) => match mo.value {
            crate::config_source::config_store::Activate::Applied { version } => json_response(
                201,
                &serde_json::json!({
                    "ok": true,
                    "id": parsed.id,
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

pub(crate) async fn handle_rules_put(
    req: hyper::Request<hyper::body::Incoming>,
    rule_id: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "rules-put");
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                "body read failed".into(),
            ))
        }
    };
    let parsed: RulePutBody = match serde_json::from_slice(&body_bytes) {
        Ok(p) => p,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e.to_string()),
            )
        }
    };

    let mut v = aegis_control::api::rules::validate_rule_body(&parsed.body);
    if let Some(id_err) = aegis_control::api::rules::validate_rule_id(rule_id) {
        v.errors.push(id_err);
        v.ok = false;
    }
    if !v.ok {
        return mutation_error_response(rule_validation_error(&v));
    }

    let (store, base_blob, expected) = match load_active_config_doc(services).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let doc_cfg = match aegis_core::load_config_str(&base_blob) {
        Ok(c) => c,
        Err(e) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                format!("active config doc failed to parse: {e}"),
            ))
        }
    };
    if !doc_cfg.rules.inline.iter().any(|r| r.id == rule_id) {
        return json_response(
            404,
            &serde_json::json!({"error": "rule_not_found", "id": rule_id}),
        );
    }

    let new_blob = match patch_rule_upsert(&base_blob, rule_id, &parsed.body, parsed.enabled) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e),
            )
        }
    };
    if let Err(e) = aegis_core::load_config_str(&new_blob) {
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            format!("patched config failed validation: {e}"),
        ));
    }

    let before = serde_json::json!({ "version": expected });
    let after = serde_json::json!({"id": rule_id, "enabled": parsed.enabled});
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
    let store_for_apply = store.clone();
    let blob = new_blob;
    let actor = pre.actor.clone();
    let outcome = services
        .mutate
        .apply_async(&req_ctx, before, after, move || async move {
            store_for_apply
                .activate(expected, blob, &actor, "update rule")
                .await
        })
        .await;
    match outcome {
        Ok(mo) => match mo.value {
            crate::config_source::config_store::Activate::Applied { version } => json_response(
                200,
                &serde_json::json!({
                    "ok": true,
                    "id": rule_id,
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

pub(crate) async fn handle_rules_delete(
    req: hyper::Request<hyper::body::Incoming>,
    rule_id: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let pre = mutation_preamble(&req, "rules-delete");

    let (store, base_blob, expected) = match load_active_config_doc(services).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let doc_cfg = match aegis_core::load_config_str(&base_blob) {
        Ok(c) => c,
        Err(e) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                format!("active config doc failed to parse: {e}"),
            ))
        }
    };
    if !doc_cfg.rules.inline.iter().any(|r| r.id == rule_id) {
        return json_response(
            404,
            &serde_json::json!({"error": "rule_not_found", "id": rule_id}),
        );
    }

    let new_blob = match patch_rule_remove(&base_blob, rule_id) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e),
            )
        }
    };
    if let Err(e) = aegis_core::load_config_str(&new_blob) {
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            format!("patched config failed validation: {e}"),
        ));
    }

    let before = serde_json::json!({ "version": expected });
    let after = serde_json::json!({"id": rule_id, "deleted": true});
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
    let store_for_apply = store.clone();
    let blob = new_blob;
    let actor = pre.actor.clone();
    let outcome = services
        .mutate
        .apply_async(&req_ctx, before, after, move || async move {
            store_for_apply
                .activate(expected, blob, &actor, "delete rule")
                .await
        })
        .await;
    match outcome {
        Ok(mo) => match mo.value {
            crate::config_source::config_store::Activate::Applied { version } => json_response(
                200,
                &serde_json::json!({
                    "ok": true,
                    "id": rule_id,
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

pub(crate) async fn handle_rules_toggle(
    req: hyper::Request<hyper::body::Incoming>,
    rule_id: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let pre = mutation_preamble(&req, "rules-toggle");

    let (store, base_blob, expected) = match load_active_config_doc(services).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let doc_cfg = match aegis_core::load_config_str(&base_blob) {
        Ok(c) => c,
        Err(e) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                format!("active config doc failed to parse: {e}"),
            ))
        }
    };
    // Read the current rule from the doc (source of truth) so the flip
    // is against the authoritative state, not the lagging local store.
    let Some(current) = doc_cfg.rules.inline.iter().find(|r| r.id == rule_id) else {
        return json_response(
            404,
            &serde_json::json!({"error": "rule_not_found", "id": rule_id}),
        );
    };
    let next_enabled = !current.enabled;

    let new_blob = match patch_rule_upsert(&base_blob, rule_id, &current.body, next_enabled) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e),
            )
        }
    };
    if let Err(e) = aegis_core::load_config_str(&new_blob) {
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            format!("patched config failed validation: {e}"),
        ));
    }

    let before = serde_json::json!({ "version": expected, "enabled": current.enabled });
    let after = serde_json::json!({"id": rule_id, "enabled": next_enabled});
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
    let store_for_apply = store.clone();
    let blob = new_blob;
    let actor = pre.actor.clone();
    let outcome = services
        .mutate
        .apply_async(&req_ctx, before, after, move || async move {
            store_for_apply
                .activate(expected, blob, &actor, "toggle rule")
                .await
        })
        .await;
    match outcome {
        Ok(mo) => match mo.value {
            crate::config_source::config_store::Activate::Applied { version } => json_response(
                200,
                &serde_json::json!({
                    "ok": true,
                    "id": rule_id,
                    "enabled": next_enabled,
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

pub(crate) async fn handle_risk_thresholds_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "risk-thresholds-put");
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                "body read failed".into(),
            ))
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");

    #[derive(serde::Deserialize)]
    struct Body {
        enabled: Option<bool>,
        challenge_at: Option<u32>,
        block_at: Option<u32>,
        max: Option<u32>,
    }
    let parsed: Body = match serde_json::from_str(if body_str.is_empty() { "{}" } else { body_str })
    {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e.to_string()),
            )
        }
    };

    let current = services.risk.thresholds();
    let next = aegis_core::config::RiskThresholds {
        // 2026-05-21 — cumulative-gate master toggle. Numeric
        // thresholds stay valid even when disabled (so re-enabling is
        // a one-flag change), so we keep the ordering checks below.
        enabled: parsed.enabled.unwrap_or(current.enabled),
        challenge_at: parsed.challenge_at.unwrap_or(current.challenge_at),
        block_at: parsed.block_at.unwrap_or(current.block_at),
        max: parsed.max.unwrap_or(current.max),
    };

    // Sanity: enforce ordering invariants the rule engine assumes.
    if next.challenge_at >= next.block_at {
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            format!(
                "challenge_at ({}) must be < block_at ({})",
                next.challenge_at, next.block_at
            ),
        ));
    }
    if next.block_at > next.max {
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            format!("block_at ({}) must be <= max ({})", next.block_at, next.max),
        ));
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
    let outcome = services
        .mutate
        .apply::<_, (), aegis_control::api::mutation::MutationError>(
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
        Err(_) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                "body read failed".into(),
            ))
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");

    #[derive(serde::Deserialize)]
    struct Body {
        paths: Vec<String>,
    }
    let parsed: Body = match serde_json::from_str(if body_str.is_empty() { "{}" } else { body_str })
    {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(format!(
                    "expected {{\"paths\": [\"/wp-admin\", ...]}}: {e}"
                )),
            )
        }
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
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            format!(
                "too many canary paths ({}); max is {MAX_CANARY_PATHS}",
                normalized.len()
            ),
        ));
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
    let outcome = services
        .mutate
        .apply::<_, (), aegis_control::api::mutation::MutationError>(
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
        Err(_) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                "body read failed".into(),
            ))
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");

    #[derive(serde::Deserialize)]
    struct Body {
        enabled: bool,
    }
    let parsed: Body = match serde_json::from_str(if body_str.is_empty() { "{}" } else { body_str })
    {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(format!(
                    "expected {{\"enabled\": true|false}}: {e}"
                )),
            )
        }
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
    let outcome = services
        .mutate
        .apply::<_, (), aegis_control::api::mutation::MutationError>(
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
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                "body read failed".into(),
            ));
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

/// 2026-05-27 (Phase B detectors fold) — get-or-create a child mapping
/// under `m[key]`, erroring if the key exists but isn't a mapping. Used
/// by [`patch_detectors`] to drill into the nested config blocks
/// (`detectors`, `detectors.per_tier`, the per-class entries).
fn yaml_child_map<'a>(
    m: &'a mut serde_yaml::Mapping,
    key: &str,
) -> Result<&'a mut serde_yaml::Mapping, String> {
    let entry = m
        .entry(serde_yaml::Value::String(key.into()))
        .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
    match entry {
        serde_yaml::Value::Mapping(mm) => Ok(mm),
        _ => Err(format!("`{key}` config is not a mapping")),
    }
}

/// Build the `TierDetectorMask` YAML shape (all 16 classes as explicit
/// bools) from a `DetectorMaskBody`. An all-`Some` mask losslessly
/// round-trips back to the full override the operator PUT when
/// `reload::apply_cfg_change_to_mask` re-derives it.
fn tier_override_yaml(mb: &aegis_security::detectors::DetectorMaskBody) -> serde_yaml::Value {
    let s = |x: &str| serde_yaml::Value::String(x.into());
    let mut entry = serde_yaml::Mapping::new();
    for (k, v) in [
        ("sqli", mb.sqli),
        ("xss", mb.xss),
        ("path_traversal", mb.path_traversal),
        ("ssrf", mb.ssrf),
        ("header_injection", mb.header_injection),
        ("body_abuse", mb.body_abuse),
        ("recon", mb.recon),
        ("brute_force", mb.brute_force),
        ("command_injection", mb.command_injection),
        ("template_injection", mb.template_injection),
        ("nosql_injection", mb.nosql_injection),
        ("open_redirect", mb.open_redirect),
        // 2026-06-12 (FIX-jwt-inspection-mask-toggle) — keep per-tier
        // JWT overrides in sync with the base-mask fix above.
        ("jwt_inspection", mb.jwt_inspection),
        ("cookie_injection", mb.cookie_injection),
        ("behavior_signals", mb.behavior_signals),
        ("velocity", mb.velocity),
        ("canary", mb.canary),
        ("ai", mb.ai),
    ] {
        entry.insert(s(k), serde_yaml::Value::Bool(v));
    }
    serde_yaml::Value::Mapping(entry)
}

/// Patch `cfg.detectors` (+ the sibling `cfg.ai.enabled`) on a YAML
/// config blob from a `DetectorsPutBody`, mirroring the live-mask
/// semantics of `apply_put_body`:
///
/// * `body.mask` present → write every base class to
///   `cfg.detectors.<class>.enabled`, **except** `ai` which routes to
///   the sibling `cfg.ai.enabled` block (AI config lives there, not in
///   `cfg.detectors`). Absent → leave the base untouched.
/// * `body.overrides[tier]` = `Some(mask)` → write
///   `cfg.detectors.per_tier.<tier>` as an all-`Some` `TierDetectorMask`;
///   `None` → remove that tier's entry. Unknown tier names are rejected.
///
/// The activated doc is re-derived on every node by
/// `reload::apply_cfg_change_to_mask`, so the fold is eventually
/// consistent across the fleet.
fn patch_detectors(
    base: &str,
    body: &aegis_control::api::detectors::DetectorsPutBody,
) -> Result<String, String> {
    use aegis_security::detectors::mask::DetectorClass;
    let mut doc: serde_yaml::Value =
        serde_yaml::from_str(base).map_err(|e| format!("base config not YAML: {e}"))?;
    let serde_yaml::Value::Mapping(map) = &mut doc else {
        return Err("base config is not a YAML mapping".into());
    };
    let s = |x: &str| serde_yaml::Value::String(x.into());

    if let Some(mask) = body.mask.as_ref() {
        // AI bit lives in the sibling `cfg.ai` block, not `cfg.detectors`.
        yaml_child_map(map, "ai")?.insert(s("enabled"), serde_yaml::Value::Bool(mask.ai));
        // The other 16 mask bits all map to a `.enabled` field under
        // `cfg.detectors` (14 `DetectorToggle` classes + `OpenRedirectConfig`
        // + `JwtInspectionConfig`, which also carry `.enabled`).
        let det = yaml_child_map(map, "detectors")?;
        for (class, enabled) in [
            (DetectorClass::Sqli, mask.sqli),
            (DetectorClass::Xss, mask.xss),
            (DetectorClass::PathTraversal, mask.path_traversal),
            (DetectorClass::Ssrf, mask.ssrf),
            (DetectorClass::HeaderInjection, mask.header_injection),
            (DetectorClass::BodyAbuse, mask.body_abuse),
            (DetectorClass::Recon, mask.recon),
            (DetectorClass::BruteForce, mask.brute_force),
            (DetectorClass::CommandInjection, mask.command_injection),
            (DetectorClass::TemplateInjection, mask.template_injection),
            (DetectorClass::NoSqlInjection, mask.nosql_injection),
            (DetectorClass::OpenRedirect, mask.open_redirect),
            // 2026-06-12 (FIX-jwt-inspection-mask-toggle) — was missing,
            // so the JWT toggle never persisted to cfg → couldn't disable.
            (DetectorClass::JwtInspection, mask.jwt_inspection),
            (DetectorClass::CookieInjection, mask.cookie_injection),
            (DetectorClass::BehaviorSignals, mask.behavior_signals),
            (DetectorClass::Velocity, mask.velocity),
            (DetectorClass::Canary, mask.canary),
        ] {
            yaml_child_map(det, class.as_str())?
                .insert(s("enabled"), serde_yaml::Value::Bool(enabled));
        }
    }

    if !body.overrides.is_empty() {
        let per_tier = {
            let det = yaml_child_map(map, "detectors")?;
            yaml_child_map(det, "per_tier")?
        };
        for (tier_raw, ov) in &body.overrides {
            let tier = aegis_control::api::detectors::parse_tier_str(tier_raw)
                .ok_or_else(|| format!("unknown tier: {tier_raw}"))?;
            let key = aegis_security::detectors::tier_str(tier);
            match ov {
                Some(mb) => {
                    per_tier.insert(s(key), tier_override_yaml(mb));
                }
                None => {
                    per_tier.remove(key);
                }
            }
        }
    }

    serde_yaml::to_string(&doc).map_err(|e| format!("re-serialize config: {e}"))
}

pub(crate) async fn handle_detectors_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "detectors-put");

    // F7 (2026-06-11 cluster QC) — optimistic-concurrency on the
    // detector mask. The dashboard echoes the `config_version` it last
    // read (GET /api/detectors) in `If-Match`; we use THAT as the CAS
    // `expected` so a write built on a stale view is rejected (412)
    // instead of silently clobbering a concurrent toggle. Absent
    // `If-Match` → legacy unconditional path (fresh server read) +
    // deprecation warn, so scripted callers that predate this don't
    // break. Parse before consuming the body.
    let if_match: Option<u64> = req
        .headers()
        .get(hyper::header::IF_MATCH)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.trim().trim_matches('"')) // tolerate a quoted ETag form
        .and_then(|s| s.parse::<u64>().ok());

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                "failed to read request body".into(),
            ))
        }
    };
    let body_str = match std::str::from_utf8(body_bytes.as_ref()) {
        Ok(s) => s,
        Err(_) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(
                    "request body is not valid UTF-8".into(),
                ),
            )
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

    // 2026-05-27 (Phase B detectors fold, option A — eventual). Route the
    // detector mask change through the cluster config plane instead of
    // flipping the local in-process `SharedDetectorMask`: patch the base
    // toggles + per-tier overrides onto the shared config document and
    // activate. Every node's watcher (incl. this one) re-derives the full
    // mask state via `apply_cfg_change_to_mask` on its next poll (~3s) —
    // the shared store is the single source of truth, so the change is
    // eventually-consistent across the fleet. This retires the per-node
    // local-snapshot model: per-tier overrides now live in the doc.
    let Some(backend) = services.state_backend.as_ref() else {
        return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
            "config plane unavailable: no state backend wired".into(),
        ));
    };
    let store = crate::config_source::config_store::ConfigStore::new(backend.clone())
        .with_nudge(services.config_nudge.clone());

    let (base_blob, current_version) = match store.load().await {
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
            None => return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(
                    "no shared config activated yet — publish a baseline via PUT /api/config first"
                        .into(),
                ),
            ),
        },
        Err(e) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                format!("config store read failed: {e}"),
            ))
        }
    };

    // F7: enforce the client's `If-Match` precondition up front so a
    // write built on a stale mask is rejected (412) BEFORE we patch /
    // validate / append an audit entry — never clobbering the
    // concurrent change the client hasn't seen. Absent `If-Match`
    // keeps the legacy unconditional behaviour (warn once) so older
    // scripted callers don't break.
    let expected = match if_match {
        Some(client_version) => {
            if client_version != current_version {
                return json_response(
                    412,
                    &serde_json::json!({
                        "ok": false,
                        "error": "version_conflict",
                        "current": current_version,
                        "request_id": pre.request_id,
                        "note": "detector mask changed since you loaded it; \
                                 re-fetch /api/detectors and retry",
                    }),
                );
            }
            client_version
        }
        None => {
            tracing::warn!(
                actor = %pre.actor,
                "PUT /api/detectors without If-Match: legacy unconditional write \
                 (no optimistic-concurrency guard) — update the client to echo config_version",
            );
            current_version
        }
    };

    let new_blob = match patch_detectors(&base_blob, &put_body) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e),
            )
        }
    };
    if let Err(e) = aegis_core::load_config_str(&new_blob) {
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            format!("patched config failed validation: {e}"),
        ));
    }

    let touched_tiers: Vec<&str> = put_body.overrides.keys().map(|k| k.as_str()).collect();
    let before = serde_json::json!({ "version": expected });
    let after = serde_json::json!({
        "base_changed": put_body.mask.is_some(),
        "tiers": touched_tiers,
    });
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: "/api/detectors",
        action: "detector_mask_set",
        reason: "operator updated detector mask",
    };

    let store_for_apply = store.clone();
    let blob = new_blob;
    let actor = pre.actor.clone();
    let outcome = services
        .mutate
        .apply_async(&req_ctx, before, after, move || async move {
            store_for_apply
                .activate(expected, blob, &actor, "update detector mask")
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
                    "note": "config activated; propagates to all nodes within a few seconds",
                    "request_id": pre.request_id,
                }),
            ),
            crate::config_source::config_store::Activate::Conflict { current } => {
                // A racing write landed between our load and the CAS.
                // With `If-Match` this is the same precondition failure
                // (412 — client re-fetches + retries); without it, keep
                // the legacy 409 for back-compat.
                let status = if if_match.is_some() { 412 } else { 409 };
                json_response(
                    status,
                    &serde_json::json!({
                        "ok": false,
                        "error": "version_conflict",
                        "current": current,
                        "request_id": pre.request_id,
                    }),
                )
            }
        },
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
        Some(sid) => services.auth_sessions.validate(sid).await.is_some(),
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
        Some(expected) if !expected.is_empty() => req
            .headers()
            .get("x-aegis-drain-token")
            .and_then(|h| h.to_str().ok())
            .map(|h| h == expected)
            .unwrap_or(false),
        _ => false,
    };
    if !session_ok && !no_admin_configured && !token_ok {
        return json_response(401, &serde_json::json!({"error": "auth_required"}));
    }

    let already = readiness.draining.swap(true, Ordering::Release);
    json_response(
        202,
        &serde_json::json!({
            "status": "draining",
            "already": already,
            "node": services
                .roster_view
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
) -> Option<(
    std::sync::Arc<aegis_control::api::blacklist::AccessListStore>,
    &'static str,
)> {
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
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            format!("unknown access list kind '{kind}'"),
        ));
    };

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                "body read failed".into(),
            ))
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");
    let parsed: aegis_control::api::blacklist::AccessListEntry =
        match serde_json::from_str(body_str) {
            Ok(e) => e,
            Err(e) => {
                return mutation_error_response(
                    aegis_control::api::mutation::MutationError::Validation(format!(
                        "invalid {label} entry: {e}"
                    )),
                );
            }
        };

    let before = serde_json::Value::Null;
    let after = serde_json::to_value(&parsed).unwrap_or(serde_json::Value::Null);
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
        Ok(o) => {
            // HIGH-2 (2026-06-13) — converge the entry fleet-wide. The
            // local store is already mutated (above); publish the
            // clamped entry to the shared config plane so the other
            // nodes' pollers adopt it. Best-effort + no-op on single-node
            // / in-memory deployments (no cluster_state wired).
            if let Some(rt) = services.interop.as_ref() {
                rt.control.publish_access_list_upsert(label, &o.value).await;
            }
            json_response(
                201,
                &serde_json::json!({
                    "ok": true,
                    "entry": o.value,
                    "request_id": pre.request_id,
                }),
            )
        }
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
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            format!("unknown access list kind '{kind}'"),
        ));
    };

    let existing = store.get(id);
    let Some(existing) = existing else {
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            format!("no {label} entry with id '{id}'"),
        ));
    };

    let before = serde_json::to_value(&existing).unwrap_or(serde_json::Value::Null);
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
    let outcome = services
        .mutate
        .apply::<_, (), aegis_control::api::mutation::MutationError>(
            &req_ctx,
            before,
            after,
            move || {
                store_for_apply.delete(&id_owned);
                Ok(())
            },
        );
    match outcome {
        Ok(_) => {
            // HIGH-2 (2026-06-13) — converge the removal fleet-wide so an
            // un-block on one node lifts on every node. Best-effort /
            // no-op on single-node deployments.
            if let Some(rt) = services.interop.as_ref() {
                rt.control.publish_access_list_remove(label, id).await;
            }
            json_response(
                200,
                &serde_json::json!({
                    "ok": true,
                    "removed": id,
                    "request_id": pre.request_id,
                }),
            )
        }
        Err(e) => mutation_error_response(e),
    }
}

// ---------------------------------------------------------------------------
// MTLS-T7 — Allowed SAN allowlist mutations
// ---------------------------------------------------------------------------

/// `PUT /api/zero-trust/downstream/sans` — whole-list replace of the
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
        return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
            "allowed-SANs store not wired".into(),
        ));
    };

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                "body read failed".into(),
            ))
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
        resource: "/api/zero-trust/downstream/sans",
        action: "zero_trust_sans_set",
        reason: "operator updated allowed SAN list",
    };

    let store_for_apply = store.clone();
    let next_for_apply = next.clone();
    let outcome = services
        .mutate
        .apply::<_, (), aegis_control::api::mutation::MutationError>(
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

/// `DELETE /api/zero-trust/downstream/sans/{san}` — remove a single entry.
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
        return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
            "allowed-SANs store not wired".into(),
        ));
    };

    let current = store.current();
    if !current.iter().any(|s| s == san) {
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            format!("no SAN entry '{san}'"),
        ));
    }
    let next: Vec<String> = current.iter().filter(|s| *s != san).cloned().collect();

    let before = serde_json::json!({"allowed": current.clone()});
    let after = serde_json::json!({"allowed": next.clone()});
    let resource = format!("/api/zero-trust/downstream/sans/{san}");
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "DELETE",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: &resource,
        action: "zero_trust_sans_removed",
        reason: "operator removed allowed SAN",
    };

    let store_for_apply = store.clone();
    let target = san.to_string();
    let outcome = services
        .mutate
        .apply::<_, (), aegis_control::api::mutation::MutationError>(
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

/// `POST /api/zero-trust/downstream/sans/{san}/test` — synthetic admit check.
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
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                "body read failed".into(),
            ))
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
        return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
            "config plane unavailable: no state backend wired".into(),
        ));
    };
    let store = crate::config_source::config_store::ConfigStore::new(backend.clone())
        .with_nudge(services.config_nudge.clone());

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
            None => return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(
                    "no shared config activated yet — publish a baseline via PUT /api/config first"
                        .into(),
                ),
            ),
        },
        Err(e) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                format!("config store read failed: {e}"),
            ))
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
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            format!("patched config failed validation: {e}"),
        ));
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
        // 2026-05-30 (QC R2-009 sub-C): the gate is
        // `services.ai_toggle == None`, which happens for **two**
        // reasons: (1) binary built without `--features ai`, OR
        // (2) feature present but `cfg.ai.model_path` is unset / the
        // ONNX file failed to load. The old wording only named (1)
        // and told the operator to flip `cfg.ai.enabled`, which is
        // misleading and wastes time on a working-feature binary.
        // The dashboard's row hint already names the right knobs;
        // mirror it here.
        let body = serde_json::json!({
            "ok": false,
            "reason": "feature_off",
            "message": "AI detector not in chain. Either: (1) rebuild with \
                        `--features ai`, OR (2) set `cfg.ai.model_path` to a \
                        valid ONNX file (e.g. `make ai-link MODEL=<path>`) and \
                        set `cfg.ai.enabled: true`.",
            "ai_feature_built": cfg!(feature = "ai"),
            "hint_check": "GET /api/ai/confidence -- feature_present field tells you which gate is closed",
        });
        return json_body_response(409, body.to_string(), "private, no-store");
    };

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                "body read failed".into(),
            ))
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
        return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
            "config plane unavailable: no state backend wired".into(),
        ));
    };
    let store = crate::config_source::config_store::ConfigStore::new(backend.clone())
        .with_nudge(services.config_nudge.clone());

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
            None => return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(
                    "no shared config activated yet — publish a baseline via PUT /api/config first"
                        .into(),
                ),
            ),
        },
        Err(e) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                format!("config store read failed: {e}"),
            ))
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
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            format!("patched config failed validation: {e}"),
        ));
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
        reason: if patch.enabled {
            "operator enabled AI detector"
        } else {
            "operator disabled AI detector"
        },
    };

    let store_for_apply = store.clone();
    let blob = new_blob;
    let actor = pre.actor.clone();
    let summary = if patch.enabled {
        "enable AI detector"
    } else {
        "disable AI detector"
    };
    let outcome = services
        .mutate
        .apply_async(&req_ctx, before, after, move || async move {
            store_for_apply
                .activate(expected, blob, &actor, summary)
                .await
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
// 2026-05-29 — runtime `confidence_threshold` for the AI detector
// ---------------------------------------------------------------------------
//
// Sibling of `handle_ai_enabled_put`: same config-plane fold (patch the
// shared YAML doc + activate so every node re-derives on its next poll
// or restart), plus a local in-process write to the shared `AtomicU32`
// so the active node's AiDetector picks up the new gate immediately —
// without waiting for the watcher round-trip. Validation rejects values
// outside [0.0, 1.0] (the model's `prob_attack` is a probability).

/// `GET /api/ai/reload` — is there a reloadable model, and from what path.
pub(crate) async fn handle_ai_reload_get(
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use aegis_control::api::ai_reload::AiReloadView;
    let view = match services.ai_reload.as_ref() {
        Some(w) => AiReloadView {
            feature_present: true,
            model_path: Some(w.model_path()),
        },
        None => AiReloadView {
            feature_present: false,
            model_path: None,
        },
    };
    json_body_response(
        200,
        serde_json::to_string(&view).unwrap_or_else(|_| "{}".into()),
        "private, no-store",
    )
}

/// `POST /api/ai/reload` — hot-reload the AI model from its configured on-disk
/// path. A **per-node, local** action: each node re-reads its own
/// `cfg.ai.model_path` and atomically swaps the new model into the live
/// detector. The data plane keeps serving on the old model until the new one is
/// fully loaded; a corrupt / half-written file is rejected and the running
/// model is kept. The ORT load is blocking, so it runs on a blocking thread.
pub(crate) async fn handle_ai_reload_post(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let pre = mutation_preamble(&req, "ai-reload");

    // Distinct from a wiring error: when no reloadable model exists (no `ai`
    // feature, batch mode, or `model_path` unset / failed to load at boot) the
    // dashboard renders a clear "unavailable" state, not a 500.
    let Some(writer) = services.ai_reload.clone() else {
        let body = serde_json::json!({
            "ok": false,
            "reason": "unavailable",
            "message": "No reloadable AI model. Needs a binary built with \
                        `--features ai`, `cfg.ai.model_path` set to a valid ONNX \
                        file, and the synchronous (non-batch) detector.",
            "ai_feature_built": cfg!(feature = "ai"),
        });
        return json_body_response(409, body.to_string(), "private, no-store");
    };

    let model_path = writer.model_path();
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "POST",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: "/api/ai/reload",
        action: "ai_model_reload",
        reason: "operator hot-reloaded the AI model",
    };
    let before = serde_json::json!({ "model_path": model_path });
    let after = serde_json::json!({ "model_path": model_path });

    let writer_for_task = writer.clone();
    let outcome = services
        .mutate
        .apply_async::<_, _, aegis_control::api::ai_reload::AiReloadReport, String>(
            &req_ctx,
            before,
            after,
            || async move {
                // ORT load is blocking — keep it off the async worker thread.
                let report = tokio::task::spawn_blocking(move || writer_for_task.reload())
                    .await
                    .map_err(|e| format!("reload task join error: {e}"))?;
                if report.ok {
                    Ok(report)
                } else {
                    // Surface the load failure; the running model is unchanged,
                    // and a failed mutation writes no audit-chain entry.
                    Err(report
                        .error
                        .clone()
                        .unwrap_or_else(|| "model load failed".into()))
                }
            },
        )
        .await;

    match outcome {
        Ok(mo) => {
            let report = mo.value;
            tracing::info!(
                model_path = %report.model_path,
                sessions = report.sessions.unwrap_or(0),
                load_ms = report.load_ms.unwrap_or(0),
                "AI model hot-reloaded via POST /api/ai/reload",
            );
            json_body_response(
                200,
                serde_json::to_string(&report).unwrap_or_else(|_| "{}".into()),
                "private, no-store",
            )
        }
        Err(e) => mutation_error_response(e),
    }
}

pub(crate) async fn handle_ai_confidence_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use aegis_control::api::ai_threshold::AiConfidencePatch;
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "ai-confidence-put");

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                "body read failed".into(),
            ))
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");
    let patch: AiConfidencePatch = match serde_json::from_str(body_str) {
        Ok(p) => p,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e.to_string()),
            )
        }
    };

    // Validate up front so we never persist (or surface) a nonsensical
    // gate. `confidence_threshold` is a probability — out-of-range or
    // non-finite values would silently misclassify every request.
    if !patch.confidence_threshold.is_finite()
        || patch.confidence_threshold < 0.0
        || patch.confidence_threshold > 1.0
    {
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            format!(
                "confidence_threshold must be a finite value in [0.0, 1.0]; got {}",
                patch.confidence_threshold
            ),
        ));
    }

    let Some(backend) = services.state_backend.as_ref() else {
        return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
            "config plane unavailable: no state backend wired".into(),
        ));
    };
    let store = crate::config_source::config_store::ConfigStore::new(backend.clone())
        .with_nudge(services.config_nudge.clone());

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
            None => return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(
                    "no shared config activated yet — publish a baseline via PUT /api/config first"
                        .into(),
                ),
            ),
        },
        Err(e) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                format!("config store read failed: {e}"),
            ))
        }
    };

    let new_blob = match patch_ai_confidence(&base_blob, patch.confidence_threshold) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e),
            )
        }
    };
    if let Err(e) = aegis_core::load_config_str(&new_blob) {
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            format!("patched config failed validation: {e}"),
        ));
    }

    let before = serde_json::json!({ "version": expected });
    let after = serde_json::json!({ "ai_confidence_threshold": patch.confidence_threshold });
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: pre.csrf_cookie.as_deref(),
        csrf_header: pre.csrf_header.as_deref(),
        actor: &pre.actor,
        request_id: &pre.request_id,
        resource: "/api/ai/confidence",
        action: "ai_confidence_put",
        reason: "operator adjusted AI confidence_threshold",
    };

    let store_for_apply = store.clone();
    let blob = new_blob;
    let actor = pre.actor.clone();
    let summary = "adjust AI confidence_threshold";
    let new_threshold = patch.confidence_threshold;
    let writer = services.ai_threshold.clone();
    let outcome = services
        .mutate
        .apply_async(&req_ctx, before, after, move || async move {
            let res = store_for_apply
                .activate(expected, blob, &actor, summary)
                .await;
            // On successful activation, update the local shared atomic so
            // this node's AiDetector reads the new gate immediately
            // instead of waiting for the watcher's next poll. Remote
            // nodes pick it up via the persisted config doc.
            if let Ok(crate::config_source::config_store::Activate::Applied { .. }) = &res {
                if let Some(w) = writer.as_ref() {
                    w.set(new_threshold);
                }
            }
            res
        })
        .await;

    match outcome {
        Ok(mo) => match mo.value {
            crate::config_source::config_store::Activate::Applied { version } => json_response(
                200,
                &serde_json::json!({
                    "ok": true,
                    "confidence_threshold": patch.confidence_threshold,
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

/// Patch `ai.confidence_threshold` on a YAML config blob — mirrors
/// `patch_ai_enabled`. Caller is expected to have already range-checked
/// the value; this just edits the YAML mapping.
fn patch_ai_confidence(base: &str, threshold: f32) -> Result<String, String> {
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
        serde_yaml::Value::String("confidence_threshold".into()),
        serde_yaml::Value::Number(serde_yaml::Number::from(threshold as f64)),
    );
    serde_yaml::to_string(&doc).map_err(|e| format!("re-serialize config: {e}"))
}

#[cfg(test)]
mod ai_confidence_patch_tests {
    use super::patch_ai_confidence;

    #[test]
    fn patches_existing_ai_block() {
        let base = "ai:\n  enabled: true\n  confidence_threshold: 0.85\n";
        let out = patch_ai_confidence(base, 0.50).unwrap();
        let parsed: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
        let v = &parsed["ai"]["confidence_threshold"];
        // serde_yaml round-trips f64; just check it's the right number.
        assert!((v.as_f64().unwrap() - 0.50).abs() < 1e-6);
        // Existing `enabled: true` survives the patch.
        assert_eq!(parsed["ai"]["enabled"].as_bool(), Some(true));
    }

    #[test]
    fn creates_ai_block_when_absent() {
        let base = "proxy:\n  bind: 127.0.0.1:8080\n";
        let out = patch_ai_confidence(base, 0.7).unwrap();
        let parsed: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
        assert!((parsed["ai"]["confidence_threshold"].as_f64().unwrap() - 0.7).abs() < 1e-6);
    }

    #[test]
    fn rejects_non_mapping_base() {
        let err = patch_ai_confidence("- not a map\n", 0.5).unwrap_err();
        assert!(err.contains("not a YAML mapping"), "got {err}");
    }
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
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                "body read failed".into(),
            ))
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
        return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
            "config plane unavailable: no state backend wired".into(),
        ));
    };
    let store = crate::config_source::config_store::ConfigStore::new(backend.clone())
        .with_nudge(services.config_nudge.clone());

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
            None => return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(
                    "no shared config activated yet — publish a baseline via PUT /api/config first"
                        .into(),
                ),
            ),
        },
        Err(e) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                format!("config store read failed: {e}"),
            ))
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
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            format!("patched config failed validation: {e}"),
        ));
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
        None => serde_json::json!({ "enabled": false,    "feature_present": false }),
    };
    json_response(200, &body)
}

/// `GET /api/ai/confidence` — the live `confidence_threshold` the data
/// plane is reading right now (from the shared `AtomicU32`), the
/// `default` loaded from `cfg.ai.confidence_threshold` at boot, and
/// whether the AI detector is actually in the chain. The dashboard
/// surfaces both numbers so operators see what config says and what
/// they've adjusted it to without re-parsing YAML on the frontend.
pub(crate) async fn handle_ai_confidence_get(
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let default = services.ai_threshold_default;
    let (current, feature_present) = match services.ai_threshold.as_ref() {
        Some(w) => (w.get(), true),
        // No writer wired → the cfg-loaded default is the only value
        // the dashboard can show. `feature_present: false` lets the UI
        // render a "feature off" banner instead of pretending the
        // input is live.
        None => (default, false),
    };
    let body = serde_json::json!({
        "confidence_threshold": current,
        "default": default,
        "feature_present": feature_present,
    });
    json_response(200, &body)
}

// ---------------------------------------------------------------------------
// RT-T3 — audit-mutated route CRUD
// ---------------------------------------------------------------------------

pub(crate) async fn handle_route_upsert(
    req: hyper::Request<hyper::body::Incoming>,
    route_id: &str,
    cfg: &aegis_core::config::WafConfig,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use aegis_control::api::routes_config::{validate_route, RouteConfigPatch};
    use http_body_util::BodyExt;

    let pre = mutation_preamble(&req, "route-upsert");

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                "body read failed".into(),
            ))
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

    // BUG-fix 2026-06-14 — route the mutation through the **versioned
    // config plane**, exactly like the pool / rule / tier handlers,
    // instead of a bare local `RouteWriter::apply`. The old local swap
    // only updated the originating node's `ArcSwap<CompiledRouteTable>`
    // and never wrote `config:waf:doc`, so peers had nothing to converge
    // to (version stuck) and the route was lost on restart. Patching the
    // shared doc + activating fires the config nudge; every node's
    // watcher re-derives the route table via `apply_cfg_change_to_routes`
    // and the change is durable + fleet-consistent.
    // See BUG-console-route-mutation-not-fleet-convergent.md.
    let (store, base_blob, expected) = match load_active_config_doc(services).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };

    // Validate the upstream reference against the **active config doc**
    // (overlaid with this node's live pool shadow), not the boot cfg
    // alone. A pool created inline ("+ Create new pool") activates into
    // the doc immediately, but the per-node pool shadow lags by the apply
    // window — validating against the doc removes the spurious "pool not
    // found" on the first route save. See BUG-create-route-pool-not-found-race.md.
    let doc_cfg = match aegis_core::load_config_str(&base_blob) {
        Ok(c) => c,
        Err(e) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                format!("active config doc invalid: {e}"),
            ))
        }
    };
    let shadow = services
        .upstream_writer
        .as_ref()
        .map(|w| w.current_pools())
        .unwrap_or_default();
    let effective_cfg = route_validation_cfg(cfg, &doc_cfg, &shadow);

    if let Err(e) = validate_route(&patch, &effective_cfg) {
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            e.to_string(),
        ));
    }

    // `RouteConfig` is `Deserialize`-only, so we serialize the validated
    // `RouteConfigPatch` (Serialize) and route the authored JSON → YAML
    // into the doc's `routes:` sequence. This carries the same
    // user-editable subset `into_route()` did (failure_mode / quota /
    // tcp_* are reset on upsert today — behaviour preserved), now with
    // `strip_prefix` round-tripping through the doc.
    let route_json = match serde_json::to_value(&patch) {
        Ok(v) => v,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Internal(e.to_string()),
            )
        }
    };

    let new_blob = match patch_routes_set(&base_blob, route_id, &route_json) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e),
            )
        }
    };
    let patched_cfg = match aegis_core::load_config_str(&new_blob) {
        Ok(c) => c,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(format!(
                    "patched config failed validation: {e}"
                )),
            )
        }
    };
    // `load_config_str` validates config structure but NOT the route
    // trie (the builder lives in the proxy crate). Run it here so a bad
    // route (regex compile failure, duplicate default in a host scope)
    // is a 400 at PUT time — preserving the feedback the old
    // `RouteWriter::apply` gave — instead of silently failing later on
    // each node's watcher apply.
    if let Err(e) = crate::route::RouteTable::build(&patched_cfg) {
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            format!("route table build failed: {e}"),
        ));
    }

    let before = serde_json::json!({ "version": expected });
    let after = serde_json::json!({ "route": route_id });
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
    let store_for_apply = store.clone();
    let blob = new_blob;
    let actor = pre.actor.clone();
    let route_id_owned = route_id.to_string();
    let outcome = services
        .mutate
        .apply_async(&req_ctx, before, after, move || async move {
            store_for_apply
                .activate(expected, blob, &actor, "upsert route")
                .await
        })
        .await;
    match outcome {
        Ok(mo) => match mo.value {
            crate::config_source::config_store::Activate::Applied { version } => json_response(
                200,
                &serde_json::json!({
                    "ok": true,
                    "route": route_id_owned,
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

pub(crate) async fn handle_route_delete(
    req: hyper::Request<hyper::body::Incoming>,
    route_id: &str,
    // The boot `cfg` is no longer consulted — existence + last-catch-all
    // guards run against the active config doc (the fleet source of truth).
    _cfg: &aegis_core::config::WafConfig,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use aegis_control::api::routes_config::is_only_catchall;

    let pre = mutation_preamble(&req, "route-delete");

    // BUG-fix 2026-06-14 — route deletes through the versioned config
    // plane (see `handle_route_upsert`). The existence + last-catch-all
    // guards run against the **active config doc** (the source of truth
    // the fleet converges to) rather than a per-node `RouteWriter`
    // shadow, so the decision is fleet-consistent.
    // See BUG-console-route-mutation-not-fleet-convergent.md.
    let (store, base_blob, expected) = match load_active_config_doc(services).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let doc_cfg = match aegis_core::load_config_str(&base_blob) {
        Ok(c) => c,
        Err(e) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                format!("active config doc invalid: {e}"),
            ))
        }
    };
    if !doc_cfg.routes.iter().any(|r| r.id == route_id) {
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            format!("no route with id '{route_id}'"),
        ));
    }

    // Refuse to remove the last catch-all — it would brick traffic on
    // every path the more-specific routes don't cover, and
    // `RouteTable::build` rejects the resulting config outright. 409
    // with a clear message so the dashboard can surface "you must add
    // another catch-all first" without round-tripping a build error.
    if is_only_catchall(&doc_cfg, route_id) {
        let body = serde_json::json!({
            "ok": false,
            "reason": "last_catchall",
            "message": format!(
                "route '{route_id}' is the only catch-all (path: '/' with no host) — add another catch-all before deleting"
            ),
        });
        return json_body_response(409, body.to_string(), "private, no-store");
    }

    let new_blob = match patch_route_remove(&base_blob, route_id) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e),
            )
        }
    };
    let patched_cfg = match aegis_core::load_config_str(&new_blob) {
        Ok(c) => c,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(format!(
                    "patched config failed validation: {e}"
                )),
            )
        }
    };
    if let Err(e) = crate::route::RouteTable::build(&patched_cfg) {
        return mutation_error_response(aegis_control::api::mutation::MutationError::Validation(
            format!("route table build failed: {e}"),
        ));
    }

    let before = serde_json::json!({ "version": expected });
    let after = serde_json::json!({ "removed": route_id });
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
    let store_for_apply = store.clone();
    let blob = new_blob;
    let actor = pre.actor.clone();
    let route_id_owned = route_id.to_string();
    let outcome = services
        .mutate
        .apply_async(&req_ctx, before, after, move || async move {
            store_for_apply
                .activate(expected, blob, &actor, "remove route")
                .await
        })
        .await;
    match outcome {
        Ok(mo) => match mo.value {
            crate::config_source::config_store::Activate::Applied { version } => json_response(
                200,
                &serde_json::json!({
                    "ok": true,
                    "removed": route_id_owned,
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
        return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
            "ddos runtime not wired by proxy boot (test bundle?)".into(),
        ));
    };
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                "body read failed".into(),
            ))
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
    let outcome = services
        .mutate
        .apply::<_, (), aegis_control::api::mutation::MutationError>(
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
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                "body read failed".into(),
            ))
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");
    let put_body: aegis_control::api::gates::RateLimitPutBody = match serde_json::from_str(body_str)
    {
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
    let outcome = services
        .mutate
        .apply::<_, (), aegis_control::api::mutation::MutationError>(
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
            return mutation_error_response(aegis_control::api::mutation::MutationError::Internal(
                "body read failed".into(),
            ))
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");
    let put_body: aegis_control::api::gates::StrikesPutBody = match serde_json::from_str(body_str) {
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
    let outcome = services
        .mutate
        .apply::<_, (), aegis_control::api::mutation::MutationError>(
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

    fn cfg_blob_with_pool_trust(trust: &str) -> String {
        format!(
            r#"
listeners:
  data: [{{ bind: "0.0.0.0:443" }}]
  admin: {{ bind: "127.0.0.1:9443" }}
routes:
  - {{ id: catch-all, path: "/", upstream: api }}
upstreams:
  api:
    members: [{{ addr: "127.0.0.1:8443" }}]
    connection: {{ tls: true }}
    upstream_mtls: {{ enabled: true, trust: {trust} }}
state: {{ backend: in_memory }}
zero_trust:
  upstream_identity:
    source: file
    cert_path: /x/c.pem
    key_ref: /x/c.key
"#
        )
    }

    #[test]
    fn pools_referencing_trust_finds_matching_pool() {
        let blob = cfg_blob_with_pool_trust("backend-ca");
        assert_eq!(pools_referencing_trust(&blob, "backend-ca"), vec!["api"]);
        // A different bundle name is not referenced.
        assert!(pools_referencing_trust(&blob, "other-ca").is_empty());
    }

    #[test]
    fn pools_referencing_trust_unparseable_blob_yields_no_refs() {
        assert!(pools_referencing_trust("not: [valid", "backend-ca").is_empty());
    }

    fn upstreams_with_trust(
        trust: &str,
    ) -> std::collections::HashMap<String, aegis_core::config::PoolConfig> {
        aegis_core::load_config_str(&cfg_blob_with_pool_trust(trust))
            .unwrap()
            .upstreams
    }

    #[tokio::test]
    async fn trust_bundle_xref_passes_when_bundle_uploaded() {
        use crate::state::in_memory::InMemoryBackend;
        let state: std::sync::Arc<dyn aegis_core::state::StateBackend> =
            std::sync::Arc::new(InMemoryBackend::new());
        state
            .cas_set(
                &aegis_core::config::upstream_trust_state_key("backend-ca"),
                None,
                &serde_json::to_vec(&aegis_core::config::UpstreamTrustRecord {
                    ca_pem: "x".into(),
                })
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let ups = upstreams_with_trust("backend-ca");
        assert!(validate_pool_trust_bundles(&ups, Some(&state)).await.is_ok());
    }

    #[tokio::test]
    async fn trust_bundle_xref_rejects_unuploaded_bundle() {
        use crate::state::in_memory::InMemoryBackend;
        let state: std::sync::Arc<dyn aegis_core::state::StateBackend> =
            std::sync::Arc::new(InMemoryBackend::new());
        let ups = upstreams_with_trust("backend-ca");
        let err = validate_pool_trust_bundles(&ups, Some(&state))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, aegis_control::api::mutation::MutationError::Validation(m)
                if m.contains("not an uploaded backend-CA bundle")),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn trust_bundle_xref_skips_file_path_trust() {
        use crate::state::in_memory::InMemoryBackend;
        // A path-style trust value is a file source — not state-checked.
        let state: std::sync::Arc<dyn aegis_core::state::StateBackend> =
            std::sync::Arc::new(InMemoryBackend::new());
        let ups = upstreams_with_trust("/etc/waf/backend-ca.pem");
        assert!(validate_pool_trust_bundles(&ups, Some(&state)).await.is_ok());
    }

    #[tokio::test]
    async fn trust_bundle_xref_noop_without_state_backend() {
        let ups = upstreams_with_trust("backend-ca");
        assert!(validate_pool_trust_bundles(&ups, None).await.is_ok());
    }

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
        assert_eq!(
            v["state"]["backend"],
            serde_yaml::Value::String("redis".into())
        );
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
        assert_eq!(
            v["response_filter"]["scrub_stack_traces"],
            serde_yaml::Value::Bool(false)
        );
        assert_eq!(
            v["response_filter"]["mask_internal_ips"],
            serde_yaml::Value::Bool(true)
        );
        assert_eq!(
            v["response_filter"]["redact_dlp"],
            serde_yaml::Value::Bool(false)
        );
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
        assert_eq!(
            v["tiers"]["high"]["challenges_enabled"].as_bool(),
            Some(true)
        );
        assert_eq!(
            v["tiers"]["high"]["cumulative_challenge_at"].as_u64(),
            Some(40)
        );
        assert!(v["tiers"]["high"]["cumulative_block_at"].is_null());
        assert_eq!(v["tiers"]["high"]["pipeline"][0].as_str(), Some("sqli"));
    }

    // ---- 2026-05-27 (Phase B detectors fold) — patch_detectors ----

    #[test]
    fn patch_detectors_writes_base_toggles_and_routes_ai_to_sibling_block() {
        use aegis_control::api::detectors::DetectorsPutBody;
        use aegis_security::detectors::{DetectorMask, DetectorMaskBody};
        let base = "listeners:\n  data:\n    - bind: \"127.0.0.1:8080\"\nai:\n  enabled: true\n";
        let mut mb = DetectorMaskBody::from(DetectorMask::all_enabled());
        mb.sqli = false; // disable sqli on the base
        mb.ai = false; // AI lives in the sibling cfg.ai block, not cfg.detectors
        let body = DetectorsPutBody {
            mask: Some(mb),
            overrides: Default::default(),
        };
        let out = patch_detectors(base, &body).unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
        assert_eq!(v["detectors"]["sqli"]["enabled"].as_bool(), Some(false));
        assert_eq!(v["detectors"]["xss"]["enabled"].as_bool(), Some(true));
        assert_eq!(
            v["ai"]["enabled"].as_bool(),
            Some(false),
            "the base mask `ai` bit routes to cfg.ai.enabled, not cfg.detectors.ai",
        );
        // open_redirect is an OpenRedirectConfig (has `.enabled`), so it
        // patches the same way as the DetectorToggle classes.
        assert_eq!(
            v["detectors"]["open_redirect"]["enabled"].as_bool(),
            Some(true)
        );
    }

    // Drift guard (FIX-jwt-inspection-mask-toggle, 2026-06-12): EVERY
    // DetectorClass must be folded into the config by `patch_detectors`,
    // or its dashboard toggle silently no-ops — the config keeps the old
    // value, so the rebuilt mask (`from_detectors_config`) keeps the bit
    // and the detector keeps running. `jwt_inspection` was the class that
    // slipped when it was added (Phase A2). This fails the build the next
    // time a class is added to `DetectorClass::ALL` but not to the
    // `patch_detectors` base-mask list.
    #[test]
    fn patch_detectors_writes_every_detector_class() {
        use aegis_control::api::detectors::DetectorsPutBody;
        use aegis_security::detectors::{DetectorClass, DetectorMask, DetectorMaskBody};
        let base = "listeners:\n  data:\n    - bind: \"127.0.0.1:8080\"\nai:\n  enabled: true\n";
        let mb = DetectorMaskBody::from(DetectorMask::none()); // every class off
        let body = DetectorsPutBody {
            mask: Some(mb),
            overrides: Default::default(),
        };
        let out = patch_detectors(base, &body).unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
        for c in DetectorClass::ALL {
            if c == DetectorClass::Ai {
                // AI routes to the sibling cfg.ai.enabled block.
                assert_eq!(
                    v["ai"]["enabled"].as_bool(),
                    Some(false),
                    "patch_detectors didn't route the ai bit to cfg.ai.enabled",
                );
                continue;
            }
            assert_eq!(
                v["detectors"][c.as_str()]["enabled"].as_bool(),
                Some(false),
                "patch_detectors didn't write detectors.{}.enabled — its toggle no-ops",
                c.as_str(),
            );
        }
    }

    #[test]
    fn patch_detectors_writes_per_tier_override() {
        use aegis_control::api::detectors::DetectorsPutBody;
        use aegis_security::detectors::{DetectorClass, DetectorMask, DetectorMaskBody};
        let base = "listeners:\n  data:\n    - bind: \"127.0.0.1:8080\"\n";
        let ov =
            DetectorMaskBody::from(DetectorMask::all_enabled().with(DetectorClass::Recon, false));
        let mut body = DetectorsPutBody::default();
        body.overrides.insert("medium".into(), Some(ov));
        let out = patch_detectors(base, &body).unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
        assert_eq!(
            v["detectors"]["per_tier"]["medium"]["recon"].as_bool(),
            Some(false),
        );
        assert_eq!(
            v["detectors"]["per_tier"]["medium"]["sqli"].as_bool(),
            Some(true),
        );
        // 2026-06-12 — jwt_inspection must be present in the per-tier
        // override too (the tier_override_yaml list was missing it).
        assert_eq!(
            v["detectors"]["per_tier"]["medium"]["jwt_inspection"].as_bool(),
            Some(true),
        );
    }

    #[test]
    fn patch_detectors_clears_per_tier_override_on_null() {
        use aegis_control::api::detectors::DetectorsPutBody;
        let base = "listeners:\n  data:\n    - bind: \"127.0.0.1:8080\"\ndetectors:\n  per_tier:\n    medium:\n      recon: false\n";
        let mut body = DetectorsPutBody::default();
        body.overrides.insert("medium".into(), None); // null clears
        let out = patch_detectors(base, &body).unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
        assert!(
            v["detectors"]["per_tier"].get("medium").is_none(),
            "null override removes the per_tier entry",
        );
    }

    #[test]
    fn patch_detectors_rejects_unknown_tier() {
        use aegis_control::api::detectors::DetectorsPutBody;
        let base = "listeners:\n  data:\n    - bind: \"127.0.0.1:8080\"\n";
        let mut body = DetectorsPutBody::default();
        body.overrides.insert("paranoid".into(), None);
        assert!(patch_detectors(base, &body).is_err());
    }

    #[test]
    fn patch_detectors_roundtrips_through_config_and_resolve() {
        use aegis_control::api::detectors::DetectorsPutBody;
        use aegis_core::tier::Tier;
        use aegis_security::detectors::{DetectorClass, DetectorMask, DetectorMaskBody, MaskState};
        // A complete, valid config so load_config_str accepts it.
        let base = r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: catch-all
    path: "/"
    upstream: default
upstreams:
  default:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
"#;
        let ov = DetectorMaskBody::from(
            DetectorMask::all_enabled().with(DetectorClass::CommandInjection, false),
        );
        let mut body = DetectorsPutBody::default();
        body.overrides.insert("critical".into(), Some(ov));
        let out = patch_detectors(base, &body).unwrap();

        // The patched blob validates (per_tier shape obeys deny_unknown_fields).
        let cfg = aegis_core::load_config_str(&out).expect("patched config validates");
        // And the apply-side re-derive reproduces the override.
        let state = MaskState::from_detectors_config(&cfg.detectors, cfg.ai.enabled);
        let crit = state.resolve(Some(Tier::Critical));
        assert!(
            !crit.is_enabled(DetectorClass::CommandInjection),
            "per_tier override survives patch → load → re-derive",
        );
    }

    // ---- 2026-05-27 (Phase B rules fold) — patch_rule_* helpers ----

    #[test]
    fn patch_rule_upsert_appends_then_replaces_in_place() {
        let base = "listeners:\n  data:\n    - bind: \"127.0.0.1:8080\"\n";
        let out = patch_rule_upsert(base, "r1", "rule r1 { allow }", true).unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
        assert_eq!(v["rules"]["inline"][0]["id"].as_str(), Some("r1"));
        assert_eq!(
            v["rules"]["inline"][0]["body"].as_str(),
            Some("rule r1 { allow }")
        );
        assert_eq!(v["rules"]["inline"][0]["enabled"].as_bool(), Some(true));

        // Upserting the same id replaces in place (no duplicate).
        let out2 = patch_rule_upsert(&out, "r1", "rule r1 { block }", false).unwrap();
        let v2: serde_yaml::Value = serde_yaml::from_str(&out2).unwrap();
        assert_eq!(v2["rules"]["inline"].as_sequence().unwrap().len(), 1);
        assert_eq!(
            v2["rules"]["inline"][0]["body"].as_str(),
            Some("rule r1 { block }")
        );
        assert_eq!(v2["rules"]["inline"][0]["enabled"].as_bool(), Some(false));
    }

    #[test]
    fn patch_rule_remove_drops_only_the_named_entry() {
        let base = "listeners:\n  data:\n    - bind: \"127.0.0.1:8080\"\nrules:\n  inline:\n    - id: r1\n      body: \"rule r1 { allow }\"\n      enabled: true\n    - id: r2\n      body: \"rule r2 { allow }\"\n      enabled: true\n";
        let out = patch_rule_remove(base, "r1").unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
        let seq = v["rules"]["inline"].as_sequence().unwrap();
        assert_eq!(seq.len(), 1);
        assert_eq!(seq[0]["id"].as_str(), Some("r2"));
    }

    // ---- 2026-05-27 (Phase B upstreams fold) — patch_upstream* helpers ----

    #[test]
    fn patch_upstreams_replace_sets_whole_map() {
        let base = "listeners:\n  data:\n    - bind: \"127.0.0.1:8080\"\nupstreams:\n  old:\n    members:\n      - addr: \"127.0.0.1:1111\"\n";
        let pools: serde_json::Value = serde_json::json!({
            "default": { "members": [ { "addr": "127.0.0.1:3000" } ] }
        });
        let out = patch_upstreams_replace(base, &pools).unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
        assert!(v["upstreams"].get("old").is_none(), "whole map replaced");
        assert_eq!(
            v["upstreams"]["default"]["members"][0]["addr"].as_str(),
            Some("127.0.0.1:3000"),
        );
    }

    #[test]
    fn patch_upstream_pool_set_then_remove() {
        let base = "listeners:\n  data:\n    - bind: \"127.0.0.1:8080\"\nupstreams:\n  a:\n    members:\n      - addr: \"127.0.0.1:1111\"\n";
        let pool: serde_json::Value =
            serde_json::json!({ "members": [ { "addr": "127.0.0.1:2222" } ] });
        let out = patch_upstream_pool_set(base, "b", &pool).unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
        assert_eq!(
            v["upstreams"]["a"]["members"][0]["addr"].as_str(),
            Some("127.0.0.1:1111"),
            "existing pool kept",
        );
        assert_eq!(
            v["upstreams"]["b"]["members"][0]["addr"].as_str(),
            Some("127.0.0.1:2222"),
            "new pool added",
        );

        let out2 = patch_upstream_pool_remove(&out, "a").unwrap();
        let v2: serde_yaml::Value = serde_yaml::from_str(&out2).unwrap();
        assert!(v2["upstreams"].get("a").is_none(), "removed");
        assert!(v2["upstreams"].get("b").is_some(), "other pool kept");
    }

    #[test]
    fn patch_routes_set_replaces_in_place_then_appends() {
        // routes is a YAML *sequence* (unlike upstreams which is a
        // mapping). Upsert must replace the entry with a matching `id`
        // in place (preserving first-match-wins order) and append new
        // ids. See BUG-console-route-mutation-not-fleet-convergent.md.
        let base = concat!(
            "listeners:\n  data:\n    - bind: \"127.0.0.1:8080\"\n",
            "routes:\n",
            "  - { id: catch-all, path: \"/\", match_type: prefix, upstream: api-pool }\n",
            "upstreams:\n  api-pool:\n    members:\n      - addr: \"127.0.0.1:1111\"\n",
        );
        let route: serde_json::Value = serde_json::json!({
            "id": "sec",
            "path": "/sec",
            "match_type": "prefix",
            "upstream": "api-pool",
            "strip_prefix": false,
        });

        // Append: a new id lands at the end of the sequence.
        let out = patch_routes_set(base, "sec", &route).unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
        let seq = v["routes"].as_sequence().unwrap();
        assert_eq!(seq.len(), 2, "new route appended");
        assert_eq!(seq[0]["id"].as_str(), Some("catch-all"), "order preserved");
        assert_eq!(seq[1]["id"].as_str(), Some("sec"));
        assert_eq!(seq[1]["strip_prefix"].as_bool(), Some(false));

        // Replace-in-place: re-upserting the same id keeps its position.
        let route2: serde_json::Value = serde_json::json!({
            "id": "sec",
            "path": "/sec",
            "match_type": "prefix",
            "upstream": "api-pool",
            "strip_prefix": true,
        });
        let out2 = patch_routes_set(&out, "sec", &route2).unwrap();
        let v2: serde_yaml::Value = serde_yaml::from_str(&out2).unwrap();
        let seq2 = v2["routes"].as_sequence().unwrap();
        assert_eq!(seq2.len(), 2, "replace in place, no duplicate");
        assert_eq!(seq2[1]["id"].as_str(), Some("sec"));
        assert_eq!(seq2[1]["strip_prefix"].as_bool(), Some(true), "value updated");
    }

    #[test]
    fn route_validation_cfg_resolves_doc_only_pool() {
        // The operator created `sec-pool` inline: it has activated into
        // the config doc, but this node's per-pool shadow hasn't caught
        // up yet (empty). A route pointing at it must validate against
        // the doc overlay, not race the per-node apply.
        // See BUG-create-route-pool-not-found-race.md.
        use aegis_control::api::routes_config::{validate_route, RouteConfigPatch};

        let boot_yaml = concat!(
            "listeners:\n  data:\n    - bind: \"127.0.0.1:8080\"\n  admin: { bind: \"127.0.0.1:9090\" }\n",
            "routes:\n  - { id: catch-all, path: \"/\", match_type: prefix, upstream: api-pool }\n",
            "upstreams:\n  api-pool: { members: [{ addr: \"127.0.0.1:1111\" }] }\n",
            "state: { backend: in_memory }\n",
        );
        // Doc = boot + the freshly-created pool the operator just saved.
        let doc_yaml = concat!(
            "listeners:\n  data:\n    - bind: \"127.0.0.1:8080\"\n  admin: { bind: \"127.0.0.1:9090\" }\n",
            "routes:\n  - { id: catch-all, path: \"/\", match_type: prefix, upstream: api-pool }\n",
            "upstreams:\n",
            "  api-pool: { members: [{ addr: \"127.0.0.1:1111\" }] }\n",
            "  sec-pool: { members: [{ addr: \"127.0.0.1:2222\" }] }\n",
            "state: { backend: in_memory }\n",
        );
        let boot = aegis_core::load_config_str(boot_yaml).unwrap();
        let doc = aegis_core::load_config_str(doc_yaml).unwrap();
        let shadow = std::collections::HashMap::new();

        let merged = route_validation_cfg(&boot, &doc, &shadow);
        assert!(
            merged.upstreams.contains_key("sec-pool"),
            "doc-only pool must be overlaid for validation",
        );

        let patch = RouteConfigPatch {
            id: "sec".into(),
            host: None,
            path: "/sec".into(),
            match_type: "prefix".into(),
            strip_prefix: true,
            methods: None,
            upstream: "sec-pool".into(),
            tier_override: None,
            default: false,
            enabled: true,
            ws_inspect: None,
        };
        assert!(
            validate_route(&patch, &merged).is_ok(),
            "route at a doc-committed pool must validate (no race)",
        );
        // Regression guard: against the boot cfg alone it would 'not found'.
        assert!(
            validate_route(&patch, &boot).is_err(),
            "boot cfg lacks the new pool — proves the overlay is what fixes it",
        );
    }

    #[test]
    fn patch_route_remove_drops_only_the_named_route() {
        let base = concat!(
            "listeners:\n  data:\n    - bind: \"127.0.0.1:8080\"\n",
            "routes:\n",
            "  - { id: catch-all, path: \"/\", match_type: prefix, upstream: api-pool }\n",
            "  - { id: sec, path: \"/sec\", match_type: prefix, upstream: api-pool }\n",
            "upstreams:\n  api-pool:\n    members:\n      - addr: \"127.0.0.1:1111\"\n",
        );
        let out = patch_route_remove(base, "sec").unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
        let seq = v["routes"].as_sequence().unwrap();
        assert_eq!(seq.len(), 1, "only the named route removed");
        assert_eq!(seq[0]["id"].as_str(), Some("catch-all"));

        // Idempotent: removing a missing id is a no-op, not an error.
        let out2 = patch_route_remove(&out, "ghost").unwrap();
        let v2: serde_yaml::Value = serde_yaml::from_str(&out2).unwrap();
        assert_eq!(v2["routes"].as_sequence().unwrap().len(), 1);
    }

    /// Bug-fix regression — console route CRUD must converge across the
    /// fleet via the versioned config plane, not stay local to the
    /// mutating node. Two nodes share one config doc (simulating shared
    /// Redis): a route activated by node A's mutation path must
    /// (1) appear in node B's live route trie within the convergence SLA,
    /// (2) bump the shared doc version, and (3) survive a node-A
    /// "restart" (rebuild from the doc, not the boot YAML).
    /// See BUG-console-route-mutation-not-fleet-convergent.md.
    #[tokio::test]
    async fn console_route_upsert_converges_across_two_nodes() {
        use crate::config_source::config_store::{Activate, ConfigStore};
        use crate::config_source::redis_source::{spawn_watcher, ApplyTargets};
        use crate::state::in_memory::InMemoryBackend;
        use aegis_core::audit::AuditBus;
        use arc_swap::ArcSwap;
        use std::sync::Arc;
        use std::time::Duration;

        // Boot config: catch-all only, no `/sec` route. Two pools exist
        // so the new route has a valid upstream.
        let boot_yaml = concat!(
            "listeners:\n  data:\n    - bind: \"127.0.0.1:8080\"\n  admin: { bind: \"127.0.0.1:9090\" }\n",
            "routes:\n  - { id: catch-all, path: \"/\", match_type: prefix, upstream: api-pool }\n",
            "upstreams:\n",
            "  api-pool: { members: [{ addr: \"127.0.0.1:1111\" }] }\n",
            "  sec-pool: { members: [{ addr: \"127.0.0.1:2222\" }] }\n",
            "state: { backend: in_memory }\n",
        );
        let boot_cfg = aegis_core::load_config_str(boot_yaml).unwrap();

        // One shared backend = one shared config doc across both nodes.
        let backend: Arc<InMemoryBackend> = Arc::new(InMemoryBackend::new());
        let store_a =
            ConfigStore::new(backend.clone() as Arc<dyn aegis_core::state::StateBackend>);

        // Node B: a live ProxyContext + a config-plane watcher polling
        // fast, exactly as `run.rs` wires it (proxy_ctx carries the route
        // table the watcher rebuilds).
        let ctx_b = Arc::new(
            crate::proxy::ProxyContext::build(
                &boot_cfg,
                Arc::new(aegis_security::NoopPipeline),
            )
            .unwrap(),
        );
        let cfg_b = Arc::new(ArcSwap::from_pointee(boot_cfg.clone()));
        let targets_b = ApplyTargets {
            detector_mask: None,
            proxy_ctx: Some(ctx_b.clone()),
            ip_rate_limiter: None,
            tls_resolver: None,
            ai_toggle: None,
            ai_threshold: None,
            response_filter_writer: None,
            tiers: None,
            rules: None,
            active_ruleset: None,
            upstream_writer: None,
            receiver_writer: None,
        };
        let store_b =
            ConfigStore::new(backend.clone() as Arc<dyn aegis_core::state::StateBackend>);
        let handle = spawn_watcher(
            store_b,
            "waf-2".to_string(),
            cfg_b.clone(),
            AuditBus::new(64),
            targets_b,
            Duration::from_millis(50),
            None,
        );

        // Before convergence: node B falls through to catch-all on /sec.
        let before = ctx_b
            .route_table
            .resolve("any", "/sec", &http::Method::GET)
            .unwrap();
        assert_eq!(
            before.route_id, "catch-all",
            "node B must not have the route before the mutation",
        );

        // Node A's console mutation path: patch the doc's routes sequence
        // and activate — exactly what `handle_route_upsert` does, minus
        // the HTTP/services layer.
        let route_json = serde_json::json!({
            "id": "sec",
            "path": "/sec",
            "match_type": "prefix",
            "upstream": "sec-pool",
            "strip_prefix": false,
        });
        let new_blob = patch_routes_set(boot_yaml, "sec", &route_json).unwrap();
        let activated = store_a
            .activate(0, new_blob, "operator", "upsert route")
            .await
            .unwrap();
        assert_eq!(
            activated,
            Activate::Applied { version: 1 },
            "the mutation must bump the shared doc version",
        );

        // (1) Node B converges within the SLA via its own watcher.
        let mut converged = false;
        for _ in 0..60 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if let Some(m) = ctx_b
                .route_table
                .resolve("any", "/sec", &http::Method::GET)
            {
                if m.route_id == "sec" {
                    converged = true;
                    break;
                }
            }
        }
        assert!(
            converged,
            "node B must serve the console-added route after convergence \
             (this is the fleet-convergence guarantee the bug broke)",
        );
        handle.abort();

        // (2) + (3) Restart durability: a fresh node built from the
        // ACTIVATED DOC (not the boot YAML, which lacks /sec) resolves
        // the route — proving it's durable, not a transient local swap.
        let store_c =
            ConfigStore::new(backend.clone() as Arc<dyn aegis_core::state::StateBackend>);
        let doc = store_c
            .load()
            .await
            .unwrap()
            .expect("activated config doc must be present");
        assert_eq!(doc.version, 1, "shared doc carries the bumped version");
        let restarted_cfg = aegis_core::load_config_str(&doc.blob).unwrap();
        let restarted_table = crate::route::RouteTable::build(&restarted_cfg).unwrap();
        let r = restarted_table
            .resolve("any", "/sec", &http::Method::GET)
            .unwrap();
        assert_eq!(
            r.route_id, "sec",
            "route survives restart because it lives in the config doc",
        );
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
