//! Audit-mutation pipeline (P1 of the security-toggle plan).
//!
//! All in-memory store writes (rules, tiers, blacklist, admin
//! policy, future security toggles) flow through one wrapper that
//!
//! 1. validates CSRF on mutating methods,
//! 2. runs the mutator closure,
//! 3. on success only — appends an [`AdminChangeEntry`] to the
//!    SHA-256 hash chain and emits the equivalent [`AuditEvent`]
//!    on the [`AuditBus`] so live-feed subscribers and SIEM sinks
//!    pick it up like any detection event.
//!
//! Failure modes
//! -------------
//! - CSRF rejection → no mutator call, no chain entry, no bus emit.
//! - Validation rejection (mutator returns `Err`) → no chain entry,
//!   no bus emit. The whole point of the wrapper is that the chain
//!   only ever contains *applied* state changes.
//!
//! [`AdminChangeEntry`]: crate::audit::AdminChangeEntry


use std::sync::{Arc, Mutex};

use aegis_core::audit::AuditEvent;
use aegis_core::AuditBus;
use serde::Serialize;

use crate::admin_auth::csrf::{requires_csrf, validate as csrf_validate, CsrfResult};
use crate::audit::chain::{ChainEntry, ChainWriter};
use crate::audit::AdminChangeEntry;

/// Why a mutation was rejected. Maps cleanly onto an HTTP status +
/// machine-readable `reason` code so handlers can render a uniform
/// error envelope without knowing the underlying details.
#[derive(Debug, Clone)]
pub enum MutationError {
    CsrfMissingCookie,
    CsrfMissingHeader,
    CsrfMismatch,
    Validation(String),
    Conflict(String),
    Internal(String),
}

impl MutationError {
    pub fn http_status(&self) -> u16 {
        match self {
            Self::CsrfMissingCookie | Self::CsrfMissingHeader | Self::CsrfMismatch => 403,
            Self::Validation(_) => 400,
            Self::Conflict(_) => 409,
            Self::Internal(_) => 500,
        }
    }

    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::CsrfMissingCookie => "csrf_missing_cookie",
            Self::CsrfMissingHeader => "csrf_missing_header",
            Self::CsrfMismatch => "csrf_mismatch",
            Self::Validation(_) => "validation",
            Self::Conflict(_) => "conflict",
            Self::Internal(_) => "internal",
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::CsrfMissingCookie => "missing aegis_csrf cookie",
            Self::CsrfMissingHeader => "missing X-CSRF-Token header",
            Self::CsrfMismatch => "csrf header does not match cookie",
            Self::Validation(m) | Self::Conflict(m) | Self::Internal(m) => m.as_str(),
        }
    }

    /// Render the standard JSON error body the dashboard expects.
    pub fn to_body(&self) -> String {
        let body = serde_json::json!({
            "ok": false,
            "reason": self.reason_code(),
            "message": self.message(),
        });
        serde_json::to_string(&body).unwrap_or_else(|_| String::from("{}"))
    }
}

impl std::fmt::Display for MutationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.reason_code(), self.message())
    }
}

impl std::error::Error for MutationError {}

/// Inputs the wrapper needs from the surrounding HTTP context. The
/// proxy admin listener fills these in once it has authenticated the
/// caller — the wrapper itself is transport-agnostic.
#[derive(Debug, Clone)]
pub struct MutationRequest<'a> {
    pub method: &'a str,
    pub csrf_cookie: Option<&'a str>,
    pub csrf_header: Option<&'a str>,
    pub actor: &'a str,
    pub request_id: &'a str,
    pub resource: &'a str,
    pub action: &'a str,
    pub reason: &'a str,
}

/// Outcome bundle: the mutator's return value plus the chain entry
/// it produced. Handlers that want to surface the new chain head in
/// the response body (e.g. for optimistic concurrency tokens) read
/// `chain_entry.hash`.
#[derive(Debug, Clone, Serialize)]
pub struct MutationOutcome<T> {
    pub value: T,
    pub chain_entry: ChainEntry,
}

/// Shared, thread-safe wrapper around a single [`ChainWriter`] plus
/// the audit bus. Cheap to clone — internals are `Arc`-shared.
#[derive(Clone)]
pub struct AuditedMutate {
    chain: Arc<Mutex<ChainWriter>>,
    bus: AuditBus,
}

impl AuditedMutate {
    pub fn new(bus: AuditBus) -> Self {
        Self {
            chain: Arc::new(Mutex::new(ChainWriter::new())),
            bus,
        }
    }

    pub fn with_chain(chain: Arc<Mutex<ChainWriter>>, bus: AuditBus) -> Self {
        Self { chain, bus }
    }

    /// Expose the underlying chain so SIEM sinks can read entries
    /// without going through the wrapper.
    pub fn chain(&self) -> Arc<Mutex<ChainWriter>> {
        Arc::clone(&self.chain)
    }

    /// Snapshot the current chain head. Convenience for tests.
    pub fn head_hash(&self) -> String {
        let writer = self.chain.lock().expect("audit chain poisoned");
        writer.head_hash().to_string()
    }

    /// Snapshot the chain length.
    pub fn chain_len(&self) -> usize {
        let writer = self.chain.lock().expect("audit chain poisoned");
        writer.len()
    }

    /// Apply a mutation under CSRF + audit-chain protection.
    ///
    /// The closure is invoked **after** CSRF passes and **only once**.
    /// If it returns `Err`, the wrapper translates the error into
    /// `MutationError::Validation` and skips the audit chain entirely
    /// — invariant: every chain entry corresponds to a state change
    /// that actually happened.
    ///
    /// OTEL-T3 — root admin-mutation span. Every audit-mutated
    /// PUT / DELETE / POST handler nests its work under one span
    /// in Jaeger labelled by resource + action so operators can
    /// follow a config change from API call → chain entry → bus
    /// emit. Closure body executes inside the span so any
    /// `tracing::warn!` / `info!` from validators or post-apply
    /// hooks land on this span.
    #[tracing::instrument(
        name = "audit.mutate.apply",
        skip(self, before, after, mutator),
        fields(
            otel.kind = "internal",
            method = req.method,
            resource = req.resource,
            action = req.action,
            actor = req.actor,
            request_id = req.request_id,
            outcome = tracing::field::Empty,
        ),
    )]
    pub fn apply<F, T, E>(
        &self,
        req: &MutationRequest<'_>,
        before: serde_json::Value,
        after: serde_json::Value,
        mutator: F,
    ) -> Result<MutationOutcome<T>, MutationError>
    where
        F: FnOnce() -> Result<T, E>,
        E: std::fmt::Display,
    {
        if requires_csrf(req.method) {
            match csrf_validate(req.csrf_cookie, req.csrf_header) {
                CsrfResult::Valid => {}
                CsrfResult::MissingCookie => return Err(MutationError::CsrfMissingCookie),
                CsrfResult::MissingHeader => return Err(MutationError::CsrfMissingHeader),
                CsrfResult::Mismatch => return Err(MutationError::CsrfMismatch),
            }
        }

        let value = mutator().map_err(|e| MutationError::Validation(e.to_string()))?;

        let entry = AdminChangeEntry {
            ts: chrono::Utc::now(),
            actor: req.actor.into(),
            resource: req.resource.into(),
            action: req.action.into(),
            reason: req.reason.into(),
            diff: serde_json::json!({ "before": before, "after": after }),
            client_ip: String::new(),
        };
        let event: AuditEvent = entry.to_audit_event(req.request_id);
        let chain_entry = {
            let mut writer = self.chain.lock().expect("audit chain poisoned");
            writer.append(event.clone())
        };
        self.bus.emit(event);

        Ok(MutationOutcome { value, chain_entry })
    }

    /// Async sibling of [`Self::apply`] for mutators whose state change
    /// is asynchronous — e.g. a `StateBackend` round-trip like the
    /// cluster config plane's `ConfigStore::activate`. Identical
    /// contract: CSRF is checked first, the future runs exactly once and
    /// only after CSRF passes, and a chain entry is written iff the
    /// future succeeds (Err → `MutationError::Validation`, no chain
    /// entry — same "every entry is a real change" invariant).
    ///
    /// The std `Mutex` guarding the chain is locked only AFTER the await
    /// completes, so it is never held across an `.await` point.
    pub async fn apply_async<F, Fut, T, E>(
        &self,
        req: &MutationRequest<'_>,
        before: serde_json::Value,
        after: serde_json::Value,
        mutator: F,
    ) -> Result<MutationOutcome<T>, MutationError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
        E: std::fmt::Display,
    {
        if requires_csrf(req.method) {
            match csrf_validate(req.csrf_cookie, req.csrf_header) {
                CsrfResult::Valid => {}
                CsrfResult::MissingCookie => return Err(MutationError::CsrfMissingCookie),
                CsrfResult::MissingHeader => return Err(MutationError::CsrfMissingHeader),
                CsrfResult::Mismatch => return Err(MutationError::CsrfMismatch),
            }
        }

        let value = mutator()
            .await
            .map_err(|e| MutationError::Validation(e.to_string()))?;

        let entry = AdminChangeEntry {
            ts: chrono::Utc::now(),
            actor: req.actor.into(),
            resource: req.resource.into(),
            action: req.action.into(),
            reason: req.reason.into(),
            diff: serde_json::json!({ "before": before, "after": after }),
            client_ip: String::new(),
        };
        let event: AuditEvent = entry.to_audit_event(req.request_id);
        let chain_entry = {
            let mut writer = self.chain.lock().expect("audit chain poisoned");
            writer.append(event.clone())
        };
        self.bus.emit(event);

        Ok(MutationOutcome { value, chain_entry })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::chain::{chain_hash, genesis_hash};

    fn req<'a>(method: &'a str, cookie: Option<&'a str>, header: Option<&'a str>) -> MutationRequest<'a> {
        MutationRequest {
            method,
            csrf_cookie: cookie,
            csrf_header: header,
            actor: "admin",
            request_id: "req-1",
            resource: "/api/rules/r1",
            action: "update",
            reason: "test",
        }
    }

    #[derive(Debug)]
    struct Boom(&'static str);
    impl std::fmt::Display for Boom {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }

    #[test]
    fn csrf_rejected_without_cookie() {
        let m = AuditedMutate::new(AuditBus::new(8));
        let r = req("PUT", None, Some("token"));
        let out: Result<MutationOutcome<()>, _> = m.apply(
            &r,
            serde_json::Value::Null,
            serde_json::Value::Null,
            || Ok::<(), Boom>(()),
        );
        let err = out.unwrap_err();
        assert!(matches!(err, MutationError::CsrfMissingCookie));
        assert_eq!(err.http_status(), 403);
        assert_eq!(m.chain_len(), 0);
    }

    #[test]
    fn csrf_rejected_without_header() {
        let m = AuditedMutate::new(AuditBus::new(8));
        let r = req("PUT", Some("token"), None);
        let out: Result<MutationOutcome<()>, _> = m.apply(
            &r,
            serde_json::Value::Null,
            serde_json::Value::Null,
            || Ok::<(), Boom>(()),
        );
        assert!(matches!(out.unwrap_err(), MutationError::CsrfMissingHeader));
    }

    #[test]
    fn csrf_rejected_on_mismatch() {
        let m = AuditedMutate::new(AuditBus::new(8));
        let r = req("DELETE", Some("aaa"), Some("bbb"));
        let out: Result<MutationOutcome<()>, _> = m.apply(
            &r,
            serde_json::Value::Null,
            serde_json::Value::Null,
            || Ok::<(), Boom>(()),
        );
        assert!(matches!(out.unwrap_err(), MutationError::CsrfMismatch));
    }

    #[test]
    fn csrf_skipped_for_get() {
        let m = AuditedMutate::new(AuditBus::new(8));
        let r = req("GET", None, None);
        let out = m
            .apply(
                &r,
                serde_json::Value::Null,
                serde_json::Value::Null,
                || Ok::<u32, Boom>(42),
            )
            .unwrap();
        // GETs aren't supposed to mutate, but if a caller mis-routes
        // one through the pipeline we still skip CSRF and run the
        // closure — the audit entry then records the read intent.
        assert_eq!(out.value, 42);
        assert_eq!(m.chain_len(), 1);
    }

    #[tokio::test]
    async fn apply_async_rejects_csrf_before_running_future() {
        let m = AuditedMutate::new(AuditBus::new(8));
        let r = req("PUT", None, Some("token"));
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran2 = ran.clone();
        let out: Result<MutationOutcome<()>, _> = m
            .apply_async(&r, serde_json::Value::Null, serde_json::Value::Null, || async move {
                ran2.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok::<(), Boom>(())
            })
            .await;
        assert!(matches!(out.unwrap_err(), MutationError::CsrfMissingCookie));
        assert!(
            !ran.load(std::sync::atomic::Ordering::SeqCst),
            "future must NOT run when CSRF fails",
        );
        assert_eq!(m.chain_len(), 0, "no chain entry on CSRF reject");
    }

    #[tokio::test]
    async fn apply_async_success_appends_one_chain_entry() {
        let m = AuditedMutate::new(AuditBus::new(8));
        let r = req("PUT", Some("tok"), Some("tok"));
        let out = m
            .apply_async(&r, serde_json::Value::Null, serde_json::json!({"v": 7}), || async {
                Ok::<u32, Boom>(7)
            })
            .await
            .unwrap();
        assert_eq!(out.value, 7);
        assert_eq!(m.chain_len(), 1);
    }

    #[tokio::test]
    async fn apply_async_failed_future_writes_no_chain_entry() {
        let m = AuditedMutate::new(AuditBus::new(8));
        let r = req("PUT", Some("tok"), Some("tok"));
        let out: Result<MutationOutcome<()>, _> = m
            .apply_async(&r, serde_json::Value::Null, serde_json::Value::Null, || async {
                Err::<(), Boom>(Boom("activation conflict"))
            })
            .await;
        assert!(matches!(out.unwrap_err(), MutationError::Validation(_)));
        assert_eq!(m.chain_len(), 0, "no chain entry when the future errors");
    }

    #[test]
    fn successful_mutation_appends_one_chain_entry() {
        let m = AuditedMutate::new(AuditBus::new(8));
        let r = req("PUT", Some("tok"), Some("tok"));
        let out = m
            .apply(
                &r,
                serde_json::json!({"enabled": false}),
                serde_json::json!({"enabled": true}),
                || Ok::<&str, Boom>("ok"),
            )
            .unwrap();
        assert_eq!(out.value, "ok");
        assert_eq!(m.chain_len(), 1);

        // Chain head matches the recorded entry's hash.
        assert_eq!(m.head_hash(), out.chain_entry.hash);
        // And the entry's hash chains from genesis correctly.
        let recomputed = chain_hash(&genesis_hash(), &out.chain_entry.event);
        assert_eq!(out.chain_entry.hash, recomputed);
    }

    #[test]
    fn validation_failure_does_not_advance_chain() {
        let m = AuditedMutate::new(AuditBus::new(8));
        let r = req("PUT", Some("tok"), Some("tok"));
        let pre_head = m.head_hash();

        let out: Result<MutationOutcome<()>, _> = m.apply(
            &r,
            serde_json::Value::Null,
            serde_json::Value::Null,
            || Err::<(), Boom>(Boom("body too large")),
        );
        let err = out.unwrap_err();
        assert!(matches!(err, MutationError::Validation(_)));
        assert_eq!(err.message(), "body too large");
        assert_eq!(err.http_status(), 400);

        // Chain unchanged.
        assert_eq!(m.chain_len(), 0);
        assert_eq!(m.head_hash(), pre_head);
    }

    #[tokio::test]
    async fn successful_mutation_emits_event_on_bus() {
        let bus = AuditBus::new(8);
        let mut rx = bus.subscribe();
        let m = AuditedMutate::with_chain(
            Arc::new(Mutex::new(ChainWriter::new())),
            bus.clone(),
        );

        let r = MutationRequest {
            method: "POST",
            csrf_cookie: Some("tok"),
            csrf_header: Some("tok"),
            actor: "alice",
            request_id: "req-bus-1",
            resource: "/api/blacklist",
            action: "add",
            reason: "manual block",
        };
        let _ = m
            .apply(
                &r,
                serde_json::json!({}),
                serde_json::json!({"cidr": "10.0.0.1/32"}),
                || Ok::<u32, Boom>(1),
            )
            .unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.request_id, "req-bus-1");
        assert!(matches!(received.class, aegis_core::audit::AuditClass::Admin));
        assert_eq!(received.action, "add");
        let fields = received.fields.as_object().unwrap();
        assert_eq!(fields["actor"], "alice");
        assert_eq!(fields["resource"], "/api/blacklist");
        assert_eq!(fields["diff"]["after"]["cidr"], "10.0.0.1/32");
    }

    #[tokio::test]
    async fn validation_failure_does_not_emit_bus_event() {
        let bus = AuditBus::new(8);
        let mut rx = bus.subscribe();
        let m = AuditedMutate::new(bus.clone());

        let r = req("PUT", Some("tok"), Some("tok"));
        let _ = m.apply(
            &r,
            serde_json::Value::Null,
            serde_json::Value::Null,
            || Err::<(), Boom>(Boom("nope")),
        );

        // No bus emit — try_recv should be empty.
        let res = rx.try_recv();
        assert!(
            matches!(
                res,
                Err(tokio::sync::broadcast::error::TryRecvError::Empty)
            ),
            "expected empty bus, got {res:?}"
        );
    }

    #[test]
    fn concurrent_writes_serialise_via_chain() {
        use std::thread;

        let m = AuditedMutate::new(AuditBus::new(64));
        let mut handles = Vec::new();
        for i in 0..16 {
            let mc = m.clone();
            handles.push(thread::spawn(move || {
                let actor = format!("admin-{i}");
                let req_id = format!("req-{i}");
                let r = MutationRequest {
                    method: "PUT",
                    csrf_cookie: Some("tok"),
                    csrf_header: Some("tok"),
                    actor: &actor,
                    request_id: &req_id,
                    resource: "/api/rules/r1",
                    action: "update",
                    reason: "concurrent",
                };
                mc.apply(
                    &r,
                    serde_json::Value::Null,
                    serde_json::json!({"i": i}),
                    || Ok::<u32, Boom>(i),
                )
                .unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(m.chain_len(), 16);

        // Verify the chain integrity end-to-end.
        let chain = m.chain();
        let writer = chain.lock().unwrap();
        let mut prev = genesis_hash();
        for entry in writer.entries() {
            let expected = chain_hash(&prev, &entry.event);
            assert_eq!(
                entry.hash, expected,
                "chain integrity broken at seq with action={}",
                entry.event.action
            );
            prev = entry.hash.clone();
        }
    }

    #[test]
    fn audit_event_carries_actor_resource_and_diff() {
        let m = AuditedMutate::new(AuditBus::new(8));
        let r = MutationRequest {
            method: "PUT",
            csrf_cookie: Some("tok"),
            csrf_header: Some("tok"),
            actor: "ops-1",
            request_id: "req-diff",
            resource: "/api/tiers/high",
            action: "update",
            reason: "bump rate",
        };
        let before = serde_json::json!({"rate_limit_rps": 100});
        let after = serde_json::json!({"rate_limit_rps": 250});
        let out = m
            .apply(
                &r,
                before.clone(),
                after.clone(),
                || Ok::<(), Boom>(()),
            )
            .unwrap();

        let ev = &out.chain_entry.event;
        let fields = ev.fields.as_object().unwrap();
        assert_eq!(fields["actor"], "ops-1");
        assert_eq!(fields["resource"], "/api/tiers/high");
        assert_eq!(fields["diff"]["before"], before);
        assert_eq!(fields["diff"]["after"], after);
        assert_eq!(ev.reason, "bump rate");
        assert_eq!(ev.request_id, "req-diff");
    }

    #[test]
    fn error_to_body_renders_documented_envelope() {
        let body = MutationError::CsrfMismatch.to_body();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["reason"], "csrf_mismatch");
        assert!(v["message"].is_string());
    }

    #[test]
    fn error_status_codes_match_taxonomy() {
        assert_eq!(MutationError::CsrfMissingCookie.http_status(), 403);
        assert_eq!(MutationError::CsrfMissingHeader.http_status(), 403);
        assert_eq!(MutationError::CsrfMismatch.http_status(), 403);
        assert_eq!(MutationError::Validation("x".into()).http_status(), 400);
        assert_eq!(MutationError::Conflict("x".into()).http_status(), 409);
        assert_eq!(MutationError::Internal("x".into()).http_status(), 500);
    }

    #[test]
    fn error_reason_codes_are_machine_readable() {
        assert_eq!(MutationError::CsrfMissingCookie.reason_code(), "csrf_missing_cookie");
        assert_eq!(MutationError::CsrfMissingHeader.reason_code(), "csrf_missing_header");
        assert_eq!(MutationError::CsrfMismatch.reason_code(), "csrf_mismatch");
        assert_eq!(MutationError::Validation("x".into()).reason_code(), "validation");
        assert_eq!(MutationError::Conflict("x".into()).reason_code(), "conflict");
        assert_eq!(MutationError::Internal("x".into()).reason_code(), "internal");
    }
}
