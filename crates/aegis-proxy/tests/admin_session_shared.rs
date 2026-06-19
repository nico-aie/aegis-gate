//! Admin sessions are shared across nodes through the `StateBackend`
//! (the multi-node fix). A session created on one `SessionStore` validates on
//! a second store sharing the same backend + signing key, and a revoke
//! propagates. Uses the in-memory backend as a stand-in for the shared
//! (Redis) store; the code path is identical.

use std::sync::Arc;

use aegis_control::admin_auth::session::SessionStore;
use aegis_core::state::StateBackend;
use aegis_proxy::state::InMemoryBackend;

#[tokio::test]
async fn sessions_are_shared_across_nodes_via_backend() {
    let backend: Arc<dyn StateBackend> = Arc::new(InMemoryBackend::new());
    let key = [7u8; 32];
    let idle = chrono::Duration::hours(1);
    let absolute = chrono::Duration::hours(8);

    // Two "nodes" sharing one backend + the same cookie-signing key (in prod,
    // both derive the key from the same cfg.admin.dashboard_auth.csrf_secret).
    let node_a = SessionStore::with_backend(key, backend.clone(), idle, absolute);
    let node_b = SessionStore::with_backend(key, backend.clone(), idle, absolute);

    // Node A issues a session. R-1 (2026-06-19): `create` now returns a
    // `Result` so a failed/read-only backend write surfaces loudly instead of
    // silently minting an unstored cookie — the in-memory backend is infallible.
    let (id, cookie) = node_a
        .create("1.2.3.4", "ua")
        .await
        .expect("in-memory backend write is infallible");

    // Node B (which never saw the login) validates it from the shared store.
    let rec = node_b
        .validate(&cookie)
        .await
        .expect("session must be shared across nodes via the backend");
    assert_eq!(rec.id, id);
    assert_eq!(rec.ip, "1.2.3.4");

    // A tampered cookie is still rejected on the other node.
    assert!(node_b.validate(&format!("{cookie}X")).await.is_none());

    // Revoke on node A → node B no longer validates (fleet-wide logout).
    assert!(node_a.revoke(&id).await);
    assert!(
        node_b.validate(&cookie).await.is_none(),
        "revoke must propagate across nodes",
    );
}
