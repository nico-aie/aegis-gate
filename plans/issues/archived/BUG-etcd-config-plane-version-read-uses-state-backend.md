# BUG — under `config_plane.store: etcd`, the read-side config-version is sourced from Redis (`state_backend`), so every `If-Match` audit-mutation 412s

- **Type:** BUG (H2b etcd config plane / admin optimistic-concurrency)
- **Severity:** 🔴 HIGH — with `config_plane.store: etcd`, **every dashboard detector-mask toggle fails** with `Toggle failed: mask changed under you — reloaded latest; try again`, and the same breaks any `If-Match`-guarded audit-mutation. The config plane itself is healthy (writes land in etcd, nodes converge, enforcement is correct) — only the admin read-side version stamp is wrong, which makes the UI's CAS unsatisfiable. No data-plane impact.
- **Status:** ✅ FIXED 2026-06-27 (branch `fix/etcd-config-plane-read-version`). The read side now
  builds its `ConfigStore` via a new `config_store_for(services)` helper (prefers
  `services.config_backend`, falls back to `state_backend`), used by `this_node_applied_version`
  + `handle_config_get` (so `GET /api/detectors`, `/api/config`, `/api/config/version` all follow
  the config plane). The `run.rs` audit found the file *publisher* had the mirror defect
  (`config_plane.file_watch: publish` wrote to Redis even under `store: etcd`) — also fixed by
  moving `plane_select::select` above the file watcher and publishing via
  `ConfigStore::with_config_backend(config_backend)` (byte-identical under `shared_state`).
  Regression test: `config_store_for_follows_config_backend_when_set`. Found in live pre-prod after
  the Redis→etcd cutover (H2b P2/P3).
- **Found:** 2026-06-26, reproduced on the live 3-node fleet (`config_plane.store: etcd`, etcd @ `10.20.0.72:2379`).
- **Area:** `crates/aegis-proxy/src/admin_dispatch.rs` — `this_node_applied_version`, `handle_config_get`, `handle_config_version_get`. Interacts with `config_source/config_store.rs` (`activate` CAS) and the `services.config_backend` wiring in `run.rs`.

## Summary

The H2b config-plane **write** path correctly uses the selected config backend
(`services.config_backend` — `EtcdConfigBackend` when `config_plane.store: etcd`, else the
shared-state backend). The **read** path that stamps `config_version` for the dashboard
does **not**: it builds its `ConfigStore` from `services.state_backend`, which is *always*
Redis (the data-plane hot-path store). Redis is no longer the config plane after cutover.

Result asymmetry under `store: etcd`:

- `GET /api/detectors` → `config_version: 0` (read from Redis, which holds no / stale
  applied-version ACKs — the per-node `config:waf:applied:*` keys are TTL'd and now written
  to **etcd**, so the Redis copies age out to absent → `0`).
- `PUT /api/detectors` → `activate()` loads the current doc from **etcd** → `current = 124`.

The dashboard echoes the GET's `config_version` (`0`) as `If-Match`. `activate()` compares
`cur_version (124) != expected_version (0)` → `Activate::Conflict { current: 124 }` →
HTTP **412**. The client re-fetches, gets `config_version: 0` again, retries with
`If-Match: 0`, conflicts again — exhausts its 3 attempts → the toast
`mask changed under you — reloaded latest; try again`. It can **never** succeed.

## Reproduction (live, `config_plane.store: etcd`)

```sh
# etcd config doc + per-node ACKs are all at v124 (converged, stable):
etcdctl get config:waf:doc        --print-value-only | jq .version       # 124
etcdctl get config:waf:applied:waf-infra-1 --print-value-only            # 124

# But the admin read-side reports 0:
curl -s -b cookies http://127.0.0.1:9443/api/detectors | jq .config_version   # => 0

# So a correct, converged toggle still 412s:
curl -s -b cookies -X PUT http://127.0.0.1:9443/api/detectors \
  -H "x-csrf-token: $CSRF" -H "If-Match: 0" \
  -H 'content-type: application/json' -d '{"mask":{"recon":false}}' -i
# => HTTP/1.1 412 Precondition Failed
#    {"error":"version_conflict","current":124, ...}
```

`GET /api/config` (the drift view) is likewise wrong under etcd: `version: 0`, empty
`applied[]` — cosmetic but misleading.

## Root cause (confirmed in code)

`this_node_applied_version` — the helper that feeds `config_version` into both
`GET /api/detectors` and `GET /api/config/version` — constructs its store from
`state_backend`:

```rust
// crates/aegis-proxy/src/admin_dispatch.rs  (~676)
async fn this_node_applied_version(services: &DashboardServices) -> Option<u64> {
    match (services.state_backend.as_ref(), services.roster_view.as_ref()) {
        (Some(backend), Some(rv)) if !rv.our_node.is_empty() => {
            let store = ConfigStore::new(backend.clone());   // ← Redis, not the config plane
            store.applied_version(&rv.our_node).await.ok()
        }
        _ => None,
    }
}
```

`ConfigStore::new(state_backend)` wraps the Redis `StateBackend`
(`SharedStateConfigBackend`). Under `store: etcd` the applied-version ACKs live in etcd, so
this reads a stale/absent Redis key → `0`. `handle_config_get` (`~596`) has the same defect
(`let Some(backend) = services.state_backend …; ConfigStore::new(backend)`).

The write path is correct for contrast — it uses the config backend:

```rust
// run.rs (~1388)  +  admin_mutate.rs detector PUT → activate()
let store = ConfigStore::with_config_backend(config_backend.clone()); // etcd under store: etcd
```

And `DashboardServices` already carries the right handle, with a comment that exactly
predicts this trap:

```rust
// crates/aegis-control/src/dashboard_services.rs (~145-152)
/// the config-plane backend selected from `config_plane.store` … so activations land on
/// the SAME store the convergence watcher reads. If `None` (test bundles), handlers fall
/// back to `state_backend`.
pub config_backend: Option<Arc<dyn aegis_core::config_backend::ConfigBackend>>,
```

The read helpers never consult `services.config_backend`; they unconditionally use
`state_backend`.

## Why full-document edits still work (and toggles don't)

`PUT /api/config` (full-document activation, e.g. the rule CRUD that added `rule-test`) uses
the legacy **unconditional** write path (no `If-Match` → server does a fresh read,
`expected = current`, always matches). Only the **`If-Match`-guarded** mutations break,
because they depend on the GET-reported `config_version` being truthful. So on a live
etcd fleet you see config edits succeeding (version climbs) while the detector toggle is
permanently stuck — which is exactly the confusing symptom reported.

## Blast radius

- **Broken:** every `If-Match`-guarded audit-mutation under `store: etcd` — confirmed:
  detector-mask toggle (`PUT /api/detectors`). Any other handler that echoes
  `config_version` as `If-Match` is suspect (audit it).
- **Wrong/cosmetic:** `GET /api/config` drift view (`version: 0`, empty `applied[]`),
  `GET /api/config/version` `applied_version` (the post-mutation convergence wait the
  dashboard polls — may mis-wait under etcd).
- **Not affected:** the data plane (enforcement correct), config convergence (nodes apply
  the etcd doc fine), `shared_state` deployments (read + write both use Redis there).

## Suggested fix

Make the read side use the **same backend the write side uses** — prefer
`services.config_backend`, fall back to `state_backend`. One helper, three call sites:

```rust
fn config_store_for(services: &DashboardServices) -> Option<ConfigStore> {
    if let Some(cb) = services.config_backend.as_ref() {
        return Some(ConfigStore::with_config_backend(cb.clone()));
    }
    services.state_backend.as_ref().map(|b| ConfigStore::new(b.clone()))
}
```

Use it in `this_node_applied_version` and `handle_config_get` (and therefore
`handle_config_version_get`). The sync fallback arm in
`admin_get.rs` `"/api/detectors"` (renders no version) is unaffected — the async cluster
dispatch is what serves the live fleet.

### Test (RED first)

A regression test that wires a `DashboardServices` with a **config_backend distinct from
state_backend**, activates a version through the config backend, and asserts
`GET /api/detectors` reports that version (not `0`) — i.e. the read store follows
`config_backend` when set. Today it returns `state_backend`'s value and fails.

## Workaround (until fixed)

Roll the config plane back to Redis: set `config_plane.store: shared_state` on every node
and restart (the cutover is a copy — Redis still holds the doc). ⚠️ Config edits made
**after** the etcd cutover live only in etcd; re-run `waf migrate-config-plane` in the
etcd→Redis direction first if they must be preserved, or re-apply them after rollback.
(For the current pre-prod fleet that means the `rule-test` inline rule + any toggles since
cutover.)

## Cross-references

- `deploy/CONFIG-PLANE-RUNBOOK.md` §11 — etcd config plane operate guide.
- `plans/future/config-etcd-source-of-truth.md` — H2b design.
- `crates/aegis-proxy/src/config_source/config_store.rs` — `activate` (the CAS that 412s),
  `current_version`, `applied_version`.
- `crates/aegis-proxy/src/admin_mutate.rs` (~4109-4214) — the `If-Match` → `activate`
  detector-mask write path.
