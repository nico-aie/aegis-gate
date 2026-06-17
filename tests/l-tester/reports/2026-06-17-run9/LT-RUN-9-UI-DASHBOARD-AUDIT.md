# Aegis-Gate Dashboard UI / Backend Cross-Audit — Run 9

| Field                  | Value                                                                                  |
|------------------------|----------------------------------------------------------------------------------------|
| Run ID                 | LT-RUN-9                                                                               |
| Date                   | 2026-06-17                                                                             |
| Approach               | Static cross-audit — UI bundle (`app.js`, 573 KB minified) vs backend Rust handlers   |
| Scope                  | `crates/aegis-control/assets/dashboard/app.js` ↔ `crates/aegis-proxy/src/admin_get.rs`, `admin_dispatch.rs`, `admin_mutate.rs`, `crates/aegis-control/src/api/zero_trust/`, `crates/aegis-control/src/interop/cluster_sync.rs`, `crates/aegis-proxy/src/cluster_control.rs` |
| Total UI/backend bugs  | **5**                                                                                  |
| High                   | **2**                                                                                  |
| Medium                 | **2**                                                                                  |
| Low                    | **1**                                                                                  |
| Feature suggestions    | **7** (Zero Trust page: 4 · Cluster sync: 3)                                          |
| Status                 | 🟡 OPEN — 2 High findings cause operator-visible feature breakage                     |

---

## Executive Summary

This run cross-checks the minified React dashboard bundle against the backend admin API handlers to find logic mismatches, dead UI code, and missing operator controls.

The most impactful bug is **UI-HIGH-01**: a hardcoded constant `SHOW_DOWNSTREAM_MTLS = false` in `app.js` permanently hides the entire **Downstream mTLS** section of the Zero Trust page. Seven backend endpoints (`/api/zero-trust/downstream/mode`, `/ca-bundle`, `/ca-bundle/capability`, `/sans`, `/sans/{san}/test`, `/connections`, `/failures`) are fully implemented and tested in the Rust layer, but no operator can ever reach them through the dashboard. The page subtitle silently changes to "WAF → backend only" direction without any indication that the other half is missing.

**UI-HIGH-02** is a related permanently-false field: `MtlsConfigView.active` is always `false` in `downstream.rs` with a comment "MTLS-T2 will populate it." MTLS-T2 never landed. If an operator configures and correctly enforces downstream mTLS at the TLS layer (e.g., by restarting with `client_auth.mode = required`), the dashboard will always report "not yet enforced," misleading them into thinking the config has no effect.

**UI-MED-01** is a cross-page coupling bug: both `ZtIdentityCard` (upstream identity upload) and `ZtUpstreamPoolsCard` (pool CA cert upload) gate their upload forms on `/api/zero-trust/downstream/ca-bundle/capability` → `allow_ca_upload`. These are *upstream* features reading a *downstream* capability endpoint. The two upload paths have independent server-side gates in `admin_mutate.rs`. If the flags ever diverge, the UI will show or hide the upstream form incorrectly.

**UI-MED-02** covers the cluster sync gap the user highlighted: there are no admin API endpoints to manually trigger convergence, check per-node sync status, or push config to peers. The cluster poller converges automatically every 2 s but there is zero operator visibility or control in the dashboard.

**UI-LOW-01** is a minor display gap: `FleetNodeBanner` reads `stats.data?.fleet_nodes` to decide whether to show "Fleet view" vs "THIS node only," but `fleet_nodes` is `null` unless `cluster.fleet_view: true` is set in config *and* a Redis backend is wired *and* at least one merge cycle has completed. In a correctly wired Redis cluster without `fleet_view`, the banner always says "showing THIS node only" even though modes and blacklists are converging normally.

---

## Finding Index

| ID          | Severity   | Category          | Short Description                                                                              |
|-------------|------------|-------------------|------------------------------------------------------------------------------------------------|
| UI-HIGH-01  | **High**   | Dead UI Code      | `SHOW_DOWNSTREAM_MTLS = false` hardcoded — entire downstream mTLS section never renders        |
| UI-HIGH-02  | **High**   | Logic Conflict    | `MtlsConfigView.active` always `false` — downstream mTLS appears "not enforced" even when it is |
| UI-MED-01   | **Medium** | Wiring Gap        | Upstream identity/pool upload gates on downstream capability endpoint — wrong coupling         |
| UI-MED-02   | **Medium** | Not Implemented   | No cluster-sync admin API — no force-sync, no per-node status, no manual nudge                 |
| UI-LOW-01   | **Low**    | Logic Conflict    | `FleetNodeBanner` shows "THIS node only" in Redis cluster when `fleet_view` is not enabled     |

---

## Detailed Findings

---

### UI-HIGH-01 — `SHOW_DOWNSTREAM_MTLS = false` Hides Entire Downstream mTLS Section

**Severity:** High  
**Category:** Dead UI Code  
**File:** `crates/aegis-control/assets/dashboard/app.js` (constant near start of bundle)

**Code snippet (extracted from minified bundle):**
```javascript
const SHOW_DOWNSTREAM_MTLS = false;   // ← hardcoded

function PageZeroTrust() {
  return React.createElement(React.Fragment, null,
    React.createElement("div", { className: "page-head" },
      // subtitle changes based on constant but no indication anything is hidden
      SHOW_DOWNSTREAM_MTLS ? "Mutual TLS in both directions …" : "Mutual TLS from the WAF to your backends"
    ),
    SHOW_DOWNSTREAM_MTLS && React.createElement(React.Fragment, null,
      React.createElement(MtlsModeCard, null),      // NEVER RENDERED
      React.createElement(MtlsCaBundleCard, null),  // NEVER RENDERED
      React.createElement(MtlsSansCard, null),      // NEVER RENDERED
    ),
    React.createElement(ZtIdentityCard, null),       // upstream — always shown
    React.createElement(ZtUpstreamPoolsCard, null),  // upstream — always shown
    React.createElement(ZtUpstreamFailuresCard, null)
  )
}
```

**Backend endpoints that are fully implemented but unreachable from the UI:**

| Endpoint | Handler | Status |
|---|---|---|
| `GET/PUT /api/zero-trust/downstream/mode` | `admin_get.rs:1149`, `admin_dispatch.rs:464` | ✅ implemented |
| `GET/PUT /api/zero-trust/downstream/ca-bundle` | `admin_get.rs:1137`, `admin_dispatch.rs:468` | ✅ implemented |
| `GET /api/zero-trust/downstream/ca-bundle/capability` | `admin_get.rs:1137` | ✅ implemented |
| `GET/PUT /api/zero-trust/downstream/sans` | `admin_get.rs:1252`, `admin_dispatch.rs:471` | ✅ implemented |
| `DELETE/POST /api/zero-trust/downstream/sans/{san}(/test)` | `admin_dispatch.rs:499` | ✅ implemented |
| `GET /api/zero-trust/downstream/connections` | `admin_get.rs:1228` | ✅ implemented |
| `GET /api/zero-trust/downstream/failures` | `admin_get.rs:1235` | ✅ implemented |
| `GET /api/zero-trust/downstream/ca-summary` | `admin_get.rs:1242` | ✅ implemented |

**Impact:** Operators cannot configure downstream mTLS (client cert validation) through the dashboard at all. The entire "client → WAF" authentication surface is invisible. The page subtitle silently reads "Mutual TLS from the WAF to your backends" with no mention that downstream is disabled in the UI.

**Suggested fix:** Set `SHOW_DOWNSTREAM_MTLS = true` in `app.js` and rebuild the bundle. If a feature-flag mechanism is desired, expose it via a server-side capability endpoint (e.g., extend `/api/zero-trust/downstream/ca-bundle/capability` with a `show_downstream_section: bool` field) rather than a build-time constant. The backend is fully ready; this is a one-line UI change.

---

### UI-HIGH-02 — `MtlsConfigView.active` Always `false` — Downstream mTLS Appears Unforced

**Severity:** High  
**Category:** Logic Conflict (documentation vs implementation)  
**File:** `crates/aegis-control/src/api/zero_trust/downstream.rs:56–59`

**Code snippet:**
```rust
/// `true` only after MTLS-T2's rustls wiring lands. Until
/// then the dashboard shows a "configured but not yet
/// enforced" pill. Set unconditionally to `false` in this
/// slice — MTLS-T2 will populate it from the live
/// `WebPkiClientVerifier` boolean.
pub active: bool,

// In from_client_auth():
active: false,  // ← always false, MTLS-T2 never landed
```

The `active` field is the boolean the downstream mTLS cards use to display "mTLS enforced ✓" vs "configured but not yet enforced ⚠." The comment refers to "MTLS-T2's rustls wiring" which does not exist in the codebase. No search across the 317 source files finds any code that sets `active: true` in this path.

**Impact (when UI-HIGH-01 is fixed):** An operator who correctly configures `cfg.zero_trust.downstream.mode = required`, restarts the proxy, and opens the Zero Trust page will see a permanent "not yet enforced" warning. This creates a false sense that mTLS is not protecting their endpoints. It could lead to an operator opening a support ticket or disabling the feature thinking it is broken.

**Suggested fix:** Thread the `WebPkiClientVerifier` or a `bool` flag from the TLS acceptor build path down into `DashboardServices` and pass it to `from_client_auth`. If the acceptor was built with `with_client_cert_verifier(...)`, `active = true`. If built with `with_no_client_auth()`, `active = false`. This mirrors the existing pattern used by `allow_ca_upload` (a `bool` field on `DashboardServices`).

---

### UI-MED-01 — Upstream Upload Form Gated on Downstream Capability Endpoint

**Severity:** Medium  
**Category:** Wiring Gap (wrong endpoint used as capability gate)  
**File:** `crates/aegis-control/assets/dashboard/app.js` — `ZtIdentityCard` and `ZtUpstreamPoolsCard` components

**Code snippet (both components):**
```javascript
// ZtIdentityCard — gates the upstream WAF client cert upload form
const canUpload = !!window.useApi(
  "/api/zero-trust/downstream/ca-bundle/capability",  // ← DOWNSTREAM endpoint
  { intervalMs: 60000, fallback: { allow_ca_upload: false } }
).data?.allow_ca_upload;

// ZtUpstreamPoolsCard — gates the pool backend CA cert upload
const canUpload = !!window.useApi(
  "/api/zero-trust/downstream/ca-bundle/capability",  // ← DOWNSTREAM endpoint
  { intervalMs: 60000, fallback: { allow_ca_upload: false } }
).data?.allow_ca_upload;
```

The downstream capability endpoint (`admin_get.rs:1137`) simply reflects `services.allow_ca_upload` — the `cfg.admin.dashboard_auth.allow_ca_upload` boolean. The upstream identity PUT handler (`admin_mutate.rs:~1422`) has its own independent gate:
```rust
if !cfg.admin.dashboard_auth.allow_ca_upload {
    return json_response(422, &serde_json::json!({
        "error": "upload_not_enabled",
        "message": "Upstream identity upload is gated …",
    }));
}
```

Currently both gates read the same config key, so the bug is latent. But the components are semantically wrong: an upstream feature (WAF-as-client cert upload) should not be controlled by a downstream capability flag. If the two capability paths are split in a future refactor (e.g., separate `allow_upstream_identity_upload` and `allow_downstream_ca_upload` flags), the UI will silently start showing/hiding the wrong form.

**Suggested fix:** Add a dedicated `GET /api/zero-trust/upstream/capability` endpoint that returns `{ allow_identity_upload: bool }` driven by the correct upstream gate. Update `ZtIdentityCard` and `ZtUpstreamPoolsCard` to poll that endpoint instead of the downstream one.

---

### UI-MED-02 — No Cluster-Sync Admin API or Dashboard Controls

**Severity:** Medium  
**Category:** Not Implemented  
**File:** `crates/aegis-proxy/src/cluster_control.rs`, `crates/aegis-control/src/interop/cluster_sync.rs`, `app.js` — `FleetNodeBanner`

**Current state:**

The cluster convergence poller (`cluster_control.rs:spawn_poller`) runs every 2 s automatically, applying peer-published mode snapshots and reset epochs from Redis. A pub/sub nudge channel (`CONTROL_BUMP_CHANNEL`) wakes the poller on control-plane mutations for ~ms convergence. This is all internal and invisible to the operator.

The only cluster surface in the UI is `FleetNodeBanner` — an informational banner showing peer count and whether fleet-view metrics are merged:
```javascript
function FleetNodeBanner() {
  // only renders if peers.length >= 2; shows info text only
  // NO sync button, NO per-node status, NO manual trigger
}
```

There are **no admin API endpoints** for:
- `POST /api/cluster/sync` — force-push current node's ModeStore / access lists to Redis immediately
- `GET /api/cluster/convergence` — show each node's applied generation vs published generation
- `POST /api/cluster/nudge` — publish a 1-byte bump to `CONTROL_BUMP_CHANNEL` to wake all pollers immediately (the infrastructure exists in `cluster_sync.rs` but has no HTTP surface)

**Impact:** In a multi-node deployment, operators have no way to verify convergence, diagnose a node that is stuck on a stale mode, or force-push a config change without waiting up to 2 s. During a live incident (e.g., setting `set_profile` to `log_only` while triaging a false-positive spike), there is no "apply now across all nodes" button.

**Suggested fix:** See Feature Suggestions §3 below for the three recommended API endpoints and corresponding dashboard cards.

---

### UI-LOW-01 — `FleetNodeBanner` Shows "THIS Node Only" in Redis Cluster Without `fleet_view`

**Severity:** Low  
**Category:** Logic Conflict (display vs operator expectation)  
**File:** `app.js` — `FleetNodeBanner`; `crates/aegis-control/src/api/stats.rs:83`, `:240`, `:403`

**Code snippet:**
```javascript
const fleetNodes = stats.data?.fleet_nodes;   // null unless fleet_view active
const fleetView  = typeof fleetNodes === "number" && fleetNodes > 0;

// In stats.rs — fleet_nodes is only set when fleet_cache is Some AND has merged:
pub fleet_nodes: Option<u32>,   // None → serializes as null
// ...
fleet_nodes: None,              // ← default when fleet_view disabled
fleet_nodes: Some(merged.nodes as u32), // ← only when MergedFleet available
```

When a cluster runs with Redis state backend (modes and access lists converging correctly) but `cluster.fleet_view: true` is not set in config, the banner shows "Traffic metrics below are `<this_node>`'s slice, not fleet totals." This is accurate for the traffic metrics panel. However, the banner gives the operator no indication that mode convergence and blacklist convergence ARE working — they may mistakenly think the cluster is not functioning at all.

**Suggested fix:** Add a separate `cluster_sync_active: bool` field to `/api/cluster` (derived from whether `spawn_poller` was called at boot, i.e., the state backend is a shared Redis). The banner can then show a second line: "Mode + access-list convergence: active (2s interval)" even when fleet-view metrics are disabled.

---

## Feature Suggestions

### 1. Fix: Enable Downstream mTLS UI Section

Turn `SHOW_DOWNSTREAM_MTLS = false` to `true` in `app.js`. The backend handlers are complete. The three hidden cards (`MtlsModeCard`, `MtlsCaBundleCard`, `MtlsSansCard`) are already wired to the correct endpoints.

Estimated effort: **1 line change + bundle rebuild**.

---

### 2. Zero Trust Page — Cert Expiry Warning Banner

The upstream identity card (`ZtIdentityCard`) already polls `/api/zero-trust/upstream/identity` and receives `certificates[].days_to_expiry`. Add a yellow banner above the card when any cert has `days_to_expiry < 30`:

```javascript
// Suggested addition inside ZtIdentityCard render:
const expiringSoon = d.certificates?.some(c => c.days_to_expiry < 30);
expiringSoon && React.createElement("div", { className: "banner warn" },
  "WAF client cert expires in < 30 days — rotate before expiry to avoid backend auth failures."
)
```

Backend already provides the data; no new API needed.

---

### 3. Zero Trust Page — Downstream Live Stats Cards

Two backend endpoints are implemented but never polled by the UI:

- `GET /api/zero-trust/downstream/connections` — per-SAN request counts (sliding window)
- `GET /api/zero-trust/downstream/failures` — TLS handshake failure histogram by reason

Add two cards below `MtlsSansCard` (only visible when `SHOW_DOWNSTREAM_MTLS = true`):
- **`ZtDownstreamConnectionsCard`** — table of principal → request count (mirrors `ZtUpstreamFailuresCard` layout)
- **`ZtDownstreamFailuresCard`** — table of reason → count with pill colors matching `ZtUpstreamFailuresCard`

---

### 4. Zero Trust Page — CA Bundle Diff Preview

The `PUT /api/zero-trust/downstream/ca-bundle` response already returns a `diff` field (added/removed certs from `diff_previews()`). Currently `MtlsCaBundleCard` (when visible) shows a flat cert list after upload. Add a "Changes" section to the success state showing:
- ✅ Added: N certs
- ❌ Removed: N certs
- Subject + fingerprint for each changed cert

No new API needed — the diff is already in the existing PUT response body.

---

### 5. Cluster Page — Force-Sync API + Dashboard Controls

Add three new admin endpoints to `admin_dispatch.rs` / `admin_mutate.rs`:

**`POST /api/cluster/sync`**  
Force-publishes the current node's `ModeStore` snapshot and access lists to Redis, then publishes a nudge byte to `CONTROL_BUMP_CHANNEL`. Backend sketch:
```rust
// In admin_mutate.rs
async fn handle_cluster_force_sync(services: &DashboardServices) -> Response<...> {
    let snap = services.rt.control.current_snapshot();
    cluster_sync::publish_modes(&state, &snap).await;
    cluster_sync::publish_bump(&state).await;  // wake peer pollers ~ms
    json_response(200, &json!({ "ok": true, "published_generation": gen }))
}
```
The nudge infrastructure (`CONTROL_BUMP_CHANNEL`, `publish_bump`) is already defined in `cluster_sync.rs` — only the HTTP surface is missing.

**`GET /api/cluster/convergence`**  
Returns per-node: `{ node_id, addr, applied_modes_gen, published_modes_gen, lag_ms }`.  
Requires each node to heartbeat its `applied_gen` into Redis (e.g., key `control:waf:applied:<node_id>`). The poller in `cluster_control.rs` writes this after each successful apply.

**Dashboard card: `ClusterSyncCard`** (add to Cluster page or Settings):
- Table: Node | Addr | Modes Gen | Convergence Status | Last Heartbeat
- "Force Sync Now" button → `POST /api/cluster/sync`
- Green/yellow/red status pill per node based on `lag_ms`

---

### 6. Cluster Page — Fleet Config Backup

Extend the existing `GET /api/config/backup.yaml` endpoint with a fleet-wide mode. Or add `GET /api/cluster/config-snapshot` that returns a JSON object with each peer's config hash (the proxy already knows peer addresses from `RosterView`). The dashboard could show whether all peers are running the same config version, and offer a "Download all configs as ZIP" action.

---

### 7. Zero Trust Page — Zero Trust Activity Feed

The backend emits audit events for every zero-trust mutation (mode change, CA bundle swap, SAN add/remove, identity upload — all go through `audit_mutate`). Add a compact activity feed card at the bottom of the Zero Trust page that fetches `/api/audit/since?resource_prefix=zero-trust&limit=20`. No new API is needed; the existing audit endpoint supports `resource_prefix` filtering.

---

## Cross-Page Wiring Table

| Feature | UI Component | Backend Endpoint | UI→Backend Wired | Net Status |
|---|---|---|---|---|
| Downstream mTLS mode | `MtlsModeCard` | `GET/PUT /api/zero-trust/downstream/mode` | ✗ (hidden) | **Dead — SHOW_DOWNSTREAM_MTLS=false** |
| Downstream CA bundle | `MtlsCaBundleCard` | `GET/PUT /api/zero-trust/downstream/ca-bundle` | ✗ (hidden) | **Dead — SHOW_DOWNSTREAM_MTLS=false** |
| Downstream allowed SANs | `MtlsSansCard` | `GET/PUT/DELETE /api/zero-trust/downstream/sans/*` | ✗ (hidden) | **Dead — SHOW_DOWNSTREAM_MTLS=false** |
| Downstream connections | (no card) | `GET /api/zero-trust/downstream/connections` | ✗ (missing card) | **Dead — no UI card** |
| Downstream failures | (no card) | `GET /api/zero-trust/downstream/failures` | ✗ (missing card) | **Dead — no UI card** |
| Upstream identity | `ZtIdentityCard` | `GET/PUT /api/zero-trust/upstream/identity` | ✓ | **Working** |
| Upstream rotation | `ZtIdentityCard` | `GET /api/zero-trust/upstream/rotation` | ✓ | **Working** |
| Upstream pool mTLS | `ZtUpstreamPoolsCard` | `GET /api/zero-trust/upstream/config` | ✓ | **Working** |
| Upstream trust bundles | `ZtUpstreamPoolsCard` | `GET/POST/DELETE /api/zero-trust/upstream/trust/*` | ✓ | **Working** |
| Upstream failures | `ZtUpstreamFailuresCard` | `GET /api/zero-trust/upstream/failures` | ✓ | **Working** |
| Cluster roster | `FleetNodeBanner` | `GET /api/cluster` | ✓ | **Working** |
| Cluster fleet metrics | `FleetNodeBanner` | `GET /api/stats` → `fleet_nodes` | ✓ (conditional) | **Working when fleet_view enabled** |
| Cluster force-sync | (no card) | (no endpoint) | ✗ | **Not implemented** |
| Cluster convergence status | (no card) | (no endpoint) | ✗ | **Not implemented** |
| Cluster nudge | (no control) | (no HTTP surface) | ✗ | **Not implemented** |

---

## Recommended Fix Priority

1. **UI-HIGH-01** — Set `SHOW_DOWNSTREAM_MTLS = true`, rebuild bundle. One-line change that unlocks the fully implemented downstream mTLS surface. Do this first.
2. **UI-HIGH-02** — Thread `active` bool from TLS acceptor state into `DashboardServices`. Without this, operators enabling downstream mTLS will see a misleading "not enforced" badge.
3. **UI-MED-01** — Add `GET /api/zero-trust/upstream/capability` and update `ZtIdentityCard` + `ZtUpstreamPoolsCard` to use it. Low-risk refactor that prevents future capability-gate drift.
4. **UI-MED-02** — Implement `POST /api/cluster/sync` + `GET /api/cluster/convergence` + `ClusterSyncCard`. The `CONTROL_BUMP_CHANNEL` infrastructure is already in `cluster_sync.rs`; only the HTTP surface and dashboard card are new work.
5. **FEAT-5 (cert expiry warning)** — Two-line UI addition, high operator value during cert rotation ceremonies.
