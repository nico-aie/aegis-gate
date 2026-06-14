# BUG — WebSocket `websocket_close` audit row shows wrong Tier (LOW) + Path (`/`)

- **Type:** BUG (observability / audit-event fields) — Live Feed, Request Detail, Investigation
- **Severity:** 🟡 Medium — cosmetic/observability, not a security miss. Misleads operators triaging WS traffic (a HIGH-tier `/ws/live` socket's close row reads LOW `/`).
- **Status:** 🟡 Planned — not started
- **Found:** 2026-06-14 (Nico, console screenshots — Live Feed + Request Detail drawer)
- **Area:** Data plane → WS bridge lifecycle audit emission (`crates/aegis-proxy/src/data_plane.rs`); dashboard Live Feed / Investigation render the same event.

## Symptom (from console)

A `/ws/live` socket (route tier **HIGH**) produces three Live Feed rows per connection:

| PROTO | PATH | TIER | correct? |
|---|---|---|---|
| `http` (handshake) | `/ws/live` | HIGH | ✅ |
| `ws-open` | `/ws/live` | HIGH | ✅ |
| `ws-close` | **`/`** | **LOW** | ❌ both wrong |

Request Detail for the `ws-close` row (Image #2): `Reason: ws_bridge_closed`, **Tier LOW**, `REQUEST: GET /`, `path /` — while `bytes_to/from_upstream`, `duration_ms`, `upstream_addr` are all correct. The Investigation page reads the same audit event, so it inherits the same wrong Tier/Path.

## Root cause (confirmed in code)

The `websocket_close` audit event is emitted inside the spawned bridge task with **`tier: None` and `path: None`** (`data_plane.rs:~2117` and `:~2125`), and its `fields` bag carries no `path`:

```rust
// websocket_close (current)
tier: None,                 // ← BUG
action: "websocket_close".into(),
route_id: Some(route_id_for_task.clone()),
method: None,
path: None,                 // ← BUG (and no fields.path)
fields: json!({ "upstream_addr", "duration_ms", "bytes_to_upstream", "bytes_from_upstream" }),
```

The `websocket_open` event (`data_plane.rs:~2152`) does it **right**:

```rust
tier: Some(route_ctx.tier),                 // real classification
route_id: Some(route_ctx.route_id.clone()),
fields: json!({ "upstream_addr", "host", "path": parts.uri.to_string() }),
```

The dashboard, when an event's `tier` is `None`, falls back to the **IP-risk bucket** (cumulative score 0 → **LOW**); when `path`/`fields.path` is absent it renders the bare `/`. Hence the close row reads `LOW /`.

The spawned bridge task captured `route_id_for_task` (so `route_id` is right) but **never captured the tier or the request URI** — only those two fields were dropped.

> Note on **Method**: both `websocket_open` and `websocket_close` set `method: None`; the UI defaults the column to `GET`. For a WebSocket the lifecycle derives from a single `GET … Upgrade` handshake, so `GET` is actually correct — there is **no** GET-vs-POST distinction between "first vs last frame" (Nico's hypothesis). The only real bug is the missing **tier** + **path** on the close event. We will set `method: Some("GET")` explicitly on both lifecycle events so the column is data-driven, not a UI guess.

## Fix plan

All edits in the WS branch of `forward_allow_to_upstream` (`data_plane.rs`):

1. **Capture into the task** (beside the existing `route_id_for_task`, before `tokio::spawn`):
   - `let ws_tier = route_ctx.tier;`
   - `let ws_path_for_close = parts.uri.to_string();` (full path incl. query, matching the open event's `fields.path`).
2. **On the `websocket_close` event**, mirror the open event:
   - `tier: Some(ws_tier),`
   - `method: Some("GET".into()),`
   - keep `path: None` at the top level (the open event also keeps it `None` and carries the path in `fields.path` — stay consistent) **and** add `"path": ws_path_for_close` into the `fields` bag.
3. **Also set `method: Some("GET".into())` on the `websocket_open` event** for symmetry (currently `None`).
4. (Optional, same root area) the `websocket_frame_block` → now `action:"block"` event already sets `tier: Some(ws_tier)` (verified) — no change needed.

## Dashboard verification (no change expected, confirm only)

- Confirm `mapAuditToLiveRow` / the tier-cell renderer (`assets/dashboard/src/data.jsx`) uses `event.tier` when present and only falls back to the risk bucket when `tier == null`. Once the close event carries `tier`, the row should read HIGH with no JS change.
- Confirm the Request Detail drawer + Investigation page read `tier` and `fields.path` from the same audit object (they do — both consume the audit event). No JS change expected; if the drawer hard-codes the top-level `path`, add a `fields.path` fallback (the open event already relies on `fields.path`).

## Test

- Unit/e2e in the existing WS test module (`data_plane.rs` `websocket_e2e_tests`): after a bridged `/ws/live` connection closes, assert the emitted `websocket_close` event has `tier == Some(<route tier>)` and `fields.path == "/ws/live"` (parallel to how `sqli_log_only_forwards_and_audits` asserts on the frame-block event).

## Out of scope

- Re-keying the open↔close↔frame events to a shared handshake `request_id` so the UI can correlate the three rows of one socket (nice-to-have, already noted in the WS plan's "out of scope").
