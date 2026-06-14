# PLAN — WebSocket frame-mode consolidation + cluster config-sync fixes

- **Type:** PLAN (bug fixes + enhancement; two related workstreams)
- **Status:** ✅ Done — shipped 2026-06-14 on `feat/ws-mode-cluster-sync` (A0–A5 + B1–B2).
- **Branch:** `feat/ws-mode-cluster-sync` (was planned on `feat/sse-streaming`)
- **Created:** 2026-06-14 (Nico, from console + 3-node live testing)

## Completion summary (2026-06-14)

All items landed via TDD (RED → GREEN), one commit each:

- **A0** — `PUT /api/mode` now calls `publish_modes()` so the dashboard
  Dry-Run toggle is fleet-wide. Handler + `mutation_preamble` made generic
  over the body to unit-test the convergence.
- **A1** — `mode_set` rollback (`handle_rollback`) publishes after the local
  apply (same bug class). (Access-list / config-plane rollbacks ride their
  own convergence and were left out of scope.)
- **A2** — `apply_cfg_change_to_client_auth` wired into the shared-store
  watcher's `apply_and_swap` via a new `ApplyTargets.client_auth`; emits
  `zero_trust_reloaded` / `zero_trust_reload_failed`. Convergence test added.
- **A3** — was **already implemented** (`block_threshold` / `cumulative_*`
  carried by `cfg.tiers` + `apply_optional_overrides`); added a regression
  guard and corrected stale doc comments.
- **A4** — structural guard test (`apply_and_swap_invokes_every_reload_helper`)
  asserts every `apply_cfg_change_to_*` is wired into the watcher. It
  immediately caught a real latent bug: **copilot** reload was file-watcher
  only — now also wired into `apply_and_swap`.
- **A5** — `/api/config` now returns this node's current global mode beside
  each node's applied version; threaded through the dashboard convergence
  pill (the per-node applied-version drift view already existed).
- **B1** — WS frame verdict AND-s the per-route `ws_inspect.mode` with the
  global mode (`mode_for_rule`); oversize gate keys on the ambient global
  default.
- **B2** — WS frame block emits `action: "block"` + `fields.surface =
  "websocket"` (consolidated onto the WAF taxonomy / Blocked KPI); metric
  name unchanged. Updated e2e tests, `05-websocket-block.sh`, `config.rs`
  doc, `websocket.md`, the metric description, and WS-03/WS-04 cases.

Docs updated: `docs/security/websocket.md`,
`docs/operations/cluster-config-distribution.md`.
- **Area:** Data plane → WebSocket frame inspection; control plane (`control:waf:*` modes) + config plane (`config:waf:doc`) fleet convergence.
- **Related:** [`BUG-console-route-mutation-not-fleet-convergent.md`](BUG-console-route-mutation-not-fleet-convergent.md) (same convergence theme, config-plane side).

## Why one doc

Two threads surfaced together while testing WebSocket enforcement on a multi-node
deployment:

1. **WebSocket frames don't honor the global dry-run/`set_profile` mode** and their
   block events use a non-standard `action`, so they neither shadow with the rest of
   the WAF nor count in the dashboard KPIs.
2. While confirming (1) would work fleet-wide, we found the **dashboard Dry-Run button
   doesn't sync across nodes at all** — plus a broader audit of which settings pages
   actually converge.

They share the same machinery (`ModeStore` + the cluster pollers), so they're planned
together. **Workstream A (sync) is the live bug and lands first; Workstream B (WS) builds
on it.**

---

## Background — how fleet convergence works today (verified)

Two independent convergence pollers, each ~2s interval + a pub/sub nudge for ~ms
convergence:

- **Control plane** — `crates/aegis-proxy/src/cluster_control.rs`, keys `control:waf:*`.
  Converges exactly: **modes** (`set_profile`/dry-run), **reset epoch**, **access lists**
  (blacklist/whitelist). Convergence requires a publisher to bump the `ClusterModeDoc`
  generation (`cluster_control.rs:96-104`).
- **Config plane** — `crates/aegis-proxy/src/config_source/redis_source.rs`, versioned
  `config:waf:doc`. Each node's watcher applies a new version via `apply_and_swap`
  (`redis_source.rs:232`).

Config-plane sections that **do** converge (called from `apply_and_swap`,
`redis_source.rs:239-289`): detector mask, **routes** (incl. per-route `ws_inspect`),
rate-limit, TLS certs, AI gate, response filter/DLP, tiers (partial — see A3), alert
receivers, rules engine, upstreams.

---

# Workstream A — cluster config sync

## A0 (HOTFIX) — `PUT /api/mode` must publish to the cluster

- **Severity:** 🔴 HIGH — dashboard Dry-Run toggle is silently node-local.
- **Symptom (live):** toggling Dry-Run in the console flips only the node that handled
  the request; behind the LB, peers keep enforcing/shadowing on their old mode.

### Root cause (confirmed)

The dashboard calls `fetch("/api/mode")` → `PUT /api/mode` → `handle_mode_put`
(`crates/aegis-proxy/src/admin_mutate.rs:~124`), which only runs `modes.set_all(new_mode)`
on the **local** in-process `ModeStore`. It never calls `rt.control.publish_modes()`, so
no `ClusterModeDoc` is written and the peer poller never converges.

`POST /__waf_control/set_profile` works precisely because it *does* publish after the local
apply (`admin_dispatch.rs:1040-1042`). The sync mechanism is fine; the dashboard endpoint
forgot to call it. `publish_modes()` is best-effort/no-op single-node (`control.rs:419`).

### Fix

In the `Ok` arm of `handle_mode_put`, after `services.mutate.apply(...)`:

```rust
Ok(_) => {
    // C-1 — propagate the new global mode to peers so the dashboard
    // Dry-Run toggle is fleet-wide, not node-local. Best-effort;
    // no-op on single-node / in-memory backends.
    rt.control.publish_modes().await;
    json_response(200, &serde_json::json!({ "ok": true, "mode": new_mode.as_str(), "request_id": pre.request_id }))
}
```

(The handler is already `async` and holds `rt`; publish goes outside the sync mutate closure.)

### Test

Convergence test paralleling `published_modes_converge_to_a_second_node`
(`cluster_control.rs:154`): node A `PUT /api/mode {log_only}` → node B's resolved mode
flips after a poll/nudge.

## A1 — audit the same bug class (other `ModeStore` mutators)

Any dashboard/admin path that mutates `ModeStore` directly **without** publishing has the
same defect. Audit each and add `publish_modes()` where missing:

- **Prime suspect:** rollback path — `crates/aegis-control/src/api/rollback.rs:363`
  (`mode_store.set_all(target_mode)`).
- Any per-feature / per-policy mode toggle reachable from the console.

*(Config-plane pages — routes/detectors/tiers — converge via a separate mechanism,
`config:waf:doc` activation, not `publish_modes`. Don't conflate the two.)*

## A2 — wire Zero Trust into the fleet config watcher

- **Severity:** 🟠 HIGH — Zero Trust / upstream-mTLS config changes are node-local until restart.
- **Root cause:** the reload helper `apply_cfg_change_to_client_auth` exists
  (`reload.rs:674`) but is only called by the local supervisor path
  (`supervisor.rs:506`) — it is **absent from `apply_and_swap`** (`redis_source.rs:232-289`).
- **Fix:** add `reload::apply_cfg_change_to_client_auth(new_cfg, targets.client_auth.as_ref())`
  to `apply_and_swap`, plumb the `client_auth` target into `ApplyTargets`, emit
  `zero_trust_reload_failed` on failure like the peers. Add a convergence test.
- Cross-ref [[project_config_plane_doc_vs_file]] and the zero_trust rebuild history.

## A3 — fold the missing tier fields

Only `risk_threshold` + `challenges_enabled` converge today; `block_threshold` +
`cumulative_*` are explicitly "not in `cfg.tiers` yet" (`reload.rs:343-344`), so those tier
edits are node-local-until-restart. Extend `cfg.tiers` + `apply_cfg_change_to_tiers` to
carry them.

## A4 — structural guard against regression

`apply_and_swap` is a hand-maintained list; a new config section is silently node-local
until someone adds its `apply_cfg_change_to_*` call (exactly how A2 happened). Add a
test/assertion that every `apply_cfg_change_to_*` helper is invoked by `apply_and_swap`.
Pair with an audit that every `admin_mutate.rs` handler writes `config:waf:doc` (CAS), not
just local state (latent class flagged at `admin_mutate.rs:5507`).

## A5 (optional, demo-friendly) — per-node applied-version on the settings page

The watcher already calls `record_applied` (`redis_source.rs:151`). Surface each node's
applied config version + current mode in the console so operators can *see* convergence and
spot a lagging node.

---

# Workstream B — WebSocket frame inspection consolidation

Depends on A0 (so the global-mode path is trustworthy fleet-wide). Both changes route the
WS block decision through the **same** `mode_for_rule(modes, Some(&tag))` path the HTTP
detectors already use (`data_plane.rs:1071`), which delivers global-mode honoring *and*
rule-taxonomy consolidation in one move.

### Current behavior (verified)

WS text-frame inspection (`data_plane.rs:1982-2071`) runs detectors, sums scores (cap 100),
compares to the tier `risk_threshold`, and on a crossing emits a `websocket_frame_block`
audit (`:2049`) + the `aegis_websocket_frame_block_total{route,tag}` metric. Enforcement is
decided purely locally: `let enforce = matches!(ws_cfg.mode, WsInspectMode::Enforce)`
(`:1971`) — it never consults the global `ModeStore`. The action string isn't `block`, so
it isn't counted by the route-stats KPI (`audit.rs:383` matches `action == "block"` only).

## B1 — WS frames honor the global mode (AND-ed with per-route `ws_inspect.mode`)

- **Decision (locked):** keep `ws_inspect.mode` as a per-route override **AND-ed** with the
  global mode → block only if **both** resolve to Enforce; either saying `log_only` ⇒
  forward + audit.
- `interop_modes: OnceLock<Arc<ModeStore>>` (`proxy.rs:95`); `mode_for_rule` (`rule_map.rs`);
  detector tags (`sqli`/`xss`/…) already map to `rules_engine/<policy>`, so global `scope:all`
  **and** per-policy toggles both apply.

### Edits (all in the WS branch of `data_plane.rs`)

1. Before the bridge `tokio::spawn` (~`:1894`, beside `ws_detectors`/`ws_mask`), capture
   `let ws_modes = upstream_ctx.interop_modes.get().cloned();` (`Option<Arc<ModeStore>>`) and
   move it into the task.
2. Inside the inspector closure, after the top `tag` is computed (~`:2024`):

   ```rust
   let global_mode = ws_modes.as_ref()
       .map(|m| mode_for_rule(m, Some(&tag)))
       .unwrap_or(Mode::Enforce);
   let effective_enforce = enforce && global_mode == Mode::Enforce;
   ```

   Use `effective_enforce` for the `WsVerdict` decision **and** for the audit `mode` string
   (so the audit truthfully reads `log_only` under global dry-run).
3. **Oversize path:** `over_cap_close` is set at bridge-config time (`:1980`) before any tag
   exists — gate it on the ambient default instead:
   `over_cap_close = enforce && ws_modes.as_ref().map(|m| m.current().default).unwrap_or(Mode::Enforce) == Mode::Enforce`.
   So in global log_only an oversize message forwards + meters rather than fail-closing (1009).

### Test

Parallel to `set_profile_log_only_forwards_enforce_blocks` (`data_plane.rs:4812`):
`set_profile_log_only_forwards_ws_frame_block` — `ModeStore` set to `LogOnly`, send a SQLi
text frame, assert it's **forwarded** to upstream and a would-block audit fires with
`mode: log_only`.

## B2 — emit `action: "block"` (consolidate with WAF rule taxonomy)

- **Edit (`data_plane.rs:2049`):** `action: "websocket_frame_block"` → `action: "block"`, and
  preserve the WS signal in `fields`:

  ```rust
  fields: serde_json::json!({
      "surface": "websocket",
      "matched_field": matched_field,
      "message_bytes": payload.len(),
  })
  ```

  `rule_id` already carries the detector tag (consolidates with HTTP rule rows); `mode` already
  distinguishes enforce vs would-block. The Live Feed renders it via the normal block path and
  `audit.rs:383` now counts it in the "Blocked" KPI with no counter change.
- **Keep** the metric name `aegis_websocket_frame_block_total{route,tag}` (it's a metric, not the
  action — the WS-specific drill-down).
- **Discriminator chosen:** `fields.surface = "websocket"`.

### Consumers to update (rename ripple)

- `data_plane.rs:4687` e2e test — assert `action == "block"` **and** `fields.surface == "websocket"`.
- `tests/protocols/05-websocket-block.sh` — grep `"action":"block"` + `"surface":"websocket"`.
- Docs/QC: `docs/security/websocket.md`; `tests/n-tester/preprod-feature-plan/cases/websocket/WS-03`, `WS-04`.
- Doc comment `crates/aegis-core/src/config.rs:1612` (mentions the old action name).
- Confirm at impl time that HTTP log_only would-blocks already emit `action:"block"` so WS
  counting log_only as "blocked" in the KPI stays **consistent** with HTTP (it does, via the
  block DecisionTag intent).

---

## Sequencing

1. **A0** (hotfix) — unblocks trustworthy fleet-wide dry-run; smallest, highest-value.
2. **B1 → B2** — WS consolidation (B1 plumbs `effective_enforce`, B2 reuses it).
3. **A1, A2** — same-bug-class + Zero Trust convergence.
4. **A3, A4, A5** — tier fields, regression guard, UI signal (polish).

A and B are independent after A0; B can proceed in parallel once A0 lands.

## Verification

- `cargo test -p aegis-proxy` (WS tests + the two new convergence/forward tests) and
  `cargo test -p aegis-control`.
- End-to-end with `make run-dev` + `tests/protocols/05-websocket-block.sh`: benign echo,
  attack `1008`, KPI increments.
- Multi-node: toggle Dry-Run in console → peers' `X-WAF-Mode` flips within ~2s; re-run the WS
  attack → frame now **forwards** with a `mode: log_only` audit row.

## Out of scope (noted, not planned here)

- Binary-frame and upstream→client inspection (explicitly accepted as out of scope by Nico).
- Threading the handshake `request_id` into the frame-block audit so open↔block↔close correlate
  in the UI (nice-to-have).
