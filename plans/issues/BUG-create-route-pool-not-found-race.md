# BUG — "pool not found" when creating a route right after creating its pool

- **Type:** BUG (UX / config-plane consistency race)
- **Severity:** 🟡 Medium — self-recovers within a few seconds; no data loss, but reads as a hard error and confuses operators.
- **Status:** 🔴 Open
- **Reported:** 2026-06-14 (Nico, from console use)
- **Area:** Dashboard → Routing & Upstreams → **Add route → "+ Create new pool"** child flow.

## Symptom

1. Open **+ Add route**, click **+ Create new pool**, author the pool, **Save**.
2. The pool immediately appears selected in the **Forward to** dropdown (and shows in the pool list).
3. Click **Save** on the route → error: **`upstream "<pool>" not found; known pools: [...]`** ("pool not found").
4. Wait a few seconds, click **Save** again → it succeeds, no other change.

## Root cause

An **optimistic UI update races the asynchronous config-plane apply.**

- Creating a pool only **activates** the shared config doc. It returns `200` with the note
  *"config activated; propagates to all nodes within a few seconds"*
  (`crates/aegis-proxy/src/admin_mutate.rs:536`, and `:413` for the bulk path). The per-node
  live pool map (`writer.current_pools()`) is rebuilt **later**, when each node applies the new
  config version via `apply_cfg_change_to_upstreams`.

- The child-pool handler `handleChildPoolSave` (`crates/aegis-control/assets/dashboard/src/pages.jsx:14074`)
  does **not** wait for that apply. On `200` it **optimistically** pushes the name into the dropdown
  (`setOptimisticPools`, `:14082`) and auto-selects it (`:14084`). So the UI *claims* the pool exists
  before the data plane agrees.

- Submitting the route runs `handle_route_upsert` → `validate_route`
  (`crates/aegis-proxy/src/admin_mutate.rs:5450-5461`), which checks
  `cfg.upstreams` **plus** `writer.current_pools()` — i.e. the per-node shadow that hasn't caught up
  yet. Miss → `RouteValidationError::UnknownUpstream`
  (`crates/aegis-control/src/api/routes_config.rs:236`) → "pool not found".

- A few seconds later the node applies the activated config, `current_pools()` includes the new pool,
  and the identical submit validates cleanly.

**Why the standalone flows don't show it:** the page-level pool/route mutations go through
`reloadAfterApply` → `await window.waitForVersion(before + 1, 10000)`
(`pages.jsx:8918`, `data.jsx:1498`) before they let the next step proceed. The
**"+ Create new pool" inside Add Route** path is the one place that skips this gate in favour of an
optimistic dropdown update.

## Impact

- Looks like a hard failure on a first-time route create; operators retry, file it as a bug, or
  assume the pool didn't save. Pure UX/perception — the eventual state is correct.
- Single-node and multi-node both affected; multi-node window is as wide as fleet convergence.

## Workaround (today)

After creating the pool inline, wait ~2–5 s before clicking **Save** on the route (or reopen the route
modal so the dropdown re-reads the live config), then save.

## Suggested fix

**Preferred — close the gap in the UI (matches the existing `reloadAfterApply` pattern):**
In `handleChildPoolSave` (`pages.jsx:14074`), capture `before = await window.currentConfigVersion()`
before `poolUpsert`, then `await window.waitForVersion(before + 1, 10000)` **before** clearing the
busy state / enabling the route **Save** button. Surface a small "pool propagating…" spinner and keep
**Save** disabled until the version lands. This guarantees the pool is live on the connected node
before route validation runs, so the first submit succeeds. Keep the optimistic select for instant
feedback, just gate the *submit*.

**Defense-in-depth — make route validation read the activated doc, not only the per-node shadow:**
`handle_route_upsert` could overlay the **active config doc** upstreams (read via
`load_active_config_doc`, the same source the pool writers commit to) onto `effective_cfg`, instead of
relying solely on `writer.current_pools()`. The pool activation has already committed to the shared
doc, so doc-based validation is immediately consistent and not subject to per-node apply lag.
Caveat: this only removes the *validation* race — confirm the route's own apply can still resolve the
pool (pool shadow may land a beat later), else a freshly-created route could transiently 502 until the
pool shadow is built. Pair with apply ordering or a short converge wait if adopted.

**Cheapest — friendlier retry:** if `route_upsert` returns `unknown_upstream` but the named pool is
present in the active config doc, return a soft, explicitly-retryable error (e.g. "pool is still
propagating, retry in a moment") instead of the bare "not found", and/or auto-retry server-side after
a brief converge wait.

## Notes / caveats

- `waitForVersion` gates on `audit_chain_len >= expected` (`data.jsx:1505`), which tracks the
  connected node's activation. On the connected/single node this lines up with the local
  `current_pools()` rebuild; cross-node convergence is still surfaced separately by the
  non-blocking convergence pill (`notifyConfigConvergence`). Worth confirming the audit-chain bump
  and the `current_pools()` apply are on the same local path before relying on the UI-only fix alone.
- Related context: the existing in-handler comment at `admin_mutate.rs:5444` ("the boot-time `cfg`
  doesn't reflect pools added at runtime … read the live pool map from the writer's shadow") is
  exactly the shadow that lags here — it fixed the *boot-snapshot* staleness but not the
  *activation→apply* window.
