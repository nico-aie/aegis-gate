# BUG — console route add/edit/delete does not converge across the fleet

- **Type:** BUG (config-plane / cluster convergence)
- **Severity:** 🔴 HIGH — breaks the leaderless "any node manages the whole fleet" guarantee for routing; LB-fronted traffic to a console-added route is non-deterministically correct, and the change is non-durable on the originating node.
- **Status:** 🔴 Open
- **Found:** 2026-06-14, pre-prod 3-node deployment (operator + QC)
- **Area:** Dashboard → Routing & Upstreams; route-CRUD path (`PUT`/`DELETE /api/routes/{id}`), `config:waf:doc`.

## Symptom

A route added (or edited/deleted) through the **console** takes effect **only on the
node that handled the console request**. Behind the round-robin LB this surfaces as
**intermittent misrouting** — the route works for the ~1/N of requests that land on the
mutating node and falls through to the catch-all on every other node.

- Added `* · /sec (prefix) → sec-pool (47.131.73.23:80)`, tier LOW, via the console
  (page shows `LIVE · AUDIT-MUTATED`).
- `https://<VIP>:56208/sec` returns the **catch-all** upstream (`http-pool` → mock `:9991`
  echo) for ~⅔ of calls and the real `sec-pool` backend for ~⅓ — i.e. one node in three.

Direct `GET /sec` to each node's `:8443` (bypassing the LB):

| node | `/sec` result | has route? |
|---|---|---|
| waf-infra-1 (10.20.0.72, the console-attached node) | real backend (sec-pool) | **yes** |
| waf-2 (10.20.0.21) | mock echo (catch-all) | **no** |
| waf-3 (10.20.0.40) | mock echo (catch-all) | **no** |

Crucially, **all three report the same applied version** (`infra=101, waf-2=101,
waf-3=101`) yet only infra has the route. No reload error in the watcher logs.

## Root cause (confirmed in code)

**Routes are the only config domain whose console mutation skips the versioned shared
config doc.** Every other mutation serializes into `config:waf:doc` and activates with a
pub/sub nudge; the route handlers instead do a bare **local** in-memory swap.

- `handle_route_upsert` (`crates/aegis-proxy/src/admin_mutate.rs:5518-5520`) applies via
  `services.mutate.apply(&req_ctx, …, move || writer_for_apply.apply(&next_cfg))`. That
  `RouteWriter` is the proxy's live `RouteTable` (`run.rs:1962-1963`), whose `apply`
  (`crates/aegis-proxy/src/route/mod.rs:119-124`) only does
  `self.inner.store(Arc::new(compiled))` + `self.raw.store(...)` — an **atomic swap of
  the originating node's `ArcSwap<CompiledRouteTable>`**. `handle_route_delete`
  (`admin_mutate.rs:5537+`) is the same shape.
- No `load_active_config_doc`, no `config:waf:doc` write, no `cas_set`, no version bump,
  no `config_nudge`. So peers have **nothing new to converge to**, and the version never
  moves (→ stuck at 101 on every node).
- Contrast the pool path (`admin_mutate.rs:472-527`): `load_active_config_doc` → patch
  the blob (`patch_upstream_pool_set`) → re-validate → `store.activate(expected, blob, …)`
  via `mutate.apply_async`, which CAS-bumps the doc and fires the nudge. Rules
  (`:2711`), tiers (`:4534`), detector mask (`:3889`), and alert receivers (`:776`) all
  follow this same pattern.

**The convergence machinery for routes already exists and is simply never fed.** The
redis config-plane watcher re-derives the route table on every doc version it sees —
`apply_cfg_change_to_routes(new_cfg, targets.proxy_ctx)` at
`crates/aegis-proxy/src/config_source/redis_source.rs:242` (which calls
`reload::apply_cfg_change_to_routes`, `config_source/reload.rs:608-616`, rebuilding the
`RouteTable` from `new_cfg.routes` and atomic-swapping). Because the mutation handler
never writes the versioned doc, no nudge fires and this rebuild never runs on the peers.

> Note: routes are **not** in the `apply_folded_stores` bundle
> (`reload.rs:539-551`, which covers AI / response-filter / tiers / rules / upstreams /
> copilot) — they ride the watcher's separate inline `apply_cfg_change_to_routes` call.
> So the redis-plane path covers routes; only the **write side** (mutation → doc) is missing.

### Corollary — non-durable on the mutating node

Because the route never reaches `config:waf:doc`, it is lost on the originating node's
next restart: the route table rebuilds from boot `waf.yaml` (which has only
`ws/grpc/catch-all`) plus whatever the watcher re-derives from the doc — neither of which
contains the console-added route. We restart nodes on every Ansible redeploy, so this
compounds.

## Impact

- **HIGH** — console route add/edit/delete is not fleet-consistent; the leaderless "any
  node manages the whole fleet" guarantee is violated for routing.
- LB-fronted traffic to a console-added route is **non-deterministically** correct (works
  ~1/N of the time, N = node count).
- **Non-durable** across restart on the mutating node.
- Erodes trust in the console: the page shows the route `LIVE` while peers silently serve
  the catch-all; operators cannot tell their change didn't land fleet-wide.

## Workaround (deliberately NOT the fix)

Putting the route in the Ansible-templated `waf.yaml` (boot config on every node) makes
it consistent + durable — but that defeats console route management and is not viable for
runtime operator edits. **Not applied**; raising the bug so console mutations converge.

## Suggested fix

1. **Route the route-CRUD mutation through the versioned config-plane path**, exactly like
   the pool/rule/tier handlers. In `handle_route_upsert` / `handle_route_delete`:
   `load_active_config_doc(services)` → patch the doc blob's `routes:` array (new helper,
   e.g. `patch_routes_set` / `patch_route_remove`, mirroring `patch_upstream_pool_set`) →
   re-validate via `load_config_str` → `store.activate(expected, blob, …)` through
   `services.mutate.apply_async` with `.with_nudge(services.config_nudge.clone())`. Every
   node's watcher then re-derives via the existing `apply_cfg_change_to_routes`
   (`redis_source.rs:242`) and the change is durable. Keep the live `RouteWriter` swap only
   as optional instant local feedback for the originating node — or drop it and let that
   node's own watcher pick the nudge up (the pool path relies wholly on the watcher).
   - Preserve current validation: `validate_route` against `effective_cfg`
     (`admin_mutate.rs:5450-5461`) and the last-catch-all guard in delete
     (`admin_mutate.rs:5577`) must still run before activate.
2. **Fleet drift indicator** — surface per-node applied-version + a route-table hash so the
   console shows "not yet converged on waf-2/waf-3" instead of a flat `LIVE`. Pairs with the
   `config:waf:applied:<node>` ACKs and the existing N2 "Applied on N/N nodes" pill.
3. **Regression test** — in a 2+ node in_memory/redis cluster, add a route on node A and
   assert node B serves it within the convergence SLA; assert the doc version bumps and the
   route survives a simulated restart of node A.

## Repro

1. 3-node fleet, shared Redis, leaderless cluster, LB round-robin in front.
2. Add a prefix route (e.g. `/sec → some-pool`) via the console on node A.
3. `GET /sec` directly on node B → catch-all (route absent), while node A serves it.
4. Compare `applied shared config version` across nodes — same number, different routes.

> **Field sighting (2026-06-14):** an operator created a route via the console, then tested
> `/<prefix>` through the VIP and saw it hit the **catch-all** instead of the chosen pool, and
> initially suspected the "Strip route prefix" toggle. That toggle is a red herring — `strip_prefix`
> only rewrites the forwarded path, never matching (`route/mod.rs:614-628`). The catch-all miss is
> this convergence bug: the LB round-robined the test onto a peer that never received the route.
> (The toggle had its own unrelated display defect — see
> [`BUG-route-strip-prefix-toggle-not-roundtripped.md`](./BUG-route-strip-prefix-toggle-not-roundtripped.md).)

## Related

- Sibling config-plane race on the route flow: [`BUG-create-route-pool-not-found-race.md`](./BUG-create-route-pool-not-found-race.md)
  (optimistic dropdown vs async pool apply). Different defect — that one is per-node apply
  *lag*; this one is routes never reaching the doc at all — but both live in the route-CRUD
  console path and would benefit from the same "gate on `waitForVersion` / converge" UX.
- Convergence + "Applied on N/N nodes" plumbing this fix reuses: N2 in
  [`archived/FIX-cluster-qc-2026-06-11-V2.md`](./archived/FIX-cluster-qc-2026-06-11-V2.md).
