# BUG — "Strip route prefix when forwarding" toggle does not round-trip (always reopens checked)

- **Type:** BUG (dashboard ↔ API state correctness)
- **Severity:** 🟡 Medium — the *applied* value is correct, but the console always re-displays
  the box as checked, so a later edit silently re-enables stripping the operator had turned off.
- **Status:** 🔴 Open
- **Found:** 2026-06-14 (Nico, console use)
- **Area:** Dashboard → Routing & Upstreams → **Add/Edit route → "Strip route prefix when
  forwarding"** checkbox; `GET /api/routes` response shape.

## Symptom

1. Edit a route, **uncheck** "Strip route prefix when forwarding", **Save** (succeeds).
2. Reopen the same route in the modal → the box is **checked again**, as if the change
   never took.

(The reporter also noticed the box auto-checks on **new** route create — that part is correct;
`strip_prefix` defaults to `true` server-side and in the draft. The defect is that an explicit
**false never displays back**.)

## Root cause (confirmed in code)

`GET /api/routes` omits `strip_prefix` entirely, so the dashboard can't tell a saved-`false`
route from a default-`true` one and falls back to `true`.

- The response struct **`RouteSummary`** (`crates/aegis-control/src/api/routes.rs:41-70`) has
  no `strip_prefix` field — it carries id / host / path / match_type / methods / upstream /
  tier_override / priority / default / enabled, and nothing else.
- `route_summaries` (`crates/aegis-proxy/src/route/mod.rs:259`, builder at `:285`) therefore
  cannot emit it; the field is dropped on the way out even though the live `RouteConfig`
  (`aegis-core/src/config.rs:1538-1539`) holds the real value.
- The dashboard reads it back with `strip_prefix: r.strip_prefix !== false`
  (`crates/aegis-control/assets/dashboard/src/pages.jsx:13969`). With the field absent,
  `undefined !== false` evaluates to **`true`**, so every route re-opens with the box checked.

**Secondary impact (not just cosmetic):** `routeBodyFromDraft`
(`pages.jsx:13987-13989`) always sends `strip_prefix: d.strip_prefix !== false`. Because the
modal re-opened with the box (wrongly) checked, the *next* save on that route — even for an
unrelated field — submits `strip_prefix: true`, **silently re-enabling stripping the operator
had disabled.** The write path itself is fine: `RouteConfigPatch.strip_prefix`
(`api/routes_config.rs:59-60`) deserializes the flip and `into_route` (`:132`) persists it;
the value is correct until the stale-checked modal clobbers it on a subsequent edit.

## Impact

- The toggle's "off" state is invisible in the console and not durable across an edit cycle.
- Operators can't trust what the box shows; an unrelated edit can revert path-stripping
  behaviour for the route without any indication.
- Affects every route regardless of cluster size (pure read/serialize defect; orthogonal to
  the fleet-convergence bug).

## Not the cause of the "goes to catch-all" misroute

The reporter saw a new route's `/prefix` test land on the **catch-all** instead of the chosen
pool, and wondered if the strip toggle was responsible. It is **not**: `strip_prefix` only
drives the forward-path rewrite (`compile_path_strip_prefix`,
`crates/aegis-proxy/src/route/mod.rs:614-628` — `strip_prefix == false → None`, path-preserving)
and has **no effect on route matching**. That misroute is the fleet-convergence defect —
the route applied only on the console-attached node and the LB sent the test to a peer that
lacked it. See [`BUG-console-route-mutation-not-fleet-convergent.md`](./BUG-console-route-mutation-not-fleet-convergent.md).

## Suggested fix

1. **Add `strip_prefix` to `RouteSummary`** (`api/routes.rs`), defaulting to `true` on deserialize
   to match `default_strip_prefix` for legacy/older clients — mirror the existing
   `#[serde(default = "default_route_summary_enabled")] enabled` pattern:
   ```rust
   #[serde(default = "default_strip_prefix_summary")]
   pub strip_prefix: bool,
   // fn default_strip_prefix_summary() -> bool { true }
   ```
2. **Populate it in `route_summaries`** (`route/mod.rs:285`): `strip_prefix: r.strip_prefix`
   (read off the migrated `RouteConfig`). Update the unit-test fixtures in `routes.rs` /
   `route/mod.rs` that build `RouteSummary` literals.
3. The dashboard already handles it correctly (`routeToDraft`/`routeBodyFromDraft`); once the
   field is present, `r.strip_prefix !== false` reflects the real saved value with no JS change.
4. **Regression test:** save a route with `strip_prefix: false`, `GET /api/routes`, assert the
   summary carries `strip_prefix: false` (and that an unrelated re-save preserves it).

## Repro

1. Add or edit a route with `match_type: prefix`, `path: /foo`.
2. Uncheck "Strip route prefix when forwarding", Save.
3. Reopen the route → box is checked again. (Confirm via `GET /api/routes`: no `strip_prefix`
   key in the route object.)
