# Routing & Upstreams — UX + feature improvements

> **Status:** Drafted 2026-06-04. Backlog of improvements for the
> **Routing & Upstreams** dashboard page (`PageUpstreams` in
> `crates/aegis-control/assets/dashboard/src/pages.jsx`) and its backing
> config-plane CRUD (`aegis-control/src/api/{routes_config,upstreams_config}.rs`,
> `aegis-proxy/src/admin_mutate.rs`). Slots under the roadmap's
> data-plane track.
>
> **Selected for first implementation (2026-06-04):** #1 **live member
> health on the page**, #2 **member connectivity probe**, #3 **route
> priority + shadow detection**. Everything else (#4–#9) is deferred to
> **far future** — see [Sequencing](#sequencing).

## Where it stands today (code-verified 2026-06-04)

The page is already mature. **Don't re-build what exists:**

- **Routes table** — search/filter (id/host/path/pool), per-route 60s
  activity pill (`/api/analytics/route-activity`), expand-to-detail,
  add/edit/delete, **Test-route resolver** (`POST` route-test → which
  route a synthetic host+method+path resolves to, with the priority
  tuple), delete guards (`last_catchall`, pool `referenced_by_routes`
  409), "How it works" orientation card, live `audit-mutated` pill.
- **Pool editor** (`PoolEditModal`) — members (`addr` / `weight` /
  `zone` / `host_header`), 5 LB strategies (round_robin /
  weighted_round_robin / least_conn / consistent_hash / p2c), health
  check (path/interval/timeout + toggle), circuit breaker
  (error_rate_threshold / open_duration + toggle), connection tuning
  (scheme / keep_alive / idle_timeout / max_idle_per_host / TLS).
- **Orphan-pool** panel (collapsed), inline "+ Create new pool" from the
  route modal, page-level "+ Add pool".
- Both routes + pools are **folded into the config plane** (hot-swap, no
  restart; `apply_cfg_change_to_{routes,upstreams}`).

## Gaps & suggestions

### UX (highest value first)

1. **Live member health is invisible on the page.** ★★★
   The API already computes it (`api/upstreams.rs` `PoolHealthEntry`
   `healthy`/`total`, member `is_healthy()`, circuit state), and the
   **Overview** tile shows the aggregate — but the page where you
   *manage* pools renders members as a plain `addr` list. An operator
   can't see which backend is down or which member's circuit is open.
   - **Add a health dot + "2/3 healthy" chip per pool** in the route
     row + pool editor; red/amber/green from the summary API.
   - **Show circuit state** (closed / open / half-open) + last-probe age
     per member in the expanded route detail.
   - Wire from the existing `useUpstreamsApi()` summary (already polled);
     no new backend.

2. **No "probe member now" / connectivity test in the pool editor.** ★★
   You can author a member but can't validate it resolves + connects
   before saving. The Test-route tool resolves *routing* only, not the
   upstream. Add a per-member "Test" button → a read-only admin endpoint
   that does a one-shot connect (+ optional health-path GET) and reports
   DNS/TCP/TLS/HTTP status. Pairs with the hostname-addressed-member
   feature (catch a typo'd `addr` before traffic does).

3. **Route priority / shadowing is opaque.** ★★
   The table is "sorted by priority" but doesn't show the priority per
   row or *why* route A precedes B. Worse: a route that can never match
   (a broader prefix above it already catches everything) is silent.
   - Show the **priority tuple** inline (it's already in the route-test
     result + the `RouteView.priority` field).
   - Flag **shadowed routes** ("unreachable — `catch-all` at higher
     priority matches first") — compute client-side from the sorted set.

4. **No import / export.** ★
   Every route/pool is a one-at-a-time modal. For non-trivial configs add
   **Export** (routes+pools → YAML, reuses `waf snapshot` shape) and
   **Import** (paste/upload → diff preview → audit-mutated apply). Big
   win for migrating or templating environments.

5. **Weighted LB has no visual.** ★
   `weighted_round_robin` exposes per-member `weight` but no preview of
   the resulting traffic split. Render a tiny stacked bar of effective
   %s in the pool editor.

### Features (align the UI with data-plane capabilities already in code)

6. **Per-route traffic management is not exposed.** ★★★
   The data plane ships `aegis-proxy/src/traffic.rs` (canary, steering,
   shadow mirror, retries) but the folded `RouteDef`
   (`routes_config.rs`) carries none of it — so it's YAML-only and
   **not editable live**. Extend `RouteDef` + the route editor with:
   - **Canary** — split a route across two pools by weight (progressive
     rollout) with a live % control.
   - **Per-route timeout + retry policy** (count, backoff, retriable
     status set).
   - **Shadow mirror** — duplicate matched traffic to a second pool,
     responses discarded (safe prod testing).
   Fold them through `apply_cfg_change_to_routes` so they hot-reload.

7. **Per-route rate-limit / quota binding.** ★★
   `aegis-proxy/src/quota.rs` exists but isn't bound per route from the
   editor. Add a "rate limit" section to the route editor (requests/window
   + burst) writing the per-route quota.

8. **Request/response header transforms per route.** ★★
   `transform/{cors,vars}.rs` exists; surface add/set/remove header rules
   + a CORS preset in the route editor (common operator ask — inject
   `X-Forwarded-*`, strip hop-by-hop, set CORS).

9. **Member drain / soft-disable.** ★★
   For maintenance, let an operator **drain** a member (stop new traffic,
   let in-flight finish) without deleting it — a per-member toggle in the
   pool editor backed by a "disabled"/"drain" member state the LB skips.
   Cleaner than delete-then-re-add.

## Sequencing

### Near-term — selected for first implementation (2026-06-04)

The chosen batch. All three are low-risk (no `RouteDef` schema change),
reuse existing APIs/health data, and directly improve day-one operability.

1. **#1 Live member health on the page** — health dot + "N/M healthy"
   chip per pool + circuit state per member, from the existing
   `useUpstreamsApi()` summary. UI-only.
2. **#2 Member connectivity probe** — per-member "Test" → a read-only
   admin endpoint doing a one-shot DNS/TCP/TLS/HTTP probe. Small backend
   endpoint + a button.
3. **#3 Route priority + shadow detection** — show the priority tuple
   inline (already in `RouteView.priority`) and flag unreachable
   (shadowed) routes, computed client-side from the sorted set. UI-only.

   *Suggested order:* #1 → #3 (both UI, ship together) → #2 (adds the
   probe endpoint).

### Far future — deferred (not scheduled)

Kept as valid designs; revisit after the near-term batch lands.

- **#4** Import / export (routes+pools YAML).
- **#5** Weighted-LB traffic-split visual.
- **#6** Per-route traffic management (canary / retry / shadow mirror) —
  **requires extending the folded `RouteDef`** (new fields all
  `#[serde(default)]` so old configs still parse, mirroring the
  detectors/rules fold).
- **#7** Per-route rate-limit / quota binding.
- **#8** Per-route request/response header transforms + CORS preset.
- **#9** Member drain / soft-disable.

## Risks / notes

- Extending `RouteDef` is a **config-plane schema change** — keep every
  new field optional + defaulted so existing stored docs + YAML keep
  loading (same discipline as the detectors/rules folds).
- Live-health rendering must degrade gracefully when `state.backend =
  in_memory` (single-node) vs redis (cluster-aggregated) — reuse the
  Scaling page's pattern.
- Traffic-management features touch the hot path; gate behind the
  existing per-route resolution and keep them off by default.
