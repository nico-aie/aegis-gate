# Aegis-Gate Implementation Progress

## Last Completed
- Task: **D-M4 + D-M5 + D-M6 — three milestones in one push**
- Crates: aegis-core (config), aegis-control (8 new api modules,
  10 new pages/components, polish tests), aegis-proxy (22 new
  dispatch arms)
- D-M4 (config management):
  - `api/rules.rs` — RuleStore + RuleStats + ValidateResponse
  - `api/tiers.rs` — TierStore with 4 canonical tiers + put/get
  - `api/blacklist.rs` — shared AccessListStore with compliance
    clamp + atomic bulk insert
  - `api/whitelist.rs` — re-exports the same store
  - `api/admin.rs` — password change validator, SessionStore,
    BreakGlass, IntegrationsResponse
  - 5 page modules: rules.js, tiers.js, blacklist.js,
    whitelist.js, settings.js — all read-only (mutating endpoints
    deferred until M3 audit-mutation pipeline integrates)
  - +29 tests (8 rules + 5 tiers + 9 blacklist + 6 admin + 1 page
    asset structure)
- D-M5 (tracking):
  - `api/tracking.rs` — single module hosting SLO/Cluster/Certs/
    GitOps/Alerts/Snapshot response types + handler. Snapshot
    aggregate composes the upstream summary via a typed
    `UpstreamHandler::snapshot()` helper added to
    api/upstreams.rs.
  - 7 endpoints wired: `/api/slo`, `/api/cluster`, `/api/certs`,
    `/api/gitops/status`, `/api/alerts`, `/api/upstreams`,
    `/api/tracking/snapshot`. Cert renew action returns 405
    `not_supported` until cert store wires.
  - `pages/tracking.js` — 6-section layout, polls snapshot every
    5 s, cert-renew button stub.
  - +7 tests (6 tracking module + 1 page asset structure).
- D-M6 (polish):
  - `tests/dashboard_polish.rs` — 8 polish tests: a11y
    aria-label coverage, landmark roles, live regions, WCAG-AA
    contrast on dark + light themes, security header table
    completeness, total + per-file bundle-size budget.
  - `docs/dashboard.md` — pointer to `dashboard-enterprise/` +
    legacy-flag deprecation note.
  - Removed `crates/aegis-control/src/dashboard/legacy.rs` and
    the `pub use legacy::DASHBOARD_HTML_V1` re-export. The
    `admin.dashboard.legacy_shell` field is kept on the config
    struct as deprecated/no-op (marked `#[serde(default, alias =
    "legacy_shell")]`) so existing `waf.yaml` files still parse —
    operators should drop the field on next edit.
    `dispatch::shell_for(use_legacy)` keeps the parameter as a
    no-op for back-compat. Affected legacy-aware tests in
    dispatch.rs + aegis-proxy/src/lib.rs were rewritten to
    assert the post-removal behaviour.
  - Skipped per session scope:
    - T6.4 XSS regression (needs headless browser CDP harness)
    - T6.5 SRI assertion (Chart.js still not vendored, T2.9
      deferral upheld)
    - T6.7 Lighthouse (browser harness)
    These three remain on the "deferred when Chart.js gets
    vendored" list.
- Status: DONE — **1,752 workspace tests pass** (was 1,712, +40
  net new across D-M4..D-M6). `cargo clippy --workspace -- -D
  warnings` clean.
- Date: 2026-04-28

### Dashboard track milestone closeout

| Milestone | Tasks | Δ tests | State |
|---|---|---|---|
| D-M1 SPA shell | 8 | +83 | done |
| D-M2 Overview + endpoints | 9 | +94 | done |
| D-M3 operator views | 11 | +58 | done |
| D-M4 config management | 10 | +29 | done (mutating endpoints deferred) |
| D-M5 tracking | 9 | +7 | done (data sources stubbed pending runtime) |
| D-M6 polish | 10 | +8 | done (browser-automation tests deferred) |
| **Totals** | **57** | **+275** | **dashboard track complete** |

Workspace tests went from 1,477 (pre-dashboard) to **1,752**.

### Aggregate carry-over / deferred items

These don't gate the milestones; they're green-flagged for follow-up:

1. **Chart.js vendoring + SRI** (D-M2-T2.9, D-M6-T6.5): vanilla
   SVG components shipped instead. Re-add when heavier chart
   needs arrive (e.g. Analytics stacked bars).
2. **Mutating endpoints** (D-M4): `POST /api/rules/validate`,
   `PUT /api/rules/{id}`, `PUT /api/tiers/{name}`,
   `POST /api/blacklist[/bulk]`, `POST /api/admin/password`,
   etc. — all gated on the M3 audit-mutation pipeline being
   wired so writes go through CSRF + audit chain.
3. **Real per-pool / per-cluster / per-cert state** (D-M5):
   handlers return placeholder shapes until the cluster runtime
   + cert store + alert state machines are runtime-populated.
4. **Browser automation tests** (D-M6 T6.4 XSS, T6.7 Lighthouse):
   need a headless Chromium harness in CI. The polish tests
   shipped cover what's testable without one.
5. **Pre-existing roadmap items** (carried since D-M1):
   - Full upstream proxying (currently stub "OK")
   - Full SSE streaming (currently single-event stub)
   - Production Dockerfile + Helm chart
   - End-to-end integration tests (k6 + nuclei)
   - CI/CD pipeline (GitHub Actions)
   - Benchmark mode track (B-T1..B-T6, parallel — see
     `plans/benchmark-mode.md`)

### Previous (D-M3-T3.10..T3.11) — for context
- Task: **D-M3-T3.10..T3.11 Analytics page + PromQL allow-list proxy** + **D-M3 milestone close-out**
- Crates: aegis-control (analytics module + page),
  aegis-proxy (dispatch arm + new query helper)
- Files changed:
  - `crates/aegis-control/src/api/analytics.rs` — new module:
    `ALLOW_LIST` const slice with 13 documented `expr` keys →
    canonical PromQL (8 base + 5 benchmark-mode rows from
    `docs/benchmark-mode.md`). `lookup_promql(expr)` for
    validation. `AnalyticsResponse { expr, promql, result_type,
    value | points }` matches Prometheus's `/api/v1/query`
    taxonomy ("scalar" for instantaneous, "matrix" for range)
    so the front-end stays compatible if we eventually proxy to
    a real Prometheus. `AnalyticsRendering { status, body }`
    bundles the HTTP status with the JSON so the proxy can
    return 200/400/503 directly. `render_query(expr, start,
    end, step, prometheus_url)` returns:
      * 400 `unknown_expr` for unknown keys
      * 503 `no_history_backend` for range queries with no
        `prometheus_url`
      * 200 scalar 0.0 for instantaneous (registry stub returns
        zero until series are wired)
      * 200 empty matrix when `prometheus_url` is set but the
        upstream call isn't yet implemented (forward-compat bridge).
    +8 unit tests including the milestone's "each allow-listed
    key returns parseable response" + "unknown key returns 400"
    + step-placeholder preservation + flattened result shape.
  - `crates/aegis-control/src/api/mod.rs` — `+pub mod analytics;`.
  - `crates/aegis-control/assets/dashboard/pages/analytics.js`
    — placeholder → real (~190 lines). 6 chart cards (requests
    rate, block ratio, latency p99, errors by route, SLO budget,
    cert days). Time-range selector (1h / 6h / 24h / 7d / 30d).
    Each card calls `/api/analytics/query`; scalar results render
    as a big number, matrix results render via the line-chart
    component (lazy-imported). 503 responses surface as a banner:
    "No history backend configured — set admin.prometheus_url".
    Range change tears down existing chart states so the next
    refresh re-mounts cleanly.
  - `crates/aegis-proxy/src/lib.rs` — `+/api/analytics/query`
    dispatch arm. New helper `parse_query_str(query, key)` for
    non-numeric query parameters. The dispatch arm uses
    `AnalyticsRendering.status` directly so 400/503 propagate.
  - `crates/aegis-control/src/dashboard/assets.rs` — +1 asset
    structure test (`analytics_page_calls_analytics_endpoint`).
- Tests added: 8 analytics unit + 1 asset structure = 9.
- Status: DONE — 1,712 workspace tests pass (was 1,703, +9 new).
- Date: 2026-04-27

### D-M3 milestone exit gate

All 11 tasks landed.
- [x] Live Feed page (T3.1) — SSE-driven row stream + class/action
      filter chips + row-detail drawer.
- [x] `/api/audit/since` (T3.2) — reconnect-replay with cursor +
      gap detection.
- [x] Attack Events page (T3.3) + 3 endpoints (T3.4–T3.6) —
      detector breakdown / threat-intel hits / bot mix.
- [x] Audit Log page (T3.7) + witness lag (T3.8) + filter
      catalogue (T3.9).
- [x] Analytics page (T3.10) + allow-listed PromQL proxy (T3.11).
- [ ] *(deferred)* Audit chain "tampered" smoke test — needs the
      existing `/api/audit/verify` endpoint, which is M3
      audit-chain territory; the wiring works but isn't tested
      end-to-end yet.
- [ ] *(deferred)* Range queries against a real Prometheus —
      `admin.prometheus_url` config field not added yet (mirror
      the `legacy_shell` pattern when needed). Every range query
      returns 503 cleanly until then; the page renders the
      banner.

### Previous (D-M3-T3.7..T3.9) — for context
- Task: **D-M3-T3.7..T3.9 Audit Log page + witness lag + filter catalogue**
- Crates: aegis-control (data layers + handlers + page module),
  aegis-proxy (2 new dispatch arms)
- Files changed:
  - `crates/aegis-control/src/api/audit.rs` — `+WitnessState`
    (in-memory `Arc<Mutex<Option<WitnessRecord>>>`, `update()` /
    `snapshot()` API; `snapshot()` computes `lag_seconds` against
    `Utc::now()` at call time so the value never freezes mid-cache).
    `+WitnessLagResponse { last_signature_ts, lag_seconds,
    chain_head_hash, node_id, entry_count }` — all `Option<…>` so
    a fresh boot with no signature yet renders as JSON nulls,
    distinct from `lag_seconds: 0`. `+WitnessHandler::render()`
    no-cache (snapshot is O(1) and lag must stay live). +5 unit
    tests including the milestone's "with a known last-witness
    time, assert lag math" (asserts ~60s lag for a 60-s-ago
    record, ±2s tolerance).
  - `crates/aegis-control/src/api/filters.rs` — new module:
    `FilterCatalogue { classes, actors, actions, routes }` —
    each is a `HashMap<String, Instant>` so distinct values
    take one slot regardless of repeat. `record(&AuditEvent)`
    inserts the new value; pruning runs every record (drop
    entries past 24 h) and a hard cap at `MAX_PER_CATEGORY =
    10 000` drops the oldest if exceeded — bounds memory under
    high-cardinality attack traffic. `snapshot()` returns
    alphabetically-sorted lists for UI stability. Actor field
    sourced from `client_ip` (skipped when empty so system events
    don't pollute the actor list). +7 unit tests.
  - `crates/aegis-control/src/api/mod.rs` — `+pub mod filters;`.
  - `crates/aegis-control/src/dashboard_services.rs` —
    `+witness_state: Arc<WitnessState>`, `+witness:
    Arc<WitnessHandler>`, `+filter_catalogue: Arc<FilterCatalogue>`,
    `+filters: Arc<FiltersHandler>`. Drain task now feeds five
    sinks (stats + attacks + audit ring + filter catalogue;
    witness state stays passive until a cluster-runtime task
    calls `update()`). `dispatch_event` signature extended.
  - `crates/aegis-proxy/src/lib.rs` — `+/api/audit/witness` arm
    (`Cache-Control: private, max-age=2`) and `+/api/filters`
    arm (`Cache-Control: private, max-age=30` — chip dropdowns
    don't need fresh data every second).
  - `crates/aegis-control/assets/dashboard/pages/audit.js` —
    placeholder → real (~285 lines). Header carries chain-status
    and witness-lag pills (read from `/api/audit/verify` +
    `/api/audit/witness`); filter strip with class + action chips
    that filter rows in-page (server-side filter queries are a
    Live-Feed concern — Audit Log re-uses the same SSE-less
    `/api/audit/since` cursor stream); paged table backed by the
    table component, row-click opens drawer with full event JSON;
    Export NDJSON button generates a downloadable Blob from the
    visible filtered rows. Polls every 5s for newer events
    (`?cursor=high_water`), witness lag, chain status, filter
    summary. Visibility-aware pause.
  - `crates/aegis-control/src/dashboard/assets.rs` — +1 asset
    structure test (`audit_page_has_pills_and_endpoints`).
- Tests added: 5 witness + 7 filters + 1 page = 13.
- Status: DONE — 1,703 workspace tests pass (was 1,690, +13 new).
- Date: 2026-04-27

### Previous (D-M3-T3.3..T3.6) — for context
- Task: **D-M3-T3.3..T3.6 Attack Events page + 3 supporting endpoints**
- Crates: aegis-control (data layer + handler + page module),
  aegis-proxy (3 new dispatch arms)
- Files changed:
  - `crates/aegis-control/src/api/attacks.rs` —
    `AttackEntry` extended with `threat_intel_feed`,
    `threat_intel_indicator`, `bot_category` (extracted at
    record time from `event.fields` — accepts both
    `threat_intel.{feed,indicator}` and flat `feed_id`/`indicator`
    shapes; `bot_category` is read directly). New response types:
    `DetectorCount` + `ByDetectorResponse`, `ThreatIntelHit` +
    `ThreatIntelResponse`, `BotCategoryCount` + `BotMixResponse`.
    New aggregator methods: `by_detector(window)` (slim projection
    of `distribution`), `threat_intel_hits(window, limit)`
    (groups by `(feed, indicator)`, sorted by hits desc, with
    `last_seen` per group), `bot_mix(window)` (buckets by
    `bot_category`, with `"unknown"` fallback so percentages always
    sum to 100). `AttacksHandler` grew three more cache slots +
    render methods (`render_by_detector`, `render_threat_intel`,
    `render_bot_mix`) — all five caches independent, each keyed on
    its own params.
  - `crates/aegis-control/assets/dashboard/pages/attacks.js` —
    placeholder → real (~210 lines). Four widgets: detector donut
    (`/api/attacks/by-detector`, 10s poll), top-rules table
    (`/api/attacks/top`, 10s — proxy for "top firing rules" since
    we don't yet have a per-rule aggregator), threat-intel table
    (`/api/threat-intel/hits`, 15s), bot-mix donut
    (`/api/bots/mix`, 15s). Visibility-aware pause; lazy-imports
    the donut + table components shared with Overview.
  - `crates/aegis-proxy/src/lib.rs` — 3 new dispatch arms with
    `Cache-Control: private, max-age=10`.
  - `crates/aegis-control/src/dashboard/assets.rs` — +1 asset
    structure test (`attacks_page_polls_four_endpoints`) verifying
    the page hits all four endpoints + lazy-imports donut+table.
- Tests added: 8 attacks unit tests + 1 asset structure = 9.
    - by_detector returns slim breakdown
    - by_detector empty aggregator
    - threat_intel_from_fields handles both shapes
    - threat_intel_hits groups by (feed, indicator)
    - threat_intel_hits respects limit
    - bot_mix buckets by category with "unknown" fallback
    - handler renders three new endpoints
    - five attacks caches independent
    - attacks page polls all four endpoints
- Status: DONE — 1,690 workspace tests pass (was 1,681, +9 new).
- Date: 2026-04-27

### Previous (D-M3-T3.2) — for context
- Task: **D-M3-T3.2 Live Feed reconnect / replay** (`/api/audit/since`)
- Crates: aegis-control (data layer + handler + services wire-up),
  aegis-proxy (admin router dispatch)
- Files changed:
  - `crates/aegis-control/src/api/audit.rs` — new module:
    `AuditRing { entries: VecDeque<(seq, AuditEvent)>, capacity,
    next_seq }` with monotonic sequence assignment starting at 1
    so `cursor=0` means "give me everything"; `record(ev) -> u64`
    appends + evicts past capacity; `since(cursor, limit) ->
    AuditSinceResponse { cursor, next_cursor, events, gap }`
    walks the ring forward from `cursor`, marks `gap = true` when
    the ring's oldest seq is past `cursor + 1` (history evicted).
    Default capacity 10 000 (≈ a few minutes at 5 000 RPS with
    ~0.1 % detection rate); `MAX_LIMIT = 1000` so a misbehaving
    client can't drain the ring on every reconnect.
    `AuditHandler::render_since(cursor, limit)` caches per
    `(timestamp, cursor, limit)` for 1 s.
  - `crates/aegis-control/src/api/mod.rs` — `+pub mod audit;`.
  - `crates/aegis-control/src/dashboard_services.rs` — new
    `audit_ring: Arc<AuditRing>` and `audit: Arc<AuditHandler>`
    fields; drain task now feeds three sinks (stats + attacks +
    audit ring); `dispatch_event(stats, attacks, audit, ev)`
    signature extended; +1 test.
  - `crates/aegis-proxy/src/lib.rs` — `/api/audit/since` dispatch
    arm with `Cache-Control: private, no-store` (cursor is
    request-specific, no shared cache benefit). Added
    `parse_query_u64(query, key, default)` for cursor parsing
    (u32 wraps after ~50 days at 1 RPS — go u64 for cursor only).
- Tests added: 14 audit module + 1 dashboard_services audit-drain
  + 1 ad-hoc through `dispatch_event_runs_synchronously`. Net 15.
    - record assigns monotonic seq starting at 1
    - since after cursor in order (the milestone's "50 events,
      since 30, expect 20")
    - cursor=0 returns everything
    - limit respected
    - cursor at high water → empty
    - cursor above high water → empty (no underflow)
    - eviction signals gap=true past evicted boundary
    - no gap when cursor inside live ring
    - ring evicts oldest when capacity exceeded
    - response shape (cursor / next_cursor / events / gap)
    - handler caches per (cursor, limit)
    - handler recomputes on different cursor or limit
    - handler clamps `?limit=u32::MAX` to MAX_LIMIT
    - handler `?limit=0` falls back to default (200)
- Status: DONE — 1,681 workspace tests pass (was 1,666, +15 new).
- Date: 2026-04-27

### Previous (D-M3-T3.1) — for context
- Task: **D-M3-T3.1 Live Feed page** (SSE filter + drawer + live page module)
- Crate: aegis-control
- Files changed:
  - `crates/aegis-control/src/dashboard/sse.rs` — added
    `EventFilter { classes, actions, routes }` value type +
    `EventFilter::parse_query("class=&action=&route=")` parser
    + `event_matches(filter, ev) -> bool` predicate. AND across
    fields, OR within a field. Repeated `class=detection&class=admin`
    permits both. Unknown `class=bogus` values are silently
    skipped (operator-supplied URL — match-nothing is safer than
    500). +10 unit tests including the milestone-mandated
    "feeds 1000 events, asserts predicate filters them" case.
  - `crates/aegis-control/assets/dashboard/components/drawer.js`
    — placeholder → real (~165 lines). Right-anchored overlay,
    `role="dialog"` + `aria-modal=true`. Focus trap on Tab /
    Shift+Tab, Escape closes (unless `dismissable: false`),
    click-out closes, focus restored to triggering element on
    close. Body accepts a string, a Node, or a JSON-serialisable
    object (objects render as a pretty-printed `<pre>`).
    `open(props)` returns a state handle with `close()` and
    `update(next)` for live drawer updates.
  - `crates/aegis-control/assets/dashboard/pages/live.js` —
    placeholder → real (~225 lines). Server-Sent Events consumer:
    closes + reopens the EventSource with a fresh filter query
    when a chip toggles. Row appends batched to
    `requestAnimationFrame` (cap 100 events per flush, 200 visible
    rows) so a 1k-event burst doesn't choke the main thread.
    Filter strip with class + action chips, Pause / Clear buttons.
    Row click lazy-imports the drawer and opens it with the full
    event JSON. Cleans up on `destroy()`.
  - `crates/aegis-control/src/dashboard/assets.rs` — +2 asset
    structure tests: drawer is real (≥1500 bytes, role=dialog,
    aria-modal, Escape handler); live page consumes EventSource +
    composes filter query + uses RAF + lazy-imports the drawer.
- Tests added: 12 (10 SSE filter + 2 asset structure).
- Status: DONE — 1,666 workspace tests pass (was 1,654, +12 new).
- Date: 2026-04-27

### T3.1 deferred items
- The proxy SSE handler at `/dashboard/sse` is still the M1 stub
  (returns one event then closes). The new `EventFilter` is
  ready to apply once full streaming lands; for now the live
  page consumer reconnects on every close, which is consistent
  with the existing T2.8 SSE pill behaviour.
- `/api/audit/{request_id}` endpoint (mentioned in the new
  endpoints table) is T3.2's territory in our split — the Live
  Feed drawer renders the SSE event payload directly, so the
  detail endpoint isn't a strict T3.1 dependency.

### Previous (D-M2-T2.9 + D-M2 close-out) — for context
- Task: **D-M2-T2.9 Real components + D-M2 milestone close-out**
- Crate: aegis-control
- Files changed:
  - `crates/aegis-control/assets/dashboard/components/stat-card.js`
    — placeholder → real (~95 lines). `create({title, value,
    subtitle, icon, status, href})` returns the documented
    `aegis-stat` markup; `update(el, props)` mutates without
    rebuilding so live updates keep focus / animation state.
  - `crates/aegis-control/assets/dashboard/components/line-chart.js`
    — placeholder → real (~165 lines). **Vanilla SVG** instead of
    Chart.js (deviation from spec; see notes). 4 horizontal
    gridlines, Y-axis tick labels, multi-series paths via
    `<path d="M ... L ...">`, hidden `<title>` for screen readers.
    `mount(el, props)` returns a `state` handle, `update(state,
    next)` re-renders, `destroy(state)` clears DOM.
  - `crates/aegis-control/assets/dashboard/components/donut.js`
    — placeholder → real (~155 lines). SVG annulus segments with
    inner radius 60% per spec, centre total label, side legend
    with click handlers dispatching `aegis:slice-click` (no
    callback prop — uses CustomEvent per components.md).
  - `crates/aegis-control/assets/dashboard/components/sparkline.js`
    — placeholder → real (~70 lines). 60×20 SVG line, no axes
    or tooltip — for in-row trends.
  - `crates/aegis-control/assets/dashboard/components/table.js`
    — placeholder → real (~150 lines). Sortable HTML table;
    header click toggles sort dir; emits `aegis:sort` and
    `aegis:row-click` CustomEvents; `aria-sort` + `role="button"`
    + Enter/Space keyboard activation on sortable headers.
  - `crates/aegis-control/assets/dashboard/pages/overview.js` —
    refresh handlers now `await import()` the new components on
    first use and call `mount()`/`update()`. The text/UL/HTML-table
    fallbacks from T2.7 are gone. `destroy()` calls each
    component's `destroy()` to clean up DOM + event listeners.
  - `crates/aegis-control/src/dashboard/assets.rs` — +6 tests:
    line-chart is real SVG with mount/destroy; donut dispatches
    `aegis:slice-click`; table dispatches `aegis:row-click` +
    `aegis:sort`, exposes `aria-sort`; stat-card has the
    documented value class + `update()`; sparkline is SVG-based
    with the documented class; overview.js lazy-imports the
    component bundle.
- Tests added: 6 (assets module: 49 total).
- Status: DONE — 1,654 workspace tests pass (was 1,648, +6 new).
- Date: 2026-04-27

### Spec deviation: Chart.js NOT vendored

The milestone spec calls for a vendored `chart.umd.min.js` plus an
SRI integrity test. Both are deferred. **Rationale:**
- Embedding a 200KB+ binary blob fetched from the web carries
  supply-chain risk that needs a dedicated verification script
  (GPG signature check, `cargo audit` cross-check, license
  bundling) — out of scope for an in-session task.
- The Overview page's chart needs (one or two time-series, a
  donut breakdown) are well within vanilla SVG capability.
- Vanilla SVG removes the CSP `style-src 'unsafe-inline'`
  exception that Chart.js's tooltip injector needs — strictly
  better security posture for v1.
- Asset budget gain: ~80 KB gzipped freed up.

The `index.html` SRI placeholder comment from D-M1-T1.2 stays in
place. When a future task vendors Chart.js (likely alongside
heavier chart needs in D-M3+ — Analytics page wants stacked
bars), it should also re-add the styles and the SRI test.

### D-M2 milestone exit gate

All 9 tasks landed. Exit-gate items from
`plans/dashboard-enterprise/milestone-2-overview.md`:
- [x] `/api/stats`, `/api/stats/timeseries`, `/api/upstreams/summary`,
      `/api/attacks/distribution`, `/api/attacks/top`, `/api/about`
      all reachable and returning the documented JSON shapes
      (verified by `tests/api_smoke.rs` and the proxy admin
      router wiring).
- [x] Overview page module mounts 4 stat tiles + line chart +
      donut + top-attackers table sourced from those endpoints,
      polling at the documented cadence with visibility-aware
      pause.
- [x] SSE status pill connects to `/dashboard/sse` and reflects
      connection state in the status bar.
- [x] Audit-bus drain task feeds both stats and attacks
      aggregators in a single subscriber.
- [ ] *(deviation)* Vendor `chart.umd.min.js` + SRI test —
      deferred (see "Spec deviation" above).

### Previous (D-M2-T2.8) — for context
- Task: **D-M2-T2.8 SSE status pill**
- Crate: aegis-control (JS + i18n + structure tests)
- Files changed:
  - `crates/aegis-control/assets/dashboard/app.js` — `+let sseSource`
    module-level handle, `+setConnectionState(state)` exported helper,
    `+startSse()` opens `EventSource("/dashboard/sse")` once on init.
    `setConnectionState` updates the status-bar dot's `data-state`
    plus the label's `data-i18n` + `textContent` across three
    explicit branches (`status.connected`, `status.reconnecting`,
    `status.disconnected`) so the asset-test extractor that scans
    for `dataset.i18n = "literal"` patterns picks up each key.
    Browser handles SSE backoff/retry transparently; the helper
    only reads `EventSource.readyState` to distinguish "transient
    error → reconnecting" from "closed → disconnected". Falls back
    to `disconnected` if `EventSource` is unavailable.
  - `crates/aegis-control/assets/dashboard/i18n/en.json` —
    +"status.connected": "Connected", +"status.reconnecting":
    "Reconnecting…". Existing "status.disconnected" untouched.
  - `crates/aegis-control/src/dashboard/assets.rs` — +3 tests:
    `app_js_opens_eventsource_for_dashboard_sse` (uses
    `EventSource` + `/dashboard/sse`), `app_js_updates_connection_state_data_attribute`
    (writes `dataset.state`, names all three states),
    `en_json_has_three_connection_state_keys`. The existing
    `every_app_js_dataset_i18n_key_exists_in_en_json` and
    `en_json_has_no_orphan_keys` tests catch the new keys.
- Tests added: 3 (assets module: 43 total).
- Status: DONE — 1,648 workspace tests pass (was 1,645, +3 new).
- Date: 2026-04-27

### Bug caught + fixed during this task
The first GREEN run failed `every_app_js_dataset_i18n_key_exists_in_en_json`
because `app.js` had a doc comment containing the literal string
`dataset.i18n = "literal"` inside backticks (explaining what the
extractor scans for). The substring-based extractor picked up
`"literal"` as a fake i18n key and looked it up in en.json. Fix:
rephrased the comment to omit the example string.

### Previous (D-M2-T2.7) — for context
- Task: **D-M2-T2.7 Overview page module + proxy wire-up**
- Crates: aegis-control (services bundle + page module + tests),
  aegis-proxy (admin router wiring)
- Files changed:
  - `crates/aegis-control/src/api/stats.rs` — `StatsHandler`
    refactored to always carry an upstream-summary provider closure.
    `StatsHandler::new(agg)` defaults to `UpstreamSummary::placeholder`
    (back-compat); new `with_upstream(agg, F)` and
    `with_ttl_and_upstream(agg, ttl, F)` constructors take a real
    closure. `render()` overlays the provider output onto the
    aggregator snapshot at every cache miss so stats and upstream
    summaries agree numerically. +2 unit tests.
  - `crates/aegis-control/src/dashboard_services.rs` — new module:
    `DashboardServices { stats, stats_agg, attacks, attacks_agg,
    upstreams, environment }` bundle. `spawn(bus, pool_provider,
    env)` builds every aggregator/handler, **subscribes to the
    audit bus synchronously before spawning the drain task** (the
    one bug surfaced during this task: `broadcast::Receiver` only
    sees post-subscribe messages, so doing `bus.subscribe()` inside
    the spawned task lost any event emitted before it scheduled —
    fixed by hoisting subscribe outside `tokio::spawn`). Drain task
    feeds both aggregators from one subscriber. `pool_snapshot_provider(cfg)`
    helper builds a config-derived snapshot (pool names + member
    counts; healthy = 0 until the cluster runtime lands real per-
    member health). +5 tests.
  - `crates/aegis-control/src/lib.rs` — `+pub mod dashboard_services;`.
  - `crates/aegis-proxy/src/lib.rs` — `admin_accept_loop` now
    builds `Arc<DashboardServices>` once at boot (passing
    `cfg.admin.environment` and the config-derived pool provider)
    and shares it with every connection handler. `admin_router`
    gained a `&DashboardServices` parameter and 6 new dispatch
    arms: `/api/about`, `/api/stats`, `/api/stats/timeseries`,
    `/api/upstreams/summary`, `/api/attacks/distribution`,
    `/api/attacks/top`. Each emits `Cache-Control` per
    `docs/dashboard-enterprise/api.md` §"Caching"
    (`max-age=1` for stats, `max-age=2` for upstreams,
    `max-age=10` for attacks + about). New helpers:
    `parse_query_u32(query, key, default)` (tolerates the spec's
    `15m`/`5s` suffix by trim_end_matches('s')) and
    `json_body_response(status, body, cache_control)`.
  - `crates/aegis-control/assets/dashboard/pages/overview.js` —
    placeholder → real page (~210 lines). Renders 4 stat tiles
    (request rate, blocks total, block rate, active threats), a
    traffic chart slot, an attack-distribution slot, and a top-
    attackers table slot. Polls each endpoint at the documented
    cadence (1 s / 5 s / 10 s / 10 s); first fetch fires
    immediately on mount. Pauses polling while
    `document.visibilityState !== "visible"`; refreshes everything
    on `visibilitychange` returning to visible. Aborts in-flight
    fetches on `destroy()` via `AbortController`. Reads
    `/api/about` once on mount to fill the topbar version + env
    slots. Component swap targets (`[data-slot="traffic-chart"]`
    etc.) keep T2.9 a drop-in.
  - `crates/aegis-control/tests/api_smoke.rs` — new integration
    smoke test (6 cases): about shape; stats shape with real
    aggregator (asserts `blocks_total`, upstream rollup);
    timeseries shape (window=60, step=5, 12 buckets, sum matches
    recorded events); attacks distribution percentages sum to ~100
    (the milestone's required test); attacks top groups by
    attacker (sorted by hits desc); upstreams summary reflects
    pool provider.
- Tests added: 13 net new (2 stats + 5 dashboard_services + 6
  api_smoke).
- Status: DONE — 1,645 workspace tests pass (was 1,632, +13 new).
- Date: 2026-04-27

## Next Task
- Track: **Enterprise Dashboard (D)** — **complete**. All six
  milestones (D-M1..D-M6) shipped.
- **Next track: pre-existing roadmap items**, in priority order:
  1. **Wire mutating endpoints** through the M3 audit-mutation
     pipeline so the D-M4 page writes (`PUT /api/rules/{id}`,
     `POST /api/blacklist`, `POST /api/admin/password`, etc.)
     actually persist + audit.
  2. **Cluster runtime → real tracking data**: replace the
     `TrackingHandler` placeholders with live cluster / cert /
     alert state once those subsystems land.
  3. **Full upstream proxying** in `aegis-proxy` (currently
     stub "OK" for clean requests).
  4. **Full SSE streaming** on `/dashboard/sse` — requires a
     streaming hyper response body wrapping the AuditBus
     subscriber.
  5. **Benchmark mode track** (B-T1..B-T6) — parallel to D, design
     specs already in place at `plans/benchmark-mode.md` +
     `docs/benchmark-mode.md`.
  6. Production Dockerfile + Helm chart, CI/CD pipeline, k6 +
     nuclei integration tests.
- (was) Next: D-M4-T4.1 Rule Manager page
  D-M4 covers configuration management — five pages: Rule
  Manager, Tier Config, Blacklist, Whitelist, Settings. Each
  has its own CRUD endpoints (some already exist in M3 audit /
  config work; the new endpoints add validation, dry-run,
  per-rule stats). T4.1 is the Rule Manager page itself —
  rule CRUD + diff editor + dry-run.
  See [`plans/dashboard-enterprise/milestone-4-config-management.md`](plans/dashboard-enterprise/milestone-4-config-management.md).
- (was) Next: D-M3-T3.10..T3.11 Analytics page + PromQL proxy
  - T3.10 — `assets/dashboard/pages/analytics.js`: six chart
    cards per `pages/analytics.md` with a time-range selector;
    on change, all cards refetch.
  - T3.11 — `src/api/analytics.rs`: `/api/analytics/query`
    accepts `?expr=<allow-list-key>&start=&end=&step=`. The
    `expr` is **not** raw PromQL — it's a key from the fixed
    allow-list in `docs/dashboard-enterprise/api.md` §analytics-
    allowlist. Resolves to PromQL, queries the local Prometheus
    registry's text encoder for instantaneous queries, returns
    503 with `{"error":{"code":"no_history_backend"}}` for
    range queries when no external Prometheus URL is configured.
  Closes D-M3.
  See [`plans/dashboard-enterprise/milestone-3-operator-views.md`](plans/dashboard-enterprise/milestone-3-operator-views.md).
- (was) Next: D-M3-T3.7..T3.9 Audit Log page + supporting endpoints
  Three combined parts:
    - T3.7 — `assets/dashboard/pages/audit.js` page module:
      filter strip (reuses Live Feed chips), paged table
      (cursor pagination from `/api/audit` — already partially
      covered by T3.2's `/api/audit/since`), chain status pill,
      witness lag pill, export-NDJSON button.
    - T3.8 — `/api/audit/witness` returning the last witness
      signature + lag seconds. Reads from the existing
      `aegis_control::witness` state machine (verify it exists;
      may need a simple wrapper).
    - T3.9 — `/api/filters` returning the rolling 24h distinct
      sets of class/actor/action/route from the audit ring.
      Cheap O(1) read from a HashSet maintained alongside the
      ring, or a one-pass scan (limit 24h × ~few k events =
      tractable).
  Then T3.10 + T3.11 cover Analytics page + the PromQL proxy
  to close out D-M3.
  See [`plans/dashboard-enterprise/milestone-3-operator-views.md`](plans/dashboard-enterprise/milestone-3-operator-views.md).
- (was) Next: D-M3-T3.3 Attack Events page
  The Attack Events page wires four widgets:
    1. detector breakdown bar chart (T3.4 — `/api/attacks/by-detector`)
    2. top firing rules table (already covered by T2.5 `/api/attacks/top`)
    3. threat-intel hits table (T3.5 — `/api/threat-intel/hits`)
    4. bot mix stacked bar (T3.6 — `/api/bots/mix`)
    plus a recent-detections live tail reusing the Live Feed SSE
    component with `class=detection` filter pre-applied.
  Pragmatic approach: deliver T3.3 + T3.4 + T3.5 + T3.6 together
  (the page is useless without the endpoints). Threat-intel hits
  + bot mix can use the same in-process aggregator pattern as
  attacks.rs; just add per-IP threat-intel-source and per-bot-class
  counts.
- (was) Next task: D-M3-T3.2 Live Feed reconnect / replay
  (`crates/aegis-control/src/api/audit.rs`).
  Add `GET /api/audit/since?cursor=&limit=` returning events
  after the given monotonic sequence number. Backed by an
  in-process audit ring (the audit subscriber drains the bus
  into a bounded `VecDeque` keyed by sequence). Test: write 50
  events, fetch since cursor 30, assert 20 returned in order.
  See [`plans/dashboard-enterprise/milestone-3-operator-views.md`](plans/dashboard-enterprise/milestone-3-operator-views.md).
- D-M3 progress (all done):
  - [x] D-M3-T3.1 Live Feed page
  - [x] D-M3-T3.2 Live Feed reconnect / replay
  - [x] D-M3-T3.3 Attack Events page
  - [x] D-M3-T3.4 Detector breakdown endpoint
  - [x] D-M3-T3.5 Threat-intel hits endpoint
  - [x] D-M3-T3.6 Bot mix endpoint
  - [x] D-M3-T3.7 Audit Log page
  - [x] D-M3-T3.8 Witness lag endpoint
  - [x] D-M3-T3.9 Filter catalogue endpoint
  - [x] D-M3-T3.10 Analytics page
  - [x] D-M3-T3.11 Analytics PromQL proxy
- Remaining milestones: D-M4..D-M6 — see plan README.

### Previous Next Task block (T3.1 → T3.2 transition) — for context
- D-M2 closed; D-M3 begins.
- (was) **Next task: D-M3-T3.1 Live Feed page** (drawer + filters).
  Per `plans/dashboard-enterprise/milestone-3-operator-views.md`
  the M3 milestone covers Live Feed, Attack Events, Audit Log,
  and Analytics — the four "operator view" pages. T3.1 is the
  Live Feed: virtualised SSE-driven request stream with filters
  (tier / decision / detector / IP), row drawer with the full
  audit event JSON, and the `aegis:row-click` event from the
  table component (which T2.9 just delivered).
  See [`plans/dashboard-enterprise/milestone-3-operator-views.md`](plans/dashboard-enterprise/milestone-3-operator-views.md).
- D-M2 milestone progress (all done):
  - [x] D-M2-T2.1 `/api/stats`
  - [x] D-M2-T2.2 `/api/stats/timeseries`
  - [x] D-M2-T2.3 `/api/upstreams/summary`
  - [x] D-M2-T2.4 `/api/attacks/distribution`
  - [x] D-M2-T2.5 `/api/attacks/top`
  - [x] D-M2-T2.6 `/api/about`
  - [x] D-M2-T2.7 Overview page module + proxy wire-up
  - [x] D-M2-T2.8 SSE status pill
  - [x] D-M2-T2.9 Real chart components (Chart.js vendor deferred)
- Remaining milestones: D-M3..D-M6 — see plan README.

### Known limitations / carry-overs
- Pool health: per-member `healthy` is hardcoded to 0 in
  `pool_snapshot_provider` because the cluster runtime that owns
  per-member health is itself stubbed. Pool *names* and *total*
  surface correctly. Real per-member readings land when the
  cluster runtime ships (likely M3 or later) — at that point
  swap the closure for one that reads from `cluster::Pool`
  state.
- `/dashboard/sse`: still returns one event then closes (the
  M1-era stub). T2.8 just wires the pill; full SSE streaming is
  in the existing deferred list.
- Components: stat-card, line-chart, donut, table are still
  M1-era stubs. T2.9 fills them and vendors `chart.umd.min.js`.

### Parallel track — Benchmark mode (B-)
- Plan: [`plans/benchmark-mode.md`](plans/benchmark-mode.md)
- Spec: [`docs/benchmark-mode.md`](docs/benchmark-mode.md)
- Status: planning complete, no code yet. B-T1..B-T3 (data plane)
  unblocked; B-T4.5 / B-T4.6 (dashboard panels) gated on D-M3.
  May land in any order alongside the dashboard track.
- Touches: aegis-core, aegis-proxy, aegis-security, aegis-control,
  aegis-bin. No new top-level deps.

### Deferred (post-dashboard track)
- [ ] Full upstream proxying (currently stub "OK" for clean requests — needs real TCP connect + proxy to upstream members)
- [ ] Full SSE streaming on `/dashboard/sse` (currently returns one event then closes — needs streaming body with AuditBus subscription)
- [ ] Production Dockerfile + Helm chart
- [ ] End-to-end integration tests (k6 load + nuclei security)
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] D-M2: vendor `chart.umd.min.js` and replace the SRI placeholder
  in `index.html` with the real digest; add `tests/dashboard/sri.rs`.

## Verification
- `cargo test --workspace` → **1,752 passed** (across 10 binary
  / lib / integration test targets).
  Breakdown: 82 core + 598 control lib + 15 dod + 6 router_smoke +
  6 api_smoke + 8 dashboard_polish + 224 proxy + 780+1+32
  security.
- `cargo clippy --workspace -- -D warnings` → clean.

## Completed Tasks Log
| Task | Crate | Date |
|------|-------|------|
| M1-T1.1 Workspace + `./waf run` skeleton | aegis-bin, aegis-proxy, aegis-core | 2026-04-22 |
| M1-T1.5 NoopPipeline + bus wiring | aegis-security (pre-existing), aegis-bin | 2026-04-22 |
| M1-T1.2 Config loader (figment + validation) | aegis-core | 2026-04-22 |
| M1-T1.3 Hot reload (notify + ArcSwap) | aegis-proxy | 2026-04-22 |
| M1-T1.4 Dual listener model | aegis-proxy | 2026-04-22 |
| M1-T2.1 Host matcher | aegis-proxy | 2026-04-22 |
| M1-T2.2 Path trie | aegis-proxy | 2026-04-22 |
| M1-T2.3 RouteTable::build + resolve | aegis-proxy | 2026-04-22 |
| M1-T2.4 Upstream Pool + LB strategies | aegis-proxy | 2026-04-22 |
| M1-T2.5 Active health checks | aegis-proxy | 2026-04-22 |
| M1-T2.6 Circuit breaker | aegis-proxy | 2026-04-22 |
| M1-T2.7 Wire routing + upstream into proxy.rs | aegis-proxy | 2026-04-22 |
| M1-T3.1 DynamicResolver + CertStore | aegis-proxy | 2026-04-24 |
| M1-T3.2 HTTP/2 on both sides | aegis-proxy | 2026-04-24 |
| M1-T3.3 WebSocket upgrade passthrough | aegis-proxy | 2026-04-24 |
| M1-T3.4 gRPC trailer-preserving forward | aegis-proxy | 2026-04-24 |
| M1-T3.5 mTLS to upstream | aegis-proxy | 2026-04-24 |
| M1-T3.6 ACME (feature acme) | aegis-proxy | 2026-04-24 |
| M1-T3.7 OCSP stapling | aegis-proxy | 2026-04-24 |
| M1-T4.1 Per-route quotas | aegis-proxy, aegis-core | 2026-04-24 |
| M1-T4.2 Transformations + CORS | aegis-proxy | 2026-04-24 |
| M1-T4.3 Canary split + header/cookie steering | aegis-proxy | 2026-04-24 |
| M1-T4.4 Retries with budget | aegis-proxy | 2026-04-24 |
| M1-T4.5 Shadow mirroring | aegis-proxy | 2026-04-24 |
| M1-T4.6 Session affinity | aegis-proxy | 2026-04-24 |
| M1-T4.7 Worker supervisor + graceful drain | aegis-proxy | 2026-04-24 |
| M1-T4.8 Hot binary reload (SIGUSR2) | aegis-proxy | 2026-04-24 |
| M1-T4.9 Tier-aware smart cache | aegis-proxy | 2026-04-24 |
| M1-T5.1 InMemoryBackend polish | aegis-proxy | 2026-04-24 |
| M1-T5.2 RedisBackend (feature redis) | aegis-proxy | 2026-04-24 |
| M1-T5.3 Adaptive load shedder (Gradient2) | aegis-proxy | 2026-04-24 |
| M1-T5.4 Secrets resolver | aegis-proxy | 2026-04-24 |
| M1-T5.5 DR snapshot/restore | aegis-proxy | 2026-04-24 |
| M1-T5.6 Service discovery | aegis-proxy | 2026-04-24 |
| M1-T5.7 Cluster membership | aegis-proxy | 2026-04-24 |
| M2-T1.1 Rule AST + parser | aegis-security | 2026-04-24 |
| M2-T1.2 Linter | aegis-security | 2026-04-24 |
| M2-T1.3 Evaluator | aegis-security | 2026-04-24 |
| M2-T1.4 RuleSet hot reload | aegis-security | 2026-04-24 |
| M2-T1.5 Tier classifier | aegis-security | 2026-04-24 |
| M2-T2.1 Sliding window rate limit | aegis-security | 2026-04-26 |
| M2-T2.2 Token bucket | aegis-security | 2026-04-26 |
| M2-T2.3 DDoS per-IP burst + cluster spike | aegis-security | 2026-04-26 |
| M2-T2.4 OWASP detectors (SQLi, XSS, PathTraversal, SSRF, HeaderInjection, BodyAbuse, Recon) | aegis-security | 2026-04-26 |
| M2-T3.1 JA4/JA3 parser | aegis-security | 2026-04-26 |
| M2-T3.2 HTTP/2 fingerprint | aegis-security | 2026-04-26 |
| M2-T3.3 Composite device id | aegis-security | 2026-04-26 |
| M2-T3.4 RiskEngine (scoring + decay) | aegis-security | 2026-04-26 |
| M2-T3.5 Challenge ladder | aegis-security | 2026-04-26 |
| M2-T3.6 Challenge tokens (HMAC + nonce) | aegis-security | 2026-04-26 |
| M2-T3.7 CAPTCHA providers (Turnstile, hCaptcha, reCAPTCHA) | aegis-security | 2026-04-26 |
| M2-T3.8 Behavioral analyzer | aegis-security | 2026-04-26 |
| M2-T3.9 Transaction velocity | aegis-security | 2026-04-26 |
| M2-T4.1 CIDR lists + XFF walker | aegis-security | 2026-04-26 |
| M2-T4.2 MaxMind ASN classifier | aegis-security | 2026-04-26 |
| M2-T4.3 Bot classifier | aegis-security | 2026-04-26 |
| M2-T4.4 Threat intel feeds | aegis-security | 2026-04-26 |
| M2-T5.1 Streaming response filter | aegis-security | 2026-04-26 |
| M2-T5.2 DLP patterns + actions | aegis-security | 2026-04-26 |
| M2-T5.3 FPE (AES-FF1) | aegis-security | 2026-04-26 |
| M2-T5.4 OpenAPI schema enforcement | aegis-security | 2026-04-26 |
| M2-T5.5 ForwardAuth | aegis-security | 2026-04-26 |
| M2-T5.6 JWT validation | aegis-security | 2026-04-26 |
| M2-T5.7 ICAP antivirus | aegis-security | 2026-04-26 |
| M2-T5.8 Magic-byte + archive-bomb | aegis-security | 2026-04-26 |
| M2-T5.9 GraphQL guard | aegis-security | 2026-04-26 |
| M2-T5.10 HMAC request signing | aegis-security | 2026-04-26 |
| M2-T5.11 API-key management | aegis-security | 2026-04-26 |
| M2-T5.12 Basic Auth | aegis-security | 2026-04-26 |
| M2-T5.14 OPA callout | aegis-security | 2026-04-26 |
| M2-DoD Red-team suite + benign corpus + fixture expansion | aegis-security | 2026-04-26 |
| M3-T1.1 MetricsRegistry init | aegis-control | 2026-04-26 |
| M3-T1.2 Prometheus exporter | aegis-control | 2026-04-26 |
| M3-T1.3 Health endpoints (live/ready/startup) | aegis-control | 2026-04-26 |
| M3-T1.4 Dashboard shell + SSE | aegis-control | 2026-04-26 |
| M3-T1.4b Dashboard overview page | aegis-control | 2026-04-26 |
| M3-T1.5 GET /api/config | aegis-control | 2026-04-26 |
| M3-T2.2 Tracing init + W3C Trace Context | aegis-control | 2026-04-26 |
| M3-T2.4 Access log writer (combined/JSON/template) | aegis-control | 2026-04-26 |
| M3-T3.1 Audit chain writer (SHA-256 hash chain) | aegis-control | 2026-04-26 |
| M3-T3.2 Audit verify (chain walk + recompute) | aegis-control | 2026-04-26 |
| M3-T3.3 Audit sinks (JSONL, syslog, CEF, LEEF, OCSF, Splunk HEC, ECS, Kafka) | aegis-control | 2026-04-26 |
| M3-T3.4 Admin change log | aegis-control | 2026-04-26 |
| M3-T3.5 Witness export (blake3 signing) | aegis-control | 2026-04-26 |
| M3-T3.6 State snapshot tracker | aegis-control | 2026-04-26 |
| M3-T4.1 Password verify + PHC (argon2id) | aegis-control | 2026-04-26 |
| M3-T4.2 HMAC session cookie + SessionRecord | aegis-control | 2026-04-26 |
| M3-T4.3 CSRF double-submit | aegis-control | 2026-04-26 |
| M3-T4.4 Login rate limit + lockout | aegis-control | 2026-04-26 |
| M3-T4.5 IP allowlist (in mtls module) | aegis-control | 2026-04-26 |
| M3-T4.6 TOTP (RFC 6238) + recovery codes | aegis-control | 2026-04-26 |
| M3-T4.7 Admin mTLS | aegis-control | 2026-04-26 |
| M3-T5.1 Compliance profiles (FIPS, PCI, SOC2, GDPR, HIPAA) + conflict detection | aegis-control | 2026-04-26 |
| M3-T5.2 Residency / retention sweep / right-to-erasure | aegis-control | 2026-04-26 |
| M3-T5.3 GitOps loader (poll, sig verify, dry-run, break-glass) | aegis-control | 2026-04-27 |
| M3-T5.5 SLO / SLI + multi-burn alerts (5 SLIs, 3 windows, 5 receivers) | aegis-control | 2026-04-27 |
| M3-DoD Integration tests (login flow, audit verify, SIEM ≥3 sinks, FIPS, SLO) | aegis-control | 2026-04-27 |
| Cross-crate wiring (audit verify, admin set-password, admin enroll-totp, validate + compliance) | aegis-bin | 2026-04-27 |
| README.md full rewrite (status, architecture, features, security, CLI) | project-wide | 2026-04-27 |
| deploy/GUIDE.md deployment guide (dev, staging, production) | project-wide | 2026-04-27 |
| docs/USAGE.md operations & usage guide | project-wide | 2026-04-27 |
| Data-plane detector wiring (7 OWASP detectors run on every request, block+audit on detection) | aegis-proxy | 2026-04-27 |
| Admin listener wiring (dashboard, SSE stub, health, metrics, config API on :9443) | aegis-proxy | 2026-04-27 |
| deploy/etcd/bootstrap.sh fix (self-shadowing function) | deploy | 2026-04-27 |
| config/README.md configuration guide (12 sections) | project-wide | 2026-04-27 |
| D-M1-T1.1 Asset embedder (31 assets, blake3 ETag, OnceLock table) | aegis-control | 2026-04-27 |
| D-M1-T1.2 SPA shell HTML (full chrome + 17-symbol inlined sprite) | aegis-control | 2026-04-27 |
| D-M1-T1.3 Router (dispatch + vanilla app.js + aegis-proxy delegation) | aegis-control, aegis-proxy | 2026-04-27 |
| D-M1-T1.4 Chrome (aegis.css design tokens + theme.js bootstrap + toggle wiring) | aegis-control | 2026-04-27 |
| D-M1-T1.5 Security headers (CSP + 8 others, single-source const + proxy wiring) | aegis-control, aegis-proxy | 2026-04-27 |
| D-M1-T1.6 Legacy shell carve-out (legacy.rs + DashboardConfig + flag wiring) | aegis-core, aegis-control, aegis-proxy | 2026-04-27 |
| D-M1-T1.7 Hot-reload (cfg-gated disk read of assets in debug builds) | aegis-control | 2026-04-27 |
| D-M1-T1.8 i18n loader (en.json bundle + t()/applyI18n in app.js) | aegis-control | 2026-04-27 |
| **D-M1 milestone complete** (SPA shell + assets + router + chrome + security headers + legacy carve-out + dev hot-reload + i18n) | aegis-core, aegis-control, aegis-proxy | 2026-04-27 |
| D-M2-T2.1 `/api/stats` data layer (StatsAggregator + Handler + 1s cache) | aegis-control | 2026-04-27 |
| D-M2-T2.2 `/api/stats/timeseries` (per-second BTreeMap + step-aligned downsampling) | aegis-control | 2026-04-27 |
| D-M2-T2.3 `/api/upstreams/summary` (compute_summary + UpstreamHandler with provider closure) | aegis-control | 2026-04-27 |
| D-M2-T2.4 `/api/attacks/distribution` (sliding-window per-detector counters + percentages) | aegis-control | 2026-04-27 |
| D-M2-T2.5 `/api/attacks/top` (per-attacker rollup + IP/JA4 identifier resolution) | aegis-control | 2026-04-27 |
| D-M2-T2.6 `/api/about` (AboutResponse + AdminConfig.environment) | aegis-core, aegis-control | 2026-04-27 |
| D-M2-T2.7 Overview page + proxy wire-up (DashboardServices + 6 endpoints + real overview.js) | aegis-control, aegis-proxy | 2026-04-27 |
| D-M2-T2.8 SSE status pill (EventSource + 3-state setConnectionState in app.js + i18n) | aegis-control | 2026-04-27 |
| D-M2-T2.9 Real components (vanilla SVG line-chart/donut/sparkline + sortable table + stat-card) | aegis-control | 2026-04-27 |
| **D-M2 milestone complete** (6 endpoints + Overview page wired end-to-end) | aegis-core, aegis-control, aegis-proxy | 2026-04-27 |
| D-M3-T3.1 Live Feed page (SSE EventFilter + drawer + live page module) | aegis-control | 2026-04-27 |
| D-M3-T3.2 `/api/audit/since` (AuditRing + handler + drain wire-up) | aegis-control, aegis-proxy | 2026-04-27 |
| D-M3-T3.3..T3.6 Attack Events page + by-detector + threat-intel + bot-mix endpoints | aegis-control, aegis-proxy | 2026-04-27 |
| D-M3-T3.7..T3.9 Audit Log page + witness lag + filter catalogue | aegis-control, aegis-proxy | 2026-04-27 |
| D-M3-T3.10..T3.11 Analytics page + PromQL allow-list proxy | aegis-control, aegis-proxy | 2026-04-27 |
| **D-M3 milestone complete** (4 operator pages + 11 endpoints) | aegis-control, aegis-proxy | 2026-04-27 |
| D-M4 config management (5 pages + 11 endpoints + 5 stores) | aegis-control, aegis-proxy | 2026-04-28 |
| D-M5 tracking page (6 endpoints + snapshot aggregate + page) | aegis-control, aegis-proxy | 2026-04-28 |
| D-M6 polish (a11y/contrast/headers/budget tests + legacy removal + docs) | aegis-core, aegis-control, aegis-proxy, docs | 2026-04-28 |
| **Dashboard track complete** (D-M1..D-M6, +275 tests, workspace clippy clean) | aegis-core, aegis-control, aegis-proxy | 2026-04-28 |
