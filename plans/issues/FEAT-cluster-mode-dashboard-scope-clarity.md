# FEAT — Cluster-mode dashboard scope clarity (node-local vs fleet-wide)

> **Type:** FEAT (observability / UX track) · **Status:** ✅ P1a/P1b/P1c COMPLETE — raised 2026-06-30
> **Track ID prefix:** `SCOPE-P1<a–c>`
> **Shipped:** **P1a** honesty pass (PR #102 — badges + degraded banner). **P1c** — Attack distribution + Composite RiskKey display (PR #102), traffic **timeseries** merge (PR #103, bounded 5m). **P1b** node-scope selector (branch `feat/dashboard-node-selector`: `993de29` backend + `a3e6fe5` frontend). **Only remaining:** the split-out Incidents federation ([`FEAT-incidents-fleet-federation.md`](./FEAT-incidents-fleet-federation.md)) — separate FEAT.
> **Related memory:** [[project_health_signals_reported_not_gating]] (display-only `observed` upstream health is inherently per-node), [[feedback_two_score_model]] / [[feedback_dev_xff_single_ip_gates]] (per-IP risk is node-local enforcement state).

**Goal (one line):** make the admin dashboard **honest and consistent about data scope in cluster mode** — today a single page silently mixes fleet-wide totals with one arbitrary node's panels, and several Security Ops surfaces are node-local with no indication. Fix is **tiered: label first, then add a node selector, then selectively promote panels to fleet-aware** — NOT a blanket "merge everything."

---

## The problem

In a multi-node fleet the operator reaches **one arbitrary node** through the LB. Whether a panel shows that node or the whole fleet is decided per-endpoint by `fleet_view()` (`crates/aegis-proxy/src/admin_get.rs:64-68`), which returns `Some(MergedFleet)` only when `cluster.fleet_view` is enabled + Redis is configured + at least one merge has published; otherwise every endpoint **silently degrades to node-local**.

The result is **mixed scope on a single page with no visual signal**:
- Overview top KPI tiles show **fleet totals**, but the timeseries chart, upstream health, and latency/risk panels right below them show **only the node you happened to hit**.
- Security Ops pages are inconsistent: Investigation is mostly fleet-wide, **Incidents is entirely node-local**, and Top Attackers is fleet-wide in one tab and node-local in another.

This is worse than a fully node-local page: the numbers look authoritative and comparable, but they aren't.

## Scope inventory (verified against code)

Gate: `fleet_view()` → `render_*_from_fleet()` (cluster-wide) vs direct `services.<x>` read (node-local). Merge logic: `crates/aegis-control/src/metrics/fleet_snapshot.rs`.

### Overview (`/api/stats` etc.)
| Panel | Scope (fleet_view on) | Source |
|---|---|---|
| Request rate / Blocks total / Block-rate % / Active threats | **Cluster-wide** | `render_from_fleet` (sum / weighted-avg) |
| Top attackers tile / By-detector / Bot mix | **Cluster-wide** | `render_top_from_fleet` / `render_by_detector_from_fleet` / `render_bot_mix_from_fleet` |
| **Request timeseries (1s buckets)** | **Node-local** | `services.stats_agg.timeseries` — no fleet path |
| **Upstream pool health** | **Node-local (inherently)** | `services.upstreams.render` — per-node connections |
| Audit trail (default) | Node-local unless `?scope=fleet` | `services.audit` / `services.fleet_audit_cache` |
| Rule stats / detector + route latency / GeoIP / cache / threat-intel | **Node-local** | direct `services.*` reads |

### Incidents (`/api/incidents`, `/api/alerts`) — `admin_get.rs:565`, `:1115`
| Panel | Scope | Source |
|---|---|---|
| Firing / Ack / Snoozed / Resolved alerts + rows | **Node-local — no fleet path at all** | `services.tracking.render_alerts()` (per-node SLO engine) + `services.incidents.enrich()` |

> Each node runs an independent SLO budget engine. An operator on node-2 **cannot see node-1's fired alerts**, and ack/snooze/resolve only applies on the node they're logged into. This is the biggest gap.

### Investigation (`pages.jsx:11288`)
| Panel | Scope | Source |
|---|---|---|
| Recent Requests (audit, 200 newest) | **Cluster-wide** (frontend sends `scope=fleet`, `data.jsx:1007`) | `fleet_audit_cache` → falls back to `services.audit` |
| Detector breakdown / Bot mix / Top-attacker pivot | **Cluster-wide** (when fleet on) | `render_*_from_fleet`, falls back node-local |

### Top Attackers (`pages.jsx:13358`)
| Tab | Scope | Source |
|---|---|---|
| **Identifier** (legacy attacker ranking) | **Cluster-wide** (when fleet on) | `/api/attacks/top` → `render_top_from_fleet` |
| **Composite RiskKey** (per-bucket risk) | **Node-local** | `/api/risk` → `render_list(services.risk)` — no fleet merge |
| Reset key (`POST /api/risk/reset_key`) | **Node-local** | clears only this node's `RiskTracker` |

## Design guardrails (what must NOT be force-merged)

- **Upstream pool health** is per-node by construction (this node's live connections). A fleet "sum" is meaningless; it must stay per-node but be **labelled** and ideally shown per-node in an "All nodes" view.
- **Composite RiskKey / per-IP risk** is node-local **enforcement** state ([[project_health_signals_reported_not_gating]], [[feedback_two_score_model]]). A merged *display* is useful, but reset stays a node-local (or fan-out) action — don't fake a single cluster value that hides divergent per-node decisions.
- Don't average latency histograms — if promoted, merge buckets, not means.

## Staging (3 PRs, ordered by value/risk; ship each green)

### SCOPE-P1a — per-panel scope badges + fleet-degraded banner · **S** · ✅ DONE (`f271df6`, `a0dcc53`)
Honesty pass. **Implementation note — simpler than originally specced:** instead of stamping a `scope`/`node_id` field on *every* endpoint payload, added one `GET /api/fleet/status` → `{configured, active, nodes}` (`render_fleet_status`, unit-tested) + a frontend per-panel capability map. This works because `fleet_view()` is all-or-nothing (one shared `fleet_cache`), so a single status signal is accurate for all panels.
- ✅ `Fleet` vs `This node` badge via shared `window.useScopeBadge()` + `ScopeBadge` widget; applied across Overview, Investigation, Top Attackers, Incidents.
- ✅ Degraded banner: `FleetNodeBanner` now distinguishes `configured && !active` (enabled but no merge yet) from fleet-off; also **fixed its over-claiming copy** (it falsely said latency was merged).
- ✅ **Incidents** + **Top Attackers → Composite RiskKey** explicitly badged so operators stop reading them as cluster truth.
- Single-node deployments render no badges (scope is moot).

### SCOPE-P1b — node-scope selector · **M** · ✅ DONE (this branch)
- ✅ Topbar `All nodes / <node>` selector (`FleetNodeSelector`), hidden on single-node. Node list from `GET /api/fleet/nodes`.
- ✅ **Pull-from-snapshot, not fan-out** (per the performance guardrail): `MergedFleet` retains the raw per-node snaps (`node_snaps`, `#[serde(skip)]`); `view_for_node` re-merges one snap, so every existing fleet renderer serves a single node. `?node=<id>` wired into all 7 fleet-capable handlers via `fleet_view_scoped`.
- ✅ Frontend: `fleetScopeStore` + `useApiScoped` (appends `?node=`, re-fetches via `useApi`'s url-keyed effect); `'all'` = today's merged view (no default behaviour change).
- ✅ Badge is scope-aware — a fleet-capable panel scoped to node X badges `X`, not `Fleet`. Node-local panels (Upstream, Incidents) stay `This node` (they don't honor `?node=` — would need fan-out).

### SCOPE-P1c — selective fleet-aware promotion · **M–L** (case-by-case, only where it adds real value)
- ✅ **Attack distribution** → DONE (`c57d276`): `render_distribution_from_fleet` reshapes the already-merged `detector_mix` (no new snapshot plumbing). Done early as a cheap quick-win.
- ✅ **Composite RiskKey** → DONE (`185014b`): `SnapRiskBucket` added to the snapshot, `merge_risk_buckets` dedups by `{ip, device_fp, session}` worst-wins (max score / max strikes / min idle / OR strike_blocked / worst level), `render_list_from_fleet`. Display-only — **reset stays node-scoped**.
- ✅ **Request timeseries** → DONE (PR #103): `SnapSecond` per-second buckets (absolute-epoch-keyed → sum-by-second), `merge_timeseries` + pure `bucketize_seconds` + `timeseries_from_fleet`. **Bounded to `FLEET_TIMESERIES_MAX_WINDOW_SECS=300` sparse** (no full-history publish); windows >5m fall back node-local; the traffic-chart badge is window-aware.
- → **Incidents federation** split out to [`FEAT-incidents-fleet-federation.md`](./FEAT-incidents-fleet-federation.md).
- Leave upstream health per-node (rendered under the node selector).

## Tests

- **P1a:** each endpoint reports correct `scope`/`node_id`; badge reflects fleet-on, fleet-degraded, and single-node; degraded banner appears only when configured-but-empty.
- **P1b:** selecting a node returns that node's data; "All nodes" returns fleet where mergeable + per-node where not; node list matches live `fleet:snap:*` keys.
- **P1c:** timeseries fleet merge sums buckets correctly + falls back node-local; incidents roll-up dedupes; RiskKey display merge takes max/union without dropping per-node divergence.

## Risks

| Sev | Risk | Mitigation |
|---|---|---|
| MEDIUM | **Incidents federation scope creep** (P1c) — SLO dedup + distributed ack is real work | split to its own FEAT if it grows; P1a badging already removes the worst confusion |
| MEDIUM | **Selector routing** (P1b) — fan-out to a specific node needs a node→address map | reuse fleet snapshot node identity; degrade to "node unreachable" rather than silent empty |
| LOW | **Payload churn** (P1a) — adding `scope`/`node_id` touches many handlers | additive field, backward-compatible; default `node` when absent |

## Acceptance

- [x] SCOPE-P1a: every panel badged Fleet/Node; fleet-degraded banner; Incidents + RiskKey explicitly marked node-local. ✅ `f271df6`, `a0dcc53`.
- [x] SCOPE-P1b: node-scope selector live (`993de29` backend + `a3e6fe5` frontend); fleet panels scope via `?node=`; node-local panels stay `This node`; scope-aware badges. **DONE.**
- [x] SCOPE-P1c: RiskKey display ✅ `185014b`, Attack distribution ✅ `c57d276`, timeseries ✅ PR #103 (bounded 5m), Incidents → own FEAT. **DONE.**
- [ ] Guardrails honored: upstream health stays per-node; RiskKey reset stays node-scoped/fan-out; latency merges buckets not means.
- [ ] `docs/control-plane/` dashboard doc notes per-panel scope; archive this FEAT on completion.

## Out of scope

Changing the `fleet_view()` enablement model or snapshot transport; making enforcement state (per-IP risk decisions) itself cluster-synchronized (that's a data-plane concern, not a dashboard one).

---

## Appendix A — panel-by-panel mergeability (verified)

Mergeability rubric: **sum** (additive counters) · **weighted-avg** (rates, weighted by node traffic) · **top-K union** (ranked lists, sum hits / max risk / union categories) · **bucket-wise** (timeseries/histograms, sum buckets — never average) · **don't-merge** (node-bound state) · **per-node display** (node-local enforcement state, mergeable for display only).

### Overview page (`PageOverview`, `pages.jsx:174-692`)

| # | Panel | Endpoint | Current scope | Verdict | How / note |
|---|---|---|---|---|---|
| 1 | Firing alerts banner | `/api/incidents` (`admin_get.rs:565`) | Node-local | **Merge — work** | Incidents federation: top-K union + dedup of SLO fires (ties to Incidents page) |
| 2 | Requests / s | `/api/stats` (`:348`) | **Fleet ✅** | Done | sum |
| 3 | Block rate · 10s | `/api/stats` | **Fleet ✅** | Done | traffic-weighted avg |
| 4 | Active threats | `/api/stats` | **Fleet ✅** | Done | sum |
| 5 | Upstream | `/api/upstreams` (`:1266`) | Node-local | **Don't merge** | Inherently per-node (this node's pool); label + per-node breakdown |
| 6 | Live attack origins (map) | `/api/attacks/top` (`:386`) | **Fleet ✅** | Done | top-K union; geoip joined at merge (`attacks.rs:977-979`) |
| 7 | Traffic vs Blocked (timeseries) | `/api/stats/timeseries` (`:357`) | Node-local | **Merge — costly** | bucket-wise sum; **timeseries payload risk** — use deltas, not full-history publish |
| 8 | Attack distribution (donut) | `/api/attacks/distribution` (`:378`) | **Fleet ✅ `c57d276`** | DONE | `render_distribution_from_fleet` reshapes `merged.detector_mix` |
| 9 | Top attacker IPs | `/api/attacks/top` | **Fleet ✅** | Done | top-K union |

**Findings:** 5/9 already merge (2,3,4,6,9). Quick win = #8 (reuses existing `detector_mix`). Costly = #7 (and the KPI **sparklines** on #2/#3 ride the same node-local timeseries, `pages.jsx:243-244`, so they're fleet-number-over-node-sparkline today). Leave #5 per-node.

### Appendix B — Incidents page (`PageIncidents`, `pages.jsx:11072-11286`)

Every element polls one node-local endpoint (`/api/incidents`, 5s). **No fleet path exists anywhere on this page** — it is the largest gap and has BOTH a read-side and a write-side problem.

| Element | Endpoint | Scope | Verdict | How / note |
|---|---|---|---|---|
| Firing / Acked / Snoozed / Resolved KPI cards | `/api/incidents` (`admin_get.rs:565`) | Node-local | **Merge — work** | sum after dedup |
| Incident queue table (status, severity, SLI, budget %, acked-by, note) | `/api/incidents` | Node-local | **Merge — work** | top-K union, **dedup by SLI+window** |
| Ack / Snooze / Resolve buttons | `POST /api/incidents/{id}/{action}` (`admin_mutate.rs:1870-2038`) | **Node-local mutation** | **Convergence fix** | fan-out or shared overlay |

**Two distinct problems:**
1. **Read side — SLO engine is per-node.** `SloEngine` (`slo.rs:626`) holds in-memory SLI ring buffers of *this node's* traffic and fires/resolves locally with no cross-node dedup. Node-1 fires while node-2 is silent. Federation = publish firing alerts to the snapshot + dedup by SLI+window (3 nodes firing one SLO = one incident).
2. **Write side — overlay doesn't converge (the nastier one).** `IncidentTracker` (`incidents.rs:108`) is a per-node `HashMap` with *optional* Redis persistence that is a **single-node restart bridge, NOT cross-node sync**. Mutate handlers never `publish_modes()` / never write the shared config doc — same class as [[project_api_mode_no_cluster_publish]]. **Ack on node-1 → node-2 still shows firing**; two operators can double-handle. Fix: all nodes *read* the existing `control:waf:incidents` hash (not just hydrate-on-boot), or fan-out the mutation.

> **Split out → [`FEAT-incidents-fleet-federation.md`](./FEAT-incidents-fleet-federation.md)** (tracked separately; `IF-P1a–d`). Read-side dedup + write-side convergence is materially heavier (and higher correctness risk) than the rest of SCOPE-P1. SCOPE-P1a still **badges** this page node-local in the meantime; the real fix lives in that FEAT. When it lands, the Investigation firing-alerts chip (Appendix C) closes for free.

### Appendix C — Investigation page (`pages.jsx:11288-11897`)

Healthiest page. Most elements already merge; the derived (client-side) elements inherit the audit table's fleet scope automatically.

| Element | Endpoint | Scope | Verdict |
|---|---|---|---|
| Posture card: req-rate / block-% | `/api/stats` | **Fleet ✅** | Done |
| Posture card: top attacker | `/api/attacks/top` | **Fleet ✅** | Done |
| Detector breakdown | `/api/attacks/by-detector` (`:545`) | **Fleet ✅** | Done |
| Bot mix | `/api/bots/mix` (`:632`) | **Fleet ✅** | Done |
| Recent Requests audit table | `/api/audit/since?scope=fleet` (`:395`) | **Fleet ✅** | Done (see tail caveat) |
| Attacker-context panel (IP pivot) | `/api/attacks/top` | **Fleet ✅** | Done |
| Audit timeline (pivot) | `/api/audit/since?scope=fleet` | **Fleet ✅** | Done |
| Pivot summary cards / action breakdown / top-detectors | — (derived from audit data) | **Fleet ✅ (inherited)** | Done |
| Posture card: firing alerts chip | `/api/incidents` (`:565`) | Node-local | **Merge — rides Incidents federation** (no new work) |
| Posture card: audit witness lag | `/api/audit/witness` (`:640`) | Node-local | **Per-node display** — merge as max/worst-case, or just label (you want to know *which* node lags) |

**Caveat:** fleet audit merge uses a **bounded 200-event tail per node** (`fleet_audit.rs:40`); merge-then-truncate-to-200 can drop the tail of busy nodes. Fine for "recent activity," not a complete cross-node audit — footnote, not a fix.

### Appendix D — Top Attackers page (`PageTopAttackers`, `pages.jsx:13358-13814`)

Two tabs with opposite scopes.

**Identifier view** (`/api/attacks/top`, `admin_get.rs:386`) — **fully fleet-merged already.** Columns merge as: hits→sum, risk→max, categories→union, country/asn/asn_class→prefer-non-null, last_seen→max. **Block action** (`POST /api/blacklist`, `admin_mutate.rs:4306`) already **publishes fleet-wide** via interop (`:4376-4378`). Nothing to do.

**Composite RiskKey view** (`/api/risk`, `admin_get.rs:976`) — **node-local, no fleet path.** Every field (`ip`, `device_fp`, `session`, `score`, `strikes`, `idle_seconds`, `level`, `strike_blocked`) is per-node `RiskTracker` (`tracker.rs:152`) state.

| Element | Scope | Verdict | How |
|---|---|---|---|
| Identifier view table + Block action | **Fleet ✅** | Done | top-K union; block fans out |
| RiskKey table (read) | **Fleet ✅ `185014b`** | DONE (display-only) | `merge_risk_buckets`: score→max, strikes→max, idle→min, level→worst, strike_blocked→OR |
| Reset bucket (`POST /api/risk/reset_key`, `admin_mutate.rs:3749`) | **Node-local mutation** | **Needs fan-out** | clears only local tracker + local durable; a bucket blocked on node-2 stays blocked |

**Reuse hint:** the merge recipe for the RiskKey *display* is **exactly** the client-side "Group by IP" logic already shipped (`pages.jsx:13447-13473`: max score, max strikes, min idle, worst level, OR strike_blocked) — same reduce, applied across nodes instead of across buckets. Caveat ([[project_health_signals_reported_not_gating]], [[feedback_two_score_model]]): risk is node-local **enforcement** state; a merged display is informational, but **reset must fan-out** (or hit shared risk state) to actually clear a bucket cluster-wide — don't show one merged value that hides divergent per-node block decisions.

## Cross-page summary

| Page | Already fleet | Easy promote | Costly / federation | Leave per-node |
|---|---|---|---|---|
| Overview | 5/9 | Attack distribution (#8) | Timeseries (#7) + sparklines | Upstream (#5) |
| Incidents | 0 | — | **Whole page (own FEAT): read dedup + write convergence** | — |
| Investigation | 8/10 | — | Firing-alerts chip (rides Incidents) | Audit witness lag |
| Top Attackers | Identifier tab | — | RiskKey reset fan-out | RiskKey display (label) |

**Build order implied:** (1) SCOPE-P1a badges everywhere + Attack-distribution quick promote; (2) SCOPE-P1b node selector for the per-node panels (Upstream, RiskKey, witness lag); (3) SCOPE-P1c timeseries fleet merge; (4) **separate FEAT** for Incidents federation (read dedup + overlay convergence) — the firing-alerts chip on Investigation closes for free when that lands.
