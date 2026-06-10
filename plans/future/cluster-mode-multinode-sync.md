# Cluster mode — multi-node console sync (leaderless, Redis-optional)

> **Status:** plan / proposal (not yet implemented).
> **Goal (operator's words):** run the WAF as a cluster of N nodes where the
> **console data syncs across every node** — config, *live traffic*, and other
> state — so an operator hitting any node (e.g. a VS Code port-forward to a
> non-"leader" node) sees the same picture. Redis may be the sync bus
> (pub/sub or shared keys), **but if Redis dies the WAF must keep proxying with
> zero impact on the upstream path**, and **the leader concept can be removed**.
>
> **Hard constraints:**
> - **≤ 5 s real-time monitor SLA** — logs/events must reach the dashboard within
>   5 s of the WAF processing the request (organizer requirement). See §2b/§2c.
> - **Cluster mode is OPTIONAL.** A single-node deploy (`state.backend =
>   in_memory`, no Redis) must keep **today's performance with zero added cost** —
>   no fleet publish task, no pub/sub, no SCAN. Every cluster mechanism is gated
>   on a shared backend being present and degrades to the existing local path.
>   See §0.
>
> **Scope note:** this is a *consolidation* plan. ~70% of "cluster mode" already
> ships. This document audits what's done, names the one real gap (fleet-wide
> live-traffic on the console), folds in the in-flight C-1 control-plane work,
> and defines the leaderless migration + the Redis-optional resilience contract.
> It supersedes the C-1/C-3/C-4 sections of
> [`plans/issues/multi-node-consistency.md`](../issues/multi-node-consistency.md)
> and reuses the flush pattern from
> [`plans/archive/multi-node-metrics-aggregation.md`](../archive/multi-node-metrics-aggregation.md).

---

## 0. Single-node stays free (cluster mode is opt-in)

Everything in this plan is **gated on a shared backend being present** and falls
back to the exact code paths that ship today. The gate is one runtime check —
`cfg.state.backend != in_memory` — already used by the metrics-aggregation
read path, so this is an established pattern, not new branching.

| Mechanism | Single node (`in_memory`, no Redis) | Multi node (Redis) |
|---|---|---|
| Config / control plane | local `ArcSwap`, file watcher (today) | + `config:waf:doc` / `control:waf:*` polling |
| Events → dashboard | in-process `AuditBus` → SSE (today, sub-second) | + `fleet:events` pub/sub fanout (§2b) |
| Live-traffic panels | local rings/registry (today) | + `fleet:snap:*` merge (§2a) |
| Fleet publish task / subscriber | **never spawned** | one background task each |
| Per-task leases (ACME/GitOps) | `InProcessLease` (today) | `RedisLease` (today) |

**Performance guarantee:** on a single node, **no fleet task is spawned, no
`PUBLISH`/`SCAN`/`SUBSCRIBE` is issued, and the request path is byte-for-byte
what it is today.** The cluster code is additive and dormant. The hot path is
unchanged in *both* modes anyway (§7 — sync is always background + best-effort),
so even enabling Redis doesn't add request-path latency; the single-node promise
is simply that the background machinery isn't even created. This is enforced at
boot wiring in `aegis_proxy::run` (spawn the fleet tasks only when a shared
backend is selected) — mirror the existing conditional spawn of the
metrics-flush task.

---

## 1. What already works (do not rebuild)

The data/state plane is **already cluster-consistent** and **already
Redis-partition-safe**. Verified in code:

| Surface | Mechanism | File |
|---|---|---|
| **Config** (detectors, rules, tiers, upstreams, risk thresholds, `ai.enabled`) | Versioned doc `config:waf:doc`, watcher converges all nodes (~3 s) | `aegis-proxy/src/supervisor.rs`, `sd/mod.rs` |
| **Risk / rate-limit / auto-block / block-list** | Shared `StateBackend` keys (`g:*`) | `aegis-security/*`, `aegis-core/src/state.rs` |
| **Challenge `/challenge/verify`** | Stateless PoW token + single-use Redis nonce (`g:nonce:*`) | round-robin safe |
| **Control plane** (`set_profile`, `reset_state`) | **C-1 ✅ landed** — `control:waf:modes` versioned doc + `control:waf:reset_epoch` counter, polled per node (Redis-gated) | `aegis-control/src/interop/cluster_sync.rs`, `aegis-proxy/src/cluster_control.rs` |
| **Access-list / route counters** (P4/P5) | Local rings + best-effort `incrby` flush; `SCAN`+sum at read | `aegis-control/src/metrics/window_flush.rs` |
| **Redis-down resilience** | `ReconcilingBackend` — local in-memory fallback, additive block-lists, replay-on-heal; **data plane never blocks on Redis** | `aegis-proxy/src/state/reconcile.rs` |
| **Cluster roster** | Heartbeat/lease store → `set_members` | `aegis-control/src/api/tracking.rs` |

**Key existing invariant (the user's hard requirement, already met):** the hot
path does at most one *best-effort* state-backend call and falls through to the
local in-memory backend on error. A Redis outage degrades *shared* features
(cross-node risk, fleet counters) but **cannot 502 the upstream**. Every new
piece of code in this plan MUST preserve that property.

---

## 2. Two fleet gaps on the console

Two distinct things don't cross nodes today. They have **different latency
requirements** and therefore **different transports** — conflating them is what
made the first draft fail the ≤5 s SLA (§2c).

| Gap | Data | Freshness need | Transport |
|---|---|---|---|
| **2a — live-traffic metrics** | RPS, p50/p95/p99, action/detector/bot mix, top-attackers | "near-real-time" gauges | leaderless snapshot polling |
| **2b — discrete logs/events** | individual security decisions (block/challenge/detection rows) | **≤ 5 s SLA** (organizer requirement) | **pub/sub fanout into the local event bus** |

### 2a. Live-traffic metrics — **leaderless self-publish + merge-on-read**

Today the dashboard's traffic panels — **RPS, decision p50/p95/p99,
top-attackers, by-detector, action mix, bot mix** — come from each node's
**local** Prometheus registry + local trackers. Shared *state* (risk,
block-list) is consistent; **per-request volume/latency/attack counts are
per-node**. So the console on node A shows ~`1/N` of fleet traffic (whatever the
LB sent it). There is no fleet view inside the WAF.

That is the "live traffic doesn't sync" symptom the operator saw on the
port-forwarded non-leader node.

This is the C-3 "fan-in" idea from the issues doc, **reworked without a leader**:

- **Each node** periodically (default **2 s**) snapshots its own live-traffic
  rollup and writes it to a self-owned Redis key
  `fleet:snap:<node_id>` with a short TTL (default **10 s**, i.e. 5× the cadence
  so a dead node ages out on its own — no sweeper, no leader to evict it).
- **Any node's console** reads the fleet view by `SCAN fleet:snap:*`, decoding
  each peer's snapshot and **merging**: sum counters/RPS, merge top-attacker
  heaps, take max/recompute percentiles (see §5 on percentile merge), union the
  roster. Stale keys are already gone via TTL.
- **Merge happens on the publish tick**, into an `ArcSwap` fleet-cache the admin
  GET dispatcher reads synchronously (it can't `.await` — same constraint the
  P4/P5 `AggregateCache` already solved). So the cross-node hop is **one**
  interval (publish→peer-merge), not two. Budget: publish 2 s + dashboard poll
  2 s ⇒ metrics gauges land in **~4 s worst case** (see §2c). Keep the dashboard
  poll at ≤ 3 s for these panels so the gauges stay inside 5 s too.

Why leaderless beats a leader fan-in:
- No single hotspot, no failover gap when the "leader" dies.
- Aligns with "remove the leader" (§4).
- Identical shape to the already-shipped metrics-counter flush — proven pattern.

Why self-publish-to-Redis beats node-to-node HTTP pull:
- Reuses the one dependency we already have; no new mTLS mesh between nodes.
- Naturally Redis-optional: lose Redis → `SCAN` returns nothing → console falls
  back to the **local** panels (clearly labelled "this node"), and the upstream
  path is untouched. Same failure mode as everything else.

### 2b. Discrete logs/events — **pub/sub fanout into the local event bus** (≤ 5 s SLA)

> **Organizer requirement:** *"Logs/Events must appear on the Dashboard within
> ≤ 5 seconds of the WAF processing the request."*

**How events reach the dashboard today:** `aegis_core::audit::AuditBus` is an
**in-process `tokio::broadcast` channel** (`aegis-core/src/audit.rs:313`). A
request is processed → an `AuditEvent` is published to the local bus →
`dashboard/sse.rs` streams it to the browser, and the jsonl/syslog sinks
subscribe too. **Single-node latency is sub-second — already ≤ 5 s.**

**The multi-node hole:** the bus is *in-process*. Node A's events never reach
node B's `AuditBus`, so a fleet dashboard viewed on node B shows **none** of node
A's events — not within 5 s, not at all (only SigNoz, on a slower path). The
snapshot in §2a carries *aggregate gauges*, **not** the discrete event rows the
requirement is about. So §2a alone **does not satisfy the SLA**.

**Fix — Redis pub/sub event fanout (this is the correct use of pub/sub):**

- At the single tap that already feeds the local `AuditBus`, also
  `PUBLISH fleet:events <event-json>` — **best-effort, off the hot path** (fire
  from the bus-subscriber side, not the request path, so a slow `PUBLISH` never
  touches request latency).
- Every node runs **one** subscriber on `fleet:events`. On each message it
  re-injects the remote `AuditEvent` into its **own** local `AuditBus`, tagged
  with the origin `node_id` and a `remote: true` flag so the fanout tap does
  **not** re-publish it (no loop).
- The dashboard SSE already streams the `AuditBus` → it now renders fleet events
  with zero changes to the SSE/sink layer. End-to-end cross-node latency =
  publish (ms) + Redis fanout (ms) + SSE push ⇒ **well under 1 s**. ✅

**Why pub/sub is right *here* but not for state (§3):** an event stream is
**append-only and loss-tolerant** — a dropped message means one row is missing
from a *remote* dashboard, never a divergence of enforcement state. So the
at-most-once weakness that disqualifies pub/sub for config/risk convergence is
harmless for a monitoring feed. And it degrades cleanly: **Redis down → cross-node
events stop, each dashboard falls back to its local events** (still sub-second,
still ≤ 5 s for that node's own traffic), while the upstream path is untouched.
Monitoring loses fleet-completeness for the outage window; protection does not.

Bounded-loss guard: cap the `fleet:events` publish rate (e.g. sample/drop when a
node is emitting > N events/s) so a traffic flood can't turn the monitor bus into
a write amplifier — the local bus + SigNoz remain the complete record.

### 2c. Latency budget vs the ≤ 5 s SLA

| Path | Hops | Worst case | ≤ 5 s? |
|---|---|---|---|
| **Discrete event, same node** | bus → SSE | < 1 s | ✅ |
| **Discrete event, cross-node (§2b)** | bus tap → `PUBLISH` → subscriber → bus → SSE | **< 1 s** | ✅ |
| **Aggregate gauge, cross-node (§2a)** | publish 2 s + dashboard poll ≤ 3 s | **~4–5 s** | ✅ (at poll ≤ 3 s) |

The **SLA-bearing path is 2b** (discrete logs/events) and it clears 5 s with wide
margin via pub/sub. The aggregate gauges (2a) are not "logs/events" in the strict
reading, but the tightened cadence keeps them inside 5 s anyway.

---

## 3. Pub/Sub vs polling — recommendation

The operator suggested Redis pub/sub. The right answer is **transport per data
class** — pub/sub and polling each fit a different job:

| Data class | Transport | Why |
|---|---|---|
| **State convergence** (config, modes, risk, reset epoch) | **polling backbone** | must be correct + self-healing; a missed message must not diverge enforcement |
| **Discrete event/log stream** (§2b, ≤ 5 s SLA) | **pub/sub fanout** (primary) | append-only, loss-tolerant, needs sub-second cross-node delivery; degrades to local on Redis death |
| **State-change latency** (optional) | **pub/sub *nudge*** on top of polling | cuts convergence to ms without making correctness depend on the message |

So pub/sub **is** used as a first-class mechanism — for the event stream that
carries the ≤ 5 s SLA — while state convergence keeps the resilient polling
backbone. The reasoning for *not* putting state convergence on pub/sub:

- **Pub/sub is at-most-once and fire-and-forget.** A node that is reconnecting,
  GC-paused, or briefly partitioned **misses** the message and silently
  diverges — exactly the bug class this plan exists to kill. Polling a versioned
  key is **self-healing**: a node always converges on its next tick regardless of
  what it missed.
- **Redis-death requirement.** If sync *depended* on pub/sub delivery, a Redis
  blip = permanent divergence until the next manual change. With polling +
  TTL'd snapshots, a Redis outage just freezes the fleet view at "last known"
  and auto-recovers on reconnect. This is the resilient default.
- **Best of both:** publish a tiny `control:waf:bump` pub/sub message on every
  config/control change. Subscribers treat it as "re-poll now" instead of
  waiting for the next interval — cutting convergence from seconds to
  milliseconds **without** making correctness depend on the message. If the
  message is lost, the next poll catches up. (Phase 4 — optional.)

**Decision:** polling stays the backbone for **state** (config 3 s,
control/snapshot 2 s). Pub/sub is **load-bearing for the event stream** (§2b —
required to meet the ≤ 5 s SLA, but loss-tolerant by nature so a Redis outage
only costs fleet-completeness, never protection). The pub/sub *state nudge* is a
separate, optional latency optimization (Phase 4), gated by a flag, never
load-bearing for correctness.

---

## 4. Remove the "leader" — but keep per-task leases

"Leader" in this codebase is **two unrelated things**. Untangle them:

### 4a. Remove — the global *leader* notion (no longer needed)

- `LeaderView` / `is_leader` in `aegis-control/src/api/tracking.rs`.
- `check_ready_strict(readiness, is_leader)` leader gating in
  `aegis-control/src/health.rs` + `aegis-proxy/src/admin_get.rs:97`
  (the `/healthz/ready` "503 not_leader" mode).
- `is_leader` / `previous_leader` fields in `slo.rs`, dashboard, and the
  `/api/cluster` response.

Replace with a **leaderless roster**: every node is equal; the roster is just
the set of nodes whose heartbeat key is live (`fleet:snap:*` already carries
liveness, so the roster can be derived from it — one fewer mechanism).
`/healthz/ready` reverts to pure node-local readiness (state rehydrated +
listeners bound + not draining). The console drops the "leader" badge and shows
a flat peer list.

### 4b. Keep — opportunistic *per-task leases* (these are NOT a leader)

`acquire_lease("acme")` and `acquire_lease("gitops")`
(`aegis-proxy/src/cluster.rs`) are **leaderless distributed mutexes**: whoever
grabs the key first runs that singleton task, for that task only. They exist to
stop **N nodes renewing the same cert / applying the same GitOps config at
once** (ACME double-issuance is a real outage). They are not a cluster leader.

- **Keep them**, rename in code/docs from "leader lease" → "task lease" to end
  the confusion.
- The `ReconcilingBackend` already does the right thing
  (`reconcile.rs` invariant #3): leases are **deliberately not reconciled** —
  an unreachable Redis **pauses** ACME/GitOps rather than risk two nodes both
  "winning". That stays. (Cert renewal pausing for a Redis blip is safe; certs
  have weeks of validity.)

**Net:** the cluster has no leader. Singleton side-tasks coordinate via
self-expiring per-task locks. Console/metrics need no coordinator because
self-publish + merge-on-read is leaderless by construction.

---

## 5. Design details for the fleet snapshot (Phase 2 core)

### Snapshot shape (`fleet:snap:<node_id>`, JSON, TTL ~10 s)

```text
node_id, ts_ms,
rps_1s / rps_10s,                      // gauges
decision_latency: { count, sum_us, p50_us, p95_us, p99_us, hist_buckets[] },
action_mix:   { allow, block, challenge, log_only, ratelimit },
detector_mix: { sqli, xss, rce, ... },
bot_mix:      { good, bad, unknown },
top_attackers: [ { ip, count, last_action } ],   // bounded (e.g. top 50)
backend_health: { connected, circuit, latency_p },
build / version
```

### Merge rules (the only subtle part)

- **Sums** (counts, action/detector/bot mix, RPS): add across nodes. ✅ trivial.
- **Top-attackers**: each node ships its bounded top-K; merge by summing per-IP
  counts across nodes, re-sort, truncate. Slightly lossy at the long tail (an IP
  ranked #51 on every node could be undercounted), acceptable for a dashboard;
  the *exact* per-IP risk is already correct in shared state for enforcement.
- **Percentiles**: you **cannot average p95s**. Ship per-node **histogram
  buckets** (the Prometheus decision-latency histogram already has them) and sum
  bucket-wise, then recompute percentiles from the merged histogram. This is the
  only field that needs the histogram, not a scalar — call it out in the
  snapshot serializer.

### Hot-path safety

- The snapshot is built from **already-collected** local registries/trackers in
  the **background publish task** — the request path does nothing new.
- Publish is **best-effort**: `set` failure logs at debug and is swallowed
  (same pattern as `cluster_sync::publish_modes`). Never turns into a 500.
- Read is from the `ArcSwap` fleet-cache; on empty/SCAN-failure it returns the
  local snapshot so the console always renders.

### Config knobs (new, all with safe defaults)

```yaml
cluster:
  fleet_view:
    enabled: true              # off → console shows local-only (today's behaviour)
    publish_interval_ms: 2000  # §2a snapshot cadence
    snapshot_ttl_ms: 10000     # 5× cadence — dead nodes self-evict
    top_attackers_k: 50
    pubsub_nudge: false        # Phase 4 — low-latency state re-poll trigger
  fleet_events:                # §2b — the ≤ 5 s logs/events SLA path
    enabled: true              # off → events are local-only (today's behaviour)
    channel: "fleet:events"
    max_publish_rate_per_s: 500 # bounded-loss guard; sample/drop above this
```

---

## 5.5 LB / ingress topology — how to route in front of the fleet

There are **two independent planes**, each fronted differently:

```
              ┌─────────── data-plane LB ───────────┐
   clients ──▶│  DNS-RR / L4 passthrough / TPROXY    │──▶ node:8080 / :8443 ──▶ upstream
              └─────────────────────────────────────┘
              ┌────────── console-plane LB ─────────┐
 operators ──▶│  round-robin / pick-any (any node)  │──▶ node:9443 (admin/console)
              └─────────────────────────────────────┘
```

### Console plane — **yes, the LB can route to any node** ✅

This is the operator's question, and it's exactly what the plan delivers. After
Phases 2–3 every node's console is a **full fleet view** (events via §2b,
metrics via §2a, config/control already shared). So:

- **Round-robin or pick-any both work** — whichever node the LB lands on shows
  the same fleet-wide picture. No "must hit the leader" anymore (there is no
  leader — §4).
- **Sessions already follow you** — admin sessions live in the shared backend
  (`admin_session_shared.rs`); login on any node validates on all, and logout is
  fleet-wide. **Requirement:** all nodes must share the same admin cookie-signing
  key (`cfg.admin.dashboard_auth.csrf_secret`) — already the design; make it
  identical in every node's config.

Three things to get right when you put an LB in front of the console:

1. **Expose the admin listener.** It binds to `127.0.0.1:9443` by default
   (loopback — that's why a port-forward was needed). To LB it, bind the admin
   listener to a routable interface and keep it locked down (admin-auth is
   already on; add network ACL / mTLS / private subnet). Don't expose 9443 to the
   public internet.
2. **Stream the SSE feed.** The live event feed is a long-lived `text/event-stream`
   connection. The LB must do **streaming pass-through** — disable response
   buffering and set a generous read/idle timeout (e.g. nginx
   `proxy_buffering off; proxy_read_timeout 1h;`). Otherwise events stall in the
   LB buffer and you blow the ≤ 5 s SLA at the *LB*, not the WAF.
3. **Sticky is optional now.** Because every node carries the full fleet feed, a
   reconnect to a *different* node just resumes the same stream — correctness
   doesn't need stickiness. Light session affinity still reduces reconnect churn
   on the SSE stream; nice-to-have, not required.

### Data plane — route for availability, but **LB type decides client-IP correctness**

Separate concern from the console, and the one real foot-gun. The WAF keys
per-client risk/rate-limit on the **TCP peer IP**:

- **DNS round-robin / L4 passthrough / TPROXY** → WAF sees the **real client IP**
  → per-IP risk, rate-limit, DDoS keys are correct. **This is the supported
  topology.** Recommend it.
- **L7 LB that terminates/SNATs** (nginx `http`, most cloud ALBs) → the WAF's peer
  is the **LB's IP for every client** → all traffic collapses onto one risk key
  unless the WAF is told to trust the LB. **C-5 ✅ landed:** set
  `proxy.trusted_proxies: [<LB CIDRs>]` and the data plane walks `X-Forwarded-For`
  right-to-left to the real client. Trust **only** proxies that sanitize XFF
  (a proxy forwarding a client-supplied XFF re-opens the F-HIGH-002 spoofing hole).

**Bottom line:** console plane → any LB, round-robin to any node, just stream the
SSE and share the signing key. Data plane → DNS-RR / L4 needs no extra config;
an L7 SNAT LB now works too once you set `proxy.trusted_proxies` to its CIDRs.

---

## 6. Implementation phases

### Phase 0 — finish & verify C-1 — ✅ LANDED (PR: multi-node-consistency)
- `set_profile` / `reset_state` converge fleet-wide via `control:waf:modes` +
  `control:waf:reset_epoch` polling (`interop::cluster_sync` +
  `cluster_control::spawn_poller`), Redis-gated; `SetProfileRequest.cluster`
  (default true) selects cluster vs node-local. Unit + in-memory round-trip
  tests green.
- **Remaining (follow-up):** a live 2-node `tests/cluster/` script —
  `set_profile {all,log_only}` on node A flips node B's `X-WAF-Mode`;
  `reset_state` on A clears B's local risk cache (needs a Redis + 2-process rig).
- This is the control-plane half of "console data syncs". The remaining gaps are
  the **live-traffic** console (Phase 2/3) and the **leaderless** migration
  (Phase 1).

### Phase 1 — remove the leader (§4a), keep task leases (§4b) — ✅ LANDED (2026-06-10, branch `feat/cluster-phase1-remove-leader`)
- ✅ `LeaderView` → `RosterView` (`api/tracking.rs`): dropped the `leader:cluster`
  holder cell + `is_leader()`/`leader_node()`/`set_holder()`; kept the `members:*`
  roster (`set_members`/`members`/`our_node`). `ClusterResponse` dropped
  `is_leader`/`leader_node` → flat `{peers, our_node}`.
- ✅ Reverted `/healthz/ready` to node-local: deleted `check_ready_strict` +
  the `?strict=1` "503 not_leader" branch (`health.rs`, `admin_get.rs`); readiness
  is state-rehydrated + listeners-bound + not-draining only.
- ✅ Removed the `leader:cluster` singleton lease + its holder poller in
  `accept.rs`; **kept** the `members:*` heartbeat + roster poller (the liveness
  source — `fleet:snap:*` doesn't exist until Phase 3, so the roster stays on the
  existing heartbeat keys, per the §4a "keep the heartbeat key" option).
- ✅ Removed the unwired `LeaderLost` SLO alert variant (`slo.rs` + `slo/dispatch.rs`).
- ✅ Renamed "leader lease" → "task lease" wording in `cluster.rs` /
  `cluster_lease/mod.rs` / `aegis-core::cluster` docs; `acquire_lease` semantics
  and the `reconcile.rs` no-reconcile-leases invariant **untouched**.
- ✅ `dashboard_services`: `leader_view` → `roster_view`,
  `spawn_with_mask_and_leader` → `spawn_with_mask_and_roster`.
- **Tests:** ACME/GitOps single-acquire under contention still green
  (`cluster.rs` `three_node_cluster_single_lease_holder` / `lease_blocked_by_holder`);
  new `tracking.rs` tests assert `/api/cluster` is a flat roster with **no**
  `is_leader`/`leader_node`. Gates: workspace + `--features redis` build;
  aegis-control 1074 + aegis-core 289 + aegis-proxy 781 green.
- **Deferred to Phase 4 (per phase split):** the dashboard still reads
  `cluster.data?.is_leader` defensively (optional chaining ⇒ `undefined` ⇒ badge
  auto-hides); the leaderless frontend cleanup (`app.jsx`/`pages.jsx`/`data.jsx`
  mock) + HA docs/openapi land in Phase 4.

### Phase 2 — fleet **event fanout** (§2b) — ✅ LANDED (2026-06-10, branch `feat/cluster-phase2-fleet-events`)
- ✅ **Sibling trait** `aegis_core::fleet::FleetBus` (`publish(channel, bytes)` +
  `subscribe(channel, bound) -> mpsc::Receiver`) — **not** on `StateBackend`
  (9+ impls). `NoopFleetBus` for single-node; `aegis_proxy::state::RedisFleetBus`
  (feature `redis`) over a **dedicated** `redis::Client` pub/sub connection,
  separate from the deadpool command pool (§7 hot-path contract).
- ✅ **Publisher** (`fleet_events::spawn_fleet_publisher`) drains the local
  `AuditBus`, rate-caps (`max_publish_rate_per_s`), origin-tags, best-effort
  `PUBLISH`es to `cluster.fleet_events.channel`.
- ✅ **Subscriber** (`spawn_fleet_subscriber`) re-emits peers' events onto a
  **separate** fleet-event bus the dashboard SSE merges in (`admin_sse` merges a
  second broadcast receiver) — **SSE-only** (operator decision 2026-06-10): remote
  events do NOT enter this node's durable sinks / audit chain (cluster plan §10).
- ✅ **Loop/echo guard — structural, no `remote` flag.** The plan's per-event
  `remote: bool` was dropped: `AuditEvent` has **128 construction sites**. Instead
  (a) the publisher reads the *local* bus while remote events land on the *fleet*
  bus it never reads, and (b) since Redis echoes a PUBLISH back to the publisher,
  the subscriber drops events whose `origin_node` (stamped into `fields`, no struct
  change) is *us*. End-to-end test proves B sees A's event and A doesn't loop.
- ✅ Config `cluster.fleet_events.{enabled,channel,max_publish_rate_per_s}` (off by
  default, gated on `state.backend: redis`); wired in `accept::spawn_fleet_event_fanout`
  (single-node spawns nothing). `config/REFERENCE.md` updated.
- **Tests:** aegis-core fleet 2, aegis-proxy fleet_events 6 (incl. in-process
  end-to-end + echo-drop), admin_sse merge green; default 786 / redis 809 / core 291
  / control 1074. **Live 2-node SSE-propagation verification deferred to the
  `tests/cluster/` rig (Task 5 / Phase-1 follow-up) — needs Redis + 2 processes.**

### Phase 3 — fleet snapshot publish + merge (§5, §2a) — ✅ LANDED (2026-06-10, branch `feat/cluster-phase3-fleet-snapshot`)
- ✅ `aegis-control/src/metrics/fleet_snapshot.rs`: `FleetSnapshot` (RPS / block-rate
  / blocks / threats / decision-latency histogram buckets / action·detector·bot
  mix / top-attackers), `merge()` (scalar sums + request-rate-weighted block-rate +
  **bucket-wise histogram percentile recompute** via the shared `quantile_ms` +
  top-attacker sum/union-categories/max-risk/truncate), `FleetCache`
  (`ArcSwap<Option<MergedFleet>>`), `build_snapshot()` (reads the live local
  aggregators), `scan_and_merge()` (decode-skip-on-error).
- ✅ Publish+merge task `accept::spawn_fleet_snapshot_task` (gated on
  `fleet_view.enabled` + non-`in_memory` backend): each `publish_interval_ms` sets
  `fleet:snap:<node>` with TTL, then `scan_prefix` + `get` + merge → `FleetCache`.
  Reads `services.stats_agg` + `services.attacks_agg` + the `total`-stage
  histogram. Single-node spawns nothing.
- ✅ Endpoint switches: `/api/stats`, `/api/attacks/top`, `/api/attacks/by-detector`,
  `/api/bots/mix` serve `render_*_from_fleet` (new methods on `StatsHandler` /
  `AttacksHandler`, MergedFleet → existing JSON shapes) when `FleetCache` is
  populated, else the local aggregator (via the `fleet_view(services)` helper in
  `admin_get`). `FleetCache` threaded on `DashboardServices` (like `fleet_event_bus`).
- ✅ Config `cluster.fleet_view.{enabled,publish_interval_ms,snapshot_ttl_ms,
  top_attackers_k}` (off by default); `config/REFERENCE.md` documented.
- **Tests:** `fleet_snapshot` 7 (scalar sums, p50/95/99 from summed histograms,
  top-attacker merge+truncate, latency-none, cache, JSON round-trip, **mock 3-node
  `StateBackend` scan+merge: RPS=sum + TTL'd node drops**). default 787 / redis OK
  / core 291 / control 1081 green.
- **Scope notes / deferred:** `action_mix` carried in the snapshot but left empty
  (canonical source `DecisionMetrics` isn't on `services` + no fleet action-mix
  endpoint) — forward-compat field. Merged panels report a fixed snapshot window
  (300 s) regardless of the client `?window=`. Tightening the dashboard poll to
  ≤ 3 s for these panels (§2c) is a frontend tweak deferred to Phase 4.

### Phase 4 — labels, durable logs, docs
- Console header: drop "leader" badge; show "Fleet view (N nodes)" vs
  "This node" toggle so per-node vs fleet is never ambiguous.
- Durable/forensic logs (C-4): the **live** ≤ 5 s feed is Phase 2; for the
  *complete historical* record keep SigNoz as the heavy path, document
  `request_id` correlation across nodes, ship `collect-audit.sh` (scp+merge by
  `ts_ms`). The pub/sub feed is lossy-by-design (monitor), so SigNoz/local files
  remain the source of truth for audit. No in-WAF durable log bus — out of scope.
- Update `docs/operations/ha-clustering.md` + `deploy/PRE-PROD-DEPLOY.md`:
  leaderless model, fleet-view + fleet-events knobs, ≤ 5 s budget, Redis-down
  behaviour table.

### Phase 5 — *optional* pub/sub state nudge (§3)
- `control:waf:bump` channel; on config/control mutation, publish a 1-byte bump;
  subscribers re-poll immediately (reuses the Phase-2 pub/sub primitive). Polling
  stays the backstop. Gated by `cluster.fleet_view.pubsub_nudge`, default off.
- **Test:** with nudge on, state convergence < 250 ms; with Redis pub/sub
  dropped, polling still converges within one interval (proves non-load-bearing).

---

## 7. Redis-down resilience — the contract every phase must keep

| Failure | Data plane (upstream) | Shared features | Fleet metrics (§2a) | Event feed ≤ 5 s (§2b) |
|---|---|---|---|---|
| Redis slow | Unaffected — best-effort, circuit breaker → local | degrade to per-node | freezes at last cache | delivery slows; local events still instant |
| Redis down | **Unaffected** — `ReconcilingBackend` local fallback; block-list additive | per-node; blocks replay on heal | `SCAN` empty → **local-only panels**, labelled | cross-node feed stops → **each dashboard shows local events** (still ≤ 5 s for own traffic) |
| Redis partition | Unaffected | counters local, reconcile on heal; **leases paused** (no split-brain ACME) | each side shows reachable peers | each side fans out within its partition |
| Redis back | Auto-reconnect, replay buffered blocks | converges | repopulates next publish tick | fanout resumes immediately |

**Non-negotiable:** no new call on the request→upstream path may `.await` Redis
synchronously. All cluster sync — including the §2b `PUBLISH` — is background
tasks + best-effort writes + local-fallback reads. The event `PUBLISH` fires from
the **bus-subscriber side**, never the request path. The pub/sub subscriber uses
a **dedicated** Redis connection so it can't stall the command pool. This is
already how config/control/metrics work; the event feed and fleet snapshot
follow suit. **Losing Redis costs monitoring completeness for the outage window,
never protection.**

---

## 8. Risks

| Risk | Severity | Mitigation |
|---|---|---|
| Removing leader breaks a hidden singleton | **High** | §4b — ACME/GitOps are *task leases*, kept; audit `acquire_lease` callers before deleting `is_leader` |
| Percentile merge done wrong (averaging p95s) | Med | ship + sum **histogram buckets**, recompute (§5) |
| Snapshot publish adds Redis write-amp at high node count | Med | 2 s cadence, one key/node, TTL self-GC; tune interval; it's off the hot path |
| Top-attacker long-tail undercount | Low | dashboard-only; enforcement uses exact shared risk keys |
| **§2b event feed misread as the durable audit record** | **Med** | it's a *lossy monitor* feed; SigNoz + local `waf_audit.log` stay the source of truth (§ Phase 4); rate-cap documented |
| Event flood turns `fleet:events` into a write amplifier | Med | `max_publish_rate_per_s` sample/drop guard; dedicated pub/sub connection |
| Pub/sub *state nudge* tempts someone to make it load-bearing | Med | keep it a *nudge*; Phase-5 test asserts polling-only convergence |
| Fleet snapshot/events leak internal IPs cross-node | Low | admin-plane only, same trust boundary as today's console |

---

## 9. Effort (rough)

| Phase | Est. |
|---|---|
| 0 — finish/verify C-1 | ~3 h (mostly tests; code largely in branch) |
| 1 — remove leader / rename leases | ~4 h |
| 2 — **fleet event fanout (≤ 5 s SLA)** | ~6 h (pub/sub primitive + dedicated conn + fanout tap + subscriber + loop guard + 2-node test) |
| 3 — fleet snapshot publish+merge | ~8 h (serializer + histogram merge + cache + wiring + tests) |
| 4 — labels/logs/docs | ~3 h |
| 5 — optional pub/sub state nudge | ~3 h |
| **Total** | **~24–27 h** (Phase 5 optional) |

---

## 10. Out of scope
- Cross-region / cross-cluster federation (SigNoz/Prometheus federation owns that).
- **Durable** cross-node log/audit store. The §2b feed is a *live* ≤ 5 s monitor
  (lossy by design); the complete forensic record stays in SigNoz + per-node
  `waf_audit.log`, correlated by `request_id`.
- Raft / strong consensus — explicitly **not** wanted; eventual convergence via
  shared keys is sufficient and Redis-optional.
- Redis durability (RDB/AOF) — operator's call; the WAF doesn't manage it.
```
