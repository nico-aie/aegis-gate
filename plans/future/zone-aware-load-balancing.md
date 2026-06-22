# Zone-aware load balancing — prefer same-zone upstream members (future plan)

> **Status:** Drafted 2026-06-22. Not started. The per-member `zone` field
> already exists end-to-end as **metadata** (config → resolve → config view →
> dashboard editor) but **no load-balancing logic reads it** — verified:
> `upstream/lb.rs` and `upstream/forward.rs` contain zero `zone` references.
> This plan makes the LB *prefer* members in the proxy's own zone, cutting
> cross-zone latency and egress cost. It changes member selection, so it must
> ship with explicit cross-zone **spillover** and coordinate with the fail-open
> change in [[passive-upstream-health]] (both edit `LbStrategy::pick`). Related:
> [[project_health_signals_reported_not_gating]].

## Goal

When an upstream pool spans multiple availability zones, route a request to a
**healthy member in the proxy node's own zone** when one exists, and only spill
over to other zones when the local zone has no healthy capacity. This is the
standard "locality-aware / topology-aware" routing that AWS (Envoy zone-aware
routing), GCP, and Cloudflare load balancers offer — it reduces tail latency
and inter-AZ data-transfer cost without the operator hand-pinning pools per
node.

Today `zone` is a label you can set and see, and nothing else. This wires it
into the data path.

---

## 1. What already ships (and what's missing)

Verified in code:

- **The field exists, fully plumbed as metadata.** `MemberConfig.zone:
  Option<String>` (`aegis-core/src/config.rs:3078`) → runtime `Member.zone`
  (`aegis-proxy/src/upstream/mod.rs:33`) → carried verbatim through DNS
  expansion (`dns_resolve.rs`, `dns_refresh.rs`, same weight+zone per resolved
  IP) → surfaced in the config view (`upstreams_config.rs:84,154`) and the pool
  editor + member tables (`pages.jsx`). It also exists on the cluster/SD structs
  (`cluster.rs:28`, `sd.rs:6`).
- **Nothing consumes it for routing.** `LbStrategy::pick`
  (`aegis-proxy/src/upstream/lb.rs:21-58`) builds the `healthy` set then applies
  the strategy (round_robin / weighted / least_conn / p2c / consistent_hash) —
  it never partitions by zone. `forward.rs` never reads `zone`.
- **The node does not know its own zone.** There is **no** self-zone concept
  anywhere — no config field, no env var. A proxy cannot prefer "its" zone
  because it has no notion of which zone it is in. **This is the gating
  prerequisite** (§2).

So the work is: (a) give the node a zone identity, (b) teach `pick` to prefer
the local zone with safe spillover, (c) make it opt-in + observable.

---

## 2. The blocking prerequisite: the node must know its own zone

Add a node-level zone identity, read once at boot:

- Config: a top-level `zone: <string>` (mirrors how other node identity is
  wired) **and/or** an `AEGIS_ZONE` env override (handy for per-pod injection
  via the Downward API / `topology.kubernetes.io/zone`). Env wins over file so
  one image deploys across zones.
- Resolve it into the runtime once (alongside the existing node/roster
  identity) and thread it to where `pick` is called (the pool registry /
  forwarder), so `pick` can compare `member.zone == self_zone`.
- When unset, the feature is inert (every member is treated as "any zone") —
  there is no behavior change for single-zone or unlabeled deployments.

## 3. Design

### 3.1 Zone preference as a modifier inside `pick`, not a new strategy
Zone-awareness is **orthogonal** to the LB algorithm — operators still want
round_robin / p2c / consistent_hash *within* the preferred zone. So implement it
as a partition step between "filter healthy" and "apply strategy" in
`LbStrategy::pick`, gated by a flag, rather than adding a `ZoneAware` enum
variant:

```text
healthy = members.filter(is_healthy)          // unchanged
if zone_pref_enabled && self_zone.is_some():
    local = healthy.filter(m.zone == self_zone)
    candidates = local  (if local is non-empty AND clears the spillover gate)
               = healthy (otherwise — spill cross-zone)
else:
    candidates = healthy
apply strategy to candidates                   // unchanged per-strategy logic
```

Consistent-hash keeps its key semantics within `candidates` (note: zone
preference narrows the rendezvous set, so a key can map to a different member
when the local zone is a strict subset — acceptable; document it).

### 3.2 Spillover (do NOT strand traffic in an under-provisioned zone)
The hard part is *when* to leave the local zone. Two viable gates:

- **v1 — presence gate:** prefer local if ≥1 local member is healthy; else use
  all healthy. Simple, correct, but can overload a single local member when the
  rest of the zone is down.
- **v2 — capacity gate (Envoy-style):** prefer local only while the healthy
  fraction of the local zone is above a threshold (e.g. local healthy ≥ X% of
  local total); below it, route a proportion cross-zone so a half-dead local
  zone doesn't get hammered. More robust under partial failure.

Start with v1; design the flag/threshold so v2 is a later refinement without a
config break.

This interacts directly with the **fail-open** decision in
[[passive-upstream-health]]: that plan already proposes `pick` fall back to the
full member set when the healthy set is empty. Zone spillover is the same shape
one level up (local-zone-empty → all-zones). **Land the fail-open change first**
(or together) so the two fallbacks compose: local-zone-empty → other zones →
(if all unhealthy) fail-open to all members. The invariant stays: **`pick`
never returns `None` for a non-empty pool**.

### 3.3 Config surface
- Pool-level opt-in: `pool.locality.{enabled, mode}` (or reuse a top-level
  default with per-pool override), default **off** → zero behavior change until
  an operator turns it on for a multi-zone pool.
- v2 threshold (when added): `pool.locality.min_local_healthy_pct`.
- Keep it separate from `pool.lb` (the strategy enum at `config.rs:2901`) so the
  two compose freely.

### 3.4 Dashboard
- The member tables already show `zone`; add a small "local" affordance (badge /
  tint) on members matching the node's zone, and surface the node's own zone
  somewhere on the Routing & Upstreams page so an operator can see "this node is
  in az-a".
- Optional: a per-zone healthy-count summary on the pool card so spillover state
  is legible ("az-a: 2/3 healthy · serving local").

---

## 4. Open decisions / risks

1. **Self-zone source of truth.** Config field vs env vs both; precedence;
   what "unset" means (inert). Pin before coding (§2).
2. **Spillover policy (the big one).** Presence gate (v1) vs capacity gate (v2).
   A naive presence gate can concentrate all traffic on the last local member
   during a partial zone outage — worse than spreading. Decide the v1 contract
   and make the gate swappable.
3. **Compose with fail-open.** Must not reintroduce a `None`/503 path. Sequence
   with [[passive-upstream-health]] §2.
4. **Consistent-hash stability.** Zone preference changes the candidate set, so
   a hash key can land on a different member than the global ring would pick.
   Confirm that's acceptable for session-affinity users (it is for cache
   locality; may surprise sticky-session users — document).
5. **Skew / hot zone.** If most proxy nodes are in one zone but backends are
   evenly spread, local preference under-utilizes other zones' backends. This is
   inherent to locality routing; the capacity gate (v2) mitigates it.
6. **DNS-expanded members.** Hostname members expand to one `Member` per
   resolved IP, all inheriting the same `zone` — so zone preference applies at
   the hostname granularity, which is correct, but a single hostname spanning
   zones can't be split (it's one zone label). Out of scope to fix.
7. **Weight interaction.** Weighted strategies operate within `candidates`;
   confirm weights still make sense once the set is zone-narrowed.

## 5. Phasing

- **P1 — node self-zone identity.** Config `zone:` + `AEGIS_ZONE` env, resolved
  at boot, threaded to the `pick` call site. No routing change yet (read-only
  plumbing + a dashboard "this node: az-a" readout). Ships safely on its own.
- **P2 — zone preference in `pick`** behind `pool.locality.enabled` (default
  off), v1 presence-gate spillover, composed with the fail-open fallback.
- **P3 — observability.** Local-member badge + per-zone healthy summary +
  metric/label for "served local vs cross-zone".
- **P4 — capacity gate (v2)** + `min_local_healthy_pct`, and (optional) outlier
  awareness so a slow-but-healthy local zone can shed load.

## 6. Tests

- (P1) `zone:`/`AEGIS_ZONE` resolve into the runtime; env overrides file; unset
  → feature inert (selection identical to today).
- (P2) pool spanning az-a/az-b, node in az-a, all healthy → only az-a members
  picked (across N picks); strategy distribution holds *within* az-a.
- (P2) local zone all unhealthy → traffic spills to az-b (no `None`, no 503).
- (P2) feature off → selection byte-identical to current behavior (regression
  guard).
- (P2) single-zone / unlabeled pool → no change.
- (P4) capacity gate: local healthy below threshold → measured cross-zone
  proportion; above → fully local.
- Invariant: `pick` never returns `None` for a non-empty pool under any zone
  configuration.

## 7. Out of scope

- Cross-zone latency *measurement* / RTT-based routing (this is topology by
  label, not by probe).
- Splitting one hostname member across zones (one label per member).
- Cluster-node zone gossip / zone-aware control-plane fan-out (the `zone` on
  `cluster.rs`/`sd.rs` is a separate concern from data-plane upstream routing).
- Active health-check behavior (unchanged; see [[passive-upstream-health]]).
