# FEAT — Incidents fleet federation (cluster-wide SLO alerts + converged overlay)

> **Type:** FEAT (observability / correctness track) · **Status:** ✅ COMPLETE — raised 2026-06-30, shipped 2026-07-01
> **Track ID prefix:** `IF-P1<a–d>`
> **Shipped:** IF-P1a stable `incident_uid` (PR #105, also fixed MED-ADM-01) · IF-P1b read-side fleet roll-up + `firing_on` breadth (PR #106) · IF-P1c cross-node overlay convergence (LWW on `updated_at`, PR #107) · IF-P1d resolve auto-resurrection (re-fire OR grace-past `RESOLVE_GRACE_SECS=300`, flap-bounded) on branch `feat/incidents-fed-p1d-resolve-resurrection`.
> **Parent / sibling:** split out of [`FEAT-cluster-mode-dashboard-scope-clarity.md`](./FEAT-cluster-mode-dashboard-scope-clarity.md) (Appendix B). That FEAT badges/labels scope across all dashboard pages; **this** one does the real federation work for Incidents. When this lands, the Investigation posture-card "firing alerts" chip (`/api/incidents`) becomes fleet-wide for free.
> **Pattern guardrail:** [[project_api_mode_no_cluster_publish]] (mutations that forget to publish converge node-local-only), [[project_apply_and_swap_helper_guard]] (every cluster-sync path must be wired + guard-tested), [[project_config_plane_doc_vs_file]] (shared-state writes vs local).

**Goal (one line):** make the **Incidents** page cluster-correct — both the **read side** (SLO alerts fire per-node today; a 3-node cluster shows 3 copies or misses fires the operator isn't routed to) and the **write side** (ack/snooze/resolve mutate node-local only; an ack on node-1 is invisible on node-2, so two operators double-handle one incident). Today this page silently misleads every multi-node, multi-operator team.

---

## Why this is its own FEAT (not part of SCOPE-P1)

The rest of the dashboard mostly already merges; the Incidents gap is heavier and carries **correctness** risk, not just display inconsistency:

- **Read side — SLO engine is per-node.** `SloEngine` (`crates/aegis-control/src/slo.rs:626`) holds in-memory SLI ring buffers of *this node's* traffic and fires/resolves locally. No cross-node dedup. There is **no fleet path at all** on `/api/incidents` (`admin_get.rs:565`) or `/api/alerts` (`admin_get.rs:1115`).
- **Write side — overlay doesn't converge.** `IncidentTracker` (`crates/aegis-control/src/api/incidents.rs:108`) is a per-node `HashMap<String, IncidentState>` with *optional* Redis persistence to the `control:waf:incidents` hash. But that persistence is a **single-node restart bridge** — written fire-and-forget, read **only on boot hydrate** (`incidents.rs:165-192`). The mutate handlers (`admin_mutate.rs:1870-2038`) call `incidents.ack/snooze/resolve()` locally and **never** `publish_modes()` / never write the shared config doc. Same failure class as the mode-publish bug.

The crux that makes this non-trivial: **incident identity is node-dependent today.** Alert IDs look like `DataPlaneAvailability-1h:1700000000` — SLI + window + *per-node fire timestamp*. So the same logical incident has a different ID on every node, which breaks both dedup (read) and overlay matching (write). Federation requires a **stable, node-independent incident identity** first.

## Staging (4 PRs, ordered by dependency; ship each green)

### IF-P1a — stable incident identity · **M** · START HERE (foundation)
Derive a node-independent incident key `incident_uid = <SLI>-<window>` (drop the per-node fire timestamp from the *identity*; keep `fired_at` as a per-node observation field).
- Re-key `IncidentTracker` state + the `control:waf:incidents` hash on `incident_uid`.
- `enrich()` (`incidents.rs:297`) matches overlay → alert by `incident_uid`, not the timestamped id.
- Migration: one-time rewrite of existing hash entries to the new key (or accept a clean slate — overlay state is operational, not historical).
- No behavior change on a single node; pure identity refactor. Lands first so b/c/d can rely on stable keys.

### IF-P1b — read-side fleet roll-up · **M**
Publish each node's firing alerts into the fleet snapshot and dedup on read.
- Extend the fleet snapshot (`crates/aegis-control/src/metrics/fleet_snapshot.rs`) with a bounded `firing_incidents: Vec<...>` per node (uid, severity, fired_at, budget_consumed_pct, node_id).
- `merge()` dedups by `incident_uid`: **one row per logical incident**, carrying `max(budget_consumed_pct)`, `min(fired_at)` (earliest node to fire), and a `firing_on: [node_id...]` list so operators see breadth.
- `GET /api/incidents` gains a fleet path via `fleet_view()` (mirror the existing `render_*_from_fleet` pattern), node-local fallback when the cache is empty.
- Keep payload bounded (firing alerts are normally few; cap + `log()` if truncated).

### IF-P1c — write-side overlay convergence · **M–L** (the correctness core)
Make the `control:waf:incidents` hash the **source of truth read by all nodes**, not just boot hydrate.
- On the `/api/incidents` read path, merge the shared overlay (read-through or short-TTL cached read of the hash) so an ack/snooze/resolve on any node is visible everywhere.
- Mutate handlers (`admin_mutate.rs:1870-2038`) keep writing the hash (already do), now keyed by `incident_uid` (from P1a) so writes from any node address the same bucket.
- Decision: **read-through shared overlay** (all nodes read the hash) is preferred over **fan-out mutation** (broadcast to every node) — fewer moving parts, no node-roster dependency, survives restart, and reuses state that already exists. Fan-out is the fallback if read-through latency is a problem.
- Wire it into the cluster-sync helper list + add the structural guard test ([[project_apply_and_swap_helper_guard]]) so a future handler can't silently regress to node-local.

### IF-P1d — divergent-state semantics + auto-resurrection · **M** (the careful one — do LAST)
Resolve the cross-node state conflicts that only exist once b/c are live.
- **Resolve while still firing elsewhere:** operator resolves on node-1 but node-2's SLO is still burning. The resolve overlay should suppress the incident fleet-wide (operator said "handled"), but must **auto-resurrect** if the underlying SLO is still/again firing after the resolve — extend the existing auto-resurrection logic (`incidents.rs:283-289`) to evaluate against the *fleet* firing set, not just local.
- **Snooze deadlines** are absolute UTC — already cross-node safe; confirm under merge.
- **Last-writer-wins** on concurrent acks from two operators: keep the audit chain as the tiebreaker record; surface `acked_by` from the winning write.

## Tests (RED-first, per stage)

- **IF-P1a:** identity refactor is behavior-preserving single-node (existing incident suite green); overlay matches alert by uid across a simulated re-fire with a new timestamp.
- **IF-P1b:** two simulated nodes both firing `X-1h` → merged view shows **one** row with `firing_on: [node-a, node-b]`, `max` budget, `min` fired_at; fleet path falls back to node-local when cache empty.
- **IF-P1c:** ack on node-1 → node-2's `/api/incidents` shows acknowledged (read-through); restart-durable; structural guard test fails if a new incident mutation skips the shared-overlay wiring.
- **IF-P1d:** resolve suppresses fleet-wide; auto-resurrects when fleet SLO still firing after resolve; snooze deadline honored across nodes; concurrent ack resolves to one `acked_by` with both in the audit chain.
- Keep the SLO burn-rate + incidents unit suites green throughout.

## Risks

| Sev | Risk | Mitigation |
|---|---|---|
| HIGH | **Resolve/resurrection loop** (P1d) — resolve fleet-wide then immediate re-fire flaps the incident | evaluate resurrection against fleet firing set + a small hysteresis/grace window; never flap faster than the SLO eval tick |
| MEDIUM | **Identity migration** (P1a) — re-keying the hash drops/mismatches in-flight overlay | overlay is operational state, not historical — accept clean-slate or one-shot rewrite; document in release note |
| MEDIUM | **Read-through latency** (P1c) — hashing Redis on every `/api/incidents` poll (5s) × operators | short-TTL cache the merged overlay (mirror `fleet_audit_cache`); fan-out fallback only if needed |
| LOW | **Snapshot bloat** (P1b) | firing alerts are few; cap + `log()` truncation; reuse existing snapshot transport |

## Acceptance

- [x] IF-P1a: node-independent `incident_uid`; single-node behavior unchanged; suite green. **PR #105** (also fixed MED-ADM-01 ack round-trip).
- [x] IF-P1b: `/api/incidents` fleet roll-up dedups by uid with `firing_on` breadth; node-local fallback intact. **PR #106**.
- [x] IF-P1c: ack/snooze/resolve from any node visible on all nodes; restart-durable (LWW on `updated_at`, clobber-safe). **PR #107**.
- [x] IF-P1d: resolve auto-resurrects on re-fire OR past `RESOLVE_GRACE_SECS` (flap-bounded); evaluated against the fleet firing set in `enrich_fleet`; snooze deadline already absolute-UTC; concurrent-ack handled by P1c LWW. **This branch**.
- [x] Sibling firing-alerts chip on Investigation goes fleet-wide for free (rides `/api/incidents`).
- [ ] `docs/control-plane/` incidents doc notes fleet behavior; archive on completion. _(doc follow-up)_

## Out of scope

In-place alert-rule editor (still YAML `cfg.alerts`); changing how the SLO engine *measures* (still per-node SLI sampling — we federate the **fired alerts**, not the raw SLI math; true cross-node SLI measurement is a separate, larger effort); the `fleet_view()` enablement model itself.
