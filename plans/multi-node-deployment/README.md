# Multi-node deployment — proposal

> **Status:** proposal · awaiting SA Team confirmation on machine count, network model, and Redis availability.
> **Authors:** Nico, 2026-05-08
> **Trigger:** SA Team will provision N machines (N ≥ 2, exact count TBD) for Aegis-Gate. Today the WAF runs on a single host; we need a deployment strategy that turns N machines into capacity, not just N copies.

---

## TL;DR

**Recommend Active-Active behind an L4 load balancer with shared state in a Redis cluster.** All N WAF nodes accept traffic in parallel; per-request work is stateless on each node; cross-node state (rate-limit counters, risk scores, blacklists, attack rollups) lives in Redis; singleton tasks (ACME renewal, GitOps sync, SLO leader-only writes) elect a leader via the existing Redis lease store.

The codebase already has the primitives — Redis-backed state, Redis-backed lease store, peer membership heartbeat, leader election, hot-reload. What's missing is an **opinionated topology + ops runbook** that the SA Team can hand to whoever racks the machines.

This document **proposes** that topology and lists the open questions we need SA to answer before we cut a delivery plan.

---

## Goals (in priority order)

1. **Linear-ish throughput scaling** — 2 nodes ≈ 1.7×, 4 ≈ 3×. Not 1×.
2. **Survive 1 node failure** with no data-plane drop and no operator action.
3. **Same operator UX** — one dashboard, one audit trail, one config source.
4. **Cap blast radius** of bad config / bad release — staged rollout, drainable nodes.
5. **No regressions on current single-node feature set** (v2.3 interop, log_only, set_profile, etc.).

Non-goals for this round:
- Geo distribution / cross-region replication (single-DC for now).
- Kubernetes — we already ship a Helm chart, but the SA Team is hinting at "machines," so this proposal is **deployment-substrate-agnostic** (works on bare metal, VMs, or k8s).

---

## What we already have (multi-node-ready primitives)

A surprising amount of the wiring is done. Inventory:

| Capability | Where | Status |
|---|---|---|
| Redis-backed shared state | `crates/aegis-proxy/src/state/redis.rs` (`RedisBackend`) + `state/reconcile.rs` (`ReconcilingBackend` for fallback) | Ready |
| Redis-backed lease store | `crates/aegis-proxy/src/cluster_lease/redis.rs` (`RedisLease` with `SET NX PX` + CAS Lua renew) | Ready |
| Peer membership heartbeat | `crates/aegis-proxy/src/accept.rs` — `members:<node_id>` keys, 15 s TTL, refreshed every 7.5 s | Ready (post-M008) |
| Leader election | `leader:cluster` lease with fenced acquire | Ready |
| Live cluster view in dashboard | `LeaderView` + `/api/cluster` + Scaling page L2 card | Ready |
| Hot-reload (no full restart) | SIGUSR2 → `HotReloader` + fd-pass binary handover (FDP) | Ready |
| Per-node graceful drain | `POST /admin/drain` → `/healthz/ready` returns 503 → external LB stops sending | Ready |
| Audit chain | Append-only JSONL per node + chain hash | Ready (per-node; central aggregation TBD — see §7) |
| Helm chart with HPA + anti-affinity + PDB | `deploy/helm/aegis-gate/` | Ready |
| `set_profile` propagation | Per-node ModeStore — **NOT yet shared** | **Gap** (see §6) |
| Per-detector mask propagation | Per-node — **NOT yet shared** | **Gap** (see §6) |

The two gaps below are the substantive engineering work for multi-node. Everything else is wiring + ops.

---

## Recommended topology

```
                       ┌──────────────────┐
            traffic →  │  L4 load balancer│  (HAProxy / cloud LB / IPVS / nginx stream)
                       │  TLS passthrough │
                       └────────┬─────────┘
                                │ TCP/443 (data plane)
                ┌───────────────┼───────────────┐
                ▼               ▼               ▼
          ┌──────────┐    ┌──────────┐    ┌──────────┐
          │ aegis-1  │    │ aegis-2  │ …  │ aegis-N  │   ← stateless per-request;
          │ :8080    │    │ :8080    │    │ :8080    │     accept loop in each
          │ :8443    │    │ :8443    │    │ :8443    │
          │ :9443    │    │ :9443    │    │ :9443    │   ← admin (cluster-internal only)
          └────┬─────┘    └────┬─────┘    └────┬─────┘
               │               │               │
               └───────┬───────┴───────┬───────┘
                       │               │
                ┌──────▼─────┐  ┌──────▼─────┐
                │ Redis      │  │ Upstream   │
                │ (cluster)  │  │ pools      │
                └────────────┘  └────────────┘
                       ▲
                       │ leader:cluster · members:* · g:lease:* · rate counters · risk scores
                       │ access-list cache · attack rollup · session store · CSRF secrets
                       │ ModeStore (NEW) · detector mask (NEW)
```

### Why L4 (not L7) at the front?

- **TLS passthrough** — Aegis-Gate is the TLS terminator. An L7 LB in front would have to terminate TLS itself, do its own WAF logic (or skip it), then re-encrypt to us. That doubles cost and creates a second policy surface.
- **Connection-level distribution** — L4 round-robin or least-conn over TCP works; HTTP/2 multiplexing per-connection is preserved.
- **Fewer feature surprises** — no L7 LB rewriting `Host`, dropping headers, or adding its own `X-Forwarded-*` (which the WAF then has to re-parse).

### Why not Anycast / BGP?

It's better in principle (no LB hop, lower latency, no LB SPOF). But it requires:
- Network team support (BGP peering with TOR / cloud router).
- ECMP + connection hashing tuning (`fou`, `ipvs`, or kernel BPF).
- Operationally heavier — every node-down event flaps a route.

**Decision:** keep BGP/Anycast as a Phase-3 option; ship L4 first.

### Why not Active-Passive?

Wastes ≥ 50 % of the capacity SA is providing. Goal #1 is throughput, not just availability.

---

## State architecture — what's shared, what's per-node

The single most important design call: what state goes in Redis vs stays local.

### Shared (Redis-backed) — must agree across nodes

| State | Why shared | Existing? | Notes |
|---|---|---|---|
| **Rate-limit counters** (`IpRateLimiter`) | A 1000-RPS attacker shouldn't get 4× more on a 4-node cluster | Partial — `RedisBackend` exists, used by `ReconcilingBackend` | Verify `IpRateLimiter` uses backend, not local-only `Mutex<HashMap>` |
| **Risk scores** (`RiskTracker`) | Must persist across nodes so a flagged client stays flagged | Partial — backend wiring needs audit | Same as above |
| **Auto-block list** (sticky blocks from risk-strikes) | Same | `RedisBackend::auto_block` exists with PSETEX | Ready |
| **Access lists** (blacklist / whitelist) | All nodes must enforce the same list within seconds of an audit-mutated POST | Partial — store is in-memory, hot-reloaded from config; runtime POSTs land on whichever node took the request | **Gap** — needs a Redis pub/sub or polling layer |
| **Cluster peer registry** (`members:*`) | Dashboard shows all peers from any node | Ready | M008-fixed |
| **Singleton lease** (`leader:cluster`, `acme:lease`, `gitops:lease`) | Only one node renews TLS / pulls GitOps | Ready | RedisLease + CAS renew |
| **CSRF secrets / session store** | Operator login on node-1 must work when LB sends them to node-2 next | **Per-node today** | **Gap** — promote `SessionStore` to Redis-backed |
| **ModeStore** (`set_profile` overrides) | Critical for v2.3 interop — OC's `set_profile` lands on one node; all nodes must enforce the new mode within seconds | **Per-node today** | **Gap** — promote to Redis with pub/sub or short-poll |
| **Detector mask** (per-detector enabled flag) | Same as ModeStore | **Per-node today** | **Gap** |
| **Attack aggregator rolling window** (Top Attackers / By-Detector / Bot Mix) | Dashboard should show cluster-wide totals, not node-local | Per-node today | **Gap** — see §7 |

### Per-node (intentionally local)

| State | Why local | Notes |
|---|---|---|
| **Hyperscan / regex pattern cache** | Read-mostly, identical across nodes once config matches | Hot-reload syncs from config |
| **Connection-level state** (active TCP/HTTP2 streams, mTLS handshakes in-flight) | Per-connection by definition | — |
| **In-flight request body buffers** | Lifetime = single request | — |
| **AI detector ONNX session** | Read-mostly model weights + per-request inference | — |
| **Audit JSONL ring** (per-node) | Append-only log written locally; central aggregation pulls/ships | See §7 |
| **Hot-reload watcher state** | Per-node config file watch | — |

---

## Audit log strategy

Every node writes its own `waf_audit.log` (JSONL, hash-chained). The contract requires `request_id` to match what the data plane stamped in `X-WAF-Request-ID` — that's already correct because the chain is per-node, not cluster-wide.

For operator UX (one Audit Trail page, not N), we need a central aggregator. Two options:

1. **Pull model** — dashboard `/api/audit/since` queries each peer in parallel via the cluster membership list, merges by timestamp. Simple, no new infra. Latency-bound by the slowest peer.
2. **Push model** — each node ships JSONL to a central sink (S3 / OpenSearch / Loki) via the existing cold-tier path; dashboard reads from the sink. Better for retention; adds a dependency.

**Recommend:** start with option 1 (no new infra, fits the existing `/api/cluster` membership pattern). Wire option 2 later if retention or cross-DC visibility becomes a requirement. The cold-tier sink machinery is already partly there (`/api/cold-tier`).

---

## Sizing & capacity (rough)

These are starting points; real numbers come from the next stress test on the SA-provided hardware.

| Knob | Suggested starting value | Rationale |
|---|---|---|
| WAF nodes | **min(SA-provided, 2)** for HA, scale up on RPS evidence | 2 covers single-node failure; more = more headroom |
| Redis | **3-node cluster** (or single + read replicas if SA can't do cluster) | Sentinel/cluster for HA; the lease + state machinery assumes Redis is reachable |
| LB | **2 instances active-passive** (HAProxy) or one cloud LB | LB itself is a SPOF if we have one |
| Per-node tokio workers | **= logical CPU count** (`runtime.workers: auto`) | Already the default in `waf.yaml` |
| Per-node CPU | ≥ 4 cores | Below this, the AI detector dominates |
| Per-node RAM | ≥ 4 GiB | Hyperscan + ONNX model + connection buffers |
| Network per node | ≥ 1 Gbps | Below this, the LB hop becomes the bottleneck |
| HPA target CPU | 70 % | Existing default in Helm; same applies bare-metal via watch + scale-out playbook |

**Throughput target:** prior single-node stress test (5k VUs, k6 mixed traffic) hit ~X RPS at p99 < Y ms. Multi-node target: linear scale to (X · 0.85 · N) RPS at the same p99 — the 0.85 is the Redis round-trip tax on shared state.

---

## Proposed rollout phases

Each phase is independently deployable and adds one capability.

### Phase 1 — Stand up 2 nodes + Redis + LB (MVP)

- Provision 2 WAF machines + 1 Redis (single instance, accept SPOF for the demo).
- L4 LB in front, round-robin.
- Verify both nodes share the access lists, rate-limit counters, and lease store by hitting each node directly.
- Acceptance: drop one node mid-traffic — LB drains it, surviving node continues serving, no audit gaps.

### Phase 2 — Promote per-node state to Redis (the engineering work)

Close the gaps from §5:
- Promote `SessionStore` to Redis-backed (so operator login survives node failover).
- Promote `ModeStore` + detector mask to Redis-backed with pub/sub for sub-second propagation. **Critical for v2.3 interop** — `set_profile` from the OC harness must land on all nodes, not just the one that received the call.
- Centralise blacklist / whitelist updates via the same pub/sub channel.
- Acceptance: `set_profile { mode: "log_only" }` on node-1 takes effect on node-2's data plane within 2 s (measured by sending traffic through node-2 and observing `X-WAF-Mode: log_only`).

### Phase 3 — Cluster-aware operator UX

- `/api/audit/since` aggregates across peers (option 1 above).
- Top Attackers / By-Detector / Bot Mix cards become cluster-wide rollups (Redis-backed sliding window).
- Scaling page Layer 2 card lists all peers with health (already wired post-M008).
- Per-node `Drain this node` button on the Scaling page (already wired).

### Phase 4 — Hardening (once Phase 1-3 is stable)

- Redis HA: Sentinel or Cluster mode, depending on SA's preference.
- LB HA: VRRP/keepalived for HAProxy, or rely on cloud LB SLA.
- Anycast/BGP option (replaces LB) — only if network team can support and the latency win is worth it.
- Cross-region: out of scope for this proposal, but the Redis-backed design doesn't preclude it.

### Phase 5 — Capacity validation

- Re-run the stress harness from `plans/hackathon-stress-test.md` against the N-node cluster.
- Compare per-node RPS vs single-node baseline; expect ≥ 0.85× linearity.
- Measure Redis round-trip distribution under load — if it's > 1 ms p99, that's our scaling ceiling, not the WAF.

---

## Open questions for SA Team

We can't finalise the delivery plan until SA confirms:

1. **How many machines, what spec?** (CPU / RAM / NIC / disk class)
2. **Same DC, same rack, or spread across racks/AZs?** Determines latency budget for Redis and audit aggregation.
3. **What load balancer is available?** Cloud LB (managed)? Hardware LB (F5/Citrix)? Or do we run HAProxy ourselves on a separate box?
4. **Redis** — do we get a managed Redis (ElastiCache / managed Redis Cluster) or do we run it ourselves on the same machines?
5. **Network bandwidth between nodes and Redis?** — `< 1 ms` round trip is the assumption; degrades fast above that.
6. **Deployment substrate** — bare metal? VMs? k8s? (We have the Helm chart for k8s; bare metal needs systemd unit + Ansible/Salt.)
7. **TLS termination** — Aegis-Gate terminates today. Confirm SA isn't planning to put a TLS-terminating L7 LB in front (would force a re-architecture).
8. **GeoIP DB distribution** — currently each node loads its own `data/geoip/*.mmdb`. SA pushes via image bake, or via a shared mount?

---

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Redis becomes a single point of failure | High (Phase 1) → Low (Phase 4) | Sentinel/Cluster in Phase 4; in-memory fallback via `ReconcilingBackend` for graceful degradation |
| `ModeStore` propagation delay between nodes violates v2.3 contract on `set_profile` | Medium | Phase 2 ships pub/sub propagation; until then, restrict multi-node to environments where the harness only hits one node |
| LB doing connection re-balance kills long-lived HTTP/2 connections during deploy | Medium | Use connection draining on rolling restarts; existing `/admin/drain` + readiness probe pattern |
| Audit chain hash-mismatch on cross-node merge | Low (per-node chains stay consistent; merge is by timestamp not hash) | Doc the merge semantics; never re-chain across nodes |
| GeoIP staleness across nodes | Low | Ship updates via `make geoip-link` + config reload; same as today |
| Cluster grows beyond what `KEYS members:*` can handle | Low (< 100 peers) | Switch list_keys impl to `SCAN` once we cross 100 nodes — flagged in `cluster_lease/redis.rs:322` |

---

## Out of scope (deliberately)

- **Geo-distributed multi-DC** — different problem (replication, latency, data sovereignty). Address when the SA roadmap calls for it.
- **Service mesh integration** (Istio / Linkerd sidecars) — orthogonal; if a mesh shows up later, the L4 LB just becomes the mesh's ingress.
- **Custom protocols** (QUIC / HTTP/3) — current stack is HTTP/1.1 + HTTP/2; not changing here.

---

## Next steps

1. Send §9 (Open questions) to SA Team — block on answers.
2. Once answered, split this proposal into delivery phases under `plans/multi-node-deployment/PHASE-*.md`, mirroring the `plans/issue-fix/tester-n-2026-05-07/` structure.
3. Phase-2 engineering work (state promotion to Redis) is the single biggest item; spike it on a 2-node dev cluster before the SA hardware lands so we don't block on hardware delivery.
4. Update `docs/STAGING-BENCHMARK.md` with the multi-node curl probes (each `/__waf_control/*` endpoint must work via the LB AND directly to each node).

---

## References

- `plans/hackathon-stress-test.md` — current single-node baseline
- `plans/binary-handover-fd-pass.md` — hot-restart machinery (per-node, not affected)
- `crates/aegis-proxy/src/cluster_lease/redis.rs` — Redis lease wire format
- `crates/aegis-proxy/src/state/redis.rs` — Redis state backend wire format
- `deploy/helm/aegis-gate/values.yaml` — current k8s defaults (replicaCount, HPA, anti-affinity)
- `Hackathon_Doc/EN_waf_interop_contract_v2.3.md` §2.5 — `set_profile` contract that drives the Phase-2 state-promotion priority
