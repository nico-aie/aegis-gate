# Cluster Ingress / Load-Balancer Plan

> **Status:** Closed — HA-T1..T5 shipped in run-05. Reference only.
>
> See [`README.md`](./README.md) for the track status board.
>
> **Original scope.** Tracked carry-over 6 (HA test methodology
> gap surfaced 2026-04-29) plus the rest of the HA roadmap
> from
> [`docs/operations/ha-clustering.md`](../docs/operations/ha-clustering.md).
>
> **Why this exists.** Today's cluster perf test fires k6 at
> each WAF node on its own port. Production deploys put a
> load balancer in front. Without modelling that LB, our
> measurements are per-node ceilings, not cluster SLOs —
> which means we can't publish failover budgets, single-VIP
> throughput, or sticky-session correctness. This plan is
> how we close that gap.

## Mission

Ship a reference HA topology (LB + 2 WAF nodes + Redis +
upstream) in `deploy/`, plus the matching test scripts in
`tests/cluster/`, plus the per-task wiring needed for the
WAF to play nicely inside that topology. After this plan
closes:

1. Operators have a copy-pasteable LB recipe for HAProxy /
   Nginx / k8s Ingress.
2. The cluster perf number we publish is a single
   single-VIP RPS, not two per-port RPSs.
3. Mid-burst failover budget (`fall × inter` per pattern
   C in the docs) is measured, not asserted.
4. The WAF surfaces what an LB needs to drive it well —
   per-node `node.id`, `/healthz/ready` semantics that
   match real LB health checks, peer membership on
   `/api/cluster.peers`.

## Scope

In scope:

- HAProxy reference container in `deploy/`, wired into
  `docker-compose.dev.yml` so `tests/cluster/run-all.sh`
  can use it.
- Two new cluster smoke scripts (`05-single-vip-baseline.sh`,
  `06-mid-burst-failover.sh`).
- Code change to accept a stable `node.id` from config so
  cluster identity survives restart.
- Code change to populate `/api/cluster.peers[]` from a
  membership view (lease-watch, not gossip).
- Doc updates: `ha-clustering.md` Roadmap rows ticked off
  as items land.

Out of scope (deferred, separate plans):

- `redis_cluster` shards (HA roadmap row 5).
- `raft` backend (HA roadmap row 6).
- `foca_swim` gossip (HA roadmap row 7).
- Production-grade LB hardening (mTLS WAF↔LB, rate-limit
  on the LB itself, etc.).

## Constraints

- **No new top-level deps in the WAF.** All changes either
  use already-pulled crates or live in `deploy/` /
  `tests/`.
- **Backwards compatible.** Existing single-node configs
  (`dev.yaml`, `prod.yaml`) keep working. Cluster
  features are opt-in.
- **Audit-first.** Membership joins / leaves emit audit
  events with `class: system`.
- **No silent topology assumptions.** The LB recipe is in
  the WAF docs but the WAF doesn't *require* HAProxy —
  Nginx + k8s Ingress patterns must remain
  spec-compatible.

## Task IDs

`HA-T<n>` — HA cluster ingress track.

## Sub-tracks

### HA-T1 — HAProxy reference deploy

| ID | File | Outcome |
|----|------|---------|
| HA-T1.1 | `deploy/haproxy/haproxy.cfg` | Multi-backend HAProxy config: `balance roundrobin`, `option httpchk GET /healthz/ready`, `inter 2s fall 2 rise 1`, ALPN h2 + http/1.1, end-to-end TLS to backends optional. |
| HA-T1.2 | `deploy/haproxy/Dockerfile` | (Optional) thin wrapper image baking the cert + cfg in for prod; reference for ops. Test rig uses upstream `haproxy:2.9-alpine` with mounted volumes. |
| HA-T1.3 | `deploy/docker-compose.dev.yml` | New `aegis-lb` service exposing `:9180` (plain) + `:9443` (TLS, mounting `tests/fixtures/tls/`). `depends_on: { aegis-redis: service_healthy, aegis-httpbin: service_started }`. |
| HA-T1.4 | `deploy/README.md` | New §"HAProxy in front of the WAF cluster" walking through the topology + bring-up. |

### HA-T2 — Single-VIP load test

| ID | File | Outcome |
|----|------|---------|
| HA-T2.1 | `tests/cluster/05-single-vip-baseline.sh` | Boots 2 WAF nodes + HAProxy. Runs k6 baseline against `aegis-lb:9180`. Asserts both backends served ≥ 30 % of traffic each (via HAProxy stats endpoint). Captures per-node RPS, single-VIP RPS, p95 / p99 latencies. |
| HA-T2.2 | `tests/cluster/06-mid-burst-failover.sh` | Boots both nodes + LB. Starts `baseline.js` for 30 s. At t=10 s `kill -9` node B. Asserts `allow_success` stays > 95 % (LB pulls B within `fall × inter`). Captures the 5xx spike duration. |
| HA-T2.3 | `tests/cluster/run-all.sh` | Drive 05 + 06 after the existing 01..04. Stays opt-in via `AEGIS_LB_TESTS=1` so devs without HAProxy pulled don't pay the bring-up cost on every run. |
| HA-T2.4 | `tests/cluster/HA-TEST-METHODOLOGY.md` | Update §"Recommendation" once HAProxy lands; flip from "this is the plan" to "this is what runs in CI". |

### HA-T3 — Stable `node.id`

| ID | File | Outcome |
|----|------|---------|
| HA-T3.1 | `crates/aegis-core/src/config.rs` | Extend top-level config with `node: { id: Option<String> }`. `serde(default)` so existing configs keep working. |
| HA-T3.2 | `crates/aegis-bin/src/lease_select.rs` | When `cfg.node.id` is set, use it verbatim. Otherwise fall back to today's hostname-PID-nanos derivation. |
| HA-T3.3 | `crates/aegis-control/src/api/tracking.rs` | `our_node` already serialises this; add a unit test that asserts the configured `node.id` round-trips. |
| HA-T3.4 | docs | `ha-clustering.md` Roadmap row 3 tick. |

### HA-T4 — Membership on `/api/cluster.peers[]`

Today `peers` is always `[]`. The dashboard shows a leader
badge but no roster. We surface peers via a lightweight
lease-watch loop (no gossip — that's HA-roadmap-7).

| ID | File | Outcome |
|----|------|---------|
| HA-T4.1 | `crates/aegis-proxy/src/cluster_lease/membership.rs` | Each node publishes a self-record under `members:<node_id>` with TTL 30 s, refreshed every 10 s via `set_nx + expire`. |
| HA-T4.2 | `crates/aegis-control/src/api/tracking.rs` | `LeaderView` gains a `members: ArcSwap<Vec<MemberRecord>>` cell. Background poller in `aegis-proxy::run` lists `members:*` keys + populates the cell. |
| HA-T4.3 | `crates/aegis-control/src/api/tracking.rs` | `ClusterResponse.peers` now reads from the cell. Each peer carries `id`, `addr`, `version`, `last_heartbeat`, `leases: Vec<String>` (we already have this shape from the v2 design — wire the data, not the schema). |
| HA-T4.4 | `tests/cluster/01-shared-counter.sh` | Strengthen: also assert both nodes see each other in `peers[]`. Today the script proves shared *counter* visibility but not shared *membership* visibility. |

### HA-T5 — LB-friendly readiness semantics

`/healthz/ready` already returns 503 during rehydrate. Two
small follow-ups for LB integration:

| ID | File | Outcome |
|----|------|---------|
| HA-T5.1 | `crates/aegis-proxy/src/lib.rs` | Optional `?strict=1` query param: when set, also returns 503 while the cluster lease is held by another node — useful for active-passive LB shapes that want to route traffic only to the leader. |
| HA-T5.2 | `crates/aegis-proxy/src/lib.rs` | Drain mode: a `SIGTERM` (or `POST /admin/drain`) flips a flag that makes `/healthz/ready` start returning 503 immediately so the LB pulls the node out, *then* the gateway finishes in-flight requests + exits. Already partially wired via `supervisor.rs`; just route through the readiness probe. |
| HA-T5.3 | `tests/cluster/06-mid-burst-failover.sh` | Add a graceful path variant that uses `SIGTERM` instead of `SIGKILL`; assert zero 5xx on the kill window. |

## Order of execution

`HA-T1 → HA-T2 → HA-T4 → HA-T3 → HA-T5`.

`HA-T2` is gated on `HA-T1` (LB has to exist before we can
test through it).

`HA-T4` (membership) gates `HA-T3` only loosely — we want
the test scripts in HA-T2 already running so the `peers[]`
assertion in HA-T4.4 has a moving baseline.

`HA-T5` last because graceful drain + leader-only readiness
are quality-of-life knobs, not gating contracts.

## Acceptance

After all five sub-tracks land:

- `tests/cluster/run-all.sh AEGIS_LB_TESTS=1` runs 6
  scripts; 6 PASS.
- `tests/results/run-NN-…/README.md` publishes a
  single-VIP RPS + a measured failover budget.
- `docs/operations/ha-clustering.md` Roadmap rows 1
  ("HA load-balancer reference deploy"), 3 ("`node.id`
  config knob"), and 8 ("Per-member health on
  `/api/cluster.peers`") are ticked off.
- `Implement-Progress.md` carry-over 6 closes.

## What we deliberately deferred

- `redis_cluster`, `raft`, `foca_swim` — orthogonal,
  separate plans. None blocks this track.
- mTLS between LB and WAF backends — nice-to-have, but
  not required for the test-methodology fix.
- Per-route active-passive routing on the LB — works
  fine on HAProxy with `backup` flag but specifies
  out of v1 of this plan.
- A full sticky-session test (cookie-based or
  source-IP-hash) — the docker bridge obscures real
  client IPs, so any sticky test on the local rig is a
  toy. Real coverage needs a multi-host CI runner;
  separate plan.

## Rough effort

- `HA-T1`: ~2 hours (HAProxy config + compose tweak +
  doc paragraph).
- `HA-T2`: ~3 hours (two scripts + run-all wiring + the
  log capture format the results README expects).
- `HA-T3`: ~1 hour (config field + lease_select branch +
  unit test).
- `HA-T4`: ~half a day (membership writer + reader +
  lease list scan + `peers[]` shape verification).
- `HA-T5`: ~half a day (readiness branch + drain path +
  graceful-kill test).

Total ≈ 1.5 days of focused work for one engineer.

## Open questions

- HAProxy vs Envoy as the reference — HAProxy is simpler
  for the test rig, Envoy is the de-facto Kubernetes
  ingress option. Picking HAProxy for HA-T1; documenting
  Envoy as a "follow this pattern" addendum in
  `ha-clustering.md` rather than a second test rig.
- Membership lease TTL — 30 s is conservative; tighter
  TTL (5 s, matching `leader:cluster`) gives faster
  detection but more Redis writes. HA-T4.1 should make
  this configurable with the conservative default.
- `/api/cluster.peers[]` schema — the v2 doc shape has
  `version`, `last_heartbeat`, `leases`. We can populate
  all three from the membership record + the existing
  lease-holder polling; there's no need to track
  `addr` separately if we use the listener bind from
  config.
