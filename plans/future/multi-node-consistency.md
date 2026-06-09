# Multi-node consistency — concerns & improvement plan

> **Status:** analysis / proposal (not yet implemented).
> **Context:** the `pre-prod` fleet runs **N WAF nodes** sharing one Redis
> (`state.redis.urls`), fronted by DNS round-robin or an nginx `stream` LB. Each
> node terminates TLS at the edge. This doc audits what is **cluster-consistent**
> vs **per-node-local** today, and proposes fixes. Concerns raised: control-plane
> sync (`/__waf_control/*`, `/challenge/verify`, config), `/healthz/ready` ↔
> upstream, admin-console aggregation, and logs.

## Summary table — what's shared vs per-node today

| Surface | Backing store | Cluster-consistent? | Gap |
|---|---|---|---|
| **Config** (detectors, rules, tiers, upstreams, risk thresholds, `ai.enabled`) | Redis `config:waf:doc` (versioned) | ✅ yes — watcher converges all nodes ~3s | — |
| **Risk score / rate-limit windows / auto-block / block-list** | Redis StateBackend (`g:*`) | ✅ yes — shared keys | — |
| **`/__waf_control/set_profile`** (enforce/log_only) | **in-process `ArcSwap`** (per node) | ❌ **no — local only** | **C-1** |
| **`/__waf_control/reset_state`** | local trackers **+** shared Redis | ⚠️ partial — Redis wiped fleet-wide, local trackers per-node | **C-1** |
| **`/challenge/verify`** | stateless token + Redis nonce (`g:nonce:*`) | ✅ yes — round-robin safe | — |
| **`/healthz/ready`** | node-local readiness signal | n/a (per-node by design) | **C-2** (upstream-blind) |
| **Admin console / dashboard metrics** (top-attackers, action mix, RPS, latency) | **local** Prometheus registry + local trackers | ❌ **no — shows local node only** | **C-3** |
| **`/api/cluster`** (roster, leader) | Redis lease store → `set_members` | ✅ yes — fleet roster | — |
| **Logs** (`logs/waf.json`, `./waf_audit.log`) | **per-node local files** | ❌ no — aggregated only in SigNoz | **C-4** |

---

## C-1. Control plane (`/__waf_control/*`) is per-node, not cluster-wide

### Current behaviour
- **`set_profile`** writes an **in-process** enforce/log_only map (`ArcSwap`,
  `aegis-control/src/interop/mode.rs`). It is **not** published to the config plane,
  so a call changes only the node that received it.
- **`reset_state`** (`interop/control.rs::reset_state_async`) clears two layers: the
  node's **local** in-process trackers (sync chain) **and** the **shared** Redis
  StateBackend (`rate-limit windows, nonces, auto-block, risk keys`). The Redis wipe
  is fleet-wide; the local-tracker wipe is per-node.
- **`/challenge/verify`** is fine — stateless PoW issuance + single-use nonce in
  shared Redis, so any node can verify a token issued by any other (round-robin safe).
- Endpoints are **loopback-gated** (`accept.rs::should_dispatch_data_plane_control`),
  reachable only from `127.0.0.1` on each node.

### The gap
The OC benchmarker (and operators) hit **one** endpoint — the LB → one node. So:
- `set_profile {all, log_only}` flips **one** node; the other N-1 keep enforcing →
  inconsistent decisions across the fleet for the same traffic.
- `reset_state` clears shared Redis once, but leaves the **other nodes' local
  trackers** warm → cross-run contamination on those nodes.

This breaks the contract's determinism guarantee (§2.4/§2.5) whenever the fleet has
> 1 node behind a balancer.

### Suggested improvements
1. **Short term (ops):** fan-out wrapper — a `fleet-control.sh` that calls
   `reset_state`/`set_profile` on **every** node's loopback admin (over SSH). Document
   in the deploy guide; use it in QC. *(No code change.)*
2. **Medium (make it cluster-native):** route `set_profile` and the local half of
   `reset_state` through the **config plane** (Redis `config:waf:doc` or a sibling
   `control:waf:*` key) so a single call converges to all nodes (same mechanism that
   already syncs detectors/`ai.enabled`). Add a `scope: node|cluster` field
   (default `cluster`) to the request so the OC can pick.
3. **Verification:** extend `tests/cluster/` with a 2-node test asserting
   `set_profile` on node A changes node B's `X-WAF-Mode`, and `reset_state` clears
   node B's local risk cache.

---

## C-2. `/healthz/ready` is upstream-blind

### Current behaviour
`/healthz/ready` is an **admin-plane open endpoint** (`admin_auth_middleware.rs`)
returning the node's own readiness — **state backend rehydrated + listeners bound +
not draining** (`state/rehydrate.rs`, `health.rs::check_ready`). It does **not**
proxy to, probe, or depend on the upstream. The LB uses it purely to gate traffic to
the node.

### The concern
A node can report **ready** while its **upstream pool is unreachable** → the LB keeps
sending it traffic, which then 502s at forward time. Readiness reflects WAF health,
not end-to-end serviceability.

### Suggested improvements
1. **Optional upstream-aware readiness:** add `health.upstream_gate: true` that folds
   a cheap upstream liveness signal (passive: recent forward success rate; or active:
   periodic `GET healthcheck_path`) into `check_ready`, so a node with all upstreams
   down de-registers itself from the LB.
2. **Keep the default OFF** — many deployments *want* the node to stay in rotation and
   surface upstream errors as 502/`circuit_breaker` rather than yank the whole node.
   Document the trade-off; let operators opt in per environment.
3. Expose a separate `/healthz/upstream` (admin) for observability regardless of the
   gate, so dashboards/LBs can see upstream health without coupling it to readiness.

---

## C-3. Admin console shows **local-node** data, not the fleet

### Current behaviour
- `/api/cluster` **is** fleet-aware — peers/leader populated from the lease store
  (`accept.rs` → `tracking::set_members`).
- But the **traffic metrics** the dashboard renders — Top Attackers, by-detector,
  bot mix, action breakdown, RPS, decision latency — come from each node's **local**
  Prometheus registry + local trackers. **Shared** state (risk scores, block-list)
  is consistent via Redis, but **per-request volume/latency/attack counts are
  per-node**. So the console on node A shows **node A's slice** of traffic, not fleet
  totals. There is **no leader-side aggregation**.

### The concern
Operators viewing the leader's dashboard see ~1/N of the picture (whatever the LB
sent that node). "Top attackers" / "RPS" / "p95" are per-node, which is misleading
for fleet situational awareness and for the dashboard scoring criterion.

### Suggested improvements
1. **Recommended — aggregate in the observability layer, not the WAF:** SigNoz
   already receives every node's traces/metrics/logs tagged `host.name=<node.id>`
   (per-node otel agents). Build the fleet dashboards there (sum RPS, p95 across
   `host.name`, top attackers by client IP fleet-wide). This is the cheapest,
   already-wired path — the WAF console stays per-node (clearly labelled "this
   node"), SigNoz is the fleet pane. **Lowest effort, highest value.**
2. **Medium — leader fan-in API:** the leader (lease holder) periodically pulls each
   peer's `/api/tracking/snapshot` (roster already known) and serves a merged
   `/api/cluster/snapshot`. Costs an internal mTLS/admin auth path + merge logic;
   risk of the leader becoming a hotspot. Only if an in-WAF fleet view is required.
3. **Cheap clarity now:** label the dashboard header with `our_node` + an
   "N-node fleet — showing THIS node" banner so per-node numbers aren't mistaken for
   fleet totals. Surface `/api/cluster` peers prominently.

---

## C-4. Logs are per-node; only SigNoz aggregates

### Current behaviour
- Each node writes its **own** `logs/waf.json` (app/tracing) and **`./waf_audit.log`**
  (contract §6 security decisions) as **local files**.
- Aggregation happens **only** in SigNoz, via a **per-node otel-collector agent**
  (filelog → OTLP, tagged `host.name`). There is **no fleet-wide log view inside the
  WAF**.
- The interop audit path (`./waf_audit.log`) is per-node → the OC reading a single
  node's file sees only that node's decisions.

### The concern
1. **Contract audit fragmentation:** the benchmarker reads `./waf_audit.log` on one
   node, but a round-robined request may have been decided on a **different** node, so
   that node's audit lacks the entry. Correlation must span all nodes.
2. **No single source of truth** for fleet logs without SigNoz.

### Suggested improvements
1. **Correlate by `request_id` across nodes** — already feasible: every response
   carries `X-WAF-Request-Id` and every node's audit/trace stamps it. Document that
   for a fleet, the OC must aggregate `./waf_audit.log` from **all** nodes (or query
   SigNoz) and join on `request_id`. Provide a `collect-audit.sh` that scps every
   node's `waf_audit.log` and merges/sorts by `ts_ms`.
2. **Optional shared audit sink:** add a Redis/object-store audit sink so all nodes
   append to one logical stream (with `node.id` per line). Heavier; SigNoz already
   covers the analytics case — only worth it if a single on-box file is mandated.
3. **Standardise the otel agent** (already drafted in `deploy/otel/collector-agent.yaml`)
   as the supported fleet-log path; make `host.name=<node.id>` mandatory so SigNoz
   joins logs+traces+metrics per node.

---

## Priority

| Concern | Severity (fleet) | Effort | Recommended action |
|---|---|---|---|
| **C-1** control-plane sync | **High** (breaks determinism) | Low (fan-out) → Med (config-plane) | fan-out now; cluster-native next |
| **C-3** console aggregation | Med (observability) | Low (SigNoz dashboards) | aggregate in SigNoz; label console per-node |
| **C-4** log aggregation | Med | Low (SigNoz) → Med (shared sink) | SigNoz + `request_id` correlation; document |
| **C-2** readiness upstream-blind | Low–Med | Med | opt-in upstream gate; `/healthz/upstream` |

**Common thread:** the **data/state plane is already cluster-consistent** (config +
risk + block-list + challenge via Redis); the gaps are in the **control plane**
(`set_profile`/`reset_state` per-node) and the **observability plane** (console +
logs per-node). The fastest wins: a control fan-out helper (C-1) and SigNoz fleet
dashboards (C-3/C-4); the cluster-native `set_profile` propagation (C-1) is the one
real code change worth scheduling.
