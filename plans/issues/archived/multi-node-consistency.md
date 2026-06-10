# Multi-node consistency — concerns & improvement plan

> **✅ RESOLVED / ARCHIVED (2026-06-10).** Every concern (C-1…C-5) is shipped or
> dropped — see the implementation plan
> [`../../archive/multi-node-consistency-implementation.md`](../../archive/multi-node-consistency-implementation.md)
> (P1/C-5, P2/C-1, P3/C-3·C-4 shipped; P4/C-2 dropped by operator decision) and
> the forward fleet-console work in
> [`../../archive/cluster-mode-multinode-sync.md`](../../archive/cluster-mode-multinode-sync.md).
> Original analysis retained below for history.

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
| **Client IP via `X-Forwarded-For`** | n/a — XFF is **ignored** (trusted-proxies empty + unplumbed) | n/a | **C-5** |

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
3. **Verification:** ✅ DONE (2026-06-10) — `tests/cluster/07-control-plane-sync.sh`
   asserts `set_profile {all,log_only}` on node A flips node B's `X-WAF-Mode`
   (observed via the data-plane response header: SQLi probe goes 403→200+log_only),
   and that `reset_state` is accepted fleet-wide. (Also fixed a config-path bug that
   had been silently skipping the whole `tests/cluster/` rig.) The medium /
   cluster-native propagation (#2) shipped as C-1 / cluster plan Phase 0.

---

## C-2. `/healthz/ready` is upstream-blind — DROPPED (2026-06-10)

Removed from the roadmap by operator decision. `/healthz/ready` stays **node-local
by design** (state rehydrated + listeners bound + not draining; `health.rs::check_ready`).
Rationale: in the shared-upstream topology every node reaches the same backends, so an
upstream outage hits all nodes equally — yanking one from the LB via readiness helps
nothing. The circuit breaker (`upstream/circuit.rs`) already surfaces upstream failures
as 502/`circuit_breaker`, which is the right signal. Re-open only if a topology with
per-node upstream-reachability divergence ever appears.

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

## C-5. `X-Forwarded-For` is ignored — no trusted-proxy plumbing (real client IP lost behind any LB)

### Current behaviour
The data plane *does* read `X-Forwarded-For` and walk it through a trusted-proxy
list (`ip_rep/xff.rs::resolve_client_ip`, called at `data_plane.rs:~283`), **but the
list is hardcoded EMPTY**:
```rust
// data_plane.rs:3197
fn default_trusted_proxies() -> Vec<ipnet::IpNet> {
    // F-HIGH-002 — default is now empty ... peer.ip() wins (safe + contract-compliant)
    Vec::new()
}
```
With no trusted proxy, `resolve_client_ip(peer, xff, [])` **always returns the TCP
peer** and ignores XFF. The config knob the comment promises
(`cfg.ip_lists.trusted_proxies`) is **not yet plumbed into the handler** — so today
there is **no way to make the WAF honor XFF**, even intentionally.

### The concern (acute in multi-node + LB)
The WAF keys per-client risk on `{ip, device_fp, session}`, where `ip` = TCP peer.
Behind anything that isn't a transparent edge:
- **L7 LB (nginx `http`)** or any SNAT hop → the WAF's peer is the **LB's IP** for
  *every* client. XFF carries the real client, but the WAF ignores it → **all traffic
  collapses onto one risk/rate-limit/DDoS key** (legit gets blocked alongside an
  attacker; per-IP limits trip globally). Verified earlier: a request with
  `X-Forwarded-For: 5.195.235.51` from `127.0.0.1` still logged `client_ip 127.0.0.1`.
- **L4 `stream` LB** → SNAT too (peer = nginx IP); `stream` can't even add XFF, so
  there's nothing to resolve.
- **DNS round-robin / TPROXY** → peer **is** the real client → correct. (This is why
  the prod topology is DNS-RR / WAF-at-edge.)

So the practical rule today: **per-IP features are only correct when the WAF sees the
real peer** (DNS-RR or TPROXY). Any LB that terminates/SNATs breaks them, and XFF
cannot rescue it yet.

### Suggested improvements
1. **Plumb `cfg.ip_lists.trusted_proxies` into the data-plane handler** — replace the
   hardcoded `default_trusted_proxies()` with the configured list (default still
   empty/safe). Then an operator fronting the fleet with a *trusted* L7 LB sets
   `trusted_proxies: [<LB CIDRs>]`, and `resolve_client_ip` walks XFF right-to-left
   to the real client. This is the single change that unblocks the L7-LB topology +
   the device_fp/risk correctness behind it.
2. **Hot-reloadable + per-listener** — make the trusted set part of the config plane
   (converges fleet-wide, C-1-style) so all nodes agree on which proxies to trust.
3. **Guardrails** — keep default empty; require explicit opt-in; document that
   trusting a proxy that doesn't *overwrite/append* XFF safely re-opens the spoofing
   hole F-HIGH-002 closed. Pair with the contract's §10 source-IP trust model.
4. **Until then**, the supported way to preserve client IP in a fleet is **DNS-RR**
   (or TPROXY); document that L7-LB + XFF is **not** functional yet. (See
   `deploy/PRE-PROD-DEPLOY.md` §13 and the nginx `http` notes.)

---

## Priority

| Concern | Severity (fleet) | Effort | Recommended action |
|---|---|---|---|
| **C-1** control-plane sync | **High** (breaks determinism) | Low (fan-out) → Med (config-plane) | fan-out now; cluster-native next |
| **C-5** XFF ignored / no trusted-proxy | **High** *if fronting with an L7/SNAT LB* | Med (plumb `trusted_proxies`) | DNS-RR/TPROXY now; plumb trusted_proxies to enable L7-LB |
| **C-3** console aggregation | Med (observability) | Low (SigNoz dashboards) | aggregate in SigNoz; label console per-node |
| **C-4** log aggregation | Med | Low (SigNoz) → Med (shared sink) | SigNoz + `request_id` correlation; document |
| ~~**C-2** readiness upstream-blind~~ | — | — | **DROPPED (2026-06-10)** — upstream-blind readiness is the correct default for shared upstreams; circuit breaker already surfaces failures |

**Common thread:** the **data/state plane is already cluster-consistent** (config +
risk + block-list + challenge via Redis); the gaps are in the **control plane**
(`set_profile`/`reset_state` per-node — C-1), **client-IP identity behind an LB**
(XFF ignored — C-5), and the **observability plane** (console + logs per-node —
C-3/C-4). Fastest wins: a control fan-out helper (C-1) + SigNoz fleet dashboards
(C-3/C-4). The two code changes worth scheduling: **cluster-native `set_profile`
propagation** (C-1) and **plumbing `trusted_proxies` so XFF works behind a trusted
LB** (C-5) — together they unlock a proper L7-LB topology with correct per-client
risk.
