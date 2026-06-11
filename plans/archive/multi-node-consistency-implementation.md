# Multi-node consistency — implementation plan

> **✅ ARCHIVED (2026-06-10).** Every concern here is shipped (P1/C-5, P2/C-1,
> P3/C-3·C-4) or dropped (P4/C-2, by operator decision). Moved from `plans/` →
> `plans/archive/` for history. Forward fleet-console work continues in
> [`cluster-mode-multinode-sync.md`](./cluster-mode-multinode-sync.md).

> **Status (2026-06-10): P1, P2, P3 implemented — P4 deferred.** Scheduling
> plan derived from the analysis in
> [`issues/multi-node-consistency.md`](../issues/archived/multi-node-consistency.md)
> (C-1…C-5).
>
> - **P1 / C-5 — ✅ shipped:** `proxy.trusted_proxies` plumbed end-to-end
>   (config → `ProxyContext` → `resolve_client_ip`); default empty.
> - **P2 / C-1 — ✅ shipped:** `set_profile` / `reset_state` converge
>   fleet-wide via `interop::cluster_sync` (`control:waf:modes` +
>   `control:waf:reset_epoch`) + a per-node poller; Redis-gated.
> - **P3 / C-3 — ✅ shipped:** `FleetNodeBanner` "showing THIS node" on the
>   Overview page. Fleet metric *aggregation* itself stays in SigNoz (and is
>   expanded in [`future/cluster-mode-multinode-sync.md`](./cluster-mode-multinode-sync.md)).
> - **P4 / C-2 — DROPPED (2026-06-10, operator decision):** upstream-aware
>   readiness removed from the roadmap. Upstream-blind readiness is the correct
>   default for the shared-upstream topology (all nodes reach the same backends,
>   so yanking one from the LB on an upstream outage helps nothing); the circuit
>   breaker already surfaces upstream failures as 502/`circuit_breaker`.
>
> The deeper fleet-console work (leaderless roster, ≤5s event fanout,
> fleet-snapshot merge) is carried forward in
> [`future/cluster-mode-multinode-sync.md`](./cluster-mode-multinode-sync.md).
> With C-2 dropped, every concern in this doc is now shipped or dropped — this
> doc can move to `archive/`.

## Framing — triage by topology, don't "fix all 5"

The **data/state plane is already cluster-consistent** (config, risk,
block-list, challenge all converge via Redis). Every gap here lives in the
**control plane (C-1)**, **client-IP identity behind an LB (C-5)**, or the
**observability plane (C-3/C-4)** — and **only bites when N>1 nodes sit
behind an SNAT/L7 load balancer.** The supported topology today (single
Redis, DNS-RR / WAF-at-edge) makes most of these *latent*, not active.

So this plan sequences by **leverage-per-effort**, not by C-number:

| Phase | Concern | Why this order | Effort | Code change? |
|---|---|---|---|---|
| **P1** | C-5 — plumb `trusted_proxies` | Small, self-contained; unblocks the **entire** L7-LB topology + per-client risk correctness. Highest leverage. | Med | ✅ yes |
| **P2** | C-1 — control-plane sync | Make `set_profile` + the local half of `reset_state` converge cluster-wide through the config plane (real code). | Med | ✅ yes |
| **P3** | C-3 / C-4 — observability | Mostly **already covered by SigNoz**. Only a per-node console banner + an audit-collect script are worth WAF-side effort. | Low | minimal |
| ~~**P4**~~ | ~~C-2 — readiness~~ | **DROPPED (2026-06-10)** — upstream-blind readiness is the correct default; the circuit breaker already surfaces upstream failures. | — | — |

**If only two things get scheduled:** P1 (C-5) + P2 (C-1 cluster-native
propagation). Together they turn "works as a single edge node" into "works
as a real fleet."

> **Boundary note** (per the WAF-vs-gateway call): nothing here crosses the
> WAF/gateway line — it's all WAF-internal plane consistency, legitimately
> in-scope for the WAF *when/if* it goes multi-node. If the AI Operator
> Copilot or another track is the active priority, this whole plan is
> "scheduled, not now" — **nothing here is broken for a single-node or
> DNS-RR deployment.**

---

## P1 — C-5: plumb `cfg…trusted_proxies` into the data-plane handler

### Goal
Make the WAF able to honor `X-Forwarded-For` from an operator-declared set
of trusted proxies, so per-client risk / rate-limit / DDoS keys are correct
behind a trusted L7/SNAT LB. Default stays **empty = peer.ip() wins** (the
F-HIGH-002-safe posture). This is the single change that unblocks the L7-LB
topology.

### Current state (verified 2026-06-10)
- `aegis-security` already has the runtime field:
  `ip_rep/mod.rs:13` `IpLists { trusted_proxies: Vec<IpNet> }` and
  `resolve_client_ip(peer, xff, &trusted)` (`ip_rep/xff.rs:13`).
- But the data plane **ignores config**: `data_plane.rs:285` calls
  `default_trusted_proxies()` which hard-returns `Vec::new()`
  (`data_plane.rs:3214`). There is **no `ip_lists` / `trusted_proxies` field
  in `WafConfig`** — `cfg.ip_lists.trusted_proxies` from the analysis is
  aspirational; it must be added.
- The function **docstring** at `data_plane.rs:3209-3213` is **stale** — it
  claims "loopback + RFC1918 out of the box," which the body no longer does.
  Fix it in this phase.

### Changes
1. **Config schema** (`crates/aegis-core/src/config.rs`)
   - Add a `trusted_proxies: Vec<String>` field (CIDR strings) to the
     network/ip-lists section of `WafConfig` (introduce a small
     `IpListsConfig` / extend the existing network config — follow whatever
     section already owns edge/source-IP knobs; keep one home for it).
   - `#[serde(default)]` → **default empty**. Validate each entry parses as
     `ipnet::IpNet` in `Config::validate()`; reject with a clear error.
2. **Thread config → handler** (`crates/aegis-proxy/src/data_plane.rs`)
   - Replace the `default_trusted_proxies()` call at `:285` with the parsed
     list sourced from the active `WafConfig` (the data plane already holds
     an `ArcSwap<Config>`-style handle; read it there).
   - Delete or repurpose `default_trusted_proxies()` (`:3214`); **rewrite the
     stale docstring** at `:3209`.
   - Confirm right-to-left XFF walk semantics are preserved
     (`resolve_client_ip` already does this — no change there).
3. **Hot-reload + fleet convergence** — the field rides the existing
   `config:waf:doc` config plane, so it converges fleet-wide on the ~3s
   watcher cadence (same mechanism as detectors). No new sync path.
4. **Guardrails** — keep default empty; require explicit opt-in; in the
   config REFERENCE doc, warn that trusting a proxy that doesn't
   overwrite/append XFF re-opens the F-HIGH-002 spoofing hole.

### Tests
- Unit: `resolve_client_ip` with a configured trusted CIDR returns the real
  client from XFF; with empty list returns the peer (regression guard for
  F-HIGH-002).
- Config: `load_config_str` accepts `trusted_proxies: ["10.0.0.0/8"]` and
  rejects a malformed CIDR.
- Data-plane integration: a request from a trusted-proxy peer with
  `X-Forwarded-For: <client>` keys risk on `<client>`; from an untrusted
  peer it keys on the peer (the existing v2.3 §6 contract assertion at
  `tests/contract/v2.3_compliance.sh:299-302` must still pass).

### Acceptance
- Default config → behavior **unchanged** (peer wins, contract green).
- With `trusted_proxies` set to the LB CIDR, a request behind an nginx
  `http` LB logs the **real client IP**, and per-IP risk/rate-limit no
  longer collapse onto the LB's address.
- Stale docstring corrected.

---

## P2 — C-1: control-plane sync (`set_profile` / `reset_state`)

### Goal
A single `set_profile` / `reset_state` call converges the whole fleet,
restoring the determinism contract (§2.4/§2.5) when N>1 nodes sit behind a
balancer.

### Current state (verified 2026-06-10)
- `set_profile` writes a purely **in-process** `ArcSwap<ModeSnapshot>`
  (`interop/mode.rs:67` `ModeStore`, no Redis/config-plane write) → flips
  **one** node only.
- `reset_state` (`interop/control.rs:316 reset_state_async`) wipes shared
  Redis fleet-wide **plus** the node-local trackers → other nodes' local
  trackers stay warm.
- Endpoints are loopback-gated; the LB hits one node.

### Approach — cluster-native propagation through the config plane (code)
Reuse the machinery that already converges `ai.enabled`/detectors fleet-wide;
**no ops fan-out script.** A single call converges every node.

1. **Publish `set_profile` to shared state.** Today it writes only the
   in-process `ArcSwap<ModeSnapshot>` (`interop/mode.rs:67`). Route the
   mutation through the config plane — write a sibling `control:waf:*` key
   (or fold the enforce/log_only map into the versioned `config:waf:doc`) via
   the existing CAS path. Each node's watcher applies the change to its local
   `ModeStore` on convergence (~3s), exactly as the detector toggle does.
2. **Make the local half of `reset_state` cluster-aware.** The shared-Redis
   wipe (`interop/control.rs:316 reset_state_async`) already fans out fleet-
   wide; keep it. Add a cluster-scoped **epoch/generation** signal on the
   same `control:waf:*` key so every node also flushes its **local** trackers
   when the epoch bumps — closing the "other nodes' local caches stay warm"
   gap.
3. **`scope: node | cluster` field, default `cluster`.** The OC/operator can
   still target a single node (the current loopback behavior) by passing
   `scope: node`; `cluster` (default) goes through the config plane.
4. **Keep the loopback gate.** The endpoints stay loopback-only on each node;
   `cluster` scope just means "this node writes the shared key," not "this
   node is reachable from off-box."

### Files (anticipated)
- `crates/aegis-control/src/interop/mode.rs` — `ModeStore` gains a
  config-plane write path (or a watcher-applied setter).
- `crates/aegis-control/src/interop/control.rs` — `reset_state*` publishes a
  cluster epoch; local-tracker flush keys off it.
- `crates/aegis-proxy/src/admin_*` — `set_profile`/`reset_state` dispatch
  parses `scope`, writes the shared key for `cluster`.
- The config-plane watcher (`config:waf:doc` apply path) — apply the
  enforce/log_only map + reset epoch to local state on convergence.

### Tests
- `tests/cluster/`: 2-node test asserting `set_profile {scope: cluster}` on
  node A flips node B's `X-WAF-Mode`, and `reset_state {scope: cluster}`
  clears node B's local risk cache (not just shared Redis).
- Unit: `scope: node` leaves peers untouched (back-compat with the loopback
  single-node behavior); a default (no `scope`) request is treated as
  `cluster`.
- Unit: config-plane round-trip — a published enforce/log_only map applies to
  a second `ModeStore` via the watcher.

### Acceptance
- One `set_profile {scope: cluster, log_only}` call (or the default scope) →
  every node reports `X-WAF-Mode: log_only` within the watcher cadence.
- One `reset_state {scope: cluster}` call → every node's local trackers
  (not just shared Redis) are cleared.
- `scope: node` preserves today's single-node behavior.

---

## P3 — C-3 / C-4: observability (console + logs)

### Goal
Operators get a correct fleet view **without** building WAF-side aggregation
that turns the leader into a hotspot.

### Decision — aggregate in SigNoz, not the WAF
SigNoz already ingests every node's metrics/traces/logs tagged
`host.name=<node.id>` via per-node otel agents. Build the fleet dashboards
there (sum RPS, p95 across `host.name`, top attackers fleet-wide). The WAF
console stays per-node, clearly labelled.

### Changes (minimal, WAF-side)
1. **C-3 — console clarity** (`crates/aegis-control/assets/dashboard`):
   add a header banner "**N-node fleet — showing THIS node** (`<node.id>`)"
   so per-node RPS / Top-Attackers / p95 are never mistaken for fleet
   totals. Surface `/api/cluster` peers prominently. *(No new aggregation
   API — explicitly **not** building the leader fan-in; it's over-engineering
   for this stage.)*
2. **C-4 — audit correlation**:
   - Add `deploy/collect-audit.sh`: scps every node's `waf_audit.log`, merges
     and sorts by `ts_ms`, joins on `X-WAF-Request-Id`.
   - Document in the deploy/QC runbook that for a fleet, the OC must
     aggregate audit across all nodes (or query SigNoz) and join on
     `request_id` — a round-robined request may be decided on a different
     node than the one whose file is being read.
   - Make `host.name=<node.id>` mandatory in the otel agent
     (`deploy/otel/collector-agent.yaml`) so SigNoz joins logs+traces+metrics
     per node.

### Tests / verification
- Manual: leader dashboard shows the banner + peer roster.
- `collect-audit.sh` against a 2-node sandbox produces a single
  `request_id`-correlated stream.

### Acceptance
- SigNoz fleet dashboard exists (ops artifact, not code).
- Console no longer presents per-node numbers as fleet totals.

---

## P4 — C-2: upstream-aware readiness — DROPPED (2026-06-10)

Removed from the roadmap by operator decision. Rationale: in the shared-upstream
topology every node reaches the same backends, so an upstream outage hits all
nodes equally — de-registering one from the LB on `/healthz/ready` helps nothing.
The circuit breaker (`upstream/circuit.rs`) already surfaces upstream failures as
502/`circuit_breaker`, which is the correct signal. Upstream-blind readiness
(WAF-health only) stays the intended behaviour. Re-open only if a per-node
upstream-reachability-divergence topology ever appears.

---

## Suggested sequencing

1. **P1 (C-5)** — schedule first. Small, unblocks L7-LB + fixes per-client
   identity. The one change with outsized payoff.
2. **P2 (C-1 cluster-native)** — the other real code change: `set_profile` +
   `reset_state` converge fleet-wide through the config plane.
3. **P3 (C-3/C-4)** — cheap clarity: console banner + collect-audit script +
   SigNoz dashboards. Mostly ops.

> The two code changes worth real engineering time are **P1** and **P2**;
> P3 is a console banner + an ops script + SigNoz dashboards. (P4/C-2 was
> dropped — see above.)
