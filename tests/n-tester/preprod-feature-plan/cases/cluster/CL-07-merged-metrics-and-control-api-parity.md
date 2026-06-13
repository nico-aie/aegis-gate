# CL-07 · Merged fleet metrics + control-API parity across nodes

**Covers:** Cluster Mode — `cluster.fleet_view` merged metrics + contract
control endpoints on every node · **Severity:** **High** ·
**Expected duration:** ~8 min · **Prereq:** CL-06 done (so there's traffic signal).

## Test

**Given** Phase-3 merged metrics: each console's Overview shows
**fleet-wide** aggregated traffic via TTL'd `fleet:snap:*` snapshots; and
the contract requires the control endpoints (§2.1–2.4) on each node.

**When** the operator compares the aggregated numbers across consoles and
exercises the control API on each node.

**Then** the three consoles agree on the merged totals (within snapshot
TTL skew), and each node answers `/__waf_control/capabilities`,
`set_profile`, `reset_state` per the contract — including the
`X-Benchmark-Secret` auth gate.

## Paste-to-Claude (copy verbatim)

> Tabs: N1=:56243, N2=:56244, N3=:56245. Data-plane tab on the LB.
>
> **Part A — merged metrics agree.**
> 1. On each of N1/N2/N3, read the aggregate traffic counters the Overview
>    shows. In each console run:
>    ```js
>    (async () => (await fetch('/api/stats/timeseries?window=3600',{credentials:'include'})).json())()
>    ```
>    and also note the Overview "total requests / blocked" cards. Report
>    each node's totals.
> 2. Tell me whether the three nodes' fleet totals agree within ~1 snapshot
>    window (they should — it's a merged view, not per-node).
>
> **Part B — control-API parity + auth gate.** For EACH node's data origin
> (control endpoints are admin-local; run from that node's admin tab):
> 3. Capabilities WITHOUT the secret → expect 403:
>    ```js
>    (async () => {
>      const r=await fetch('/__waf_control/capabilities');
>      return {status:r.status};
>    })()
>    ```
> 4. Capabilities WITH the secret → expect 200 + a `features` map:
>    ```js
>    (async () => {
>      const r=await fetch('/__waf_control/capabilities',
>        {headers:{'X-Benchmark-Secret':'waf-hackathon-2026-ctrl'}});
>      return {status:r.status, body: await r.json()};
>    })()
>    ```
> 5. `reset_state` with the secret → expect `{ok:true, audit_log_preserved:true}`
>    and a < 5 s response:
>    ```js
>    (async () => {
>      const t=performance.now();
>      const r=await fetch('/__waf_control/reset_state',{method:'POST',
>        headers:{'X-Benchmark-Secret':'waf-hackathon-2026-ctrl'}});
>      return {status:r.status, ms: Math.round(performance.now()-t), body: await r.json()};
>    })()
>    ```
> Report results per node.

## Pass criteria

- [ ] Overview fleet totals **agree across all 3 consoles** within one
      snapshot window (divergence beyond TTL skew ⇒ HIGH: fleet_view broken).
- [ ] `/__waf_control/capabilities` returns **403 without** the secret on
      every node (§2.2).
- [ ] With the secret, returns 200 + a stable `features` map + `active.default_mode` (§2.3).
- [ ] `reset_state` returns `ok:true` + `audit_log_preserved:true`,
      synchronously, in < 5 s on every node (§2.4).
- [ ] All control responses are identical in shape across the 3 nodes (parity).
- [ ] Overview mounts cleanly on all three.

## Findings template

- Per-node fleet totals + agreement verdict.
- Per-node control-API: 403-no-secret? capabilities shape? reset_state ms + audit_log_preserved?
- Any node whose control API differs from the others.
