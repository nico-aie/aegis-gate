# CP-07 · Copilot summary is cluster-aware (fleet-wide telemetry)

**Covers:** AI Copilot — cluster-aware summarization (`copilot/cluster.rs`) ·
**Severity:** **Medium** · **Expected duration:** ~6 min ·
**Prereq:** CP-02 green; traffic driven via the LB (spread across nodes).

## Test

**Given** the cluster telemetry surface (merged audit / fleet_view) is what
the copilot was built to summarize — "what's happening across the fleet, in
one paragraph". The summary should reflect activity handled by **all**
nodes, not just the node whose console you asked from.

**When** the operator drives attacks through the LB (spread across the 3
nodes) and requests a summary from each console.

**Then** the summaries reflect the **fleet-wide** picture and are
**consistent** across N1/N2/N3 (same incident, same top attackers), not
three divergent single-node views.

## Paste-to-Claude (copy verbatim)

> Data-plane tab on the LB; tabs N1/N2/N3.
>
> 1. Drive a clear, attributable burst via the LB (reuse CL-06 step 1 with a
>    distinctive IP set, e.g. 198.51.100.20-24) so it spreads across nodes.
> 2. Request a summary on N1, then N2, then N3:
>    ```js
>    (async () => (await (await fetch('/api/copilot/summary',{credentials:'include'})).json()))()
>    ```
> 3. Compare the three briefs: do they name the same top attackers / attack
>    types / targets (fleet-wide), or does each node only describe ~1/3 of
>    the traffic (per-node, not cluster-aware)?

## Pass criteria

- [ ] Each console's summary reflects the **fleet-wide** burst, not just its
      own node's share.
- [ ] The three summaries are materially **consistent** (same incident,
      same top attackers) — divergent single-node views ⇒ MEDIUM
      (cluster-awareness gap).
- [ ] No node errors when summarizing.

## Findings template

- The three briefs side by side.
- Fleet-wide vs per-node verdict; consistency notes.
