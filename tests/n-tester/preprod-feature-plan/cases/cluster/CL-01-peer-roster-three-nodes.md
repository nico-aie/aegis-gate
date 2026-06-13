# CL-01 · Cluster shows a 3-peer roster with distinct node identity

**Covers:** Cluster Mode — leaderless peer roster · **Severity:** **High** ·
**Expected duration:** ~5 min · **Prereq:** all 3 consoles logged in.

## Test

**Given** three WAF nodes behind the LB, each with its own admin console.

**When** the operator opens each console and reads `/api/cluster` (and the
Overview / Scaling page that renders it).

**Then** every node reports the **same flat roster of 3 peers**, each node
identifies **itself** correctly via `our_node` (a different value per
console), and there is **no leader** field (`is_leader` / `leader_node`
must be absent — the cluster is leaderless).

## Paste-to-Claude (copy verbatim)

> I have three tabs open, logged in as admin:
> - N1 = http://185.23.199.194:56243/
> - N2 = http://185.23.199.194:56244/
> - N3 = http://185.23.199.194:56245/
>
> On EACH tab, run this in the page console and report the JSON:
>
> ```js
> (async () => (await fetch('/api/cluster', {credentials:'include'})).json())()
> ```
>
> For each node tell me: (a) the list of peer node ids/addresses, (b) the
> `our_node` value, (c) whether any field named `is_leader`, `leader`, or
> `leader_node` appears anywhere in the payload.
>
> Then on N1 click the left-sidebar **Scaling** page (and **Overview**),
> screenshot the node/peer panel, and tell me how many nodes it shows and
> whether each is marked healthy/ready.

## Pass criteria

- [ ] All three consoles return a roster of **exactly 3 peers**, and the
      three rosters list the same set of nodes.
- [ ] `our_node` differs across N1/N2/N3 and matches the console you ran it on.
- [ ] **No** `is_leader` / `leader` / `leader_node` field anywhere (leaderless).
- [ ] Scaling/Overview renders 3 nodes, each shown healthy/ready — and the
      panel does not paint red on a healthy fleet (reserve red for outages).
- [ ] Page mounts cleanly on all three (no error-boundary card).

## Findings template

- The three `our_node` values + roster.
- Any leader field present (→ HIGH, contradicts leaderless design).
- Screenshot name of the Scaling node panel per node.
