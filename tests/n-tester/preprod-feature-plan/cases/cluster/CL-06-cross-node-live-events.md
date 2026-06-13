# CL-06 · Live Feed shows events generated on other nodes (fleet_events)

**Covers:** Cluster Mode — cross-node live event sync (`cluster.fleet_events`,
Redis pub/sub) · **Severity:** **High** · **Expected duration:** ~6 min ·
**Prereq:** data-plane tab on LB; CL-01 green.

## Test

**Given** Phase-2 console sync: live security events are published over
`cluster.fleet_events` so any console shows the **fleet's** activity, not
just its own node's.

**When** the operator drives attack traffic through the LB (spread across
nodes) and watches the **Live Feed** on a single console.

**Then** the Live Feed on that one console surfaces events that were
handled by the **other** nodes — i.e. the count of blocked attacks shown
is fleet-wide, and each event row carries the originating node / peer info,
with audit fields (`method`, `path`, `status`, `detectors`) populated.

## Paste-to-Claude (copy verbatim)

> Data-plane tab at http://185.23.199.194:56208/__qa-anchor.
> Admin tab N1 = http://185.23.199.194:56243/ → open the **Live Feed** page,
> leave it visible (resume/streaming, not paused).
>
> 1. From the data-plane tab, drive 15 obvious attacks spread by the LB:
>    ```js
>    (async () => {
>      const atk=['/?q=<script>alert(1)</script>','/login?u=admin\'+OR+1=1--',
>                 '/files?p=../../../../etc/passwd','/.env','/fetch?url=http://169.254.169.254/'];
>      for (let i=0;i<15;i++){
>        await fetch(atk[i%atk.length]+'&n='+i,{headers:{'X-Forwarded-For':'198.51.100.'+(20+i%5)}});
>      }
>      return 'done';
>    })()
>    ```
> 2. Watch N1's Live Feed. Tell me: roughly how many of those 15 appear,
>    and whether any row indicates it was handled by a node OTHER than N1
>    (look for a node id / peer column or in the row-detail drawer).
> 3. Open one row's detail drawer; report whether `method`, `path`,
>    `status`, and `detectors` are populated, and whether `X-WAF-Request-Id`
>    correlates to a value you can also see in the row.
> 4. Cross-check: on N2 open Live Feed — does it show the same fleet-wide
>    set (allowing for ordering)? Screenshot both feeds.

## Pass criteria

- [ ] N1's Live Feed surfaces events handled by other nodes (fleet-wide,
      not just N1's share) — if N1 only ever shows ~1/3 of the traffic,
      cross-node sync is broken (HIGH).
- [ ] Event rows carry node/peer attribution (or the detail drawer does).
- [ ] Audit fields `method` / `path` / `status` / `detectors` populated;
      not `—` placeholders.
- [ ] Each blocked request is **one** row, not two (no double-write).
- [ ] N2's feed shows the same fleet-wide set.
- [ ] Live Feed mounts cleanly; Pause/Resume + filters work.

## Findings template

- Count seen on N1 vs the 15 driven; node attribution present?
- Drawer field completeness.
- Any double-rows; screenshots N1 + N2.
