# MT-07 · Zero Trust config converges across the cluster + nav badge cleanup

**Covers:** mTLS — `zero_trust` config is shared cluster state; plus the
"drop NEW nav badges" cleanup (commit `b94f93e`) · **Severity:** **High** ·
**Expected duration:** ~6 min · **Prereq:** MT-02 green; CL-02 green.

## Test

**Given** Zero Trust config flows through the same config plane as the rest
(so a change on one node converges fleet-wide), and the nav was cleaned up
to drop the transient "NEW" badges.

**When** the operator changes a Zero Trust setting on **node-1** and checks
node-2/node-3, and reviews the sidebar nav.

**Then** the change converges to the other consoles within the convergence
window, and the sidebar no longer shows stale "NEW" badges on the mTLS /
Zero Trust nav items.

## Paste-to-Claude (copy verbatim)

> Tabs: N1=:56243, N2=:56244, N3=:56245.
>
> 1. On all three, snapshot the downstream/upstream Zero Trust config:
>    ```js
>    (async () => {
>      const u = await (await fetch('/api/zero-trust/upstream/config',{credentials:'include'})).json();
>      const v = await (await fetch('/api/config/version',{credentials:'include'})).json();
>      return {version:v, upstream:u};
>    })()
>    ```
> 2. On **N1**, make a safe, observable Zero Trust change (e.g. toggle
>    downstream `mode` disabled⇄optional if a ca_bundle exists, or add a SAN
>    to `allowed_sans`). Save; note time + toast.
> 3. Poll N2 and N3; report seconds until both reflect the change AND show a
>    higher config version. Revert on N1; confirm reconvergence.
> 4. On each console's sidebar, check the **Zero Trust** (and any mTLS)
>    nav item: is there a leftover "NEW" badge? Screenshot the sidebar.

## Pass criteria

- [ ] Zero Trust change made on N1 converges to N2 **and** N3 ≤ 10 s
      (MEDIUM 10–30 s; HIGH > 30 s).
- [ ] Config version advances on all three.
- [ ] Revert reconverges.
- [ ] **No** "NEW" badge on the Zero Trust / mTLS nav items (a leftover
      badge ⇒ regression of `b94f93e`, LOW).
- [ ] Zero Trust page mounts cleanly on all three nodes.

## Findings template

- Convergence times N1→N2 / N1→N3.
- Version before/after.
- Nav badge present? screenshot.
