# CL-02 · A config change on one node converges to the whole fleet

**Covers:** Cluster Mode — config-plane convergence · **Severity:** **Critical** ·
**Expected duration:** ~8 min · **Prereq:** CL-01 green; all 3 consoles open.

## Test

**Given** the leaderless config plane (modes / detector mask / access
lists are shared state, hot-swapped via the config plane).

**When** the operator makes one observable config change on **node-1's**
console — flip a single **detector** off on the Detectors page (e.g.
`recon` or `xss`) and Save.

**Then** within a short convergence window (target ≤ 10 s, fail if > 30 s)
**node-2 and node-3** reflect the same detector state, the config
**version** advances on all three, and an **audit row** records the
mutation with actor + chain hash. Flipping it back converges too.

## Paste-to-Claude (copy verbatim)

> Tabs: N1=:56243, N2=:56244, N3=:56245 (all logged in).
>
> 1. On N1, N2, N3 capture the baseline. In each page console run:
>    ```js
>    (async () => {
>      const det = await (await fetch('/api/detectors',{credentials:'include'})).json();
>      const ver = await (await fetch('/api/config/version',{credentials:'include'})).json();
>      return {ver, detectors: det};
>    })()
>    ```
>    Report each node's config version and the enabled/disabled state of the
>    `recon` (or `xss`) detector.
>
> 2. On **N1 only**, open the **Detectors** sidebar page, find the `recon`
>    row, toggle it **OFF**, and Save. Note the toast text and time.
>
> 3. Immediately start polling N2 and N3 (re-run the snippet above every
>    ~3 s). Tell me how many seconds until N2 and N3 BOTH show `recon`
>    disabled AND a config version greater than their baseline.
>
> 4. On any node, open **Audit Trail**, find the mutation row for this
>    change, and report: actor, action, and whether a chain hash is shown.
>
> 5. Re-enable `recon` on N2 this time; confirm N1 and N3 converge back.
> Screenshot N3's Detectors page showing `recon` disabled during step 3.

## Pass criteria

- [ ] Baseline versions captured on all 3 nodes.
- [ ] After the N1 toggle, N2 **and** N3 show `recon` disabled within ≤ 10 s
      (MEDIUM if 10–30 s, HIGH/fail if > 30 s or never).
- [ ] Config **version advances** on all three nodes (not just N1).
- [ ] An audit row records the mutation with **actor + chain hash**.
- [ ] Re-enabling from a *different* node (N2) also converges to N1+N3
      (proves any node can write, leaderless).
- [ ] No console errors; Detectors page mounts on all three.

## Findings template

- Convergence times N1→N2, N1→N3 (seconds).
- Version before/after per node.
- Audit row actor + chain-hash present? screenshot name.
