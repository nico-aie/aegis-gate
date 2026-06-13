# CL-03 · Config versions, rollback, and 409 conflict on concurrent edit

**Covers:** Cluster Mode — config versioning + rollback + optimistic concurrency ·
**Severity:** **High** · **Expected duration:** ~8 min · **Prereq:** CL-02 green.

## Test

**Given** the config plane keeps a version history (`/api/config/versions`,
`/api/config/version`) and supports rollback (`/api/config/rollback`,
`/api/config/versions/<n>/rollback`).

**When** the operator (a) makes a change and rolls it back, and (b) races
two consoles editing the same config concurrently.

**Then** rollback restores the prior config + advances the version (forward
rollback, not a silent rewrite), and the concurrent edit's loser gets a
**409 conflict** surfaced as a toast (not a silent overwrite or a crash).

## Paste-to-Claude (copy verbatim)

> Tabs: N1=:56243, N2=:56244.
>
> **Part A — rollback.**
> 1. On N1 console: `(async()=>(await fetch('/api/config/versions',{credentials:'include'})).json())()`
>    — report the latest version number `V`.
> 2. On N1, make a small change via the UI (e.g. Access Lists → add a
>    whitelist entry `id=cl03-tmp, kind=ip, value=198.51.100.7`). Note the
>    new version `V+1`.
> 3. On N1 open the config/version card (Scaling page or wherever the
>    ConfigVersion card lives) and click **Rollback** to version `V`
>    (or POST `/api/config/rollback`). Report the toast.
> 4. Re-read `/api/config/versions` — confirm the whitelist entry is gone
>    and the version is now `V+2` (rollback moves forward, doesn't rewind
>    the counter). Confirm N2 converges to the same state.
>
> **Part B — 409 conflict.**
> 5. On N1 and N2, open the SAME editable config surface (e.g. Detectors,
>    same detector row). On N1 read current version, on N2 read current
>    version (should match).
> 6. On N1 make a change + Save (version advances). Then on N2 — WITHOUT
>    reloading — make a different change + Save against the now-stale version.
> 7. Report N2's result: do you get a **409 conflict** toast and an
>    auto-reload to the fresh state, or did N2 silently overwrite N1?

## Pass criteria

- [ ] `/api/config/versions` lists a monotonic history.
- [ ] Rollback restores the target config AND advances the version forward.
- [ ] Rolled-back state converges to the other node.
- [ ] Concurrent stale write on N2 → **409**, surfaced as a clear toast,
      ideally with auto-reload to fresh state (silent overwrite = HIGH/fail;
      crash/blank = CRITICAL).
- [ ] No error-boundary on either console.

## Findings template

- Version numbers V / V+1 / V+2 observed.
- Rollback toast text.
- 409 toast text + whether the loser auto-reloaded; screenshot.
