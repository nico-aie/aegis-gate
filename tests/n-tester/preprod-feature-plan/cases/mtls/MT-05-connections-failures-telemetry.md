# MT-05 · mTLS connections + failures telemetry (UI ↔ API parity)

**Covers:** mTLS — `/api/zero-trust/downstream/connections`, `/api/zero-trust/downstream/failures`,
`/api/zero-trust/downstream/ca-summary` rendering · **Severity:** **Medium** ·
**Expected duration:** ~5 min · **Prereq:** MT-01 green (ideally after MT-03/04
so there's signal).

## Test

**Given** the Zero Trust page renders live mTLS connections, failures, and a
CA summary from their APIs.

**When** the operator compares the rendered tables/cards against the raw API.

**Then** counts and rows match, failures show actionable reasons (expired /
unknown-CA / SAN-reject / no-cert), and empty states are honest (no fake
rows on a fresh page).

## Paste-to-Claude (copy verbatim)

> Admin tab N1, Zero Trust page.
>
> 1. Read all three APIs:
>    ```js
>    (async () => {
>      const g = async p => (await fetch(p,{credentials:'include'})).json();
>      return {ca: await g('/api/zero-trust/downstream/ca-summary'),
>              conn: await g('/api/zero-trust/downstream/connections'),
>              fail: await g('/api/zero-trust/downstream/failures')};
>    })()
>    ```
>    Report row counts for connections + failures, and the CA summary fields.
> 2. Compare to the UI: do the connections table row count and failures row
>    count match the API? Does the CA summary card match (anchors, expiry)?
> 3. Inspect a failure row: is the **reason** human-readable and actionable
>    (e.g. "unknown CA", "SAN not allowed", "no client cert", "expired"),
>    and does it indicate direction (downstream vs upstream)?
> 4. If both lists are empty, confirm the UI shows an honest empty state
>    ("no connections" / "no failures"), not a spinner or stale data.

## Pass criteria

- [ ] UI connection + failure counts match the API exactly.
- [ ] CA summary card matches `/api/zero-trust/downstream/ca-summary`.
- [ ] Failure rows carry readable, actionable reasons + direction.
- [ ] Empty state is honest (no fabricated rows, no infinite spinner).
- [ ] No console errors; sorting/expand controls (if any) work.

## Findings template

- API vs UI counts (conn / fail).
- Sample failure reason text + direction label.
- Empty-state behaviour if applicable.
