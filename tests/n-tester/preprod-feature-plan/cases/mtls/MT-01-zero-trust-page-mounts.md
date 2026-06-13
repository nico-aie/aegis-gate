# MT-01 · Zero Trust page mounts and shows both directions + telemetry cards

**Covers:** mTLS — unified Zero Trust console page (Beta) · **Severity:** **High** ·
**Expected duration:** ~5 min · **Prereq:** a console logged in.

## Test

**Given** one **Zero Trust** (Beta) console page owns **both** mTLS
directions — downstream (verify client certs presented to the WAF) and
upstream (WAF dials backends with its own client identity) — backed by
`/api/zero-trust/downstream/{connections,failures,ca-summary}` and `/api/zero-trust/upstream/config`.

**When** the operator opens the Zero Trust page on a console.

**Then** the page mounts cleanly, clearly separates the two directions, and
renders the CA summary / connections / failures cards from their APIs
without error.

## Paste-to-Claude (copy verbatim)

> Admin tab N1 = http://185.23.199.194:56243/. In the sidebar, open the
> **Zero Trust** page (may be marked Beta).
>
> 1. Confirm it mounts (no "Page render error" card). Screenshot the page.
> 2. Tell me whether the page clearly shows the two directions —
>    **Downstream** (client certs *to* the WAF) and **Upstream**
>    (WAF→backend identity) — and what controls each section has.
> 3. In the page console, fetch the backing APIs and confirm each returns
>    200 + a sane shape:
>    ```js
>    (async () => {
>      const get = async p => { const r=await fetch(p,{credentials:'include'});
>        return {p, status:r.status, body: await r.json().catch(()=>'(non-json)')}; };
>      return [await get('/api/zero-trust/downstream/ca-summary'),
>              await get('/api/zero-trust/downstream/connections'),
>              await get('/api/zero-trust/downstream/failures'),
>              await get('/api/zero-trust/upstream/config')];
>    })()
>    ```
>    Report each status + a one-line shape summary.
> 4. Confirm the UI cards (CA summary, connections, failures) reflect those
>    API values (counts/rows match).

## Pass criteria

- [ ] Zero Trust page mounts cleanly (no error-boundary, no red console errors).
- [ ] Both directions are clearly labelled and separated.
- [ ] All four APIs return 200 with sane shapes.
- [ ] UI cards match the API values (count parity).
- [ ] Page renders on N2/N3 too (spot-check at least one other node).

## Findings template

- Screenshot name; both-directions present?
- Per-API status + shape.
- Any UI/API count mismatch.
