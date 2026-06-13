# CL-04 · A blacklist entry added on one node blocks on every node via the LB

**Covers:** Cluster Mode — shared block-list state · **Severity:** **Critical** ·
**Expected duration:** ~7 min · **Prereq:** CL-02 green; data-plane tab open on LB.

## Test

**Given** block lists are shared cluster state (additive on heal,
split-brain safe) and the LB fans traffic across all 3 nodes.

**When** the operator adds an IP blacklist entry on **node-1's** console.

**Then** requests from that IP through the **LB** are blocked **no matter
which node serves them** — verified by hammering the LB enough times to
hit all three nodes — and the block response carries the correct contract
headers (`X-WAF-Action: block`, `X-WAF-Rule-Id: blacklist*`).

## Paste-to-Claude (copy verbatim)

> Data-plane tab is open at http://185.23.199.194:56208/__qa-anchor.
> Admin tab N1 = http://185.23.199.194:56243/.
>
> 1. From the data-plane tab, baseline the test IP (should NOT be blocked):
>    ```js
>    (async () => {
>      const r = await fetch('/', {headers:{'X-Forwarded-For':'203.0.113.77'}});
>      return {status:r.status, action:r.headers.get('x-waf-action'),
>              rule:r.headers.get('x-waf-rule-id'), rid:r.headers.get('x-waf-request-id')};
>    })()
>    ```
>    Report status + headers (expect allow/200 or upstream 502, NOT 403).
>
> 2. On N1, open **Access Lists**, Blacklist tab, **Add entry**:
>    kind=`ip`, value=`203.0.113.77`, note=`cl04`. Save. Confirm the row
>    appears and note the toast.
>
> 3. Back on the data-plane tab, fire the SAME request 12 times in a loop
>    (the LB should spread these across all 3 nodes), collecting status +
>    `x-waf-action` + `x-waf-rule-id` each time:
>    ```js
>    (async () => {
>      const out=[];
>      for (let i=0;i<12;i++){
>        const r=await fetch('/?n='+i,{headers:{'X-Forwarded-For':'203.0.113.77'}});
>        out.push({status:r.status, action:r.headers.get('x-waf-action'),
>                  rule:r.headers.get('x-waf-rule-id')});
>      }
>      return out;
>    })()
>    ```
>    Tell me whether ALL 12 are blocked (403) with action=block.
>
> 4. Cleanup: on N1 delete the `203.0.113.77` blacklist row.

## Pass criteria

- [ ] Baseline request is NOT 403 before the entry is added.
- [ ] After adding on N1, **all 12** LB requests return **403**
      (any single 200/allow ⇒ a node didn't get the shared entry ⇒ CRITICAL).
- [ ] Block responses carry `X-WAF-Action: block` and
      `X-WAF-Rule-Id` starting `blacklist` (per §5.1 / §7).
- [ ] `X-WAF-Request-Id` present on every response (8–64 chars).
- [ ] Entry visible on N2/N3 Access Lists pages too (shared state, not just N1).
- [ ] Cleanup delete propagates (one follow-up LB request returns to baseline).

## Findings template

- Per-request status/action table (12 rows).
- Any node that let it through (correlate with which node if a node id header exists).
- Header consistency notes.
