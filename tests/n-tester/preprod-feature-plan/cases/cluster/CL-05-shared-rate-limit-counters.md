# CL-05 · Rate-limit counters are shared fleet-wide, not per-node

**Covers:** Cluster Mode — shared rate-limit counters · **Severity:** **High** ·
**Expected duration:** ~7 min · **Prereq:** data-plane tab on LB; CL-01 green.

## Test

**Given** the cluster's design guarantee: "10 rps/IP means 10 rps/IP across
the fleet, not 10 rps/IP × N nodes" (counters are shared named buckets via
the Redis `StateBackend`).

**When** the operator drives a burst from one IP through the LB (which
spreads it across all 3 nodes).

**Then** the rate limit trips at roughly the **fleet-wide** threshold — NOT
at ~3× the threshold — and limited responses report `X-WAF-Action: rate_limit`
(or `challenge`/`block` per the configured action) with `X-WAF-Mode: enforce`.

> Read the configured limit first (Scaling / runtime / `/api/loadmode` or
> the rate-limit config) so you know the expected trip point. If the limit
> is unknown, this case still detects the **gross** ×3 failure: a fleet that
> never trips until ~3× the single-node limit means counters are per-node.

## Paste-to-Claude (copy verbatim)

> Data-plane tab at http://185.23.199.194:56208/__qa-anchor.
>
> 1. On an admin tab, find the per-IP rate limit (Scaling page or
>    `/api/runtime` / rate-limit config). Report the limit `L` rps and the
>    action it takes (rate_limit / challenge / block).
>
> 2. From the data-plane tab, send a tight burst of N = max(40, 5×L)
>    requests from ONE spoofed IP and record where it starts being limited:
>    ```js
>    (async () => {
>      const out=[]; const N=40;
>      for (let i=0;i<N;i++){
>        const r=await fetch('/api/list?i='+i,{headers:{'X-Forwarded-For':'203.0.113.88'}});
>        out.push({i, status:r.status, action:r.headers.get('x-waf-action'),
>                  mode:r.headers.get('x-waf-mode'), risk:r.headers.get('x-waf-risk-score')});
>      }
>      const firstLimited = out.find(x=>x.status===429 || /rate_limit|challenge|block/.test(x.action||''));
>      return {firstLimited, tail: out.slice(-5)};
>    })()
>    ```
>    Tell me the index of the first limited request and the action/mode/status.
>
> 3. Sanity: report whether the trip index is near `L` (fleet-wide, correct)
>    or near `3×L` (per-node leak).

## Pass criteria

- [ ] Configured limit `L` identified (or noted as unknown).
- [ ] The burst trips near the **fleet-wide** limit, not ~3×L
      (tripping only near 3×L ⇒ HIGH: counters are per-node).
- [ ] Limited responses report a limiting `X-WAF-Action`
      (`rate_limit`/`challenge`/`block`) with `X-WAF-Mode: enforce`.
- [ ] `X-WAF-Risk-Score` is a 0–100 integer and rises across the burst.
- [ ] No 5xx / dropped connections during the burst (that's a different bug).

## Findings template

- Limit `L`, action, observed trip index.
- Verdict: fleet-wide vs per-node.
- Any anomalous statuses in the tail sample.
