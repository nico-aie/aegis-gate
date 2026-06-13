# WS-06 · WS handshake carries contract headers and correlates to audit

**Covers:** WebSocket — contract §5 headers on the handshake + §5.3
consistency · **Severity:** **High** · **Expected duration:** ~4 min ·
**Prereq:** WS-01 green; data-plane tab on LB.

## Test

**Given** the handshake is a normal HTTP request through the pipeline, it
must carry the §5.1 required response headers, and `X-WAF-Request-Id` must
match the corresponding audit-log `request_id` (§5.3 / §6).

**When** the operator probes the WS handshake endpoint and inspects both
the response headers and the matching audit row.

**Then** all required `X-WAF-*` headers are present and internally
consistent, and the handshake's `X-WAF-Request-Id` is findable in the audit
log with the same value.

## Paste-to-Claude (copy verbatim)

> Data-plane tab on the LB. Admin tab N1 for audit lookup.
>
> 1. Probe a clean handshake and capture all WAF headers:
>    ```js
>    (async () => {
>      const r = await fetch('/ws',
>        {headers:{'Upgrade':'websocket','Connection':'Upgrade',
>                  'Sec-WebSocket-Version':'13','Sec-WebSocket-Key':'dGhlIHNhbXBsZSBub25jZQ==',
>                  'X-Forwarded-For':'192.0.2.61'}});
>      const h={}; for (const k of ['x-waf-request-id','x-waf-action','x-waf-mode',
>        'x-waf-rule-id','x-waf-risk-score','x-waf-cache']) h[k]=r.headers.get(k);
>      return {status:r.status, headers:h};
>    })()
>    ```
>    Report status + every header value.
>
> 2. On N1 admin, run:
>    ```js
>    (async () => (await fetch('/api/audit/since?limit=20',{credentials:'include'})).json())()
>    ```
>    Find the audit row whose `request_id` equals the `x-waf-request-id` from
>    step 1. Report whether it's found and that the ids match exactly.

## Pass criteria

- [ ] `X-WAF-Request-Id` present, 8–64 chars `[A-Za-z0-9._-]`.
- [ ] `X-WAF-Action` lowercase + a valid value; `X-WAF-Mode` ∈ {enforce,log_only}.
- [ ] `X-WAF-Rule-Id` set or `none`; `X-WAF-Risk-Score` 0–100 int;
      `X-WAF-Cache` ∈ {HIT,MISS,BYPASS} (BYPASS expected for an upgrade).
- [ ] The handshake's `X-WAF-Request-Id` is found in the audit log with the
      **same** value (missing/mismatch ⇒ HIGH per §5.3).

## Findings template

- Full header set + any missing/malformed (note severity).
- Request-id correlation: found? exact match?
