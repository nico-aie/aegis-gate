# WS-02 · A malicious WS handshake is blocked before the socket is created

**Covers:** WebSocket — handshake runs the full security pipeline (always-on
phase 1) · **Severity:** **High** · **Expected duration:** ~5 min ·
**Prereq:** WS-01 green; data-plane tab on LB.

## Test

**Given** phase 1 of WS inspection: the `GET … Upgrade: websocket` request
runs through detectors, per-IP risk, operator rules, and the mTLS identity
gate exactly like any HTTP request. A handshake that trips a detector or a
blocked IP **never becomes a socket**.

**When** the operator attempts a WS upgrade whose URL/headers carry an
attack (e.g. SQLi/path-traversal in the query), or comes from a
blacklisted IP.

**Then** the handshake is **rejected** (no `101`; a `4xx` + `X-WAF-Action:
block`), the socket is never established, and an audit row records the
blocked handshake.

## Paste-to-Claude (copy verbatim)

> Data-plane tab on http://185.23.199.194:56208/__qa-anchor. WS route `/ws`.
>
> 1. **Clean handshake control** (should succeed → 101/open): use the WS
>    snippet from WS-01 against `/ws`. Confirm it opens.
>
> 2. **Malicious-URL handshake** (should be blocked before upgrade). The
>    upgrade itself can't easily set XFF from `WebSocket`, so probe the
>    handshake as a plain GET with the Upgrade headers via fetch to read
>    the WAF decision headers:
>    ```js
>    (async () => {
>      const r = await fetch('/ws?q=' + encodeURIComponent("<script>alert(1)</script>"),
>        {headers:{'Upgrade':'websocket','Connection':'Upgrade',
>                  'Sec-WebSocket-Version':'13','Sec-WebSocket-Key':'dGhlIHNhbXBsZSBub25jZQ==',
>                  'X-Forwarded-For':'8.8.8.8'}});
>      return {status:r.status, action:r.headers.get('x-waf-action'),
>              rule:r.headers.get('x-waf-rule-id'), mode:r.headers.get('x-waf-mode'),
>              rid:r.headers.get('x-waf-request-id')};
>    })()
>    ```
>    Report status + headers. Expect a non-101 (4xx) with `x-waf-action: block`
>    and a `detector:` rule id — NOT a `101`.
>
> 3. Then try the actual `WebSocket('/ws?q=<script>…')` upgrade and confirm
>    it does NOT stay open (closes without a usable session).
>
> 4. On an admin **Live Feed / Audit Trail**, find the blocked-handshake row
>    and report its action + detectors.

## Pass criteria

- [ ] Clean handshake opens (control).
- [ ] Malicious handshake returns a **4xx, not 101**, with
      `X-WAF-Action: block` and a `detector:`-prefixed `X-WAF-Rule-Id`.
- [ ] The malicious `WebSocket()` upgrade does not yield a working socket.
- [ ] An audit row records the blocked handshake with detector tag.
- [ ] `X-WAF-Request-Id` present and correlates to the audit row.

## Findings template

- Clean vs malicious handshake status + headers.
- Audit row action/detectors; request-id correlation.
