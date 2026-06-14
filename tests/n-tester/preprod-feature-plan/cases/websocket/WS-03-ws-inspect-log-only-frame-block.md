# WS-03 · ws_inspect (log_only) audits a hostile frame but forwards it

**Covers:** WebSocket — frame inspection phase 2, `ws_inspect.mode: log_only` ·
**Severity:** **High** · **Expected duration:** ~6 min ·
**Prereq:** WS-01 green; a route with `ws_inspect.enabled: true, mode: log_only`.

## Test

**Given** `ws_inspect` reassembles client→upstream **text** frames and runs
them through the body detectors (XSS / SQLi / body_abuse). In `log_only`
mode a frame over the block threshold is **still forwarded**, but a `block`
audit event (with `surface: websocket`) fires with `mode: log_only`.

**When** the operator sends a SQLi/XSS text frame over an established socket
to a `log_only` route.

**Then** the frame is **delivered** (echo comes back / upstream sees it),
**and** a `block` audit row (`surface: websocket`) appears with `mode: log_only`
and the detector tag — proving detection ran without enforcement (matches
contract §2.5 log_only semantics).

## Paste-to-Claude (copy verbatim)

> Confirm via admin **Routing & Upstreams** which WS route has
> `ws_inspect: log_only` (ask me if unclear; I'll point you at the route).
> Data-plane tab on the LB. Use that route's path below (assume `/ws`).
>
> 1. Open a socket and send one benign then one SQLi text frame:
>    ```js
>    (async () => {
>      const ws = new WebSocket(location.origin.replace(/^http/,'ws')+'/ws');
>      const log=[];
>      await new Promise(r=>{ws.onopen=()=>r();});
>      ws.onmessage=e=>log.push(['echo',String(e.data).slice(0,60)]);
>      ws.send('benign hello');
>      await new Promise(r=>setTimeout(r,300));
>      ws.send("' UNION SELECT username,password FROM users--");
>      await new Promise(r=>setTimeout(r,600));
>      const code = await new Promise(r=>{ws.onclose=e=>r(e.code); ws.close(1000);});
>      return {echoes: log, closeCode: code};
>    })()
>    ```
>    Report: did BOTH frames echo back (i.e. the SQLi frame was forwarded,
>    not dropped), and the close code (should be clean 1000, NOT 1008).
>
> 2. On an admin **Audit Trail / Live Feed**, find the
>    WS block event for this socket (`action: block`, `surface: websocket`).
>    Report its `mode`,
>    detector tag (`sqli`), and that it's marked log_only.

## Pass criteria

- [ ] The SQLi frame is **forwarded** (echoes back) — log_only does not block.
- [ ] Socket closes clean `1000` (not `1008`) — no enforcement.
- [ ] A `block` audit event (`surface: websocket`) fires with **`mode: log_only`**
      and the `sqli` detector tag.
- [ ] The benign frame also passes (no false positive).

## Findings template

- Echoes seen; close code.
- Audit event present? its mode + detector tag.
- Any case where log_only actually blocked (→ HIGH: log_only semantics violated).
