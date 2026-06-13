# WS-05 · Live Feed renders "WS Proto" as plain text + shows open/close events

**Covers:** WebSocket — dashboard render fix (commit `d359e5b`) +
`websocket_open` / `websocket_close` audit events · **Severity:** **Medium** ·
**Expected duration:** ~5 min · **Prereq:** WS-01 green.

## Test

**Given** the fix: the Live Feed "WS Proto" value used to render as a
wrapping pill that broke the row layout; it now renders as **plain text**.
WS sessions also emit `websocket_open` and `websocket_close` audit events.

**When** the operator opens a WS session through the LB and watches the
Live Feed on an admin console.

**Then** `websocket_open` and `websocket_close` rows appear, the **WS Proto**
field renders as inline plain text (no wrapping pill / no layout break), and
the rows are legible at standard widths.

## Paste-to-Claude (copy verbatim)

> Admin tab N1 = http://185.23.199.194:56243/ → open **Live Feed**.
> Data-plane tab on the LB.
>
> 1. From the data-plane tab, open and cleanly close a WS session:
>    ```js
>    (async () => {
>      const ws=new WebSocket(location.origin.replace(/^http/,'ws')+'/ws');
>      await new Promise(r=>{ws.onopen=()=>r(); ws.onerror=()=>r();});
>      await new Promise(r=>setTimeout(r,400));
>      await new Promise(r=>{ws.onclose=()=>r(); ws.close(1000);});
>      return 'ws cycle done';
>    })()
>    ```
> 2. On N1's Live Feed, find the `websocket_open` and `websocket_close`
>    rows. Screenshot them.
> 3. Inspect the **WS Proto** cell: is it plain inline text, or a pill that
>    wraps / overflows / breaks the row height? Report exactly what it looks
>    like and whether the row layout stays intact.
> 4. Resize the browser to ~1024px wide and confirm the row still renders
>    cleanly (no overlap, no clipped text).

## Pass criteria

- [ ] `websocket_open` AND `websocket_close` rows appear in the Live Feed.
- [ ] "WS Proto" renders as **plain text**, not a wrapping pill (the
      regression); row layout is not broken.
- [ ] Rows legible at 1024px and full width.
- [ ] No console errors while the WS events stream in.

## Findings template

- Screenshot of the WS Proto cell (full width + 1024px).
- Both open/close events present?
- Any layout break / pill regression.
