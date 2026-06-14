# WS-04 · ws_inspect (enforce) blocks a hostile frame (1008) — and known limits

**Covers:** WebSocket — frame inspection enforce mode + **BUG-WS-2 / BUG-WS-3**
known limitations · **Severity:** **High** (enforce path); **INFO** for the
two known bugs · **Expected duration:** ~7 min · **Prereq:** WS-03 done.

## Test

**Given** `ws_inspect.mode: enforce`: a frame over the block threshold is
**not forwarded** and the socket is closed with WS code **`1008`**. Two
documented limitations apply:
- **BUG-WS-2** — the **AI** detector over-blocks ~100% of WS frames in
  enforce (ONNX OOD on per-frame views, `tag="ai"`). Expected workaround:
  keep `ws_inspect` body-detector-only / AI off / log_only.
- **BUG-WS-3** — on the **plaintext** bridge the block sends a bare TCP
  close instead of the `1008` frame (TLS delivers `1008` cleanly).

**When** the operator sends a SQLi text frame to an `enforce` route over the
plaintext LB, then (if a TLS data port is exposed) over TLS.

**Then** the hostile frame is **blocked** (not forwarded), and the close is
a bare TCP close on plaintext (BUG-WS-3, INFO) / a clean `1008` on TLS. A
benign frame must still pass — confirm enforce isn't blocking everything
(the BUG-WS-2 footgun) when AI is in the WS path.

## Paste-to-Claude (copy verbatim)

> I'll point you at a route configured `ws_inspect: enforce` (body detectors,
> AI OFF for WS per BUG-WS-2 workaround). Data-plane tab on the LB. Path `/ws`.
>
> 1. Plaintext enforce, benign then SQLi:
>    ```js
>    (async () => {
>      const ws=new WebSocket(location.origin.replace(/^http/,'ws')+'/ws');
>      const log=[];
>      await new Promise(r=>{ws.onopen=()=>r();});
>      ws.onmessage=e=>log.push(['echo',String(e.data).slice(0,60)]);
>      ws.send('benign hello'); await new Promise(r=>setTimeout(r,300));
>      ws.send("' OR 1=1-- union select"); 
>      const code=await new Promise(r=>{ws.onclose=e=>r([e.code,e.reason]); setTimeout(()=>{try{ws.close(1000)}catch(_){}} ,1500);});
>      return {echoes: log, close: code};
>    })()
>    ```
>    Report: did the benign frame echo? did the SQLi frame echo (it should
>    NOT)? what close code/reason came back?
>
> 2. On admin Audit Trail, confirm a `block` event with `surface: websocket`,
>    `mode: enforce`, and `sqli` tag.
>
> 3. (If a TLS data port is exposed, e.g. wss://…:<tlsport>/ws) repeat
>    step 1 over `wss://` and report the close code — expect a clean `1008`.

## Pass criteria

- [ ] Benign frame is forwarded (echoes) — enforce is NOT blocking
      everything (if it is and AI is on the WS path, that's **BUG-WS-2**,
      file INFO + confirm the AI-off workaround fixes it; do NOT file HIGH).
- [ ] SQLi frame is **blocked** (no echo, socket closes).
- [ ] `block` audit row (`surface: websocket`) with `mode: enforce` + `sqli` tag.
- [ ] Plaintext close is a bare TCP close (no `1008` frame) → confirms
      **BUG-WS-3**, file **INFO** (expected).
- [ ] TLS path (if available) closes with a clean **`1008`** → INFO/pass.

## Findings template

- Plaintext: benign echoed? sqli blocked? close code/reason.
- Audit event mode + tag.
- TLS path close code (if tested).
- Confirm BUG-WS-2 / BUG-WS-3 still match the documented behaviour (INFO).
