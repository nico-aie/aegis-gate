# WS-01 · WebSocket upgrades succeed on the plaintext LB (no 1006 drop)

**Covers:** WebSocket bug fix — `.with_upgrades()` on the plaintext listener
(commit `6aed24c`) · **Severity:** **Critical** (this is THE bug fixed) ·
**Expected duration:** ~5 min · **Prereq:** data-plane tab on LB; a WS route exists.

## Test

**Given** the bug: the plaintext data listener served connections with bare
`serve_connection` (no `.with_upgrades()`), so every WS upgrade on the
plaintext port returned `101` then immediately dropped with a bare `1006`.
The fix enables upgrades so the plaintext branch matches the TLS branch.

**When** a client opens a WebSocket through the LB (`ws://185.23.199.194:56208/...`).

**Then** the upgrade **completes and the socket stays open** — an echo /
ping round-trips — instead of closing with `1006` immediately after `101`.

## Paste-to-Claude (copy verbatim)

> Open a data-plane tab at http://185.23.199.194:56208/__qa-anchor.
> Pre-prod has a dedicated WS route `/ws` → `ws-pool` (10.20.0.72:9992) AND
> a catch-all `/` → `http-pool` (10.20.0.72:9991) that **also bridges WS**.
> Test BOTH paths — `/ws` first, then `/` — since the regression was on the
> plaintext listener regardless of route.
>
> In the page console, open a WS to the LB and observe whether it stays up
> (run once with `path='/ws'`, then again with `path='/'`):
>
> ```js
> (async () => {
>   const path = '/ws';   // re-run with path = '/' for the catch-all
>   const url = (location.origin.replace(/^http/,'ws')) + path;
>   return await new Promise(res => {
>     const ws = new WebSocket(url);
>     const log = [];
>     const t0 = performance.now();
>     ws.onopen   = () => { log.push(['open', Math.round(performance.now()-t0)]); ws.send('hello-ws-01'); };
>     ws.onmessage= e => { log.push(['message', String(e.data).slice(0,40)]); };
>     ws.onclose  = e => { log.push(['close', e.code, e.reason]); res({log}); };
>     ws.onerror  = () => { log.push(['error']); };
>     setTimeout(() => { try{ws.close(1000);}catch(_){}}, 2500);
>   });
> })()
> ```
>
> Report the event log. I'm looking for: did `open` fire, did it stay open
> for the full ~2.5 s (vs closing almost immediately), what was the final
> close code, and did any echo `message` come back.

## Pass criteria

- [ ] `open` fires and the socket **stays open** ~2.5 s (does not close
      within tens of ms of opening).
- [ ] Final close code is a **clean `1000`** (operator-initiated), **not a
      bare `1006`** (the regression signature).
- [ ] If the route echoes, the sent frame round-trips back.
- [ ] **Both** `/ws` (ws-pool) **and** the catch-all `/` (http-pool, which
      also bridges WS) upgrade successfully and stay open.
- [ ] (Cross-check) repeat 3–4 times so the LB hits multiple nodes; every
      node upgrades successfully — not just one (a single node missing the
      fix ⇒ CRITICAL).

## Findings template

- Event log (open ms, messages, close code).
- Per-node behaviour if distinguishable across retries.
- If still 1006: the plaintext `.with_upgrades()` fix didn't reach this build.
