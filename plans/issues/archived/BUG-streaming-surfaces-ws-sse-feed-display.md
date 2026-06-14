# BUG — streaming surfaces (WebSocket + SSE) are mislabeled / unattributable in the Live Feed

- **Type:** BUG (observability / dashboard + audit-event fields) — Live Feed, Request Detail, Investigation
- **Severity:** 🟡 Medium — no security miss (blocks ARE enforced + audited + KPI-counted), but operators can't see/attribute streaming-surface activity, so a working defense looks like it isn't firing.
- **Status:** ✅ Shipped 2026-06-14 (TDD). See Resolution below.

## ✅ Resolution (2026-06-14)

- **Server (`data_plane.rs`):** the `surface:"websocket"` frame-block emit now stamps `method: Some(ws_method)` + `fields.path = ws_uri` (dynamic — the real handshake method/URI already in the inspector scope; **no hardcoded path**). WS close/open already carry tier+method+path (sibling fix). Regression: `sqli_log_only_forwards_and_audits` extended to assert the block event has `method == GET` + `fields.path == "/"` (the test's actual route — proves dynamic, not a literal `/ws/live`).
- **Dashboard (`data.jsx`):** new `streamingProto(action, ev, f)` — `surface==='websocket'` or status `101` ⇒ `websocket`; `fields.streamed===true` ⇒ `sse`; else `http` — used by both the backfill mapper and the live SSE handler. `ws-open`/`ws-close` are filtered out of the Live Feed via `FEED_HIDDEN_ACTIONS` (Option A — kept in Audit Trail). Dead `websocket_frame_block` left only as a legacy backfill alias (pre-B2 ring rows). Verdict stays in the Action column. (`streamingProto` logic verified via a standalone node check; repo has no JS test harness.)
- **Drawer (`pages.jsx`):** a `WebSocket frame` section (`surface`/`matched_field`/`message_bytes`) and an `SSE stream` "response stream not inspected (by design)" note (from `streamed`/`response_inspection_skipped`/`reason`); both excluded from the generic Extra-fields dump. `app.js` rebuilt.

**Out of scope (follow-up):** nesting frame blocks *under* the handshake row (Chrome's Messages model) still needs a shared `request_id` across handshake→frame→close.

---

- **Scope:** **WebSocket** (`/ws/live`) **and Server-Sent Events** (`/api/notifications/stream`, any `text/event-stream`).
- **Area:** `crates/aegis-proxy/src/data_plane.rs` (WS frame-block + SSE streamed emit), `crates/aegis-proxy/src/accept.rs` (per-request audit), `crates/aegis-control/assets/dashboard/src/data.jsx` + `pages.jsx` (feed mapping + drawer).
- **Sibling (fixed):** [`BUG-ws-lifecycle-audit-missing-tier-path.md`](./BUG-ws-lifecycle-audit-missing-tier-path.md) — same missing-`fields.path` family on the WS close event.
- **Not this bug (detection, tracked elsewhere):** SSE/WS request-side **detection** gaps (CSWSH/Origin, Host-SSRF, CRLF auth/hijack) live in [`PLAN-sec-regression-2026-06-14-triage.md`](./PLAN-sec-regression-2026-06-14-triage.md) P3. This issue is about **displaying + attributing** what the WAF already decides, not closing detection holes.

## Design target — Chrome DevTools Network parity (Nico, 2026-06-14)

Chrome models each streaming connection as **one row**, typed by surface, with the per-frame/per-event payload nested *inside* that request:
- **WebSocket:** one row = the handshake `GET … 101 Switching Protocols` (`ws://…/ws/live`); frames live in the **Messages** tab. Type = `ws`.
- **SSE:** one row = the `GET … 200` to the stream (`text/event-stream`); events live in the **EventStream** tab. Type = `eventsource`.

The WAF Live Feed should read the same way: **one row per connection, typed by surface in the Proto column, verdict in the Action column**, plus extra rows only for security-relevant events (a blocked WS frame / a blocked SSE request).

### Design rules (apply to BOTH surfaces)

1. **Proto column = the surface** — `websocket` / `sse` — never `http`. Today both render `http` (the proto map only special-cases `websocket_open`/`websocket_close`). Derive proto from: status `101` ⇒ `websocket`; `fields.surface == "websocket"` ⇒ `websocket`; `decision.streamed` / `fields.streamed == true` (or `Content-Type: text/event-stream`) ⇒ `sse`.
2. **Verdict lives in Action, not Proto** — `allow` / `block`. (Rejected: `ws-block` / `ws-msg` proto labels.)
3. **Path + method come from the real request**, captured dynamically — `method: GET` + the actual URI. **Never hardcode `/ws/live` or `/api/notifications/stream`** (routes are unknown in general).
4. **Blocked events get their own row AND are logged to sinks** — attributable to the surface (`websocket` / `sse`), with the detector in `rule_id` and the specifics (`matched_field`, `message_bytes` for WS; `streamed`/`reason` for SSE) in the drawer.
5. **Drop always-allow lifecycle noise from the Live Feed** (see decision) — but keep it in the durable Audit Trail / sinks.

---

## WebSocket — current state & gaps

In `run-20260614-210530` (AI off, gate off) **93 WS attacks were blocked** (`actual:"block"`: 22 xss + 22 cmdi + 22 sqli + 15 nosqli frame injections + a few handshake catches), yet the feed showed only `http` / `ws-open` / `ws-close` rows for `/ws/live`, all **ALLOW**.

**By design (NOT bugs):** `ws-open`/`ws-close` are lifecycle, mapped to `allow` (`data.jsx:360-362`); the block IS enforced/audited/KPI-counted (B2: `action:"block"` + `fields.surface:"websocket"`, `aegis_websocket_frame_block_total`).

**Gaps:**
- **Frame-block event has no path.** `data_plane.rs` (~`:2098`) emits `path: None`, `method: None`, `fields: {surface, matched_field, message_bytes}` — no `fields.path` ⇒ feed falls back to `PATH = '/'`, `METHOD = GET`. (Same family as the fixed close-event bug.)
- **Feed never reads `fields.surface`** (`data.jsx:405-409`) ⇒ `proto = http` ⇒ a WS block is indistinguishable from an HTTP block.
- **Dead code:** `decisionAction` (`data.jsx:360`) + the reload `REAL_ACTIONS` set (`:459`) still reference the **retired** `websocket_frame_block` action.

### ✅ Decision (Nico) — Option A (Chrome-parity): drop `ws-open` / `ws-close` from the Live Feed

`ws-open`/`ws-close` are always `allow`, so they are **removed from the Live Feed**. The connection is represented by the handshake row (`GET … 101`, relabeled `proto: websocket`); a blocked frame adds a `websocket · GET · <path> · block` row. Per connection: **1 connection row + N block rows**, like DevTools. Lifecycle stays in the durable **Audit Trail + sinks** (rejected: 3+ always-allow rows per benign connection).

---

## SSE — current state & gaps

**How it works today (`data_plane.rs:2452-2478`):** when the upstream response is `text/event-stream`, `mode.is_streaming()` returns `DecisionTag::allow().with_streamed(true)` — the body streams straight through. **Request-side + response-HEADER inspection already ran; the response BODY is never inspected** (it can't be re-read) — a deliberate, documented trade-off (`docs/data-plane/sse-streaming.md`). `accept.rs:2090-2099` stamps `fields.streamed` / `response_inspection_skipped:true` / `reason:"streaming"` on the allow audit.

So an SSE stream is **always one `allow` row**, which is actually already close to Chrome's single-row model — but:

**Gaps (mirror WS):**
- **Proto = `http`, not `sse`.** No surface label, despite `decision.streamed`/`fields.streamed` being available. Chrome calls it `eventsource`.
- **A blocked SSE is a request-side block** (CRLF/path-injection, auth, origin — fired *before* streaming) and today renders as a plain `http` block, not attributable to the SSE surface.
- **The "why no response inspection" is captured but not surfaced.** `fields.streamed` + `response_inspection_skipped` + `reason:"streaming"` already ride the audit, but the drawer doesn't explain to the operator that the event stream is pass-through-by-design. This is the analogue of Chrome's EventStream tab — except our answer is "stream not inspected (by design)", which we should state plainly rather than leave the row looking like an un-scanned allow.

**By design (NOT bugs):** the streamed response body / server-pushed events are **not** inspected and get **no per-event rows** — consistent with both our perf/security trade-off and with not cluttering the feed. We do not (and will not here) build an EventStream-style per-event view.

---

## Fix plan (no code yet)

**Server (`data_plane.rs` / `accept.rs`):**
- WS frame-block emit: add `fields.path = <handshake URI>` (dynamic, via the `ws_path_for_close` capture) + `method: Some("GET")`. Tier already `Some(ws_tier)`.
- SSE: ensure the streamed `allow` audit carries enough to label it — `fields.streamed` already set; confirm `fields.path`/`method` are populated on the streamed allow (they ride the normal accept.rs allow emit). No new server fields needed for SSE beyond what's stamped.
- Lifecycle (`websocket_open`/`websocket_close`): keep emitting to the audit ring + sinks; the **dashboard** filters them out of the Live Feed (client-side — no server change to drop them).

**Dashboard (`data.jsx`):**
- Proto derivation in `mapAuditToLiveRow`: status `101` **or** `fields.surface === 'websocket'` ⇒ `proto = 'websocket'`; `fields.streamed === true` (or `Content-Type: text/event-stream`) ⇒ `proto = 'sse'`; else `http`. Drop the `ws-open`/`ws-close` proto branches.
- For `action === 'block' && fields.surface === 'websocket'`: use `fields.path` + `method:'GET'`.
- Filter `websocket_open` / `websocket_close` out of the **Live Feed** stream (Option A); keep them in the Audit Trail view.
- Remove the dead `websocket_frame_block` references (`:360`, `:459`).

**Dashboard drawer (`pages.jsx`):**
- WS row: show the handshake headers (already captured) + a "blocked frame" section (`matched_field`, `message_bytes`, detector) — the Messages-tab analogue.
- SSE row: show a "response stream not inspected (by design)" note driven by `fields.streamed` / `response_inspection_skipped` / `reason`, so an allowed SSE row is self-explanatory rather than looking like an un-scanned pass-through.

## Test (when coded)

- WS e2e (`data_plane.rs websocket_e2e_tests`): after a blocked malicious frame, assert the `action:"block"` event has `fields.surface == "websocket"`, `method == Some("GET")`, and `fields.path` equals the **actual** handshake path used by the test (don't assert a hardcoded literal — proves dynamic capture).
- SSE: an integration/unit check that a `text/event-stream` allow carries `fields.streamed == true` + `reason == "streaming"`, and that `mapAuditToLiveRow` yields `protocol === 'sse'` for it.
- Dashboard unit: `mapAuditToLiveRow` yields `protocol === 'websocket'` for a `101` handshake and a `block`+`surface=websocket` event, `'sse'` for a streamed allow, and excludes `websocket_open`/`websocket_close` from the live rows.

## Related

- [[project_hyper_normalizes_framing]] — WS handshake/framing context.
- [`PLAN-sec-regression-2026-06-14-triage.md`](./PLAN-sec-regression-2026-06-14-triage.md) P3 — SSE/WS request-side **detection** gaps (separate from this display work).
- [`BUG-audit-detail-no-riskkey-no-headers-on-allow.md`](./BUG-audit-detail-no-riskkey-no-headers-on-allow.md) — the "headers for all requests + sinks" (Fix B) ask pairs with the drawer work here.
</content>
