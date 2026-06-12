# Fix plan — WebSocket / SSE attack detection (QC report response)

> **Status:** Drafted 2026-06-12. Code-verified against `develop`.
> Responds to `WEBSOCKET_ATTACK_REPORT.md` (4/29 blocked = 13.8%).
>
> **Read this first — the report is partly wrong.** Per the standing
> "verify against code, docs drift both ways" caution, every claim below was
> checked in `crates/`. Several "misses" are config gaps or non-issues, not
> missing detection. The corrected picture changes the priority order.

---

## 1. Verified findings (what's real vs. not)

| Report item | Verdict (code-checked) | Evidence |
|---|---|---|
| **RC-1** ws_inspect "not clear which detectors run" | **Wired & complete.** The bridge runs the FULL detector chain on each text frame. | `data_plane.rs:2000-2089` builds a `BodyPeek` from the frame + `RequestView` and calls `run_all_filtered(detectors, mask, view)`; sums scores vs `ws_block_at`; emits `websocket_frame_block`. **It also injects `Content-Type: text/plain`** (`data_plane.rs:1933`) so `body_is_scannable` passes and sqli/xss/nosql/cmdi DO scan the payload. |
| RC-1 cause it "doesn't work" | **Config + default.** `ws_inspect` is absent from `dev.yaml`'s catch-all, AND `WsInspectMode` defaults to **`LogOnly`** (`config.rs`), so even enabled it logs without blocking → QC's blocked-count stays ~0. | `config/dev.yaml:92` catch-all has no `ws_inspect`; `WsInspectMode::default = LogOnly`. |
| Oversize frame "fail-closed 1009" | **REAL GAP — it's fail-OPEN.** Text frames over `max_message_bytes` are `FrameAction::Forward { skipped_oversize: true }` — forwarded **uninspected**. Bypass-by-size: pad a malicious frame over the cap to skip inspection. | `ws_inspect.rs:194-213`. The module doc comment ("fail-closed 1009") is aspirational/wrong. |
| **RC-3** sqli/nosql don't scan Cookie | **Real, deliberate.** Cookie/header scanning was REMOVED from sqli (adtech-cookie false positives). | `sqli.rs:94-96` comment. |
| **RC-2 / RC-4** WS + SSE Origin (CSWSH) | **Real gap.** No `Origin` allowlist anywhere in the WS/SSE path. | no `origin` match in `data_plane.rs` / `proto/*`. |
| **RC-5** `Sec-WebSocket-Protocol` XSS not scanned | **Real but low-severity.** `header_injection` scans header values for CRLF, not XSS; WS-specific headers aren't special-cased. Only exploitable if the backend echoes the chosen subprotocol into a rendered context. | `header_injection.rs` patterns are CRLF-only. |
| `connection_header_variant` bypass | **NOT a bug.** `is_websocket_upgrade` tokenizes `Connection` (`split(',').any(== "upgrade")`), so `keep-alive, Upgrade` is correctly detected as a WS upgrade. | `proto/ws.rs::is_websocket_upgrade`. |
| `ip_spoof_via_forwarded_header` | **NOT a bug in dev.** Dev doesn't trust `X-Forwarded-For` (all traffic → 127.0.0.1). Spoofing XFF changes nothing. Revisit only if a prod profile enables XFF trust without a trusted-proxy allowlist. | dev XFF gate (memory). |
| **RC-6** binary-frame TCP tunnel | **Architectural, real.** Binary frames are never inspected (pass-through verbatim). Hard to fix generically. | `ws_inspect.rs` doc + `accept` logic. |
| **RC-7** ws_message tests = 1006 | **Test-env limitation.** No real WS upstream at :9999 → 101 then immediate 1006 close → frames never flow → can't observe frame blocking. | report §7; `stub-pool` 127.0.0.1:9999. |

**Net:** RC-1 (13 frame attacks) is fixed by **config + an enforce default**, not new code. The genuinely-new code gaps are **Origin allowlist (CSWSH)** and **oversize fail-closed**. Cookie scanning is real but FP-prone. The rest are non-issues or architectural.

---

## 2. Workstreams

### P0 — WS frame inspection ON BY DEFAULT (no config) — operator-directed

Nico's call (2026-06-12, revised): **don't make `ws_inspect` a config at all.**
Every WebSocket connection should be inspected by default — no YAML block, no
UI toggle — exactly like HTTP requests are inspected without per-route opt-in.

- **Invert the default in the WS-upgrade path** (`data_plane.rs:~1787`).
  Today: inspect only if `route.ws_inspect.enabled == true` (default OFF =
  zero-copy passthrough). Change to: **inspect every WS upgrade by default
  (enforce)**, taking the default-inspect branch with `strip_extensions: true`.
  Keep `route.ws_inspect = Some({ enabled: false })` as an **internal opt-OUT
  escape hatch** (a route that genuinely needs raw passthrough), but it is NOT
  surfaced in the UI and not needed in normal config.
- **`WsInspectMode` default `LogOnly` → `Enforce`** so default-on actually
  blocks. Update the stale "tune before enforcing" comment.
- **No `dev.yaml` change needed** and **no UI toggle** — default-on means
  `make run-copilot` inspects WS frames with zero config. (Drop the
  route-editor-toggle item from the earlier draft.)
- **Verified-safe caveats** (document, don't block):
  - *Compression:* inspecting strips `Sec-WebSocket-Extensions` from the
    forwarded handshake (`ws_forward.rs:80`), so `permessage-deflate` is never
    negotiated and frames stay decodable. Cost = no WS compression (bandwidth,
    not breakage).
  - *Binary frames:* still forwarded verbatim (uninspected) — so a
    binary-protocol WS keeps working; only text frames are inspected.
  - *Zero-copy fast path:* lost for WS (the point — we now inspect). CPU/latency
    cost is per-text-message, bounded by `max_message_bytes`.
  - *Sanity-check the admin/live-feed WS + SSE* aren't disrupted by default-on
    enforcement (control-plane frames shouldn't trip detectors, but verify).
- **Drive-by:** fix the unused-import warning
  `aegis_core::config::CertSource` (`upstream/tls.rs:75`) — delete the line
  (the `match` doesn't name `CertSource::` variants). Keeps `clippy
  --workspace -D warnings` green.

**Effort:** ~half day (mostly the default-inversion + the enforce default +
tests; no UI work now). Unblocks QC's 13 frame attacks — detection is already
wired.

### ~~P1 — WS/SSE Origin allowlist (CSWSH)~~ — SKIPPED (Nico, 2026-06-12)

Descoped. The 5 CSWSH / cross-site-SSE techniques will **not** be covered.
Rationale (Nico's call): Origin/cookie-trust enforcement sits closer to the
app/gateway session layer than the WAF, and the cost/benefit isn't worth it
now. Reflected in the expected-detection table (§4) — CSWSH stays uncovered.
(If revisited later: per-route `ws_origin_allowlist` + `require_origin`,
shared host-match helper, applied at the WS-upgrade gate and the SSE path.)

### P1 — Oversize-frame: small inspection cap, fail-closed over it

**Problem:** `ws_inspect.rs:194-213` forwards over-cap text frames
**uninspected** (fail-OPEN) — an attacker pads a malicious frame over
`max_message_bytes` to skip inspection.

**Performance consideration (Nico):** the size *check* itself is free —
`payload.len() > max` is already computed. The real lever is the **cap**, which
bounds how much the WAF buffers per message to inspect. The 13 real frame
attacks are tiny JSON (`{"op":"pong","topic":"admin'--"}`), far under any sane
cap, and WS for this app class (live feed / chat / notifications / betting
ops) carries **small control/JSON messages**, not multi-MB blobs.

**Plan — small cap + fail-closed (the performance-conscious choice):**
- Set a **small default `max_message_bytes`** (proposed **256 KiB**, down from
  the 4 MiB codec default). The WAF then only ever buffers ≤256 KiB per message
  to inspect → bounded memory + latency, and every realistic attack payload AND
  legit control message fits under it and IS inspected.
- Over the cap in **Enforce**: **close with WS Close `1009`** (Message Too Big)
  instead of forwarding uninspected — closes the bypass-by-size, matching the
  module's own (currently false) "fail-closed 1009" doc comment. In `LogOnly`:
  forward but emit an audit so operators see size-bypass attempts.
- Net cost: a route that legitimately streams >256 KiB single WS messages would
  be closed. For this app class that's not expected; if a specific route needs
  it, the internal per-route `ws_inspect` override can raise its cap (escape
  hatch, not UI-surfaced).

**Alternative considered (not chosen now):** *prefix inspection* — inspect the
first `max` bytes of an over-cap message and forward the rest. Bounds memory
the same way and avoids hard-blocking legit large messages, but is bypassable
by padding the payload *after* the prefix, and adds streaming complexity. The
small-cap + fail-closed approach is simpler and safe for small-message WS;
revisit prefix-inspection only if a route genuinely needs large legit frames.

**Effort:** ~half day (lower the default cap + one `FrameAction`/close branch +
a stat/audit + tests).

### P2 — Cookie injection scanning (RC-3) — real, FP-prone

Re-introduce sqli/nosql scanning of cookie values, but **carefully** — the
last attempt was removed for adtech-cookie false positives.

- Scope to **session-shaped cookie names** only (`sid`, `session`,
  `session_id`, `auth`, `token`, `jwt`) rather than all cookies, OR a dedicated
  `CookieInjectionDetector` with a tight, high-confidence pattern set + a
  conservative score. Ship **log_only**-equivalent (low score) first and review
  FP on real traffic before promoting (mirror the `jwt_role_priv` rollout).
- Note: `jwt_inspection` already decodes JWT-shaped cookies; this covers the
  non-JWT session-cookie SQLi/NoSQLi case.

**Effort:** ~1 day incl. FP review. Lower priority — the cookie→SQL sink is an
app-side concern (parameterised queries); this is defense-in-depth.

### P3 / Won't-fix-now

- **`Sec-WebSocket-Protocol` XSS (RC-5):** optional — extend `header_injection`
  to scan WS-subprotocol/extension headers for `<script>`/HTML-metachar shapes
  at a low score. Low severity (needs a backend that reflects the subprotocol).
- **Binary-frame tunnel (RC-6):** don't attempt generic binary inspection. If
  needed, add an opt-in per-route `deny_binary_frames` so a JSON-over-WS API
  can refuse binary opcodes outright. Document the limitation.
- **`ip_spoof` / `connection_variant`:** non-issues (see §1). No change.
- **Test env (RC-7):** QC needs a real WS echo upstream at :9999 to observe
  frame blocking (`wscat --listen 9999` or a tiny `websockets` server). Document
  in the QC guide; not a code fix.

---

## 3. Sequencing

| Order | Item | Why |
|---|---|---|
| 1 | **P0** (WS inspect ON BY DEFAULT — invert default + enforce default + CertSource warning; no YAML/UI) | Unblocks QC's 13 frame attacks immediately; detection already wired. Operator-directed. |
| 2 | **P1 oversize: small cap + fail-closed** | Small; closes the bypass-by-size that would otherwise undercut P0. |
| 3 | **P2 cookie scanning** | FP-prone; ship log_only, review. |
| 4 | **P3** | Optional / document. |
| — | ~~WS/SSE Origin allowlist (CSWSH)~~ | **SKIPPED** (Nico). |

Suggested PRs: **PR1 = P0** (default inversion + enforce + warning), **PR2 =
oversize small-cap fail-closed**, **PR3 = cookie scanning** (separate for FP
review).

## 4. Expected detection after fixes

| Fix | Techniques | Note |
|---|---|---|
| P0 default-on ws_inspect + enforce | 13 ws_message (sqli/xss/nosql/cmdi) | Needs a real WS upstream to observe (RC-7). |
| Oversize small-cap fail-closed | `oversized_ws_frame` | Was a size-bypass. |
| Cookie scanning | 2 cookie sqli/nosql | log_only first. |
| **Skipped** | 5 CSWSH (WS + SSE Origin) | Descoped (Nico). |
| Out of scope | binary tunnel, ip_spoof, connection_variant | Non-issues / architectural. |

Net realistic: **13.8% → ~70%** (4 already + 13 frame + 1 oversize + 2 cookie ≈
20/29), with the honest caveats that (a) the 13 frame detections need a live WS
upstream to *demonstrate*, (b) CSWSH is intentionally uncovered, and (c) binary
tunneling stays uninspectable by design.

## 5. Related
- `WEBSOCKET_ATTACK_REPORT.md` — the QC report (corrected here).
- [[project_hyper_normalizes_framing]] — analogous "verify the architecture
  before trusting the report" lesson.
- [[feedback_dev_xff_single_ip_gates]] — why `ip_spoof` is a dev non-issue.
- [[feedback_waf_action_vs_mode]] — log_only vs enforce: verify real outcome
  (status / `X-WAF-Mode`), not `X-WAF-Action`.
