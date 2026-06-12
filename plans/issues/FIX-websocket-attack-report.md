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

### P1 — WS/SSE Origin allowlist (CSWSH) — real gap, code + config

Cross-Site WebSocket Hijacking + cross-site SSE: a malicious page opens a
`WebSocket`/`EventSource` to us; the browser attaches the victim's cookie; if
we accept any `Origin`, the attacker streams the victim's data. Origin
enforcement at the edge is a legitimate WAF function.

- **Config:** per-route `ws_origin_allowlist: Vec<String>` + `require_origin:
  bool` (literal host or `*.example.com` glob, reusing the open-redirect /
  jwt-jku matcher). Applies to **both** WS upgrades and SSE responses
  (`Accept: text/event-stream`).
- **Code:** in the WS-upgrade gate (`data_plane.rs:~1787`) and the SSE path,
  before forwarding: if `require_origin` and no `Origin` → block; if `Origin`
  host ∉ allowlist → block (403 + `cswsh_origin_blocked` audit). Empty
  allowlist + `require_origin:false` = today's behaviour (no-op), so it's
  opt-in and non-breaking.
- **dev.yaml:** seed the allowlist for the exam host so QC's 5 CSWSH techniques
  are caught.

**Effort:** ~1 day (shared origin-match helper + two call sites + config + UI
field later).

### P1 — Oversize-frame fail-closed — real bypass-by-size

`ws_inspect.rs:194-213` forwards over-cap text frames **uninspected**. An
attacker pads a malicious frame over `max_message_bytes` to skip inspection.

- Change the over-cap behaviour when `mode == Enforce`: **close the connection
  with WS Close `1009`** (Message Too Big) instead of forwarding uninspected —
  fail-closed, matching the module's own (currently false) doc comment. In
  `LogOnly`, keep forwarding but emit an audit so operators see the size-bypass
  attempts before enforcing.
- Keep a sane default `max_message_bytes` (codec 4 MiB) so legit large messages
  aren't the common case; document that enforce = fail-closed over the cap.

**Effort:** ~half day (one `FrameAction` branch + a stat/audit + tests).

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
| 2 | **P1 oversize fail-closed** | Small, closes the bypass-by-size that would otherwise undercut P0. |
| 3 | **P1 WS/SSE Origin allowlist** | Real CSWSH gap; +5 techniques. Bigger (shared helper + 2 call sites + config/UI). |
| 4 | **P2 cookie scanning** | FP-prone; ship log_only, review. |
| 5 | **P3** | Optional / document. |

Suggested PRs: **PR1 = P0** (config + UI + warning), **PR2 = oversize +
Origin allowlist**, **PR3 = cookie scanning** (separate for FP review).

## 4. Expected detection after fixes

| Fix | Techniques | Note |
|---|---|---|
| P0 enable ws_inspect + enforce | 13 ws_message (sqli/xss/nosql/cmdi) | Needs a real WS upstream to observe (RC-7). |
| Oversize fail-closed | `oversized_ws_frame` | Was a size-bypass. |
| Origin allowlist | 5 CSWSH (WS + SSE) | +`cross_site_sse_hijacking`. |
| Cookie scanning | 2 cookie sqli/nosql | log_only first. |
| Out of scope | binary tunnel, ip_spoof, connection_variant | Non-issues / architectural. |

Net realistic: **13.8% → ~80%+**, with the honest caveats that (a) the 13
frame detections need a live WS upstream to *demonstrate*, and (b) binary
tunneling stays uninspectable by design.

## 5. Related
- `WEBSOCKET_ATTACK_REPORT.md` — the QC report (corrected here).
- [[project_hyper_normalizes_framing]] — analogous "verify the architecture
  before trusting the report" lesson.
- [[feedback_dev_xff_single_ip_gates]] — why `ip_spoof` is a dev non-issue.
- [[feedback_waf_action_vs_mode]] — log_only vs enforce: verify real outcome
  (status / `X-WAF-Mode`), not `X-WAF-Action`.
