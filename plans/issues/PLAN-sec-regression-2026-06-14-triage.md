# PLAN — SEC regression triage (QC r2 run 2026-06-14) → fix/improve

- **Type:** PLAN (triage of a QC security-regression run → prioritized fix/improve backlog)
- **Status:** 🟡 Planned — analysis updated against the known run config; ready to start coding P1/P2
- **Source:** `tests/n-tester/r2-regression/reports/run-20260614-192320.md` (= `latest.md`); runner `tests/n-tester/r2-regression/run_all.py`
- **Created:** 2026-06-14 (Nico — "QC give new SEC report, investigate + plan")
- **Updated:** 2026-06-14 — Nico confirmed run config: **cumulative IP-risk thresholds OFF, all detectors ON incl. AI**. Re-interpreted accordingly (see below).
- **Headline:** 1159 tests · **detection 60.3%** · **374 FN** (attacks allowed) · **42 FP** (benign blocked) · target `http://localhost:8080`

## ✅ Config is now known — the 60.3% is a clean per-request baseline

This run was executed with **`risk.thresholds.enabled = false` (cumulative IP-risk gate OFF)** and **every detector enabled, including AI**. That resolves the confounds the first draft of this plan flagged as unknown:

1. **Single-IP / cumulative-poisoning (was confound #1/#2): NEUTRALIZED.** With the cumulative gate off, no request is blocked or challenged on accumulated IP risk. Every decision is **per-request detector output**. Confirmed in the log: **all 42 FPs are `actual:"block"` (zero `challenge`)**, and all 374 FN are `actual:"allow"`. There is no challenge band in play, so the earlier "these FPs are cumulative-band collateral that will clear after a reset" hypothesis is **false** — they are real per-request blocks.
2. **AI / config state (was confound #4): KNOWN.** AI was ON. So SQLi at 65% with 38 FN, XSS 9 FN, CMDi 9 FN are detection misses **that AI did not save**, not "maybe AI was off." This makes them higher-severity than the draft assumed.

Remaining caveats (do **not** over-correct for these):
- **Plaintext `:8080` surface** — no TLS ⇒ `device_fp` is `None`; irrelevant to per-request detection but keep in mind for any handshake/fingerprint-dependent control. Cross-ref [[feedback_dev_xff_single_ip_gates]].
- **SSE/WS request-vs-response** — only the *response-side* server-frame SSE injection is a by-design stream-through; everything else tested is request-borne (see SSE/WS sections).

### Step 0 (now mostly satisfied) — one complementary run to attribute AI vs rules

The gate-off baseline is done. The single missing experiment is a **gate-off + AI-OFF** run, to split each FN/FP between the rule engine and the AI detector:
- FNs that flip allow→block with AI on were AI saves; FNs that stay allowed in **both** runs are rule-engine gaps that AI also misses (top priority to fix at the rule layer).
- FPs that disappear with AI off were **AI over-blocks** (the prime suspect for the benign over-block below); FPs that persist are rule-engine over-fire.
- Record AI on/off, the config file, and tier thresholds in both report headers.

Only after that split do we know whether the benign over-block (next section) is an AI-tuning problem or a rule problem. Everything else below is actionable now.

---

## 🔴 Top finding — systemic benign over-block (42 FP, all real)

37 of 99 benign-baseline requests (**~37%**) plus 4 caching + 1 WS were blocked **per-request** with the gate off. The breadth rules out "special-character SQLi/XSS over-fire" as the whole story:

- **Plain alphanumeric names blocked:** `name=Alice` (baseline-0038), `name=user_42` (baseline-0045), `name=Jean-Luc` (hyphen only). No injection characters at all.
- **No-payload requests blocked:** `/favicon.ico`, `/static/js/app.js` (also caching-0020/21/32/33), `GET /api/profile`, `GET /game/list`, `GET /api/public/stats`.
- **Benign banking/auth POSTs blocked:** `/deposit` ×6, `/withdrawal` ×2, `/otp` ×3.
- **Benign bodies blocked:** `/api/feedback` prose ×5, `/api/analytics/events` gzip ×4, `PUT /api/profile` i18n ×4.
- **Special-character names** (still real FPs, subset of the above): `O'Brien`, `Anaïs`, `李雷`, `Smith & Co`, `5 < 10 fan`.

Because plain `Alice` and static assets are blocked with **no payload and the gate off**, this looks like a **systemic over-block from an aggressive detector** (prime suspect: AI, given it was on and flags prose/i18n/analytics), not character-level SQLi/XSS tuning. **The AI-off run above is the decisive test.** A ~37% benign block rate is the single most user-impacting issue in this report and gates everything else — a WAF that 403s `favicon.ico` and `name=Alice` is unshippable in enforce mode. Cross-ref [[feedback_waf_action_vs_mode]] (confirm these are enforce-mode blocks, not log-only annotations).

### ✅ P0 attribution result — AI-off run `run-20260614-210530` (gate off, **AI OFF**, all rules on)

The decisive AI-off run landed. It settles the top finding and splits FN/FP between AI and the rule engine.

- **FP: 42 → 8.** ~34 of 42 benign blocks were **AI over-blocks** — CONFIRMED. With AI off, `name=Alice`, `/favicon.ico`, `/static/js/app.js`, `/api/feedback` prose, `/api/analytics` gzip, i18n profile **all clear**. The **residual 8 are real rule-engine FPs**: `POST /deposit` ×5, `POST /withdrawal` ×2, `PUT /api/profile` ×1. → **P1 shrinks dramatically and changes owner:** the fix is either (a) tune the **AI** block threshold / whitelist static+benign-shaped traffic (it drove ~80% of the FPs), and/or (b) fix the small rule over-fire on `/deposit`/`/withdrawal`/`/api/profile` (must-fix regardless of AI).
- **FN: 374 → 488; detection 60.3% → 52.7%.** AI contribution by class (AI-on% − AI-off%): **cors +50, protocol +35, cmdi +21, caching +15, websocket +12, sse +8, jwt +7, ssrf +6, xss +4, sqli +2, nosql +2, path +2** (rate-limit +50 is noise — mostly skipped).
- **Rule-only gaps (allowed in BOTH runs → AI can't save them → fix at the rule layer, highest priority):** **sqli (AI +2 only — its 38–41 FN are RULE gaps: mixed-case `sElEcT` + hex `0x27…`)**, several **cmdi** arg-style/`%00`, **jwt** route coverage. These are the durable P2 detector work — they don't depend on the AI debate.
- **AI is the workhorse for cmdi (body-borne: `/api/feedback`, `/api/bet-reports/export`, `/cgi-bin/*`), cors (cross-origin), protocol (methods), caching (cache-deception), sse.** Turning AI off tanks these. So those classes are "keep AI on (and tune its FP)" OR "write new rules" — a product call, not a pure bug.

**Bottom line for P1:** keep AI **on** for detection (it adds real coverage in 5+ classes), but **fix its benign over-block** (threshold/whitelist) so the 8→34 FP class disappears; separately fix the 8 residual rule FPs. P2 rule work (sqli mixed-case+hex, cmdi, jwt) proceeds independently since AI doesn't cover them.

---

## Triage by class (re-interpreted under gate-off + AI-on)

| Class | Detect% | FN | FP | Bucket | Note (updated) |
|---|--:|--:|--:|---|---|
| path-traversal | 100 | 0 | 0 | ✅ | clean |
| injection-nosql | 96 | 2 | 0 | 🟢 minor gap | 2 variants (`POST /login` nosql-0041/42) |
| ssrf | 94 | 2 | 0 | 🟢 minor gap | `POST /game/1/play` (body-borne URL) |
| xss | 89 | 9 | 0 | 🟡 real gap | mixed-case/backtick variants survive **with AI on** |
| injection-cmdi | 88 | 9 | 0 | 🟡 real gap | arg-style (`| id`, `& whoami`) + nullbyte-suffix survive AI |
| cors | 75 | 6 | 0 | 🔵 scope | `GET /admin/users` cross-origin — gateway/app scope (cf. WS report RC-4) |
| caching | 73 | 5 | 4 FP | 🟡 real gap | cache-deception FN real; **4 FP are real static-asset blocks** (part of the over-block above) |
| injection-sqli | 65 | 38 | 0 | 🔴 real gap | **AI on and still 65%** — mixed-case (`sElEcT`) + hex (`0x27…`) bypass both rules and AI |
| auth-jwt | 51 | 30 | 0 | 🟡 real gap | `jwt_inspection` coverage holes on `GET /admin/*`, `/api/profile`, `POST /deposit` |
| rate-limit | 50 | 3 | 0 | ⚪ mostly skipped (88) | needs the dedicated rate-limit harness |
| protocol | 43 | 21 | 0 | 🔵 mostly scope | method hardening ruled gateway-scope earlier ([[project_docs_overstate_impl]]); revisit |
| websocket | 42 | 185 | 1 | 🔴 real gap (handshake) | **frame injection 88/88 CAUGHT**; misses are handshake/upgrade controls (see below) |
| sse | 9 | 64 | 0 | 🔴 real gap (request-side) | only server-frame injection is by-design skipped; auth/hijack/splitting are request-borne misses |
| benign-baseline | 63 | 0 | 37 | 🔴 FP — all real | systemic over-block (top finding above) |

---

## WebSocket (185 FN) — gap is the handshake/upgrade control plane, NOT frame inspection

Per-category breakdown (gate off, so these are pure detection results):

**Caught (frame inspection works):**
- `ws_message_injection_sqli / xss / cmdi / nosqli` — **22/22 each (88/88)** ✅
- `ws_dos_large_frame` 22/22 ✅, curated oversized-frame, handshake-tamper (curated bad-version/missing-key/missing-origin/tcp-tunnel-subproto), upgrade on `/admin/users` & `/api/transactions` ✅

**Missed (handshake/upgrade controls):**
- `cswsh` 22/22 FN + 3 curated CSWSH cross-site Origin → **Origin not validated on WS upgrade** (overlaps cors/RC-4 gateway-scope debate)
- `ws_ssrf_via_host_header` 22/22 + 1 curated → **Host-header SSRF on upgrade**
- `ws_tcp_tunnel` 22/22 → subprotocol TCP-tunnel
- `ws_proxy_smuggle` 22/22 · `ws_protocol_waf_bypass` 22/22 → protocol-level upgrade smuggling/bypass (cross-ref [[project_hyper_normalizes_framing]])
- `ws_dos_ping_flood` 22/22 → volumetric (likely out of per-request WAF scope; rate-limit harness)
- `ws_handshake_tamper` 21/22 (curated 1 pass) · `ws_auth_bypass` 15/22 · `ws_upgrade_path_bypass` 12/22 (incl. `/deposit`) → partial coverage

**Action:** this is NOT BUG-WS-2 (AI over-blocking frames) — frames are fully caught. Add upgrade-time controls: Origin allowlist (CSWSH), Host-header validation (SSRF), subprotocol/proxy-smuggle rejection, and complete the auth/path-bypass coverage on `/ws/live`. Decide CSWSH ownership (WAF vs gateway, cf. RC-4). The 1 WS FP is `websocket-0002` "Benign WS subscribe frame" — re-check after the over-block fix.

## SSE (64 FN) — request-side auth/hijack/splitting are real; only server-frame injection is by-design

- `sse_message_injection (server frame)` 22 → **SKIPPED** (response-side stream-through; documented `docs/data-plane/sse-streaming.md` trade-off). Not a gap.
- `sse_auth_bypass` 22/22 FN → request-side auth not enforced on `/api/notifications/stream` — **real gap**
- `sse_hijack` 18/22 FN + 2 curated cross-site → Origin not enforced on SSE — **real gap**
- `sse_response_splitting` 22/22 FN → **CRLF in the request URL** (`/api/notifications/stream%0d%0aX-Injected: evil`, raw `\r\n`, `%0a`, space-injected) — request-borne, must be caught — **real gap**

**Action:** the earlier "SSE bypassed by design" framing was too broad. Add request-side CRLF/path-injection detection and Origin/auth checks on the SSE endpoint. Only the server-frame subset stays a documented trade-off.

---

## Prioritized plan

**P0 — attribution run (small, unblocks root-causing):** one **gate-off + AI-OFF** re-run to split FN/FP between AI and the rule engine (see Step 0). Record AI/config/thresholds in the header. This tells us whether the benign over-block is AI tuning vs rules, and which FN are rule-only gaps.

**P1 — systemic benign over-block (ship-blocker, user-facing):** ~37% benign block rate, incl. `name=Alice`, `/favicon.ico`, `/static/js/app.js`, `/deposit`, `/otp`, gzip analytics, i18n profile, prose feedback. Triage with the P0 AI-off split:
- If AI-driven → tune/raise the AI block threshold for benign-shaped traffic; whitelist static/asset paths from semantic scoring.
- If rule-driven → fix the over-firing rule(s) (context-aware: lone quote/angle/`&` in a short `name=` value, plain alphanumerics, and no-payload static GETs must not block).
- Add the full QC benign set (special-char names + static + no-payload POSTs) as FP regression fixtures.

**P2 — real detection gaps (AI confirmed on; close at the rule layer where AI misses):**
- **sqli (38 FN)** — mixed-case (`sElEcT`, `Pg_sLeEp`) and hex-literal (`0x27…`) bypass rules **and** AI. Add case-folding/normalization + hex-string decode before SQLi matching; mine exact payloads from the `.jsonl`.
- **xss (9)** + **cmdi (9)** — mixed-case/backtick XSS, arg-style + nullbyte-suffix CMDi. Add the same normalization (mixed-case fold, `%00` strip) ahead of matching.
- **auth-jwt (30 FN)** — extend `jwt_inspection` to the missed routes (`GET /admin/*`, `/api/profile`, `POST /deposit`).
- **caching cache-deception (5 FN)** — rule for `<sensitive-path>.<static-ext>` path-confusion (`/admin/*.css`, `/api/**/*.js`, `/deposit/.css`).

**P3 — WS handshake controls + SSE request-side (now characterized, real):**
- **WS upgrade controls** — Origin allowlist (CSWSH), Host-header validation (SSRF), subprotocol/proxy-smuggle rejection, finish auth/path-bypass coverage. Frame inspection already works; don't touch it.
- **SSE request-side** — CRLF/path-injection detection + Origin/auth on `/api/notifications/stream`. Leave server-frame injection as the documented trade-off.
- **ping-flood / volumetric WS** — defer to the rate-limit harness.

**P4 — scope calls (confirm intent, likely WONTFIX-as-WAF):**
- **protocol HTTP methods** (TRACE/TRACK/DEBUG/CONNECT/PROPFIND/…): earlier decision = gateway scope. Re-affirm or add an optional method-allowlist gate.
- **cors + CSWSH Origin**: cross-origin enforcement is gateway/app scope (RC-4). Decide once for both HTTP-CORS and WS-CSWSH.
- **`/__control/*`** protocol/WS cases: decoy path (`/__control/`, not loopback-only `/__waf_control/`); confirm they 404 to upstream and aren't a real surface. Cross-ref [[project_control_plane_loopback_only]].

## Verification / done criteria

- P0 AI-off run committed with AI/config/thresholds in the header; FN/FP attributed AI-vs-rule.
- P1: benign block rate → ~0 on the QC benign set (special-char names, static assets, no-payload POSTs) in enforce mode, with no SQLi/XSS/CMDi regression.
- P2: each FN payload from the `.jsonl` either covered by a new/normalized rule case or attributed to AI (with AI confirmed on); SQLi back above target with mixed-case + hex variants caught.
- P3: WS upgrade controls (Origin/Host/subproto/auth/path) and SSE request-side (CRLF/Origin/auth) covered; frame inspection unchanged; server-frame SSE injection documented as a deliberate trade-off.

## Related

- [[project_docs_overstate_impl]] — verify against code, both directions.
- [[feedback_two_score_model]], [[feedback_challenge_band_diagnostics]], [[feedback_dev_xff_single_ip_gates]] — gate-off neutralizes these confounds for this run; keep for future gate-on runs.
- [[project_hyper_normalizes_framing]] — relevant to WS proxy-smuggle / protocol-bypass misses.
- Production-miss analysis (`PRODUCTION_MISS_ANALYSIS.md` §8) — "rule vs AI" split (P0/P2) is the same theme.
- WS lifecycle audit bug: [`BUG-ws-lifecycle-audit-missing-tier-path.md`](./BUG-ws-lifecycle-audit-missing-tier-path.md) (separate, observability-only).
</content>
</invoke>
