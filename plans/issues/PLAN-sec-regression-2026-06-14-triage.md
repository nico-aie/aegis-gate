# PLAN — SEC regression triage (QC r2 run 2026-06-14) → fix/improve

- **Type:** PLAN (triage of a QC security-regression run → prioritized fix/improve backlog)
- **Status:** 🟡 Planned — not started (analysis done; needs a clean re-baseline before coding most items)
- **Source:** `tests/n-tester/r2-regression/reports/run-20260614-192320.md` (= `latest.md`); runner `tests/n-tester/r2-regression/run_all.py`
- **Created:** 2026-06-14 (Nico — "QC give new SEC report, investigate + plan")
- **Headline:** 1159 tests · **detection 60.3%** · **374 FN** (attacks allowed) · **42 FP** (benign blocked) · target `http://localhost:8080`

## ⚠️ Read this first — the 60.3% is confounded; don't fix blind

Before treating FN/FP as WAF gaps, account for **test-methodology + config** effects that the run did **not** control for:

1. **Single source IP, no per-case reset.** The runner sends all 1159 requests from **`127.0.0.1`** and only optionally resets state **once** at the very start (`run_all.py:280` `--reset-state`), never between cases. With no XFF/IP rotation, every request shares one cumulative-risk bucket (`build_risk_key` = `ip+device_fp+session`; one UA, no session ⇒ pure-IP key). Cross-ref [[feedback_dev_xff_single_ip_gates]], [[feedback_two_score_model]], [[feedback_challenge_band_diagnostics]].
2. **A 429-challenge on a benign request is scored as FP** (`run_all.py:227-233`: `expected==allow` and `actual in (block,challenge)` ⇒ FP). So when the poisoned IP drifts into the **challenge band** (`challenge_at:40 ≤ score < block_at:80`), *benign* requests get `429` and are counted **FP** — even though no detector fired on them. The static-asset / `/deposit` / `/favicon.ico` FPs below are almost certainly this, **not** detector false positives.
3. **FN = genuine `allow`.** An attack counts as caught if it gets block **or** challenge; FN only if it got `allow`. So the 374 FN are real pass-throughs at the moment the IP was *not* in a gating band — i.e. genuine **per-request** detection misses (good signal), but their *count* is sensitive to when in the run the IP was hot.
4. **Unknown AI / config state.** The report doesn't record whether the AI detector was enabled, which config the `:8080` server booted, or the tier thresholds in effect. AI on/off swings sqli/xss/cmdi/jwt/ssrf materially (the AI detector is the obfuscated-payload workhorse — see the production-miss analysis).
5. **Plain `:8080`.** Some surfaces behave differently on the plaintext data port (historical `with_upgrades` WS gap, no TLS fingerprint ⇒ `device_fp` is `None` ⇒ pure-IP keying, amplifying #1).

### Step 0 (MUST precede coding) — re-baseline cleanly

Re-run with the IP/cumulative confound removed so per-request detection is isolated:
- **either** reset-state **per case** (or per class), **or** send a **distinct client IP / `X-Forwarded-For` per case** (requires the edge to trust XFF in the test profile), **or** run with the **cumulative gate off** (`risk.thresholds.enabled:false`) to measure pure per-request detection.
- Record **AI enabled?**, the **config file**, and tier thresholds in the report header.
- Produce two numbers per class: **per-request detection** (gate off) vs **with cumulative** (gate on). The gap between them is the IP-poisoning contribution.

Only the residual FN/FP after Step 0 are real WAF work. The buckets below pre-classify what to expect.

---

## Triage by class

| Class | Detect% | FN | FP | Bucket | Note |
|---|--:|--:|--:|---|---|
| path-traversal | 100 | 0 | 0 | ✅ | clean |
| injection-nosql | 96 | 2 | 0 | 🟢 minor gap | 2 variants |
| ssrf | 94 | 2 | 0 | 🟢 minor gap | |
| xss | 89 | 9 | 0 | 🟡 real gap | obfuscation variants (AI-dependent) |
| injection-cmdi | 88 | 9 | 0 | 🟡 real gap | encoding variants |
| cors | 75 | 6 | 0 | 🔵 scope | `GET /admin/users` cross-origin — CORS/Origin is gateway/app scope (cf. WS report RC-4) |
| caching | 73 | 5 | 4 FP | 🟡 real gap | **cache-deception**: `/admin/users.css`, `/api/transactions/x.js`, `/deposit/.css` — sensitive path + fake static ext; 4 FP are real static assets blocked (poisoning) |
| injection-sqli | 65 | 38 | 0 | 🔴 real gap | low for SQLi — confirm AI on; obfuscated/encoded variants |
| auth-jwt | 51 | 30 | 0 | 🟡 real gap | `jwt_inspection` coverage holes (e.g. `jwt-0014 GET /admin/users`) |
| rate-limit | 50 | 3 | 0 | ⚪ mostly skipped (88) | needs the dedicated rate-limit harness |
| protocol | 43 | 21 | 0 | 🔵 mostly scope | TRACE/TRACK/DEBUG/CONNECT/PROPFIND/PATCH/DELETE/OPTIONS + `/__control/*` — HTTP-method hardening **ruled out-of-WAF-scope** earlier ([[project_docs_overstate_impl]] triage); revisit decision |
| websocket | 42 | 185 | 1 | 🔴 investigate | all `/ws/live` GET — frame-inspection not catching; AI-over-block (BUG-WS-2) or below-threshold frames or harness counts every frame |
| sse | 9 | 64 | 0 | 🔴 investigate | all `/api/notifications/stream` — **response-stream**; SSE streams through with **no response-body inspection by design** ⇒ response-borne attacks are invisible. Confirm attack vector (request vs response) before calling it a gap |
| benign-baseline | 63 | 0 | 37 | 🟠 FP — mixed | see below |

### benign-baseline FP (37) — split real vs artifact

- **Real per-request detector FP** (would 403 on the *first* request regardless of poisoning): `/game/1?name=O'Brien` (apostrophe → SQLi), `name=5 < 10 fan` (angle → XSS), `name=Smith & Co` (ampersand), `name=Anaïs`/`李雷` (non-ASCII). These are **legitimate special-character names** tripping SQLi/XSS. **This is the highest-value FP fix** — real users have apostrophes in names.
- **Artifact (cumulative-band collateral)** — re-test after Step 0; expect these to clear: `/favicon.ico`, `/static/js/app.js`, `POST /otp`, `POST /deposit`, `POST /withdrawal`, `POST /api/feedback`, `POST /api/analytics/events`, `GET /api/public/stats`. No payload — blocked because the shared IP was hot.

---

## Prioritized plan

**P0 — methodology (unblocks everything):** Step 0 re-baseline (per-case reset **or** per-case IP/XFF), record AI+config, emit gate-off vs gate-on numbers. Until this lands, treat all class %s as lower bounds with unknown poisoning tax.

**P1 — real detector FP (user-facing):** SQLi/XSS over-fire on benign special chars (apostrophe / `<` / `&` / non-ASCII) in `name=` query values. Tune `sqli.rs` / `xss.rs` (context-aware: a lone quote/angle in a short value isn't an injection) + add the QC benign-name set as FP regression fixtures. **Verify these 403 pre-poisoning first.**

**P2 — real detection gaps (confirm AI on, then close per class):**
- **sqli (38 FN)** + **xss (9)** + **cmdi (9)** — obfuscated/encoded variants; mine the exact FN payloads from `run-20260614-192320.jsonl`, add detector cases or confirm AI covers them.
- **auth-jwt (30 FN)** — extend `jwt_inspection` for the missed variants.
- **caching cache-deception (5 FN)** — add a recon/rule for `<sensitive-path>.<static-ext>` (path-confusion), e.g. `/admin/*.css`, `/api/**/*.js` to a non-static handler.

**P3 — investigate-then-decide (don't assume gap):**
- **sse (9%, 64 FN)** — characterize: is the attack in the request (must be caught) or the streamed response (bypassed by design — `docs/data-plane/sse-streaming.md`)? If request-side and allowed, real gap; if response-side, it's the documented stream-through trade-off → decide whether SSE needs opt-in response inspection.
- **websocket (42%, 185 FN)** — characterize: handshake attack (should be caught) vs text-frame attack (needs `ws_inspect` enabled + cross threshold) vs harness counting each frame as a case. Cross-ref BUG-WS-2 (AI over-blocks WS frames) and the new global-mode AND (a fleet/route `log_only` forwards). Confirm `ws_inspect` was enabled on `/ws/live` in the test config.

**P4 — scope calls (confirm intent, likely WONTFIX-as-WAF):**
- **protocol HTTP methods** (TRACE/TRACK/DEBUG/CONNECT/PROPFIND/…): earlier decision = gateway scope. Re-affirm or add an optional method-allowlist gate.
- **cors** (`GET /admin/users` cross-origin): CORS/Origin enforcement is gateway/app scope (cf. WS report RC-4). Decide.
- **`/__control/*`** protocol cases: these probe a *decoy* control path (`/__control/`, not the loopback-only `/__waf_control/`); confirm they 404 to upstream and aren't a real surface. Cross-ref [[project_control_plane_loopback_only]].

## Verification / done criteria

- Step-0 re-baseline report committed with AI+config recorded and gate-off vs gate-on columns.
- P1 benign-name FPs: 0 FP on the special-char name fixtures (pre-poisoning), no SQLi/XSS regression.
- P2 classes: FN payloads triaged from the `.jsonl`; each either covered by a new detector/rule case or attributed to AI (with AI confirmed on).
- P3: SSE + WS each have a written "request-borne vs by-design-bypass" determination before any detector change.

## Related

- [[project_docs_overstate_impl]] — verify against code, both directions.
- Production-miss analysis (`PRODUCTION_MISS_ANALYSIS.md` §8) — same single-IP / composite-key / XFF themes; the "rule vs AI" split applies to P2.
- WS lifecycle audit bug: [`BUG-ws-lifecycle-audit-missing-tier-path.md`](./BUG-ws-lifecycle-audit-missing-tier-path.md) (separate, observability-only).
