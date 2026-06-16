# PLAN — SEC regression: AI threshold sweep (0.65–0.85) eval + detector-improvement backlog (2026-06-16)

- **Type:** PLAN (evaluation of an AI-threshold tuning sweep → root-caused fix backlog for AI **and** rule detectors)
- **Status:** 🔴 The full threshold sweep (0.65 → 0.85) did **not** fix the benign over-block — root cause is the AI scoring mechanism, not the threshold. Confirmed by per-rule attribution (`ai` is the dominant blocker). Rule-detector gaps are code-level root-caused with fixes below.
- **Supersedes:** `PLAN-sec-regression-2026-06-16-newmodel.md` (model A/B comparison) as the current state-of-play.
- **Runs compared (all: cumulative IP-risk gate OFF — `X-WAF-Risk-Score` may display 100 but does not enforce; all detectors ON):**
  - **Old model** — `run-20260614-192320.md` (pass 633 · FN 374 · FP 42 · 60.3%)
  - **New model @ thr 0.65** — `run-20260616-201503.md` (pass 608 · FN 333 · FP 108 · 58.0%)
  - **New model @ thr 0.75** — `run-20260616-203643.md` (pass 607 · FN 340 · FP 102 · 57.9%)
  - **New model @ thr 0.80** — `run-20260616-210835.md` (pass 608 · FN 340 · FP 101 · 58.0%)
  - **New model @ thr 0.85** — `run-20260616-215428.md` (pass 610 · FN 269 · FP 97 · rejected-pre-WAF 73 · 62.5%) — clean full-corpus run on the newer runner.
  - *Superseded attempts:* `run-20260616-205942` (mislabeled 0.85 — different config profile) and `run-20260616-213946` (partial corpus, websocket+rate-limit only). Excluded.

## 1. Threshold sweep result — the lever barely moves (and that is the diagnosis)

The apples-to-apples metric across every run is the **benign-baseline class** (99 cases, zero pre-WAF rejections in any run — so the newer runner's rejected-400 bucket doesn't distort it):

| AI threshold | benign-baseline pass | benign-baseline FP | total FP |
|---|--:|--:|--:|
| old model (ref) | 62 | 37 | 42 |
| 0.65 | 6 | 93 | 108 |
| 0.75 | 11 | 88 | 102 |
| 0.80 | 12 | 87 | 101 |
| 0.85 | 16 | 83 | 97 |

The trend is smooth and monotonic: raising the AI confidence threshold across the **entire 0.65 → 0.85 range** claws back only **10 benign requests** (93 → 83 blocked), leaving **83/99 benign cases still blocked at 0.85** — vs 37 under the old model. Threshold tuning trades a few benign unblocks for re-opened attacks and **never escapes the ~80s benign-block floor**. **Threshold tuning is not the lever** — §2 shows why from the code.

**Per-rule attribution corroborates it.** The newer runner surfaces `X-WAF-Rule-Id`; at 0.85 (`run-20260616-215428`) the firing counts are `ai` **209**, xss 69, sqli 50, command_injection 46, path_traversal 43, … — the AI detector fires ~3× more than any other detector and is the dominant block source, exactly as the score-mechanism root cause predicts.

> **Note on overall FN/detection across runners.** The 0.85 run uses a newer runner that adds a **Rejected (pre-WAF 400)** bucket (73 cases: sqli 32, sse 22, cmdi 9, xss 9, protocol 1) — malformed payloads the HTTP server 400s before the WAF sees them. This inflates some attack-class detection% (sqli/xss/cmdi/protocol jump toward 100%) by removing hard cases from the denominator rather than by detecting them. So overall FN/detection are **not** directly comparable to the older-runner sweep rows; the benign-baseline FP column above is the comparable metric and is unaffected (0 rejected there).

## 2. Root cause of the benign over-block — the AI score mechanism, not the threshold

Code evidence (`crates/aegis-security/src/detectors`):

- **AI emits a flat score of 60** — `scores.rs › mod ai::AI = 60`, and `ai/mod.rs:211,225` construct the signal with `score: scores::ai::AI` and **`scale_score_by_prob: false`** (lines 212, 226). So a flagged request always adds exactly 60, regardless of how confident the model is.
- **The catch-all route runs at tier `high` = block threshold 60** (`config/dev.yaml`: `tier_override: high`; tier ladder `critical=50/high=60/medium=70/low=80`). A request blocks when summed detector score **≥** the tier threshold.
- Therefore **any single AI signal (60) on the high tier blocks the request by itself** — AI is effectively a solo-blocking detector at the corpus's default tier.
- The `confidence_threshold` only decides **whether** the signal is emitted; once emitted, the outcome is a guaranteed block. The bundled model is documented to "over-fire on benign traffic at every threshold below 0.95 (~75% FP at 0.85 on `/favicon.ico`, `/static/app.js`, `/api/list`)" (`config/dev.yaml` AI block). The new model scores benign traffic confidently **≥ 0.85**, so the entire 0.65 → 0.85 sweep leaves 80+ benign blocks intact (93 → 83) — exactly what the runs show. The threshold would have to climb to ~0.95+ to matter, and even then at a steep detection cost.

**Conclusion:** the over-block is structural. You cannot tune it away with the threshold short of ~0.95 (which also loses detection). Fix the **scoring/enforcement mechanism**.

### Fix options for the AI detector (in preference order)

1. **Demote AI to a corroborating signal (recommended).** Lower `scores::ai::AI` from **60 → 35** (a value on the documented ladder, below every protective tier). AI can then never block alone on critical/high/medium — it must **stack** with a rule detector (e.g. AI 35 + sqli 70 = 105). This kills the benign solo-blocks while keeping AI's value where it corroborates a real attack. Lowest-risk, no model work.
2. **Enable proportional scoring** — set `scale_score_by_prob: true` so `signal_score = round(60 × prob_attack)`. Helps only if the model's benign probabilities are < 1.0; given the "confidently wrong on benign" behavior, combine with option 1.
3. **Run AI in `log_only`** (control-plane `set_profile … "policies":["ai"],"mode":"log_only"`) so AI signals appear in audit but never enforce — capture the protocol/cors/ssrf detection wins without the availability hit while options 1/2 are calibrated.
4. **Per-deployment calibration** (documented path): sample ≥1h clean traffic, pick the threshold giving < 5% FP, only then raise enforcement. Necessary before shipping `enabled: true` regardless.

**Decision gate:** do not ship the new model in enforce mode until option 1 (or 1+2) lands and benign-baseline FP returns to ≤ old-model levels.

## 3. Improve the OTHER detectors too — evidence + solutions

The AI debate is orthogonal to these. Each gap below was reproduced against the detector source, not inferred from the score alone.

### 3a. SQLi (35 FN, 68%) — the misses are NOT a casing bug; fix hex-encoding + trace the pipeline

I tested the live `SQLI_PATTERNS` (`sqli.rs:10-56`) against the slipped payloads:

| FN payload | Regex result |
|---|---|
| `' OR '1'='1`, `' oR 1=1--`, `UnIoN SeLeCt …`, `OrDeR By 8--`, `wAiTfOr dElAy`, `'; DROP TABLE …`, path `/game/1 uNiOn sElEcT …` | **MATCH** (all patterns are `(?i)` case-insensitive) |
| `0x27206f7220313d31` (sqli-0096/97/98/99) | **MISS** |

- **Evidence A — hex-encoding is a real regex gap.** `0x27206f7220313d31` decodes to `' or 1=1`, but the `0x[0-9a-f]{8,}` rule was deliberately **removed** (`sqli.rs:40-44`) to stop GPU-id/hash FPs, and `normalize_for_detection` (`mod.rs:313-325`) only does URL/HTML/unicode decoding — no hex. So hex-literal SQLi slips with nothing to catch it.
  - **Solution:** add a **hex-string decoder** to `normalize_for_detection`: for each even-length `0x[0-9a-f]+` run, decode to bytes and append the decoded string as a scan variant. This catches `0x27…` because the **decoded** `' or 1=1` trips the existing `OR 1=1` rule, while a GPU id `0x0000C0DE` decodes to non-SQL bytes and stays clean — so it fixes the FN **without** reintroducing the FP that caused the rule's removal. Add sqli-0096..0099 as regression fixtures.
- **Evidence B — the mixed-case misses are a pipeline/coverage problem, not the patterns.** Since the regexes match these payloads in isolation yet the requests are allowed end-to-end (and a sqli signal scores 70 ≥ 60, which *would* block), the SQLi detector is **not firing in the live path** for these shapes — likely query-value decoding or detector-applicability for `?page=`/`?limit=` values and path-segment payloads (`/game/1 uNiOn…`).
  - **Solution:** do **not** spend effort "adding case-folding" — it already exists via `(?i)`. Instead add the exact slipped payloads as **end-to-end** fixtures and trace why `inspect()` doesn't emit: confirm `req.uri.to_string()` carries the decoded query value into `check_patterns`, and that no earlier short-circuit (route/tier/decode) drops it. This is the highest-FN class, so the trace is worth it.

### 3b. header_injection / SSE response-splitting (part of the 64 SSE FN) — CRLF scan is query-only

- **Evidence.** `header_injection.rs:38-42` scans **only** `req.uri.query()` (plus header values) for CRLF. The SSE splitting payloads carry the CRLF in the **path**: `/api/notifications/stream%0d%0aX-Injected: evil` (also raw `\r\n`, `%0a`) — there is no `?`, so `req.uri.query()` is `None` and the injection is never inspected. This matches the report's `sse_response_splitting` 22/22 FN and `protocol-0005` path-CRLF miss.
  - **Solution:** also scan the **decoded path** for CR/LF in `header_injection::inspect` — `check(&url_decode(req.uri.path()), "path", …)`. Raw `\r`/`\n` (or `%0d`/`%0a`) in a path has no benign use, so FP risk is ~0. Add the SSE/protocol CRLF payloads as fixtures.

### 3c. WebSocket handshake controls (≈186-192 FN) — frame inspection works, the upgrade plane is unguarded

- **Evidence (carried from prior triage, unchanged in all three runs).** WS frame-injection sub-tests pass 88/88; the misses are all upgrade-time: CSWSH (Origin not validated), `ws_ssrf_via_host_header`, `ws_tcp_tunnel` / `ws_proxy_smuggle` (subprotocol), partial `ws_auth_bypass` / `ws_upgrade_path_bypass`.
  - **Solution:** add upgrade-time controls on `/ws/live` — Origin allowlist (CSWSH), Host-header validation (SSRF), subprotocol/proxy-smuggle rejection, finish auth/path-bypass coverage. Leave frame inspection alone. Decide CSWSH ownership (WAF vs gateway) once, jointly with HTTP-CORS.

### 3d. auth-jwt (24 FN), cmdi (9), xss (9) — secondary

- jwt: extend `jwt_inspection` route coverage to the still-missed routes (improved old→new but 24 remain). cmdi: arg-style (`| id`, `& whoami`) + `%00`-suffix — strip trailing `%00` before matching and detect lone shell-metachar + command token. xss: 9 mixed-case/backtick variants — same e2e-trace approach as SQLi 3b (verify the detector fires, since `(?i)` patterns likely match in isolation).

## 4. What the new model genuinely improved (keep — don't regress when fixing FP)

Over the old model, both new-model runs close real gaps: **protocol 43% → 97%**, **cors 75% → 100%**, **ssrf 94% → 100%**, **auth-jwt 51% → 61%**. These are the reason to keep AI **on** (log-only or demoted-score), not off.

## 5. Prioritized actions

1. **P1 — AI scoring fix (ship-blocker):** demote `ai::AI` 60 → 35 (option 1), optionally `scale_score_by_prob: true`; re-run; target benign-baseline FP ≤ old-model (≤8 residual rule FPs) with no loss of the protocol/cors/ssrf/jwt wins. Until then keep AI `log_only` in enforce deployments.
2. **P2 — SQLi:** add hex-string decode to `normalize_for_detection` (+fixtures); e2e-trace the mixed-case/path FNs (don't touch `(?i)`).
3. **P2 — header_injection:** scan decoded path for CRLF (+SSE/protocol fixtures).
4. **P3 — WS upgrade controls; SSE request-side auth/Origin; jwt route coverage; cmdi `%00`/arg-style.**
5. **Add the full QC benign set as FP regression fixtures** so future model/threshold swaps can't silently reintroduce the over-block.

## 6. Verification / done criteria

- New-model enforce run with `ai::AI = 35`: benign-baseline FP ≤ old-model; protocol/cors/ssrf/jwt detection unchanged or better.
- SQLi: sqli-0096..0099 (hex) caught with `clean_hex_blob`/`clean_hash_param` negatives still green; mixed-case FNs either caught after the pipeline trace or filed with the exact root cause.
- header_injection: SSE/protocol path-CRLF payloads caught; no new benign-path FP.
- A `new-model + AI-OFF` run committed to re-confirm the rule-engine FP floor (`/deposit`×5, `/withdrawal`×2, `PUT /api/profile`×1) is unchanged.

## Source data

- `run-20260614-192320`, `run-20260616-201503`, `run-20260616-203643` (`.md` + `.summary.json`).
- Code: `crates/aegis-security/src/detectors/{scores.rs, ai/mod.rs, sqli.rs, header_injection.rs, mod.rs}`; `config/dev.yaml` (tiers + AI block).
- Prior: `PLAN-sec-regression-2026-06-16-newmodel.md`, `PLAN-sec-regression-2026-06-14-triage.md` (superseded).
