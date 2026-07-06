# FEAT — OTP / second-factor brute-force detection

**Status:** ✅ COMPLETE & MERGED to develop 2026-07-06 (PR #168, commit ff410deb; merge
d9e80386) — TDD, workspace green. Deferred: live `/otp` smoke against a running server
(enforcement path unit/workspace-verified only).
**Author:** planning pass 2026-07-06
**Area:** `crates/aegis-security/src/detectors/brute_force.rs`, config + reload wiring
**Evidence:** `tests/s-tester/reports/OTP_bruteforce_report.md` (Round-2 BTC logs, 514 `/otp` events)
**Related:** [[project_attack_vector_coverage_assessment]] (AC track), `velocity_sequence.rs`
(OTP step class precedent), [[project_two_score_model]], [[project_waf_vs_gateway_boundary]]

> **Design north star (owner directive):** *detect the risk case, do NOT trade it against
> false positives.* Every axis below is chosen because its signature is **absent from
> legitimate traffic by construction** — not because it's aggressive. We add **stateful**
> signals with thresholds far above any legit behaviour; we do **not** lower existing
> thresholds, and we do **not** put a content/AI detector on `otp_code`.

---

## 1. Problem / confirmed gap

`BruteForceDetector` gates on a hardcoded `is_auth_path()` allowlist (`brute_force.rs:548`)
that covers password login (`/login`, `/signin`, …) but **not the OTP / second-factor
step.** The hackathon target proves it:

```
POST /login   { username, password }   → returns short-lived login_token   [COVERED]
POST /otp     { login_token, otp_code } → verifies OTP, sets session cookie  [NOT COVERED]
```

Nothing in the brute-force detector inspects `/otp` today.

### What the S-Tester Round-2 evidence actually shows

`tests/s-tester/reports/OTP_bruteforce_report.md` analysed 514 real `/otp` events:

| Pattern | Shape | Volume | Caught by |
|---|---|---|---|
| **#3 — OTP spraying (DOMINANT)** | **one fixed `otp_code=000090` across 458 distinct `login_token`s, 1 IP, 0.4 req/s, 21 min** | **458 / 465 brute reqs** | IP risk-score reputation **only** |
| #1 — per-session code grind | one `login_token` tries several codes (`123456`, `132456`, sequential `000001…`) | minor this round | — |
| Injection in `otp_code` | SQLi/XSS/cmd fuzzing of the field | 8 | content detectors (correct) |

### Raw-data validation (`otp_events.json`, 514 records)

Analysing the raw events confirms the axis design and pins the thresholds to ground truth:

| Metric | Value | Implication |
|---|---|---|
| distinct `login_token`s submitting `000090` | **458** | Axis B target |
| **max distinct tokens on `000090` in any 60 s window** | **44** | threshold 10 fires ~15 s in, ~4× margin |
| codes clustered by ≥10 distinct tokens | **exactly 1** (`000090`) | Axis B fires **once**, zero other clusters → no FP on real data |
| every other `otp_code` value (injections, random strings, `000001`) | **1 token each** | never clusters → not double-counted as brute force |
| distinct codes per token histogram | 459×1, 1×2, **1×6** | Axis A (thr 5) fires on exactly the one grind token |
| brute events catchable **only** by Axis B | **458 / 465 (~99 %)** | per-token axis alone misses the attack — Axis B is the workhorse |
| distinct IPs | 3 | single-IP this round; IP is rotatable — see invariant argument §3.0 |

Both recommended thresholds (spray 10, grind 5) are **data-backed with wide margin** and
sit far above anything legitimate traffic produces.

Three conclusions drive the design:

1. **The dominant shape is spraying, not per-session grinding.** A single code bet against
   many sessions. A per-session ("many codes per token") axis alone **misses it entirely** —
   each token shows only one code.
2. **It was stopped this round by luck: one IP.** The block came from cumulative **IP
   risk-score**, *not* a brute-force detector. The report's explicit warning: **rotate IPs
   next round → reputation never accumulates → the spray gets through.** We need an
   **IP-independent** signal.
3. **This is behavioural, not content.** Each `{"otp_code":"000090"}` is individually
   benign — the AI content-detector flagging it is a *content* false positive. Brute force
   is a property of the *aggregate*, so it needs a **stateful detector**, exactly what the
   owner directive calls for. (Report §5.E lists the anti-patterns we must avoid: pure per-IP
   rate-limit, content/AI on the code, IP reputation.)

**Boundary check:** we *count guess velocity per identity/code*; we never verify or consume
the OTP or `login_token`. Count-only → stays WAF-side of [[project_waf_vs_gateway_boundary]].

Secondary root cause: `is_auth_path` being compiled-in means operators can't add their own
OTP route (`/challenge/verify`, `/api/2fa/verify`, …) without a rebuild.

---

## 2. Requirements

1. `/otp` + common second-factor verify routes are recognised as an auth surface.
2. **Axis B — per-code spray (PRIMARY, IP-independent):** count **distinct `login_token`s
   (identities) submitting the *same* `otp_code`** within the window; fire above a
   threshold (**20**). This is the characteristic spray signature from the evidence and
   survives IP rotation. **FP-safe by construction** — random 6-digit OTPs do not collide
   across many distinct legit sessions in a 60 s window; `000090`×458 is not chance. (Raw
   data peaked at 44/60 s, so 20 keeps ~2× margin — owner asked to widen the FP buffer.)
3. **Axis A — per-token grind (SECONDARY):** count **distinct `otp_code` guesses per
   `login_token`**; fire above threshold **10** (owner call — doubled from 5 to widen the
   FP buffer). Catches sustained per-session grinding. Tradeoff accepted: the sole grind
   case in the Round-2 data tried only 6 codes, so Axis A will **not** trip on that
   specific sample — but that shape is single-source and still covered by the per-IP axis
   and cumulative IP-risk, and grinding is the minor axis (1/465 events). Axis B carries the
   detection.
4. **Per-IP axis** stays live on OTP paths (fast single-source catch, e.g. this round's
   1-IP campaign) — reuses the existing axis once `/otp` is in the allowlist. No threshold
   change.
5. Never key the per-session identity on `otp_code` (that's the guess). Axis B keys the
   *cluster* on the code and counts identities; Axis A keys on the identity and counts
   codes. Two separate extractors.
6. Emit distinct signal tags (`brute_force_otp_spray`, `brute_force_otp`) with audit fields
   that never contain the plaintext code; feed the normal additive risk pipeline.
7. **No new config** (owner directive — config surface is already large). Thresholds and the
   OTP path list are **hardcoded constants**, exactly like the existing per-user
   (`user_threshold = 5`) and per-device (`device_threshold = 10`) axes. The OTP axes are
   gated by the existing `brute_force.enabled` toggle — nothing new in YAML.
8. Both new axes participate in `count_scope: fleet` via the **existing** `fleet_check`
   seam and the already-installed backend — critical because IP rotation usually pairs with
   hitting multiple nodes. No reload-helper change needed: `count_scope` already flows
   through `apply_cfg_change_to_brute_force`, and there are no new knobs to hot-apply.

**Out of scope (note, don't build):**
- Failure-aware (401-counting) — needs the response-outcome channel wired into the detector;
  observability-only today ([[project_egress_observability_track]]). Deferred. *(Note: for
  spray/grind the attempt-count axes already fire pre-response, so this is an enhancement,
  not a gap.)*
- Token/OTP validation or invalidation (gateway/app concern — report §5.A/F).
- Tiered CAPTCHA response (report §5.D) — the WAF emits a score; challenge-vs-block is the
  existing risk-pipeline decision, not new code here.

---

## 3. Design

### 3.0 Why Axes A + B are complete (the invariant argument)

To brute an OTP the attacker must hold **one** dimension fixed — that's what makes it an
attack rather than a lottery:

- **Fix the code, vary the token** → *spraying* (bet an account has code X). **Axis B** keys
  on the code, counts distinct tokens.
- **Fix the token, vary the code** → *grinding* one live session. **Axis A** keys on the
  token, counts distinct codes.
- **Vary both** → no strategy; against a 10⁶ space with short-lived one-time tokens the
  success probability is ~0, and single-source volume still trips **per-IP**.

They can rotate IP and even their TLS fingerprint (JA4-light is coarse and attacker-
controlled — §3.8), but **code-reuse is the one thing they cannot drop without giving up the
attack.**
Axes A/B key on exactly those two invariants, which is why this pairing is complete by
construction, not merely fitted to the Round-2 sample. It is also why we do **not** anchor
the primary defence on IP or device fingerprint (report §5.E anti-patterns).

### 3.1 Path classification
Add `is_otp_path(path, extra)` beside `is_auth_path`, same matching rules (trailing-slash
trim, ASCII-lowercase, exact `matches!` over built-ins **+ operator entries**). Built-ins:
```
/otp /api/otp /verify-otp /otp/verify /2fa /2fa/verify /api/2fa/verify
/mfa /mfa/verify /verify /challenge/verify /api/auth/verify /totp /api/totp
```
Exact-path only (no substring) — substring on an additive-score gate risks FPs on business
routes like `/verify-email`. `inspect` runs when a request hits an auth **or** OTP path with
the existing credential-method/header gate.

### 3.2 Axis B — per-code spray counter (the centrepiece)
State: `otp_code_state: Mutex<HashMap<CodeHash, Vec<(IdentityHash, Instant)>>>`.
- Key = hash of the submitted `otp_code`. Value = distinct submitting identities in window.
- **Identity** = `login_token` (body) → else `sid`/`session` cookie → else `Bearer` token.
- On each `/otp` request: extract `(code, identity)`; if identity is **newly distinct** for
  that code, push. Fire when `distinct_identities(code) > OTP_SPRAY_THRESHOLD` (const **20**).
- **IP is never consulted** → immune to IP rotation, which is the whole point.
- Dedup by identity so one token retrying the same code doesn't inflate.
- Cap the per-code vec at `threshold * 2`; bound the map like the other per-key maps.
- **Fleet:** on a locally-new distinct identity, `fleet_check("otp_spray", code_hash,
  newly_distinct, otp_spray_threshold)` — reuses the existing shared-counter seam
  (bucket/TTL/fail-safe/cache) verbatim. Converges a spray load-balanced across nodes.

**FP analysis (the load-bearing argument):** legit OTP codes are uniformly random over
10⁶. The chance that >10 *distinct* legit sessions submit the *identical* code inside one
60 s window is ~negligible. The only way Axis B fires is a deliberate fixed-code spray (or
an app bug issuing duplicate OTPs — which we *should* surface). → zero practical FP.

### 3.3 Axis A — per-token grind counter
State: `otp_token_state: Mutex<HashMap<IdentityHash, Vec<(CodeHash, Instant)>>>`.
- Count **distinct codes** per identity; fire above `OTP_GRIND_THRESHOLD` (const **10**).
- Store hashed codes only (don't retain OTP secrets in detector memory).
- Fleet via `fleet_check("otp_grind", identity, …)`.
- FP: legit = 1–2 codes per token; threshold 5 is unreachable by legit use.

### 3.4 Per-IP axis
Already fires once `/otp` is path-recognised (verify with a test). Note: this round's
0.4 req/s single-IP spray = ~24/min > the 10/60s default, so per-IP *would* have caught it
had `/otp` been in the allowlist — but Axis B is what holds under IP rotation. No threshold
change (lowering it would FP on shared egress — violates the directive).

### 3.5 Signals
```
Axis B: Signal { score: OTP_SCORE /*40*/, tag: "brute_force_otp_spray",
                 field: format!("otp_spray:code_hash={}", short_hash) }   // never plaintext
Axis A: Signal { score: OTP_SCORE /*40*/, tag: "brute_force_otp",
                 field: format!("otp:id={}", identity_prefix) }
```
Both OTP axes emit **score 40** (owner call) — deliberately just below the standard
`brute_force::DEFAULT` (50), so an OTP hit compounds with any other signal / cumulative
IP-risk to reach the block threshold rather than blocking on a single request. Honours
"detect the risk, don't trade off FP": the score contributes confidently but the block
decision stays with the risk pipeline until field-proven.

### 3.6 Config — **none** (owner directive)
No new YAML. Thresholds + the OTP path list are module constants, mirroring the existing
axes:
```rust
const OTP_SPRAY_THRESHOLD: u32 = 20;   // Axis B: distinct tokens per identical code / window
const OTP_GRIND_THRESHOLD: u32 = 10;   // Axis A: distinct codes per token / window
const OTP_SCORE: u32 = 40;             // both OTP axes (below brute_force::DEFAULT=50)
// is_otp_path(): built-in exact-path list (§3.1), same shape as is_auth_path()
```
The OTP axes are gated by the existing `brute_force.enabled` toggle and ride the existing
`count_scope` for fleet. `BruteForceToggle` is untouched. This matches how `user_threshold`
/ `device_threshold` are already hardcoded — one consistent story, zero config growth.

### 3.7 Wiring
- **No change** to `run.rs` beyond what exists (`set_count_scope` already applied), and **no
  change** to `apply_cfg_change_to_brute_force` — `count_scope` already flows to the OTP
  fleet axes and there are no new knobs to hot-apply, so the apply-helper guard test needs
  no extension.
- Dashboard: `brute_force` already on the detector card; new tags surface in audit/live-feed
  automatically. No new page.

### 3.8 JA4 / device-fingerprint — recommendation: **enrichment only, NOT a trigger**

Investigated the current approach (`listener/tls.rs::compute_post_handshake_fingerprint`):

- It is **"JA4-light", not canonical JA4.** rustls 0.23 doesn't expose the ClientHello
  extension list post-handshake, so the fingerprint is built from only
  `negotiated_cipher + ALPN + TLS version + SNI-type` (format `t{ver}{sni}_{cipher}_{alpn}`).
  Its own doc comment: *"coarser than canonical JA4… stable enough to distinguish client
  classes (Chrome vs curl vs sqlmap)."* Canonical JA4 capture is an unwired stub
  (`plans/future/unwired-stubs-catalog.md § "JA4 capture"`).
- `device_fp = hash(JA4-light + User-Agent)`; present only on the TLS path (plaintext → None).

**Why not a JA4-keyed OTP axis** (argument from the *algorithm*, not the old logs — see note):
JA4-light is **low-cardinality by construction** — the brute-force device axis keys on the
raw `ja4` string, whose only inputs are `cipher + ALPN + version + SNI-type`. TLS 1.3
narrows that to a handful of values (≈3 common ciphers × h2/http1.1 × …), so it groups by
client *class*, not per-attacker (its own doc comment: "distinguishes Chrome vs curl vs
sqlmap"). A "distinct tokens/IPs per fingerprint" OTP axis would therefore sweep many
legitimate users who share one TLS class into a single bucket on a busy login/OTP endpoint →
**false positives**, violating the "no FP trade-off" directive. It's also the *easiest*
dimension for an attacker to vary, and it's **redundant** — Axis B already catches the spray
on the one invariant the attacker cannot drop (code reuse), so JA4 adds no coverage at real
FP cost.

> **Note on the data:** the Round-2 logs showed only 2 distinct `device_fp`, but those were
> produced by an **older, simpler fingerprinting** implementation — *not* current JA4-light —
> so they do **not** quantify JA4-light's real cardinality. The argument above stands on the
> JA4-light algorithm's inputs, independent of that sample.

**What JA4 IS good for here (zero FP):** carry the JA4-light fingerprint in the OTP-spray
signal's audit field (the AttacksAggregator already keys `fp:<ja4>`), so once Axis B has
*already* flagged a spray, ops can corroborate "all N came from one TLS fingerprint" and
pivot on it. Display/attribution only — never a trigger.

**Recommendation:** (1) do **not** add a JA4-based OTP axis; (2) add JA4-light to the spray
signal's audit metadata for attribution; (3) leave the existing per-device axis as-is but
**note** it will begin running on `/otp` once the path is allowlisted — given JA4-light's
coarseness, treat its OTP firings as low-confidence corroboration, not a standalone block
reason (Axis B is the trustworthy signal). Canonical-JA4 capture stays a separate, deferred
project and is **not** a prerequisite for this feature.

---

## 4. Phases

> **Progress:** P1 ✅ · P2 ✅ · P3 ✅ (all in `crates/aegis-security/src/detectors/brute_force.rs`;
> docs in `docs/security/detectors/brute-force.md` + dashboard tooltip). 41 brute_force unit
> tests, full workspace green.

### BF-OTP-P1 — path coverage + Axis B (spray) + Axis A (grind)  ← the whole feature
`is_otp_path` + built-ins; `extract_otp_identity` + code extraction (JSON/form/cookie/
bearer); both state maps with dedup, hashing, caps; hardcoded thresholds; two signals;
per-IP verified live on `/otp`. **Closes the evidenced gap** (Axis B stops the IP-rotating
spray; Axis A the grind). Full FP-guard test matrix (§5).

### BF-OTP-P2 — fleet aggregation for both OTP axes
Route Axis A/B through the existing `fleet_check` seam (`count_scope` already flows). Clone
the three existing fleet tests (converge across two nodes; fail-safe to per-node on backend
error; `per_node` default never touches backend). **High priority given the IP-rotation
threat** — rotation commonly spans nodes.

### BF-OTP-P3 — docs
Detector docs/cheatsheet (rules-page doc guard may require coverage —
[[project_rules_page_gaps_plan]]). Note the failure-aware (401) upgrade as deferred.

---

## 5. Test matrix (FP-safety is a first-class assertion)

**Detection (risk cases fire):**
- Axis B: 21 distinct `login_token`s submit the same `000090` → `brute_force_otp_spray`
  (> 20).
- Axis B is IP-independent: same 21 tokens across 21 *different* IPs still fires.
- Axis A: one token submits 11 distinct codes → `brute_force_otp` (> 10).
- Per-IP still fires on `/otp` at its own threshold.
- Fleet: spray split 11+10 across two nodes converges > 20.

**False-positive guards (must NOT fire — the directive):**
- 50 distinct tokens each submit a *distinct random* code → **no signal** (Axis B only
  clusters identical codes).
- One token submits the same code twice (flaky client) → **no Axis A** (distinct-code dedup).
- One IP legitimately proxies many users, each 1 correct OTP → **no Axis B** (distinct codes),
  per-IP within threshold.
- Non-OTP path (`/verify-email`, `/api/profile`) → **no signal**.
- `otp_code` carrying SQLi/XSS → handled by content detectors, **not** double-counted as
  brute force (still keyed by its hash; won't cluster unless repeated across tokens).

**Hygiene:** signal fields never contain plaintext `otp_code`; identity extractor never
returns the code; per_node default makes zero backend calls.

---

## 6. Risks

| Risk | Sev | Mitigation |
|---|---|---|
| Axis B FP on legit code collision | LOW | random 10⁶ space; threshold 10 distinct tokens/code/window is unreachable by chance (see §3.2) |
| Axis A FP on retry/typo | LOW | distinct-code dedup + threshold 5 |
| Keying per-session identity on the guess → never fires | HIGH-if-wrong | explicit `never_keys_on_otp_code` test; identity vs code are separate extractors |
| Substring path match over-fires | MED | exact-path `matches!` only |
| Retaining OTP plaintext in memory | MED | hash codes; truncate audit fields |
| IP-rotation still evades if fleet off | MED | Axis B is IP-independent per-node already; P3 adds cross-node convergence |
| Reload helper not extended → node-local | MED | extend apply-helper guard test |
| Lowering per-IP threshold to "help" → shared-egress FP | avoided | explicitly NOT doing this (directive) |

---

## 7. Complexity
**MEDIUM.** Axis A/B mirror the existing user/device axes almost line-for-line; Axis B is
the same "distinct-X per key" shape, just (code→identities) instead of (user→IPs). Fleet is
pure reuse. Bulk is config + tests. Rough: P1 ~1 day, P2 ~½ day, P3 ~3 h, P4 ~2 h.

---

## 8. Decisions — RESOLVED (owner, 2026-07-06)

1. **Axis B spray threshold = 20.** (Doubled from 10 to widen the FP buffer. Raw data
   peaked at 44/60 s, so 20 fires with ~2× margin.)
2. **Axis A grind threshold = 10.** (Doubled from 5. Tradeoff noted §2.3 — won't trip the
   6-code Round-2 sample; per-IP + cumulative risk cover single-source grinding.)
3. **OTP score = 40** for both axes (below `brute_force::DEFAULT` 50; compounds via risk
   pipeline, no single-request auto-block).
4. **No new config.** `auth_paths` and OTP paths stay system-controlled hardcoded lists.
5. **No JA4 OTP axis** — JA4-light is enrichment-only (§3.8): coarse by algorithm and
   attacker-controlled, so it would trade off FP. Add it to the spray signal's audit field
   for attribution only.

No open questions. Ready to implement **BF-OTP-P1** on owner's go.
