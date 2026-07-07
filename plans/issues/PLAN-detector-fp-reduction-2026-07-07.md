# PLAN — Content-detector false-positive reduction (S/L-Tester 2026-07-07)

> **Type:** PLAN (detector FP-reduction) · **Status:** 🟡 Phase 1 SHIPPED (unmerged) · drafted 2026-07-07
>
> **Progress (2026-07-07):** **Phase 1 complete & green** on the working tree (`cargo test -p aegis-security --lib` = 2167 pass; workspace green modulo the known macOS FSEvents supervisor flake, verified pre-existing on clean baseline). Shipped surgical tightenings: **XS-1** (numeric-entity narrowed to angle-brackets only — full removal would have dropped the double-URL-encoded entity-XSS catch, since `normalize_for_detection` does not compose url→entity decode), **XS-2** (`Function(` case-sensitive), **XS-3** (`\balert(`/`\bprompt(`/`\bconfirm(`/`\beval(` boundary+no-space), **MA-1** (credential/token key-NAMES dropped from body/form surface), **MA-2** (`owner`/`system`/`sa` dropped from escalating role values), **SQ-1** (bounded `'[^']{0,32}--` + bounded non-greedy `/\*.{0,64}?\*/`), **CI-2** (brace-expansion requires an inner path/space), **CI-3** (`$IFS` non-identifier boundary, lookahead-free two-alternative form). Each has RED-then-GREEN negative fixtures; stale positives converted with rationale. **Phase 2 (SQ-2 tiering, CI-1 CMD tiering) and Phase 3 not started.** See §7 for a higher-leverage structural finding surfaced by the second report.
> **Track ID prefixes:** `MA-<n>` (mass-assignment) · `SQ-<n>` (sqli) · `CI-<n>` (command-injection) · `XS-<n>` (xss)
> **Source:** S-Tester benign-FP counts (below) + L-Tester `tests/l-tester/reports/2026-07-07/20260707_133556_legitimate_report.md` (692 real-site captures, ~1.04M requests).
> **Sibling / prior art:** [`archived/PLAN-detector-gaps-serious-2026-07-06.md`](./archived/PLAN-detector-gaps-serious-2026-07-06.md), [`archived/PLAN-cmdi-recall-2026-07-06.md`](./archived/PLAN-cmdi-recall-2026-07-06.md). This plan runs the **opposite** direction (tighten, not broaden) and must not undo those recall wins.

**Objective:** cut benign blocks on the four heaviest FP detectors — **mass-assignment, sqli, command-injection, xss** — with **zero or minimal true-positive loss**. Every change here is either (a) a surgical regex tightening whose dropped matches are provably re-caught by a stronger sibling pattern, or (b) a scoring/corroboration change that keeps unambiguous exploit signatures at block tier while demoting bare single-token noise.

---

## 0. Root cause (shared across all four)

Each of these detectors emits a **single block-tier score on the first pattern match and returns** — no corroboration, no tiering:

| Detector | Score const | File | Effect |
|---|---|---|---|
| sqli | `SQLI = 70` (`scores.rs:72`) | `sqli.rs` | one regex hit → block on `high`(60)/`medium`(70) tiers |
| xss | `XSS = 70` (`scores.rs:76`) | `xss.rs` | one hit → block |
| command-injection | `BASELINE = 70` (`scores.rs:140`) | `command_injection.rs` | one hit → block |
| mass-assignment | `MASS_ASSIGNMENT = 60` (`scores.rs:108`) | `body_abuse.rs` | one hit → block on `critical`(50)/`high`(60) |

So **a single over-broad substring match on benign traffic is an outright block.** The FP counts are dominated by a small number of patterns that match ordinary e-commerce/SaaS payloads: function-name tokens (`concat(`, `char(`, `sleep(`), English command words in facet lists (`filter=running|training`), credential field *names* echoed in write bodies (`access_token`), bare HTML numeric entities (`&#39;`), and case-insensitive `Function(`.

> **Note on severity framing.** The L-Tester report already rates overall FP at **0.56%** and every rule `<2%`. This is not a fire — it is a polish pass. But each FP is an *outright block of a real user's request*, and mass-assignment alone accounts for ~1,100–1,318 of them. The wins below are cheap and low-risk, so they are worth shipping. Do **not** trade recall for these.

### S-Tester benign-FP counts (context)
```
mass-assignment 1,104 · sqli 659 · xss 447 · command-injection 311 · ssrf 300
template-injection 278 · ai 272 · jwt-alg-none 208 · jwt-time-forged 152
path-traversal 109 · load-shed 101 · recon-path 100
```
This plan addresses the top 4 (mass-assignment, sqli, command-injection, xss). ssrf/template-injection/ai and the jwt/recon classes are **out of scope here** — flag for a follow-up if the top-4 fixes don't move the aggregate enough.

---

## Phasing

- **Phase 1 — Surgical, zero/near-zero recall-loss regex tightenings.** MA-1/MA-2, SQ-1, CI-2/CI-3, XS-1/XS-2/XS-3. Independent one-file edits, each with an added negative fixture and no positive-test breakage (except where explicitly noted). Ship first, measure.
- **Phase 2 — Structural corroboration/tiering.** SQ-2, CI-1. These change the "first-match-wins single score" model into HIGH-confidence-vs-ambiguous tiers with metachar/2-hit corroboration. Larger, one owner-decision each (a positive test breaks). Ship after Phase 1 is measured.
- **Phase 3 — Optional / targeted.** MA-3, SQ-3 (YQL endpoint scope), CI-4, XS-4/XS-5. Do only if the corpus still shows the class after Phases 1–2.

---

## 1. Mass-assignment — `crates/aegis-security/src/detectors/body_abuse.rs`  (~1,104 FP, the #1 source)

Detection already splits into three JSON matchers (FLAG needs truthy value, ROLE needs escalating value, NAME is **key-name-only**). The NAME matcher is the remaining FP surface; FLAG/ROLE have small residual leaks.

### MA-1 · Strip credential/token key-names from the body NAME set · **S** · Phase 1 · START HERE
**The single biggest mass-assignment FP win.** `MASS_ASSIGN_NAME_JSON` (`body_abuse.rs:141`, key list at `L118`/`L120`) fires on the *key name alone* for `access_token, accessToken, refresh_token, refreshToken, api_key, apiKey, api_token, apiToken`. Legit clients POST/PUT these to their own backends constantly (OAuth refresh, SDK/session bootstrap) — this is the driver behind instagram/semrush/sephora. The code's **own comment** (`body_abuse.rs:68-79`) already made exactly this argument to remove them from the *query* surface (`s1_query_access_token` clean, `L999`); extend the same logic to the body/form NAME set.

- **Change:** remove the token/credential keys (`L118` `api_key|apiKey|api_token|apiToken`, `L120` `access_token|accessToken|refresh_token|refreshToken`) from the JSON/form NAME matcher. **Keep** `password_hash|passwordHash` (rarely a benign write body) and `permissions|privileges|grants` (real mass-assignment surface).
- **Rationale:** a stolen-token-in-write-body is an authz/gateway concern, not classic mass-assignment; the value here is near-zero and the FP is high.
- **Recall cost:** negligible.
- **Tests:** flip `ma_access_token` (`L658`), `ma_refresh_token` (`L659`), `ma_api_key` (`L656`), and any `s1_body_*`/`s1_form_body_api_key_*` positives to `ma_clean_*` negatives. Add `ma_clean_access_token_body`, `ma_clean_refresh_token_put_body`.

### MA-2 · Drop `owner`, `system`, `sa` from ROLE escalation values · **S** · Phase 1
`MASS_ASSIGN_ROLE_VALUES` (`body_abuse.rs:109`) treats `owner` and `system` as privilege-escalation. But `{"role":"owner"}` is the standard doc/workspace owner role and `{"role":"system"}`/`{"role":"user"}` is the ubiquitous LLM/chat-message shape → wetransfer/office-clipchamp/roughtrade + any AI feature.

- **Change:** remove `owner`, `system`, `sa` from `MASS_ASSIGN_ROLE_VALUES`. Keep `administrator|superadmin|super_admin|superuser|sysadmin|admin|root` — these still cover privilege escalation.
- **Recall cost:** low. Add negatives `ma_clean_role_owner`, `ma_clean_role_system`, `ma_clean_role_user`.

### MA-3 · Require key+value combo for `verified`/`email_verified` · **S** · Phase 3 (optional)
FLAG matcher (`L98-102`) fires on `verified:true`/`email_verified:true`. A profile object echoing `"verified":true` (verified-badge shape) is benign. Either drop `verified`/`email_verified` from FLAG or require a corroborating privilege key in the same body. Do only if MA-1/MA-2 leave a residual.

**MA acceptance:** the L-Tester benign sites (browsing_office_powerpoint, semrush, sephora, wetransfer, roughtrade, instagram) drop toward zero mass-assignment fires; the mass-assignment positive suite (`admin:true`, `role:admin`, `is_admin:true`, `permissions:["*"]`) stays green.

---

## 2. sqli — `crates/aegis-security/src/detectors/sqli.rs`  (~659 FP)

`check_patterns` (`sqli.rs:108-119`) loops `Vec<Regex>` and **returns after the first match** → exactly one 70 signal, no corroboration. Two greedy regexes and a cluster of function-name-only patterns are the culprits, plus the YQL-by-design endpoint.

### SQ-1 · Bound the two greedy/unbounded regexes · **S** · Phase 1 · START HERE (pure FP win, no recall loss)
- `sqli.rs:29` `'[^']*--` → `'[^']{0,32}--`. Real breakout comments (`admin'--`, `' OR 1=1--`) are short; the unbounded span matches an apostrophe early in a JSON body and a `--` far later.
- `sqli.rs:30` `/\*.*\*/` (greedy C-comment) → `/\*.{0,64}?\*/` (bounded, non-greedy), or demote to the ambiguous tier (SQ-2). Bare C-comments collide with embedded CSS/JS/analytics.
- **Recall cost:** ≈0 — real tautology/stacked-comment payloads still match; add negatives with a long JSON body containing a stray `'` … `--` and a CSS `/* … */` blob.

### SQ-2 · Tier patterns + require corroboration · **M** · Phase 2 (the real fix)
Split `SQLI_PATTERNS` into HIGH-confidence (keep score 70, single-hit block) and AMBIGUOUS (lower score ~30–35, block only on corroboration):

- **HIGH (keep 70):** `UNION…SELECT` (L12), `DROP TABLE` (L17), `ALTER TABLE` (L18), `';DROP|DELETE|…` (L22), quoted tautology `'…OR'…'='` (L21), `WAITFOR DELAY` (L31), `LOAD_FILE` (L34), `INTO OUT/DUMPFILE` (L35), `xp_cmdshell` (L37), `information_schema` (L38), `EXTRACTVALUE`/`UPDATEXML` (L50-51).
- **AMBIGUOUS (→ ~30-35):** `SELECT.+FROM` (L13), `UPDATE.+SET` (L15), `INSERT INTO` (L14), `DELETE FROM` (L16), `OR 1=1`/`AND 1=1` (L19-20), `BENCHMARK(`/`SLEEP(` (L32-33), `EXEC ` (L36), `CHAR(n)` (L45), `CONCAT(` (L46), `ORDER BY n` (L48), `CASE WHEN` (L49), `GROUP BY…HAVING` (L47), `/*…*/` (L30 from SQ-1).
- **Block rule:** a block requires **a HIGH hit**, OR **two AMBIGUOUS hits**, OR **one AMBIGUOUS hit + an injection metacharacter** (`'`, `"`, `)`, `;`, `--`, `/*`) in the same inspected field. Benign standalone `concat(`/`sleep(`/`char(65)`/`order by 1` stop blocking; `';SLEEP(5)--` / `1) UNION SELECT` still block.
- **Structural:** requires changing the return-after-first-match at `sqli.rs:116` to accumulate. **Keep the `Vec<Regex>` loop** — the LT-P2 `#[ignore]` RegexSet guard (`sqli.rs:398-476`) established RegexSet is slower; do not switch. See [[project_regexset_slower_than_vec]].
- **Tests:** add negatives `sqli_clean_concat_body`, `sqli_clean_char65`, `sqli_clean_order_by_1`, `sqli_clean_sleep_analytics`; assert the existing `sqli_sleep`/`sqli_char_func`/`sqli_concat` positives are re-shaped to carry a metachar (`/?id=1';SLEEP(5)--`) so they still block, OR consciously accept demotion — **owner decision** (these three current positives are bare-token and will stop single-hit blocking).

### SQ-3 · Endpoint scope for YQL-by-design surfaces · **M** · Phase 3 (optional, brittle)
`/v2/public/yql` accepts Yahoo Query Language — literally `SELECT … FROM … ORDER BY n` — so lines 13 & 48 fire on legitimate traffic that no regex tightening can fix. If the corpus still shows it after SQ-2, add a narrow path-scoped downgrade for the exact YQL path (not a broad allowlist — weigh bypass risk). Prefer leaving `/graphql` fully scanned (SQ-2 already clears its `concat(`/`char(` noise).

**SQ acceptance:** onedrive_al/canva/virginatlantic/instagram sqli fires drop sharply; the unambiguous SQLi positive suite stays green; `/graphql` benign bodies clean.

---

## 3. command-injection — `crates/aegis-security/src/detectors/command_injection.rs`  (~311 FP)

Grounded against the repo's own `tests/security/regex_dataset/fp_candidates.ndjson` (15k cmdi candidates): the metachar-adjacency contract from the 2026-05-22 ARG-boundary fix **holds** for synthetic data, but **real retail/travel facet vocabulary** surfaces the driver — English command words in pipe/`;`-delimited option lists. Preserve the ~75% recall win from the cmdi-recall plan; do not touch the standalone high-value literals.

### CI-1 · Tier the CMD alternation (HIGH_SIGNAL bare, AMBIGUOUS needs an arg) · **M** · Phase 2 (biggest win)
`CMD` alternation at `command_injection.rs:91` mixes true exec tokens with English/param words (`id, ls, cat, rm, mv, sh, more, less, head, tail, tr, tee, dd, env, type, dir, net, reg, ver, sleep, timeout, ping, python, perl, ruby, php`). These are exactly the facet/sort vocabulary of e-commerce APIs (`filter=running|training`, `sort=price|asc|dir`, `nav=home|cat|sale`) → nike/kohl's/skyscanner.

- **Change:** split `CMD` into:
  - **HIGH_SIGNAL** (non-English exec-only: `whoami, uname, nc, ncat, netcat, curl, wget, bash, zsh, ksh, dash, powershell, nslookup, chmod, chown, mkfifo, systeminfo, tasklist, ipconfig, ifconfig, findstr, certutil, netstat, hostname, base64, xxd`) — keep current behavior: fire on bare metachar adjacency (`|whoami`, `&&systeminfo`).
  - **AMBIGUOUS** (the English-word subset) — in the pipe/semi/chain patterns (`L116-118`) require a real shell-arg tail after the token: a flag/path/arg (`\s+[-/\w]`), a further chain (`[;|&]`), or `$IFS`. Keeps `;rm -rf`, `;type C:\…`, `;sleep 5`, `|cat /etc/passwd`; drops arg-less data segments `…|id`, `…|cat|…`, `…|dir`.
- **Recall cost:** only bare arg-less `|id`/`|ls`/`|dir` with no chain. **One positive test breaks:** `cmdi_pipe_dir` (`/run?p=x|dir`, `L398`) — owner either accepts the trade (recon intent is still covered by retained `ipconfig`/`systeminfo`/`whoami`) or re-anchors it to `|dir /s`.

### CI-2 · Tighten `brace_exp` to require a path/space inside braces · **S** · Phase 1 (free GraphQL fix)
`brace_exp` (`L157`) fires on `{"query":"{ping,latency,id}"}` / `{ls,name}` (minified GraphQL / JS object literals). Real brace-expansion payloads target paths/URLs.
- **Change:** require a `/` or whitespace inside the braces: `\{cmd,[^}]*[/\s][^}]*\}`. `{cat,/etc/passwd}` / `{curl,http://evil/x}` still fire; GraphQL `{ls,name}` / `{ping,latency}` stop. **Recall cost:** ≈0.

### CI-3 · Add trailing boundary to `$IFS` · **XS** · Phase 1 (trivial)
`ifs` (`L146`) `\$\{?IFS\}?` prefix-matches `$IFSomething`. Add a trailing non-alpha boundary: `\$\{?IFS\}?(?![A-Za-z])`. No recall cost.

### CI-4 · Require arg for AMBIGUOUS tokens inside `$(…)`/backticks · **M** · Phase 3 (optional, partial)
`subshell_dollar`/`subshell_backtick` (`L114-115`) fire on doc-prose `` `id` `` / `$(cat)` in JSON/text bodies (the 1,139-hit backtick-markdown category). Gating is **partial** — the classic positives `cmdi_subshell_arg = $(id)` (`L362`) and `cmdi_backtick = `whoami`` (`L366`) rely on bare tokens, so `whoami`/`id` must stay bare-eligible; only the broader English subset can require an arg. Lower priority (hits `/api/docs`, not retail). Do only if the backtick class shows in the corpus.

> **Do NOT touch:** `/bin/sh` (L123), `cat /etc/passwd` (L125), `sh -c` (L135), `powershell -enc` (L137), `child_process`/`execSync` (L169-170), Log4Shell `${jndi…}` (L52-64), ThinkPHP `invokefunction` (L76-77). Zero observed FP, high recall value. Leave `__proto__`/`constructor.constructor` (L172-173) as-is (SG-3 recall) — watch-list only.

**CI acceptance:** nike/kohl's/lowe_s/skyscanner cmdi fires drop; the cmdi positive suite stays green except the owner-adjudicated `cmdi_pipe_dir`; `fp_candidates.ndjson` cmdi fire count trends down.

---

## 4. xss — `crates/aegis-security/src/detectors/xss.rs`  (~447 FP)

Prior FP-reduction ("exec-sink gating") gated `javascript:` (L20), `on…=` handlers (L28), and `<svg>/<img>` (L34-35) — **do not regress those three.** The remaining FP surface is bare JS-call tokens and bare structural tags that were never given a context requirement. Ranks 1–3 mirror the existing S6 unicode-escape / cookie-drop precedent.

### XS-1 · Drop the bare numeric-entity pattern · **S** · Phase 1 · START HERE (highest FP kill, ≈0 loss)
`xss.rs:39` `(?i)&#x?[0-9a-f]+;` fires on every benign numeric HTML entity — `&#39;` (apostrophe), `&#169;`, `&#8217;`, `&#160;` — pervasive in product descriptions / localized fare rules / analytics blobs on alibaba/virginatlantic/target. **Real** entity-encoded XSS (`&#x3c;script`) is already caught: `normalize_for_detection` runs HTML-entity decode, then `<script[\s>]` (L12) matches. Verified against `xss_entity_numeric_decimal/hex` (existing positives pass via the decode path, not via L39).
- **Change:** delete the L39 pattern. **Recall cost:** ≈0.

### XS-2 · Fix `Function(` case-sensitivity · **S** · Phase 1
`xss.rs:48` `(?i)Function\s*\(` is case-insensitive → matches benign lowercase `function(` in any embedded JS/GraphQL/serialized payload.
- **Change:** require the constructor form `\bnew\s+Function\s*\(`, or at minimum drop `(?i)` so only capital-F `Function(` matches. **Recall cost:** negligible (constructor abuse is `new Function`/capital-F).

### XS-3 · Anchor the English-word call patterns · **S** · Phase 1
`alert(` (L40), `prompt(` (L41), `confirm(` (L42), `eval(` (L45) use `\s*(` and no `\b` → match `Confirm (your order)`, `retrieval(`, `medieval(`.
- **Change:** `\balert\(`, `\bprompt\(`, `\bconfirm\(`, `\beval\(` (word-boundary, drop `\s*`). XSS payloads are `alert(1)` (no space, token boundary); benign English copy has a space or no boundary. **Recall cost:** ≈0.

### XS-4 · Co-occurrence gate for bare DOM/JS tokens · **M** · Phase 3 (optional)
`window.` (L44), `document.(cookie|write|…)` (L43), `setTimeout(`/`setInterval(` (L46-47), `.innerHTML=`/`.outerHTML=` (L49-50), `fromCharCode(` (L51) are only XSS-dangerous alongside a markup/scheme sink. Gate them behind "input also contains a tag-open `<[a-z]` or `javascript:`/`data:text/html`." Medium FP kill, small loss on pure-JS-context injection (largely already covered by tag patterns). Do only if 1–3 leave a residual.

### XS-5 · Scope the bare structural tags · **S** · Phase 3 (optional)
Bare `<iframe`/`<object`/`<embed`/`<form` (L29-33) fire on rich product HTML (embedded maps/video, benign forms). Minimum: drop `<form` (CSRF/phishing surface, not XSS). Optionally require `<iframe|<object|<embed` to carry a dangerous attribute (`src=`/`srcdoc=`/`onerror=`).

> **Leave alone:** the three exec-sink-gated patterns (L20/L28/L34-35), the `<script` tag patterns (L12-13), and `CSS_PATTERNS` (L71-90) — structurally tight, not FP culprits.

**XS acceptance:** alibaba/virginatlantic/target/delta xss fires drop; the xss positive suite (`<script>alert(1)`, entity-encoded `<script`, `<img onerror=`, `javascript:alert`) stays green.

---

## 5. Validation & discipline (all tracks)

- **TDD, zero-FP:** for every change add the negative fixture(s) named above **first** (RED = current over-block), then make the edit (GREEN), and confirm no existing *positive* regresses except the two explicitly owner-adjudicated ones (`cmdi_pipe_dir`, the three bare-token sqli positives under SQ-2).
- **Raw-form truth:** validate with Rust unit tests on **raw percent-encoded** forms — the l-tester python harness double-decodes; recon/query FP reports over-state `%2F`-style artifacts. See [[project_ltester_decodes_dataplane_raw]].
- **Corpus regression:** re-run `tests/security/regex_dataset/fp_candidates.ndjson` before/after (cmdi especially) and the S/L-Tester benign datasets; record the fire-count delta per class in the PR.
- **Style:** `body_abuse.rs`, `command_injection.rs`, `sqli.rs`, `xss.rs` are large — hand-match surrounding style, do **not** `cargo fmt` whole files. See [[project_rustfmt_whole_crate_hazard]].
- **Workspace green baseline** must hold (`cargo test --workspace`). See [[feedback_test_suite_green_baseline]] — detector FP-reduction commits routinely make *older detection tests* stale; that is expected, confirm intent before "fixing" a detector back.

## 6. Non-goals / deferred
- ssrf (300), template-injection (278), ai (272), jwt-alg-none (208), jwt-time-forged (152), path-traversal (109), load-shed (101), recon-path (100) FP — **not in this plan.** Open a follow-up only if the top-4 fixes don't move the aggregate.
- Cross-detector corroboration engine (a shared multi-signal scorer) — SQ-2/CI-1 do per-detector tiering; a *global* corroboration layer is a bigger architecture change, explicitly out of scope.
- Lowering block scores below 60 — rejected; leaves noise in audit/cumulative-risk. Tighten the match instead.

---

## 7. Higher-leverage structural finding — from `_FP_ANALYSIS_SUMMARY.md` (2026-07-07)

A second L-Tester artifact (`tests/l-tester/reports/2026-07-07/_FP_ANALYSIS_SUMMARY.md`) groups all 18 FP
classes into **4 shared root causes** and makes a load-bearing point the per-detector regex work (§1–§4)
does **not** fully capture: **the single biggest FP driver is content detectors running on bodies that
are opaque telemetry / session-replay / binary, not parseable input.** That group alone is
**~2,700 / 5,822 FP (~46%)** — bigger than every regex fix in this plan combined.

### Group 1 — content detectors on opaque/telemetry/binary bodies (**~46% of all FP**) · **the priority**
Affects `sqli`, `command-injection`, `template-injection`, `css-injection`, part of `xss`. The bodies are
Akamai `sensor_data`, Tealeaf `TealeafTarget.jsp`, PerimeterX, `/collect`, `/v2/recording`, `/ajax/bnzai`,
`/_ajax/ae/createBatch`, plus real binary uploads (`%PDF`, `application/octet-stream`, high-entropy blobs).
The existing gates (`form_body_is_opaque_beacon`, `body_is_scannable`) catch the *single-dominant-blob*
sensor shape but miss: (a) **binary/opaque content types** the origin won't parse as text, and (b)
**multi-field replay/telemetry** bodies that aren't one dominant blob.

**Proposed track FP-G1 (shared, one change, biggest ROI):** strengthen the shared body gate in
`detectors/mod.rs` rather than any single detector —
- **G1-a · magic-byte / binary skip:** in `body_is_scannable` (or a pre-filter), skip bodies whose first
  bytes are a known binary magic (`%PDF`, `PK\x03\x04`, `\x89PNG`, `GIF8`, `\xFF\xD8\xFF`, gzip `\x1f\x8b`)
  or whose declared type is `application/octet-stream` / `image/*` / `application/pdf`. FP≈0, zero recall
  loss (real injection is not delivered as a PDF body the origin parses as SQL).
- **G1-b · generalise the beacon gate to multi-field high-entropy replay:** relax
  `form_body_is_opaque_beacon`'s single-dominant-blob requirement so a body that is *mostly* high-entropy
  base64/replay across several fields is also skipped. FP-sensitive — must keep the high-signal-shape
  fast-path (`has_high_signal_injection_shape`) so a padded real payload is still scanned.
- **G1-c (owner call) · endpoint (host,path) allowlist for known bot-defense/replay/analytics collectors.**
  Highest raw FP kill but the **security-sensitive** option — an allowlisted collector path becomes an
  inspection blind spot. Recommend NOT a blanket allowlist; prefer G1-a/G1-b (content-shaped, not
  identity-shaped) first, and only add a **narrow, per-(host,path)** allowlist if the corpus still shows a
  concentrated collector after G1-a/b. Whatever is skipped must `log()` so it isn't a silent blind spot.

### Group 3 — over-greedy JWT parser (**360 FP, only 2 sites**) · ✅ **SHIPPED (develop)**
`jwt-alg-none` (208) + `jwt-time-forged` (152) are almost entirely **one site each** (target, ulta):
base64 session/visitor cookies parsed as JWTs. Fix in `jwt_inspection.rs`: only treat a token as a JWT when
it is **3 dot-separated parts that base64-decode to JSON with a standard header (`alg`/`typ`) + claims**, and
only from `Authorization: Bearer` / cookies named `*token*`; skip static `.js/.css/.svg` and opaque base64
ids. This is a ~360-FP win concentrated in 2 sites — cheap, high-confidence, out of the top-4 but the best
FP-per-effort after Group 1.

### Group 2 — query "URL/`//`/`..`/JS-in-a-param" (`ssrf`, `open-redirect`, `path-traversal`, `header-injection`, part of `xss`)
Context/target scoping: SSRF/redirect only when the destination is an external non-allowlisted domain /
internal IP; traversal only on a real `../` path separator (not `..` inside an id); CRLF only when the value
reaches a response header; split null-byte `%00` into its own rule. Deferred — separate from the top-4.

### Group 4 — thresholds / business rules (`mass-assignment`, `nosql`, `method-override`, `body-*`, `ai`)
Route-scoped size/depth limits, system-key allowlist (`$type`), accept `X-HTTP-Method-Override`, tune the ML
threshold; several should **warn**, not block. MA-1/MA-2 (shipped) already cover the mass-assignment slice.

> **Reconciliation with §1–§4:** the per-detector regex tightenings (Phase 1 shipped, Phase 2 pending) remain
> valid and complementary — they clean the *query-string* and *parseable-body* FP that Group 1 gating does
> not touch (e.g. `/graphql` `concat(`, retail facet pipe-lists, benign entities in URIs). But **FP-G1-a/b is
> now the recommended next step over Phase 2**, because it removes ~46% of FP with near-zero recall risk in
> one shared change, whereas Phase 2 tiering is more invasive per detector and each breaks a positive test.

---

## Suggested ship order (updated 2026-07-07)
1. ✅ **Phase 1 batch — SHIPPED (develop `62fa91b2`):** MA-1, MA-2, SQ-1, CI-2, CI-3, XS-1, XS-2, XS-3.
2. ✅ **FP-G1-a + G1-b — SHIPPED (develop):** shared `body_is_opaque(headers, body)` in `detectors/mod.rs`
   = opaque/binary content-type skip (`content_type_is_opaque`: pdf/image/video/audio/font/octet-stream/
   protobuf/grpc/zip/wasm) **+** whole-body high-entropy skip (`body_is_high_entropy`: ≥512 bytes, ≥5.0
   bits/char, guarded by the `has_high_signal_injection_shape` fast-path). Wired into sqli, cmdi, xss, ssrf,
   template (replacing the bare `form_body_is_opaque_beacon` call). RED-then-GREEN: template skips an opaque
   PDF body with a stray `${7*7}`; ssrf skips a high-entropy JSON replay with a coincidental metadata-IP URL;
   readable JSON (even with ids) and injection-shaped bodies stay scannable (FN-safety tests). Workspace green.
   **Note:** the ≥5.0-bit entropy floor is conservative but should be re-tuned against the captured telemetry
   corpus when available.
3. ✅ **Group 3 JWT parser tightening — SHIPPED (develop):** `jwt_inspection.rs` — **JWT-1** structural gate
   (a token fires only when its header carries a string `alg` AND its payload decodes to a JSON object; a
   misparsed base64 cookie satisfies neither), and **JWT-2** auth-cookie-name gate (`cookie_name_is_auth`:
   only cookies whose name contains `token`/`jwt`/`auth`/`bearer` or is exactly `sid`/`sess`/`session`/`sso`/
   `access` are JWT-scanned — Adobe Target `mbox`, Adobe Analytics `s_vi`, Tealeaf visitor cookies are no
   longer misparsed). Authorization: Bearer path unchanged. RED-then-GREEN; all real detections (alg-none,
   x5c, kid, jku, time-forged) preserved. Suite green (75 pass).
4. ✅ **Phase 2 — SHIPPED (develop), recall preserved (owner: "do it, preserve recall"):**
   - **SQ-2 (sqli.rs):** split `SQLI_PATTERNS` → `SQLI_HIGH` (unambiguous, single-hit block) + `SQLI_AMBIGUOUS`
     (function-name / clause-bridge: `SELECT…FROM`, `UPDATE…SET`, `SLEEP(`, `BENCHMARK(`, `EXEC`, `CHAR(n)`,
     `CONCAT(`, `ORDER BY n`). Ambiguous fires ONLY with a `--` SQL-comment corroborator in the same field, so
     a lone benign `concat(`/`char(`/`SELECT…FROM` (analytics/GraphQL/**YQL**) emits **no** signal. Recall
     preserved: added a HIGH pattern for a time-func in an injection context (`(?:AND|OR|;|\))\s*(?:SLEEP|
     BENCHMARK|PG_SLEEP)\(`) so realistic blind SQLi (`1 AND SLEEP(5)`) still blocks; bare-token positives
     re-anchored to realistic `'…--` / `UNION` forms. red_team suite green.
   - **CI-1 (command_injection.rs):** split the CMD alternation → `HIGH_CMD` (exec/recon binaries, fire on bare
     metachar) + `AMBIG_CMD` (English facet words `id`/`cat`/`ls`/`dir`/`ping`/`sleep`…, require a real
     argument tail `AMBIG_ARG`). Pipe/`;`/chain facet lists (`filter=running|training|id`, `sort=price|asc|dir`)
     no longer fire; real `;cat /etc/passwd` / `|dir /s` still do. Subshell/backtick keep the full set. Only
     `cmdi_pipe_dir` re-anchored (`|dir /s`).
   RED-then-GREEN throughout; `cargo test -p aegis-security` 2190 pass, 0 warnings.
5. **G1-c allowlist / Group 2 / Group 4 / Phase 3:** only the residual the corpus still shows after a re-run.
